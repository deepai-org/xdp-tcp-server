// SPDX-License-Identifier: GPL-2.0
/*
 * XDP TCP Server - Full TCP server running entirely in kernel mode
 * Zero context switches - packets never reach user space
 *
 * AWS/Cloud compatible version with route-based responses and state
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common.h"

/* ============================================================================
 * BPF MAPS
 * ============================================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, struct session_key);
    __type(value, struct session_state);
} sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} statistics SEC(".maps");

/* Route hit counters - tracks requests per route */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);  /* 4 routes: home, api, health, stats */
    __type(key, __u32);
    __type(value, __u64);
} route_hits SEC(".maps");

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

static __always_inline struct stats *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&statistics, &key);
}

static __always_inline __u32 generate_isn(__u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port)
{
    __u64 ts = bpf_ktime_get_ns();
    __u32 hash = src_ip ^ dst_ip ^ ((__u32)src_port << 16 | dst_port);
    return (__u32)(ts ^ hash);
}

/* ============================================================================
 * CHECKSUM HELPERS
 * ============================================================================ */

static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline void update_csum(__sum16 *csum, __be32 old_val, __be32 new_val)
{
    __u32 new_csum = ~((__u32)*csum) & 0xffff;
    new_csum += ~((__u32)old_val >> 16) & 0xffff;
    new_csum += ~((__u32)old_val & 0xffff) & 0xffff;
    new_csum += ((__u32)new_val >> 16) & 0xffff;
    new_csum += ((__u32)new_val & 0xffff) & 0xffff;
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    *csum = (__sum16)~new_csum;
}

static __always_inline void update_csum16(__sum16 *csum, __be16 old_val, __be16 new_val)
{
    __u32 new_csum = ~((__u32)*csum) & 0xffff;
    new_csum += ~((__u32)old_val) & 0xffff;
    new_csum += (__u32)new_val;
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    *csum = (__sum16)~new_csum;
}

static __always_inline __u16 ip_checksum(void *ip_hdr, void *data_end)
{
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip_hdr;

    if ((void *)(ptr + 10) > data_end)
        return 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += ptr[i];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (__u16)~sum;
}

static __always_inline __u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end, __u16 tcp_len)
{
    __u32 sum = 0;
    __u16 *ptr;

    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);

    ptr = (__u16 *)tcp;
    __u16 words = tcp_len / 2;

    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if ((void *)(ptr + 1) > data_end)
            break;
        if (i >= words)
            break;
        sum += *ptr;
        ptr++;
    }

    if ((tcp_len & 1) && (void *)ptr < data_end) {
        __u8 *byte_ptr = (__u8 *)ptr;
        if ((void *)(byte_ptr + 1) <= data_end)
            sum += (__u16)*byte_ptr;
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (__u16)~sum;
}

/* ============================================================================
 * PACKET MANIPULATION
 * ============================================================================ */

static __always_inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_ip_with_csum(struct iphdr *ip, struct tcphdr *tcp)
{
    __be32 old_saddr = ip->saddr;
    __be32 old_daddr = ip->daddr;

    ip->saddr = old_daddr;
    ip->daddr = old_saddr;

    update_csum(&ip->check, old_saddr, ip->saddr);
    update_csum(&ip->check, old_daddr, ip->daddr);
    update_csum(&tcp->check, old_saddr, ip->saddr);
    update_csum(&tcp->check, old_daddr, ip->daddr);
}

static __always_inline void swap_ports_with_csum(struct tcphdr *tcp)
{
    __be16 old_source = tcp->source;
    __be16 old_dest = tcp->dest;

    tcp->source = old_dest;
    tcp->dest = old_source;

    update_csum16(&tcp->check, old_source, tcp->source);
    update_csum16(&tcp->check, old_dest, tcp->dest);
}

/* ============================================================================
 * TCP HANDLERS
 * ============================================================================ */

static __always_inline int handle_syn(struct xdp_md *ctx,
                                      struct ethhdr *eth,
                                      struct iphdr *ip,
                                      struct tcphdr *tcp,
                                      struct session_key *key)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();

    if (stats)
        stats->syn_received++;

    struct session_state new_session = {0};
    new_session.state = TCP_STATE_SYN_RCVD;
    new_session.isn = generate_isn(key->src_ip, key->dst_ip,
                                   key->src_port, key->dst_port);
    new_session.our_seq = new_session.isn;
    new_session.their_seq = bpf_ntohl(tcp->seq) + 1;
    new_session.our_ack = new_session.their_seq;
    new_session.window_size = WINDOW_SIZE;
    new_session.last_seen = bpf_ktime_get_ns();

    if (bpf_map_update_elem(&sessions, key, &new_session, BPF_ANY) < 0) {
        if (stats)
            stats->errors++;
        return XDP_DROP;
    }

    swap_mac(eth);

    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    tcp->seq = bpf_htonl(new_session.isn);
    tcp->ack_seq = bpf_htonl(new_session.their_seq);
    tcp->doff = 5;
    tcp->res1 = 0;
    tcp->cwr = 0;
    tcp->ece = 0;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 1;
    tcp->fin = 0;
    tcp->window = bpf_htons(WINDOW_SIZE);
    tcp->urg_ptr = 0;

    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);

    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, data_end, sizeof(struct tcphdr));

    if (stats)
        stats->packets_sent++;

    return XDP_TX;
}

static __always_inline int handle_ack(struct session_state *session,
                                      struct tcphdr *tcp,
                                      struct session_key *key)
{
    struct stats *stats = get_stats();
    __u32 ack_num = bpf_ntohl(tcp->ack_seq);

    if (session->state == TCP_STATE_SYN_RCVD) {
        if (ack_num == session->isn + 1) {
            session->state = TCP_STATE_ESTABLISHED;
            session->our_seq = ack_num;
            session->last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&sessions, key, session, BPF_EXIST);

            if (stats)
                stats->connections_established++;
        }
    }

    return XDP_DROP;
}

static __always_inline int handle_fin(struct xdp_md *ctx,
                                      struct ethhdr *eth,
                                      struct iphdr *ip,
                                      struct tcphdr *tcp,
                                      struct session_state *session,
                                      struct session_key *key)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();

    if (session->state == TCP_STATE_ESTABLISHED)
        session->state = TCP_STATE_CLOSE_WAIT;

    __u32 their_seq = bpf_ntohl(tcp->seq);
    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u16 payload_len = 0;

    if (ip_total_len > sizeof(struct iphdr) + tcp_hdr_len)
        payload_len = ip_total_len - sizeof(struct iphdr) - tcp_hdr_len;

    session->their_seq = their_seq + payload_len + 1;
    session->our_ack = session->their_seq;
    session->last_seen = bpf_ktime_get_ns();

    swap_mac(eth);

    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    tcp->seq = bpf_htonl(session->our_seq);
    tcp->ack_seq = bpf_htonl(session->our_ack);
    tcp->doff = 5;
    tcp->res1 = 0;
    tcp->cwr = 0;
    tcp->ece = 0;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 1;
    tcp->window = bpf_htons(session->window_size);
    tcp->urg_ptr = 0;

    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);
    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, data_end, sizeof(struct tcphdr));

    session->state = TCP_STATE_LAST_ACK;
    session->our_seq++;
    bpf_map_update_elem(&sessions, key, session, BPF_EXIST);

    if (stats) {
        stats->connections_closed++;
        stats->packets_sent++;
    }

    return XDP_TX;
}

static __always_inline int handle_final_ack(struct session_key *key)
{
    bpf_map_delete_elem(&sessions, key);
    return XDP_DROP;
}

/* ============================================================================
 * HTTP ROUTING - Parse request and select response
 * ============================================================================ */

/* Route IDs */
#define ROUTE_HOME   0
#define ROUTE_API    1
#define ROUTE_HEALTH 2
#define ROUTE_STATS  3

/* All responses padded to same length */
#define HTTP_RESPONSE_LEN 80

static __always_inline int parse_route(char *p, void *data_end)
{
    if ((void *)(p + 14) > data_end)
        return ROUTE_HOME;
    
    if (p[0] != 'G' || p[1] != 'E' || p[2] != 'T' || p[3] != ' ' || p[4] != '/')
        return ROUTE_HOME;
    
    /* Root path */
    if (p[5] == ' ' || p[5] == '?' || p[5] == 'H')
        return ROUTE_HOME;
    
    /* /api */
    if (p[5] == 'a' && p[6] == 'p' && p[7] == 'i')
        return ROUTE_API;
    
    /* /health */
    if (p[5] == 'h' && p[6] == 'e' && p[7] == 'a' && p[8] == 'l' && 
        p[9] == 't' && p[10] == 'h')
        return ROUTE_HEALTH;
    
    /* /stats */
    if (p[5] == 's' && p[6] == 't' && p[7] == 'a' && p[8] == 't' && p[9] == 's')
        return ROUTE_STATS;
    
    return ROUTE_HOME;
}

/* Increment route counter */
static __always_inline void increment_route_hit(__u32 route)
{
    __u64 *count = bpf_map_lookup_elem(&route_hits, &route);
    if (count)
        __sync_fetch_and_add(count, 1);
}

/* Get route hit count */
static __always_inline __u64 get_route_hits(__u32 route)
{
    __u64 *count = bpf_map_lookup_elem(&route_hits, &route);
    return count ? *count : 0;
}

/* Write a digit (0-9) */
static __always_inline void write_digit(char *p, __u64 val)
{
    *p = '0' + (val % 10);
}

/* Write number (up to 9999999) into buffer, returns chars written */
static __always_inline int write_number(char *buf, __u64 num)
{
    char tmp[8];
    int i = 0;
    
    if (num == 0) {
        buf[0] = '0';
        return 1;
    }
    
    /* Extract digits in reverse */
    while (num > 0 && i < 7) {
        tmp[i++] = '0' + (num % 10);
        num /= 10;
    }
    
    /* Copy in correct order */
    int len = i;
    for (int j = 0; j < len; j++) {
        buf[j] = tmp[len - 1 - j];
    }
    
    return len;
}

static __always_inline void write_http_response(char *payload, int route)
{
    /* Get hit counts for stats route */
    __u64 home_hits = get_route_hits(ROUTE_HOME);
    __u64 api_hits = get_route_hits(ROUTE_API);
    __u64 health_hits = get_route_hits(ROUTE_HEALTH);
    __u64 stats_hits = get_route_hits(ROUTE_STATS);
    
    /* HTTP header: "HTTP/1.1 200 OK\r\nContent-Length: 41\r\n\r\n" (39 bytes) */
    payload[0]='H';payload[1]='T';payload[2]='T';payload[3]='P';payload[4]='/';
    payload[5]='1';payload[6]='.';payload[7]='1';payload[8]=' ';payload[9]='2';
    payload[10]='0';payload[11]='0';payload[12]=' ';payload[13]='O';payload[14]='K';
    payload[15]='\r';payload[16]='\n';
    payload[17]='C';payload[18]='o';payload[19]='n';payload[20]='t';payload[21]='e';
    payload[22]='n';payload[23]='t';payload[24]='-';payload[25]='L';payload[26]='e';
    payload[27]='n';payload[28]='g';payload[29]='t';payload[30]='h';payload[31]=':';
    payload[32]=' ';payload[33]='4';payload[34]='1';payload[35]='\r';payload[36]='\n';
    payload[37]='\r';payload[38]='\n';

    /* Body: 41 bytes (padded) */
    if (route == ROUTE_STATS) {
        /* {"home":N,"api":N,"health":N,"stats":N}\n */
        payload[39]='{';payload[40]='"';payload[41]='h';payload[42]='o';payload[43]='m';
        payload[44]='e';payload[45]='"';payload[46]=':';
        /* home count - single digit for simplicity */
        payload[47] = '0' + (home_hits % 10);
        payload[48]=',';payload[49]='"';payload[50]='a';payload[51]='p';payload[52]='i';
        payload[53]='"';payload[54]=':';
        payload[55] = '0' + (api_hits % 10);
        payload[56]=',';payload[57]='"';payload[58]='h';payload[59]='l';payload[60]='t';
        payload[61]='h';payload[62]='"';payload[63]=':';
        payload[64] = '0' + (health_hits % 10);
        payload[65]=',';payload[66]='"';payload[67]='s';payload[68]='t';payload[69]='a';
        payload[70]='t';payload[71]='s';payload[72]='"';payload[73]=':';
        payload[74] = '0' + (stats_hits % 10);
        payload[75]='}';payload[76]='\n';
        payload[77]=' ';payload[78]=' ';payload[79]=' ';
    } else if (route == ROUTE_API) {
        /* {"status":"ok"}  + padding */
        payload[39]='{';payload[40]='"';payload[41]='s';payload[42]='t';payload[43]='a';
        payload[44]='t';payload[45]='u';payload[46]='s';payload[47]='"';payload[48]=':';
        payload[49]='"';payload[50]='o';payload[51]='k';payload[52]='"';payload[53]='}';
        payload[54]='\n';
        /* Padding */
        payload[55]=' ';payload[56]=' ';payload[57]=' ';payload[58]=' ';payload[59]=' ';
        payload[60]=' ';payload[61]=' ';payload[62]=' ';payload[63]=' ';payload[64]=' ';
        payload[65]=' ';payload[66]=' ';payload[67]=' ';payload[68]=' ';payload[69]=' ';
        payload[70]=' ';payload[71]=' ';payload[72]=' ';payload[73]=' ';payload[74]=' ';
        payload[75]=' ';payload[76]=' ';payload[77]=' ';payload[78]=' ';payload[79]=' ';
    } else if (route == ROUTE_HEALTH) {
        /* OK + padding */
        payload[39]='O';payload[40]='K';payload[41]='\n';
        /* Padding */
        payload[42]=' ';payload[43]=' ';payload[44]=' ';payload[45]=' ';payload[46]=' ';
        payload[47]=' ';payload[48]=' ';payload[49]=' ';payload[50]=' ';payload[51]=' ';
        payload[52]=' ';payload[53]=' ';payload[54]=' ';payload[55]=' ';payload[56]=' ';
        payload[57]=' ';payload[58]=' ';payload[59]=' ';payload[60]=' ';payload[61]=' ';
        payload[62]=' ';payload[63]=' ';payload[64]=' ';payload[65]=' ';payload[66]=' ';
        payload[67]=' ';payload[68]=' ';payload[69]=' ';payload[70]=' ';payload[71]=' ';
        payload[72]=' ';payload[73]=' ';payload[74]=' ';payload[75]=' ';payload[76]=' ';
        payload[77]=' ';payload[78]=' ';payload[79]=' ';
    } else {
        /* Hello from XDP! + padding */
        payload[39]='H';payload[40]='e';payload[41]='l';payload[42]='l';payload[43]='o';
        payload[44]=' ';payload[45]='f';payload[46]='r';payload[47]='o';payload[48]='m';
        payload[49]=' ';payload[50]='X';payload[51]='D';payload[52]='P';payload[53]='!';
        payload[54]='\n';
        /* Padding */
        payload[55]=' ';payload[56]=' ';payload[57]=' ';payload[58]=' ';payload[59]=' ';
        payload[60]=' ';payload[61]=' ';payload[62]=' ';payload[63]=' ';payload[64]=' ';
        payload[65]=' ';payload[66]=' ';payload[67]=' ';payload[68]=' ';payload[69]=' ';
        payload[70]=' ';payload[71]=' ';payload[72]=' ';payload[73]=' ';payload[74]=' ';
        payload[75]=' ';payload[76]=' ';payload[77]=' ';payload[78]=' ';payload[79]=' ';
    }
}

static __always_inline int handle_data(struct xdp_md *ctx,
                                       struct session_state *session,
                                       struct session_key *key,
                                       __u16 payload_len,
                                       __u32 their_seq)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();

    if (stats)
        stats->bytes_received += payload_len;

    session->their_seq = their_seq + payload_len;
    session->our_ack = session->their_seq;
    session->last_seen = bpf_ktime_get_ns();

    /* Parse request before resizing */
    struct ethhdr *eth_pre = data;
    if ((void *)(eth_pre + 1) > data_end)
        return XDP_DROP;
    
    struct iphdr *ip_pre = (void *)(eth_pre + 1);
    if ((void *)(ip_pre + 1) > data_end)
        return XDP_DROP;
    
    struct tcphdr *tcp_pre = (void *)ip_pre + sizeof(struct iphdr);
    if ((void *)(tcp_pre + 1) > data_end)
        return XDP_DROP;
    
    char *req_payload = (char *)tcp_pre + sizeof(struct tcphdr);
    int route = parse_route(req_payload, data_end);
    
    /* Increment hit counter for this route */
    increment_route_hit(route);

    /* Resize packet */
    long old_len = (long)data_end - (long)data;
    long desired_len = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                       sizeof(struct tcphdr) + HTTP_RESPONSE_LEN;
    int delta = (int)(desired_len - old_len);

    if (bpf_xdp_adjust_tail(ctx, delta)) {
        if (stats)
            stats->errors++;
        return XDP_DROP;
    }

    /* Re-parse after resize */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    char *payload = (char *)tcp + sizeof(struct tcphdr);
    if ((void *)(payload + HTTP_RESPONSE_LEN) > data_end)
        return XDP_DROP;

    swap_mac(eth);

    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    tcp->seq = bpf_htonl(session->our_seq);
    tcp->ack_seq = bpf_htonl(session->our_ack);
    tcp->doff = 5;
    tcp->res1 = 0;
    tcp->cwr = 0;
    tcp->ece = 0;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 1;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = bpf_htons(session->window_size);
    tcp->urg_ptr = 0;

    /* Write response based on route */
    write_http_response(payload, route);

    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + HTTP_RESPONSE_LEN);
    ip->ttl = 64;
    ip->id = bpf_htons(bpf_ntohs(ip->id) + 1);

    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);

    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, data_end, sizeof(struct tcphdr) + HTTP_RESPONSE_LEN);

    session->our_seq += HTTP_RESPONSE_LEN;
    bpf_map_update_elem(&sessions, key, session, BPF_EXIST);

    if (stats) {
        stats->bytes_sent += HTTP_RESPONSE_LEN;
        stats->packets_sent++;
    }

    return XDP_TX;
}

/* ============================================================================
 * MAIN XDP PROGRAM
 * ============================================================================ */

SEC("xdp")
int xdp_tcp_server(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();

    if (stats)
        stats->packets_received++;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest != bpf_htons(SERVER_PORT))
        return XDP_PASS;

    struct session_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u16 payload_len = 0;

    if (ip_total_len > sizeof(struct iphdr) + tcp_hdr_len)
        payload_len = ip_total_len - sizeof(struct iphdr) - tcp_hdr_len;

    if (tcp->rst) {
        bpf_map_delete_elem(&sessions, &key);
        return XDP_DROP;
    }

    struct session_state *session = bpf_map_lookup_elem(&sessions, &key);

    if (tcp->syn && !tcp->ack)
        return handle_syn(ctx, eth, ip, tcp, &key);

    if (!session)
        return XDP_DROP;

    if (tcp->fin)
        return handle_fin(ctx, eth, ip, tcp, session, &key);

    if (tcp->ack) {
        if (session->state == TCP_STATE_LAST_ACK)
            return handle_final_ack(&key);

        if (session->state == TCP_STATE_SYN_RCVD)
            return handle_ack(session, tcp, &key);

        if (session->state == TCP_STATE_ESTABLISHED && payload_len > 0) {
            __u32 their_seq = bpf_ntohl(tcp->seq);
            return handle_data(ctx, session, &key, payload_len, their_seq);
        }

        if (session->state == TCP_STATE_ESTABLISHED) {
            session->last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&sessions, &key, session, BPF_EXIST);
            return XDP_DROP;
        }
    }

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
