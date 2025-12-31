// SPDX-License-Identifier: GPL-2.0
/*
 * XDP TCP Server - Full TCP server running entirely in kernel mode
 * Zero context switches - packets never reach user space
 *
 * AWS/Cloud compatible version using bpf_redirect and incremental checksums
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
 * CHECKSUM HELPERS - Incremental updates for cloud compatibility
 * ============================================================================ */

/* Fold a 32-bit checksum into 16 bits */
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/* Update checksum when a 32-bit value changes */
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

/* Update checksum when a 16-bit value changes */
static __always_inline void update_csum16(__sum16 *csum, __be16 old_val, __be16 new_val)
{
    __u32 new_csum = ~((__u32)*csum) & 0xffff;
    new_csum += ~((__u32)old_val) & 0xffff;
    new_csum += (__u32)new_val;
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    *csum = (__sum16)~new_csum;
}

/* Calculate full IP checksum */
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

/* Calculate TCP checksum from scratch */
static __always_inline __u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end, __u16 tcp_len)
{
    __u32 sum = 0;
    __u16 *ptr;

    /* Pseudo-header */
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);

    ptr = (__u16 *)tcp;

    /* Calculate number of complete 16-bit words */
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

    /* Handle odd byte at the end - on little-endian, don't shift!
     * The odd byte is the LOW byte of a 16-bit word with HIGH byte = 0 */
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

/* Swap IPs and update checksums incrementally */
static __always_inline void swap_ip_with_csum(struct iphdr *ip, struct tcphdr *tcp)
{
    __be32 old_saddr = ip->saddr;
    __be32 old_daddr = ip->daddr;

    /* Swap IPs */
    ip->saddr = old_daddr;
    ip->daddr = old_saddr;

    /* Update IP checksum for IP swap */
    update_csum(&ip->check, old_saddr, ip->saddr);
    update_csum(&ip->check, old_daddr, ip->daddr);

    /* Update TCP checksum for IP swap (pseudo-header) */
    update_csum(&tcp->check, old_saddr, ip->saddr);
    update_csum(&tcp->check, old_daddr, ip->daddr);
}

/* Swap ports and update TCP checksum */
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

    /* Create new session */
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

    /* Swap MAC addresses */
    swap_mac(eth);

    /* Swap IP addresses */
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    /* Swap ports */
    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    /* Set TCP header for SYN-ACK */
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

    /* Set IP length */
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    /* Recalculate IP checksum from scratch */
    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);

    /* Recalculate TCP checksum from scratch */
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

    /* Swap MAC addresses */
    swap_mac(eth);

    /* Swap IP addresses */
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    /* Swap ports */
    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    /* Set TCP header for FIN-ACK */
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

    /* Set IP length */
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    /* Recalculate checksums from scratch */
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
 * HTTP RESPONSE - Simple fixed response
 * ============================================================================ */

/*
 * HTTP Response (41 bytes):
 * HTTP/1.1 200 OK\r\n  = 17 bytes
 * Content-Length: 3\r\n = 19 bytes
 * \r\n                  = 2 bytes
 * Hi\n                  = 3 bytes
 * Total                 = 41 bytes
 */
#define HTTP_RESPONSE_LEN 41

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

    /* Update session state with incoming data */
    session->their_seq = their_seq + payload_len;
    session->our_ack = session->their_seq;
    session->last_seen = bpf_ktime_get_ns();

    /* ========================================================================
     * CRITICAL FIX: Physically resize the packet buffer
     *
     * AWS Nitro/ENA hypervisors are strict: if the Ethernet frame size
     * doesn't match the IP length field, the packet is dropped.
     *
     * We must use bpf_xdp_adjust_tail() to resize the buffer.
     * ======================================================================== */

    /* Calculate current packet size and desired size */
    long old_len = (long)data_end - (long)data;

    /* Desired: Ethernet (14) + IP (20) + TCP (20) + HTTP (41) = 95 bytes */
    long desired_len = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                       sizeof(struct tcphdr) + HTTP_RESPONSE_LEN;

    /* Delta: positive to grow, negative to shrink */
    int delta = (int)(desired_len - old_len);

    /* Resize the packet buffer */
    if (bpf_xdp_adjust_tail(ctx, delta)) {
        if (stats)
            stats->errors++;
        return XDP_DROP;
    }

    /* ========================================================================
     * CRITICAL: After bpf_xdp_adjust_tail, ALL pointers are invalidated.
     * We MUST re-parse the packet from scratch.
     * ======================================================================== */

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

    /* Payload starts after TCP header */
    char *payload = (char *)tcp + sizeof(struct tcphdr);
    if ((void *)(payload + HTTP_RESPONSE_LEN) > data_end)
        return XDP_DROP;

    /* Swap MAC addresses */
    swap_mac(eth);

    /* Swap IP addresses */
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    /* Swap ports */
    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    /* Set TCP header for response */
    tcp->seq = bpf_htonl(session->our_seq);
    tcp->ack_seq = bpf_htonl(session->our_ack);
    tcp->doff = 5;  /* 20-byte TCP header, no options */
    tcp->res1 = 0;
    tcp->cwr = 0;
    tcp->ece = 0;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 1;  /* Push data */
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = bpf_htons(session->window_size);
    tcp->urg_ptr = 0;

    /* Write HTTP response payload (41 bytes) */
    /* HTTP/1.1 200 OK\r\n (17 bytes) */
    payload[0]='H';payload[1]='T';payload[2]='T';payload[3]='P';payload[4]='/';
    payload[5]='1';payload[6]='.';payload[7]='1';payload[8]=' ';payload[9]='2';
    payload[10]='0';payload[11]='0';payload[12]=' ';payload[13]='O';payload[14]='K';
    payload[15]='\r';payload[16]='\n';
    /* Content-Length: 3\r\n (19 bytes) */
    payload[17]='C';payload[18]='o';payload[19]='n';payload[20]='t';payload[21]='e';
    payload[22]='n';payload[23]='t';payload[24]='-';payload[25]='L';payload[26]='e';
    payload[27]='n';payload[28]='g';payload[29]='t';payload[30]='h';payload[31]=':';
    payload[32]=' ';payload[33]='3';payload[34]='\r';payload[35]='\n';
    /* \r\n (2 bytes) */
    payload[36]='\r';payload[37]='\n';
    /* Hi\n (3 bytes) */
    payload[38]='H';payload[39]='i';payload[40]='\n';

    /* Set IP header with payload */
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + HTTP_RESPONSE_LEN);
    ip->ttl = 64;
    ip->id = bpf_htons(bpf_ntohs(ip->id) + 1);  /* Increment IP ID to avoid dedup */

    /* Recalculate checksums */
    ip->check = 0;
    ip->check = ip_checksum(ip, data_end);

    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, data_end, sizeof(struct tcphdr) + HTTP_RESPONSE_LEN);

    /* Update session state */
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
