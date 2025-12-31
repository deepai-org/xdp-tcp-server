// SPDX-License-Identifier: GPL-2.0
/*
 * XDP TCP Server - "Baby Redis" key-value store
 * Simplified version with 8-char keys and 16-char values
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common.h"

/* Simple 8-byte key */
struct kv_key {
    __u64 k;
};

/* Simple 16-byte value */
struct kv_value {
    __u64 v1;
    __u64 v2;
};

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

/* Key-value store - 1000 entries, 8-byte keys, 16-byte values */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, struct kv_key);
    __type(value, struct kv_value);
} kvstore SEC(".maps");

/* ============================================================================
 * HELPERS
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

static __always_inline __u16 ip_checksum(void *ip_hdr, void *data_end)
{
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip_hdr;
    if ((void *)(ptr + 10) > data_end) return 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) sum += ptr[i];
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline __u16 tcp_checksum(struct iphdr *ip, struct tcphdr *tcp,
                                          void *data_end, __u16 tcp_len)
{
    __u32 sum = 0;
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons(tcp_len);
    __u16 *ptr = (__u16 *)tcp;
    #pragma unroll
    for (int i = 0; i < 50; i++) {
        if ((void *)(ptr + 1) > data_end) break;
        if (i >= tcp_len / 2) break;
        sum += *ptr++;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

/* ============================================================================
 * TCP HANDLERS (simplified)
 * ============================================================================ */

static __always_inline int handle_syn(struct xdp_md *ctx, struct ethhdr *eth,
                                      struct iphdr *ip, struct tcphdr *tcp,
                                      struct session_key *key)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();
    if (stats) stats->syn_received++;

    struct session_state s = {0};
    s.state = TCP_STATE_SYN_RCVD;
    s.isn = generate_isn(key->src_ip, key->dst_ip, key->src_port, key->dst_port);
    s.our_seq = s.isn;
    s.their_seq = bpf_ntohl(tcp->seq) + 1;
    s.our_ack = s.their_seq;
    s.window_size = WINDOW_SIZE;
    s.last_seen = bpf_ktime_get_ns();
    bpf_map_update_elem(&sessions, key, &s, BPF_ANY);

    swap_mac(eth);
    __be32 t = ip->saddr; ip->saddr = ip->daddr; ip->daddr = t;
    __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;

    tcp->seq = bpf_htonl(s.isn);
    tcp->ack_seq = bpf_htonl(s.their_seq);
    tcp->doff = 5; tcp->res1 = 0;
    tcp->syn = 1; tcp->ack = 1; tcp->fin = 0; tcp->rst = 0; tcp->psh = 0;
    tcp->window = bpf_htons(WINDOW_SIZE);

    ip->tot_len = bpf_htons(40);
    ip->check = 0; ip->check = ip_checksum(ip, data_end);
    tcp->check = 0; tcp->check = tcp_checksum(ip, tcp, data_end, 20);

    if (stats) stats->packets_sent++;
    return XDP_TX;
}

static __always_inline int handle_fin(struct xdp_md *ctx, struct ethhdr *eth,
                                      struct iphdr *ip, struct tcphdr *tcp,
                                      struct session_state *s, struct session_key *key)
{
    void *data_end = (void *)(long)ctx->data_end;
    s->their_seq = bpf_ntohl(tcp->seq) + 1;
    s->our_ack = s->their_seq;

    swap_mac(eth);
    __be32 t = ip->saddr; ip->saddr = ip->daddr; ip->daddr = t;
    __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;

    tcp->seq = bpf_htonl(s->our_seq);
    tcp->ack_seq = bpf_htonl(s->our_ack);
    tcp->doff = 5; tcp->syn = 0; tcp->ack = 1; tcp->fin = 1; tcp->rst = 0; tcp->psh = 0;
    tcp->window = bpf_htons(s->window_size);

    ip->tot_len = bpf_htons(40);
    ip->check = 0; ip->check = ip_checksum(ip, data_end);
    tcp->check = 0; tcp->check = tcp_checksum(ip, tcp, data_end, 20);

    s->our_seq++;
    s->state = TCP_STATE_LAST_ACK;
    bpf_map_update_elem(&sessions, key, s, BPF_EXIST);
    return XDP_TX;
}

/* Response: 60 bytes = header(39) + body(21) */
#define RESP_LEN 60

/*
 * Routes:
 *   GET /g/KEY      -> get key (8 chars max)
 *   GET /s/KEY/VAL  -> set key=val
 *   GET /           -> help
 */
static __always_inline int handle_data(struct xdp_md *ctx, struct session_state *s,
                                       struct session_key *key, __u16 plen, __u32 their_seq)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();

    s->their_seq = their_seq + plen;
    s->our_ack = s->their_seq;
    s->last_seen = bpf_ktime_get_ns();

    /* Parse before resize */
    struct ethhdr *e = data;
    if ((void *)(e + 1) > data_end) return XDP_DROP;
    struct iphdr *i = (void *)(e + 1);
    if ((void *)(i + 1) > data_end) return XDP_DROP;
    struct tcphdr *t = (void *)i + 20;
    if ((void *)(t + 1) > data_end) return XDP_DROP;
    char *req = (char *)t + 20;
    if ((void *)(req + 20) > data_end) return XDP_DROP;

    /* Parse command: "GET /X/..." */
    int cmd = 0; /* 0=home, 1=get, 2=set */
    struct kv_key kk = {0};
    struct kv_value kv = {0};

    if (req[0]=='G' && req[1]=='E' && req[2]=='T' && req[3]==' ' && req[4]=='/') {
        if (req[5]=='g' && req[6]=='/') {
            cmd = 1;
            /* Key at req[7..14] */
            if ((void *)(req + 15) <= data_end) {
                char *k = (char *)&kk.k;
                k[0]=req[7]; k[1]=req[8]; k[2]=req[9]; k[3]=req[10];
                k[4]=req[11]; k[5]=req[12]; k[6]=req[13]; k[7]=req[14];
            }
        } else if (req[5]=='s' && req[6]=='/') {
            cmd = 2;
            /* Key at req[7..14], value at req[16..31] */
            if ((void *)(req + 32) <= data_end) {
                char *k = (char *)&kk.k;
                k[0]=req[7]; k[1]=req[8]; k[2]=req[9]; k[3]=req[10];
                k[4]=req[11]; k[5]=req[12]; k[6]=req[13]; k[7]=req[14];
                char *v = (char *)&kv;
                v[0]=req[16]; v[1]=req[17]; v[2]=req[18]; v[3]=req[19];
                v[4]=req[20]; v[5]=req[21]; v[6]=req[22]; v[7]=req[23];
                v[8]=req[24]; v[9]=req[25]; v[10]=req[26]; v[11]=req[27];
                v[12]=req[28]; v[13]=req[29]; v[14]=req[30]; v[15]=req[31];
            }
        }
    }

    /* Resize packet */
    long delta = (long)(14 + 20 + 20 + RESP_LEN) - ((long)data_end - (long)data);
    if (bpf_xdp_adjust_tail(ctx, (int)delta)) return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;
    struct tcphdr *tcp = (void *)ip + 20;
    if ((void *)(tcp + 1) > data_end) return XDP_DROP;
    char *body = (char *)tcp + 20;
    if ((void *)(body + RESP_LEN) > data_end) return XDP_DROP;

    swap_mac(eth);
    __be32 tmp = ip->saddr; ip->saddr = ip->daddr; ip->daddr = tmp;
    __be16 pt = tcp->source; tcp->source = tcp->dest; tcp->dest = pt;

    tcp->seq = bpf_htonl(s->our_seq);
    tcp->ack_seq = bpf_htonl(s->our_ack);
    tcp->doff = 5; tcp->syn = 0; tcp->ack = 1; tcp->fin = 0; tcp->rst = 0; tcp->psh = 1;
    tcp->window = bpf_htons(s->window_size);

    /* HTTP header: "HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n" = 39 bytes */
    body[0]='H';body[1]='T';body[2]='T';body[3]='P';body[4]='/';body[5]='1';body[6]='.';body[7]='1';
    body[8]=' ';body[9]='2';body[10]='0';body[11]='0';body[12]=' ';body[13]='O';body[14]='K';body[15]='\r';
    body[16]='\n';body[17]='C';body[18]='o';body[19]='n';body[20]='t';body[21]='e';body[22]='n';body[23]='t';
    body[24]='-';body[25]='L';body[26]='e';body[27]='n';body[28]='g';body[29]='t';body[30]='h';body[31]=':';
    body[32]=' ';body[33]='2';body[34]='1';body[35]='\r';body[36]='\n';body[37]='\r';body[38]='\n';

    /* Body: 21 bytes */
    char *out = body + 39;

    if (cmd == 1) {
        /* GET */
        struct kv_value *v = bpf_map_lookup_elem(&kvstore, &kk);
        if (v) {
            char *src = (char *)v;
            out[0]=src[0];out[1]=src[1];out[2]=src[2];out[3]=src[3];
            out[4]=src[4];out[5]=src[5];out[6]=src[6];out[7]=src[7];
            out[8]=src[8];out[9]=src[9];out[10]=src[10];out[11]=src[11];
            out[12]=src[12];out[13]=src[13];out[14]=src[14];out[15]=src[15];
            out[16]='\n';out[17]=' ';out[18]=' ';out[19]=' ';out[20]=' ';
        } else {
            out[0]='(';out[1]='n';out[2]='i';out[3]='l';out[4]=')';out[5]='\n';
            out[6]=' ';out[7]=' ';out[8]=' ';out[9]=' ';out[10]=' ';out[11]=' ';
            out[12]=' ';out[13]=' ';out[14]=' ';out[15]=' ';out[16]=' ';out[17]=' ';
            out[18]=' ';out[19]=' ';out[20]=' ';
        }
    } else if (cmd == 2) {
        /* SET */
        bpf_map_update_elem(&kvstore, &kk, &kv, BPF_ANY);
        out[0]='O';out[1]='K';out[2]='\n';
        out[3]=' ';out[4]=' ';out[5]=' ';out[6]=' ';out[7]=' ';out[8]=' ';out[9]=' ';
        out[10]=' ';out[11]=' ';out[12]=' ';out[13]=' ';out[14]=' ';out[15]=' ';out[16]=' ';
        out[17]=' ';out[18]=' ';out[19]=' ';out[20]=' ';
    } else {
        /* HOME */
        out[0]='B';out[1]='a';out[2]='b';out[3]='y';out[4]=' ';out[5]='R';out[6]='e';out[7]='d';
        out[8]='i';out[9]='s';out[10]='\n';
        out[11]=' ';out[12]=' ';out[13]=' ';out[14]=' ';out[15]=' ';out[16]=' ';out[17]=' ';
        out[18]=' ';out[19]=' ';out[20]=' ';
    }

    ip->tot_len = bpf_htons(20 + 20 + RESP_LEN);
    ip->ttl = 64;
    ip->check = 0; ip->check = ip_checksum(ip, data_end);
    tcp->check = 0; tcp->check = tcp_checksum(ip, tcp, data_end, 20 + RESP_LEN);

    s->our_seq += RESP_LEN;
    bpf_map_update_elem(&sessions, key, s, BPF_EXIST);

    if (stats) { stats->bytes_sent += RESP_LEN; stats->packets_sent++; }
    return XDP_TX;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

SEC("xdp")
int xdp_tcp_server(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct stats *stats = get_stats();
    if (stats) stats->packets_received++;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + 20;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    if (tcp->dest != bpf_htons(SERVER_PORT)) return XDP_PASS;

    struct session_key key = {
        .src_ip = ip->saddr, .dst_ip = ip->daddr,
        .src_port = tcp->source, .dst_port = tcp->dest,
    };

    __u16 plen = bpf_ntohs(ip->tot_len) - 20 - (tcp->doff * 4);
    if (tcp->rst) { bpf_map_delete_elem(&sessions, &key); return XDP_DROP; }

    struct session_state *s = bpf_map_lookup_elem(&sessions, &key);

    if (tcp->syn && !tcp->ack)
        return handle_syn(ctx, eth, ip, tcp, &key);

    if (!s) return XDP_DROP;

    if (tcp->fin)
        return handle_fin(ctx, eth, ip, tcp, s, &key);

    if (tcp->ack) {
        if (s->state == TCP_STATE_LAST_ACK) {
            bpf_map_delete_elem(&sessions, &key);
            return XDP_DROP;
        }
        if (s->state == TCP_STATE_SYN_RCVD) {
            s->state = TCP_STATE_ESTABLISHED;
            s->our_seq = bpf_ntohl(tcp->ack_seq);
            bpf_map_update_elem(&sessions, &key, s, BPF_EXIST);
            if (stats) stats->connections_established++;
            return XDP_DROP;
        }
        if (s->state == TCP_STATE_ESTABLISHED && plen > 0)
            return handle_data(ctx, s, &key, plen, bpf_ntohl(tcp->seq));
    }

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
