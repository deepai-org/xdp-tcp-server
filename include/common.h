/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

/* TCP States */
#define TCP_STATE_LISTEN      0
#define TCP_STATE_SYN_RCVD    1
#define TCP_STATE_ESTABLISHED 2
#define TCP_STATE_FIN_WAIT1   3
#define TCP_STATE_FIN_WAIT2   4
#define TCP_STATE_CLOSING     5
#define TCP_STATE_TIME_WAIT   6
#define TCP_STATE_CLOSE_WAIT  7
#define TCP_STATE_LAST_ACK    8
#define TCP_STATE_CLOSED      9

/* TCP Flags */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* Server configuration */
#define SERVER_PORT 3456
#define MAX_SESSIONS 10000
#define MAX_PAYLOAD_SIZE 1024
#define WINDOW_SIZE 65535

/* Session key - identifies a TCP connection (4-tuple) */
struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/* Session state - our "socket" in kernel space */
struct session_state {
    __u32 state;           /* TCP state machine */
    __u32 our_seq;         /* Our current sequence number */
    __u32 their_seq;       /* Their sequence number (what we ACK) */
    __u32 our_ack;         /* What we're acknowledging */
    __u16 window_size;     /* Flow control window */
    __u64 last_seen;       /* Timestamp for timeout handling */
    __u32 isn;             /* Initial sequence number */
};

/* Statistics */
struct stats {
    __u64 packets_received;
    __u64 packets_sent;
    __u64 syn_received;
    __u64 connections_established;
    __u64 connections_closed;
    __u64 bytes_received;
    __u64 bytes_sent;
    __u64 errors;
};

#endif /* __COMMON_H */
