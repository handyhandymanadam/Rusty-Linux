/* Stand-ins for what the pristine slice of net/ipv4/tcp_htcp.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32; typedef uint32_t __u32;
extern unsigned int hz_g; extern unsigned long jiffies;
#define HZ ((int)hz_g)
#define tcp_jiffies32 ((u32)jiffies)
#define __read_mostly
#define module_param(a, b, c)
#define MODULE_PARM_DESC(a, b)
#define static_assert(x) _Static_assert(x, #x)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define clamp(v, lo, hi) ((v) < (lo) ? (lo) : (v) > (hi) ? (hi) : (v))
static inline int between(u32 s1, u32 s2, u32 s3) { return s3 - s2 >= s1 - s2; }
#define TCP_CA_Open 0
#define TCP_CA_Disorder 1
#define TCP_CA_CWR 2
#define TCP_CA_Recovery 3
#define TCP_CA_Loss 4
#define TCPF_CA_Open (1 << TCP_CA_Open)
#define TCPF_CA_Disorder (1 << TCP_CA_Disorder)
static inline unsigned long usecs_to_jiffies(const unsigned int u) { return (u64)u * HZ / 1000000 + ((u64)u * HZ % 1000000 != 0); }
static inline unsigned long msecs_to_jiffies(const unsigned int m) { return ((u64)m * HZ + 999) / 1000; }
struct tcp_sock { u32 snd_cwnd, snd_cwnd_cnt, snd_cwnd_clamp, snd_ssthresh; };
struct inet_connection_sock { u8 icsk_ca_state; };
struct ack_sample { u32 pkts_acked; s32 rtt_us; };
#endif
