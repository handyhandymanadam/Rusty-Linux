/* Stand-ins for what the pristine slice of net/ipv4/tcp_illinois.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32;
#define U32_MAX ((u32)~0U)
#define __read_mostly
#define module_param(a, b, c)
#define MODULE_PARM_DESC(a, b)
#define static_assert(x) _Static_assert(x, #x)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define do_div(n, base) ({ u32 __rem = (n) % (base); (n) /= (base); __rem; })
#define TCP_CA_Loss 4
#define after(a, b) ((s32)((b) - (a)) < 0)
struct tcp_sock { u32 snd_nxt, snd_cwnd, snd_cwnd_cnt, snd_cwnd_clamp, snd_ssthresh; };
struct ack_sample { u32 pkts_acked; s32 rtt_us; };
#endif
