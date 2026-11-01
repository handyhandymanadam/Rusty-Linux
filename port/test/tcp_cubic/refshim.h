/* Stand-ins for what the pristine slice of net/ipv4/tcp_cubic.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32;
extern unsigned int hz_g; extern u32 tj, cube_rtt_scale, beta_scale; extern u64 cube_factor; extern int tcp_friendliness;
#define HZ ((int)hz_g)
#define tcp_jiffies32 tj
#define static_assert(x) _Static_assert(x, #x)
#define BICTCP_HZ 10
#define __maybe_unused __attribute__((unused))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define do_div(n, base) ({ u32 __rem = (n) % (base); (n) /= (base); __rem; })
static inline int fls64(u64 x) { return x ? 64 - __builtin_clzll(x) : 0; }
static inline u64 div64_u64(u64 a, u64 b) { return a / b; }
static inline unsigned long usecs_to_jiffies(const unsigned int u) { return (u64)u * HZ / 1000000 + ((u64)u * HZ % 1000000 != 0); }
#endif
