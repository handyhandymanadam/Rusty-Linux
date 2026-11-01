/* Stand-ins for what the pristine slice of net/ipv4/tcp_bic.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32; typedef uint32_t __u32;
extern unsigned int hz_g; extern u32 tj;
#define HZ ((int)hz_g)
#define tcp_jiffies32 tj
#define static_assert(x) _Static_assert(x, #x)
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
