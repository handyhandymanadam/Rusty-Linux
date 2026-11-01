/* kernel shim for the bch differential: the few kernel interfaces lib/bch.c and bch_glue.c use, with injectable allocation failure and leak counting */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define static_assert _Static_assert
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define __init
#define EINVAL 22
#define EBADMSG 74
#define GFP_KERNEL 0
typedef uint8_t u8; typedef uint32_t u32;
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define swap(a, b) do { __typeof__(a) t_ = (a); (a) = (b); (b) = t_; } while (0)
static inline int fls(unsigned int x) { return x ? 32 - __builtin_clz(x) : 0; }
static inline u8 bitrev8(u8 b) { b = (b & 0xf0) >> 4 | (b & 0x0f) << 4; b = (b & 0xcc) >> 2 | (b & 0x33) << 2; b = (b & 0xaa) >> 1 | (b & 0x55) << 1; return b; }
#define cpu_to_be32(x) __builtin_bswap32(x)
extern int warn_count;
#define WARN_ON(c) ({ bool c_ = !!(c); warn_count += c_; c_; })
#define printk(...) ((void)0)
#define KERN_ERR ""
extern int alloc_fail_in;	/* fail the Nth next allocation; 0 = never */
extern long live_allocs;
static inline void *kmalloc(size_t sz, int f) { (void)f; if (alloc_fail_in && --alloc_fail_in == 0) return NULL; void *p = malloc(sz ? sz : 1); if (p) { memset(p, 0xA5, sz); live_allocs++; } return p; }
static inline void *kzalloc(size_t sz, int f) { (void)f; if (alloc_fail_in && --alloc_fail_in == 0) return NULL; void *p = calloc(1, sz ? sz : 1); if (p) live_allocs++; return p; }
static inline void kfree(void *p) { if (p) { live_allocs--; free(p); } }
#endif
