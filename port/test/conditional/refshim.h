/* Stand-ins for what the pristine security/selinux/ss/conditional.c and the glue wrappers use (the conditional translation unit; avtab, hashtab and symtab have their own shims). */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef u16 __le16; typedef u32 __le32;
#define EINVAL 22
#define ENOMEM 12
#define EEXIST 17
#define U32_MAX ((u32)~0U)
#define __init
#define __ro_after_init
#define unlikely(x) __builtin_expect(!!(x), 0)
#define static_assert(x) _Static_assert(x, #x)
#define check_mul_overflow(a, b, d) __builtin_mul_overflow(a, b, d)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define hweight16(x) __builtin_popcount((u16)(x))
static inline unsigned long rounddown_pow_of_two(unsigned long n) { unsigned long r = 1; while (r * 2 <= n) r *= 2; return r; }
static inline unsigned long roundup_pow_of_two(unsigned long n) { unsigned long r = 1; while (r < n) r *= 2; return r; }
#define pr_err(...) printf(__VA_ARGS__)
#define pr_warn(...) printf(__VA_ARGS__)
#define pr_debug(...) do { } while (0)
#define cond_resched() do { resched_count++; } while (0)
#define GFP_KERNEL 2
#define __GFP_NOWARN 0x200
struct kmem_cache { int x; };
typedef int gfp_t;
extern long fail_in, live_nodes, allocs, live, resched_count;
extern struct kmem_cache *avtab_node_cachep, *avtab_xperms_cachep, *hashtab_node_cachep;
static char zero_size_ptr[1];
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live_nodes++; return calloc(1, c == avtab_node_cachep ? 24 : c == avtab_xperms_cachep ? 36 : 24);
}
static inline void kmem_cache_free(struct kmem_cache *c, void *p) { live_nodes--; free(p); }
static inline void *kvcalloc(size_t n, size_t sz, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live_nodes++; return calloc(n, sz);
}
static inline void kvfree(void *p) { if (p) live_nodes--; free(p); }
static inline void *kcalloc(size_t n, size_t sz, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	if (n == 0 || sz == 0) return zero_size_ptr;
	if (n > (1u << 20)) return NULL;
	live++; return calloc(n, sz);
}
static inline void *kzalloc(size_t sz, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live++; return calloc(1, sz);
}
static inline void *kmemdup(const void *src, size_t sz, gfp_t g)
{
	void *p;
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	if (sz == 0) return zero_size_ptr;
	live++; p = malloc(sz); memcpy(p, src, sz); return p;
}
static inline void kfree(void *p) { if (p && p != zero_size_ptr) { live--; free(p); } }
#endif
