/* Stand-ins for what the pristine security/selinux/ss/avtab.c, avtab.h and the avtab_glue.c wrappers use. */
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
#define pr_err(...) printf(__VA_ARGS__)
#define pr_warn(...) printf(__VA_ARGS__)
#define pr_debug(...) do { } while (0)
#define GFP_KERNEL 2
struct kmem_cache { int x; };
typedef int gfp_t;
extern struct kmem_cache *avtab_node_cachep, *avtab_xperms_cachep;
extern long fail_in, live_nodes, allocs;
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live_nodes++; return calloc(1, c == avtab_node_cachep ? 24 : 36);
}
static inline void kmem_cache_free(struct kmem_cache *c, void *p) { live_nodes--; free(p); }
static inline void *kvcalloc(size_t n, size_t sz, gfp_t g)
{
	allocs++;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live_nodes++; return calloc(n, sz);
}
static inline void kvfree(void *p) { if (p) live_nodes--; free(p); }
#endif
