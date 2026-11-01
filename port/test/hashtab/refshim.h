/* Stand-ins for what the pristine security/selinux/ss/hashtab.c, symtab.c and the glue wrappers use. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define EINVAL 22
#define ENOMEM 12
#define EEXIST 17
#define U32_MAX ((u32)~0U)
#define __init
#define __ro_after_init
#define static_assert(x) _Static_assert(x, #x)
#define cond_resched() do { resched_count++; } while (0)
extern long resched_count;
static inline unsigned long roundup_pow_of_two(unsigned long n) { unsigned long r = 1; while (r < n) r *= 2; return r; }
#define GFP_KERNEL 2
#define __GFP_NOWARN 0x200
struct kmem_cache { int x; };
typedef int gfp_t;
extern struct kmem_cache *hashtab_node_cachep;
extern long fail_in, live;
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t g)
{
	if (fail_in > 0 && --fail_in == 0) return NULL;
	live++; return calloc(1, 24);
}
static inline void kmem_cache_free(struct kmem_cache *c, void *p) { live--; free(p); }
static char zero_size_ptr[1];
static inline void *kcalloc(size_t n, size_t sz, gfp_t g)
{
	if (fail_in > 0 && --fail_in == 0) return NULL;
	if (n > (1u << 20)) return NULL;
	if (n == 0) return zero_size_ptr;
	live++; return calloc(n, sz);
}
static inline void kfree(void *p) { if (p && p != zero_size_ptr) { live--; free(p); } }
#endif
