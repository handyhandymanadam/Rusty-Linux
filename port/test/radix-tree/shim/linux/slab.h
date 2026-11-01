#ifndef SHR_SLAB_H
#define SHR_SLAB_H
#include <linux/types.h>
#include <stdlib.h>
struct kmem_cache { int dummy; };
extern long fail_node; extern long nodes_live;
static inline void *kmem_cache_alloc(struct kmem_cache *c, gfp_t gfp) { (void)c; (void)gfp; if (fail_node < 0 || (fail_node > 0 && --fail_node == 0)) return NULL; nodes_live++; return calloc(1, 4096); }
static inline void kmem_cache_free(struct kmem_cache *c, void *p) { (void)c; nodes_live--; free(p); }
static inline struct kmem_cache *kmem_cache_create(const char *n, unsigned sz, unsigned al, unsigned long fl, void (*ctor)(void *)) { return NULL; }
#define SLAB_PANIC 0
#define SLAB_RECLAIM_ACCOUNT 0
#endif
