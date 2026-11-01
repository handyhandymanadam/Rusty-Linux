/* Standalone stand-ins for what the pristine slice of kernel/user_namespace.c uses. The kernel's isspace() is its _ctype table: \t \n \v \f \r, space, 0xa0. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#undef bsearch
#define bsearch t_bsearch
typedef uint32_t u32;
#define EPERM 1
#define ENOMEM 12
#define EINVAL 22
#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340
struct uid_gid_extent { u32 first; u32 lower_first; u32 count; };
struct uid_gid_map {
	union {
		struct { struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS]; u32 nr_extents; };
		struct { struct uid_gid_extent *forward; struct uid_gid_extent *reverse; };
	};
};
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
typedef unsigned gfp_t;
#define GFP_KERNEL 0
extern long allocs_out, alloc_fail_in;
void *t_alloc(size_t n);
#define kmalloc_array(n, sz, g) t_alloc((n) * (sz))
#define kmemdup_array(src, n, sz, g) ({ void *p_ = t_alloc((n) * (sz)); if (p_) memcpy(p_, (src), (n) * (sz)); p_; })
int t_isspace(int c);
#define isspace(c) t_isspace(c)
char *skip_spaces(const char *s);
unsigned long simple_strtoul(const char *cp, char **endp, unsigned base);
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void *swap);
void *bsearch(const void *key, const void *base, size_t num, size_t size, int (*cmp)(const void *, const void *));
#endif
