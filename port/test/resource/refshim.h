/* Stand-ins for what the pristine slice of kernel/resource.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long resource_size_t;
typedef unsigned long long u64;
#define EBUSY 16
#define EINVAL 22
#define ENODEV 19
#define IORESOURCE_TYPE_BITS 0x00001f00UL
#define IORESOURCE_SIZEALIGN 0x00040000UL
#define IORESOURCE_STARTALIGN 0x00080000UL
#define IORESOURCE_UNSET 0x20000000UL
#define IORES_DESC_NONE 0
enum { REGION_INTERSECTS, REGION_DISJOINT, REGION_MIXED };
struct resource { resource_size_t start, end; const char *name; unsigned long flags, desc; struct resource *parent, *sibling, *child; };
typedef resource_size_t (*resource_alignf)(void *data, const struct resource *res, resource_size_t size, resource_size_t align);
struct resource_constraint { resource_size_t min, max, align; resource_alignf alignf; void *alignf_data; };
extern struct resource iomem_resource;
extern int warns, bugs, dbg_released, remove_calls;
#define resource_lock 0
#define read_lock(x) ((void)0)
#define read_unlock(x) ((void)0)
#define write_lock(x) ((void)0)
#define write_unlock(x) ((void)0)
#define max(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ > b_ ? a_ : b_; })
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define ALIGN(x, a) ((((x) + ((__typeof__(x))(a) - 1))) & ~((__typeof__(x))(a) - 1))
#define WARN_ON(c) ({ int w_ = !!(c); if (w_) warns++; w_; })
#define BUG_ON(c) do { if (c) bugs++; } while (0)
#define printk(...) (dbg_released++)
#define KERN_DEBUG ""
static inline resource_size_t resource_size(const struct resource *r) { return r->end - r->start + 1; }
static inline unsigned long resource_type(const struct resource *r) { return r->flags & IORESOURCE_TYPE_BITS; }
static inline bool resource_contains(const struct resource *r1, const struct resource *r2)
{
	if (resource_type(r1) != resource_type(r2)) return false;
	if (r1->flags & IORESOURCE_UNSET || r2->flags & IORESOURCE_UNSET) return false;
	return r1->start <= r2->start && r1->end >= r2->end;
}
static inline bool resource_overlaps(const struct resource *r1, const struct resource *r2) { return r1->start <= r2->end && r1->end >= r2->start; }
static inline bool resource_intersection(const struct resource *r1, const struct resource *r2, struct resource *r)
{
	if (!resource_overlaps(r1, r2)) return false;
	r->start = max(r1->start, r2->start); r->end = min(r1->end, r2->end); return true;
}
#define DEFINE_RES(_start, _size, _flags) ((struct resource){ .start = (_start), .end = (_start) + (_size) - 1, .flags = (_flags), .desc = IORES_DESC_NONE })
void arch_remove_reservations(struct resource *avail);
#endif
