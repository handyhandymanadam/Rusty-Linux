/* Stand-ins for what the pristine security/selinux/ss/ebitmap.c, ebitmap.h and the ebitmap_glue.c wrappers use. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef u32 __le32; typedef u64 __le64;
#define CONFIG_64BIT 1
#define BITS_PER_LONG 64
#define EINVAL 22
#define ENOMEM 12
#define U32_MAX ((u32)~0U)
#define fallthrough __attribute__((fallthrough))
#define __init
#define __ro_after_init
#define __noreturn __attribute__((noreturn))
#define unlikely(x) __builtin_expect(!!(x), 0)
#define static_assert(x) _Static_assert(x, #x)
#define check_mul_overflow(a, b, d) __builtin_mul_overflow(a, b, d)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define BITS_PER_U64_UNUSED 0
static inline u32 rol32(u32 w, unsigned s) { return (w << (s & 31)) | (w >> ((32 - s) & 31)); }
static inline unsigned long __fls(unsigned long w) { return 63 - __builtin_clzl(w); }
/* find_first_bit / find_next_bit: deliberately the slow bit-by-bit definition. */
static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	unsigned long i;
	for (i = offset; i < size; i++)
		if (addr[i / 64] >> (i % 64) & 1) return i;
	return size;
}
#define find_first_bit(addr, size) find_next_bit(addr, size, 0)
#define rounddown(x, y) ({ typeof(x) __x = (x); __x - (__x % (y)); })
#define roundup(x, y) ({ typeof(y) __y = y; (((x) + (__y - 1)) / __y) * __y; })
#define BUG() do { printf("BUG\n"); fflush(stdout); exit(3); } while (0)
#define BUG_ON(c) do { if (c) BUG(); } while (0)
#define pr_err(...) printf(__VA_ARGS__)
#define GFP_ATOMIC 1
#define GFP_KERNEL 2
struct kmem_cache { int x; };
typedef int gfp_t;
extern struct kmem_cache *ebitmap_node_cachep;
extern long fail_in, live_nodes, allocs; extern unsigned long gfp_log;
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t g)
{
	void *p;
	allocs++; gfp_log = gfp_log * 31 + g;
	if (fail_in > 0 && --fail_in == 0) return NULL;
	p = calloc(1, 64); live_nodes++; return p;
}
static inline void kmem_cache_free(struct kmem_cache *c, void *p) { live_nodes--; free(p); }
struct policy_file { char *data; size_t len; };
static inline int next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
	if (bytes > fp->len) return -EINVAL;
	memcpy(buf, fp->data, bytes); fp->data += bytes; fp->len -= bytes; return 0;
}
static inline int put_entry(const void *buf, size_t bytes, size_t num, struct policy_file *fp)
{
	size_t len;
	if (unlikely(check_mul_overflow(bytes, num, &len))) return -EINVAL;
	if (len > fp->len) return -EINVAL;
	memcpy(fp->data, buf, len); fp->data += len; fp->len -= len; return 0;
}
#endif
