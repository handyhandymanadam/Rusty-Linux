/* kernel shim for the scatterlist differential: just enough of the page, slab, kmap, bug/warn and scatterlist.h machinery for
 * lib/scatterlist.c (everything above extract_user_to_sg) and for scatterlist_glue.c. The scatterlist.h part is the real header's text for
 * the configuration under test (no CONFIG_DEBUG_SG); with -DNODMA the struct has no dma_length / dma_flags (16 bytes), without it 32. */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef unsigned int gfp_t;
typedef u64 dma_addr_t;
typedef u64 phys_addr_t;

#define EINVAL 22
#define ENOMEM 12
#define EOPNOTSUPP 95
#define EIO 5
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a) ALIGN((x) - ((a) - 1), (a))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define min_t(t, a, b) ({ t a_ = (a); t b_ = (b); a_ < b_ ? a_ : b_; })
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define IS_ENABLED(x) 0
#define static_assert _Static_assert
#define GFP_DMA 0x1u
#define GFP_KERNEL 0x400u
#define MAX_ERRNO 4095
#define ERR_PTR(e) ((void *)(long)(e))
#define PTR_ERR(p) ((long)(p))
#define IS_ERR(p) ((unsigned long)(p) >= (unsigned long)-MAX_ERRNO)

extern int warn_count;
#define WARN_ON(cond) ({ bool c_ = !!(cond); if (c_) warn_count++; c_; })
#define WARN_ON_ONCE(cond) ({ static bool once_; bool c_ = !!(cond); if (c_ && !once_) { once_ = true; warn_count++; } c_; })
#define WARN_ONCE(cond, ...) ({ static bool once_; bool c_ = !!(cond); if (c_ && !once_) { once_ = true; warn_count++; } c_; })
#define BUG_ON(cond) do { if (cond) { fprintf(stderr, "BUG at %s:%d\n", __FILE__, __LINE__); abort(); } } while (0)
#define VM_WARN_ON_ONCE(x) do { } while (0)
#include <stdio.h>

/* pages: a pool of struct page (64-byte aligned, as in the kernel) with a 4 KiB data page behind each */
struct page { unsigned long pfn; int pgmap; int pad; } __attribute__((aligned(64)));
#define NPAGES 1024
extern struct page g_pages[NPAGES];
extern unsigned char g_pagedata[NPAGES][4096];
static inline unsigned long page_to_pfn(struct page *p) { return p->pfn; }
static inline struct page *pfn_to_page(unsigned long pfn) { return &g_pages[pfn]; }
static inline phys_addr_t page_to_phys(struct page *p) { return (phys_addr_t)p->pfn << PAGE_SHIFT; }
static inline bool zone_device_pages_have_same_pgmap(struct page *a, struct page *b) { return a->pgmap == b->pgmap; }
static inline void *page_address(struct page *p) { return g_pagedata[p->pfn]; }
struct page *alloc_pages(gfp_t gfp, unsigned int order);
void __free_pages(struct page *page, unsigned int order);
void *kmalloc_array(size_t n, size_t size, gfp_t gfp);
void kfree(const void *p);
unsigned long __get_free_page(gfp_t gfp);
void free_page(unsigned long addr);
static inline void kmemleak_alloc(const void *p, size_t size, int min_count, gfp_t gfp) { }
static inline void kmemleak_free(const void *p) { }

/* kmap flavours: the mapping is the page's data; the atomic one disables page faults until unmapped */
extern int g_atomic_depth, g_flushes;
static inline void *kmap_atomic(struct page *p) { g_atomic_depth++; return page_address(p); }
static inline void kunmap_atomic(void *a) { g_atomic_depth--; }
static inline void *kmap_local_page(struct page *p) { return page_address(p); }
static inline void kunmap_local(void *a) { }
static inline void *kmap(struct page *p) { return page_address(p); }
static inline void kunmap(struct page *p) { }
static inline bool pagefault_disabled(void) { return g_atomic_depth > 0; }
static inline void flush_dcache_page(struct page *p) { g_flushes++; }

struct scatterlist {
	unsigned long	page_link;
	unsigned int	offset;
	unsigned int	length;
	dma_addr_t	dma_address;
#ifndef NODMA
	unsigned int	dma_length;
	unsigned int    dma_flags;
#endif
};
#ifndef NODMA
#define CONFIG_NEED_SG_DMA_LENGTH 1
#define CONFIG_NEED_SG_DMA_FLAGS 1
#define sg_dma_len(sg)		((sg)->dma_length)
#else
#define sg_dma_len(sg)		((sg)->length)
#endif
#define CONFIG_SGL_ALLOC 1

struct sg_table { struct scatterlist *sgl; unsigned int nents; unsigned int orig_nents; };
struct sg_append_table { struct sg_table sgt; struct scatterlist *prv; unsigned int total_nents; };
#define SG_CHAIN	0x01UL
#define SG_END		0x02UL
#define SG_PAGE_LINK_MASK (SG_CHAIN | SG_END)
static inline unsigned int __sg_flags(struct scatterlist *sg) { return sg->page_link & SG_PAGE_LINK_MASK; }
static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg) { return (struct scatterlist *)(sg->page_link & ~SG_PAGE_LINK_MASK); }
static inline bool sg_is_chain(struct scatterlist *sg) { return __sg_flags(sg) & SG_CHAIN; }
static inline bool sg_is_last(struct scatterlist *sg) { return __sg_flags(sg) & SG_END; }
static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
	if (sg_is_last(sg))
		return NULL;
	sg++;
	if (unlikely(sg_is_chain(sg)))
		sg = sg_chain_ptr(sg);
	return sg;
}
static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	unsigned long page_link = sg->page_link & (SG_CHAIN | SG_END);
	BUG_ON((unsigned long)page & SG_PAGE_LINK_MASK);
	sg->page_link = page_link | (unsigned long) page;
}
static inline void sg_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset)
{
	sg_assign_page(sg, page);
	sg->offset = offset;
	sg->length = len;
}
static inline struct page *sg_page(struct scatterlist *sg) { return (struct page *)((sg)->page_link & ~SG_PAGE_LINK_MASK); }
#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
static inline void __sg_chain(struct scatterlist *chain_sg, struct scatterlist *sgl)
{
	chain_sg->offset = 0;
	chain_sg->length = 0;
	chain_sg->page_link = ((unsigned long) sgl | SG_CHAIN) & ~SG_END;
}
static inline void sg_chain(struct scatterlist *prv, unsigned int prv_nents, struct scatterlist *sgl) { __sg_chain(&prv[prv_nents - 1], sgl); }
static inline void sg_mark_end(struct scatterlist *sg) { sg->page_link |= SG_END; sg->page_link &= ~SG_CHAIN; }
static inline dma_addr_t sg_phys(struct scatterlist *sg) { return page_to_phys(sg_page(sg)) + sg->offset; }
static inline void sg_init_marker(struct scatterlist *sgl, unsigned int nents) { sg_mark_end(&sgl[nents - 1]); }
static inline void sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen) { abort(); }
typedef struct scatterlist *(sg_alloc_fn)(unsigned int, gfp_t);
typedef void (sg_free_fn)(struct scatterlist *, unsigned int);
#define SG_MAX_SINGLE_ALLOC		(PAGE_SIZE / sizeof(struct scatterlist))

struct sg_page_iter {
	struct scatterlist	*sg;
	unsigned int		sg_pgoffset;
	unsigned int		__nents;
	int			__pg_advance;
};
struct sg_dma_page_iter { struct sg_page_iter base; };
static inline struct page *sg_page_iter_page(struct sg_page_iter *piter) { return sg_page(piter->sg) + piter->sg_pgoffset; }
#define SG_MITER_ATOMIC		(1 << 0)
#define SG_MITER_TO_SG		(1 << 1)
#define SG_MITER_FROM_SG	(1 << 2)
#define SG_MITER_LOCAL		(1 << 3)
struct sg_mapping_iter {
	struct page		*page;
	void			*addr;
	size_t			length;
	size_t			consumed;
	struct sg_page_iter	piter;
	unsigned int		__offset;
	unsigned int		__remaining;
	unsigned int		__flags;
};

int sg_nents(struct scatterlist *sg);
int sg_nents_for_len(struct scatterlist *sg, u64 len);
struct scatterlist *sg_last(struct scatterlist *s, unsigned int);
void sg_init_table(struct scatterlist *, unsigned int);
void sg_init_one(struct scatterlist *, const void *, unsigned int);
void __sg_free_table(struct sg_table *, unsigned int, unsigned int, sg_free_fn *, unsigned int);
void sg_free_table(struct sg_table *);
void sg_free_append_table(struct sg_append_table *sgt);
int __sg_alloc_table(struct sg_table *, unsigned int, unsigned int, struct scatterlist *, unsigned int, gfp_t, sg_alloc_fn *);
int sg_alloc_table(struct sg_table *, unsigned int, gfp_t);
int sg_alloc_append_table_from_pages(struct sg_append_table *sgt, struct page **pages, unsigned int n_pages, unsigned int offset,
				     unsigned long size, unsigned int max_segment, unsigned int left_pages, gfp_t gfp_mask);
int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pages, unsigned int n_pages, unsigned int offset,
				      unsigned long size, unsigned int max_segment, gfp_t gfp_mask);
struct scatterlist *sgl_alloc_order(unsigned long long length, unsigned int order, bool chainable, gfp_t gfp, unsigned int *nent_p);
struct scatterlist *sgl_alloc(unsigned long long length, gfp_t gfp, unsigned int *nent_p);
void sgl_free_n_order(struct scatterlist *sgl, int nents, int order);
void sgl_free_order(struct scatterlist *sgl, int order);
void sgl_free(struct scatterlist *sgl);
void __sg_page_iter_start(struct sg_page_iter *piter, struct scatterlist *sglist, unsigned int nents, unsigned long pgoffset);
bool __sg_page_iter_next(struct sg_page_iter *piter);
bool __sg_page_iter_dma_next(struct sg_dma_page_iter *dma_iter);
void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl, unsigned int nents, unsigned int flags);
bool sg_miter_skip(struct sg_mapping_iter *miter, off_t offset);
bool sg_miter_next(struct sg_mapping_iter *miter);
void sg_miter_stop(struct sg_mapping_iter *miter);
size_t sg_copy_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen, off_t skip, bool to_buffer);
size_t sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents, const void *buf, size_t buflen);
size_t sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen);
size_t sg_pcopy_from_buffer(struct scatterlist *sgl, unsigned int nents, const void *buf, size_t buflen, off_t skip);
size_t sg_pcopy_to_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen, off_t skip);
size_t sg_zero_buffer(struct scatterlist *sgl, unsigned int nents, size_t buflen, off_t skip);
#endif
