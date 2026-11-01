// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007 Jens Axboe <jens.axboe@oracle.com>
 *
 * Scatterlist handling helpers.
 */
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/kmemleak.h>
#include <linux/bvec.h>
#include <linux/uio.h>
#include <linux/folio_queue.h>
#include <linux/stddef.h>

/*
 * RUST PORT (lib/scatterlist.c, 6.18.49): the algorithms -- sg_nents*, sg_last, sg_init_table, __sg_free_table, __sg_alloc_table,
 * get_next_sg, sg_alloc_append_table_from_pages, sgl_alloc_order, sgl_free_n_order, the page iterators, the mapping iterator and
 * sg_copy_buffer/sg_zero_buffer -- are in scatterlist_rs.rs. This file keeps every exported entry point (its MODVERSIONS
 * fingerprint comes from the DWARF of the definition) as a thunk, the functions that only call other exports or the allocators
 * (sg_init_one, sg_alloc_table, sg_free_table, sg_free_append_table, sg_alloc_table_from_pages_segment, the sg_copy_ and sg_pcopy_ families
 * wrappers), and one-line wrappers (rust_sgw_*) for every header inline or macro whose body depends on the configuration
 * (CONFIG_DEBUG_SG, CONFIG_NEED_SG_DMA_*, CONFIG_ARCH_NO_SG_CHAIN, kmap flavours, VM_WARN, BUG_ON/WARN_ON sites). A warning or a
 * BUG raised from a wrapper names this file, not scatterlist.c (recorded divergence). extract_iter_to_sg() is upstream C, in
 * scatterlist_extract.c. Upstream's whole file is installed as scatterlist_norust.c for CONFIG_RUST=n.
 */
static_assert(PAGE_SHIFT == 12);
static_assert(sizeof(gfp_t) == 4 && sizeof(off_t) == 8 && sizeof(dma_addr_t) == 8);
static_assert(offsetof(struct scatterlist, page_link) == 0 && offsetof(struct scatterlist, offset) == 8 &&
	      offsetof(struct scatterlist, length) == 12);
static_assert(sizeof(struct sg_table) == 16 && offsetof(struct sg_table, sgl) == 0 && offsetof(struct sg_table, nents) == 8 &&
	      offsetof(struct sg_table, orig_nents) == 12);
static_assert(sizeof(struct sg_append_table) == 32 && offsetof(struct sg_append_table, sgt) == 0 &&
	      offsetof(struct sg_append_table, prv) == 16 && offsetof(struct sg_append_table, total_nents) == 24);
static_assert(sizeof(struct sg_page_iter) == 24 && offsetof(struct sg_page_iter, sg) == 0 &&
	      offsetof(struct sg_page_iter, sg_pgoffset) == 8 && offsetof(struct sg_page_iter, __nents) == 12 &&
	      offsetof(struct sg_page_iter, __pg_advance) == 16);
static_assert(sizeof(struct sg_dma_page_iter) == 24 && offsetof(struct sg_dma_page_iter, base) == 0);
static_assert(sizeof(struct sg_mapping_iter) == 72 && offsetof(struct sg_mapping_iter, page) == 0 &&
	      offsetof(struct sg_mapping_iter, addr) == 8 && offsetof(struct sg_mapping_iter, length) == 16 &&
	      offsetof(struct sg_mapping_iter, consumed) == 24 && offsetof(struct sg_mapping_iter, piter) == 32 &&
	      offsetof(struct sg_mapping_iter, __offset) == 56 && offsetof(struct sg_mapping_iter, __remaining) == 60 &&
	      offsetof(struct sg_mapping_iter, __flags) == 64);
static_assert(SG_MITER_ATOMIC == 1 && SG_MITER_TO_SG == 2 && SG_MITER_FROM_SG == 4 && SG_MITER_LOCAL == 8);

/* the Rust side (scatterlist_rs.rs) */
int rust_scatterlist_nents(struct scatterlist *sg);
int rust_scatterlist_nents_for_len(struct scatterlist *sg, u64 len);
struct scatterlist *rust_scatterlist_last(struct scatterlist *sgl, unsigned int nents);
void rust_scatterlist_init_table(struct scatterlist *sgl, unsigned int nents);
void rust_scatterlist_free_table(struct sg_table *table, unsigned int max_ents, unsigned int nents_first_chunk,
				 sg_free_fn *free_fn, unsigned int num_ents);
int rust_scatterlist_alloc_table(struct sg_table *table, unsigned int nents, unsigned int max_ents,
				 struct scatterlist *first_chunk, unsigned int nents_first_chunk, gfp_t gfp_mask,
				 sg_alloc_fn *alloc_fn);
int rust_scatterlist_alloc_append(struct sg_append_table *sgt_append, struct page **pages, unsigned int n_pages,
				  unsigned int offset, unsigned long size, unsigned int max_segment, unsigned int left_pages,
				  gfp_t gfp_mask);
struct scatterlist *rust_scatterlist_sgl_alloc_order(unsigned long long length, unsigned int order, bool chainable,
						     gfp_t gfp, unsigned int *nent_p);
void rust_scatterlist_sgl_free_n_order(struct scatterlist *sgl, int nents, int order);
void rust_scatterlist_page_iter_start(struct sg_page_iter *piter, struct scatterlist *sglist, unsigned int nents,
				      unsigned long pgoffset);
bool rust_scatterlist_page_iter_next(struct sg_page_iter *piter);
bool rust_scatterlist_page_iter_dma_next(struct sg_dma_page_iter *dma_iter);
void rust_scatterlist_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl, unsigned int nents,
				  unsigned int flags);
bool rust_scatterlist_miter_skip(struct sg_mapping_iter *miter, off_t offset);
bool rust_scatterlist_miter_next(struct sg_mapping_iter *miter);
void rust_scatterlist_miter_stop(struct sg_mapping_iter *miter);
size_t rust_scatterlist_copy_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen, off_t skip,
				    bool to_buffer);
size_t rust_scatterlist_zero_buffer(struct scatterlist *sgl, unsigned int nents, size_t buflen, off_t skip);

/* the C side the Rust calls */
size_t rust_sgw_size(void);
size_t rust_sgw_max_single_alloc(void);
struct scatterlist *rust_sgw_next(struct scatterlist *sg);
bool rust_sgw_is_last(struct scatterlist *sg);
void rust_sgw_init_marker(struct scatterlist *sgl, unsigned int nents);
void rust_sgw_mark_end(struct scatterlist *sg);
struct scatterlist *rust_sgw_chain_ptr(struct scatterlist *sg);
void rust_sgw_chain(struct scatterlist *prv, unsigned int prv_nents, struct scatterlist *sgl);
void rust_sgw___chain(struct scatterlist *chain_sg, struct scatterlist *sgl);
void rust_sgw_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset);
struct page *rust_sgw_page(struct scatterlist *sg);
u64 rust_sgw_phys(struct scatterlist *sg);
unsigned int rust_sgw_dma_len(struct scatterlist *sg);
unsigned long rust_sgw_page_to_pfn(struct page *page);
struct page *rust_sgw_pfn_to_page(unsigned long pfn);
bool rust_sgw_pages_mergeable(struct page *a, struct page *b);
struct page *rust_sgw_iter_page(struct sg_page_iter *piter);
struct scatterlist *rust_sgw_kmalloc(unsigned int nents, gfp_t gfp);
struct scatterlist *rust_sgw_kmalloc_array_nodma(unsigned int n, gfp_t gfp);
void rust_sgw_kfree(void *p);
struct page *rust_sgw_alloc_pages(gfp_t gfp, unsigned int order);
void rust_sgw_free_pages(struct page *page, unsigned int order);
void *rust_sgw_kmap(struct page *page, unsigned int flags);
void rust_sgw_kunmap(void *addr, struct page *page, unsigned int flags);
void rust_sgw_flush_dcache_page(struct page *page);
bool rust_sgw_no_chain(void);
bool rust_sgw_nents_gt_max(bool cond);
void rust_sgw_bug_not_last(struct scatterlist *sg);
void rust_sgw_warn_max_segment(bool cond);
void rust_sgw_warn_offset(bool cond);
void rust_sgw_warn_miter_flags(bool cond);
void rust_sgw_warn_consumed(bool cond);
void rust_sgw_warn_once_length(unsigned long long length);
void rust_sgw_sgl_free_order(struct scatterlist *sgl, int order);

/**
 * sg_nents - return total count of entries in scatterlist
 * @sg:		The scatterlist
 *
 * Description:
 * Allows to know how many entries are in sg, taking into account
 * chaining as well
 *
 **/
int sg_nents(struct scatterlist *sg)
{
	return rust_scatterlist_nents(sg);
}
EXPORT_SYMBOL(sg_nents);

/**
 * sg_nents_for_len - return total count of entries in scatterlist
 *                    needed to satisfy the supplied length
 * @sg:		The scatterlist
 * @len:	The total required length
 *
 * Description:
 * Determines the number of entries in sg that are required to meet
 * the supplied length, taking into account chaining as well
 *
 * Returns:
 *   the number of sg entries needed, negative error on failure
 *
 **/
int sg_nents_for_len(struct scatterlist *sg, u64 len)
{
	return rust_scatterlist_nents_for_len(sg, len);
}
EXPORT_SYMBOL(sg_nents_for_len);

/**
 * sg_last - return the last scatterlist entry in a list
 * @sgl:	First entry in the scatterlist
 * @nents:	Number of entries in the scatterlist
 *
 * Description:
 *   Should only be used casually, it (currently) scans the entire list
 *   to get the last entry.
 *
 *   Note that the @sgl pointer passed in need not be the first one,
 *   the important bit is that @nents denotes the number of entries that
 *   exist from @sgl.
 *
 **/
struct scatterlist *sg_last(struct scatterlist *sgl, unsigned int nents)
{
	return rust_scatterlist_last(sgl, nents);
}
EXPORT_SYMBOL(sg_last);

/**
 * sg_init_table - Initialize SG table
 * @sgl:	   The SG table
 * @nents:	   Number of entries in table
 *
 * Notes:
 *   If this is part of a chained sg table, sg_mark_end() should be
 *   used only on the last table part.
 *
 **/
void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	rust_scatterlist_init_table(sgl, nents);
}
EXPORT_SYMBOL(sg_init_table);

/**
 * sg_init_one - Initialize a single entry sg list
 * @sg:		 SG entry
 * @buf:	 Virtual address for IO
 * @buflen:	 IO length
 *
 **/
void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
	sg_init_table(sg, 1);
	sg_set_buf(sg, buf, buflen);
}
EXPORT_SYMBOL(sg_init_one);

/*
 * The default behaviour of sg_alloc_table() is to use these kmalloc/kfree
 * helpers.
 */
static struct scatterlist *sg_kmalloc(unsigned int nents, gfp_t gfp_mask)
{
	if (nents == SG_MAX_SINGLE_ALLOC) {
		/*
		 * Kmemleak doesn't track page allocations as they are not
		 * commonly used (in a raw form) for kernel data structures.
		 * As we chain together a list of pages and then a normal
		 * kmalloc (tracked by kmemleak), in order to for that last
		 * allocation not to become decoupled (and thus a
		 * false-positive) we need to inform kmemleak of all the
		 * intermediate allocations.
		 */
		void *ptr = (void *) __get_free_page(gfp_mask);
		kmemleak_alloc(ptr, PAGE_SIZE, 1, gfp_mask);
		return ptr;
	} else
		return kmalloc_array(nents, sizeof(struct scatterlist),
				     gfp_mask);
}

static void sg_kfree(struct scatterlist *sg, unsigned int nents)
{
	if (nents == SG_MAX_SINGLE_ALLOC) {
		kmemleak_free(sg);
		free_page((unsigned long) sg);
	} else
		kfree(sg);
}

/**
 * __sg_free_table - Free a previously mapped sg table
 * @table:	The sg table header to use
 * @max_ents:	The maximum number of entries per single scatterlist
 * @nents_first_chunk: Number of entries int the (preallocated) first
 * 	scatterlist chunk, 0 means no such preallocated first chunk
 * @free_fn:	Free function
 * @num_ents:	Number of entries in the table
 *
 *  Description:
 *    Free an sg table previously allocated and setup with
 *    __sg_alloc_table().  The @max_ents value must be identical to
 *    that previously used with __sg_alloc_table().
 *
 **/
void __sg_free_table(struct sg_table *table, unsigned int max_ents,
		     unsigned int nents_first_chunk, sg_free_fn *free_fn,
		     unsigned int num_ents)
{
	rust_scatterlist_free_table(table, max_ents, nents_first_chunk, free_fn, num_ents);
}
EXPORT_SYMBOL(__sg_free_table);

/**
 * sg_free_append_table - Free a previously allocated append sg table.
 * @table:	 The mapped sg append table header
 *
 **/
void sg_free_append_table(struct sg_append_table *table)
{
	__sg_free_table(&table->sgt, SG_MAX_SINGLE_ALLOC, 0, sg_kfree,
			table->total_nents);
}
EXPORT_SYMBOL(sg_free_append_table);


/**
 * sg_free_table - Free a previously allocated sg table
 * @table:	The mapped sg table header
 *
 **/
void sg_free_table(struct sg_table *table)
{
	__sg_free_table(table, SG_MAX_SINGLE_ALLOC, 0, sg_kfree,
			table->orig_nents);
}
EXPORT_SYMBOL(sg_free_table);

/**
 * __sg_alloc_table - Allocate and initialize an sg table with given allocator
 * @table:	The sg table header to use
 * @nents:	Number of entries in sg list
 * @max_ents:	The maximum number of entries the allocator returns per call
 * @first_chunk: first SGL if preallocated (may be %NULL)
 * @nents_first_chunk: Number of entries in the (preallocated) first
 * 	scatterlist chunk, 0 means no such preallocated chunk provided by user
 * @gfp_mask:	GFP allocation mask
 * @alloc_fn:	Allocator to use
 *
 * Description:
 *   This function returns a @table @nents long. The allocator is
 *   defined to return scatterlist chunks of maximum size @max_ents.
 *   Thus if @nents is bigger than @max_ents, the scatterlists will be
 *   chained in units of @max_ents.
 *
 * Notes:
 *   If this function returns non-0 (eg failure), the caller must call
 *   __sg_free_table() to cleanup any leftover allocations.
 *
 **/
int __sg_alloc_table(struct sg_table *table, unsigned int nents,
		     unsigned int max_ents, struct scatterlist *first_chunk,
		     unsigned int nents_first_chunk, gfp_t gfp_mask,
		     sg_alloc_fn *alloc_fn)
{
	return rust_scatterlist_alloc_table(table, nents, max_ents, first_chunk, nents_first_chunk, gfp_mask, alloc_fn);
}
EXPORT_SYMBOL(__sg_alloc_table);

/**
 * sg_alloc_table - Allocate and initialize an sg table
 * @table:	The sg table header to use
 * @nents:	Number of entries in sg list
 * @gfp_mask:	GFP allocation mask
 *
 *  Description:
 *    Allocate and initialize an sg table. If @nents is larger than
 *    SG_MAX_SINGLE_ALLOC a chained sg table will be setup.
 *
 **/
int sg_alloc_table(struct sg_table *table, unsigned int nents, gfp_t gfp_mask)
{
	int ret;

	ret = __sg_alloc_table(table, nents, SG_MAX_SINGLE_ALLOC,
			       NULL, 0, gfp_mask, sg_kmalloc);
	if (unlikely(ret))
		sg_free_table(table);
	return ret;
}
EXPORT_SYMBOL(sg_alloc_table);

static bool pages_are_mergeable(struct page *a, struct page *b)
{
	if (page_to_pfn(a) != page_to_pfn(b) + 1)
		return false;
	if (!zone_device_pages_have_same_pgmap(a, b))
		return false;
	return true;
}

/**
 * sg_alloc_append_table_from_pages - Allocate and initialize an append sg
 *                                    table from an array of pages
 * @sgt_append:  The sg append table to use
 * @pages:       Pointer to an array of page pointers
 * @n_pages:     Number of pages in the pages array
 * @offset:      Offset from start of the first page to the start of a buffer
 * @size:        Number of valid bytes in the buffer (after offset)
 * @max_segment: Maximum size of a scatterlist element in bytes
 * @left_pages:  Left pages caller have to set after this call
 * @gfp_mask:	 GFP allocation mask
 *
 * Description:
 *    In the first call it allocate and initialize an sg table from a list of
 *    pages, else reuse the scatterlist from sgt_append. Contiguous ranges of
 *    the pages are squashed into a single scatterlist entry up to the maximum
 *    size specified in @max_segment.  A user may provide an offset at a start
 *    and a size of valid data in a buffer specified by the page array. The
 *    returned sg table is released by sg_free_append_table
 *
 * Returns:
 *   0 on success, negative error on failure
 *
 * Notes:
 *   If this function returns non-0 (eg failure), the caller must call
 *   sg_free_append_table() to cleanup any leftover allocations.
 *
 *   In the fist call, sgt_append must by initialized.
 */
int sg_alloc_append_table_from_pages(struct sg_append_table *sgt_append,
		struct page **pages, unsigned int n_pages, unsigned int offset,
		unsigned long size, unsigned int max_segment,
		unsigned int left_pages, gfp_t gfp_mask)
{
	return rust_scatterlist_alloc_append(sgt_append, pages, n_pages, offset, size, max_segment, left_pages, gfp_mask);
}
EXPORT_SYMBOL(sg_alloc_append_table_from_pages);

/**
 * sg_alloc_table_from_pages_segment - Allocate and initialize an sg table from
 *                                     an array of pages and given maximum
 *                                     segment.
 * @sgt:	 The sg table header to use
 * @pages:	 Pointer to an array of page pointers
 * @n_pages:	 Number of pages in the pages array
 * @offset:      Offset from start of the first page to the start of a buffer
 * @size:        Number of valid bytes in the buffer (after offset)
 * @max_segment: Maximum size of a scatterlist element in bytes
 * @gfp_mask:	 GFP allocation mask
 *
 *  Description:
 *    Allocate and initialize an sg table from a list of pages. Contiguous
 *    ranges of the pages are squashed into a single scatterlist node up to the
 *    maximum size specified in @max_segment. A user may provide an offset at a
 *    start and a size of valid data in a buffer specified by the page array.
 *
 *    The returned sg table is released by sg_free_table.
 *
 *  Returns:
 *   0 on success, negative error on failure
 */
int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pages,
				unsigned int n_pages, unsigned int offset,
				unsigned long size, unsigned int max_segment,
				gfp_t gfp_mask)
{
	struct sg_append_table append = {};
	int err;

	err = sg_alloc_append_table_from_pages(&append, pages, n_pages, offset,
					       size, max_segment, 0, gfp_mask);
	if (err) {
		sg_free_append_table(&append);
		return err;
	}
	memcpy(sgt, &append.sgt, sizeof(*sgt));
	WARN_ON(append.total_nents != sgt->orig_nents);
	return 0;
}
EXPORT_SYMBOL(sg_alloc_table_from_pages_segment);

#ifdef CONFIG_SGL_ALLOC

/**
 * sgl_alloc_order - allocate a scatterlist and its pages
 * @length: Length in bytes of the scatterlist. Must be at least one
 * @order: Second argument for alloc_pages()
 * @chainable: Whether or not to allocate an extra element in the scatterlist
 *	for scatterlist chaining purposes
 * @gfp: Memory allocation flags
 * @nent_p: [out] Number of entries in the scatterlist that have pages
 *
 * Returns: A pointer to an initialized scatterlist or %NULL upon failure.
 */
struct scatterlist *sgl_alloc_order(unsigned long long length,
				    unsigned int order, bool chainable,
				    gfp_t gfp, unsigned int *nent_p)
{
	return rust_scatterlist_sgl_alloc_order(length, order, chainable, gfp, nent_p);
}
EXPORT_SYMBOL(sgl_alloc_order);

/**
 * sgl_alloc - allocate a scatterlist and its pages
 * @length: Length in bytes of the scatterlist
 * @gfp: Memory allocation flags
 * @nent_p: [out] Number of entries in the scatterlist
 *
 * Returns: A pointer to an initialized scatterlist or %NULL upon failure.
 */
struct scatterlist *sgl_alloc(unsigned long long length, gfp_t gfp,
			      unsigned int *nent_p)
{
	return sgl_alloc_order(length, 0, false, gfp, nent_p);
}
EXPORT_SYMBOL(sgl_alloc);

/**
 * sgl_free_n_order - free a scatterlist and its pages
 * @sgl: Scatterlist with one or more elements
 * @nents: Maximum number of elements to free
 * @order: Second argument for __free_pages()
 *
 * Notes:
 * - If several scatterlists have been chained and each chain element is
 *   freed separately then it's essential to set nents correctly to avoid that a
 *   page would get freed twice.
 * - All pages in a chained scatterlist can be freed at once by setting @nents
 *   to a high number.
 */
void sgl_free_n_order(struct scatterlist *sgl, int nents, int order)
{
	rust_scatterlist_sgl_free_n_order(sgl, nents, order);
}
EXPORT_SYMBOL(sgl_free_n_order);

/**
 * sgl_free_order - free a scatterlist and its pages
 * @sgl: Scatterlist with one or more elements
 * @order: Second argument for __free_pages()
 */
void sgl_free_order(struct scatterlist *sgl, int order)
{
	sgl_free_n_order(sgl, INT_MAX, order);
}
EXPORT_SYMBOL(sgl_free_order);

/**
 * sgl_free - free a scatterlist and its pages
 * @sgl: Scatterlist with one or more elements
 */
void sgl_free(struct scatterlist *sgl)
{
	sgl_free_order(sgl, 0);
}
EXPORT_SYMBOL(sgl_free);

#endif /* CONFIG_SGL_ALLOC */

void __sg_page_iter_start(struct sg_page_iter *piter,
			  struct scatterlist *sglist, unsigned int nents,
			  unsigned long pgoffset)
{
	rust_scatterlist_page_iter_start(piter, sglist, nents, pgoffset);
}
EXPORT_SYMBOL(__sg_page_iter_start);

bool __sg_page_iter_next(struct sg_page_iter *piter)
{
	return rust_scatterlist_page_iter_next(piter);
}
EXPORT_SYMBOL(__sg_page_iter_next);

bool __sg_page_iter_dma_next(struct sg_dma_page_iter *dma_iter)
{
	return rust_scatterlist_page_iter_dma_next(dma_iter);
}
EXPORT_SYMBOL(__sg_page_iter_dma_next);

/**
 * sg_miter_start - start mapping iteration over a sg list
 * @miter: sg mapping iter to be started
 * @sgl: sg list to iterate over
 * @nents: number of sg entries
 * @flags: sg iterator flags
 *
 * Description:
 *   Starts mapping iterator @miter.
 *
 * Context:
 *   Don't care.
 */
void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl,
		    unsigned int nents, unsigned int flags)
{
	rust_scatterlist_miter_start(miter, sgl, nents, flags);
}
EXPORT_SYMBOL(sg_miter_start);

/**
 * sg_miter_skip - reposition mapping iterator
 * @miter: sg mapping iter to be skipped
 * @offset: number of bytes to plus the current location
 *
 * Description:
 *   Sets the offset of @miter to its current location plus @offset bytes.
 *   If mapping iterator @miter has been proceeded by sg_miter_next(), this
 *   stops @miter.
 *
 * Context:
 *   Don't care.
 *
 * Returns:
 *   true if @miter contains the valid mapping.  false if end of sg
 *   list is reached.
 */
bool sg_miter_skip(struct sg_mapping_iter *miter, off_t offset)
{
	return rust_scatterlist_miter_skip(miter, offset);
}
EXPORT_SYMBOL(sg_miter_skip);

/**
 * sg_miter_next - proceed mapping iterator to the next mapping
 * @miter: sg mapping iter to proceed
 *
 * Description:
 *   Proceeds @miter to the next mapping.  @miter should have been started
 *   using sg_miter_start().  On successful return, @miter->page,
 *   @miter->addr and @miter->length point to the current mapping.
 *
 * Context:
 *   May sleep if !SG_MITER_ATOMIC && !SG_MITER_LOCAL.
 *
 * Returns:
 *   true if @miter contains the next mapping.  false if end of sg
 *   list is reached.
 */
bool sg_miter_next(struct sg_mapping_iter *miter)
{
	return rust_scatterlist_miter_next(miter);
}
EXPORT_SYMBOL(sg_miter_next);

/**
 * sg_miter_stop - stop mapping iteration
 * @miter: sg mapping iter to be stopped
 *
 * Description:
 *   Stops mapping iterator @miter.  @miter should have been started
 *   using sg_miter_start().  A stopped iteration can be resumed by
 *   calling sg_miter_next() on it.  This is useful when resources (kmap)
 *   need to be released during iteration.
 *
 * Context:
 *   Don't care otherwise.
 */
void sg_miter_stop(struct sg_mapping_iter *miter)
{
	rust_scatterlist_miter_stop(miter);
}
EXPORT_SYMBOL(sg_miter_stop);

/**
 * sg_copy_buffer - Copy data between a linear buffer and an SG list
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy from
 * @buflen:		 The number of bytes to copy
 * @skip:		 Number of bytes to skip before copying
 * @to_buffer:		 transfer direction (true == from an sg list to a
 *			 buffer, false == from a buffer to an sg list)
 *
 * Returns the number of copied bytes.
 *
 **/
size_t sg_copy_buffer(struct scatterlist *sgl, unsigned int nents, void *buf,
		      size_t buflen, off_t skip, bool to_buffer)
{
	return rust_scatterlist_copy_buffer(sgl, nents, buf, buflen, skip, to_buffer);
}
EXPORT_SYMBOL(sg_copy_buffer);

/**
 * sg_copy_from_buffer - Copy from a linear buffer to an SG list
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy from
 * @buflen:		 The number of bytes to copy
 *
 * Returns the number of copied bytes.
 *
 **/
size_t sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents,
			   const void *buf, size_t buflen)
{
	return sg_copy_buffer(sgl, nents, (void *)buf, buflen, 0, false);
}
EXPORT_SYMBOL(sg_copy_from_buffer);

/**
 * sg_copy_to_buffer - Copy from an SG list to a linear buffer
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy to
 * @buflen:		 The number of bytes to copy
 *
 * Returns the number of copied bytes.
 *
 **/
size_t sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents,
			 void *buf, size_t buflen)
{
	return sg_copy_buffer(sgl, nents, buf, buflen, 0, true);
}
EXPORT_SYMBOL(sg_copy_to_buffer);

/**
 * sg_pcopy_from_buffer - Copy from a linear buffer to an SG list
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy from
 * @buflen:		 The number of bytes to copy
 * @skip:		 Number of bytes to skip before copying
 *
 * Returns the number of copied bytes.
 *
 **/
size_t sg_pcopy_from_buffer(struct scatterlist *sgl, unsigned int nents,
			    const void *buf, size_t buflen, off_t skip)
{
	return sg_copy_buffer(sgl, nents, (void *)buf, buflen, skip, false);
}
EXPORT_SYMBOL(sg_pcopy_from_buffer);

/**
 * sg_pcopy_to_buffer - Copy from an SG list to a linear buffer
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy to
 * @buflen:		 The number of bytes to copy
 * @skip:		 Number of bytes to skip before copying
 *
 * Returns the number of copied bytes.
 *
 **/
size_t sg_pcopy_to_buffer(struct scatterlist *sgl, unsigned int nents,
			  void *buf, size_t buflen, off_t skip)
{
	return sg_copy_buffer(sgl, nents, buf, buflen, skip, true);
}
EXPORT_SYMBOL(sg_pcopy_to_buffer);

/**
 * sg_zero_buffer - Zero-out a part of a SG list
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buflen:		 The number of bytes to zero out
 * @skip:		 Number of bytes to skip before zeroing
 *
 * Returns the number of bytes zeroed.
 **/
size_t sg_zero_buffer(struct scatterlist *sgl, unsigned int nents,
		       size_t buflen, off_t skip)
{
	return rust_scatterlist_zero_buffer(sgl, nents, buflen, skip);
}
EXPORT_SYMBOL(sg_zero_buffer);

/* ---- wrappers for the Rust side: each is one header inline or macro, so the configuration-dependent body stays the C one ---- */
size_t rust_sgw_size(void) { return sizeof(struct scatterlist); }
size_t rust_sgw_max_single_alloc(void) { return SG_MAX_SINGLE_ALLOC; }
struct scatterlist *rust_sgw_next(struct scatterlist *sg) { return sg_next(sg); }
bool rust_sgw_is_last(struct scatterlist *sg) { return sg_is_last(sg); }
void rust_sgw_init_marker(struct scatterlist *sgl, unsigned int nents) { sg_init_marker(sgl, nents); }
void rust_sgw_mark_end(struct scatterlist *sg) { sg_mark_end(sg); }
struct scatterlist *rust_sgw_chain_ptr(struct scatterlist *sg) { return sg_chain_ptr(sg); }
void rust_sgw_chain(struct scatterlist *prv, unsigned int prv_nents, struct scatterlist *sgl) { sg_chain(prv, prv_nents, sgl); }
void rust_sgw___chain(struct scatterlist *chain_sg, struct scatterlist *sgl) { __sg_chain(chain_sg, sgl); }
void rust_sgw_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset)
{
	sg_set_page(sg, page, len, offset);
}
struct page *rust_sgw_page(struct scatterlist *sg) { return sg_page(sg); }
u64 rust_sgw_phys(struct scatterlist *sg) { return sg_phys(sg); }
unsigned int rust_sgw_dma_len(struct scatterlist *sg) { return sg_dma_len(sg); }
unsigned long rust_sgw_page_to_pfn(struct page *page) { return page_to_pfn(page); }
struct page *rust_sgw_pfn_to_page(unsigned long pfn) { return pfn_to_page(pfn); }
bool rust_sgw_pages_mergeable(struct page *a, struct page *b) { return pages_are_mergeable(a, b); }
struct page *rust_sgw_iter_page(struct sg_page_iter *piter) { return sg_page_iter_page(piter); }
struct scatterlist *rust_sgw_kmalloc(unsigned int nents, gfp_t gfp) { return sg_kmalloc(nents, gfp); }
struct scatterlist *rust_sgw_kmalloc_array_nodma(unsigned int n, gfp_t gfp)
{
	return kmalloc_array(n, sizeof(struct scatterlist), gfp & ~GFP_DMA);
}
void rust_sgw_kfree(void *p) { kfree(p); }
struct page *rust_sgw_alloc_pages(gfp_t gfp, unsigned int order) { return alloc_pages(gfp, order); }
void rust_sgw_free_pages(struct page *page, unsigned int order) { __free_pages(page, order); }
void *rust_sgw_kmap(struct page *page, unsigned int flags)
{
	if (flags & SG_MITER_ATOMIC)
		return kmap_atomic(page);
	else if (flags & SG_MITER_LOCAL)
		return kmap_local_page(page);
	else
		return kmap(page);
}
void rust_sgw_kunmap(void *addr, struct page *page, unsigned int flags)
{
	if (flags & SG_MITER_ATOMIC) {
		WARN_ON_ONCE(!pagefault_disabled());
		kunmap_atomic(addr);
	} else if (flags & SG_MITER_LOCAL)
		kunmap_local(addr);
	else
		kunmap(page);
}
void rust_sgw_flush_dcache_page(struct page *page) { flush_dcache_page(page); }
bool rust_sgw_no_chain(void) { return IS_ENABLED(CONFIG_ARCH_NO_SG_CHAIN); }
/* upstream checks nents > max_ents only under CONFIG_ARCH_NO_SG_CHAIN (WARN_ON_ONCE) */
bool rust_sgw_nents_gt_max(bool cond)
{
#ifdef CONFIG_ARCH_NO_SG_CHAIN
	if (WARN_ON_ONCE(cond))
		return true;
#endif
	return false;
}
void rust_sgw_bug_not_last(struct scatterlist *sg) { BUG_ON(!sg_is_last(sg)); }
void rust_sgw_warn_max_segment(bool cond) { WARN_ON(cond); }
void rust_sgw_warn_offset(bool cond) { WARN_ON(cond); }
void rust_sgw_warn_miter_flags(bool cond) { WARN_ON(cond); }
void rust_sgw_warn_consumed(bool cond) { WARN_ON(cond); }
void rust_sgw_warn_once_length(unsigned long long length) { WARN_ONCE(length, "length = %lld\n", length); }
void rust_sgw_sgl_free_order(struct scatterlist *sgl, int order)
{
#ifdef CONFIG_SGL_ALLOC
	sgl_free_order(sgl, order);
#endif
}
