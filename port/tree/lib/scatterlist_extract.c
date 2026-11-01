// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007 Jens Axboe <jens.axboe@oracle.com>
 *
 * Scatterlist handling helpers.
 *
 * RUST PORT (lib/scatterlist.c, 6.18.49): this file is upstream's extract_iter_to_sg() and its five helpers, byte for byte
 * (lines 1085-1414 of the original). They walk struct iov_iter, folio_queue and xarray, whose layouts and accessors vary by
 * configuration, and have no algorithm of their own beyond list filling, so they stay C. The rest of the file is in
 * scatterlist_glue.c (exports, configuration-dependent wrappers) and scatterlist_rs.rs (the algorithms). Upstream's whole file is
 * installed as scatterlist_norust.c for CONFIG_RUST=n.
 */
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/kmemleak.h>
#include <linux/bvec.h>
#include <linux/uio.h>
#include <linux/folio_queue.h>

/*
 * Extract and pin a list of up to sg_max pages from UBUF- or IOVEC-class
 * iterators, and add them to the scatterlist.
 */
static ssize_t extract_user_to_sg(struct iov_iter *iter,
				  ssize_t maxsize,
				  struct sg_table *sgtable,
				  unsigned int sg_max,
				  iov_iter_extraction_t extraction_flags)
{
	struct scatterlist *sg = sgtable->sgl + sgtable->nents;
	struct page **pages;
	unsigned int npages;
	ssize_t ret = 0, res;
	size_t len, off;

	/* We decant the page list into the tail of the scatterlist */
	pages = (void *)sg + array_size(sg_max, sizeof(struct scatterlist));
	pages -= sg_max;

	do {
		res = iov_iter_extract_pages(iter, &pages, maxsize, sg_max,
					     extraction_flags, &off);
		if (res <= 0)
			goto failed;

		len = res;
		maxsize -= len;
		ret += len;
		npages = DIV_ROUND_UP(off + len, PAGE_SIZE);
		sg_max -= npages;

		for (; npages > 0; npages--) {
			struct page *page = *pages;
			size_t seg = min_t(size_t, PAGE_SIZE - off, len);

			*pages++ = NULL;
			sg_set_page(sg, page, seg, off);
			sgtable->nents++;
			sg++;
			len -= seg;
			off = 0;
		}
	} while (maxsize > 0 && sg_max > 0);

	return ret;

failed:
	while (sgtable->nents > sgtable->orig_nents)
		unpin_user_page(sg_page(&sgtable->sgl[--sgtable->nents]));
	return res;
}

/*
 * Extract up to sg_max pages from a BVEC-type iterator and add them to the
 * scatterlist.  The pages are not pinned.
 */
static ssize_t extract_bvec_to_sg(struct iov_iter *iter,
				  ssize_t maxsize,
				  struct sg_table *sgtable,
				  unsigned int sg_max,
				  iov_iter_extraction_t extraction_flags)
{
	const struct bio_vec *bv = iter->bvec;
	struct scatterlist *sg = sgtable->sgl + sgtable->nents;
	unsigned long start = iter->iov_offset;
	unsigned int i;
	ssize_t ret = 0;

	for (i = 0; i < iter->nr_segs; i++) {
		size_t off, len;

		len = bv[i].bv_len;
		if (start >= len) {
			start -= len;
			continue;
		}

		len = min_t(size_t, maxsize, len - start);
		off = bv[i].bv_offset + start;

		sg_set_page(sg, bv[i].bv_page, len, off);
		sgtable->nents++;
		sg++;
		sg_max--;

		ret += len;
		maxsize -= len;
		if (maxsize <= 0 || sg_max == 0)
			break;
		start = 0;
	}

	if (ret > 0)
		iov_iter_advance(iter, ret);
	return ret;
}

/*
 * Extract up to sg_max pages from a KVEC-type iterator and add them to the
 * scatterlist.  This can deal with vmalloc'd buffers as well as kmalloc'd or
 * static buffers.  The pages are not pinned.
 */
static ssize_t extract_kvec_to_sg(struct iov_iter *iter,
				  ssize_t maxsize,
				  struct sg_table *sgtable,
				  unsigned int sg_max,
				  iov_iter_extraction_t extraction_flags)
{
	const struct kvec *kv = iter->kvec;
	struct scatterlist *sg = sgtable->sgl + sgtable->nents;
	unsigned long start = iter->iov_offset;
	unsigned int i;
	ssize_t ret = 0;

	for (i = 0; i < iter->nr_segs; i++) {
		struct page *page;
		unsigned long kaddr;
		size_t off, len, seg;

		len = kv[i].iov_len;
		if (start >= len) {
			start -= len;
			continue;
		}

		kaddr = (unsigned long)kv[i].iov_base + start;
		off = kaddr & ~PAGE_MASK;
		len = min_t(size_t, maxsize, len - start);
		kaddr &= PAGE_MASK;

		maxsize -= len;
		ret += len;
		do {
			seg = min_t(size_t, len, PAGE_SIZE - off);
			if (is_vmalloc_or_module_addr((void *)kaddr))
				page = vmalloc_to_page((void *)kaddr);
			else
				page = virt_to_page((void *)kaddr);

			sg_set_page(sg, page, seg, off);
			sgtable->nents++;
			sg++;
			sg_max--;

			len -= seg;
			kaddr += PAGE_SIZE;
			off = 0;
		} while (len > 0 && sg_max > 0);
		ret -= len;

		if (maxsize <= 0 || sg_max == 0)
			break;
		start = 0;
	}

	if (ret > 0)
		iov_iter_advance(iter, ret);
	return ret;
}

/*
 * Extract up to sg_max folios from an FOLIOQ-type iterator and add them to
 * the scatterlist.  The pages are not pinned.
 */
static ssize_t extract_folioq_to_sg(struct iov_iter *iter,
				   ssize_t maxsize,
				   struct sg_table *sgtable,
				   unsigned int sg_max,
				   iov_iter_extraction_t extraction_flags)
{
	const struct folio_queue *folioq = iter->folioq;
	struct scatterlist *sg = sgtable->sgl + sgtable->nents;
	unsigned int slot = iter->folioq_slot;
	ssize_t ret = 0;
	size_t offset = iter->iov_offset;

	BUG_ON(!folioq);

	if (slot >= folioq_nr_slots(folioq)) {
		folioq = folioq->next;
		if (WARN_ON_ONCE(!folioq))
			return 0;
		slot = 0;
	}

	do {
		struct folio *folio = folioq_folio(folioq, slot);
		size_t fsize = folioq_folio_size(folioq, slot);

		if (offset < fsize) {
			size_t part = umin(maxsize - ret, fsize - offset);

			sg_set_page(sg, folio_page(folio, 0), part, offset);
			sgtable->nents++;
			sg++;
			sg_max--;
			offset += part;
			ret += part;
		}

		if (offset >= fsize) {
			offset = 0;
			slot++;
			if (slot >= folioq_nr_slots(folioq)) {
				if (!folioq->next) {
					WARN_ON_ONCE(ret < iter->count);
					break;
				}
				folioq = folioq->next;
				slot = 0;
			}
		}
	} while (sg_max > 0 && ret < maxsize);

	iter->folioq = folioq;
	iter->folioq_slot = slot;
	iter->iov_offset = offset;
	iter->count -= ret;
	return ret;
}

/*
 * Extract up to sg_max folios from an XARRAY-type iterator and add them to
 * the scatterlist.  The pages are not pinned.
 */
static ssize_t extract_xarray_to_sg(struct iov_iter *iter,
				    ssize_t maxsize,
				    struct sg_table *sgtable,
				    unsigned int sg_max,
				    iov_iter_extraction_t extraction_flags)
{
	struct scatterlist *sg = sgtable->sgl + sgtable->nents;
	struct xarray *xa = iter->xarray;
	struct folio *folio;
	loff_t start = iter->xarray_start + iter->iov_offset;
	pgoff_t index = start / PAGE_SIZE;
	ssize_t ret = 0;
	size_t offset, len;
	XA_STATE(xas, xa, index);

	rcu_read_lock();

	xas_for_each(&xas, folio, ULONG_MAX) {
		if (xas_retry(&xas, folio))
			continue;
		if (WARN_ON(xa_is_value(folio)))
			break;
		if (WARN_ON(folio_test_hugetlb(folio)))
			break;

		offset = offset_in_folio(folio, start);
		len = min_t(size_t, maxsize, folio_size(folio) - offset);

		sg_set_page(sg, folio_page(folio, 0), len, offset);
		sgtable->nents++;
		sg++;
		sg_max--;

		maxsize -= len;
		ret += len;
		if (maxsize <= 0 || sg_max == 0)
			break;
	}

	rcu_read_unlock();
	if (ret > 0)
		iov_iter_advance(iter, ret);
	return ret;
}

/**
 * extract_iter_to_sg - Extract pages from an iterator and add to an sglist
 * @iter: The iterator to extract from
 * @maxsize: The amount of iterator to copy
 * @sgtable: The scatterlist table to fill in
 * @sg_max: Maximum number of elements in @sgtable that may be filled
 * @extraction_flags: Flags to qualify the request
 *
 * Extract the page fragments from the given amount of the source iterator and
 * add them to a scatterlist that refers to all of those bits, to a maximum
 * addition of @sg_max elements.
 *
 * The pages referred to by UBUF- and IOVEC-type iterators are extracted and
 * pinned; BVEC-, KVEC-, FOLIOQ- and XARRAY-type are extracted but aren't
 * pinned; DISCARD-type is not supported.
 *
 * No end mark is placed on the scatterlist; that's left to the caller.
 *
 * @extraction_flags can have ITER_ALLOW_P2PDMA set to request peer-to-peer DMA
 * be allowed on the pages extracted.
 *
 * If successful, @sgtable->nents is updated to include the number of elements
 * added and the number of bytes added is returned.  @sgtable->orig_nents is
 * left unaltered.
 *
 * The iov_iter_extract_mode() function should be used to query how cleanup
 * should be performed.
 */
ssize_t extract_iter_to_sg(struct iov_iter *iter, size_t maxsize,
			   struct sg_table *sgtable, unsigned int sg_max,
			   iov_iter_extraction_t extraction_flags)
{
	if (maxsize == 0 || sg_max == 0)
		return 0;

	switch (iov_iter_type(iter)) {
	case ITER_UBUF:
	case ITER_IOVEC:
		return extract_user_to_sg(iter, maxsize, sgtable, sg_max,
					  extraction_flags);
	case ITER_BVEC:
		return extract_bvec_to_sg(iter, maxsize, sgtable, sg_max,
					  extraction_flags);
	case ITER_KVEC:
		return extract_kvec_to_sg(iter, maxsize, sgtable, sg_max,
					  extraction_flags);
	case ITER_FOLIOQ:
		return extract_folioq_to_sg(iter, maxsize, sgtable, sg_max,
					    extraction_flags);
	case ITER_XARRAY:
		return extract_xarray_to_sg(iter, maxsize, sgtable, sg_max,
					    extraction_flags);
	default:
		pr_err("%s(%u) unsupported\n", __func__, iov_iter_type(iter));
		WARN_ON_ONCE(1);
		return -EIO;
	}
}
EXPORT_SYMBOL_GPL(extract_iter_to_sg);
