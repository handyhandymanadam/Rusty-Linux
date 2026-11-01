// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (lib/idr.c, 6.18.49): the IDA half -- ida_alloc_range(), ida_find_first_range(), ida_free(), ida_destroy() -- is in idr_rs.rs. This file
 * is upstream's with those four bodies replaced by thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition); the IDR half (it
 * sits on lib/radix-tree.c, not ported) is verbatim. The wrappers below are what Rust cannot express: the xa_lock calls (spinlock_t depends on
 * the configuration), kzalloc()/kfree() (allocation-profiling macros), xas_next_entry() (a header inline) and the WARN (the warning now names
 * this file -- recorded divergence). Upstream's whole file is installed as idr_norust.c for CONFIG_RUST=n.
 */
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

static_assert(sizeof(struct xa_state) == 56 && offsetof(struct xa_state, xa) == 0 && offsetof(struct xa_state, xa_index) == 8 &&
	      offsetof(struct xa_state, xa_shift) == 16 && offsetof(struct xa_state, xa_sibs) == 17 && offsetof(struct xa_state, xa_offset) == 18 &&
	      offsetof(struct xa_state, xa_pad) == 19 && offsetof(struct xa_state, xa_node) == 24 && offsetof(struct xa_state, xa_alloc) == 32 &&
	      offsetof(struct xa_state, xa_update) == 40 && offsetof(struct xa_state, xa_lru) == 48);
static_assert(sizeof(struct ida_bitmap) == 128 && IDA_BITMAP_BITS == 1024 && BITS_PER_XA_VALUE == 63 && XA_FREE_MARK == 0 && XA_PRESENT == 8 &&
	      offsetof(struct ida, xa) == 0);

int rust_ida_alloc_range(struct xarray *xa, unsigned int min, unsigned int max, gfp_t gfp);
int rust_ida_find_first_range(struct xarray *xa, unsigned int min, unsigned int max);
void rust_ida_free(struct xarray *xa, unsigned int id);
void rust_ida_destroy(struct xarray *xa);
void rust_ida_lock(struct xarray *xa, unsigned long *flags);
void rust_ida_unlock(struct xarray *xa, unsigned long flags);
struct ida_bitmap *rust_ida_kzalloc(gfp_t gfp);
struct ida_bitmap *rust_ida_kzalloc_nowait(void);
void rust_ida_kfree(void *p);
void *rust_ida_xas_next_entry(struct xa_state *xas, unsigned long max);
void rust_ida_warn_not_allocated(unsigned int id);

void rust_ida_lock(struct xarray *xa, unsigned long *flags)
{
	unsigned long f;

	xa_lock_irqsave(xa, f);
	*flags = f;
}
void rust_ida_unlock(struct xarray *xa, unsigned long flags) { xa_unlock_irqrestore(xa, flags); }
struct ida_bitmap *rust_ida_kzalloc(gfp_t gfp) { return kzalloc(sizeof(struct ida_bitmap), gfp); }
struct ida_bitmap *rust_ida_kzalloc_nowait(void) { return kzalloc(sizeof(struct ida_bitmap), GFP_NOWAIT); }
void rust_ida_kfree(void *p) { kfree(p); }
void *rust_ida_xas_next_entry(struct xa_state *xas, unsigned long max) { return xas_next_entry(xas, max); }
void rust_ida_warn_not_allocated(unsigned int id) { WARN(1, "ida_free called for id=%d which is not allocated.\n", id); }


/**
 * idr_alloc_u32() - Allocate an ID.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @nextid: Pointer to an ID.
 * @max: The maximum ID to allocate (inclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @nextid and @max.
 * Note that @max is inclusive whereas the @end parameter to idr_alloc()
 * is exclusive.  The new ID is assigned to @nextid before the pointer
 * is inserted into the IDR, so if @nextid points into the object pointed
 * to by @ptr, a concurrent lookup will not find an uninitialised ID.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: 0 if an ID was allocated, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.  If an error occurred,
 * @nextid is unchanged.
 */
int idr_alloc_u32(struct idr *idr, void *ptr, u32 *nextid,
			unsigned long max, gfp_t gfp)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	unsigned int base = idr->idr_base;
	unsigned int id = *nextid;

	if (WARN_ON_ONCE(!(idr->idr_rt.xa_flags & ROOT_IS_IDR)))
		idr->idr_rt.xa_flags |= IDR_RT_MARKER;
	if (max < base)
		return -ENOSPC;

	id = (id < base) ? 0 : id - base;
	radix_tree_iter_init(&iter, id);
	slot = idr_get_free(&idr->idr_rt, &iter, gfp, max - base);
	if (IS_ERR(slot))
		return PTR_ERR(slot);

	*nextid = iter.index + base;
	/* there is a memory barrier inside radix_tree_iter_replace() */
	radix_tree_iter_replace(&idr->idr_rt, &iter, slot, ptr);
	radix_tree_iter_tag_clear(&idr->idr_rt, &iter, IDR_FREE);

	return 0;
}
EXPORT_SYMBOL_GPL(idr_alloc_u32);

/**
 * idr_alloc() - Allocate an ID.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @start and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{
	u32 id = start;
	int ret;

	if (WARN_ON_ONCE(start < 0))
		return -EINVAL;

	ret = idr_alloc_u32(idr, ptr, &id, end > 0 ? end - 1 : INT_MAX, gfp);
	if (ret)
		return ret;

	return id;
}
EXPORT_SYMBOL_GPL(idr_alloc);

/**
 * idr_alloc_cyclic() - Allocate an ID cyclically.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @start and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 * The search for an unused ID will start at the last ID allocated and will
 * wrap around to @start if no free IDs are found before reaching @end.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{
	u32 id = idr->idr_next;
	int err, max = end > 0 ? end - 1 : INT_MAX;

	if ((int)id < start)
		id = start;

	err = idr_alloc_u32(idr, ptr, &id, max, gfp);
	if ((err == -ENOSPC) && (id > start)) {
		id = start;
		err = idr_alloc_u32(idr, ptr, &id, max, gfp);
	}
	if (err)
		return err;

	idr->idr_next = id + 1;
	return id;
}
EXPORT_SYMBOL(idr_alloc_cyclic);

/**
 * idr_remove() - Remove an ID from the IDR.
 * @idr: IDR handle.
 * @id: Pointer ID.
 *
 * Removes this ID from the IDR.  If the ID was not previously in the IDR,
 * this function returns %NULL.
 *
 * Since this function modifies the IDR, the caller should provide their
 * own locking to ensure that concurrent modification of the same IDR is
 * not possible.
 *
 * Return: The pointer formerly associated with this ID.
 */
void *idr_remove(struct idr *idr, unsigned long id)
{
	return radix_tree_delete_item(&idr->idr_rt, id - idr->idr_base, NULL);
}
EXPORT_SYMBOL_GPL(idr_remove);

/**
 * idr_find() - Return pointer for given ID.
 * @idr: IDR handle.
 * @id: Pointer ID.
 *
 * Looks up the pointer associated with this ID.  A %NULL pointer may
 * indicate that @id is not allocated or that the %NULL pointer was
 * associated with this ID.
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 *
 * Return: The pointer associated with this ID.
 */
void *idr_find(const struct idr *idr, unsigned long id)
{
	return radix_tree_lookup(&idr->idr_rt, id - idr->idr_base);
}
EXPORT_SYMBOL_GPL(idr_find);

/**
 * idr_for_each() - Iterate through all stored pointers.
 * @idr: IDR handle.
 * @fn: Function to be called for each pointer.
 * @data: Data passed to callback function.
 *
 * The callback function will be called for each entry in @idr, passing
 * the ID, the entry and @data.
 *
 * If @fn returns anything other than %0, the iteration stops and that
 * value is returned from this function.
 *
 * idr_for_each() can be called concurrently with idr_alloc() and
 * idr_remove() if protected by RCU.  Newly added entries may not be
 * seen and deleted entries may be seen, but adding and removing entries
 * will not cause other entries to be skipped, nor spurious ones to be seen.
 */
int idr_for_each(const struct idr *idr,
		int (*fn)(int id, void *p, void *data), void *data)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	int base = idr->idr_base;

	radix_tree_for_each_slot(slot, &idr->idr_rt, &iter, 0) {
		int ret;
		unsigned long id = iter.index + base;

		if (WARN_ON_ONCE(id > INT_MAX))
			break;
		ret = fn(id, rcu_dereference_raw(*slot), data);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL(idr_for_each);

/**
 * idr_get_next_ul() - Find next populated entry.
 * @idr: IDR handle.
 * @nextid: Pointer to an ID.
 *
 * Returns the next populated entry in the tree with an ID greater than
 * or equal to the value pointed to by @nextid.  On exit, @nextid is updated
 * to the ID of the found value.  To use in a loop, the value pointed to by
 * nextid must be incremented by the user.
 */
void *idr_get_next_ul(struct idr *idr, unsigned long *nextid)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	void *entry = NULL;
	unsigned long base = idr->idr_base;
	unsigned long id = *nextid;

	id = (id < base) ? 0 : id - base;
	radix_tree_for_each_slot(slot, &idr->idr_rt, &iter, id) {
		entry = rcu_dereference_raw(*slot);
		if (!entry)
			continue;
		if (!xa_is_internal(entry))
			break;
		if (slot != &idr->idr_rt.xa_head && !xa_is_retry(entry))
			break;
		slot = radix_tree_iter_retry(&iter);
	}
	if (!slot)
		return NULL;

	*nextid = iter.index + base;
	return entry;
}
EXPORT_SYMBOL(idr_get_next_ul);

/**
 * idr_get_next() - Find next populated entry.
 * @idr: IDR handle.
 * @nextid: Pointer to an ID.
 *
 * Returns the next populated entry in the tree with an ID greater than
 * or equal to the value pointed to by @nextid.  On exit, @nextid is updated
 * to the ID of the found value.  To use in a loop, the value pointed to by
 * nextid must be incremented by the user.
 */
void *idr_get_next(struct idr *idr, int *nextid)
{
	unsigned long id = *nextid;
	void *entry = idr_get_next_ul(idr, &id);

	if (WARN_ON_ONCE(id > INT_MAX))
		return NULL;
	*nextid = id;
	return entry;
}
EXPORT_SYMBOL(idr_get_next);

/**
 * idr_replace() - replace pointer for given ID.
 * @idr: IDR handle.
 * @ptr: New pointer to associate with the ID.
 * @id: ID to change.
 *
 * Replace the pointer registered with an ID and return the old value.
 * This function can be called under the RCU read lock concurrently with
 * idr_alloc() and idr_remove() (as long as the ID being removed is not
 * the one being replaced!).
 *
 * Returns: the old value on success.  %-ENOENT indicates that @id was not
 * found.  %-EINVAL indicates that @ptr was not valid.
 */
void *idr_replace(struct idr *idr, void *ptr, unsigned long id)
{
	struct radix_tree_node *node;
	void __rcu **slot = NULL;
	void *entry;

	id -= idr->idr_base;

	entry = __radix_tree_lookup(&idr->idr_rt, id, &node, &slot);
	if (!slot || radix_tree_tag_get(&idr->idr_rt, id, IDR_FREE))
		return ERR_PTR(-ENOENT);

	__radix_tree_replace(&idr->idr_rt, node, slot, ptr);

	return entry;
}
EXPORT_SYMBOL(idr_replace);

/**
 * DOC: IDA description
 *
 * The IDA is an ID allocator which does not provide the ability to
 * associate an ID with a pointer.  As such, it only needs to store one
 * bit per ID, and so is more space efficient than an IDR.  To use an IDA,
 * define it using DEFINE_IDA() (or embed a &struct ida in a data structure,
 * then initialise it using ida_init()).  To allocate a new ID, call
 * ida_alloc(), ida_alloc_min(), ida_alloc_max() or ida_alloc_range().
 * To free an ID, call ida_free().
 *
 * ida_destroy() can be used to dispose of an IDA without needing to
 * free the individual IDs in it.  You can use ida_is_empty() to find
 * out whether the IDA has any IDs currently allocated.
 *
 * The IDA handles its own locking.  It is safe to call any of the IDA
 * functions without synchronisation in your code.
 *
 * IDs are currently limited to the range [0-INT_MAX].  If this is an awkward
 * limitation, it should be quite straightforward to raise the maximum.
 */

/*
 * Developer's notes:
 *
 * The IDA uses the functionality provided by the XArray to store bitmaps in
 * each entry.  The XA_FREE_MARK is only cleared when all bits in the bitmap
 * have been set.
 *
 * I considered telling the XArray that each slot is an order-10 node
 * and indexing by bit number, but the XArray can't allow a single multi-index
 * entry in the head, which would significantly increase memory consumption
 * for the IDA.  So instead we divide the index by the number of bits in the
 * leaf bitmap before doing a radix tree lookup.
 *
 * As an optimisation, if there are only a few low bits set in any given
 * leaf, instead of allocating a 128-byte bitmap, we store the bits
 * as a value entry.  Value entries never have the XA_FREE_MARK cleared
 * because we can always convert them into a bitmap entry.
 *
 * It would be possible to optimise further; once we've run out of a
 * single 128-byte bitmap, we currently switch to a 576-byte node, put
 * the 128-byte bitmap in the first entry and then start allocating extra
 * 128-byte entries.  We could instead use the 512 bytes of the node's
 * data as a bitmap before moving to that scheme.  I do not believe this
 * is a worthwhile optimisation; Rasmus Villemoes surveyed the current
 * users of the IDA and almost none of them use more than 1024 entries.
 * Those that do use more than the 8192 IDs that the 512 bytes would
 * provide.
 *
 * The IDA always uses a lock to alloc/free.  If we add a 'test_bit'
 * equivalent, it will still need locking.  Going to RCU lookup would require
 * using RCU to free bitmaps, and that's not trivial without embedding an
 * RCU head in the bitmap, which adds a 2-pointer overhead to each 128-byte
 * bitmap, which is excessive.
 */

/**
 * ida_alloc_range() - Allocate an unused ID.
 * @ida: IDA handle.
 * @min: Lowest ID to allocate.
 * @max: Highest ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between @min and @max, inclusive.  The allocated ID will
 * not exceed %INT_MAX, even if @max is larger.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max,
			gfp_t gfp)
{
	return rust_ida_alloc_range(&ida->xa, min, max, gfp);
}
EXPORT_SYMBOL(ida_alloc_range);

/**
 * ida_find_first_range - Get the lowest used ID.
 * @ida: IDA handle.
 * @min: Lowest ID to get.
 * @max: Highest ID to get.
 *
 * Get the lowest used ID between @min and @max, inclusive.  The returned
 * ID will not exceed %INT_MAX, even if @max is larger.
 *
 * Context: Any context. Takes and releases the xa_lock.
 * Return: The lowest used ID, or errno if no used ID is found.
 */
int ida_find_first_range(struct ida *ida, unsigned int min, unsigned int max)
{
	return rust_ida_find_first_range(&ida->xa, min, max);
}
EXPORT_SYMBOL(ida_find_first_range);

/**
 * ida_free() - Release an allocated ID.
 * @ida: IDA handle.
 * @id: Previously allocated ID.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void ida_free(struct ida *ida, unsigned int id)
{
	rust_ida_free(&ida->xa, id);
}
EXPORT_SYMBOL(ida_free);

/**
 * ida_destroy() - Free all IDs.
 * @ida: IDA handle.
 *
 * Calling this function frees all IDs and releases all resources used
 * by an IDA.  When this call returns, the IDA is empty and can be reused
 * or freed.  If the IDA is already empty, there is no need to call this
 * function.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void ida_destroy(struct ida *ida)
{
	rust_ida_destroy(&ida->xa);
}
EXPORT_SYMBOL(ida_destroy);

#ifndef __KERNEL__
extern void xa_dump_index(unsigned long index, unsigned int shift);
#define IDA_CHUNK_SHIFT		ilog2(IDA_BITMAP_BITS)

static void ida_dump_entry(void *entry, unsigned long index)
{
	unsigned long i;

	if (!entry)
		return;

	if (xa_is_node(entry)) {
		struct xa_node *node = xa_to_node(entry);
		unsigned int shift = node->shift + IDA_CHUNK_SHIFT +
			XA_CHUNK_SHIFT;

		xa_dump_index(index * IDA_BITMAP_BITS, shift);
		xa_dump_node(node);
		for (i = 0; i < XA_CHUNK_SIZE; i++)
			ida_dump_entry(node->slots[i],
					index | (i << node->shift));
	} else if (xa_is_value(entry)) {
		xa_dump_index(index * IDA_BITMAP_BITS, ilog2(BITS_PER_LONG));
		pr_cont("value: data %lx [%px]\n", xa_to_value(entry), entry);
	} else {
		struct ida_bitmap *bitmap = entry;

		xa_dump_index(index * IDA_BITMAP_BITS, IDA_CHUNK_SHIFT);
		pr_cont("bitmap: %p data", bitmap);
		for (i = 0; i < IDA_BITMAP_LONGS; i++)
			pr_cont(" %lx", bitmap->bitmap[i]);
		pr_cont("\n");
	}
}

static void ida_dump(struct ida *ida)
{
	struct xarray *xa = &ida->xa;
	pr_debug("ida: %p node %p free %d\n", ida, xa->xa_head,
				xa->xa_flags >> ROOT_TAG_SHIFT);
	ida_dump_entry(xa->xa_head, 0);
}
#endif
