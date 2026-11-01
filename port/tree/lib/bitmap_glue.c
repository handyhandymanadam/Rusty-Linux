// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/bitmap.c
 * Helper functions for bitmap.h.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/slab.h>

/*
 * RUST PORT (lib/bitmap.c, 6.18.49): every bitmap operation (__bitmap_*, bitmap_cut, bitmap_find_next_zero_area_off,
 * bitmap_remap, bitmap_bitremap, bitmap_onto/bitmap_fold under CONFIG_NUMA, bitmap_from/to_arr32) is in bitmap_rs.rs,
 * with its EXPORT_SYMBOLs. What stays here is allocation: bitmap_alloc*, bitmap_free and the devm_ pair, which are
 * slab and device-resource calls. Upstream's file is installed as bitmap_norust.c for CONFIG_RUST=n.
 */

unsigned long *bitmap_alloc(unsigned int nbits, gfp_t flags)
{
	return kmalloc_array(BITS_TO_LONGS(nbits), sizeof(unsigned long),
			     flags);
}
EXPORT_SYMBOL(bitmap_alloc);

unsigned long *bitmap_zalloc(unsigned int nbits, gfp_t flags)
{
	return bitmap_alloc(nbits, flags | __GFP_ZERO);
}
EXPORT_SYMBOL(bitmap_zalloc);

unsigned long *bitmap_alloc_node(unsigned int nbits, gfp_t flags, int node)
{
	return kmalloc_array_node(BITS_TO_LONGS(nbits), sizeof(unsigned long),
				  flags, node);
}
EXPORT_SYMBOL(bitmap_alloc_node);

unsigned long *bitmap_zalloc_node(unsigned int nbits, gfp_t flags, int node)
{
	return bitmap_alloc_node(nbits, flags | __GFP_ZERO, node);
}
EXPORT_SYMBOL(bitmap_zalloc_node);

void bitmap_free(const unsigned long *bitmap)
{
	kfree(bitmap);
}
EXPORT_SYMBOL(bitmap_free);

static void devm_bitmap_free(void *data)
{
	unsigned long *bitmap = data;

	bitmap_free(bitmap);
}

unsigned long *devm_bitmap_alloc(struct device *dev,
				 unsigned int nbits, gfp_t flags)
{
	unsigned long *bitmap;
	int ret;

	bitmap = bitmap_alloc(nbits, flags);
	if (!bitmap)
		return NULL;

	ret = devm_add_action_or_reset(dev, devm_bitmap_free, bitmap);
	if (ret)
		return NULL;

	return bitmap;
}
EXPORT_SYMBOL_GPL(devm_bitmap_alloc);

unsigned long *devm_bitmap_zalloc(struct device *dev,
				  unsigned int nbits, gfp_t flags)
{
	return devm_bitmap_alloc(dev, nbits, flags | __GFP_ZERO);
}
EXPORT_SYMBOL_GPL(devm_bitmap_zalloc);
