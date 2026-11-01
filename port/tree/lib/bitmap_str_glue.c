// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitmap.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/hex.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>

#include "kstrtox.h"

/**
 * bitmap_parse_user - convert an ASCII hex string in a user buffer into a bitmap
 *
 * @ubuf: pointer to user buffer containing string.
 * @ulen: buffer size in bytes.  If string is smaller than this
 *    then it must be terminated with a \0.
 * @maskp: pointer to bitmap array that will contain result.
 * @nmaskbits: size of bitmap, in bits.
 */
int bitmap_parse_user(const char __user *ubuf,
			unsigned int ulen, unsigned long *maskp,
			int nmaskbits)
{
	char *buf;
	int ret;

	buf = memdup_user_nul(ubuf, ulen);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	ret = bitmap_parse(buf, UINT_MAX, maskp, nmaskbits);

	kfree(buf);
	return ret;
}
EXPORT_SYMBOL(bitmap_parse_user);

/**
 * bitmap_print_to_pagebuf - convert bitmap to list or hex format ASCII string
 * @list: indicates whether the bitmap must be list
 * @buf: page aligned buffer into which string is placed
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 *
 * Output format is a comma-separated list of decimal numbers and
 * ranges if list is specified or hex digits grouped into comma-separated
 * sets of 8 digits/set. Returns the number of characters written to buf.
 *
 * It is assumed that @buf is a pointer into a PAGE_SIZE, page-aligned
 * area and that sufficient storage remains at @buf to accommodate the
 * bitmap_print_to_pagebuf() output. Returns the number of characters
 * actually printed to @buf, excluding terminating '\0'.
 */
int bitmap_print_to_pagebuf(bool list, char *buf, const unsigned long *maskp,
			    int nmaskbits)
{
	ptrdiff_t len = PAGE_SIZE - offset_in_page(buf);

	return list ? scnprintf(buf, len, "%*pbl\n", nmaskbits, maskp) :
		      scnprintf(buf, len, "%*pb\n", nmaskbits, maskp);
}
EXPORT_SYMBOL(bitmap_print_to_pagebuf);

/**
 * bitmap_print_to_buf  - convert bitmap to list or hex format ASCII string
 * @list: indicates whether the bitmap must be list
 *      true:  print in decimal list format
 *      false: print in hexadecimal bitmask format
 * @buf: buffer into which string is placed
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 * @off: in the string from which we are copying, We copy to @buf
 * @count: the maximum number of bytes to print
 */
static int bitmap_print_to_buf(bool list, char *buf, const unsigned long *maskp,
		int nmaskbits, loff_t off, size_t count)
{
	const char *fmt = list ? "%*pbl\n" : "%*pb\n";
	ssize_t size;
	void *data;

	data = kasprintf(GFP_KERNEL, fmt, nmaskbits, maskp);
	if (!data)
		return -ENOMEM;

	size = memory_read_from_buffer(buf, count, &off, data, strlen(data) + 1);
	kfree(data);

	return size;
}

/**
 * bitmap_print_bitmask_to_buf  - convert bitmap to hex bitmask format ASCII string
 * @buf: buffer into which string is placed
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 * @off: in the string from which we are copying, We copy to @buf
 * @count: the maximum number of bytes to print
 *
 * The bitmap_print_to_pagebuf() is used indirectly via its cpumap wrapper
 * cpumap_print_to_pagebuf() or directly by drivers to export hexadecimal
 * bitmask and decimal list to userspace by sysfs ABI.
 * Drivers might be using a normal attribute for this kind of ABIs. A
 * normal attribute typically has show entry as below::
 *
 *   static ssize_t example_attribute_show(struct device *dev,
 *		struct device_attribute *attr, char *buf)
 *   {
 *	...
 *	return bitmap_print_to_pagebuf(true, buf, &mask, nr_trig_max);
 *   }
 *
 * show entry of attribute has no offset and count parameters and this
 * means the file is limited to one page only.
 * bitmap_print_to_pagebuf() API works terribly well for this kind of
 * normal attribute with buf parameter and without offset, count::
 *
 *   bitmap_print_to_pagebuf(bool list, char *buf, const unsigned long *maskp,
 *			   int nmaskbits)
 *   {
 *   }
 *
 * The problem is once we have a large bitmap, we have a chance to get a
 * bitmask or list more than one page. Especially for list, it could be
 * as complex as 0,3,5,7,9,... We have no simple way to know it exact size.
 * It turns out bin_attribute is a way to break this limit. bin_attribute
 * has show entry as below::
 *
 *   static ssize_t
 *   example_bin_attribute_show(struct file *filp, struct kobject *kobj,
 *		struct bin_attribute *attr, char *buf,
 *		loff_t offset, size_t count)
 *   {
 *	...
 *   }
 *
 * With the new offset and count parameters, this makes sysfs ABI be able
 * to support file size more than one page. For example, offset could be
 * >= 4096.
 * bitmap_print_bitmask_to_buf(), bitmap_print_list_to_buf() wit their
 * cpumap wrapper cpumap_print_bitmask_to_buf(), cpumap_print_list_to_buf()
 * make those drivers be able to support large bitmask and list after they
 * move to use bin_attribute. In result, we have to pass the corresponding
 * parameters such as off, count from bin_attribute show entry to this API.
 *
 * The role of cpumap_print_bitmask_to_buf() and cpumap_print_list_to_buf()
 * is similar with cpumap_print_to_pagebuf(),  the difference is that
 * bitmap_print_to_pagebuf() mainly serves sysfs attribute with the assumption
 * the destination buffer is exactly one page and won't be more than one page.
 * cpumap_print_bitmask_to_buf() and cpumap_print_list_to_buf(), on the other
 * hand, mainly serves bin_attribute which doesn't work with exact one page,
 * and it can break the size limit of converted decimal list and hexadecimal
 * bitmask.
 *
 * WARNING!
 *
 * This function is not a replacement for sprintf() or bitmap_print_to_pagebuf().
 * It is intended to workaround sysfs limitations discussed above and should be
 * used carefully in general case for the following reasons:
 *
 *  - Time complexity is O(nbits^2/count), comparing to O(nbits) for snprintf().
 *  - Memory complexity is O(nbits), comparing to O(1) for snprintf().
 *  - @off and @count are NOT offset and number of bits to print.
 *  - If printing part of bitmap as list, the resulting string is not a correct
 *    list representation of bitmap. Particularly, some bits within or out of
 *    related interval may be erroneously set or unset. The format of the string
 *    may be broken, so bitmap_parselist-like parser may fail parsing it.
 *  - If printing the whole bitmap as list by parts, user must ensure the order
 *    of calls of the function such that the offset is incremented linearly.
 *  - If printing the whole bitmap as list by parts, user must keep bitmap
 *    unchanged between the very first and very last call. Otherwise concatenated
 *    result may be incorrect, and format may be broken.
 *
 * Returns the number of characters actually printed to @buf
 */
int bitmap_print_bitmask_to_buf(char *buf, const unsigned long *maskp,
				int nmaskbits, loff_t off, size_t count)
{
	return bitmap_print_to_buf(false, buf, maskp, nmaskbits, off, count);
}
EXPORT_SYMBOL(bitmap_print_bitmask_to_buf);

/**
 * bitmap_print_list_to_buf  - convert bitmap to decimal list format ASCII string
 * @buf: buffer into which string is placed
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 * @off: in the string from which we are copying, We copy to @buf
 * @count: the maximum number of bytes to print
 *
 * Everything is same with the above bitmap_print_bitmask_to_buf() except
 * the print format.
 */
int bitmap_print_list_to_buf(char *buf, const unsigned long *maskp,
			     int nmaskbits, loff_t off, size_t count)
{
	return bitmap_print_to_buf(true, buf, maskp, nmaskbits, off, count);
}
EXPORT_SYMBOL(bitmap_print_list_to_buf);

/*
 * RUST PORT (lib/bitmap-str.c, 6.18.49): bitmap_parselist() and bitmap_parse() with their helpers (struct region,
 * bitmap_getnum, the region scanners, bitmap_get_x32_reverse) and EXPORT_SYMBOLs are in bitmap_str_rs.rs. What stays
 * here needs the allocator, user memory or the printf machinery: the _user variants and the bitmap_print_* functions.
 * Upstream's file is installed as bitmap-str_norust.c for CONFIG_RUST=n.
 */

/**
 * bitmap_parselist_user() - convert user buffer's list format ASCII
 * string to bitmap
 *
 * @ubuf: pointer to user buffer containing string.
 * @ulen: buffer size in bytes.  If string is smaller than this
 *    then it must be terminated with a \0.
 * @maskp: pointer to bitmap array that will contain result.
 * @nmaskbits: size of bitmap, in bits.
 *
 * Wrapper for bitmap_parselist(), providing it with user buffer.
 */
int bitmap_parselist_user(const char __user *ubuf,
			unsigned int ulen, unsigned long *maskp,
			int nmaskbits)
{
	char *buf;
	int ret;

	buf = memdup_user_nul(ubuf, ulen);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	ret = bitmap_parselist(buf, maskp, nmaskbits);

	kfree(buf);
	return ret;
}
EXPORT_SYMBOL(bitmap_parselist_user);

