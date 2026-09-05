// SPDX-License-Identifier: GPL-2.0
/*
 * UCS2 string handling
 *
 * PORTED TO RUST. All seven bodies are lib/ucs2_string_rs.rs; what is left
 * here is the seven C entry symbols, their EXPORT_SYMBOL() lines, and
 * ucs2_strscpy()'s argument checks -- which include a WARN_ON_ONCE, and
 * WARN_ON_ONCE plants a bug-table entry naming this file and line.
 *
 * lib/ucs2_string_rs.rs records one deliberate divergence: ucs2_strnlen()
 * reads one element fewer than the C, which over-reads by one when the
 * whole of maxlength is non-NUL. The return value is unchanged; only a read
 * of memory nobody promised was there goes away.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 */

#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/ucs2_string.h>
#include <linux/kabi.h>

/* lib/ucs2_string_rs.rs */
ssize_t rust_ucs2_strscpy(ucs2_char_t *dst, const ucs2_char_t *src, size_t count);
int rust_ucs2_strncmp(const ucs2_char_t *a, const ucs2_char_t *b, size_t len);
/* from build-fast/lib/ucs2_string.o -- reproduces 0x534031cb */
KABI_TYPE_STRING(
	"ucs2_as_utf8",
	"subprogram ( formal_parameter pointer_type { typedef_type u8 { typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) } } } dest , formal_parameter pointer_type { const_type { typedef_type ucs2_char_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } src , formal_parameter base_type unsigned long byte_size(8) encoding(7) maxlength ) -> base_type unsigned long byte_size(8) encoding(7)");
/* from build-fast/lib/ucs2_string.o -- reproduces 0x7bd8db2c */
KABI_TYPE_STRING(
	"ucs2_utf8size",
	"subprogram ( formal_parameter pointer_type { const_type { typedef_type ucs2_char_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } src ) -> base_type unsigned long byte_size(8) encoding(7)");
/* from build-fast/lib/ucs2_string.o -- reproduces 0x55e65ea0 */
KABI_TYPE_STRING(
	"ucs2_strsize",
	"subprogram ( formal_parameter pointer_type { const_type { typedef_type ucs2_char_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } data , formal_parameter base_type unsigned long byte_size(8) encoding(7) maxlength ) -> base_type unsigned long byte_size(8) encoding(7)");
/* from build-fast/lib/ucs2_string.o -- reproduces 0xe590780d */
KABI_TYPE_STRING(
	"ucs2_strlen",
	"subprogram ( formal_parameter pointer_type { const_type { typedef_type ucs2_char_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } s ) -> base_type unsigned long byte_size(8) encoding(7)");
/* from build-fast/lib/ucs2_string.o -- reproduces 0x21fe470c */
KABI_TYPE_STRING(
	"ucs2_strnlen",
	"subprogram ( formal_parameter pointer_type { const_type { typedef_type ucs2_char_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } s , formal_parameter typedef_type size_t { typedef_type __kernel_size_t { typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) } } } maxlength ) -> base_type unsigned long byte_size(8) encoding(7)");

EXPORT_SYMBOL(ucs2_strnlen);


EXPORT_SYMBOL(ucs2_strlen);


EXPORT_SYMBOL(ucs2_strsize);

/**
 * ucs2_strscpy() - Copy a UCS2 string into a sized buffer.
 *
 * @dst: Pointer to the destination buffer where to copy the string to.
 * @src: Pointer to the NUL-terminated string to copy.
 * @count: Size of the destination buffer, in UCS2 characters.
 *
 * Like strscpy(), but for UCS2 strings.
 */
ssize_t ucs2_strscpy(ucs2_char_t *dst, const ucs2_char_t *src, size_t count)
{
	/*
	 * Ensure that both the amount of data and its size fit in an ssize_t.
	 * The WARN stays here: it plants a bug-table entry naming this file
	 * and line, which is what makes the splat say ucs2_strscpy().
	 */
	if (count == 0 || WARN_ON_ONCE(count > INT_MAX / sizeof(*dst)))
		return -E2BIG;

	return rust_ucs2_strscpy(dst, src, count);
}
EXPORT_SYMBOL(ucs2_strscpy);

int ucs2_strncmp(const ucs2_char_t *a, const ucs2_char_t *b, size_t len)
{
	return rust_ucs2_strncmp(a, b, len);
}
EXPORT_SYMBOL(ucs2_strncmp);


EXPORT_SYMBOL(ucs2_utf8size);

/*
 * copy at most maxlength bytes of whole utf8 characters to dest from the
 * ucs2 string src.
 *
 * The return value is the number of characters copied, not including the
 * final NUL character.
 */

EXPORT_SYMBOL(ucs2_as_utf8);

MODULE_DESCRIPTION("UCS2 string handling");
MODULE_LICENSE("GPL v2");
