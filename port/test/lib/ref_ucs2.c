/* SPDX-License-Identifier: GPL-2.0
 *
 * The UCS-2 oracle. NOT a transcription: this compiles the pristine
 * lib/ucs2_string.c itself, names moved aside. See README.
 */
#define ucs2_strnlen	ref_ucs2_strnlen
#define ucs2_strlen	ref_ucs2_strlen
#define ucs2_strsize	ref_ucs2_strsize
#define ucs2_strscpy	ref_ucs2_strscpy
#define ucs2_strncmp	ref_ucs2_strncmp
#define ucs2_utf8size	ref_ucs2_utf8size
#define ucs2_as_utf8	ref_ucs2_as_utf8

#include <limits.h>
#include <linux/errno.h>
#include <linux/bug.h>

#include "../../pristine/lib/ucs2_string.c"
