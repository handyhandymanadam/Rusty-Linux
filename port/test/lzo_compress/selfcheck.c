/* SPDX-License-Identifier: GPL-2.0
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME pristine
 * C, so `run.sh --selfcheck` exercises every line of main.c with an arm
 * that cannot disagree. Proves the plumbing, not the port.
 */
#include <stddef.h>

#define FWD(name) \
	int ref_##name(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem); \
	int rs_##name(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem) \
	{ return ref_##name(src, src_len, dst, dst_len, wrkmem); }

FWD(lzo1x_1_compress)
FWD(lzorle1x_1_compress)
FWD(lzo1x_1_compress_safe)
FWD(lzorle1x_1_compress_safe)
