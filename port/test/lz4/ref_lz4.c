/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The oracle: PRISTINE lib/lz4/lz4_decompress.c, compiled under renamed
 * globals so both arms live in one binary.
 *
 * Nothing is transcribed -- the file is #include'd, the idiom
 * port/test/lib/ref_sort.c established. NOT -Dstatic=: lz4_decompress.c is
 * built entirely out of FORCE_INLINE statics whose specialisation is the whole
 * point, and stripping `static` would compile a different program.
 */
#define LZ4_decompress_safe            ref_LZ4_decompress_safe
#define LZ4_decompress_safe_partial    ref_LZ4_decompress_safe_partial
#define LZ4_decompress_fast            ref_LZ4_decompress_fast
#define LZ4_setStreamDecode            ref_LZ4_setStreamDecode
#define LZ4_decompress_safe_continue   ref_LZ4_decompress_safe_continue
#define LZ4_decompress_fast_continue   ref_LZ4_decompress_fast_continue
#define LZ4_decompress_safe_usingDict  ref_LZ4_decompress_safe_usingDict
#define LZ4_decompress_fast_usingDict  ref_LZ4_decompress_fast_usingDict

#include "lz4_decompress.c"
