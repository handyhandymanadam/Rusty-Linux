// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/* ******************************************************************
 * Common functions of New Generation Entropy library
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 *  You can contact the author at :
 *  - FSE+HUF source repository : https://github.com/Cyan4973/FiniteStateEntropy
 *  - Public forum : https://groups.google.com/forum/#!forum/lz4c
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
****************************************************************** */

/*
 * # Shape: this file is now three entry thunks and nothing else
 *
 * FSE_readNCount(), HUF_readStats() and HUF_readStats_wksp() are
 * EXPORT_SYMBOL_GPL'd from lib/zstd/zstd_common_module.c:21-23. Under
 * CONFIG_GENDWARFKSYMS the MODVERSIONS CRC of an exported symbol is computed
 * from the DWARF of its *definition*, and a Rust definition changes the type
 * names the CRC is built from -- which breaks module loading, GOALS.md §2
 * criterion 4. So the definitions stay C and their bodies moved to Rust.
 * That is the lib/bcd shape, and GOALS.md §1's first exception: forced, not
 * chosen.
 *
 * Everything else this file used to hold is now defined directly by
 * lib/zstd/common/entropy_common_rs.rs under its own name -- the
 * lib/union_find shape -- because nothing else here is exported and so
 * nothing else carries a CRC:
 *
 *	FSE_readNCount_bmi2	was called only by fse_decompress.o, which is
 *				now Rust too, so the call is internal
 *	FSE_versionNumber	referenced by nothing, kernel-wide
 *	FSE_isError		\  referenced by nothing: every in-tree caller
 *	FSE_getErrorName	 | gets the #define in zstd_internal.h:39-40,
 *	HUF_isError		 | huf_compress.c:38, huf_decompress.c:75 or
 *	HUF_getErrorName	/  fse_compress.c:36 instead
 *
 * The symbols are all still defined, by the Rust, so `nm` output is
 * unchanged.
 *
 * Everything else is in lib/zstd/common/entropy_common_rs.rs.
 */

#include "mem.h"
#include "error_private.h"       /* ERR_*, ERROR */
#define FSE_STATIC_LINKING_ONLY  /* FSE_MIN_TABLELOG */
#include "fse.h"
#include "huf.h"

/* lib/zstd/common/entropy_common_rs.rs */
size_t rust_HUF_readStats(BYTE* huffWeight, size_t hwSize, U32* rankStats,
                          U32* nbSymbolsPtr, U32* tableLogPtr,
                          const void* src, size_t srcSize);
/*! HUF_readStats() :
    Read compact Huffman tree, saved by HUF_writeCTable().
    `huffWeight` is destination buffer.
    `rankStats` is assumed to be a table of at least HUF_TABLELOG_MAX U32.
    @return : size read from `src` , or an error Code .
    Note : Needed by HUF_readCTable() and HUF_readDTableX?() .
*/
size_t HUF_readStats(BYTE* huffWeight, size_t hwSize, U32* rankStats,
                     U32* nbSymbolsPtr, U32* tableLogPtr,
                     const void* src, size_t srcSize)
{
    /* The C's U32 wksp[HUF_READ_STATS_WORKSPACE_SIZE_U32] moved with the
     * body: it is a plain stack array of the same 219 words on the Rust
     * side, and no allocator is involved on either side. */
    return rust_HUF_readStats(huffWeight, hwSize, rankStats, nbSymbolsPtr,
                              tableLogPtr, src, srcSize);
}


