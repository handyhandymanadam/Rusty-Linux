// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

/*
 * THIS FILE IS NOW THREE ENTRY THUNKS. The bodies are in
 * lib/zstd/common/zstd_common_rs.rs.
 *
 * WHY THE C HAS TO STAY. zstd_common_module.c:24-26 EXPORT_SYMBOL_GPL's
 * ZSTD_isError, ZSTD_getErrorName and ZSTD_getErrorCode. Under
 * CONFIG_GENDWARFKSYMS a symbol's MODVERSIONS CRC is computed from the DWARF
 * of its DEFINITION, so defining any of the three in Rust changes its CRC and
 * breaks module loading against a stock kernel -- GOALS.md §2 criterion 4.
 * The C definition stays; the body moves. Same arrangement as
 * common/entropy_common.c.
 *
 * ZSTD_versionNumber, ZSTD_versionString and ZSTD_getErrorString are NOT
 * exported and have no callers kernel-wide, so they carry no CRC and the Rust
 * defines them directly. They are not here.
 */

#define ZSTD_DEPS_NEED_MALLOC
#include "error_private.h"
#include "zstd_internal.h"

#undef ZSTD_isError   /* defined within zstd_internal.h */
/*! ZSTD_isError() :
 *  tells if a return value is an error code
 *  symbol is required for external callers */


/*! ZSTD_getErrorName() :
 *  provides error code string from function result (useful for debugging) */


/*! ZSTD_getError() :
 *  convert a `size_t` function result into a proper ZSTD_errorCode enum */

