/* SPDX-License-Identifier: GPL-2.0
 *
 * The xxHash oracle. NOT a transcription: this compiles the pristine
 * lib/xxhash.c itself, with its exported names moved aside. See README.
 */
#define __LITTLE_ENDIAN 1

#define xxh32_copy_state	ref_xxh32_copy_state
#define xxh64_copy_state	ref_xxh64_copy_state
#define xxh32			ref_xxh32
#define xxh64			ref_xxh64
#define xxh32_reset		ref_xxh32_reset
#define xxh64_reset		ref_xxh64_reset
#define xxh64_update		ref_xxh64_update
#define xxh64_digest		ref_xxh64_digest

#include "../../pristine/lib/xxhash.c"
