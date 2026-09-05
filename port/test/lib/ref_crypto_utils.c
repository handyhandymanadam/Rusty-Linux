/* SPDX-License-Identifier: GPL-2.0
 *
 * The __crypto_xor oracle. NOT a transcription: this compiles the pristine
 * lib/crypto/utils.c itself, name moved aside, with the two configuration
 * flags forced to the x86-64 values so both arms are compiled for the same
 * machine. See README.
 */
#define __crypto_xor	ref_crypto_xor
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#define CONFIG_64BIT 1

#include <linux/types.h>
#include <linux/compiler.h>
#ifndef IS_ENABLED
#define IS_ENABLED(x) (x)
#endif
static inline unsigned long __ffs(unsigned long x) { return __builtin_ctzl(x); }

#include "../../pristine/lib/crypto/utils.c"
