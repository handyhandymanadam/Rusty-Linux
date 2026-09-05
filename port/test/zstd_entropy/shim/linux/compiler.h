/* SPDX-License-Identifier: GPL-2.0 */
/* zstd_entropy shim: <linux/compiler.h>.
 *
 * mem.h includes it for `inline`; lib/zstd/common/compiler.h includes it for
 * the attribute spellings below. Everything here is a no-op or the obvious
 * GCC attribute -- none of it selects a code path.
 */
#ifndef _SHIM_ZSTD_LINUX_COMPILER_H
#define _SHIM_ZSTD_LINUX_COMPILER_H
#include <linux/kernel.h>   /* likely/unlikely/__always_inline/noinline */

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef __must_check
#define __must_check __attribute__((warn_unused_result))
#endif
#ifndef barrier
#define barrier() __asm__ __volatile__("" : : : "memory")
#endif
#endif
