/* SPDX-License-Identifier: GPL-2.0 */
/* zstd_entropy shim: <linux/swab.h> -- mem.h's MEM_swap32/64. */
#ifndef _SHIM_ZSTD_LINUX_SWAB_H
#define _SHIM_ZSTD_LINUX_SWAB_H
#include <stdint.h>
#define swab16(x) __builtin_bswap16((uint16_t)(x))
#define swab32(x) __builtin_bswap32((uint32_t)(x))
#define swab64(x) __builtin_bswap64((uint64_t)(x))
#endif
