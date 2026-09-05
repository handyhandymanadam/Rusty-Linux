/* SPDX-License-Identifier: GPL-2.0 */
/* zstd_entropy shim: <linux/types.h>.
 *
 * lib/zstd/common/mem.h uses the uint*_t spellings directly, so all this owes
 * it is <stdint.h>. It also owes it the ENDIANNESS FACT: mem.h decides
 * MEM_LITTLE_ENDIAN on `#if defined(__LITTLE_ENDIAN)` and does NOT include
 * <linux/kernel.h>, while glibc's <endian.h> defines BOTH __LITTLE_ENDIAN and
 * __BIG_ENDIAN as names for the two orders. Left alone, that test is true on
 * every host and MEM_readLE* would silently skip the byteswap on a big-endian
 * build -- in BOTH arms, so the differential would still pass. Pulling in the
 * shared shim, which undefines whichever of the two is false here, is what
 * makes the oracle compile the paths the kernel compiles.
 */
#ifndef _SHIM_ZSTD_LINUX_TYPES_H
#define _SHIM_ZSTD_LINUX_TYPES_H
#include <stdint.h>
#include <stddef.h>
#include <linux/kernel.h>
#endif
