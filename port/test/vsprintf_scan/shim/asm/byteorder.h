/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_ASM_BYTEORDER_H
#define _SHIM_VSPRINTF_ASM_BYTEORDER_H
#include <linux/types.h>
/* x86_64: little-endian, matching this project's only target. Macros, not
 * static inline functions -- decpair[]'s static initializer needs these to
 * be genuine constant-expressions (a function call, even one GCC could
 * fold, is rejected by the front end's "initializer element is not
 * constant" check regardless of -O level). __builtin_bswap* IS accepted
 * in a constant-expression position when its argument is constant. */
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_be32(x) ((u32)__builtin_bswap32(x))
#define htons(x) ((u16)__builtin_bswap16(x))
#define ntohs(x) ((u16)__builtin_bswap16(x))
#define htonl(x) ((u32)__builtin_bswap32(x))
#define ntohl(x) ((u32)__builtin_bswap32(x))
#define swab32(x) ((u32)__builtin_bswap32(x))
#endif
