/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_BITOPS_H
#define _SHIM_LINUX_BITOPS_H
#include <linux/types.h>
static inline u32 rol32(u32 v, u8 s) { return (v << s) | (v >> (32 - s)); }
static inline u32 ror32(u32 v, u8 s) { return (v >> s) | (v << (32 - s)); }
static inline u64 rol64(u64 v, u8 s) { return (v << s) | (v >> (64 - s)); }
#endif
