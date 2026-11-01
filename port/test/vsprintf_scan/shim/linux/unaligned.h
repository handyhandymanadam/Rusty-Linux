/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_UNALIGNED_H
#define _SHIM_VSPRINTF_LINUX_UNALIGNED_H
#include <string.h>
#include <linux/types.h>

static inline u32 get_unaligned_u32(const u32 *p)
{
	u32 v;
	memcpy(&v, p, sizeof(v));
	return v;
}
#define get_unaligned(p) get_unaligned_u32(p)

#endif
