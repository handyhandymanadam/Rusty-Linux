/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_RANGE_H
#define _SHIM_VSPRINTF_LINUX_RANGE_H
#include <linux/types.h>

struct range {
	u64 start;
	u64 end;
};

#endif
