/* SPDX-License-Identifier: GPL-2.0-only */
/* Layout test only: CONFIG_XARRAY_MULTI on (real config), but NO
 * XA_CHUNK_SHIFT override -- unlike ../../shim/linux/kernel.h, this
 * test needs the REAL header's own #ifndef XA_CHUNK_SHIFT /
 * IS_ENABLED(CONFIG_BASE_SMALL) logic to run, once per CONFIG_BASE_SMALL
 * arm (passed via -DCONFIG_BASE_SMALL=0 or =1 on the command line). */
#ifndef _SHIM_XARRAY_LAYOUT_LINUX_KERNEL_H
#define _SHIM_XARRAY_LAYOUT_LINUX_KERNEL_H
#include_next <linux/kernel.h>

#define CONFIG_XARRAY_MULTI 1

#endif
