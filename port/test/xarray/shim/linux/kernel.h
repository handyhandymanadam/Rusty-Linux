/* SPDX-License-Identifier: GPL-2.0-only */
/* Delta over the shared base: CONFIG_XARRAY_MULTI must be on so the real
 * multi-order/split code paths (the ones this harness cares most about)
 * compile in, and XA_CHUNK_SHIFT is lowered so multi-level trees and
 * sibling runs appear at small, fuzzable indices instead of needing
 * thousands of entries -- see the approved verification plan sent to
 * rusty-linux-e6, item 2. xarray.h guards its own definition with
 * #ifndef, so defining it here (before xarray.h is ever included) wins. */
#ifndef _SHIM_XARRAY_LINUX_KERNEL_H
#define _SHIM_XARRAY_LINUX_KERNEL_H
#include_next <linux/kernel.h>

#define CONFIG_XARRAY_MULTI 1
#define XA_CHUNK_SHIFT 4

#endif
