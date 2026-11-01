/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SHIM_XARRAY_LINUX_SCHED_MM_H
#define _SHIM_XARRAY_LINUX_SCHED_MM_H
#define might_alloc(gfp) do { (void)(gfp); } while (0)
#endif
