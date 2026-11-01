/* SPDX-License-Identifier: GPL-2.0-only */
/* Single-threaded harness: no real lock ordering to validate. */
#ifndef _SHIM_XARRAY_LINUX_LOCKDEP_H
#define _SHIM_XARRAY_LINUX_LOCKDEP_H
#define lockdep_is_held(lock) 1
#define lockdep_assert_held(lock) do { (void)(lock); } while (0)
#endif
