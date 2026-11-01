/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SHIM_XARRAY_LINUX_COMPILER_H
#define _SHIM_XARRAY_LINUX_COMPILER_H
#include <linux/kernel.h>	/* the shared base: likely/unlikely */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
/* Sparse-only annotations; empty for a plain gcc/clang build, same as the
 * real <linux/compiler_types.h> when __CHECKER__ is not defined. */
#define __force
#define __rcu
#define __must_check
#define __must_hold(x)
#ifndef __bitwise
#define __bitwise
#endif

#endif
