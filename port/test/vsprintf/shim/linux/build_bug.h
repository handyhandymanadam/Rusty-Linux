/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_BUILD_BUG_H
#define _SHIM_LINUX_BUILD_BUG_H
/* Real static_assert(cond) (a single-argument form) is C23; -std=gnu11's
 * _Static_assert always needs a message. Redefined here as a 1-arg macro
 * matching the C's own single-argument call sites. */
#define static_assert(cond) _Static_assert(cond, #cond)
#endif
