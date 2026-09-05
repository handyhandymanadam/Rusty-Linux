/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_BUG_H
#define _SHIM_LINUX_BUG_H
/*
 * The oracle does not splat; the point is what it returns. These evaluate
 * to the condition, like the kernel's, because callers use them in `if`.
 */
#define WARN_ON(x)      (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define BUG_ON(x)       ((void)(x))
#endif
