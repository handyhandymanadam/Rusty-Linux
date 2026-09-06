/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_KERNEL_H
#define _SHIM_LINUX_KERNEL_H
#define likely(x) (x)
#define unlikely(x) (x)
#define pr_debug(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define fallthrough do { } while (0) /* unused: this file uses real C fallthrough */
#endif
