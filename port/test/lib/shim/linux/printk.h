/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_PRINTK_H
#define _SHIM_LINUX_PRINTK_H
/* The oracle does not print; the point is what it returns. */
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#endif
