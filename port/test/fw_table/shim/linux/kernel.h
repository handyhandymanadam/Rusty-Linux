/* SPDX-License-Identifier: GPL-2.0-only */
/* port/test/fw_table/shim/linux/kernel.h -- the shared base plus this
 * module's delta, which is printk.
 *
 * pr_err()/pr_warn() are macros over _printk() with a KERN_* level byte
 * prepended to the format string, and this file defines no pr_fmt, so
 * printk.h's default `#define pr_fmt(fmt) fmt` applies and NOTHING else is
 * added. Both arms therefore call the same _printk with the same format
 * string and the same arguments -- drv.c defines that _printk and captures
 * what each arm asked to print, so the DIAGNOSTIC TEXT is one of the things
 * compared. That matters here: the C passes proc->id rather than
 * proc[i].id to both diagnostics, which is very likely an upstream slip and
 * is reproduced, and the format carries `%4.4s` over a signature that need
 * not be NUL-terminated. */
#ifndef _SHIM_FW_TABLE_LINUX_KERNEL_H
#define _SHIM_FW_TABLE_LINUX_KERNEL_H

#include_next <linux/kernel.h>

int _printk(const char *fmt, ...);

#define KERN_SOH     "\001"
#define KERN_ERR     KERN_SOH "3"
#define KERN_WARNING KERN_SOH "4"

#define pr_err(fmt, ...)  _printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) _printk(KERN_WARNING fmt, ##__VA_ARGS__)

#endif
