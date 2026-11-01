/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_STRING_HELPERS_LINUX_KERNEL_H
#define _SHIM_STRING_HELPERS_LINUX_KERNEL_H
#include_next <linux/kernel.h>
#include <stddef.h>

extern char *kasprintf(unsigned int gfp, const char *fmt, ...);
extern int snprintf(char *buf, size_t size, const char *fmt, ...);
extern char *get_options(const char *str, int nints, int *ints);

#endif
