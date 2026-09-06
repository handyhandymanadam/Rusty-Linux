/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_KERNEL_H
#define _SHIM_LINUX_KERNEL_H
#include <limits.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define max_t(type, a, b) ({ type __x = (a); type __y = (b); __x > __y ? __x : __y; })
#define clamp(val, lo, hi) ((val) < (lo) ? (lo) : (val) > (hi) ? (hi) : (val))

#endif
