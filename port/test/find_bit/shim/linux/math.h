/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_MATH_H
#define _SHIM_LINUX_MATH_H
#define round_down(x, y) ((x) & ~((__typeof__(x))(y) - 1))
#endif
