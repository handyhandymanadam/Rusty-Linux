/* SPDX-License-Identifier: GPL-2.0 */
/* Only referenced inside `#ifdef __BIG_ENDIAN` blocks in lib/find_bit.c,
 * which this shim (and this project's only target arch, x86-64) never
 * defines -- so those blocks, and any real need for swab(), never
 * actually compile. Present only so the #include resolves. */
#ifndef _SHIM_LINUX_SWAB_H
#define _SHIM_LINUX_SWAB_H
#endif
