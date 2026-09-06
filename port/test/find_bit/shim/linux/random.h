/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/random.h: get_random_u32_below()
 * is a static inline wrapper upstream that falls through to
 * __get_random_u32_below() whenever `ceil` isn't a compile-time constant
 * (always true here, called with a runtime bitmap weight). drv.c defines
 * __get_random_u32_below() itself, deterministically, so the C and Rust
 * arms of find_random_bit() can be compared for the same draw. */
#ifndef _SHIM_LINUX_RANDOM_H
#define _SHIM_LINUX_RANDOM_H

unsigned int __get_random_u32_below(unsigned int ceil);

static inline unsigned int get_random_u32_below(unsigned int ceil)
{
	return __get_random_u32_below(ceil);
}

#endif
