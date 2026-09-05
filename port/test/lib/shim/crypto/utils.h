/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_CRYPTO_UTILS_H
#define _SHIM_CRYPTO_UTILS_H
#include <linux/types.h>
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int len);
#endif
