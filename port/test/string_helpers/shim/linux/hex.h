/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_HEX_H
#define _SHIM_LINUX_HEX_H

extern const char hex_asc[];
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]

extern int hex_to_bin(unsigned char ch);

#endif
