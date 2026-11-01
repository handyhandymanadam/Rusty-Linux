/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_HEX_H
#define _SHIM_VSPRINTF_LINUX_HEX_H
/* Real content, matching include/linux/hex.h. hex_asc/hex_asc_upper are
 * real EXPORT_SYMBOL tables (now lib/hexdump_rs.rs) -- defined once in
 * stubs.c with the real values, shared by both arms. */
extern const char hex_asc[];
extern const char hex_asc_upper[];
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]

static inline char *hex_byte_pack(char *buf, unsigned char byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}
static inline char *hex_byte_pack_upper(char *buf, unsigned char byte)
{
	*buf++ = hex_asc_upper_hi(byte);
	*buf++ = hex_asc_upper_lo(byte);
	return buf;
}

#endif
