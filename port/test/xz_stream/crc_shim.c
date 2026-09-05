/* SPDX-License-Identifier: GPL-2.0
 *
 * crc32_le() for the harness.
 *
 * In a kernel build, xz_stream.h:15 defines
 *     xz_crc32(buf, size, crc) := ~crc32_le(~crc, buf, size)
 * so the PORT calls crc32_le() -- which is right, and is what the kernel
 * links. The harness compiles the C side through xz_config.h instead, the
 * non-__KERNEL__ path, where lib/xz/xz_crc32.c supplies a table-driven
 * xz_crc32() and there is no crc32_le() anywhere.
 *
 * Rather than give the Rust its own CRC, define crc32_le() by INVERTING the
 * identity above against the C's own table. Both arms then share one CRC
 * implementation, so a CRC disagreement can only come from the stream logic
 * under test and never from two spellings of the same polynomial.
 */
#include <stdint.h>
#include <stddef.h>

uint32_t xz_crc32(const uint8_t *buf, size_t size, uint32_t crc);
void xz_crc32_init(void);

uint32_t crc32_le(uint32_t crc, const unsigned char *p, size_t len)
{
	return ~xz_crc32(p, len, ~crc);
}

/* xz_crc32.c's table is filled by xz_crc32_init(); the kernel calls it from
 * xz_dec_init(). Both arms go through this, so call it once at startup. */
__attribute__((constructor)) static void harness_crc_init(void) { xz_crc32_init(); }
