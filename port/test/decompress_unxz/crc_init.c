/* SPDX-License-Identifier: GPL-2.0
 *
 * xz_crc32.c's table (xz_crc32_table[256]) is populated by xz_crc32_init(),
 * never called in the non-XZ_PREBOOT arm this port replaces -- there,
 * xz_stream.h redefines xz_crc32(buf, size, crc) to
 * `~crc32_le(~crc, buf, size)` instead, and the kernel's real crc32_le()
 * (lib/crc/crc32-main.c) needs no init. This harness's backend is compiled
 * through the non-__KERNEL__ path instead (see run.sh's BACKEND_INC), which
 * keeps the table-driven xz_crc32() live and needs it initialised once --
 * same fix port/test/xz_stream/crc_shim.c already uses, for the same
 * reason: every uninitialised-table CRC check failed, which read as "every
 * archive is corrupt" until traced back to this.
 */
void xz_crc32_init(void);

__attribute__((constructor)) static void harness_crc_init(void)
{
	xz_crc32_init();
}
