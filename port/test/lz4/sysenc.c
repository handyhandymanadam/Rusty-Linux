/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The corpus encoder, and it is deliberately NOT the in-tree one.
 *
 * port/test/lzo/ uses lib/lzo/lzo1x_compress.c because it is the encoder the
 * kernel ships beside the decoder under test. The same arrangement was tried
 * here first and lib/lz4/lz4_compress.c DOES NOT ROUND-TRIP when built in this
 * harness: LZ4_compress_default() followed by LZ4_decompress_safe() returns the
 * right length and the wrong bytes.
 *
 * THAT IS THE ENCODER, NOT THE DECODER, AND IT WAS MEASURED RATHER THAN
 * ASSUMED. The same compressed stream handed to the system liblz4's
 * LZ4_decompress_safe() decodes to the same wrong bytes -- so the kernel's
 * decoder, which is what this project is porting, agrees with an independent
 * implementation and the encoder is the odd one out. The cause is NOT
 * ESTABLISHED; it is a userspace-build question about lz4_compress.c, which
 * this project does not port. Recorded in STATUS.md rather than guessed at.
 *
 * Using liblz4 instead is not a compromise for a DECODER differential: the
 * streams now come from outside the tree entirely, which is the same property
 * that makes port/test/xz/'s xz(1)-generated vectors strong.
 *
 * This file is compiled WITHOUT include/linux/lz4.h on the include path,
 * because the kernel's header declares LZ4_compress_default() with a fifth
 * workspace parameter that liblz4's does not have.
 */
extern int LZ4_compress_default(const char *src, char *dst, int src_size,
				int dst_capacity);

int sys_lz4_compress(const char *src, char *dst, int n, int cap);

int sys_lz4_compress(const char *src, char *dst, int n, int cap)
{
	return LZ4_compress_default(src, dst, n, cap);
}
