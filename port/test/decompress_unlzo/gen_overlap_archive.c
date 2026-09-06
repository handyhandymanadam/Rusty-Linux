/*
 * gen_overlap_archive.c -- build a LZOP archive with SMALL blocks (real
 * lzo1x-compressed, valid LZOP framing, just not the block size the real
 * `lzop` CLI itself would choose) to force decompress_unlzo_rs.rs's
 * leftover-data ptr::copy through a genuinely overlapping case.
 *
 * WHY THIS EXISTS. Adversarial review of the port found that this
 * project's real-lzop-CLI corpus never exercises that copy's overlap path:
 * lzop always chunks at 256KB decompressed, and even a fully-zero 256KB
 * block compresses to src_len ~1183 (total ~1195 with its 12-byte prefix)
 * -- comfortably larger than the ~259-byte leftover the wrapper's initial
 * oversized header read can produce, so the overlap window a bigger block
 * would need never opens. It is real LZO1X compression and real LZOP
 * framing throughout; only the block-size POLICY (small, not 256KB) is
 * not what lzop itself would pick, which the kernel wrapper does not care
 * about -- it trusts whatever dst_len each block prefix declares, up to
 * LZO_BLOCK_SIZE.
 *
 * usage: gen_overlap_archive <in> <out> <block_size>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int lzo1x_1_compress(const unsigned char *src, size_t src_len,
			     unsigned char *dst, size_t *dst_len, void *wrkmem);
#define LZO1X_1_MEM_COMPRESS (16384 * sizeof(unsigned char *))

static void put_be32(FILE *f, unsigned int v)
{
	unsigned char b[4] = { (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff };
	fwrite(b, 1, 4, f);
}

int main(int argc, char **argv)
{
	FILE *in, *out;
	long len, off;
	unsigned char *data, *comp, *wrkmem;
	long block_size;

	if (argc < 4) { fprintf(stderr, "usage: %s in out block_size\n", argv[0]); return 2; }
	block_size = atol(argv[3]);

	in = fopen(argv[1], "rb");
	if (!in) { perror(argv[1]); return 2; }
	fseek(in, 0, SEEK_END);
	len = ftell(in);
	fseek(in, 0, SEEK_SET);
	data = malloc(len ? (size_t)len : 1);
	if (len && fread(data, 1, (size_t)len, in) != (size_t)len) { perror("fread"); return 2; }
	fclose(in);

	comp = malloc((size_t)block_size + block_size / 16 + 64 + 3);
	wrkmem = malloc(LZO1X_1_MEM_COMPRESS);

	out = fopen(argv[2], "wb");
	if (!out) { perror(argv[2]); return 2; }

	/* Minimal 38-byte LZOP header, matching run.sh's stdin-piped lzop
	 * output exactly (version 0x1040, no filter, no filename). */
	{
		static const unsigned char magic[9] = {
			0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a
		};
		fwrite(magic, 1, 9, out);
		put_be32(out, 0); /* placeholder, overwritten below */
	}
	/* version(2)=0x1040, lib_version(2), needed_version(2)=0x0940, method(1) */
	fseek(out, 9, SEEK_SET);
	{
		unsigned char hdr[7] = { 0x10, 0x40, 0x20, 0xa0, 0x09, 0x40, 0x02 };
		fwrite(hdr, 1, 7, out);
	}
	fputc(1, out); /* level */
	put_be32(out, 0x0300000dU); /* flags, no filter (matches real lzop output) */
	put_be32(out, 0x000081a4U); /* mode */
	put_be32(out, 0); /* mtime_low */
	put_be32(out, 0); /* mtime_high (version >= 0x0940) */
	fputc(0, out); /* filename length 0 */
	put_be32(out, 0); /* header checksum -- unlzo() never verifies it */

	off = 0;
	do {
		long this_chunk = len - off;
		size_t csize;

		if (this_chunk > block_size)
			this_chunk = block_size;
		lzo1x_1_compress(data + off, (size_t)this_chunk, comp, &csize, wrkmem);
		put_be32(out, (unsigned int)this_chunk);
		put_be32(out, (unsigned int)csize);
		put_be32(out, 0); /* checksum -- unlzo() never verifies it either */
		fwrite(comp, 1, csize, out);
		off += this_chunk;
	} while (off < len);
	put_be32(out, 0); /* end marker */

	fclose(out);
	free(data);
	free(comp);
	free(wrkmem);
	return 0;
}
