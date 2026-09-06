/*
 * gen_archive.c -- build a kernel-format LZ4 "archive" (the framing
 * lib/decompress_unlz4.c actually parses: ARCHIVE_MAGICNUMBER, then
 * length-prefixed LZ4 block-compressed chunks) from a plaintext file, using
 * the system liblz4 for the compression itself. Test-corpus generation
 * only, not part of the port or the differential binary.
 *
 * usage: gen_archive <in> <out> [chunk_size]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARCHIVE_MAGICNUMBER 0x184C2102u

extern int LZ4_compressBound(int isize);
extern int LZ4_compress_default(const char *src, char *dst, int srcSize, int maxOutputSize);

static void put_le32(FILE *f, unsigned int v)
{
	unsigned char b[4] = { v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff };
	fwrite(b, 1, 4, f);
}

int main(int argc, char **argv)
{
	FILE *in, *out;
	long len, off;
	unsigned char *data, *comp;
	long chunk_size = 8L << 20;
	int cap;

	if (argc < 3) { fprintf(stderr, "usage: %s in out [chunk_size]\n", argv[0]); return 2; }
	if (argc >= 4) chunk_size = atol(argv[3]);

	in = fopen(argv[1], "rb");
	if (!in) { perror(argv[1]); return 2; }
	fseek(in, 0, SEEK_END);
	len = ftell(in);
	fseek(in, 0, SEEK_SET);
	data = malloc(len ? (size_t)len : 1);
	if (len && fread(data, 1, (size_t)len, in) != (size_t)len) { perror("fread"); return 2; }
	fclose(in);

	cap = LZ4_compressBound((int)(chunk_size < len ? chunk_size : (len ? len : 1)));
	comp = malloc((size_t)cap);

	out = fopen(argv[2], "wb");
	if (!out) { perror(argv[2]); return 2; }
	put_le32(out, ARCHIVE_MAGICNUMBER);

	off = 0;
	do {
		long this_chunk = len - off;
		int csize;

		if (this_chunk > chunk_size)
			this_chunk = chunk_size;
		csize = LZ4_compress_default((const char *)data + off, (char *)comp,
					      (int)this_chunk, cap);
		if (csize <= 0) { fprintf(stderr, "LZ4_compress_default failed\n"); return 1; }
		put_le32(out, (unsigned int)csize);
		fwrite(comp, 1, (size_t)csize, out);
		off += this_chunk;
	} while (off < len);

	fclose(out);
	free(data);
	free(comp);
	return 0;
}
