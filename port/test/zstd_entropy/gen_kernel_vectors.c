/* SPDX-License-Identifier: GPL-2.0
 *
 * Regenerate lib/libtest_zstd_generated.h.
 *
 * THE COMPRESSOR IS SYSTEM libzstd, NOT THE KERNEL'S. CONFIG_ZSTD_COMPRESS is
 * n in both our configs, so the in-tree compressor is not even built -- but
 * that is not the only reason. libzstd is an implementation neither arm of the
 * differential derives from, which makes these vectors the third instrument:
 * the only kind of check that can see a bug BOTH arms share. The kernel
 * decompresses at boot and must reproduce a plaintext libzstd chose the
 * encoding for.
 *
 * WHICH CODE THE VECTORS ACTUALLY REACH IS MEASURED, NOT ASSUMED. A frame that
 * happens to use raw literals never calls HUF_readStats and never touches the
 * ported file; a boot test built from such frames would pass while proving
 * nothing (notes/STATUS.md lesson 9). So this walks each frame's block headers and
 * reports the Literals_Block_Type of every block, and REFUSES TO EMIT unless
 * enough of them are Compressed (type 2, a Huffman table is present) or
 * Treeless (type 3).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zstd.h>

static uint64_t rng_state = 0x5eed5eed5eedULL;
static uint64_t rng(void)
{
	uint64_t x = rng_state;
	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	rng_state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

/* Six shapes, chosen so the encoder is pushed down different paths: skewed
 * literals want a Huffman table, long repeats want sequences, and
 * near-incompressible data is the raw-literal control. */
static size_t make_plain(int shape, unsigned char *p, size_t cap)
{
	static const char *words[] = {
		"the ", "kernel ", "decompressor ", "reads ", "a ", "frame ",
		"and ", "writes ", "bytes ", "into ", "memory ", "safely ",
		"because ", "every ", "bound ", "was ", "checked ", "first ",
	};
	size_t n = 0;

	switch (shape) {
	case 0:					/* text-like: Huffman + matches */
		while (n < cap - 32)
			n += (size_t)sprintf((char *)p + n, "%s",
					     words[rng() % 18]);
		break;
	case 1:					/* skewed bytes: Huffman's best case */
		for (n = 0; n < cap; n++) {
			uint64_t r = rng();
			p[n] = (unsigned char)((r % 100) < 70 ? 'a' + (r % 4)
							     : r % 256);
		}
		break;
	case 2:					/* long repeats: sequence-heavy */
		for (n = 0; n < 64 && n < cap; n++)
			p[n] = (unsigned char)('A' + (rng() % 26));
		while (n < cap) {
			size_t len = 16 + rng() % 200;
			size_t off = rng() % n;
			if (len > cap - n)
				len = cap - n;
			if (off + len > n)
				len = n - off;
			if (!len) { p[n++] = (unsigned char)rng(); continue; }
			memcpy(p + n, p + off, len);
			n += len;
		}
		break;
	case 3:					/* near-incompressible control */
		for (n = 0; n < cap; n++)
			p[n] = (unsigned char)rng();
		break;
	case 4:					/* runs: RLE-ish literals */
		while (n < cap) {
			size_t len = 1 + rng() % 40;
			unsigned char v = (unsigned char)(rng() % 12);
			if (len > cap - n)
				len = cap - n;
			memset(p + n, v, len);
			n += len;
		}
		break;
	default:				/* mixed */
		for (n = 0; n < cap; n++)
			p[n] = (unsigned char)((n % 7 == 0) ? rng()
					       : 'a' + ((n / 3) % 20));
		break;
	}
	return n > cap ? cap : n;
}

/* ---- frame walker: which literals block types does this frame use? ----- */
static uint32_t rd24(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

/* Counts blocks by Literals_Block_Type into lit[4]; returns 0 on success. */
static int walk_frame(const unsigned char *f, size_t n, unsigned lit[4],
		      unsigned *blocks)
{
	size_t i = 0;
	unsigned char fhd;
	unsigned fcs_flag, single, dict_flag, fcs_size;

	if (n < 6 || rd24(f) != 0x2FB528u || f[3] != 0xFD)
		return -1;			/* 0xFD2FB528 little-endian */
	i = 4;
	fhd = f[i++];
	fcs_flag  = (unsigned)(fhd >> 6);
	single    = (fhd >> 5) & 1;
	dict_flag = fhd & 3;
	if (!single)
		i++;				/* Window_Descriptor */
	i += dict_flag == 3 ? 4 : dict_flag;
	fcs_size = fcs_flag == 0 ? (single ? 1u : 0u)
		 : fcs_flag == 1 ? 2u : fcs_flag == 2 ? 4u : 8u;
	i += fcs_size;

	for (;;) {
		unsigned last, type;
		uint32_t bh, size;

		if (i + 3 > n)
			return -1;
		bh = rd24(f + i);
		i += 3;
		last = bh & 1;
		type = (bh >> 1) & 3;
		size = bh >> 3;
		if (i + size > n)
			return -1;
		(*blocks)++;
		if (type == 2) {		/* Compressed_Block */
			if (size < 1)
				return -1;
			lit[f[i] & 3]++;
		} else {
			lit[0]++;		/* raw/RLE block: no literals hdr */
		}
		i += size;
		if (last)
			break;
	}
	return 0;
}

static const char *lit_name[4] = { "Raw", "RLE", "Compressed(HUF)", "Treeless" };

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "lib/libtest_zstd_generated.h";
	FILE *o;
	unsigned char plain[8192], comp[16384];
	unsigned lit_total[4] = { 0, 0, 0, 0 };
	unsigned blocks_total = 0;
	int shape, level, nvec = 0;
	struct { size_t pl, cl; } sizes[64];

	o = fopen(path, "w");
	if (!o) { perror(path); return 1; }

	fprintf(o,
"/* SPDX-License-Identifier: GPL-2.0 */\n"
"/* GENERATED by port/test/zstd_entropy/gen_kernel_vectors.c -- do not edit.\n"
" *\n"
" * Compressed by SYSTEM libzstd, an implementation neither arm of the\n"
" * differential derives from. The kernel decompresses these at boot through\n"
" * lib/zstd/common/entropy_common_rs.rs and must reproduce the plaintext.\n"
" */\n\n");

	for (shape = 0; shape < 6; shape++) {
		for (level = 1; level <= 9; level += 4) {
			size_t pl = make_plain(shape, plain, sizeof plain);
			size_t cl = ZSTD_compress(comp, sizeof comp,
						  plain, pl, level);
			size_t k;
			unsigned lit[4] = { 0, 0, 0, 0 };
			unsigned blocks = 0;

			if (ZSTD_isError(cl)) {
				fprintf(stderr, "compress failed: %s\n",
					ZSTD_getErrorName(cl));
				return 1;
			}
			if (walk_frame(comp, cl, lit, &blocks) != 0) {
				fprintf(stderr, "frame walk failed "
					"(shape %d level %d)\n", shape, level);
				return 1;
			}
			for (k = 0; k < 4; k++)
				lit_total[k] += lit[k];
			blocks_total += blocks;

			fprintf(o, "/* shape %d, level %d: %zu -> %zu bytes; "
				   "literals blocks Raw=%u RLE=%u HUF=%u "
				   "Treeless=%u */\n",
				shape, level, pl, cl,
				lit[0], lit[1], lit[2], lit[3]);
			fprintf(o, "static const u8 lt_zsplain%d[] __initconst = {",
				nvec);
			for (k = 0; k < pl; k++)
				fprintf(o, "%s%u,", k % 20 ? "" : "\n\t",
					plain[k]);
			fprintf(o, "\n};\n");
			fprintf(o, "static const u8 lt_zscomp%d[] __initconst = {",
				nvec);
			for (k = 0; k < cl; k++)
				fprintf(o, "%s%u,", k % 20 ? "" : "\n\t",
					comp[k]);
			fprintf(o, "\n};\n\n");
			sizes[nvec].pl = pl;
			sizes[nvec].cl = cl;
			nvec++;
		}
	}

	fprintf(o, "struct lt_zsvec {\n"
		   "\tconst u8 *plain;\n\tunsigned int plain_len;\n"
		   "\tconst u8 *comp;\n\tunsigned int comp_len;\n};\n\n");
	fprintf(o, "static const struct lt_zsvec lt_zsvecs[] __initconst = {\n");
	for (shape = 0; shape < nvec; shape++)
		fprintf(o, "\t{ lt_zsplain%d, %zu, lt_zscomp%d, %zu },\n",
			shape, sizes[shape].pl, shape, sizes[shape].cl);
	fprintf(o, "};\n");
	fclose(o);

	printf("%d vectors, %u blocks total\n", nvec, blocks_total);
	for (shape = 0; shape < 4; shape++)
		printf("  literals %-16s %u\n", lit_name[shape], lit_total[shape]);

	/* THE GATE. A vector set with no Huffman table never enters
	 * HUF_readStats and so never enters the ported file at all. */
	if (lit_total[2] + lit_total[3] < 8) {
		fprintf(stderr,
			"\nREFUSING TO EMIT: only %u of %u blocks carry a\n"
			"Huffman literals section, so these vectors would not\n"
			"reach HUF_readStats and the boot test would prove\n"
			"nothing about the port.\n",
			lit_total[2] + lit_total[3], blocks_total);
		remove(path);
		return 2;
	}
	printf("\nok: %u blocks carry a Huffman literals section\n",
	       lit_total[2] + lit_total[3]);
	return 0;
}
