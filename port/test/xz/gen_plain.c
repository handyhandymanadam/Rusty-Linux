/* SPDX-License-Identifier: 0BSD */
/*
 * Emit the plaintext for one kernel vector on stdout.
 *
 *     gen_plain <filter-id> <length>
 *
 * THE RULES IN lt_xgen() BELOW ARE THE SAME RULES lib/libtest.c USES. If the
 * two drift, the kernel test compares against a plaintext nothing produced
 * and fails for a reason that has nothing to do with the port. Change both or
 * neither -- gen-vectors.sh diffs them on every run.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint32_t u32;

/* LT_XGEN_BEGIN */
static void lt_xgen(int kind, u8 *b, unsigned int n)
{
	u32 s = 0x1234567u + (u32)kind * 2654435761u;
	unsigned int i;

	for (i = 0; i < n; i++) {
		s = s * 1103515245u + 12345u;
		/* Repeat an earlier run a third of the time, so the stream
		 * actually compresses and LZMA2 emits matches rather than a
		 * wall of literals. */
		if (i >= 64 && ((s >> 16) & 3) == 0)
			b[i] = b[i - 64];
		else
			b[i] = (u8)(s >> 24);
	}

	/* Plant the branch patterns this filter rewrites. Every 8 bytes, so
	 * they land on the 4-byte grid the word-oriented filters look at and
	 * on the 2-byte grid the others use. */
	for (i = 0; i + 8 < n; i += 8) {
		switch (kind) {
		case 4:				/* x86: CALL rel32 */
			b[i] = 0xE8;
			b[i + 4] = (i & 8) ? 0x00 : 0xFF;
			break;
		case 5:				/* PowerPC: bl */
			b[i] = 0x48;
			b[i + 3] = 0x01;
			break;
		case 7:				/* ARM: BL */
			b[i + 3] = 0xEB;
			break;
		case 8:				/* ARM-Thumb: BL pair */
			b[i + 1] = 0xF0;
			b[i + 3] = 0xF8;
			break;
		case 9:				/* SPARC: CALL */
			b[i] = 0x40;
			b[i + 1] = 0x00;
			break;
		case 10:			/* ARM64: BL */
			b[i + 3] = 0x94;
			break;
		case 11:			/* RISC-V: JAL */
			b[i] = 0xEF;
			b[i + 1] = 0x00;
			break;
		default:
			break;
		}
	}
}
/* LT_XGEN_END */

int main(int argc, char **argv)
{
	int kind;
	unsigned int n;
	u8 *b;

	if (argc != 3)
		return 2;

	kind = atoi(argv[1]);
	n = (unsigned int)strtoul(argv[2], NULL, 0);
	b = malloc(n);
	if (!b)
		return 2;

	lt_xgen(kind, b, n);
	if (fwrite(b, 1, n, stdout) != n)
		return 2;

	free(b);
	return 0;
}
