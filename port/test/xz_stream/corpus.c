/* SPDX-License-Identifier: GPL-2.0
 *
 * Corpus for the lib/xz/xz_dec_stream.c differential.
 *
 * Streams are produced by SYSTEM liblzma, which is derived from nothing in
 * this tree. That matters twice over: it is a real .xz encoder rather than
 * something we wrote, and it gives the harness an INDEPENDENT ORACLE -- if
 * both the kernel C and the Rust share a bug, liblzma will not.
 *
 * The zlib harness went 30,000 runs without that check and it turned out to
 * be truncating most of its decodes. See logs/build-limits.md, 2026-09-04.
 */
#include <stdlib.h>
#include <string.h>
#include <lzma.h>

static unsigned long rs;
static unsigned rnd(void) { rs = rs * 6364136223846793005ULL + 1442695040888963407ULL;
                            return (unsigned)(rs >> 33); }
void corpus_seed(unsigned long s) { rs = s ? s : 0x9e3779b97f4a7c15ULL; }

/* Plaintext shapes. The container parser cares about SIZES and BOUNDARIES far
 * more than about content, so the spread here is deliberately over lengths --
 * including 0, 1, and sizes either side of the block and temp-buffer edges. */
unsigned long corpus_plain(int kind, unsigned char *buf, unsigned long cap)
{
	unsigned long n, i;

	switch (kind & 7) {
	case 0: n = 0; break;
	case 1: n = 1; break;
	case 2: n = 1 + rnd() % 64; break;
	case 3: n = 1 + rnd() % 4096; break;
	case 4: n = 4096 + rnd() % 4096; break;
	case 5: n = 1 + rnd() % 200000; break;
	case 6: n = 1 + rnd() % 700000; break;
	default: n = 1 + rnd() % 20; break;
	}
	if (n > cap) n = cap;

	switch (kind & 3) {
	case 0:  for (i = 0; i < n; i++) buf[i] = 0; break;                 /* runs */
	case 1:  for (i = 0; i < n; i++) buf[i] = (unsigned char)rnd(); break; /* random */
	case 2:  for (i = 0; i < n; i++) buf[i] = (unsigned char)(i & 0x3f); break;
	default: for (i = 0; i < n; i++)                                     /* mixed */
			buf[i] = (unsigned char)((i % 71 < 40) ? (rnd() & 0xff) : (i & 0xff));
		break;
	}
	return n;
}

/* Compress to a real .xz stream. `check` selects the integrity check, which is
 * the thing xz_dec_stream.c branches on hardest: NONE, CRC32, CRC64, SHA256. */
long corpus_xz(const unsigned char *src, unsigned long n,
	       unsigned char *dst, unsigned long cap, int check, unsigned preset)
{
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret r;
	lzma_check ck;

	switch (check & 3) {
	case 0:  ck = LZMA_CHECK_NONE;   break;
	case 1:  ck = LZMA_CHECK_CRC32;  break;
	case 2:  ck = LZMA_CHECK_CRC64;  break;
	default: ck = LZMA_CHECK_SHA256; break;
	}

	r = lzma_easy_encoder(&s, preset % 10, ck);
	if (r != LZMA_OK) return -1;

	s.next_in = src;   s.avail_in = n;
	s.next_out = dst;  s.avail_out = cap;
	r = lzma_code(&s, LZMA_FINISH);
	{
		long out = (long)(cap - s.avail_out);
		lzma_end(&s);
		return (r == LZMA_STREAM_END) ? out : -1;
	}
}

/* THE INDEPENDENT ORACLE: decode with liblzma, which shares no code with
 * either arm. Returns the decoded length, or -1. */
long corpus_xz_decode(const unsigned char *src, unsigned long n,
		      unsigned char *dst, unsigned long cap)
{
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret r;

	if (lzma_stream_decoder(&s, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK)
		return -1;
	s.next_in = src;   s.avail_in = n;
	s.next_out = dst;  s.avail_out = cap;
	r = lzma_code(&s, LZMA_FINISH);
	{
		long out = (long)(cap - s.avail_out);
		lzma_end(&s);
		return (r == LZMA_STREAM_END) ? out : -1;
	}
}

/* ---------------------------------------------------------------------------
 * Reaching the Block Header body.
 *
 * An adversarial review on 2026-09-04 found that this harness could never
 * execute dec_block_header()'s body. lzma_easy_encoder emits one Block with
 * Flags 0x00, and dec_block_header() validates the header CRC32 FIRST
 * (xz_dec_stream.c:457) -- so every bit-flip died at that gate, leaving
 * dec_vli() over temp.buf, the BCJ arm, both "Valid Filter Flags always take
 * at least two bytes" bounds checks and the Header Padding loop unexecuted.
 *
 * The fix is to mutate the Block Header and then REPAIR its CRC32, so the
 * mutation survives the gate and reaches the code under test.
 *
 * Layout, xz_stream.h: bytes 0..11 are the Stream Header. The Block Header
 * starts at 12; its first byte encodes its size as (b + 1) * 4; its last four
 * bytes are a CRC32 over everything before them.
 * ------------------------------------------------------------------------ */

/* Returns 1 if a Block Header byte was mutated and its CRC repaired. */
int corpus_mutate_block_header(unsigned char *s, unsigned long len,
			       unsigned (*rnd)(void))
{
	unsigned long bh, hsize, body, off;
	uint32_t crc;

	bh = 12;
	if (len < bh + 8)
		return 0;
	if (s[bh] == 0)			/* 0 marks the Index, not a Block */
		return 0;
	hsize = ((unsigned long)s[bh] + 1) * 4;
	if (bh + hsize > len || hsize < 8)
		return 0;

	body = hsize - 4;		/* everything the CRC covers */
	/* Byte 0 is the size field itself; changing it desynchronises the whole
	 * stream rather than testing the header parser, so leave it alone. */
	off = 1 + (rnd() % (body - 1));
	s[bh + off] ^= (unsigned char)(1u << (rnd() % 8));

	crc = lzma_crc32(s + bh, body, 0);
	s[bh + body + 0] = (unsigned char)(crc);
	s[bh + body + 1] = (unsigned char)(crc >> 8);
	s[bh + body + 2] = (unsigned char)(crc >> 16);
	s[bh + body + 3] = (unsigned char)(crc >> 24);
	return 1;
}
