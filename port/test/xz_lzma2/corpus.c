/* SPDX-License-Identifier: GPL-2.0
 *
 * Corpus for the lib/xz/xz_dec_lzma2.c differential.
 *
 * RAW LZMA2 chunk streams, produced by SYSTEM liblzma's raw encoder -- which
 * is exactly what xz_dec_lzma2_run() consumes. Driving that function DIRECTLY
 * is the point: an adversarial review of the xz_dec_stream port on 2026-09-04
 * showed that testing only through the full pipeline left whole functions
 * unreachable, because the container layer rejects malformed input before the
 * inner layer ever sees it.
 *
 * liblzma is derived from nothing in this tree, so it is also the INDEPENDENT
 * ORACLE -- the check that can see a bug the kernel C and the port share.
 */
#include <stdlib.h>
#include <string.h>
#include <lzma.h>

static unsigned long rs;
static unsigned rnd(void) { rs = rs * 6364136223846793005ULL + 1442695040888963407ULL;
                            return (unsigned)(rs >> 33); }
void corpus_seed(unsigned long s) { rs = s ? s : 0x9e3779b97f4a7c15ULL; }

/* Plaintext shapes. LZMA2 cares about match distances and literal runs, so the
 * spread is over REPETITION STRUCTURE, not just length. */
unsigned long corpus_plain(int kind, unsigned char *buf, unsigned long cap)
{
	unsigned long n, i;

	switch (kind & 7) {
	case 0: n = 0; break;
	case 1: n = 1 + rnd() % 8; break;
	case 2: n = 1 + rnd() % 300; break;
	case 3: n = 1 + rnd() % 9000; break;
	case 4: n = 1 + rnd() % 70000; break;
	default: n = 1 + rnd() % 300000; break;
	}
	if (n > cap) n = cap;

	switch (kind & 7) {
	case 0: case 1:
		for (i = 0; i < n; i++) buf[i] = (unsigned char)rnd();
		break;
	case 2:  /* long runs -- exercises dict_repeat with short distances */
		for (i = 0; i < n; i++) buf[i] = (unsigned char)(i / 64);
		break;
	case 3:  /* a repeating block -- long match distances */
		for (i = 0; i < n; i++) buf[i] = (unsigned char)((i % 1021) * 7);
		break;
	case 4:  /* incompressible -- forces uncompressed LZMA2 chunks */
		for (i = 0; i < n; i++) buf[i] = (unsigned char)rnd();
		break;
	case 5:  /* mostly zero with rare noise */
		memset(buf, 0, n);
		for (i = 0; i < n / 512 + 1; i++) buf[rnd() % (n ? n : 1)] = (unsigned char)rnd();
		break;
	default: /* mixed */
		for (i = 0; i < n; i++)
			buf[i] = (unsigned char)((i % 71 < 40) ? (rnd() & 0xff) : (i & 0x1f));
		break;
	}
	return n;
}

/* The LZMA2 Filter Properties byte the kernel's xz_dec_lzma2_reset() takes.
 * xz_lzma2.h: dict_size = (2 | (props & 1)) << (props / 2 + 11). */
static int props_for_dict(uint32_t dict)
{
	int p;

	for (p = 0; p < 41; p++)
		if (((uint32_t)(2 | (p & 1)) << (p / 2 + 11)) >= dict)
			return p;
	return 40;
}

/* Encode `src` as a raw LZMA2 chunk stream. Returns the length, or -1.
 * `*props_out` receives the byte xz_dec_lzma2_reset() needs, and `*dict_out`
 * the dictionary size that byte encodes. */
long corpus_lzma2(const unsigned char *src, unsigned long n,
		  unsigned char *dst, unsigned long cap, unsigned preset,
		  int *props_out, uint32_t *dict_out)
{
	lzma_options_lzma opt;
	lzma_filter f[2];
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret r;
	int p;

	if (lzma_lzma_preset(&opt, preset % 10))
		return -1;
	/* Keep the dictionary small enough that the harness can afford it and
	 * large enough to still exercise long distances. */
	if (opt.dict_size > (1u << 22))
		opt.dict_size = 1u << 22;

	p = props_for_dict(opt.dict_size);
	opt.dict_size = (uint32_t)(2 | (p & 1)) << (p / 2 + 11);

	f[0].id = LZMA_FILTER_LZMA2; f[0].options = &opt;
	f[1].id = LZMA_VLI_UNKNOWN;  f[1].options = NULL;

	if (lzma_raw_encoder(&s, f) != LZMA_OK)
		return -1;
	s.next_in = src;  s.avail_in = n;
	s.next_out = dst; s.avail_out = cap;
	r = lzma_code(&s, LZMA_FINISH);
	{
		long out = (long)(cap - s.avail_out);
		lzma_end(&s);
		if (r != LZMA_STREAM_END)
			return -1;
		*props_out = p;
		*dict_out = opt.dict_size;
		return out;
	}
}

/* THE INDEPENDENT ORACLE: decode the same raw LZMA2 with liblzma. */
long corpus_lzma2_decode(const unsigned char *src, unsigned long n,
			 unsigned char *dst, unsigned long cap, uint32_t dict)
{
	lzma_options_lzma opt;
	lzma_filter f[2];
	lzma_stream s = LZMA_STREAM_INIT;
	lzma_ret r;

	if (lzma_lzma_preset(&opt, 6))
		return -1;
	opt.dict_size = dict;
	f[0].id = LZMA_FILTER_LZMA2; f[0].options = &opt;
	f[1].id = LZMA_VLI_UNKNOWN;  f[1].options = NULL;

	if (lzma_raw_decoder(&s, f) != LZMA_OK)
		return -1;
	s.next_in = src;  s.avail_in = n;
	s.next_out = dst; s.avail_out = cap;
	r = lzma_code(&s, LZMA_FINISH);
	{
		long out = (long)(cap - s.avail_out);
		lzma_end(&s);
		return (r == LZMA_STREAM_END || r == LZMA_OK) ? out : -1;
	}
}
