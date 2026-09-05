/* SPDX-License-Identifier: 0BSD */
/*
 * Differential test for lib/xz/xz_dec_bcj.c -> xz_dec_bcj_rs.rs.
 *
 * Two arms in one binary. The only difference between them is which
 * implementation is called; the corpus, the chunking script and the fake
 * LZMA2 below are shared, byte for byte, by both.
 *
 * Three stages, and the third is the one that matters:
 *
 *   filters    each of the seven filters called DIRECTLY on a byte window,
 *              at a chosen s->pos and x86_prev_mask. Compares the whole
 *              buffer, the return value, and the carried mask.
 *
 *   wrapper    xz_dec_bcj_run() driven through a scripted fake LZMA2, so the
 *              chunk boundaries -- the axis the 16-byte temp buffer exists
 *              for -- can be chosen adversarially rather than hoped for.
 *              Compares the output stream AND the sequence of return codes.
 *
 *   invariant  the streamed output must equal the SAME filter applied to the
 *              whole buffer in one call. This shares no code with the
 *              wrapper, so it can catch a mistake the wrapper and its oracle
 *              would both make -- which is the only kind a two-arm
 *              differential is blind to (logs/hooks.md).
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/xz.h>

struct xz_dec_bcj;
struct xz_dec_lzma2;

/* The oracle -- pristine C, renamed. */
size_t ref_bcj_filter(uint32_t kind, uint32_t pos, uint32_t *prev_mask,
		      uint8_t *buf, size_t size);
size_t ref_state_size(void);
struct xz_dec_bcj *ref_xz_dec_bcj_create(bool single_call);
enum xz_ret ref_xz_dec_bcj_reset(struct xz_dec_bcj *s, uint8_t id);
enum xz_ret ref_xz_dec_bcj_run(struct xz_dec_bcj *s, struct xz_dec_lzma2 *l,
			       struct xz_buf *b);

/* The port. */
size_t rs_bcj_filter(uint32_t kind, uint32_t pos, uint32_t *prev_mask,
		     uint8_t *buf, size_t size);
size_t rust_xz_dec_bcj_size(void);
void rust_xz_dec_bcj_init(void *s, bool single_call);
int xz_dec_bcj_reset(void *s, uint8_t id);
int xz_dec_bcj_run(void *s, struct xz_dec_lzma2 *l, struct xz_buf *b);

#define BCJ_X86      4
#define BCJ_POWERPC  5
#define BCJ_ARM      7
#define BCJ_ARMTHUMB 8
#define BCJ_SPARC    9
#define BCJ_ARM64   10
#define BCJ_RISCV   11

static const uint8_t KINDS[7] = {
	BCJ_X86, BCJ_POWERPC, BCJ_ARM, BCJ_ARMTHUMB,
	BCJ_SPARC, BCJ_ARM64, BCJ_RISCV
};
static const char *const KIND_NAME[7] = {
	"x86", "powerpc", "arm", "armthumb", "sparc", "arm64", "riscv"
};

/* --------------------------------------------------------------------- */

static uint64_t rng_s;

static uint32_t rnd(void)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return (uint32_t)(rng_s >> 32);
}

static uint32_t rnd_n(uint32_t n)
{
	return n ? rnd() % n : 0;
}

/*
 * A buffer that the filters actually bite on. Uniform random bytes hit an
 * x86 E8/E9 opcode about once in 128 and an ARM 0xEB top byte about once in
 * 1024 aligned words, which reaches the interesting branches but not often
 * enough to be the whole corpus. So patterns are planted deliberately, at
 * both aligned and unaligned offsets, and the density is varied per buffer.
 */
static void fill(uint8_t *b, size_t n, uint32_t kind)
{
	uint32_t density = 1 + rnd_n(8);	/* 1 in `density` positions */
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)rnd();

	for (i = 0; i + 8 <= n; i++) {
		if (rnd_n(density * 4) != 0)
			continue;

		switch (kind) {
		case BCJ_X86:
			b[i] = (rnd() & 1) ? 0xE8 : 0xE9;
			/* Half the time make the msbyte test succeed. */
			if (rnd() & 1)
				b[i + 4] = (rnd() & 1) ? 0x00 : 0xFF;
			break;
		case BCJ_POWERPC:
			/* bl: 0x48000001 with the 24-bit displacement free */
			b[i & ~(size_t)3] = 0x48;
			b[(i & ~(size_t)3) + 3] = (uint8_t)(b[(i & ~(size_t)3) + 3] | 1);
			b[(i & ~(size_t)3) + 3] = (uint8_t)(b[(i & ~(size_t)3) + 3] & ~2);
			break;
		case BCJ_ARM:
			b[(i & ~(size_t)3) + 3] = 0xEB;
			break;
		case BCJ_ARMTHUMB:
			b[i | 1] = (uint8_t)(0xF0 | (rnd() & 7));
			if ((i | 1) + 2 < n)
				b[(i | 1) + 2] = (uint8_t)(0xF8 | (rnd() & 7));
			break;
		case BCJ_SPARC:
			/* call: instr >> 22 == 0x100 or 0x1FF */
			b[i & ~(size_t)3] = (rnd() & 1) ? 0x40 : 0x7F;
			b[(i & ~(size_t)3) + 1] = (uint8_t)
				((b[(i & ~(size_t)3)] == 0x40) ? (rnd() & 0x3F)
							       : (0xC0 | (rnd() & 0x3F)));
			break;
		case BCJ_ARM64:
			if (rnd() & 1) {
				/* BL: instr >> 26 == 0x25 */
				b[(i & ~(size_t)3) + 3] = (uint8_t)(0x94 | (rnd() & 3));
			} else {
				/* ADRP: instr & 0x9F000000 == 0x90000000 */
				b[(i & ~(size_t)3) + 3] = (uint8_t)
					(0x90 | (rnd() & 0x60));
			}
			break;
		case BCJ_RISCV:
			if (rnd() & 1) {
				b[i] = 0xEF;			/* JAL  */
				b[i + 1] = (uint8_t)(rnd() & 0xF0);
			} else {
				b[i] = 0x17;			/* AUIPC */
			}
			break;
		default:
			break;
		}
	}
}

/* --------------------------------------------------------------------- */
/* The fake LZMA2: emits a fixed source in a scripted sequence of chunk
 * sizes. Both arms call THIS function -- there is only one of it -- and the
 * driver resets its state before each arm, so any divergence is in the BCJ
 * code and not in what it was fed. */

static struct {
	const uint8_t *src;
	size_t len, pos;
	const uint16_t *chunk;
	size_t nchunk, ci;
	/* Return this instead of XZ_OK on call number `err_at`. A real LZMA2
	 * returns XZ_DATA_ERROR, XZ_MEM_ERROR or XZ_BUF_ERROR on a corrupt or
	 * exhausted stream, and xz_dec_bcj_run() has two `return s.ret` paths
	 * that only those reach. Without this they were dead in this harness. */
	size_t err_at;
	enum xz_ret err;
} fake;

enum xz_ret xz_dec_lzma2_run(struct xz_dec_lzma2 *s, struct xz_buf *b);

enum xz_ret xz_dec_lzma2_run(struct xz_dec_lzma2 *s, struct xz_buf *b)
{
	size_t room = b->out_size - b->out_pos;
	size_t want = fake.chunk[fake.ci++ % fake.nchunk];
	size_t left = fake.len - fake.pos;
	size_t n = want < room ? want : room;

	(void)s;
	if (n > left)
		n = left;

	memcpy(b->out + b->out_pos, fake.src + fake.pos, n);
	b->out_pos += n;
	fake.pos += n;

	if (fake.err_at != 0 && fake.ci == fake.err_at)
		return fake.err;

	return fake.pos == fake.len ? XZ_STREAM_END : XZ_OK;
}

#define MAX_CALLS 4096

struct trace {
	size_t out_len;
	size_t ncall;
	int ret[MAX_CALLS];
	uint16_t got[MAX_CALLS];
};

/* Drive one arm. Returns 0 on a clean finish, 1 if it ran out of calls. */
static int drive(int arm, const uint8_t *src, size_t len, uint8_t id,
		 const uint16_t *chunks, size_t nchunk, size_t out_chunk,
		 bool single_call, size_t err_at, enum xz_ret err,
		 uint8_t *out, size_t cap, struct trace *t)
{
	void *s;
	struct xz_buf b;
	size_t total = 0;
	int r = XZ_OK;

	fake.src = src;
	fake.len = len;
	fake.pos = 0;
	fake.chunk = chunks;
	fake.nchunk = nchunk;
	fake.ci = 0;
	fake.err_at = err_at;
	fake.err = err;

	if (arm == 0) {
		s = ref_xz_dec_bcj_create(single_call);
		if (ref_xz_dec_bcj_reset(s, id) != XZ_OK)
			abort();
	} else {
		s = malloc(rust_xz_dec_bcj_size());
		rust_xz_dec_bcj_init(s, single_call);
		if (xz_dec_bcj_reset(s, id) != XZ_OK)
			abort();
	}

	t->ncall = 0;
	while (t->ncall < MAX_CALLS) {
		size_t room = cap - total;
		size_t want = out_chunk < room ? out_chunk : room;

		b.in = NULL;
		b.in_pos = 0;
		b.in_size = 0;
		b.out = out + total;
		b.out_pos = 0;
		b.out_size = want;

		r = arm == 0 ? (int)ref_xz_dec_bcj_run(s, NULL, &b)
			     : xz_dec_bcj_run(s, NULL, &b);

		t->ret[t->ncall] = r;
		t->got[t->ncall] = (uint16_t)b.out_pos;
		t->ncall++;
		total += b.out_pos;

		if (r != XZ_OK)
			break;
		/* SINGLE-CALL MODE MEANS ONE CALL. xz_dec_run() is documented
		 * to be called exactly once in XZ_SINGLE mode, and
		 * xz_dec_bcj_run() returns XZ_OK with the output left
		 * UNFILTERED when the next filter is not finished -- output a
		 * caller that never calls again will never see filtered.
		 * Calling again anyway would test a contract the kernel does
		 * not have. */
		if (single_call)
			break;
		if (b.out_pos == 0 && want == 0)
			break;
		if (b.out_pos == 0 && fake.pos == fake.len)
			break;
	}

	free(s);
	t->out_len = total;
	return t->ncall >= MAX_CALLS ? 1 : 0;
}

/* --------------------------------------------------------------------- */

static unsigned long long fail_count;

static void hexdump(const char *tag, const uint8_t *b, size_t n)
{
	size_t i;

	printf("  %-8s", tag);
	for (i = 0; i < n && i < 32; i++)
		printf(" %02x", b[i]);
	if (n > 32)
		printf(" ...(%zu)", n);
	printf("\n");
}

static void mismatch(const char *what, uint32_t kind, unsigned long long run)
{
	printf("MISMATCH  %s  filter=%s  run=%llu\n", what,
	       KIND_NAME[kind == BCJ_X86 ? 0 : kind == BCJ_POWERPC ? 1 :
			 kind == BCJ_ARM ? 2 : kind == BCJ_ARMTHUMB ? 3 :
			 kind == BCJ_SPARC ? 4 : kind == BCJ_ARM64 ? 5 : 6],
	       run);
	fail_count++;
}

#define BUFMAX 4096

int main(int argc, char **argv)
{
	unsigned long long runs = argc > 1 ? strtoull(argv[1], NULL, 0) : 50000;
	unsigned long long seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 20260903;
	unsigned long long i;
	unsigned long long filter_cases = 0, wrap_cases = 0, inv_cases = 0;
	unsigned long long filtered_bytes = 0;
	static uint8_t src[BUFMAX], a[BUFMAX], c[BUFMAX];
	static uint8_t oa[BUFMAX * 2], ob[BUFMAX * 2], whole[BUFMAX];
	static struct trace ta, tb;
	uint16_t chunks[8];

	rng_s = seed ? seed : 1;

	printf("xz_dec_bcj differential: %llu runs, seed %llu\n", runs, seed);
	printf("oracle struct xz_dec_bcj: %zu bytes; port: %zu bytes\n",
	       ref_state_size(), rust_xz_dec_bcj_size());
	if (rust_xz_dec_bcj_size() == 0 || rust_xz_dec_bcj_size() > 256) {
		printf("IMPLAUSIBLE state size\n");
		return 2;
	}

	/* ---- stage 0: every Filter ID through xz_dec_bcj_reset() ----
	 *
	 * This is the one place the port deliberately differs from the C: the
	 * Rust has no BCJ_IA64 arm, because CONFIG_XZ_DEC_IA64 has no Kconfig
	 * stanza in 6.18 and the oracle here is compiled without XZ_DEC_IA64
	 * for the same reason. So the two must agree on all 256 ids -- and
	 * until an adversarial review pointed it out, nothing tested that
	 * reset() rejects anything at all. */
	{
		struct xz_dec_bcj *ra = ref_xz_dec_bcj_create(false);
		void *rb = malloc(rust_xz_dec_bcj_size());
		unsigned id;

		rust_xz_dec_bcj_init(rb, false);
		for (id = 0; id < 256; id++) {
			int va = (int)ref_xz_dec_bcj_reset(ra, (uint8_t)id);
			int vb = xz_dec_bcj_reset(rb, (uint8_t)id);

			if (va != vb) {
				printf("MISMATCH  reset(%u)  ref=%d rs=%d\n",
				       id, va, vb);
				fail_count++;
			}
		}
		printf("  reset      256 Filter IDs, %s\n",
		       fail_count ? "MISMATCHED" : "identical verdicts");
		free(ra);
		free(rb);
		if (fail_count)
			goto done;
	}

	/* ---- stage 1: the filters, called directly ---- */
	for (i = 0; i < runs; i++) {
		uint32_t kind = KINDS[rnd_n(7)];
		size_t len;
		uint32_t pos, m_a, m_b, seed_mask;
		size_t ra, rb;

		/* Lengths clustered at the boundaries every filter checks. */
		switch (rnd_n(4)) {
		case 0:  len = rnd_n(24); break;
		case 1:  len = rnd_n(80); break;
		case 2:  len = 16 + rnd_n(200); break;
		default: len = rnd_n(BUFMAX); break;
		}

		switch (rnd_n(4)) {
		case 0:  pos = 0; break;
		case 1:  pos = rnd_n(4096); break;
		case 2:  pos = 0xFFFFFF00u + rnd_n(256); break;
		default: pos = rnd(); break;
		}
		/* s->pos is only ever advanced by whole filtered runs, but it
		 * is a bare uint32_t and the filters subtract it, so the wrap
		 * is reachable on a >4 GiB block. Test it deliberately. */

		seed_mask = rnd_n(16);
		m_a = seed_mask;
		m_b = seed_mask;

		fill(src, len, kind);
		memcpy(a, src, len);
		memcpy(c, src, len);

		ra = ref_bcj_filter(kind, pos, &m_a, a, len);
		rb = rs_bcj_filter(kind, pos, &m_b, c, len);

		if (ra != rb) {
			mismatch("filter return value", kind, i);
			printf("  len=%zu pos=%08x mask=%u  ref=%zu rs=%zu\n",
			       len, pos, seed_mask, ra, rb);
		} else if (memcmp(a, c, len) != 0) {
			size_t k;

			mismatch("filter output", kind, i);
			for (k = 0; k < len && a[k] == c[k]; k++)
				;
			printf("  len=%zu pos=%08x mask=%u  first diff at %zu\n",
			       len, pos, seed_mask, k);
			hexdump("in", src + (k > 8 ? k - 8 : 0), 24);
			hexdump("ref", a + (k > 8 ? k - 8 : 0), 24);
			hexdump("rs", c + (k > 8 ? k - 8 : 0), 24);
		} else if (m_a != m_b) {
			mismatch("carried x86_prev_mask", kind, i);
			printf("  len=%zu pos=%08x mask=%u  ref=%u rs=%u\n",
			       len, pos, seed_mask, m_a, m_b);
		}

		filtered_bytes += ra;
		filter_cases++;
		if (fail_count > 8)
			goto done;
	}

	/* ---- stage 2 and 3: the wrapper, and the chunking invariant ---- */
	for (i = 0; i < runs; i++) {
		uint32_t kind = KINDS[rnd_n(7)];
		size_t len = 1 + rnd_n(1500);
		size_t out_chunk;
		bool single = false;
		uint32_t m = 0;
		size_t j, n, err_at;
		enum xz_ret err;
		int over_a, over_b;

		n = 1 + rnd_n(8);
		for (j = 0; j < n; j++) {
			/* Chunk sizes clustered around the 16-byte temp
			 * buffer, where the straddle logic lives. */
			switch (rnd_n(4)) {
			case 0:  chunks[j] = (uint16_t)(1 + rnd_n(4)); break;
			case 1:  chunks[j] = (uint16_t)(1 + rnd_n(20)); break;
			case 2:  chunks[j] = (uint16_t)(1 + rnd_n(64)); break;
			default: chunks[j] = (uint16_t)(1 + rnd_n(600)); break;
			}
		}

		switch (rnd_n(7)) {
		case 0:  out_chunk = 1 + rnd_n(4); break;
		case 1:  out_chunk = 1 + rnd_n(17); break;
		case 2:  out_chunk = 1 + rnd_n(64); break;
		case 3:  out_chunk = 1 + rnd_n(300); break;
		case 4:  out_chunk = BUFMAX; break;
		case 5:  out_chunk = BUFMAX; single = true; break;
		/* Single-call mode with an output buffer too small for the
		 * stream. This is the ONLY way to reach
		 *     if (ret != STREAM_END && (ret != OK || single_call))
		 *         return ret;
		 * with ret == XZ_OK, and it is reachable in the kernel:
		 * decompress_unxz.c uses XZ_SINGLE for the in-place path. */
		default: out_chunk = 1 + rnd_n(len); single = true; break;
		}

		/* SINGLE-CALL MODE IS A DIFFERENT CONTRACT, and driving it like
		 * the multi-call one tests something the kernel never does.
		 * xz_dec_bcj_run() returns immediately when the next filter
		 * returns XZ_OK in single-call mode -- leaving that output
		 * UNFILTERED for a caller that will never call again. So in
		 * single-call mode the whole stream has to arrive in one
		 * xz_dec_lzma2_run(), which is exactly what a real LZMA2
		 * decoder does when XZ_SINGLE was requested. */
		if (single) {
			n = 1;
			chunks[0] = 0xFFFF;
		}

		/* One run in six makes the next filter in the chain fail, which
		 * is the only thing that reaches xz_dec_bcj_run()'s two error
		 * propagations. Both arms get the SAME failure. */
		{
			static const enum xz_ret ERRS[3] = {
				XZ_DATA_ERROR, XZ_MEM_ERROR, XZ_BUF_ERROR
			};

			if (rnd_n(6) == 0) {
				err_at = 1 + rnd_n(6);
				err = ERRS[rnd_n(3)];
			} else {
				err_at = 0;
				err = XZ_OK;
			}
		}

		fill(src, len, kind);

		memset(oa, 0xAA, sizeof(oa));
		memset(ob, 0x55, sizeof(ob));
		over_a = drive(0, src, len, (uint8_t)kind, chunks, n,
			       out_chunk, single, err_at, err,
			       oa, sizeof(oa), &ta);
		over_b = drive(1, src, len, (uint8_t)kind, chunks, n,
			       out_chunk, single, err_at, err,
			       ob, sizeof(ob), &tb);

		if (over_a != over_b) {
			mismatch("call-limit reached by only one arm", kind, i);
		} else if (ta.out_len != tb.out_len) {
			mismatch("wrapper output length", kind, i);
			printf("  len=%zu out_chunk=%zu  ref=%zu rs=%zu\n",
			       len, out_chunk, ta.out_len, tb.out_len);
		} else if (memcmp(oa, ob, ta.out_len) != 0) {
			size_t k;

			for (k = 0; k < ta.out_len && oa[k] == ob[k]; k++)
				;
			mismatch("wrapper output", kind, i);
			printf("  len=%zu out_chunk=%zu  first diff at %zu\n",
			       len, out_chunk, k);
			hexdump("ref", oa + (k > 8 ? k - 8 : 0), 24);
			hexdump("rs", ob + (k > 8 ? k - 8 : 0), 24);
		} else if (ta.ncall != tb.ncall ||
			   memcmp(ta.ret, tb.ret, ta.ncall * sizeof(int)) != 0 ||
			   memcmp(ta.got, tb.got, ta.ncall * sizeof(uint16_t)) != 0) {
			mismatch("wrapper call trace", kind, i);
			printf("  len=%zu out_chunk=%zu  calls ref=%zu rs=%zu\n",
			       len, out_chunk, ta.ncall, tb.ncall);
		}
		wrap_cases++;

		/* The invariant: chunking must not change the answer. The
		 * reference here is the filter applied to the whole buffer in
		 * ONE call, which shares no code with the wrapper. */
		if (!over_a && !single && err_at == 0 && ta.out_len == len) {
			memcpy(whole, src, len);
			m = 0;
			ref_bcj_filter(kind, 0, &m, whole, len);
			if (memcmp(whole, ob, len) != 0) {
				size_t k;

				for (k = 0; k < len && whole[k] == ob[k]; k++)
					;
				mismatch("chunking changed the answer", kind, i);
				printf("  len=%zu out_chunk=%zu chunks[0]=%u"
				       "  first diff at %zu\n",
				       len, out_chunk, chunks[0], k);
				hexdump("whole", whole + (k > 8 ? k - 8 : 0), 24);
				hexdump("streamed", ob + (k > 8 ? k - 8 : 0), 24);
			}
			inv_cases++;
		}

		if (fail_count > 8)
			goto done;
	}

done:
	printf("\n");
	printf("  filters    %llu cases, %llu bytes filtered\n",
	       filter_cases, filtered_bytes);
	printf("  wrapper    %llu cases\n", wrap_cases);
	printf("  invariant  %llu cases\n", inv_cases);
	printf("\n");
	if (fail_count) {
		printf("FAILED -- %llu mismatches\n", fail_count);
		return 1;
	}
	printf("OK -- 0 mismatches\n");
	return 0;
}
