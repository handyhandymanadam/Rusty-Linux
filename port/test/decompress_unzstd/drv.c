/*
 * port/test/decompress_unzstd/drv.c -- userspace differential for
 * lib/decompress_unzstd.c.
 *
 * Unlike unlz4/unlzo/unxz, no third-party library or shared-pristine-backend
 * trick is needed for isolation: this wrapper calls the real, exported
 * `zstd_*` kernel API (lib/zstd/zstd_decompress_module.c) directly, and
 * that's exactly what BOTH arms here link against -- the pristine C oracle
 * (`cref_unzstd`, built from port/pristine/lib/decompress_unzstd.c with its
 * own entry renamed) and the Rust wrapper under test. The backend behind
 * those zstd_* symbols is compiled from the plain-C arm of lib/zstd/ (the
 * CONFIG_RUST=n Makefile branch: common/entropy_common.c, error_private.c,
 * fse_decompress.c, zstd_common.c, decompress/huf_decompress.c, unmodified
 * decompress/zstd_ddict.c, zstd_decompress.c, zstd_decompress_block.c) --
 * same precedent as decompress_unxz's shared-pristine-backend choice: what's
 * under test is THIS wrapper's buffer/error/window-size logic, not which
 * language the backend happens to be compiled from on either arm.
 *
 * Ground truth is independent of both arms: each case is a (real
 * `zstd`-CLI-produced archive, plaintext) pair, output compared against the
 * plaintext directly.
 *
 * Covers, per the pattern the last four reviews established, AND fixed by
 * adversarial review of this file's own first version (commit 05c7d1a):
 *  - buffer mode (fill=NULL, flush=NULL -> decompress_single()) and
 *    fill/flush callback mode (-> the streaming loop in __unzstd()), not
 *    just one;
 *  - a corrupted-payload-byte comparison that checks the exact return code,
 *    the exact bytes/length written by each arm before failing, AND the
 *    exact error() message text -- not return code alone, which cannot
 *    distinguish "failed for the right reason" from "failed for a
 *    completely different one" (finding E: an earlier version compared
 *    only `c_ret != r_ret`, and both arms return -1 for nearly every
 *    corrupt input regardless of which internal check actually fired);
 *  - the corruption offset computed from the REAL frame header size
 *    (zstd_get_frame_header()'s own header_size field, not a guessed
 *    constant) plus the 3-byte block header, landing inside block payload;
 *  - an explicit assertion that the corruption was actually DETECTED
 *    (finding C: a case too small to corrupt was silently "passing" by
 *    doing nothing at all -- skips are now counted and reported
 *    separately, never folded into the pass count, and every non-skipped
 *    corrupt case requires the C oracle to actually report an error, since
 *    a corrupted-but-undetected case would prove nothing about the port);
 *  - the poison-detection gate using the "0/$n_poison cases passed"
 *    exact-count check, run across ALL THREE stages -- buffer mode,
 *    callback mode, AND the corrupt-case comparison (finding D: an earlier
 *    version's DBZ_PROVE_CAN_FAIL=1 skipped the callback-mode and
 *    corrupt-case stages entirely, so "0/N cases passed" was only ever a
 *    true statement about buffer mode, not about the harness as a whole).
 *
 * DBZ_PROVE_CAN_FAIL=1 poisons each stage's own comparison -- a flipped
 * output byte for buffer and callback mode, a forced-wrong return code for
 * the corrupt-case comparison -- proving each comparison can independently
 * fail, not just one of the three.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/zstd.h>

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_unzstd(unsigned char *input, long in_len, fill_fn fill,
			flush_fn flush, unsigned char *output, long *posp,
			error_fn error);

extern int unzstd(unsigned char *input, long in_len, fill_fn fill,
		   flush_fn flush, unsigned char *output, long *posp,
		   error_fn error);

/* Userspace stand-in for the vmalloc the Rust side calls (see
 * decompress_unzstd_rs.rs and its C alloc-shim neighbour).
 *
 * `size` is `unsigned long`, not `unsigned int` -- found by adversarial
 * review (finding A): an earlier version narrowed this to 32 bits, exactly
 * matching the bug it was meant to catch in the shipped C shim, so both
 * arms truncated identically and agreed with each other while being wrong
 * in the same way. A stand-in that reproduces the defect it exists to
 * catch is worse than no stand-in.
 */
void *decompress_unzstd_alloc(unsigned long size) { return malloc(size); }
void vfree(const void *p) { free((void *)p); }

static char c_last_error[256];
static char r_last_error[256];
static void record_c_error(char *msg) { snprintf(c_last_error, sizeof(c_last_error), "%s", msg); }
static void record_r_error(char *msg) { snprintf(r_last_error, sizeof(r_last_error), "%s", msg); }

static unsigned char *read_file(const char *path, long *out_len)
{
	FILE *f = fopen(path, "rb");
	unsigned char *buf;
	long n;

	if (!f) { perror(path); exit(2); }
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n ? (size_t)n : 1);
	if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("fread"); exit(2); }
	fclose(f);
	*out_len = n;
	return buf;
}

/* fill/flush-callback mode -- both have no user-data parameter (see
 * decompress_unzstd_rs.rs's FillFn/FlushFn), so like the kernel's own
 * callers this reads from and writes to file-scope globals, reset before
 * each call. */
static const unsigned char *cb_src;
static long cb_src_len, cb_src_pos;
static unsigned char *cb_dst;
static long cb_dst_pos;
/* 0 = no cap (run_callback_mode's known-valid case: real content size always
 * matches the known plaintext length exactly, so cb_dst is sized for it).
 * Nonzero only in run_corrupt_case, as a hard backstop independent of any
 * reasoning about how far a corrupted stream could get zstd to write before
 * it errors -- see that function's comment. */
static long cb_dst_cap;

static long cb_fill(void *buf, unsigned long len)
{
	long n = cb_src_len - cb_src_pos;

	if (n > (long)len)
		n = (long)len;
	if (n < 0)
		n = 0;
	memcpy(buf, cb_src + cb_src_pos, (size_t)n);
	cb_src_pos += n;
	return n;
}

static long cb_flush(void *buf, unsigned long len)
{
	long n = (long)len;

	if (cb_dst_cap > 0 && cb_dst_pos + n > cb_dst_cap) {
		/* Clamp rather than overrun cb_dst. A short return makes
		 * __unzstd's own `f(...) != out.pos` check fail the call
		 * with "Failed to flush()" -- a real, comparable error code
		 * on both arms, not a crash. */
		n = cb_dst_cap - cb_dst_pos;
		if (n < 0)
			n = 0;
	}
	memcpy(cb_dst + cb_dst_pos, buf, (size_t)n);
	cb_dst_pos += n;
	return n;
}

/* Runs one (archive, plaintext) pair through fill+flush mode on both
 * implementations, comparing output and exact return code. Returns 1 on
 * any mismatch (printing why), 0 if both sides agree with the plaintext.
 * Under prove_can_fail, poisons the Rust output before comparing it (same
 * shape as main()'s buffer-mode poison) rather than skipping this stage
 * entirely -- finding D. */
static int run_callback_mode(const char *arc_path, const unsigned char *arc, long arc_len,
			      const unsigned char *plain, long plain_len, int prove_can_fail)
{
	long outcap = plain_len + 65536;
	unsigned char *c_out = calloc(1, (size_t)outcap);
	unsigned char *r_out = calloc(1, (size_t)outcap);
	int c_ret, r_ret, ok = 1;

	cb_dst_cap = 0;

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = c_out; cb_dst_pos = 0;
	c_last_error[0] = 0;
	c_ret = cref_unzstd(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_c_error);
	if (c_ret != 0) {
		printf("FAIL %s (fill/flush): C oracle returned %d (%s)\n", arc_path, c_ret, c_last_error);
		ok = 0;
	} else if (cb_dst_pos != plain_len || memcmp(c_out, plain, (size_t)plain_len) != 0) {
		printf("FAIL %s (fill/flush): C oracle output != plaintext\n", arc_path);
		ok = 0;
	}

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = r_out; cb_dst_pos = 0;
	r_last_error[0] = 0;
	r_ret = unzstd(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_r_error);
	if (r_ret != 0) {
		printf("FAIL %s (fill/flush): Rust returned %d (%s)\n", arc_path, r_ret, r_last_error);
		ok = 0;
	} else {
		if (prove_can_fail && plain_len > 0)
			r_out[0] ^= 0xFF;
		if (cb_dst_pos != plain_len || memcmp(r_out, plain, (size_t)plain_len) != 0) {
			if (!prove_can_fail)
				printf("FAIL %s (fill/flush): Rust output != plaintext\n", arc_path);
			ok = 0;
		}
	}

	if (ok && c_ret != r_ret) {
		printf("FAIL %s (fill/flush): return code mismatch C=%d Rust=%d\n",
		       arc_path, c_ret, r_ret);
		ok = 0;
	}

	if (ok)
		printf("ok   %s (fill/flush): %ld bytes\n", arc_path, plain_len);

	free(c_out);
	free(r_out);
	return !ok;
}

/*
 * Corrupts one byte INSIDE the first block's compressed PAYLOAD -- never
 * the frame header or the 3-byte block header -- and checks C and Rust
 * agree in full: exact return code, exact bytes/length actually written,
 * AND the exact error() message text (finding E -- an earlier version
 * compared only the return code, which both arms set to -1 for nearly
 * every corrupt input regardless of which internal check actually fired,
 * so "failed for the right reason" was never actually checked).
 *
 * The offset is computed from zstd_get_frame_header()'s own `header_size`
 * field for THIS archive, not a guessed constant: found the hard way on
 * unlzo and unxz that a hardcoded offset can land inside a format header,
 * where a structural check (there: LZO block-length sanity / xz block-CRC)
 * catches the corruption before the payload decoder the test means to
 * exercise ever runs, silently testing nothing. header_size + 3 (the block
 * header) + 4 (a few bytes of margin into the payload) is verified >
 * header_size by construction, not assumed.
 *
 * Deliberately run through FILL/FLUSH mode, not buffer mode: buffer mode's
 * out_len is `UINTPTR_MAX - (uintptr_t)out_buf` (see __unzstd()'s own
 * comment) -- effectively no real ceiling at all, trusted upstream only
 * because the real single-call caller already owns a destination region
 * sized for the (uncorrupted) frame's own declared content size. Handing
 * that path a CORRUPTED frame gives zstd_decompress_dctx a dst_capacity
 * that does not describe this test's actual scratch allocation, which is
 * exactly the shape of bug that made an earlier version of unlz4's harness
 * segfault itself on corrupted input. Fill/flush mode has no such gap: the
 * real internal output buffer is the fixed ZSTD_IOBUF_SIZE (128KB) chunk
 * decompress_unzstd_alloc() actually allocates, and flush() is called on
 * every full or final chunk -- cb_dst below only ever needs to hold a
 * generous multiple of the known real plaintext size, not "however much a
 * corrupted stream might convince zstd to write in one call."
 *
 * Sets `*skipped` and returns 0 if the archive is too small to corrupt
 * meaningfully (the caller counts this separately from both passes and
 * failures -- finding C). Otherwise returns 1 on any mismatch, 0 if both
 * arms agree.
 */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len,
			     long plain_len, int prove_can_fail, int *skipped)
{
	zstd_frame_header header;
	size_t hret;
	long payload_off;
	unsigned char *bad1, *bad2;
	long cb_cap;
	int c_ret, r_ret;
	unsigned char *c_dst, *r_dst;
	long c_len, r_len;

	*skipped = 0;

	hret = zstd_get_frame_header(&header, arc, (size_t)arc_len);
	if (zstd_is_error(hret) || hret != 0) {
		printf("skip %s (corrupt): could not parse frame header for offset\n", arc_path);
		*skipped = 1;
		return 0;
	}
	payload_off = (long)header.headerSize + 3 + 4;
	if (payload_off + 1 > arc_len) {
		printf("skip %s (corrupt): archive too small to reach payload\n", arc_path);
		*skipped = 1;
		return 0;
	}

	bad1 = malloc((size_t)arc_len);
	bad2 = malloc((size_t)arc_len);
	memcpy(bad1, arc, (size_t)arc_len);
	memcpy(bad2, arc, (size_t)arc_len);
	bad1[payload_off] ^= 0xFF;
	bad2[payload_off] ^= 0xFF;

	cb_cap = plain_len * 4 + (4 << 20);
	cb_dst_cap = cb_cap;

	cb_src = bad1; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = calloc(1, (size_t)cb_cap); cb_dst_pos = 0;
	c_last_error[0] = 0;
	c_ret = cref_unzstd(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_c_error);
	c_dst = cb_dst;
	c_len = cb_dst_pos;

	cb_src = bad2; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = calloc(1, (size_t)cb_cap); cb_dst_pos = 0;
	r_last_error[0] = 0;
	r_ret = unzstd(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_r_error);
	r_dst = cb_dst;
	r_len = cb_dst_pos;

	cb_dst_cap = 0;
	free(bad1); free(bad2);

	/* A corruption that neither arm even notices tests nothing -- the
	 * comparison below would happily pass two implementations that both
	 * silently accepted corrupt data. zstd's default content checksum
	 * (the `zstd` CLI enables it unless --no-check) makes this a real
	 * assertion, not an assumption: a single flipped payload byte is
	 * expected to be caught. */
	if (c_ret == 0) {
		printf("FAIL %s (corrupt): C oracle did NOT detect the corruption -- this case tests nothing\n",
		       arc_path);
		free(c_dst); free(r_dst);
		return 1;
	}

	if (prove_can_fail) {
		/* Force a disagreement rather than skip this stage under
		 * poison (finding D): the callback/corrupt stages were
		 * previously never exercised by DBZ_PROVE_CAN_FAIL=1 at all. */
		r_ret = c_ret + 12345;
	}

	if (c_ret != r_ret) {
		if (!prove_can_fail)
			printf("FAIL %s (corrupt): return code mismatch C=%d Rust=%d\n",
			       arc_path, c_ret, r_ret);
		free(c_dst); free(r_dst);
		return 1;
	}
	if (c_len != r_len || memcmp(c_dst, r_dst, (size_t)c_len) != 0) {
		printf("FAIL %s (corrupt): output-before-failure mismatch (C wrote %ld bytes, Rust wrote %ld)\n",
		       arc_path, c_len, r_len);
		free(c_dst); free(r_dst);
		return 1;
	}
	if (strcmp(c_last_error, r_last_error) != 0) {
		printf("FAIL %s (corrupt): error() message mismatch: C=\"%s\" Rust=\"%s\"\n",
		       arc_path, c_last_error, r_last_error);
		free(c_dst); free(r_dst);
		return 1;
	}

	printf("ok   %s (corrupt): both return %d (\"%s\")\n", arc_path, c_ret, c_last_error);
	free(c_dst); free(r_dst);
	return 0;
}

int main(int argc, char **argv)
{
	int prove_can_fail = getenv("DBZ_PROVE_CAN_FAIL") != NULL;
	int cases = 0, fails = 0, skips = 0;
	int a;

	if (argc < 3 || (argc - 1) % 2 != 0) {
		fprintf(stderr, "usage: %s (archive plaintext)...\n", argv[0]);
		return 2;
	}

	for (a = 1; a + 1 < argc; a += 2) {
		const char *arc_path = argv[a];
		const char *plain_path = argv[a + 1];
		long arc_len, plain_len, outcap, c_pos = 0, r_pos = 0;
		unsigned char *arc, *plain, *c_out, *r_out, *arc1, *arc2;
		int c_ret, r_ret, ok = 1;
		int skipped;

		arc = read_file(arc_path, &arc_len);
		plain = read_file(plain_path, &plain_len);
		outcap = plain_len + 65536;
		c_out = calloc(1, outcap);
		r_out = calloc(1, outcap);
		arc1 = malloc(arc_len ? (size_t)arc_len : 1);
		arc2 = malloc(arc_len ? (size_t)arc_len : 1);
		memcpy(arc1, arc, (size_t)arc_len);
		memcpy(arc2, arc, (size_t)arc_len);
		cases++;

		/* Buffer mode: fill=flush=NULL -> decompress_single(). */
		c_last_error[0] = 0;
		c_ret = cref_unzstd(arc1, arc_len, NULL, NULL, c_out, &c_pos, record_c_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, c_last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		r_last_error[0] = 0;
		r_ret = unzstd(arc2, arc_len, NULL, NULL, r_out, &r_pos, record_r_error);
		if (r_ret != 0) {
			printf("FAIL %s: Rust returned %d (%s)\n", arc_path, r_ret, r_last_error);
			ok = 0;
		} else {
			if (prove_can_fail && plain_len > 0)
				r_out[0] ^= 0xFF;
			if (memcmp(r_out, plain, (size_t)plain_len) != 0) {
				if (!prove_can_fail)
					printf("FAIL %s: Rust output != plaintext\n", arc_path);
				ok = 0;
			}
			/*
			 * NOT checked: bytes past plain_len. Tried this (a
			 * slack-must-stay-zero check, matching port/test/lib's
			 * base64 poisoning) and it fired on real, non-corrupt,
			 * non-poisoned decompresses -- verified empirically
			 * against the PRISTINE C oracle directly (a standalone
			 * harness outside this file, not assumed) that it does
			 * the identical thing: byte `plain_len` of a real
			 * decompress of ascii_repeat.txt is 0x74 ('t', the
			 * start of the plaintext repeating) on BOTH arms. This
			 * is zstd's own documented wildcopy behavior: given an
			 * effectively unbounded dstCapacity (this buffer-mode
			 * path's `UINTPTR_MAX - out_buf`, same as the C's own),
			 * the block decoder is free to overwrite a few bytes
			 * past the true logical output length as a performance
			 * trade-off, on both arms identically -- not a
			 * Rust-vs-C divergence, so not something this
			 * differential should assert against.
			 */
		}

		if (ok && c_pos != r_pos) {
			printf("FAIL %s: consumed-length mismatch C=%ld Rust=%ld\n",
			       arc_path, c_pos, r_pos);
			ok = 0;
		}

		if (!ok)
			fails++;
		else
			printf("ok   %s (%ld bytes)\n", arc_path, plain_len);

		cases++;
		if (run_callback_mode(arc_path, arc, arc_len, plain, plain_len, prove_can_fail))
			fails++;

		cases++;
		if (run_corrupt_case(arc_path, arc, arc_len, plain_len, prove_can_fail, &skipped)) {
			fails++;
		} else if (skipped) {
			/* A skip is neither a pass nor a fail -- counted
			 * separately so it can never read as "passed" the way
			 * bunzip2/unlz4's poison-gate finding warned against
			 * (finding C). */
			cases--;
			skips++;
		}

		free(arc); free(plain); free(c_out); free(r_out); free(arc1); free(arc2);
	}

	if (skips)
		printf("%d cases skipped (not counted as passed or failed)\n", skips);
	printf("%d/%d cases passed\n", cases - fails, cases);
	return fails ? 1 : 0;
}
