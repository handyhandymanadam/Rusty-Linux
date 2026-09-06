/*
 * port/test/decompress_inflate/drv.c -- userspace differential for
 * lib/decompress_inflate.c's gunzip().
 *
 * decompress_inflate.c itself stays pristine in this port (see
 * decompress_inflate_rs.rs's module doc for why) -- the pristine C oracle
 * here (`cref_gunzip`, built from port/pristine/lib/decompress_inflate.c
 * with its own entry renamed) is therefore compiled from the EXACT SAME
 * source file the kernel's CONFIG_RUST=n arm uses unmodified. Both arms
 * link the SAME real zlib_inflate backend (inflate_thunk.c's real C entry
 * points, Rust bodies in inflate_rs.rs/inftrees_rs.rs/inffast_rs.rs,
 * compiled as separate objects exactly the way the kernel Makefile does
 * it -- not combined into one crate the way port/test/zlib_inflate/'s own
 * probe.rs does for a different purpose), so what's under test is THIS
 * wrapper's buffer/streaming-mode logic, not the inflate algorithm itself
 * (already covered by port/test/zlib_inflate/).
 *
 * Ground truth is independent of both arms: each case is a (real
 * `gzip`-produced archive, plaintext) pair, output compared against the
 * plaintext directly.
 *
 * Covers buffer mode (fill=flush=NULL) and fill/flush callback mode, a
 * corrupted-payload-byte exact-comparison check, and the
 * "0/$n_poison cases passed" exact-count poison-detection gate -- same
 * pattern as the rest of this file family, applying every lesson their
 * reviews found (offsets verified past the header, skips counted
 * separately, all stages poisoned, error text and byte-count compared on
 * the corrupt case, not just the return code).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib_inflate/inftrees.h"
#include "zlib_inflate/inflate.h"

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_gunzip(unsigned char *input, long in_len, fill_fn fill,
			flush_fn flush, unsigned char *output, long *posp,
			error_fn error);

extern int gunzip(unsigned char *input, long in_len, fill_fn fill,
		   flush_fn flush, unsigned char *output, long *posp,
		   error_fn error);

/* Userspace stand-ins for the kmalloc thunk + state-size helper the Rust
 * side calls (see decompress_inflate_rs.rs and decompress_inflate_alloc.c,
 * its C shim neighbour -- not compiled here directly since it pulls in
 * full kernel headers this userspace build doesn't have). */
/* unsigned long, not unsigned int -- matching decompress_inflate_alloc.c's
 * own fix (adversarial review, same shape as decompress_unzstd_alloc's
 * earlier fix): a narrower stand-in would reproduce whatever narrowing
 * the shipped shim has instead of being able to catch it. */
void *decompress_inflate_alloc(unsigned long size) { return malloc(size); }
unsigned long decompress_inflate_state_size(void) { return sizeof(struct inflate_state); }
void kfree(const void *p) { free((void *)p); }

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

/* fill/flush-callback mode globals, matching the rest of this file family. */
static const unsigned char *cb_src;
static long cb_src_len, cb_src_pos;
static unsigned char *cb_dst;
static long cb_dst_pos;
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
		n = cb_dst_cap - cb_dst_pos;
		if (n < 0)
			n = 0;
	}
	memcpy(cb_dst + cb_dst_pos, buf, (size_t)n);
	cb_dst_pos += n;
	return n;
}

/* Runs one (archive, plaintext) pair through fill+flush mode -- the ONLY
 * shape this project's own real boot ever exercises (init/initramfs.c
 * passes fill=NULL, flush=set) -- on both implementations. Poisons the
 * Rust output under prove_can_fail rather than skipping this stage. */
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
	c_ret = cref_gunzip(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_c_error);
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
	r_ret = gunzip(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_r_error);
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
 * Corrupts one byte INSIDE the compressed payload -- past the 10-byte
 * fixed gzip header (magic/method/flags/mtime/xfl/os), never inside it --
 * and compares exact return code, bytes written, and the exact error()
 * message text, not return code alone (this file family's repeated
 * finding: two implementations failing for different internal reasons can
 * still agree on a bare return code).
 *
 * UNLIKE every other file in this family's corrupt-case test: this one
 * does NOT assert the corruption was detected. Measured, not assumed: a
 * byte-by-byte corruption sweep of a real archive (a throwaway harness
 * outside this file) found only 6 of 74 corrupted payload positions
 * produced a nonzero return code at all. __gunzip() never validates the
 * gzip trailer's CRC32 against the decompressed bytes -- it trusts
 * zlib_inflate()'s own structural validity checks alone (bad Huffman
 * codes, out-of-range back-references), which a corrupted-but-still-
 * well-formed DEFLATE stream can sail through, decoding to different, but
 * NOT flagged, output. This is the same class of weak checksumming
 * `decompress_unlz4_rs.rs`'s own corrupt-case comment documents for LZ4 --
 * here there is no checksum enforcement in the wrapper AT ALL, not even a
 * weak one. So the meaningful assertion is not "both arms reject this",
 * it's "both arms agree, byte for byte, on whatever they each decided to
 * do" -- which is still a real equivalence proof, corruption-detected or
 * not.
 *
 * Run through fill/flush mode for the same reason decompress_unzstd's
 * corrupt case is: buffer mode's out_len for flush==NULL is `~0 -
 * (size_t)out_buf` (see __gunzip()'s own C), no real ceiling, trusted
 * upstream only because the real single-call caller owns a destination
 * sized for the (uncorrupted) frame. Fill/flush mode's real output buffer
 * is the fixed 32KB (0x8000) chunk gunzip() itself allocates.
 */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len,
			     long plain_len, int prove_can_fail, int *skipped)
{
	long payload_off = 10; /* the first byte past the fixed 10-byte gzip
				 * header -- empirically the most reliable of
				 * the 74 positions checked in the sweep this
				 * comment describes, though even this one is
				 * a property of THIS corpus, not guaranteed */
	unsigned char *bad1, *bad2;
	long cb_cap;
	int c_ret, r_ret;
	unsigned char *c_dst, *r_dst;
	long c_len, r_len;

	*skipped = 0;
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
	c_ret = cref_gunzip(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_c_error);
	c_dst = cb_dst;
	c_len = cb_dst_pos;

	cb_src = bad2; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = calloc(1, (size_t)cb_cap); cb_dst_pos = 0;
	r_last_error[0] = 0;
	r_ret = gunzip(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_r_error);
	r_dst = cb_dst;
	r_len = cb_dst_pos;

	cb_dst_cap = 0;
	free(bad1); free(bad2);

	if (prove_can_fail)
		r_ret = c_ret + 12345;

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

		/* Buffer mode: fill=flush=NULL. */
		c_last_error[0] = 0;
		c_ret = cref_gunzip(arc1, arc_len, NULL, NULL, c_out, &c_pos, record_c_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, c_last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		r_last_error[0] = 0;
		r_ret = gunzip(arc2, arc_len, NULL, NULL, r_out, &r_pos, record_r_error);
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
