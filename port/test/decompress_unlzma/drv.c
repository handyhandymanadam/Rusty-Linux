/*
 * port/test/decompress_unlzma/drv.c -- userspace differential for
 * lib/decompress_unlzma.c's unlzma().
 *
 * Self-contained algorithm (like decompress_bunzip2), not a thin wrapper
 * over a shared backend: the pristine C oracle (`cref_unlzma`, built from
 * port/pristine/lib/decompress_unlzma.c with its own entry renamed) IS the
 * whole reference LZMA range-coder decoder, no isolation trick needed.
 *
 * Ground truth is independent of both arms: each case is a (real
 * `xz -F lzma`-produced archive, plaintext) pair -- the standard
 * "lzma_alone" file format (13-byte header: 1-byte properties, 4-byte
 * little-endian dict size, 8-byte little-endian uncompressed size or
 * 0xFFFFFFFFFFFFFFFF for unknown) is exactly what struct lzma_header
 * expects, verified by hand against a real archive's bytes before writing
 * this, not assumed.
 *
 * Covers buffer mode (fill=flush=NULL) and fill/flush callback mode, a
 * corrupted-payload-byte comparison (return code, bytes written, and the
 * exact error() message text -- not return code alone), and the
 * "0/$n_poison cases passed" exact-count poison-detection gate -- same
 * pattern as the rest of this file family, applying every lesson their
 * reviews found.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_unlzma(unsigned char *input, long in_len, fill_fn fill,
			flush_fn flush, unsigned char *output, long *posp,
			error_fn error);

extern int unlzma(unsigned char *input, long in_len, fill_fn fill,
		   flush_fn flush, unsigned char *output, long *posp,
		   error_fn error);

/* Userspace stand-ins for the kmalloc/vmalloc thunks the Rust side calls
 * (see decompress_unlzma_rs.rs and decompress_unlzma_alloc.c, its C shim
 * neighbour). unsigned long, not unsigned int -- matching the shipped
 * shim's own parameter type (this file family's now-familiar lesson: a
 * narrower stand-in reproduces whatever narrowing the real shim has
 * instead of being able to catch it). */
void *decompress_unlzma_alloc(unsigned long size) { return malloc(size); }
void *decompress_unlzma_large_alloc(unsigned long size) { return malloc(size); }
void kfree(const void *p) { free((void *)p); }
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

/* Runs one (archive, plaintext) pair through fill+flush mode on both
 * implementations. Poisons the Rust output under prove_can_fail rather
 * than skipping this stage entirely.
 *
 * in_len=0, not arc_len -- found the hard way: unlzma()'s C, unlike
 * gunzip's or unlz4's, does NOT reset in_len when it internally allocates
 * inbuf for a NULL `buf` (`if (buf) inbuf = buf; else inbuf =
 * malloc(LZMA_IOBUF_SIZE);` has no `else` branch touching `in_len`, unlike
 * e.g. decompress_inflate.c's `zbuf = malloc(...); len = 0;`). Passing
 * arc_len there sets rc->buffer_end past a freshly-allocated, still-empty
 * buffer, so rc_init_code()'s first read pulls uninitialized bytes for
 * the header instead of calling rc_read() to fill it first -- confirmed
 * by both arms failing IDENTICALLY (same wrong output) when this was
 * arc_len, which is what a harness bug looks like, not a Rust-vs-C
 * divergence. 0 makes `rc->ptr >= rc->buffer_end` true immediately,
 * forcing the real fill() call before anything is read -- matching what
 * a real streaming caller needs to pass for this specific file. */
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
	c_ret = cref_unlzma(NULL, 0, cb_fill, cb_flush, NULL, NULL, record_c_error);
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
	r_ret = unlzma(NULL, 0, cb_fill, cb_flush, NULL, NULL, record_r_error);
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
 * Corrupts one byte INSIDE the compressed payload -- past the fixed
 * 13-byte lzma_alone header (properties/dict_size/dst_size), never inside
 * it -- and compares exact return code, bytes written, and the exact
 * error() message text.
 *
 * Run through fill/flush mode for the same reason the rest of this file
 * family's corrupt cases are: buffer mode's output sizing for a NULL
 * `output` uses MIN(header.dst_size, header.dict_size), which for a
 * lzma_alone stream with unknown size (dst_size = UINT64_MAX, this
 * corpus's default) collapses to dict_size -- large (megabytes) and,
 * more importantly, a value this test controls only indirectly through
 * the corpus generator's compression level. Fill/flush mode's real
 * output buffer is the fixed 64KB write_byte()/wr->flush() chunking (the
 * dict_size the CORPUS was generated with controls the internal ring
 * buffer size, not this harness's own allocation), which this harness
 * caps explicitly via cb_dst_cap regardless.
 */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len,
			     long plain_len, int prove_can_fail, int *skipped)
{
	long payload_off = 13 + 4; /* past the fixed 13-byte lzma_alone header */
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
	c_ret = cref_unlzma(NULL, 0, cb_fill, cb_flush, NULL, NULL, record_c_error);
	c_dst = cb_dst;
	c_len = cb_dst_pos;

	cb_src = bad2; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = calloc(1, (size_t)cb_cap); cb_dst_pos = 0;
	r_last_error[0] = 0;
	r_ret = unlzma(NULL, 0, cb_fill, cb_flush, NULL, NULL, record_r_error);
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
		c_ret = cref_unlzma(arc1, arc_len, NULL, NULL, c_out, &c_pos, record_c_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, c_last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		r_last_error[0] = 0;
		r_ret = unlzma(arc2, arc_len, NULL, NULL, r_out, &r_pos, record_r_error);
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
