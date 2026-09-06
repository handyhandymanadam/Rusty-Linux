/*
 * port/test/decompress_unlz4/drv.c -- userspace differential for
 * lib/decompress_unlz4.c.
 *
 * This wrapper's own substance is the archive framing (magic + length-
 * prefixed chunks), not LZ4 block decompression -- that's already ported
 * and tested separately (port/test/lz4/). Both the pristine C oracle and
 * the Rust wrapper here are linked against the SYSTEM liblz4's real
 * LZ4_decompress_safe (declared with the exact signature ours expects),
 * so the two arms differ ONLY in the wrapper logic being ported -- the
 * same reasoning as testing a thin dispatcher against a trusted backend
 * rather than re-proving the backend.
 *
 * Ground truth is independent of both: each case is a (kernel-format
 * archive, plaintext) pair, the archive built by gen_archive.c from
 * plaintext this project generates, output compared against that
 * plaintext directly.
 *
 * Each pair also runs through run_callback_mode() (fill+flush, not just
 * buffer mode) and run_corrupt_case() (a corrupted first chunk length,
 * checking C and Rust return the SAME negative code, not just that both
 * reject it) -- added after adversarial review found the original version
 * of this file only ever exercised buffer mode on valid input, which is
 * exactly the blind spot that let a hardcoded -1 (discarding LZ4's real
 * error code) through undetected.
 *
 * DBZ_PROVE_CAN_FAIL=1 flips one output byte after a successful Rust
 * decompress, before the comparison -- proving the comparison itself
 * can fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_unlz4(unsigned char *input, long in_len, fill_fn fill,
		       flush_fn flush, unsigned char *output, long *posp,
		       error_fn error);

extern int unlz4(unsigned char *input, long in_len, fill_fn fill,
		  flush_fn flush, unsigned char *output, long *posp,
		  error_fn error);

/* Userspace stand-in for the vmalloc the Rust side calls (see
 * decompress_unlz4_rs.rs and its C alloc-shim neighbour). */
void *decompress_unlz4_alloc(unsigned int size) { return malloc(size); }
void vfree(const void *p) { free((void *)p); }

static char last_error[256];
static void record_error(char *msg)
{
	snprintf(last_error, sizeof(last_error), "%s", msg);
}

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

/*
 * fill/flush-callback mode, and exact-return-code parity on corrupted
 * input -- both added after adversarial review found the buffer-mode-only
 * differential above never exercised either callback arm (D3) or any
 * error path at all (D4), which is exactly how an earlier version of this
 * port's hardcoded -1 on LZ4 decode failure went undetected.
 *
 * fill/flush have no user-data parameter (see decompress_unlz4_rs.rs's
 * FillFn/FlushFn) -- like the kernel's own callers, this reads from and
 * writes to state in file-scope globals, reset before each call.
 */
static const unsigned char *cb_src;
static long cb_src_len, cb_src_pos;
static unsigned char *cb_dst;
static long cb_dst_pos;

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
	memcpy(cb_dst + cb_dst_pos, buf, len);
	cb_dst_pos += (long)len;
	return (long)len;
}

/* Runs one (archive, plaintext) pair through fill+flush mode on both
 * implementations, comparing output and exact return code. Returns 1 on
 * any mismatch (printing why), 0 if both sides agree with the plaintext. */
static int run_callback_mode(const char *arc_path, const unsigned char *arc, long arc_len,
			      const unsigned char *plain, long plain_len)
{
	long outcap = plain_len + 65536;
	unsigned char *c_out = calloc(1, (size_t)outcap);
	unsigned char *r_out = calloc(1, (size_t)outcap);
	int c_ret, r_ret, ok = 1;

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = c_out; cb_dst_pos = 0;
	last_error[0] = 0;
	c_ret = cref_unlz4(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_error);
	if (c_ret != 0) {
		printf("FAIL %s (fill/flush): C oracle returned %d (%s)\n", arc_path, c_ret, last_error);
		ok = 0;
	} else if (cb_dst_pos != plain_len || memcmp(c_out, plain, (size_t)plain_len) != 0) {
		printf("FAIL %s (fill/flush): C oracle output != plaintext\n", arc_path);
		ok = 0;
	}

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = r_out; cb_dst_pos = 0;
	last_error[0] = 0;
	r_ret = unlz4(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_error);
	if (r_ret != 0) {
		printf("FAIL %s (fill/flush): Rust returned %d (%s)\n", arc_path, r_ret, last_error);
		ok = 0;
	} else if (cb_dst_pos != plain_len || memcmp(r_out, plain, (size_t)plain_len) != 0) {
		printf("FAIL %s (fill/flush): Rust output != plaintext\n", arc_path);
		ok = 0;
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

/* Corrupts one byte INSIDE the first chunk's compressed PAYLOAD (never the
 * length prefix) and checks C and Rust return the EXACT SAME code -- not
 * just that both reject it (LZ4 is weakly checksummed, so a corrupted
 * payload is not guaranteed to make it fail at all). Exact-code parity is
 * the case D1 (a hardcoded -1 where C propagates LZ4's own error code) hid
 * behind: both sides returned nonzero, so a check that only asked "did
 * both fail?" would have passed anyway.
 *
 * NOT the length prefix: neither implementation bounds-checks a chunk's
 * declared length against the bytes actually left in the buffer (buffer
 * mode, inherited from upstream -- the same hazard libtest's module doc
 * notes for why it has no truncated-archive sub-test), so flipping that
 * byte can, on an unlucky value, WRAP THE LENGTH LARGER instead of
 * smaller and hand LZ4_decompress_safe a real out-of-bounds read. Found
 * the hard way: an earlier version of this function did exactly that and
 * segfaulted the harness itself. */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len)
{
	unsigned char *bad1, *bad2;
	unsigned char *scratch;
	long c_pos = 0, r_pos = 0;
	int c_ret, r_ret;

	if (arc_len < 9)
		return 0;

	bad1 = malloc((size_t)arc_len);
	bad2 = malloc((size_t)arc_len);
	memcpy(bad1, arc, (size_t)arc_len);
	memcpy(bad2, arc, (size_t)arc_len);
	bad1[8] ^= 0xFF;
	bad2[8] ^= 0xFF;

	/*
	 * Sized for the true worst case, not arc_len: LZ4 is weakly
	 * checksummed, so corrupted payload bytes are not guaranteed to make
	 * LZ4_decompress_safe fail -- it may "succeed" and write up to
	 * LZ4_DEFAULT_UNCOMPRESSED_CHUNK_SIZE (8MB) regardless of how small
	 * the archive was. This function does not assume rejection for
	 * exactly that reason; only that C and Rust land on the same answer.
	 */
#define UNLZ4_MAX_CHUNK (8 << 20)
	scratch = calloc(1, UNLZ4_MAX_CHUNK + 65536);
	last_error[0] = 0;
	c_ret = cref_unlz4(bad1, arc_len, NULL, NULL, scratch, &c_pos, record_error);
	memset(scratch, 0, UNLZ4_MAX_CHUNK + 65536);
	last_error[0] = 0;
	r_ret = unlz4(bad2, arc_len, NULL, NULL, scratch, &r_pos, record_error);
#undef UNLZ4_MAX_CHUNK

	free(bad1); free(bad2); free(scratch);

	if (c_ret != r_ret) {
		printf("FAIL %s (corrupt): return code mismatch C=%d Rust=%d\n",
		       arc_path, c_ret, r_ret);
		return 1;
	}
	printf("ok   %s (corrupt): both return %d\n", arc_path, c_ret);
	return 0;
}

int main(int argc, char **argv)
{
	int prove_can_fail = getenv("DBZ_PROVE_CAN_FAIL") != NULL;
	int cases = 0, fails = 0;
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

		last_error[0] = 0;
		c_ret = cref_unlz4(arc1, arc_len, NULL, NULL, c_out, &c_pos, record_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		last_error[0] = 0;
		r_ret = unlz4(arc2, arc_len, NULL, NULL, r_out, &r_pos, record_error);
		if (r_ret != 0) {
			printf("FAIL %s: Rust returned %d (%s)\n", arc_path, r_ret, last_error);
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

		if (!prove_can_fail) {
			cases++;
			if (run_callback_mode(arc_path, arc, arc_len, plain, plain_len))
				fails++;
			cases++;
			if (run_corrupt_case(arc_path, arc, arc_len))
				fails++;
		}

		free(arc); free(plain); free(c_out); free(r_out); free(arc1); free(arc2);
	}

	printf("%d/%d cases passed\n", cases - fails, cases);
	return fails ? 1 : 0;
}
