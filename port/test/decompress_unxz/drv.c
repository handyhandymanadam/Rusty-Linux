/*
 * port/test/decompress_unxz/drv.c -- userspace differential for
 * lib/decompress_unxz.c.
 *
 * This wrapper's own substance is picking single-call vs multi-call mode
 * and shuttling bytes through fill()/flush() -- the .xz container format
 * itself is entirely xz_dec_run()'s job. Both the pristine C oracle and
 * the Rust wrapper here call the SAME real backend: the kernel's own
 * pristine lib/xz/{xz_dec_stream,xz_dec_lzma2,xz_dec_bcj,xz_crc32}.c,
 * compiled once and shared -- same reasoning port/test/xz_stream/run.sh
 * already uses to test xz_dec_stream_rs.rs itself (real symbol names,
 * nothing renamed at this layer; only unxz()/cref_unxz() differ).
 *
 * Ground truth is independent of both: each case is a (.xz file,
 * plaintext) pair, the .xz file produced by the REAL `xz` CLI from
 * plaintext this project generates, output compared against that
 * plaintext directly.
 *
 * Each pair also runs through run_callback_mode() (fill+flush, not just
 * single-call buffer mode, with a real in_used pointer on both arms -- an
 * earlier version passed NULL, leaving one of unxz()'s two in_used
 * accumulation points untested by every case in this file) and
 * run_corrupt_case() (a corrupted byte past the BLOCK header too, not just
 * the 12-byte stream header -- an earlier version corrupted a byte inside
 * the block header, caught by its own CRC32 check before ever reaching
 * LZMA2, and the error-message text on both sides, not just the return
 * code, which collapses every error to -1 and so cannot alone prove the
 * message-mapping switch is right).
 *
 * DBXZ_PROVE_CAN_FAIL=1 flips one output byte after a successful Rust
 * decompress, before the comparison -- proving the comparison itself can
 * fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_unxz(unsigned char *in, long in_size, fill_fn fill, flush_fn flush,
		      unsigned char *out, long *in_used, error_fn error);

extern int unxz(unsigned char *in, long in_size, fill_fn fill, flush_fn flush,
		 unsigned char *out, long *in_used, error_fn error);

/* Userspace stand-in for the kmalloc/kfree the Rust side calls (see
 * decompress_unxz_rs.rs and its C alloc-shim neighbour). */
void *decompress_unxz_alloc(unsigned int size) { return malloc(size); }
void kfree(const void *p) { free((void *)p); }

static char c_last_error[256], r_last_error[256];
static void record_c_error(char *msg) { snprintf(c_last_error, sizeof(c_last_error), "%s", msg); }
static void record_r_error(char *msg) { snprintf(r_last_error, sizeof(r_last_error), "%s", msg); }

/* Compares the error() message text, not just the return code -- unxz()
 * collapses every xz_ret into a small set of return codes (mostly -1), so
 * two different error messages could share a return code and a
 * return-code-only check would never notice. Call only when both sides
 * actually took an error path (both ret != 0); returns 1 (fail) on a
 * mismatch. */
static int check_error_parity(const char *arc_path, const char *tag)
{
	if (strcmp(c_last_error, r_last_error) != 0) {
		printf("FAIL %s (%s): error message mismatch C=\"%s\" Rust=\"%s\"\n",
		       arc_path, tag, c_last_error, r_last_error);
		return 1;
	}
	return 0;
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

static int run_callback_mode(const char *arc_path, const unsigned char *arc, long arc_len,
			      const unsigned char *plain, long plain_len)
{
	long outcap = plain_len + 65536;
	unsigned char *c_out = calloc(1, (size_t)outcap);
	unsigned char *r_out = calloc(1, (size_t)outcap);
	long c_used = 0, r_used = 0;
	int c_ret, r_ret, ok = 1;

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = c_out; cb_dst_pos = 0;
	c_last_error[0] = 0;
	c_ret = cref_unxz(NULL, 0, cb_fill, cb_flush, NULL, &c_used, record_c_error);
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
	r_ret = unxz(NULL, 0, cb_fill, cb_flush, NULL, &r_used, record_r_error);
	if (r_ret != 0) {
		printf("FAIL %s (fill/flush): Rust returned %d (%s)\n", arc_path, r_ret, r_last_error);
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
	if (ok && c_ret != 0 && check_error_parity(arc_path, "fill/flush"))
		ok = 0;
	if (ok && c_used != r_used) {
		printf("FAIL %s (fill/flush): consumed-length mismatch C=%ld Rust=%ld\n",
		       arc_path, c_used, r_used);
		ok = 0;
	}

	if (ok)
		printf("ok   %s (fill/flush): %ld bytes, %ld bytes consumed\n",
		       arc_path, plain_len, c_used);

	free(c_out);
	free(r_out);
	return !ok;
}

/* Corrupts one byte past the BLOCK header, not just the 12-byte stream
 * header -- checked by hand against this corpus's actual `xz --check=crc32`
 * output: the block header is [12, 28) at level 0 and [12, 32) at levels
 * 6/9 (its own encoded-size byte at offset 12, real size (byte+1)*4).
 * Offset 16 (an earlier version's choice) sits INSIDE that range: every
 * corruption was caught by the block header's own CRC32 check before
 * LZMA2 ever ran, the same class of bug an early port/test/decompress_unlzo
 * corrupt-test had. 40 clears the block header at every level this
 * corpus uses, landing in the actual LZMA2 payload. */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len)
{
	unsigned char *bad1, *bad2, *c_scratch, *r_scratch;
	long c_used = 0, r_used = 0, payload_off = 40;
	int c_ret, r_ret;

	if (arc_len < payload_off + 1) {
		printf("skip %s (corrupt): archive too small to corrupt at offset %ld\n",
		       arc_path, payload_off);
		return 0;
	}

	bad1 = malloc((size_t)arc_len);
	bad2 = malloc((size_t)arc_len);
	memcpy(bad1, arc, (size_t)arc_len);
	memcpy(bad2, arc, (size_t)arc_len);
	bad1[payload_off] ^= 0xFF;
	bad2[payload_off] ^= 0xFF;

	/* Generously large: single-call mode writes directly into this with
	 * no bound of its own (b.out_size = (size_t)-1 when flush == NULL). */
#define UNXZ_SCRATCH_CAP (4 * 1024 * 1024)
	c_scratch = calloc(1, UNXZ_SCRATCH_CAP);
	r_scratch = calloc(1, UNXZ_SCRATCH_CAP);
	c_last_error[0] = 0;
	c_ret = cref_unxz(bad1, arc_len, NULL, NULL, c_scratch, &c_used, record_c_error);
	r_last_error[0] = 0;
	r_ret = unxz(bad2, arc_len, NULL, NULL, r_scratch, &r_used, record_r_error);

	free(bad1); free(bad2);

	if (c_ret != r_ret) {
		printf("FAIL %s (corrupt): return code mismatch C=%d Rust=%d\n",
		       arc_path, c_ret, r_ret);
		free(c_scratch); free(r_scratch);
		return 1;
	}
	if (c_ret != 0 && check_error_parity(arc_path, "corrupt")) {
		free(c_scratch); free(r_scratch);
		return 1;
	}
	if (c_ret == 0 && memcmp(c_scratch, r_scratch, UNXZ_SCRATCH_CAP) != 0) {
		printf("FAIL %s (corrupt): both return 0 but output differs\n", arc_path);
		free(c_scratch); free(r_scratch);
		return 1;
	}
#undef UNXZ_SCRATCH_CAP
	free(c_scratch); free(r_scratch);

	printf("ok   %s (corrupt): both return %d\n", arc_path, c_ret);
	return 0;
}

int main(int argc, char **argv)
{
	int prove_can_fail = getenv("DBXZ_PROVE_CAN_FAIL") != NULL;
	int cases = 0, fails = 0;
	int a;

	if (argc < 3 || (argc - 1) % 2 != 0) {
		fprintf(stderr, "usage: %s (xzfile plaintext)...\n", argv[0]);
		return 2;
	}

	for (a = 1; a + 1 < argc; a += 2) {
		const char *arc_path = argv[a];
		const char *plain_path = argv[a + 1];
		long arc_len, plain_len, outcap, c_used = 0, r_used = 0;
		unsigned char *arc, *plain, *c_out, *r_out, *arc1, *arc2;
		int c_ret, r_ret, ok = 1;

		arc = read_file(arc_path, &arc_len);
		plain = read_file(plain_path, &plain_len);
		outcap = plain_len + 65536;
		c_out = calloc(1, (size_t)outcap);
		r_out = calloc(1, (size_t)outcap);
		arc1 = malloc(arc_len ? (size_t)arc_len : 1);
		arc2 = malloc(arc_len ? (size_t)arc_len : 1);
		memcpy(arc1, arc, (size_t)arc_len);
		memcpy(arc2, arc, (size_t)arc_len);
		cases++;

		c_last_error[0] = 0;
		c_ret = cref_unxz(arc1, arc_len, NULL, NULL, c_out, &c_used, record_c_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, c_last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		r_last_error[0] = 0;
		r_ret = unxz(arc2, arc_len, NULL, NULL, r_out, &r_used, record_r_error);
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

		if (ok && c_used != r_used) {
			printf("FAIL %s: consumed-length mismatch C=%ld Rust=%ld\n",
			       arc_path, c_used, r_used);
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
