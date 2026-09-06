/*
 * port/test/decompress_unlzo/drv.c -- userspace differential for
 * lib/decompress_unlzo.c.
 *
 * This wrapper's own substance is the LZOP header parsing (parse_header())
 * and the block framing (dst_len/src_len prefixes) around a call to
 * lzo1x_decompress_safe() -- which is already a real EXPORT_SYMBOL (the
 * lib/bcd shape, body in lzo1x_decompress_safe_rs.rs). Both the pristine C
 * oracle and the Rust wrapper here are linked against the SYSTEM liblzo2's
 * real lzo1x_decompress_safe, isolating the wrapper logic being ported --
 * same reasoning port/test/decompress_unlz4/ uses for LZ4_decompress_safe.
 *
 * Ground truth is independent of both: each case is a (lzop archive,
 * plaintext) pair, the archive produced by the REAL `lzop` CLI tool from
 * plaintext this project generates -- not hand-built framing, so the
 * corpus is never wrong about what a real lzop stream looks like -- output
 * compared against that plaintext directly.
 *
 * Each pair also runs through run_callback_mode() (fill+flush, not just
 * buffer mode) and run_corrupt_case() (a corrupted payload byte -- never
 * the length prefix, which can wrap larger on an unlucky value and hand
 * lzo1x_decompress_safe a real out-of-bounds read, exactly as
 * port/test/decompress_unlz4/'s first version of this same idea found the
 * hard way -- checking C and Rust return the EXACT SAME code).
 *
 * DBZO_PROVE_CAN_FAIL=1 flips one output byte after a successful Rust
 * decompress, before the comparison -- proving the comparison itself can
 * fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long (*fill_fn)(void *, unsigned long);
typedef long (*flush_fn)(void *, unsigned long);
typedef void (*error_fn)(char *);

extern int cref_unlzo(unsigned char *input, long in_len, fill_fn fill,
		       flush_fn flush, unsigned char *output, long *posp,
		       error_fn error);

extern int unlzo(unsigned char *input, long in_len, fill_fn fill,
		  flush_fn flush, unsigned char *output, long *posp,
		  error_fn error);

/* Userspace stand-in for the kmalloc/kfree the Rust side calls (see
 * decompress_unlzo_rs.rs and its C alloc-shim neighbour). */
void *decompress_unlzo_alloc(unsigned int size) { return malloc(size); }
void kfree(const void *p) { free((void *)p); }

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

/* fill/flush have no user-data parameter -- state lives in file-scope
 * globals, reset before each call. */
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
	int c_ret, r_ret, ok = 1;

	cb_src = arc; cb_src_len = arc_len; cb_src_pos = 0;
	cb_dst = c_out; cb_dst_pos = 0;
	last_error[0] = 0;
	c_ret = cref_unlzo(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_error);
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
	r_ret = unlzo(NULL, arc_len, cb_fill, cb_flush, NULL, NULL, record_error);
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

/* Corrupts one byte inside the first block's compressed PAYLOAD -- not the
 * length prefix, see this file's header comment -- and checks C and Rust
 * return the exact same code. LZO is weakly checksummed, so rejection
 * isn't guaranteed; only parity is asserted. */
static int run_corrupt_case(const char *arc_path, const unsigned char *arc, long arc_len)
{
	unsigned char *bad1, *bad2;
	long c_pos = 0, r_pos = 0, payload_off;
	int c_ret, r_ret;

	/* 38 = the LZOP header size when lzop compresses from STDIN (run.sh's
	 * corpus is generated exactly that way): magic(9) + version/libver/
	 * needver/method(7) + level(1, version>=0x0940) + flags(4, no
	 * filter) + mode+mtime_low(8) + mtime_high(4, version>=0x0940) +
	 * filename-length byte(1) + filename(0, stdin has none) +
	 * checksum(4) = 38, then the first block's dst_len/src_len/checksum
	 * prefix (12 bytes) and its compressed payload. Fixed and verified
	 * against this corpus's actual archives, not guessed -- a per-file
	 * name-length-dependent header (lzop given a real filename) would
	 * make this offset wrong per file, which is why run.sh pipes
	 * through stdin instead of passing a path. */
	payload_off = 38 + 12;
	if (arc_len < payload_off + 1) {
		/* Explicit, not a silent pass: found by adversarial review --
		 * an earlier version of this function returned 0 here, which
		 * main() counts as a passing case with no comparison ever
		 * run. empty.txt's archive is exactly this small. */
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

	/* Sized for the true worst case (one LZO_BLOCK_SIZE block), not
	 * arc_len -- see port/test/decompress_unlz4/drv.c's run_corrupt_case
	 * for why arc_len-based sizing already segfaulted a harness once. */
#define UNLZO_MAX_BLOCK (256 * 1024)
	{
		unsigned char *c_scratch = calloc(1, UNLZO_MAX_BLOCK + 65536);
		unsigned char *r_scratch = calloc(1, UNLZO_MAX_BLOCK + 65536);

		last_error[0] = 0;
		c_ret = cref_unlzo(bad1, arc_len, NULL, NULL, c_scratch, &c_pos, record_error);
		last_error[0] = 0;
		r_ret = unlzo(bad2, arc_len, NULL, NULL, r_scratch, &r_pos, record_error);

		free(bad1); free(bad2);

		if (c_ret != r_ret) {
			printf("FAIL %s (corrupt): return code mismatch C=%d Rust=%d\n",
			       arc_path, c_ret, r_ret);
			free(c_scratch); free(r_scratch);
			return 1;
		}
		/*
		 * If both "succeed" the corruption wasn't caught (LZO is
		 * weakly checksummed, and a stored/uncompressed block --
		 * dst_len == src_len -- just memcpy()s, so a corrupted
		 * payload byte changes the OUTPUT but not the return code
		 * at all). Found by adversarial review: with only the
		 * return-code check, every stored-block or trivially-small
		 * archive in the corpus "passed" this function without the
		 * corruption being checked against anything. Compare the
		 * actual bytes produced in that case instead.
		 */
		if (c_ret == 0 && memcmp(c_scratch, r_scratch, UNLZO_MAX_BLOCK + 65536) != 0) {
			printf("FAIL %s (corrupt): both return 0 but output differs\n", arc_path);
			free(c_scratch); free(r_scratch);
			return 1;
		}
		free(c_scratch); free(r_scratch);
	}
#undef UNLZO_MAX_BLOCK

	printf("ok   %s (corrupt): both return %d\n", arc_path, c_ret);
	return 0;
}

int main(int argc, char **argv)
{
	int prove_can_fail = getenv("DBZO_PROVE_CAN_FAIL") != NULL;
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
		c_out = calloc(1, (size_t)outcap);
		r_out = calloc(1, (size_t)outcap);
		arc1 = malloc(arc_len ? (size_t)arc_len : 1);
		arc2 = malloc(arc_len ? (size_t)arc_len : 1);
		memcpy(arc1, arc, (size_t)arc_len);
		memcpy(arc2, arc, (size_t)arc_len);
		cases++;

		last_error[0] = 0;
		c_ret = cref_unlzo(arc1, arc_len, NULL, NULL, c_out, &c_pos, record_error);
		if (c_ret != 0) {
			printf("FAIL %s: C oracle returned %d (%s)\n", arc_path, c_ret, last_error);
			ok = 0;
		} else if (memcmp(c_out, plain, (size_t)plain_len) != 0) {
			printf("FAIL %s: C oracle output != plaintext\n", arc_path);
			ok = 0;
		}

		last_error[0] = 0;
		r_ret = unlzo(arc2, arc_len, NULL, NULL, r_out, &r_pos, record_error);
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
