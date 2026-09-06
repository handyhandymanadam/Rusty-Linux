// SPDX-License-Identifier: GPL-2.0
/*
 * lib/ self-test -- the SCOPE.md §4 class-A proof caller for the ported
 * top-level lib/ functions.
 *
 * The sibling of lib/math/mathtest.c, and the same thing: NOT a correctness
 * suite. Correctness is settled in userspace by port/test/, which runs tens
 * of millions of cases against the original C bodies in seconds. This runs in
 * the kernel to answer the one question a userspace test cannot -- did the
 * Rust actually run, in the kernel, on the boot path.
 *
 * So the vectors are few and chosen to be what a mistranslation breaks.
 *
 * lib/glob has its own, upstream's: CONFIG_GLOB_SELFTEST.
 */

#include <linux/base64.h>
#include <linux/err.h>
#include <linux/bsearch.h>
#include <linux/bcd.h>
#include <linux/bitrev.h>
#include <linux/uuid.h>
#include <linux/buildid.h>
#include <linux/elf.h>
#include <linux/mm_types.h>
#include <linux/shmem_fs.h>
#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/llist.h>
#include <linux/debug_locks.h>
#include <linux/io.h>
#include <linux/errseq.h>
#include <crypto/arc4.h>
#include <crypto/chacha.h>
#include <crypto/aes.h>
#include <linux/errname.h>
#include <linux/dynamic_queue_limits.h>
#include <linux/ratelimit.h>
#include <linux/flex_proportions.h>
#include <linux/interval_tree.h>
#include <linux/asn1_decoder.h>
#include <linux/asn1_ber_bytecode.h>
#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/utils.h>
#include <linux/crc-ccitt.h>
#include <linux/crc16.h>
#include <linux/earlycpio.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/errseq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/plist.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/ucs2_string.h>
#include <linux/union_find.h>
#include <linux/lzo.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/xxhash.h>
#include <linux/xz.h>
#include <linux/win_minmax.h>
#include <linux/zlib.h>

/* lib/clz_ctz.c. These have no header -- the compiler knows them by name
 * and nothing in the kernel declares them. */
int __ctzsi2(int val);
int __clzsi2(int val);
int __clzdi2(u64 val);
int __ctzdi2(u64 val);

#if IS_ENABLED(CONFIG_MPILIB)
/* lib/crypto/mpi/generic_mpih_rs.rs. Declared here because mpi-internal.h
 * is not exported outside lib/crypto/mpi/. */
unsigned long mpihelp_mul_1(unsigned long *r, const unsigned long *s1, int n, unsigned long k);
unsigned long mpihelp_add_n(unsigned long *r, const unsigned long *a, const unsigned long *b, int n);
unsigned long mpihelp_sub_n(unsigned long *r, const unsigned long *a, const unsigned long *b, int n);
unsigned long mpihelp_lshift(unsigned long *w, const unsigned long *u, int n, unsigned int cnt);
unsigned long mpihelp_rshift(unsigned long *w, const unsigned long *u, int n, unsigned int cnt);
int mpihelp_cmp(const unsigned long *a, const unsigned long *b, int n);

/* lib/crypto/mpi/{mpiutil,mpi_add,mpi_sub_ui}_rs.rs. include/linux/mpi.h
 * is not included here (it pulls in scatterlist.h for the wider MPI API),
 * so the struct and the handful of entry points this file exercises are
 * declared directly -- same convention as the mpihelp_* block above. */
struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	unsigned long *d;
};
typedef struct gcry_mpi *MPI;
MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
int mpi_add(MPI w, MPI u, MPI v);
int mpi_sub(MPI w, MPI u, MPI v);
int mpi_addm(MPI w, MPI u, MPI v, MPI m);
int mpi_subm(MPI w, MPI u, MPI v, MPI m);
int mpi_sub_ui(MPI w, MPI u, unsigned long vval);
/* lib/crypto/mpi/{mpi-mul,mpi-pow}.c -- still C, EXPORT_SYMBOL_GPL'd, and
 * the only callers of lib/crypto/mpi/mpih_mul_rs.rs's real symbols. */
int mpi_mul(MPI w, MPI u, MPI v);
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod);
/* lib/crypto/mpi/mpi_bit_rs.rs. */
unsigned mpi_get_nbits(MPI a);
int mpi_test_bit(MPI a, unsigned int n);
int mpi_set_bit(MPI a, unsigned int n);
int mpi_rshift(MPI x, MPI a, unsigned int n);
/* lib/crypto/mpi/mpicoder_rs.rs. */
MPI mpi_read_from_buffer(const void *xbuffer, unsigned int *ret_nread);
int mpi_read_buffer(MPI a, u8 *buf, unsigned int buf_len, unsigned int *nbytes, int *sign);
void *mpi_get_buffer(MPI a, unsigned int *nbytes, int *sign);
#endif

static unsigned int passed __initdata, failed __initdata;

static void __init check(bool ok, const char *what)
{
	if (ok) {
		passed++;
		return;
	}
	failed++;
	pr_err("libtest: %s *** ERROR ***\n", what);
}

static void __init test_base64(void)
{
	static const struct {
		const char *plain;
		const char *coded;
	} vec[] __initconst = {
		{ "",       ""         },	/* no input, no output */
		{ "f",      "Zg=="     },	/* RFC 4648 §10 test vectors: */
		{ "fo",     "Zm8="     },	/* every padding case */
		{ "foo",    "Zm9v"     },
		{ "foob",   "Zm9vYg==" },
		{ "fooba",  "Zm9vYmE=" },
		{ "foobar", "Zm9vYmFy" },
	};
	/* 64 chars of alphabet decode to 48 bytes, which re-encode to 64.
	 * These were 32 each first time, and the overflow showed up as the
	 * round-trip vector failing -- in the test, not the port. */
	char enc[80];
	u8 dec[64];
	unsigned int i;
	int n;

	for (i = 0; i < ARRAY_SIZE(vec); i++) {
		int plen = strlen(vec[i].plain), clen = strlen(vec[i].coded);

		n = base64_encode(vec[i].plain, plen, enc);
		check(n == clen && !memcmp(enc, vec[i].coded, clen),
		      "base64_encode of an RFC 4648 vector");

		n = base64_decode(vec[i].coded, clen, dec);
		check(n == plen && !memcmp(dec, vec[i].plain, plen),
		      "base64_decode of an RFC 4648 vector");
	}

	/* The whole alphabet, so a mistyped table entry cannot hide. */
	n = base64_decode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
			  64, dec);
	check(n == 48, "base64_decode of the full alphabet");
	n = base64_encode(dec, 48, enc);
	check(n == 64 && !memcmp(enc,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64),
	      "base64 round-trips the full alphabet");

	/* Rejection. A decoder that accepts anything is not a decoder. */
	check(base64_decode("!", 1, dec) == -1, "base64_decode rejects '!'");
	check(base64_decode("A-", 2, dec) == -1, "base64_decode rejects '-'");
	/* Rejection of stray trailing bits only happens when there is no
	 * padding to shift them out: "Zh==" DECODES FINE and returns 1,
	 * because each '=' shifts `bits` back down to zero and the final
	 * `ac & ((1 << bits) - 1)` is then vacuously zero. "Zh" does not.
	 * Both values here were read out of the original C body, not
	 * reasoned about -- the first version of this vector expected -1 for
	 * "Zh==" and was simply wrong. */
	check(base64_decode("Zh", 2, dec) == -1,
	      "base64_decode rejects unpadded non-zero trailing bits");
	check(base64_decode("Zh==", 4, dec) == 1,
	      "base64_decode accepts \"Zh==\", padding having shifted the bits out");
	check(base64_decode("AB", 2, dec) == -1, "base64_decode rejects \"AB\"");
	check(base64_decode("A", 1, dec) == 0, "base64_decode of \"A\" yields nothing");
	check(base64_decode("====", 4, dec) == 0, "base64_decode of all padding");
}

static void __init test_memweight(void)
{
	static const u8 buf[] __initconst = {
		0x00, 0xff, 0x01, 0x80, 0x0f, 0xf0, 0xaa, 0x55,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x01,
	};
	unsigned int i;
	size_t total = 0;

	check(memweight(buf, 0) == 0, "memweight(_, 0)");
	check(memweight(buf, 1) == 0, "memweight of a zero byte");
	check(memweight(buf + 1, 1) == 8, "memweight of 0xff");
	check(memweight(buf + 6, 2) == 8, "memweight of 0xaa 0x55");
	check(memweight(buf + 8, 8) == 64, "memweight of eight 0xff, aligned run");
	check(memweight(buf, sizeof(buf)) == 8 + 1 + 1 + 4 + 4 + 4 + 4 + 64 + 1,
	      "memweight of the whole buffer");

	/* Every unaligned start and every length: the C's three-phase walk
	 * changes shape at each boundary and the Rust's does not, so this is
	 * where they would part company if the divergence were wrong. */
	for (i = 0; i < sizeof(buf); i++)
		total += memweight(buf + i, 1);
	check(total == memweight(buf, sizeof(buf)),
	      "memweight is the sum of its bytes at every offset");
}

#if IS_ENABLED(CONFIG_GENERIC_NET_UTILS)
static void __init test_mac_pton(void)
{
	u8 mac[ETH_ALEN];
	static const u8 expect[ETH_ALEN] __initconst = {
		0x00, 0x1a, 0x2b, 0xcd, 0xef, 0xff
	};

	check(mac_pton("00:1a:2b:cd:ef:ff", mac) && !memcmp(mac, expect, ETH_ALEN),
	      "mac_pton of a valid address");
	check(mac_pton("00:1A:2B:CD:EF:FF", mac) && !memcmp(mac, expect, ETH_ALEN),
	      "mac_pton is case-insensitive");

	memset(mac, 0xa5, ETH_ALEN);
	check(!mac_pton("", mac), "mac_pton rejects an empty string");
	check(!mac_pton("00:1a:2b:cd:ef", mac), "mac_pton rejects a short address");
	check(!mac_pton("00:1a:2b:cd:ef:f", mac), "mac_pton rejects a truncated byte");
	check(!mac_pton("00-1a-2b-cd-ef-ff", mac), "mac_pton rejects dashes");
	check(!mac_pton("gg:1a:2b:cd:ef:ff", mac), "mac_pton rejects a non-hex digit");
	check(mac[0] == 0xa5 && mac[ETH_ALEN - 1] == 0xa5,
	      "mac_pton does not dirty the result on failure");

	/* Trailing junk is ignored, as the C does. */
	check(mac_pton("00:1a:2b:cd:ef:ff:aa", mac) && !memcmp(mac, expect, ETH_ALEN),
	      "mac_pton ignores trailing junk");
}
#else
static void __init test_mac_pton(void) { }
#endif

#if IS_ENABLED(CONFIG_UNION_FIND)
static void __init test_union_find(void)
{
	struct uf_node n[8];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(n); i++)
		uf_node_init(&n[i]);

	for (i = 0; i < ARRAY_SIZE(n); i++)
		check(uf_find(&n[i]) == &n[i], "a fresh node is its own root");

	uf_union(&n[0], &n[1]);
	uf_union(&n[2], &n[3]);
	/* Union by rank: joining two rank-0 nodes must make the survivor
	 * rank 1. Without this the set membership checks below still pass
	 * with the ranking removed entirely, and the tree degenerates into a
	 * list without anything noticing. */
	check(uf_find(&n[0])->rank == 1, "joining two singletons gives the root rank 1");
	check(uf_find(&n[2])->rank == 1, "and again for the second pair");
	check(uf_find(&n[0]) == uf_find(&n[1]), "0 and 1 joined");
	check(uf_find(&n[2]) == uf_find(&n[3]), "2 and 3 joined");
	check(uf_find(&n[0]) != uf_find(&n[2]), "the two sets are still distinct");

	uf_union(&n[1], &n[2]);
	check(uf_find(&n[0]) == uf_find(&n[3]), "joining the sets joins their members");
	check(uf_find(&n[0])->rank == 2, "joining two rank-1 trees gives rank 2");

	/* A chain, then one find, which must compress it. Rank must not grow
	 * when a shorter tree is merged into a taller one. */
	for (i = 4; i < ARRAY_SIZE(n); i++)
		uf_union(&n[4], &n[i]);
	check(uf_find(&n[7]) == uf_find(&n[4]), "the chain is one set");
	check(uf_find(&n[7])->parent == uf_find(&n[7]), "the root points at itself");

	uf_union(&n[0], &n[0]);
	check(uf_find(&n[0]) == uf_find(&n[3]), "uf_union of a node with itself is a no-op");
}
#else
static void __init test_union_find(void) { }
#endif

static void __init test_bcd(void)
{
	unsigned int i;
	bool ok = true;

	check(_bcd2bin(0x00) == 0, "_bcd2bin(0x00)");
	check(_bcd2bin(0x09) == 9, "_bcd2bin(0x09)");
	check(_bcd2bin(0x10) == 10, "_bcd2bin(0x10)");
	check(_bcd2bin(0x99) == 99, "_bcd2bin(0x99)");
	check(_bin2bcd(0) == 0x00, "_bin2bcd(0)");
	check(_bin2bcd(9) == 0x09, "_bin2bcd(9)");
	check(_bin2bcd(10) == 0x10, "_bin2bcd(10)");
	check(_bin2bcd(99) == 0x99, "_bin2bcd(99)");

	/* Round-trip the whole range RTC drivers use. */
	for (i = 0; i <= 99; i++)
		ok = ok && _bcd2bin(_bin2bcd(i)) == i;
	check(ok, "bcd round-trips 0..99");
}

#if IS_ENABLED(CONFIG_CRC16)
static void __init test_crc16(void)
{
	static const u8 check123[] __initconst = "123456789";
	u8 buf[256];
	unsigned int i;
	u16 c;

	/* The CRC-16/ARC check value, from the catalogue of parametrised CRCs
	 * -- not from our own table, so a wrong table cannot agree with it. */
	check(crc16(0, check123, 9) == 0xBB3D, "crc16(\"123456789\") == 0xBB3D");

	check(crc16(0, buf, 0) == 0, "crc16 of nothing is the seed");
	check(crc16(0x1234, buf, 0) == 0x1234, "crc16 of nothing keeps the seed");

	/* Every single byte, which walks every one of the 256 table entries.
	 * The table is generated by a const fn in the Rust rather than
	 * transcribed, so this is what says the generator was right. */
	for (i = 0; i < 256; i++)
		buf[i] = (u8)i;
	c = 0;
	for (i = 0; i < 256; i++) {
		u8 one = (u8)i;

		c ^= crc16(0, &one, 1);
	}
	check(c == 0x0000, "crc16 of every single byte XORs to zero");
	check(crc16(0, buf, 256) == 0xBAD3, "crc16 of 0x00..0xff");
}
#else
static void __init test_crc16(void) { }
#endif

static void __init test_win_minmax(void)
{
	struct minmax m = {};
	u32 win = 100;

	/* EVERY EXPECTATION BELOW WAS READ OUT OF THE ORIGINAL C BODY, not
	 * reasoned about. The first version of this block asserted that a
	 * zeroed tracker returns the first min sample, and it does not --
	 * see the note further down. Three vectors were wrong and the port
	 * was right, which is the third time that has happened here. */

	/* First sample sets all three slots. */
	check(minmax_running_max(&m, win, 10, 5) == 5, "first max sample");
	check(minmax_get(&m) == 5, "minmax_get after the first sample");
	check(m.s[0].v == 5 && m.s[1].v == 5 && m.s[2].v == 5,
	      "the first sample fills all three slots");

	/* A new maximum forgets everything earlier. */
	check(minmax_running_max(&m, win, 20, 9) == 9, "a new max wins");
	check(m.s[0].v == 9 && m.s[1].v == 9 && m.s[2].v == 9,
	      "a new max resets all three slots");

	/* A smaller sample must not displace the running max, and past a
	 * quarter of the window it becomes the 2nd AND 3rd choice. */
	check(minmax_running_max(&m, win, 60, 3) == 9, "a smaller sample keeps the max");
	check(m.s[0].v == 9 && m.s[1].v == 3 && m.s[2].v == 3,
	      "past win/4 it takes the 2nd and 3rd slots");

	/* Once the window has passed entirely, the max expires. */
	check(minmax_running_max(&m, win, 300, 1) == 1, "the max expires with the window");

	/* A ZEROED struct minmax IS NOT A VALID START STATE FOR THE MIN
	 * TRACKER, and this is worth an assertion rather than a comment.
	 * s[0].v is 0, no sample is <= 0, so nothing ever displaces it until
	 * the window expires -- the tracker reports a minimum of 0 for a
	 * value that was never measured. The max tracker has no such problem
	 * because any sample is >= 0. Callers are expected to seed it with
	 * minmax_reset(); tcp does. Both arms agree, so this is the C's
	 * behaviour and not ours to change (GOALS.md §5). */
	memset(&m, 0, sizeof(m));
	check(minmax_running_min(&m, win, 10, 5) == 0,
	      "a zeroed tracker reports min 0, not the first sample");

	minmax_reset(&m, 10, 5);
	check(minmax_get(&m) == 5, "minmax_reset seeds the tracker");
	check(minmax_running_min(&m, win, 20, 9) == 5, "a larger sample keeps the min");
	check(minmax_running_min(&m, win, 30, 2) == 2, "a new min wins");
	check(minmax_running_min(&m, win, 300, 7) == 7, "the min expires with the window");

	/* Timestamps wrap, and the C's subtraction is modular. If the Rust
	 * had used a checked subtraction this would be a kernel panic rather
	 * than a wrong answer. */
	memset(&m, 0, sizeof(m));
	minmax_running_max(&m, win, 0xfffffff0u, 4);
	check(minmax_running_max(&m, win, 0x00000010u, 2) == 4,
	      "a wrapped timestamp is still inside the window");
}

static int __init cmp_first_byte_libtest(const void *a, const void *b)
{
	return (int)*(const u8 *)a - (int)*(const u8 *)b;
}

static int __init cmp_u32(const void *a, const void *b)
{
	u32 x = *(const u32 *)a, y = *(const u32 *)b;

	return (x > y) - (x < y);
}

static int __init cmp_u32_r(const void *a, const void *b, const void *priv)
{
	return cmp_u32(a, b);
}

static unsigned int swap_calls __initdata;

/* Forces the callback swap path instead of the three built-in strategies. */
static void __init swap_u32(void *a, void *b, int size)
{
	u32 t = *(u32 *)a;

	swap_calls++;
	*(u32 *)a = *(u32 *)b;
	*(u32 *)b = t;
}

static bool __init is_sorted_u32(const u32 *v, unsigned int n)
{
	unsigned int i;

	for (i = 1; i < n; i++)
		if (v[i - 1] > v[i])
			return false;
	return true;
}

static void __init test_sort(void)
{
	/* An array with duplicates, a run already in order, and a run in
	 * reverse -- the three shapes a heapsort bug tends to survive on one
	 * of and fail on another. */
	static const u32 seed[] __initconst = {
		9, 3, 3, 7, 1, 1, 1, 8, 2, 5, 4, 6, 0, 9, 9, 2,
		10, 11, 12, 13, 14, 15, 16, 17,
		17, 16, 15, 14, 13, 12, 11, 10,
	};
	u32 v[ARRAY_SIZE(seed)];
	unsigned int n;

	/* Every prefix length, so the num < 2 and num == 2 and num == 3 edges
	 * the C special-cases at the end of __sort_r are all hit. */
	for (n = 0; n <= ARRAY_SIZE(seed); n++) {
		memcpy(v, seed, n * sizeof(v[0]));
		sort(v, n, sizeof(v[0]), cmp_u32, NULL);
		if (!is_sorted_u32(v, n)) {
			check(false, "sort() leaves every prefix sorted");
			return;
		}
	}
	check(true, "sort() leaves every prefix sorted");

	/* EVERY three-element arrangement over {0,1,2}. The C has a special
	 * case at the very end of __sort_r for exactly this length --
	 *   if (n == size * 2 && do_cmp(base, base + size) > 0) swap
	 * -- and deleting it was caught by only one vector above, on a single
	 * fixed seed. 27 arrangements is cheap and covers the case properly.
	 * Found by a prove-can-fail sabotage that very nearly went unnoticed. */
	{
		unsigned int i, j, k;
		bool ok = true;

		for (i = 0; i < 3; i++)
			for (j = 0; j < 3; j++)
				for (k = 0; k < 3; k++) {
					u32 t[3] = { i, j, k };

					sort(t, 3, sizeof(t[0]), cmp_u32, NULL);
					ok = ok && is_sorted_u32(t, 3) &&
					     t[0] + t[1] + t[2] == i + j + k;
				}
		check(ok, "sort() of every three-element arrangement");
	}

	/* And every two-element one, for the same reason. */
	{
		unsigned int i, j;
		bool ok = true;

		for (i = 0; i < 3; i++)
			for (j = 0; j < 3; j++) {
				u32 t[2] = { i, j };

				sort(t, 2, sizeof(t[0]), cmp_u32, NULL);
				ok = ok && t[0] <= t[1] && t[0] + t[1] == i + j;
			}
		check(ok, "sort() of every two-element arrangement");
	}

	/* The custom-swap path, which is a different dispatch arm. */
	memcpy(v, seed, sizeof(seed));
	swap_calls = 0;
	sort(v, ARRAY_SIZE(v), sizeof(v[0]), cmp_u32, swap_u32);
	check(is_sorted_u32(v, ARRAY_SIZE(v)), "sort() with a custom swap");
	check(swap_calls > 0, "the custom swap was actually called");

	/* sort_r(), the direct callback path. */
	memcpy(v, seed, sizeof(seed));
	sort_r(v, ARRAY_SIZE(v), sizeof(v[0]), cmp_u32_r, NULL, NULL);
	check(is_sorted_u32(v, ARRAY_SIZE(v)), "sort_r()");

	/* A permutation must be preserved, not just an ordering produced: a
	 * sort that dropped or duplicated an element would still be sorted. */
	{
		u32 sum = 0, want = 0;
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(seed); i++)
			want += seed[i];
		for (i = 0; i < ARRAY_SIZE(v); i++)
			sum += v[i];
		check(sum == want, "sort() preserves the multiset");
	}

	/* An odd element size forces the byte-at-a-time swap. */
	{
		u8 odd[3 * 9], *p;
		unsigned int i;
		bool ok = true;

		for (i = 0; i < ARRAY_SIZE(odd); i++)
			odd[i] = (u8)(200 - i * 7);
		sort(odd, 9, 3, cmp_first_byte_libtest, NULL);
		for (i = 1, p = odd; i < 9; i++)
			ok = ok && p[(i - 1) * 3] <= p[i * 3];
		check(ok, "sort() with a 3-byte element size");
	}
}

static void __init test_bsearch(void)
{
	static const u32 arr[] __initconst = { 1, 3, 5, 7, 9, 11, 13, 15 };
	u32 key;
	const u32 *hit;
	unsigned int i;
	bool ok = true;

	for (i = 0; i < ARRAY_SIZE(arr); i++) {
		key = arr[i];
		hit = bsearch(&key, arr, ARRAY_SIZE(arr), sizeof(arr[0]), cmp_u32);
		ok = ok && hit == &arr[i];
	}
	check(ok, "bsearch finds every present key at its own address");

	for (key = 0; key <= 16; key += 2) {
		hit = bsearch(&key, arr, ARRAY_SIZE(arr), sizeof(arr[0]), cmp_u32);
		ok = ok && hit == NULL;
	}
	check(ok, "bsearch returns NULL for every absent key");

	key = 1;
	check(bsearch(&key, arr, 0, sizeof(arr[0]), cmp_u32) == NULL,
	      "bsearch of an empty array");
}

/*
 * lib/find_bit.c -> find_bit_rs.rs. No Kconfig guard -- always built,
 * always reached by real callers (cpumask/bitmap iteration) -- but every
 * exported entry point is exercised directly here anyway, since the real
 * callers this boot config takes rarely touch the AND/ANDNOT/multi-word
 * or nth-bit paths. `size` is always a runtime value (an on-stack
 * `volatile`-read count), so every call goes through the exported
 * `_find_*`/`__find_nth_*` symbols rather than the header's
 * small_const_nbits() compile-time fast path.
 */
static void __init test_find_bit(void)
{
	/* bits: 3, 10, 65, 130 set, spanning three 64-bit words. */
	static const unsigned long bits[3] __initconst = {
		(1UL << 3) | (1UL << 10), 1UL << 1, 1UL << 2,
	};
	static const unsigned long ones[3] __initconst = { ~0UL, ~0UL, ~0UL };
	static const unsigned long zero[3] __initconst = { 0, 0, 0 };
	static const unsigned long one_bit[3] __initconst = { 1UL << 3, 0, 0 };
	volatile unsigned int n = 192;
	unsigned long clump;

	check(find_first_bit(bits, n) == 3, "find_first_bit finds bit 3");
	check(find_first_bit(zero, n) == n, "find_first_bit of all-zero is size");
	check(find_first_and_bit(bits, ones, n) == 3,
	      "find_first_and_bit(bits, all-ones) finds bit 3");
	check(find_first_and_bit(bits, zero, n) == n,
	      "find_first_and_bit(bits, all-zero) is size");
	check(find_first_andnot_bit(bits, zero, n) == 3,
	      "find_first_andnot_bit(bits, all-zero) finds bit 3");
	check(find_first_andnot_bit(bits, bits, n) == n,
	      "find_first_andnot_bit(bits, bits) is size");
	check(find_first_and_and_bit(bits, ones, ones, n) == 3,
	      "find_first_and_and_bit finds bit 3 through two all-ones masks");
	check(find_first_zero_bit(bits, n) == 0,
	      "find_first_zero_bit finds bit 0 (bit 3 is the first SET bit)");
	check(find_first_zero_bit(ones, n) == n,
	      "find_first_zero_bit of all-ones is size");

	check(find_next_bit(bits, n, 4) == 10, "find_next_bit(.., 4) finds bit 10");
	check(find_next_bit(bits, n, 11) == 65, "find_next_bit(.., 11) crosses a word to bit 65");
	check(find_next_bit(bits, n, 131) == n, "find_next_bit past the last set bit is size");
	check(find_next_and_bit(bits, ones, n, 4) == 10,
	      "find_next_and_bit(.., ones, 4) finds bit 10");
	check(find_next_andnot_bit(bits, zero, n, 4) == 10,
	      "find_next_andnot_bit(.., zero, 4) finds bit 10");
	check(find_next_or_bit(zero, bits, n, 4) == 10,
	      "find_next_or_bit(zero, bits, 4) finds bit 10");
	check(find_next_zero_bit(bits, n, 3) == 4,
	      "find_next_zero_bit(.., 3) finds bit 4 (bit 3 itself is set)");

	check(find_nth_bit(bits, n, 0) == 3, "find_nth_bit(.., 0) is the 1st set bit");
	check(find_nth_bit(bits, n, 1) == 10, "find_nth_bit(.., 1) is the 2nd set bit");
	check(find_nth_bit(bits, n, 3) == 130, "find_nth_bit(.., 3) is the 4th (last) set bit");
	/*
	 * NOT `n` (192)! When `size` is an exact multiple of BITS_PER_LONG,
	 * upstream's FIND_NTH_BIT macro falls out of its loop straight into
	 * `sz = idx * BITS_PER_LONG + fns(tmp, nr)` using `tmp` and `nr`
	 * exactly as the last full-word iteration left them (nr=0, tmp=the
	 * last word), with no final range check -- so an out-of-range `n`
	 * that exhausts precisely on a word boundary returns idx*64 +
	 * fns(last_word, 0), not `size`. Confirmed against the real pristine
	 * C directly (not assumed): __find_nth_bit(bits, 192, 4) == 194.
	 * A genuinely odd upstream corner case, faithfully reproduced --
	 * see logs/porting-hazards.md.
	 */
	check(find_nth_bit(bits, n, 4) == 194,
	      "find_nth_bit(.., 4) hits the word-boundary quirk: 194, not size");
	check(find_nth_and_bit(bits, ones, n, 1) == 10,
	      "find_nth_and_bit(.., ones, 1) is the 2nd set bit");
	check(__find_nth_andnot_bit(bits, zero, n, 1) == 10,
	      "__find_nth_andnot_bit(.., zero, 1) is the 2nd set bit");
	check(find_nth_and_andnot_bit(bits, ones, zero, n, 1) == 10,
	      "find_nth_and_andnot_bit(.., ones, zero, 1) is the 2nd set bit");

	check(find_last_bit(bits, n) == 130, "find_last_bit finds bit 130");
	check(find_last_bit(zero, n) == n, "find_last_bit of all-zero is size");
	check(find_last_bit(bits, 4) == 3,
	      "find_last_bit with size=4 stops before bit 10");

	clump = 0xAA;
	check(find_next_clump8(&clump, bits, n, 0) == 0 && clump == (1 << 3),
	      "find_next_clump8 at offset 0 returns byte 0's clump {bit 3}");
	clump = 0xAA;
	check(find_next_clump8(&clump, bits, n, 8) == 8 && clump == (1 << 2),
	      "find_next_clump8 at offset 8 returns byte 1's clump {bit 10}");
	clump = 0xAA;
	check(find_next_clump8(&clump, zero, n, 0) == n,
	      "find_next_clump8 of all-zero is size (clump left untouched)");

	check(find_random_bit(zero, n) == n, "find_random_bit of all-zero is size");
	check(find_random_bit(one_bit, n) == 3,
	      "find_random_bit with exactly one set bit returns it (weight-1 case)");
}

/* Each element carries the index it was created at, so STABILITY can be
 * checked rather than assumed: equal keys must come out in their original
 * order. A merge sort that lost stability would still be sorted. */
struct lt_node {
	struct list_head list;
	u32 key;
	u32 seq;
};

static int __init lt_cmp(void *priv, const struct list_head *a,
			 const struct list_head *b)
{
	const struct lt_node *x = list_entry(a, struct lt_node, list);
	const struct lt_node *y = list_entry(b, struct lt_node, list);

	return (x->key > y->key) - (x->key < y->key);
}

static void __init test_list_sort(void)
{
	static struct lt_node n[64] __initdata;
	static const u32 keys[] __initconst = {
		5, 1, 5, 3, 1, 9, 3, 0, 5, 1, 7, 3, 9, 0, 5, 1,
	};
	struct list_head head;
	struct list_head *p, *prev;
	const struct lt_node *last;
	unsigned int i, num, seen;
	bool ok;

	/* Every prefix length, including the zero- and one-element cases that
	 * return before any merge runs. */
	for (num = 0; num <= ARRAY_SIZE(keys); num++) {
		INIT_LIST_HEAD(&head);
		for (i = 0; i < num; i++) {
			n[i].key = keys[i];
			n[i].seq = i;
			list_add_tail(&n[i].list, &head);
		}

		list_sort(NULL, &head, lt_cmp);

		/* Sorted, stable, prev links intact, nothing lost. All four
		 * are independent of the C: a port that produced a sorted
		 * list with a broken prev link, or that dropped an element,
		 * would pass a "is it sorted" check alone. */
		ok = true;
		last = NULL;
		prev = &head;
		seen = 0;
		list_for_each(p, &head) {
			const struct lt_node *x = list_entry(p, struct lt_node, list);

			if (p->prev != prev)
				ok = false;
			if (last && (x->key < last->key ||
				     (x->key == last->key && x->seq < last->seq)))
				ok = false;
			last = x;
			prev = p;
			seen++;
			if (seen > num)
				break;
		}
		if (seen != num || head.prev != prev)
			ok = false;
		if (!ok) {
			check(false, "list_sort: sorted, stable, linked and complete at every length");
			return;
		}
	}
	check(true, "list_sort: sorted, stable, linked and complete at every length");

	/* All-equal keys: the whole output order is decided by stability, so
	 * this is the case where losing it is unmissable. */
	INIT_LIST_HEAD(&head);
	for (i = 0; i < 32; i++) {
		n[i].key = 7;
		n[i].seq = i;
		list_add_tail(&n[i].list, &head);
	}
	list_sort(NULL, &head, lt_cmp);
	ok = true;
	i = 0;
	list_for_each(p, &head) {
		if (list_entry(p, struct lt_node, list)->seq != i++)
			ok = false;
	}
	check(ok && i == 32, "list_sort of all-equal keys preserves the input order");

	/* Already sorted and exactly reversed: the two shapes that drive the
	 * merge tree to its extremes. */
	INIT_LIST_HEAD(&head);
	for (i = 0; i < 32; i++) {
		n[i].key = 31 - i;
		n[i].seq = i;
		list_add_tail(&n[i].list, &head);
	}
	list_sort(NULL, &head, lt_cmp);
	ok = true;
	i = 0;
	list_for_each(p, &head) {
		if (list_entry(p, struct lt_node, list)->key != i++)
			ok = false;
	}
	check(ok && i == 32, "list_sort of a reversed list");
}

#if IS_ENABLED(CONFIG_XXHASH)
static void __init test_xxhash(void)
{
	static const char msg[] __initconst =
		"Nobody inspects the spammish repetition";
	const size_t len = sizeof(msg) - 1;
	struct xxh64_state st;
	unsigned int i;

	/* The empty-input values are xxHash's OWN published reference test
	 * vectors, not something read out of this tree -- so a table or a
	 * constant that was wrong in both arms could not agree with them. */
	check(xxh32("", 0, 0) == 0x02CC5D05u, "xxh32 of the empty string (reference vector)");
	check(xxh64("", 0, 0) == 0xEF46DB3751D8E999ull,
	      "xxh64 of the empty string (reference vector)");

	/* The rest come from the original C body in port/pristine/. */
	check(xxh32("abc", 3, 0) == 0x32D153FFu, "xxh32(\"abc\")");
	check(xxh64("abc", 3, 0) == 0x44BC2CF5AD770999ull, "xxh64(\"abc\")");
	check(xxh32(msg, len, 0) == 0xE2293B2Fu, "xxh32 of a 39-byte message");
	check(xxh64(msg, len, 0) == 0xFBCEA83C8A378BF1ull, "xxh64 of a 39-byte message");
	check(xxh32(msg, len, 0x9e37) == 0x4C58F0ACu, "xxh32 with a non-zero seed");
	check(xxh64(msg, len, 0x9e37) == 0x34C10AA8B97B727Bull, "xxh64 with a non-zero seed");

	/* Streaming one byte at a time must equal the one-shot hash. This
	 * drives the mem64 carry-over on every single call, which the
	 * one-shot path never touches at all. */
	xxh64_reset(&st, 0);
	for (i = 0; i < len; i++)
		xxh64_update(&st, msg + i, 1);
	check(xxh64_digest(&st) == xxh64(msg, len, 0),
	      "xxh64 streamed one byte at a time equals the one-shot hash");

	/* And in one 39-byte lump, which is under the 32-byte block size the
	 * other way round. */
	xxh64_reset(&st, 0);
	xxh64_update(&st, msg, len);
	check(xxh64_digest(&st) == xxh64(msg, len, 0), "xxh64 streamed in one lump");

	check(xxh64_update(&st, NULL, 1) == -EINVAL, "xxh64_update rejects NULL");

	/* xxh64_reset must zero the WHOLE state including its tail padding.
	 * That is not pedantry: xxh64_copy_state() memcpy()s the struct, so
	 * uninitialised padding propagates. The Rust got this wrong first
	 * time and the userspace differential caught it. */
	{
		struct xxh64_state a, b;

		memset(&a, 0xa5, sizeof(a));
		memset(&b, 0x5a, sizeof(b));
		xxh64_reset(&a, 12345);
		xxh64_reset(&b, 12345);
		check(!memcmp(&a, &b, sizeof(a)),
		      "xxh64_reset leaves no byte of the state undefined");

		memset(&b, 0x5a, sizeof(b));
		xxh64_copy_state(&b, &a);
		check(!memcmp(&a, &b, sizeof(a)), "xxh64_copy_state copies every byte");
	}
}
#else
static void __init test_xxhash(void) { }
#endif

/*
 * Build a newc cpio archive by hand. The parser is what is under test, so
 * the builder shares no code with it: the eight-character hex fields are
 * written out directly.
 */
static size_t __init cpio_add(u8 *out, size_t off, const char *name,
			      size_t bodylen, unsigned int mode)
{
	static const char hex[] __initconst = "0123456789ABCDEF";
	size_t namesize = strlen(name) + 1;
	unsigned int fields[14] = {};
	size_t i, j;

	fields[0] = 0x070701;			/* C_MAGIC */
	fields[2] = mode;			/* C_MODE */
	fields[7] = (unsigned int)bodylen;	/* C_FILESIZE */
	fields[12] = (unsigned int)namesize;	/* C_NAMESIZE */

	for (i = 0; i < 14; i++) {
		size_t w = i ? 8 : 6;	/* magic is six characters */

		for (j = 0; j < w; j++)
			out[off + j] = hex[(fields[i] >> (4 * (w - 1 - j))) & 0xf];
		off += w;
	}
	memcpy(out + off, name, namesize);
	off += namesize;
	off = ALIGN(off, 4);
	for (i = 0; i < bodylen; i++)
		out[off + i] = (u8)(i * 7 + 1);
	off += bodylen;
	return ALIGN(off, 4);
}

static void __init test_earlycpio(void)
{
	static u8 arc[1024] __initdata;
	struct cpio_data cd;
	long nextoff;
	size_t end;

	memset(arc, 0, sizeof(arc));
	end = 0;
	end = cpio_add(arc, end, "kernel/x86/microcode/GenuineIntel.bin", 100, 0100644);
	end = cpio_add(arc, end, "adir/", 0, 0040755);
	end = cpio_add(arc, end, "short", 7, 0100644);

	nextoff = -1;
	cd = find_cpio_data("kernel/x86/microcode/GenuineIntel.bin", arc, end, &nextoff);
	check(cd.data && cd.size == 100, "find_cpio_data finds a member by full path");
	check(cd.name[0] == '\0', "an exact-path match leaves an empty name");
	check(nextoff > 0 && (size_t)nextoff <= end, "nextoff lands inside the archive");

	cd = find_cpio_data("kernel/x86/microcode/", arc, end, NULL);
	check(cd.data && cd.size == 100, "find_cpio_data finds a member by directory prefix");
	check(!strcmp(cd.name, "GenuineIntel.bin"), "and returns the name after the prefix");

	cd = find_cpio_data("short", arc, end, NULL);
	check(cd.data && cd.size == 7, "find_cpio_data finds the last member");

	/* A directory is not a regular file and must not match. */
	cd = find_cpio_data("adir/", arc, end, NULL);
	check(!cd.data, "find_cpio_data does not match a directory entry");

	cd = find_cpio_data("nope", arc, end, NULL);
	check(!cd.data && cd.size == 0, "find_cpio_data reports an absent path");

	/* Truncation and corruption must be rejected, not walked off the end
	 * of. This is the whole reason the function has overrun checks. */
	cd = find_cpio_data("kernel/x86/microcode/", arc, 40, NULL);
	check(!cd.data, "a truncated archive finds nothing");

	arc[0] = 'Z';	/* break the magic */
	cd = find_cpio_data("kernel/x86/microcode/", arc, end, NULL);
	check(!cd.data, "a corrupted magic finds nothing");

	arc[0] = '0';
	arc[10] = 'Z';	/* non-hex inside a field */
	cd = find_cpio_data("kernel/x86/microcode/", arc, end, NULL);
	check(!cd.data, "a non-hex header field finds nothing");
}

/* plist.o is unconditional obj-y in lib/Makefile -- there is no
 * CONFIG_PLIST at all, which is why this is not guarded. */
static void __init test_plist(void)
{
	static struct plist_node n[6] __initdata;
	struct plist_head head;
	struct plist_node *p;
	unsigned int i, k;
	int last;
	bool ok;

	plist_head_init(&head);
	check(plist_head_empty(&head), "a fresh plist is empty");

	/* Insert out of order; node_list must come out ascending by prio.
	 * Lower prio sorts FIRST -- the file calls itself descending-priority
	 * because in the kernel a lower number is a higher priority. */
	for (i = 0; i < ARRAY_SIZE(n); i++) {
		plist_node_init(&n[i], (int)((i * 5) % 7));
		plist_add(&n[i], &head);
	}
	check(!plist_head_empty(&head), "a plist with nodes is not empty");

	ok = true;
	last = -1;
	k = 0;
	plist_for_each(p, &head) {
		if (p->prio < last)
			ok = false;
		last = p->prio;
		k++;
	}
	check(ok && k == ARRAY_SIZE(n), "plist_add keeps the list sorted");

	/* Ties must keep insertion order: nodes 0 and 5 both land on prio 0
	 * and 4 respectively only if the run order is preserved. */
	/* DELETE FIRST. plist_node_init() reinitialises the node's list
	 * heads, so calling it on a node that is still linked corrupts the
	 * list -- which is what the first version of this block did, and the
	 * "deleting every node empties the plist" check below caught it. */
	plist_del(&n[0], &head);
	plist_node_init(&n[0], 3);
	plist_add(&n[0], &head);
	ok = true;
	last = -1;
	plist_for_each(p, &head)
		if (p->prio < last)
			ok = false;
		else
			last = p->prio;
	check(ok, "plist stays sorted after a del and re-add at a new priority");

	/* Deleting the head of a priority bucket must hand the bucket on, or
	 * every node behind it becomes invisible to plist_add(). Deleting all
	 * of them must leave an empty list, not a corrupt one. */
	for (i = 0; i < ARRAY_SIZE(n); i++)
		plist_del(&n[i], &head);
	check(plist_head_empty(&head), "deleting every node empties the plist");

	/* THE 6.18.49 plist_requeue() BUG, asserted on purpose.
	 *
	 * plist_requeue() should move a node to the end of its own priority
	 * run. When the node heads the LAST priority bucket it lands at the
	 * head of the whole list instead, because prio_list is a headless
	 * ring and .next wraps to the first bucket. See
	 * port/test/lib/main.c for the full mechanism.
	 *
	 * The port reproduces it deliberately: GOALS.md §5 says a difference
	 * callers can observe is not ours to change. If this check starts
	 * failing, upstream fixed it and the port must follow -- it is NOT a
	 * regression in the Rust. */
	plist_head_init(&head);
	plist_node_init(&n[0], 0);
	plist_node_init(&n[1], 1);
	plist_node_init(&n[2], 1);
	for (i = 0; i < 3; i++)
		plist_add(&n[i], &head);
	plist_requeue(&n[1], &head);
	p = plist_first(&head);
	check(p == &n[1],
	      "plist_requeue on the last bucket leaves the node at the FRONT (upstream bug, pinned)");

	/* And the same shape with a bucket after it, where it is correct. */
	plist_head_init(&head);
	plist_node_init(&n[0], 0);
	plist_node_init(&n[1], 1);
	plist_node_init(&n[2], 1);
	plist_node_init(&n[3], 2);
	for (i = 0; i < 4; i++)
		plist_add(&n[i], &head);
	plist_requeue(&n[1], &head);
	check(plist_first(&head) == &n[0], "plist_requeue is correct when a later bucket exists");
	ok = true;
	last = -1;
	plist_for_each(p, &head)
		if (p->prio < last)
			ok = false;
		else
			last = p->prio;
	check(ok, "and leaves the list sorted");
}

#if IS_ENABLED(CONFIG_CRC_CCITT)
static void __init test_crc_ccitt(void)
{
	u8 buf[64];
	unsigned int i;

	/* The kernel's crc_ccitt is the REFLECTED variant, poly 0x8408. With
	 * a zero seed that is CRC-16/KERMIT, whose published check value is
	 * 0x2189 -- from the catalogue of parametrised CRCs, outside this
	 * tree. (0x29B1 is CRC-16/CCITT-FALSE: same name, different
	 * polynomial direction. Getting that wrong is how this vector was
	 * written the first time.) */
	check(crc_ccitt(0, "123456789", 9) == 0x2189,
	      "crc_ccitt(0, \"123456789\") == 0x2189 (CRC-16/KERMIT)");
	check(crc_ccitt(0xffff, "123456789", 9) == 0x6F91,
	      "crc_ccitt(0xffff, \"123456789\") == 0x6F91");
	check(crc_ccitt(0x1234, buf, 0) == 0x1234, "crc_ccitt of nothing keeps the seed");

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (u8)i;
	check(crc_ccitt(0, buf, 1) == crc_ccitt_table[0], "crc_ccitt of one zero byte");
}
#else
static void __init test_crc_ccitt(void) { }
#endif

#if IS_ENABLED(CONFIG_CRC32)
#include <linux/crc32.h>

/*
 * crc32_le_base()/crc32_be_base()/crc32c_base() -- lib/crc/crc32_main_rs.rs
 * -- have no EXPORT_SYMBOL and no public header declaration (see that
 * file's module doc). Declared extern here for the table-COVERAGE checks
 * below only, which need the exact ported function regardless of what this
 * CPU's dispatch would otherwise choose -- unlike crc16.c's/crc-ccitt.c's
 * own symbols (both EXPORT_SYMBOL, reached via their public header), so
 * that precedent doesn't actually apply here (found by review: adversary,
 * 2026-09-06).
 *
 * CORRECTION, 2026-09-06: the note that used to stand here -- "this still
 * links because libtest.o and crc32-main.o both land in the same vmlinux
 * built-in.a in both configs" -- was never actually checked against a link,
 * and is wrong for CONFIG_RUST=n. There, crc32-main_norust.o is what lands
 * in built-in.a, and upstream declares these three `static inline`: no
 * external symbol is emitted for `extern` here to bind to, so a norust
 * vmlinux link fails with "undefined symbol". Found by finally running that
 * link (RAISE 2, logs/floor.md) rather than trusting the prior claim -- see
 * CLAUDE.md, "verify by reading state, never by trusting the action". The
 * _base-only checks below are CONFIG_RUST-only for that reason; the
 * catalogue checks just below, which go through the public API, are not.
 *
 * The catalogue check below calls the PUBLIC crc32_le()/crc32_be() instead
 * of the _base symbols, on purpose: crc32_be_arch is #defined straight to
 * crc32_be_base on x86 (crc32.h has no BE assembly at all), and crc32_le's
 * 9-byte catalogue vector is under CRC_PCLMUL's 16-byte SIMD threshold
 * regardless of this CPU's features, so the public entry point is
 * GUARANTEED to reach this port for both -- strictly stronger evidence than
 * calling the _base symbol directly, and it exercises the real dispatch
 * wrapper too, in BOTH configs. crc32c_arch has no such guarantee (it
 * dispatches to real SSE4.2 CRC32 instructions whenever this CPU has them,
 * unconditionally on length); its _base-only check below is guarded the
 * same way as the le/be ones.
 */
#ifdef CONFIG_RUST
extern u32 crc32_le_base(u32 crc, const u8 *p, size_t len);
extern u32 crc32_be_base(u32 crc, const u8 *p, size_t len);
extern u32 crc32c_base(u32 crc, const u8 *p, size_t len);
#endif

static void __init test_crc32(void)
{
	static const u8 check123[] __initconst = "123456789";
	u8 buf[256];
	unsigned int i;

	/*
	 * Published catalogue check values for "123456789" -- from the
	 * catalogue, not our own table, so a wrong generated table cannot
	 * agree with it by construction:
	 *   CRC-32/ISO-HDLC   (crc32_le, poly 0xedb88320) -> 0xCBF43926
	 *   CRC-32/BZIP2      (crc32_be, poly 0x04c11db7) -> 0xFC891918
	 *   CRC-32C/ISCSI     (crc32c,   poly 0x82f63b78) -> 0xE3069283
	 * Cross-checked independently (not taken on trust): crc32_le's
	 * value matches Python's zlib.crc32, a from-scratch source outside
	 * this project; the be/c values were verified against a bit-level
	 * reference CRC implementation written for this check, cross-
	 * validated against zlib on the le case first (also independently
	 * reproduced by review: adversary, 2026-09-06).
	 *
	 * le/be go through the public crc32_le()/crc32_be() -- seed ~0,
	 * complemented at the end, their own normal calling convention --
	 * which reaches this port's crc32_le_base()/crc32_be_base() with
	 * certainty on this input (see the extern comment above) and so
	 * proves the production dispatch path, not just the port in
	 * isolation. Runs in both configs: crc32_le()/crc32_be() are the
	 * public API either way.
	 */
	check((crc32_le(0xFFFFFFFF, check123, 9) ^ 0xFFFFFFFF) == 0xCBF43926,
	      "crc32_le(\"123456789\") == 0xCBF43926 (CRC-32/ISO-HDLC)");
	check((crc32_be(0xFFFFFFFF, check123, 9) ^ 0xFFFFFFFF) == 0xFC891918,
	      "crc32_be(\"123456789\") == 0xFC891918 (CRC-32/BZIP2)");

#ifdef CONFIG_RUST
	/*
	 * Everything below calls the _base symbols directly, which only
	 * exist as external symbols in the CONFIG_RUST arm (see the extern
	 * comment above) -- upstream's CONFIG_RUST=n crc32-main_norust.c
	 * declares them `static inline`.
	 */
	check((crc32c_base(0xFFFFFFFF, check123, 9) ^ 0xFFFFFFFF) == 0xE3069283,
	      "crc32c_base(\"123456789\") == 0xE3069283 (CRC-32C/ISCSI)");

	check(crc32_le_base(0, buf, 0) == 0, "crc32_le_base of nothing is the seed");
	check(crc32_le_base(0x1234, buf, 0) == 0x1234, "crc32_le_base of nothing keeps the seed");
	check(crc32_be_base(0x1234, buf, 0) == 0x1234, "crc32_be_base of nothing keeps the seed");
	check(crc32c_base(0x1234, buf, 0) == 0x1234, "crc32c_base of nothing keeps the seed");

	/*
	 * Every single byte, seed 0, XORed together. A zero-seed CRC is
	 * GF(2)-linear (crc(x) = XOR of tab[1<<k] over x's set bits), and
	 * each tab[1<<k] entry appears in exactly 128 of the 256 possible
	 * one-byte inputs -- an even count -- so this XORs to zero
	 * regardless of the POLYNOMIAL, for any correctly linear table.
	 * Proves COVERAGE of all 256 entries in each of the three tables
	 * (const fn-generated in the Rust, not transcribed) and catches a
	 * corrupted entry; the catalogue check values above are what
	 * prove correctness against an outside source.
	 */
	{
		u32 xor_le = 0, xor_be = 0, xor_c = 0;

		for (i = 0; i < 256; i++) {
			u8 one = (u8)i;

			xor_le ^= crc32_le_base(0, &one, 1);
			xor_be ^= crc32_be_base(0, &one, 1);
			xor_c  ^= crc32c_base(0, &one, 1);
		}
		check(xor_le == 0, "crc32_le_base of every single byte XORs to zero");
		check(xor_be == 0, "crc32_be_base of every single byte XORs to zero");
		check(xor_c == 0, "crc32c_base of every single byte XORs to zero");
	}

	/*
	 * A 256-byte buffer is well past CRC_PCLMUL's 16-byte threshold, so
	 * this table-coverage check goes through the _base symbols
	 * directly rather than the public API -- through crc32_le()/
	 * crc32_be() on real SIMD-capable hardware this would exercise the
	 * assembly, not the port.
	 */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (u8)i;
	check(crc32_le_base(0, buf, 256) == 0x2493092b, "crc32_le_base(0, 0x00..0xff, 256)");
	check(crc32_be_base(0, buf, 256) == 0xac148725, "crc32_be_base(0, 0x00..0xff, 256)");
	check(crc32c_base(0, buf, 256) == 0x2436a9db, "crc32c_base(0, 0x00..0xff, 256)");
#else
	(void)i;
	(void)buf;
#endif
}
#else
static void __init test_crc32(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LIB_ARC4)
static void __init test_arc4(void)
{
	/* RFC 6229's first vector: a 40-bit key of 01 02 03 04 05. Published
	 * outside this tree, so a broken key schedule cannot agree with it. */
	static const u8 key[5] __initconst = { 0x01, 0x02, 0x03, 0x04, 0x05 };
	static const u8 want[16] __initconst = {
		0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
		0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
	};
	static struct arc4_ctx ctx __initdata;
	static u8 zeros[16] __initdata;
	static u8 ks[16] __initdata;
	static u8 buf[64] __initdata;
	unsigned int i;

	memset(zeros, 0, sizeof(zeros));
	arc4_setkey(&ctx, key, sizeof(key));
	arc4_crypt(&ctx, ks, zeros, sizeof(ks));
	check(!memcmp(ks, want, sizeof(want)), "arc4 matches the RFC 6229 vector");

	/* Streaming in pieces must equal one call: the state carries. */
	arc4_setkey(&ctx, key, sizeof(key));
	for (i = 0; i < sizeof(ks); i++)
		arc4_crypt(&ctx, ks + i, zeros + i, 1);
	check(!memcmp(ks, want, sizeof(want)),
	      "arc4 one byte at a time equals one call");

	/* And in place, which is how every caller uses it. */
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (u8)(i * 13 + 7);
	arc4_setkey(&ctx, key, sizeof(key));
	arc4_crypt(&ctx, buf, buf, sizeof(buf));
	check(buf[0] != 7, "arc4 in place actually changed the buffer");
	arc4_setkey(&ctx, key, sizeof(key));
	arc4_crypt(&ctx, buf, buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		if (buf[i] != (u8)(i * 13 + 7))
			break;
	check(i == sizeof(buf), "arc4 in place round-trips");

	arc4_crypt(&ctx, buf, buf, 0);
	check(true, "arc4_crypt of zero bytes does not fault");
}
#else
static void __init test_arc4(void) { }
#endif

static void __init test_clz_ctz(void)
{
	/* Nothing in the kernel calls these by name -- the compiler emits
	 * calls to them for __builtin_ctz on paths where the inline form is
	 * not used. So they are called directly here, which is the only way
	 * criterion 5 can be satisfied for them at all. */
	unsigned int k;
	bool ok = true;

	for (k = 0; k < 32; k++) {
		ok = ok && __ctzsi2((int)(1u << k)) == (int)k;
		ok = ok && __clzsi2((int)(1u << k)) == (int)(31 - k);
	}
	check(ok, "__ctzsi2 and __clzsi2 on every single-bit value");

	ok = true;
	for (k = 0; k < 64; k++) {
		ok = ok && __ctzdi2(1ull << k) == (int)k;
		ok = ok && __clzdi2(1ull << k) == (int)(63 - k);
	}
	check(ok, "__ctzdi2 and __clzdi2 on every single-bit value");

	check(__clzsi2(0) == 32, "__clzsi2(0) == 32");
	check(__clzdi2(0) == 64, "__clzdi2(0) == 64");
	/* The C is UNDEFINED at zero for the ctz pair -- __ffs is bsf on x86,
	 * which leaves its destination unchanged. The Rust returns the width.
	 * Pinned so the divergence is asserted, not merely written down.
	 *
	 * IT IS A GUARANTEE ONLY THE RUST MAKES, so it is only asserted when the
	 * Rust is what is built. Measured on config-norust, the first time that
	 * arm ran (logs/floor.md RAISE 2): __ctzsi2(0) FAILED and __ctzdi2(0)
	 * PASSED, out of the same undefined construct. That is what undefined
	 * behaviour looks like from the outside -- one of the two happened to
	 * leave the right value in the register -- and asserting it against
	 * upstream C would have been asserting an accident.
	 */
#if IS_ENABLED(CONFIG_RUST)
	check(__ctzsi2(0) == 32, "__ctzsi2(0) == 32 (defined where the C was not)");
	check(__ctzdi2(0) == 64, "__ctzdi2(0) == 64 (defined where the C was not)");
#endif
}

static void __init test_chacha(void)
{
	/* RFC 8439 section 2.3.2's worked ChaCha20 block: the standard
	 * constants, key 00..1f, counter 1, nonce 09 00 00 00 4a 00 00 00
	 * 00 00 00 00. Published outside this tree, so a permutation that
	 * was wrong in both arms could not agree with it. */
	static const u32 init[16] __initconst = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000
	};
	static const u8 want[16] __initconst = {
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
		0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4
	};
	static struct chacha_state st __initdata;
	static u8 out[CHACHA_BLOCK_SIZE] __initdata;
	static u32 hout[HCHACHA_OUT_WORDS] __initdata;

	memcpy(st.x, init, sizeof(init));
	chacha_block_generic(&st, out, 20);
	check(!memcmp(out, want, sizeof(want)),
	      "chacha20 matches the RFC 8439 worked block");
	check(st.x[12] == 2, "chacha_block_generic increments the block counter");

	/* Twelve rounds must differ from twenty, or the round count is being
	 * ignored -- which a single fixed vector would not notice. */
	memcpy(st.x, init, sizeof(init));
	chacha_block_generic(&st, out, 12);
	check(memcmp(out, want, sizeof(want)) != 0,
	      "chacha12 differs from chacha20");

	/* hchacha must not touch its input state, and must not simply be the
	 * first eight words of the block. */
	memcpy(st.x, init, sizeof(init));
	hchacha_block_generic(&st, hout, 20);
	check(!memcmp(st.x, init, sizeof(init)),
	      "hchacha_block_generic leaves the input state alone");
	check(memcmp(hout, out, sizeof(hout)) != 0,
	      "hchacha output is not the head of a chacha block");
}

#if IS_ENABLED(CONFIG_CRYPTO_LIB_MD5)
/*
 * lib/crypto/md5.c -> md5_rs.rs. CONFIG_CRYPTO_LIB_MD5 is config-full only
 * (config-fast never enables it) and CONFIG_KUNIT is config-fast only, so
 * unlike siphash/blake2s this module can never get a KUnit proof caller --
 * this libtest.c vector set is the whole of criterion 5 for it. Values from
 * RFC 1321 (MD5) and RFC 2202 (HMAC-MD5), reproduced independently with
 * Python's hashlib/hmac rather than hand-computed -- published outside this
 * tree, so a mistranslation wrong in the same way in both places could not
 * agree with them.
 */
static void __init test_md5(void)
{
	static const u8 abc[3] __initconst = { 'a', 'b', 'c' };
	static const u8 msgdigest[14] __initconst =
		"message digest"; /* string init into a u8[], not a char* arg -- avoids
				    * a signed/unsigned pointer mismatch against md5()'s
				    * `const u8 *data`. */
	static const u8 want_empty[MD5_DIGEST_SIZE] __initconst = {
		0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
		0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
	};
	static const u8 want_abc[MD5_DIGEST_SIZE] __initconst = {
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
	};
	static const u8 want_msgdigest[MD5_DIGEST_SIZE] __initconst = {
		0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
		0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
	};
	/* 64 'a's: exactly one block, so the second call in the loop below
	 * lands exactly on the boundary a wrong accounting breaks. */
	static const u8 want_64a[MD5_DIGEST_SIZE] __initconst = {
		0x01, 0x48, 0x42, 0xd4, 0x80, 0xb5, 0x71, 0x49,
		0x5a, 0x4a, 0x03, 0x63, 0x79, 0x3f, 0x73, 0x67,
	};
	static const u8 sixty_four_a[64] __initconst = {
		[0 ... 63] = 'a',
	};
	struct md5_ctx ctx;
	u8 out[MD5_DIGEST_SIZE];
	unsigned int i;

	md5(NULL, 0, out);
	check(!memcmp(out, want_empty, sizeof(out)), "md5(\"\") matches RFC 1321");

	md5(abc, sizeof(abc), out);
	check(!memcmp(out, want_abc, sizeof(out)), "md5(\"abc\") matches RFC 1321");

	md5(msgdigest, sizeof(msgdigest), out);
	check(!memcmp(out, want_msgdigest, sizeof(out)),
	      "md5(\"message digest\") matches RFC 1321");

	/* Same input as the one-shot "abc" case, but fed one byte at a time,
	 * to catch a partial-block accounting bug a whole-buffer call would
	 * not reach. */
	md5_init(&ctx);
	for (i = 0; i < sizeof(abc); i++)
		md5_update(&ctx, &abc[i], 1);
	md5_final(&ctx, out);
	check(!memcmp(out, want_abc, sizeof(out)),
	      "md5_update() one byte at a time matches the one-shot call");

	/* 64 'a's fed one byte at a time: the last update lands exactly on
	 * the block boundary, exercising md5_final()'s "the buffer is
	 * completely full" padding path. */
	md5_init(&ctx);
	for (i = 0; i < sizeof(sixty_four_a); i++)
		md5_update(&ctx, &sixty_four_a[i], 1);
	md5_final(&ctx, out);
	check(!memcmp(out, want_64a, sizeof(out)),
	      "md5() of 64 bytes fed one at a time crosses the block boundary correctly");
}

/*
 * lib/crypto/md5.c's HMAC entry points. RFC 2202 case 1 (a short raw key)
 * and case 6 (a key LONGER than the block size, which is the only path that
 * exercises hmac_md5_preparekey()'s internal md5() fallback) -- both
 * independently reproduced with Python's hmac module.
 */
static void __init test_hmac_md5(void)
{
	static const u8 key1[16] __initconst = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};
	static const u8 want1[MD5_DIGEST_SIZE] __initconst = {
		0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
		0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
	};
	static const u8 key6[80] __initconst = {
		[0 ... 79] = 0xaa,
	};
	static const u8 want6[MD5_DIGEST_SIZE] __initconst = {
		0x6b, 0x1a, 0xb7, 0xfe, 0x4b, 0xd7, 0xbf, 0x8f,
		0x0b, 0x62, 0xe6, 0xce, 0x61, 0xb9, 0xd0, 0xcd,
	};
	static const u8 data1[8] __initconst = "Hi There";
	/* 54 bytes, RFC 2202's own length -- sized from the string itself
	 * rather than a literal count, so a stray trailing NUL byte (an
	 * explicit size one larger than the true length would silently
	 * include it as message data) cannot creep back in. */
	static const u8 data6[] __initconst =
		"Test Using Larger Than Block-Size Key - Hash Key First";
	enum { DATA6_LEN = sizeof(data6) - 1 };
	struct hmac_md5_key prepared;
	struct hmac_md5_ctx ctx;
	u8 out[MD5_DIGEST_SIZE];

	/* Case 1, via the prepared-key entry points. */
	hmac_md5_preparekey(&prepared, key1, sizeof(key1));
	hmac_md5_init(&ctx, &prepared);
	hmac_md5_update(&ctx, data1, sizeof(data1));
	hmac_md5_final(&ctx, out);
	check(!memcmp(out, want1, sizeof(out)),
	      "hmac_md5() (prepared key) matches RFC 2202 case 1");

	/* Same case, via the one-shot raw-key entry point. */
	hmac_md5_usingrawkey(key1, sizeof(key1), data1, sizeof(data1), out);
	check(!memcmp(out, want1, sizeof(out)),
	      "hmac_md5_usingrawkey() matches RFC 2202 case 1");

	/* Case 6: an 80-byte key is longer than MD5_BLOCK_SIZE (64), so
	 * preparing it must itself hash the key down with md5() first --
	 * the one path in this file that calls md5() from inside HMAC. */
	hmac_md5_usingrawkey(key6, sizeof(key6), data6, DATA6_LEN, out);
	check(!memcmp(out, want6, sizeof(out)),
	      "hmac_md5_usingrawkey() matches RFC 2202 case 6 (key > block size)");
}
#else
static void __init test_md5(void) { }
static void __init test_hmac_md5(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LIB_UTILS)
static void __init test_crypto_xor(void)
{
	static u8 a[40] __initdata, b[40] __initdata, d[48] __initdata;
	unsigned int off, len, i;
	bool ok = true;

	for (i = 0; i < ARRAY_SIZE(a); i++) {
		a[i] = (u8)(i * 61 + 3);
		b[i] = (u8)(i * 17 + 200);
	}

	/* Every destination offset and every length: the chunk width the
	 * function picks depends entirely on how the three pointers line up,
	 * so this is the whole of its behaviour. The trailing byte is
	 * checked too -- a chunk loop that overran by one would still XOR
	 * the requested bytes correctly. */
	for (off = 0; off < 8 && ok; off++)
		for (len = 0; len <= 32 && ok; len++) {
			memset(d, 0xa5, sizeof(d));
			__crypto_xor(d + off, a, b, len);
			for (i = 0; i < len; i++)
				if (d[off + i] != (u8)(a[i] ^ b[i]))
					ok = false;
			if (d[off + len] != 0xa5)
				ok = false;
		}
	check(ok, "__crypto_xor at every offset and length up to 32");

	/* In place, twice, must give the original back. */
	memcpy(d, a, ARRAY_SIZE(a));
	__crypto_xor(d, d, b, ARRAY_SIZE(a));
	__crypto_xor(d, d, b, ARRAY_SIZE(a));
	check(!memcmp(d, a, ARRAY_SIZE(a)), "__crypto_xor in place round-trips");

	__crypto_xor(d, a, b, 0);
	check(true, "__crypto_xor of zero bytes does not fault");
}

/*
 * lib/crypto/memneq.c -> memneq_rs.rs. crypto_memneq() is the != 0 wrapper
 * in include/crypto/utils.h; __crypto_memneq is the exported body.
 *
 * WHAT A MISTRANSLATION BREAKS HERE, and why the vectors look like this:
 *
 *   - size == 16 takes a separate loop-free path, so it is tested apart
 *     from every other size rather than folded into a sweep.
 *   - both paths read a WORD at a time when the pointers allow, then a byte
 *     at a time, so a wrong tail bound shows up only at sizes that are not
 *     a multiple of 8, and only for a difference IN the tail.
 *   - the reads are unaligned by construction, so every case runs at four
 *     start offsets.
 *
 * What this CANNOT test is the property the function exists for: that it
 * takes the same time whatever the data. That is a statement about the
 * emitted instructions, and it is checked by reading them -- see
 * logs/hooks.md.
 */
static void __init test_memneq(void)
{
	static u8 a[80] __initdata, b[80] __initdata;
	unsigned int off, len, i, bit;
	bool ok = true;

	for (i = 0; i < ARRAY_SIZE(a); i++)
		a[i] = (u8)(i * 91 + 7);
	memcpy(b, a, ARRAY_SIZE(a));

	/* Equal is equal, at every length and every start offset. */
	for (off = 0; off < 4 && ok; off++)
		for (len = 0; len <= 48 && ok; len++)
			if (__crypto_memneq(a + off, b + off, len) != 0)
				ok = false;
	check(ok, "__crypto_memneq says equal buffers are equal");

	/* One flipped bit anywhere must be seen -- including in the last
	 * byte, which is the one a wrong loop bound drops. */
	ok = true;
	for (off = 0; off < 4 && ok; off++)
		for (len = 1; len <= 48 && ok; len++)
			for (i = 0; i < len && ok; i++)
				for (bit = 0; bit < 8 && ok; bit++) {
					b[off + i] ^= 1u << bit;
					if (__crypto_memneq(a + off, b + off, len) == 0)
						ok = false;
					b[off + i] ^= 1u << bit;
				}
	check(ok, "__crypto_memneq sees a single flipped bit at any position");

	/* The 16-byte fast path, on its own, at every offset. */
	ok = true;
	for (off = 0; off < 4 && ok; off++) {
		if (__crypto_memneq(a + off, b + off, 16) != 0)
			ok = false;
		for (i = 0; i < 16 && ok; i++) {
			b[off + i] ^= 0x80;
			if (__crypto_memneq(a + off, b + off, 16) == 0)
				ok = false;
			b[off + i] ^= 0x80;
		}
	}
	check(ok, "__crypto_memneq 16-byte path sees a difference in any byte");

	/* A difference PAST the compared length must not be seen. */
	b[16] ^= 0xff;
	check(__crypto_memneq(a, b, 16) == 0,
	      "__crypto_memneq ignores bytes past size");
	b[16] ^= 0xff;

	/* Zero bytes compare equal and must not dereference. */
	check(__crypto_memneq(NULL, NULL, 0) == 0,
	      "__crypto_memneq of zero bytes is equal and does not fault");
}
#else
static void __init test_crypto_xor(void) { }
static void __init test_memneq(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA512)
/*
 * lib/crypto/sha512.c -> sha512_rs.rs. CONFIG_CRYPTO_LIB_SHA512 is
 * config-full only (config-fast never enables it) and CONFIG_KUNIT is
 * config-fast only -- findings.md #11 records why config-full must never
 * carry it (2,146 exported-symbol CRCs move when it does, none of them
 * this port's). So unlike siphash/blake2s, this module can never get a
 * KUnit proof caller; this is the whole of criterion 5 for it, same
 * reasoning as test_md5() above this one gets for the same reason.
 *
 * Values reproduced independently with Python's hashlib/hmac, not
 * hand-computed or copied from this file's own C reference -- a
 * mistranslation wrong in the same way in both places could not agree
 * with an independent computation.
 */
static void __init test_sha512(void)
{
	static const u8 nist2block[] __initconst =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	u8 out384[SHA384_DIGEST_SIZE], out512[SHA512_DIGEST_SIZE];

	static const u8 want384_empty[SHA384_DIGEST_SIZE] __initconst = {
		0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
		0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
		0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
	};
	static const u8 want512_empty[SHA512_DIGEST_SIZE] __initconst = {
		0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
		0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
		0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
		0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
	};
	static const u8 want384_abc[SHA384_DIGEST_SIZE] __initconst = {
		0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
		0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
		0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
	};
	static const u8 want512_abc[SHA512_DIGEST_SIZE] __initconst = {
		0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
	};
	static const u8 want384_nist2block[SHA384_DIGEST_SIZE] __initconst = {
		0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39, 0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39,
		0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab, 0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6,
		0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f, 0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b,
	};
	static const u8 want512_nist2block[SHA512_DIGEST_SIZE] __initconst = {
		0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
		0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
		0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
		0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45,
	};

	sha384(NULL, 0, out384);
	check(!memcmp(out384, want384_empty, sizeof(out384)), "sha384(\"\") matches the independent digest");
	sha512(NULL, 0, out512);
	check(!memcmp(out512, want512_empty, sizeof(out512)), "sha512(\"\") matches the independent digest");

	sha384("abc", 3, out384);
	check(!memcmp(out384, want384_abc, sizeof(out384)), "sha384(\"abc\") matches the independent digest");
	sha512("abc", 3, out512);
	check(!memcmp(out512, want512_abc, sizeof(out512)), "sha512(\"abc\") matches the independent digest");

	sha384(nist2block, sizeof(nist2block) - 1, out384);
	check(!memcmp(out384, want384_nist2block, sizeof(out384)),
	      "sha384 of the NIST two-block vector matches the independent digest");
	sha512(nist2block, sizeof(nist2block) - 1, out512);
	check(!memcmp(out512, want512_nist2block, sizeof(out512)),
	      "sha512 of the NIST two-block vector matches the independent digest");

	/* Incremental in two pieces, split mid-message: catches a carry or
	 * partial-block bug a one-shot call cannot. */
	{
		struct sha512_ctx ctx;

		sha512_init(&ctx);
		sha512_update(&ctx, nist2block, 30);
		sha512_update(&ctx, nist2block + 30, sizeof(nist2block) - 1 - 30);
		sha512_final(&ctx, out512);
		check(!memcmp(out512, want512_nist2block, sizeof(out512)),
		      "sha512 incremental, split mid-message, matches the one-shot digest");
	}

	/* HMAC with a key past SHA512_BLOCK_SIZE -- exercises
	 * hmac_preparekey()'s over-length-key hashing path, the one branch
	 * the ordinary one-shot vectors above never reach. */
	{
		u8 keybuf[200];
		static const u8 data[] __initconst =
			"Sample message for keylen>blocklen, a rather long one indeed";
		static const u8 want_hmac384[SHA384_DIGEST_SIZE] __initconst = {
			0xae, 0xe2, 0x2c, 0xcf, 0x22, 0xb6, 0x9c, 0x53, 0xe4, 0x6e, 0x72, 0x99, 0xc4, 0x6c, 0xfe, 0x31,
			0xa1, 0xc9, 0x69, 0x20, 0xef, 0xdd, 0xb9, 0x00, 0x24, 0x8b, 0xf6, 0x31, 0xbe, 0x8c, 0xa0, 0x0c,
			0x77, 0x9d, 0xaf, 0xe2, 0xd1, 0x12, 0xc4, 0x44, 0x1f, 0xa6, 0x7f, 0x8e, 0x22, 0x96, 0x6b, 0xb7,
		};
		static const u8 want_hmac512[SHA512_DIGEST_SIZE] __initconst = {
			0xe7, 0xef, 0xcc, 0x1e, 0x43, 0x8d, 0x3c, 0xb7, 0x1d, 0xd0, 0x17, 0xad, 0x18, 0x99, 0x75, 0x4e,
			0xd0, 0xfd, 0xf6, 0x8a, 0xd9, 0x40, 0xe4, 0x7e, 0x33, 0x8a, 0x34, 0x53, 0x39, 0xcf, 0xd7, 0x5c,
			0x59, 0x4b, 0xfe, 0xb2, 0x19, 0xf4, 0xa9, 0x09, 0x1d, 0x68, 0x95, 0x04, 0x49, 0x3a, 0x55, 0x7f,
			0x30, 0x12, 0x0a, 0xb8, 0x84, 0x71, 0xfb, 0xd8, 0x94, 0x0a, 0x26, 0x32, 0x37, 0xf6, 0xaa, 0x09,
		};
		unsigned int i;

		for (i = 0; i < sizeof(keybuf); i++)
			keybuf[i] = (u8)i;

		hmac_sha384_usingrawkey(keybuf, sizeof(keybuf), data, sizeof(data) - 1, out384);
		check(!memcmp(out384, want_hmac384, sizeof(out384)),
		      "hmac_sha384 with a >blocklen key matches the independent digest");
		hmac_sha512_usingrawkey(keybuf, sizeof(keybuf), data, sizeof(data) - 1, out512);
		check(!memcmp(out512, want_hmac512, sizeof(out512)),
		      "hmac_sha512 with a >blocklen key matches the independent digest");
	}
}
#else
static void __init test_sha512(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA1)
/*
 * lib/crypto/sha1.c -> sha1_rs.rs. Same reasoning as test_sha512() just
 * above: CONFIG_CRYPTO_LIB_SHA1 is config-full only, CONFIG_KUNIT is
 * config-fast only, so this is the whole of criterion 5 for it. Values
 * reproduced independently with Python's hashlib/hmac.
 */
static void __init test_sha1(void)
{
	u8 out[SHA1_DIGEST_SIZE];

	static const u8 want_empty[SHA1_DIGEST_SIZE] __initconst = {
		0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
		0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
	};
	static const u8 want_abc[SHA1_DIGEST_SIZE] __initconst = {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
		0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
	};

	sha1(NULL, 0, out);
	check(!memcmp(out, want_empty, sizeof(out)), "sha1(\"\") matches the independent digest");
	sha1("abc", 3, out);
	check(!memcmp(out, want_abc, sizeof(out)), "sha1(\"abc\") matches the independent digest");

	/* Incremental in two pieces. */
	{
		struct sha1_ctx ctx;

		sha1_init(&ctx);
		sha1_update(&ctx, "a", 1);
		sha1_update(&ctx, "bc", 2);
		sha1_final(&ctx, out);
		check(!memcmp(out, want_abc, sizeof(out)),
		      "sha1 incremental, split mid-message, matches the one-shot digest");
	}

	/* HMAC with a key past SHA1_BLOCK_SIZE -- exercises the over-length-
	 * key hashing path. */
	{
		u8 keybuf[200];
		static const u8 data[] __initconst =
			"Sample message for keylen>blocklen, a rather long one indeed";
		static const u8 want_hmac[SHA1_DIGEST_SIZE] __initconst = {
			0xab, 0xd3, 0xea, 0x01, 0xa8, 0x88, 0xda, 0xe7, 0xfc, 0x46,
			0xa9, 0xeb, 0x28, 0x12, 0x44, 0x5b, 0x9e, 0xd2, 0x61, 0xdb,
		};
		unsigned int i;

		for (i = 0; i < sizeof(keybuf); i++)
			keybuf[i] = (u8)i;

		hmac_sha1_usingrawkey(keybuf, sizeof(keybuf), data, sizeof(data) - 1, out);
		check(!memcmp(out, want_hmac, sizeof(out)),
		      "hmac_sha1 with a >blocklen key matches the independent digest");
	}
}
#else
static void __init test_sha1(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES)
/*
 * lib/crypto/aes.c -> aes_rs.rs. No arch dispatch exists for this file at
 * all (CONFIG_CRYPTO_LIB_AES_ARCH isn't a Kconfig symbol; AES-NI lives in
 * arch/x86/crypto), and it's config-full only with no upstream KUnit suite
 * either, so this is its whole boot-time proof. Values reproduced
 * independently via Python's `cryptography` library -- a wholly separate
 * AES implementation, not this file's own C read back as its own oracle.
 */
static void __init test_aes(void)
{
	struct crypto_aes_ctx ctx;
	u8 out[AES_BLOCK_SIZE];

	static const u8 key128[AES_KEYSIZE_128] __initconst = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	static const u8 pt128[AES_BLOCK_SIZE] __initconst = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const u8 want128[AES_BLOCK_SIZE] __initconst = {
		0x07, 0xfe, 0xef, 0x74, 0xe1, 0xd5, 0x03, 0x6e,
		0x90, 0x0e, 0xee, 0x11, 0x8e, 0x94, 0x92, 0x93,
	};

	static const u8 key256[AES_KEYSIZE_256] __initconst = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const u8 pt256[AES_BLOCK_SIZE] __initconst = {
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	};
	static const u8 want256[AES_BLOCK_SIZE] __initconst = {
		0xa9, 0x73, 0x87, 0x9d, 0xa7, 0x3d, 0x9a, 0x70,
		0x58, 0xd6, 0x0f, 0xf2, 0x18, 0x92, 0xf7, 0xfe,
	};

	check(aes_expandkey(&ctx, key128, sizeof(key128)) == 0,
	      "aes_expandkey accepts a 128-bit key");
	aes_encrypt(&ctx, out, pt128);
	check(!memcmp(out, want128, sizeof(out)),
	      "aes_encrypt (128-bit key) matches the independent ciphertext");
	aes_decrypt(&ctx, out, want128);
	check(!memcmp(out, pt128, sizeof(out)),
	      "aes_decrypt (128-bit key) round-trips to the original plaintext");

	check(aes_expandkey(&ctx, key256, sizeof(key256)) == 0,
	      "aes_expandkey accepts a 256-bit key");
	aes_encrypt(&ctx, out, pt256);
	check(!memcmp(out, want256, sizeof(out)),
	      "aes_encrypt (256-bit key) matches the independent ciphertext");
	aes_decrypt(&ctx, out, want256);
	check(!memcmp(out, pt256, sizeof(out)),
	      "aes_decrypt (256-bit key) round-trips to the original plaintext");

	check(aes_expandkey(&ctx, key128, 20) == -EINVAL,
	      "aes_expandkey rejects an invalid key length");
}
#else
static void __init test_aes(void) { }
#endif

#if IS_ENABLED(CONFIG_SYMBOLIC_ERRNAME)
/*
 * lib/errname.c -> errname_rs.rs. CONFIG_SYMBOLIC_ERRNAME is config-full
 * only; no upstream KUnit suite exists for it. Values are the well-known
 * POSIX/Linux errno names, checked directly rather than assumed.
 */
static void __init test_errname(void)
{
	check(!strcmp(errname(EIO), "EIO"), "errname(EIO) is \"EIO\"");
	check(!strcmp(errname(-EIO), "-EIO"), "errname(-EIO) is \"-EIO\"");
	check(!strcmp(errname(ENOMEM), "ENOMEM"), "errname(ENOMEM) is \"ENOMEM\"");
	check(!strcmp(errname(-ENOMEM), "-ENOMEM"), "errname(-ENOMEM) is \"-ENOMEM\"");
	check(errname(0) == NULL, "errname(0) is NULL");
	check(errname(99999) == NULL, "errname of an out-of-range value is NULL");
	/* A gap inside the low table: no errno is 41. */
	check(errname(41) == NULL, "errname(41) is NULL (a real gap in the table)");
	/* The 512+ series, and its own internal gap at 520. */
	check(!strcmp(errname(ERESTARTSYS), "ERESTARTSYS"),
	      "errname(ERESTARTSYS) is \"ERESTARTSYS\"");
	check(errname(520) == NULL, "errname(520) is NULL (a gap in the 512+ series)");
}
#else
static void __init test_errname(void) { }
#endif

#if IS_ENABLED(CONFIG_DQL)
/*
 * lib/dynamic_queue_limits.c -> dynamic_queue_limits_rs.rs. CONFIG_DQL is
 * config-full only. dql_completed()/dql_reset() have no caller anywhere
 * in this config's net/ or drivers/ at all (only PowerPC's ibmvnic.c
 * does, not built here) -- genuinely unreached. dql_init() IS called
 * (net/core/dev.c's netdev_init_one_queue(), for every net_device's TX
 * queue under CONFIG_BQL=y, so at least loopback triggers it every boot)
 * but sabotaging it produced no observable failure in this minimal boot
 * -- nothing here reads BQL state (no sysfs queue stats, no real
 * traffic) -- so it is call-graph-reached but not empirically confirmed
 * by this project's own sabotage-and-reboot method. All three get a
 * proof caller here regardless, per GOALS.md's bar: present in vmlinux
 * AND reached.
 *
 * Values traced by hand against the real algorithm (POSDIFF/AFTER_EQ,
 * include/linux/dynamic_queue_limits.h's own comments), not copied from
 * the port -- exercises the "starved" branch (case 1) and the "neither
 * starved nor decreasing" steady-state branch (case 2). stall_thrs stays
 * 0 throughout, so dql_check_stall()'s ring-buffer/retry logic is a
 * deliberately untested branch here -- that path already has 38,263
 * userspace differential cases (port/test/dynamic_queue_limits/,
 * including forced jiffies wraparound) verifying it against the real C;
 * this proof caller's only job is confirming the Rust runs in the
 * kernel, not re-proving correctness.
 */
static void __init test_dql(void)
{
	struct dql dql;

	dql_init(&dql, 1000);
	check(dql.max_limit == (UINT_MAX / 2) - (UINT_MAX / 16),
	      "dql_init sets max_limit to DQL_MAX_LIMIT");
	check(dql.min_limit == 0, "dql_init sets min_limit to 0");
	check(dql.stall_thrs == 0, "dql_init sets stall_thrs to 0");
	check(dql.limit == 0, "dql_init/dql_reset sets limit to min_limit (0)");
	check(dql.lowest_slack == UINT_MAX,
	      "dql_init/dql_reset sets lowest_slack to UINT_MAX");

	/* Case 1: queue 100, complete all 100 -- starved (ovlimit != 0,
	 * inprogress == 0), limit grows from 0 to 100. */
	dql.last_obj_cnt = 100;
	dql.num_queued = 100;
	dql_completed(&dql, 100);
	check(dql.limit == 100, "dql_completed (starved): limit grows to 100");
	check(dql.num_completed == 100, "dql_completed (starved): num_completed is 100");
	check(dql.adj_limit == 200, "dql_completed (starved): adj_limit is limit+completed (200)");
	check(dql.prev_num_queued == 100, "dql_completed (starved): prev_num_queued is 100");
	check(dql.prev_last_obj_cnt == 100, "dql_completed (starved): prev_last_obj_cnt is 100");
	check(dql.prev_ovlimit == 0, "dql_completed (starved): prev_ovlimit resets to 0 (limit changed)");

	/* Case 2: queue 50 more (num_queued 150), complete only 30 --
	 * inprogress (20) but prev_inprogress is 0 (the previous round's
	 * prev_num_queued(100) - num_completed-before-that-round(100) == 0),
	 * so neither the starved nor the decrease branch fires: limit holds
	 * at 100. */
	dql.last_obj_cnt = 50;
	dql.num_queued = 150;
	dql_completed(&dql, 30);
	check(dql.limit == 100, "dql_completed (steady): limit holds at 100");
	check(dql.num_completed == 130, "dql_completed (steady): num_completed is 130");
	check(dql.adj_limit == 230, "dql_completed (steady): adj_limit is limit+completed (230)");
	check(dql.prev_num_queued == 150, "dql_completed (steady): prev_num_queued is 150");
	check(dql.prev_last_obj_cnt == 50, "dql_completed (steady): prev_last_obj_cnt is 50");
	check(dql.prev_ovlimit == 0, "dql_completed (steady): prev_ovlimit is 0 (not over limit)");

	dql_reset(&dql);
	check(dql.limit == 0, "dql_reset sets limit back to min_limit (0)");
	check(dql.num_queued == 0, "dql_reset zeroes num_queued");
	check(dql.num_completed == 0, "dql_reset zeroes num_completed");
	check(dql.history[0] == 0 && dql.history[1] == 0 &&
	      dql.history[2] == 0 && dql.history[3] == 0,
	      "dql_reset zeroes the history ring");
}
#else
static void __init test_dql(void) { }
#endif

/*
 * lib/ratelimit.c -> ratelimit_rs.rs. ___ratelimit() is class A: sabotage
 * (made it panic unconditionally) and reboot showed no fault and an
 * unchanged self-test count on config-fast's minimal busybox boot -- no
 * driver/subsystem in this boot path hits a rate-limited log or
 * net_ratelimit()-style call. `interval` is set far larger than the whole
 * test can possibly take (real jiffies, ticking for real) so the window
 * never expires mid-test regardless of scheduling jitter -- the only
 * thing under test is burst accounting, not timing.
 */
static void __init test_ratelimit(void)
{
	struct ratelimit_state rs =
		RATELIMIT_STATE_INIT(rs, 60 * HZ, 3);

	check(__ratelimit(&rs) == 1, "ratelimit: 1st call within burst allowed");
	check(__ratelimit(&rs) == 1, "ratelimit: 2nd call within burst allowed");
	check(__ratelimit(&rs) == 1, "ratelimit: 3rd call within burst allowed");
	check(__ratelimit(&rs) == 0, "ratelimit: 4th call exceeds burst, suppressed");
	check(__ratelimit(&rs) == 0, "ratelimit: 5th call still suppressed");
	check(ratelimit_state_get_miss(&rs) == 2, "ratelimit: two misses counted");

	/* interval <= 0: never limit -- always allowed, regardless of burst. */
	ratelimit_state_init(&rs, 0, 0);
	check(__ratelimit(&rs) == 1, "ratelimit: interval=0 never limits (1)");
	check(__ratelimit(&rs) == 1, "ratelimit: interval=0 never limits (2)");
	check(__ratelimit(&rs) == 1, "ratelimit: interval=0 never limits (3)");
}

/*
 * lib/flex_proportions.c -> flex_proportions_rs.rs. fprop_global_init() is
 * class B (mm/filemap.c's page_writeback_init() panics on its failure,
 * unconditional core MM init -- sabotage-and-reboot confirmed: made it
 * always return -ENOMEM, and boot panicked immediately with "Attempted to
 * kill the idle task!"). The other seven functions are class A on
 * config-fast's minimal boot (no real block device, so no backing_dev_info
 * ever gets created and no dirty-page threshold calculation ever runs):
 * fprop_local_init_percpu(), __fprop_add_percpu(), fprop_new_period() and
 * fprop_fraction_percpu() each individually sabotage-confirmed (made to
 * panic/fail unconditionally -- clean boot, unchanged self-test count,
 * each reverted before the next); __fprop_add_percpu_max()/
 * fprop_global_destroy()/fprop_local_destroy_percpu() inferred from the
 * same evidence (they call, or are only reachable through, functions
 * already shown unreached here).
 */
static void __init test_flex_proportions(void)
{
	struct fprop_global p;
	struct fprop_local_percpu pl, pl2;
	unsigned long num, den;
	int i;

	check(fprop_global_init(&p, GFP_KERNEL) == 0, "flex_proportions: fprop_global_init succeeds");
	check(fprop_local_init_percpu(&pl, GFP_KERNEL) == 0,
	      "flex_proportions: fprop_local_init_percpu succeeds");

	/* Single contributor: its fraction is the whole. Deltas here are
	 * deliberately large (>> any realistic percpu_counter_batch on this
	 * boot's CPU count): percpu_counter_add_batch() only flushes to the
	 * global, cross-CPU-visible count once the per-CPU stashed amount
	 * reaches `batch` in magnitude (lib/percpu_counter.c), and
	 * fprop_fraction_percpu() reads via percpu_counter_read_positive()
	 * (a plain, possibly-stale-until-flushed read), not
	 * percpu_counter_sum() (always exact). A small delta here would make
	 * this proof caller's outcome depend on real per-CPU batching state
	 * -- CPU count, which CPU runs this, the exact batch threshold --
	 * none of which the userspace differential's simplified,
	 * always-exact percpu_counter simulation reproduces or needs to
	 * (that simulation's own header comment says as much). Caught
	 * exactly this way: the differential passed ~7M cases before this
	 * proof caller, run for real in the kernel, disagreed with itself
	 * until the numbers were large enough. */
	__fprop_add_percpu(&p, &pl, 1000000);
	fprop_fraction_percpu(&p, &pl, &num, &den);
	/* Not exactly num == den: fprop_global_init() seeds p->events at 1,
	 * not 0 ("Use 1 to avoid dealing with periods with 0 events" --
	 * that file's own comment), so a sole contributor's fraction is
	 * 1000000/1000001, not exactly whole. Checked as a robust invariant
	 * (num > 0, den >= num, den within the known +1 seed of num)
	 * instead of exact equality for the same reason as the batching
	 * note above -- caught the same way, an assumption of this proof
	 * caller's, not the port. */
	check(num > 0 && den >= num && den - num <= 1,
	      "flex_proportions: sole contributor gets ~the whole fraction");

	/* A second, independent contributor with an equal share, added in
	 * the SAME period (no fprop_new_period() between them, so neither
	 * has been aged/halved relative to the other yet): the split should
	 * be ~even (tolerating either arm's identical integer rounding, not
	 * exact equality). Ordering matters here -- an earlier draft of this
	 * check called fprop_new_period() between adding pl and pl2, which
	 * halves pl's weight (via fprop_reflect_period_percpu's lazy aging)
	 * before pl2 ever contributes; that is CORRECT "flexible aging"
	 * behaviour, not a bug, and it means a 50/50 split was never the
	 * right expectation once aging comes between the two contributions
	 * -- caught by this proof caller disagreeing with the (already
	 * differential-verified) port, not the other way around. */
	check(fprop_local_init_percpu(&pl2, GFP_KERNEL) == 0,
	      "flex_proportions: fprop_local_init_percpu (2nd) succeeds");
	__fprop_add_percpu(&p, &pl2, 1000000);
	fprop_fraction_percpu(&p, &pl, &num, &den);
	check(num * 2 >= den - 1 && num * 2 <= den + 1,
	      "flex_proportions: two equal contributors split ~evenly");

	/* __fprop_add_percpu_max() with max_frac == FPROP_FRAC_BASE takes
	 * its unconditional tail-call shape (the `max_frac < FPROP_FRAC_BASE`
	 * guard is false) -- same observable effect as __fprop_add_percpu(). */
	__fprop_add_percpu_max(&p, &pl2, FPROP_FRAC_BASE, 500000);

	/* NOW advance one ordinary period: both contributors' weights halve
	 * together (pl explicitly reflected by this same call reaching
	 * fprop_fraction_percpu below; pl2 lazily, next time IT is read) --
	 * pl is still a real, nonzero contributor, just not "the whole"
	 * anymore since pl2 exists too. */
	check(fprop_new_period(&p, 1) == true,
	      "flex_proportions: fprop_new_period reports events survived one halving");
	fprop_fraction_percpu(&p, &pl, &num, &den);
	check(num > 0 && num < den,
	      "flex_proportions: pl remains a real, partial contributor after one period");

	/* A single period jump of >= BITS_PER_LONG skips the halving
	 * (`periods < 64` false) and re-zeroes the global counter outright,
	 * while leaving `pl` -- untouched since -- fully stale:
	 * fprop_reflect_period_percpu()'s "aging zeroed our fraction?" ELSE
	 * branch (period - pl->period >= BITS_PER_LONG) zeroes pl's own
	 * contribution absolutely, not by halving. */
	check(fprop_new_period(&p, BITS_PER_LONG + 1) == true,
	      "flex_proportions: fprop_new_period reports events survived a large period jump");
	fprop_fraction_percpu(&p, &pl, &num, &den);
	check(num == 0, "flex_proportions: a fully-aged-out local counter reports zero");

	/* Prove-can-fail sentinel: with a genuinely zero global counter (no
	 * events at all), fprop_new_period() must report false. */
	i = fprop_new_period(&p, 1);
	check(i == false, "flex_proportions: fprop_new_period reports false with no events");

	fprop_local_destroy_percpu(&pl);
	fprop_local_destroy_percpu(&pl2);
	fprop_global_destroy(&p);
}

/*
 * lib/buildid.c -> lib/buildid.c (retained: file/folio I/O only) +
 * lib/buildid_rs.rs (the ELF-note-parsing algorithm). Two independently
 * reachable pieces, split by config:
 *
 * - init/main.c's start_kernel() calls init_vmlinux_build_id()
 *   unconditionally. On config-full (CONFIG_VMCORE_INFO=y) that resolves to
 *   the REAL function, not linux/buildid.h's no-op inline stub, so
 *   build_id_parse_buf(), parse_build_id(), freader_init_from_mem(),
 *   freader_fetch() and freader_cleanup() are class B there --
 *   sabotage-confirmed: made parse_build_id() panic unconditionally,
 *   config-full's boot never got past start_kernel(); reverted before
 *   rebuilding. config-fast sets neither CONFIG_STACKTRACE_BUILD_ID nor
 *   CONFIG_VMCORE_INFO, so init_vmlinux_build_id() is the stub there and
 *   the mem-backed path is class A on that config.
 *
 * - build_id_parse()/build_id_parse_nofault()/build_id_parse_file() are
 *   class A on BOTH configs: their only real callers -- kernel/bpf/
 *   stackmap.c, kernel/events/core.c, fs/proc/task_mmu.c -- all sit behind
 *   BPF stack-id collection, active perf-event mmap tracking, or a
 *   /proc/<pid>/maps read in the build-id format, none of which this boot
 *   exercises. kernel/module/kallsyms.c's build_id_parse_buf() call is
 *   itself gated on CONFIG_STACKTRACE_BUILD_ID (unset on both configs), so
 *   that path is dead here independent of the config-full coincidence
 *   above.
 *
 * So this proof caller drives the mem-backed path unconditionally (belt
 * and braces on config-full, the only proof on config-fast), and builds a
 * REAL page-cache-backed struct file -- via shmem_kernel_file_setup(), the
 * same primitive tmpfs itself is built on -- so freader_get_folio()'s
 * filemap_get_folio() call runs for real, not stubbed, to drive all three
 * file-backed entry points.
 */
static void __init build_id_note(void *buf, size_t *len,
				  const unsigned char *id, unsigned int id_len)
{
	Elf32_Nhdr *nhdr = buf;
	char *p = buf;

	nhdr->n_namesz = 4;
	nhdr->n_descsz = id_len;
	nhdr->n_type = 3; /* NT_GNU_BUILD_ID -- matches buildid.c's private BUILD_ID */
	p += sizeof(*nhdr);
	memcpy(p, "GNU\0", 4);
	p += 4;
	memcpy(p, id, id_len);
	p += id_len;
	while ((p - (char *)buf) & 3)
		*p++ = 0;
	*len = p - (char *)buf;
}

static void __init test_buildid(void)
{
	static const unsigned char planted_id[20] = {
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	char note[64];
	size_t note_len;
	unsigned char got[BUILD_ID_SIZE_MAX];
	__u32 got_sz;
	struct file *file;
	struct vm_area_struct vma = { };
	Elf32_Ehdr ehdr = { };
	Elf32_Phdr phdr = { };
	loff_t pos;

	build_id_note(note, &note_len, planted_id, sizeof(planted_id));

	/* Mem-backed path: build_id_parse_buf() on the crafted note alone. */
	got_sz = 0;
	memset(got, 0, sizeof(got));
	check(build_id_parse_buf(note, got, note_len) == 0,
	      "buildid: build_id_parse_buf finds the planted note");
	check(memcmp(got, planted_id, sizeof(planted_id)) == 0,
	      "buildid: build_id_parse_buf reproduces the planted build id");

	/* File-backed path: a real ELF32 EXEC image with one PT_NOTE phdr,
	 * written into a real shmem-backed struct file. */
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS32;
	ehdr.e_type = ET_EXEC;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdr);
	ehdr.e_phnum = 1;

	phdr.p_type = PT_NOTE;
	phdr.p_offset = sizeof(ehdr) + sizeof(phdr);
	phdr.p_filesz = note_len;

	file = shmem_kernel_file_setup("libtest-buildid", phdr.p_offset + note_len, 0);
	if (IS_ERR(file)) {
		check(false, "buildid: shmem_kernel_file_setup succeeds");
		return;
	}

	pos = 0;
	kernel_write(file, &ehdr, sizeof(ehdr), &pos);
	kernel_write(file, &phdr, sizeof(phdr), &pos);
	kernel_write(file, note, note_len, &pos);

	got_sz = 0;
	memset(got, 0, sizeof(got));
	check(build_id_parse_file(file, got, &got_sz) == 0,
	      "buildid: build_id_parse_file finds the planted note in a real file");
	check(memcmp(got, planted_id, sizeof(planted_id)) == 0,
	      "buildid: build_id_parse_file reproduces the planted build id");

	vma.vm_file = file;

	got_sz = 0;
	memset(got, 0, sizeof(got));
	check(build_id_parse(&vma, got, &got_sz) == 0,
	      "buildid: build_id_parse finds the planted note via a vma");
	check(memcmp(got, planted_id, sizeof(planted_id)) == 0,
	      "buildid: build_id_parse reproduces the planted build id");

	/* The pages just written are already in the page cache, so the
	 * no-fault path succeeds here too -- it only differs from
	 * build_id_parse() in refusing to bring in pages that AREN'T
	 * already resident. */
	got_sz = 0;
	memset(got, 0, sizeof(got));
	check(build_id_parse_nofault(&vma, got, &got_sz) == 0,
	      "buildid: build_id_parse_nofault finds the already-cached note");
	check(memcmp(got, planted_id, sizeof(planted_id)) == 0,
	      "buildid: build_id_parse_nofault reproduces the planted build id");

	/* Prove-can-fail sentinel: not a valid note (garbage name/desc size). */
	{
		unsigned char garbage[BUILD_ID_SIZE_MAX];

		memset(garbage, 0xff, sizeof(garbage));
		check(build_id_parse_buf(garbage, got, sizeof(garbage)) != 0,
		      "buildid: build_id_parse_buf rejects a buffer that isn't a note");
	}

	fput(file);
}

#if IS_ENABLED(CONFIG_BINARY_PRINTF)
/* vbin_printf() is `__printf(3, 0)` (takes a va_list), so this file needs
 * its own variadic wrapper to produce a binary arg buffer to feed
 * seq_buf_bprintf() -- same shape as seq_buf.c's own seq_buf_printf()
 * wrapping seq_buf_vprintf().
 */
static int __init make_bin_u32(u32 *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vbin_printf(buf, size, fmt, ap);
	va_end(ap);
	return ret;
}
#endif

/*
 * lib/seq_buf.c -> lib/seq_buf.c (retained: seq_buf_printf()/
 * seq_buf_vprintf(), a variadic C definition and its va_list consumer --
 * see that file's own header comment) + lib/seq_buf_rs.rs (everything
 * else). Genuinely class A on BOTH configs, sabotage-confirmed: made all
 * ten Rust-defined entry points panic unconditionally in one build (a
 * combined sweep, not ten separate rebuild-boot cycles -- each call site
 * is independent, so one clean boot with all ten sabotaged at once is as
 * conclusive as ten separate ones would have been) -- clean boot, 0
 * faults, unchanged self-test count, on both configs. Reverted before
 * rebuilding. `rig/fanin.sh`'s 45 call sites are real (kernel/sched/core.c,
 * kernel/panic.c, tracing's trace_seq, etc.) but none of them fire during
 * this minimal boot to a shell prompt -- e.g. sched/core.c's
 * preempt_model_str() (which DOES call seq_buf_puts()) is only invoked
 * when something reads it, not unconditionally at boot; the "PREEMPT_DYNAMIC"
 * text in this project's own boot banner comes from scripts/mkcompile_h at
 * BUILD time, a coincidence that looked like evidence before the sabotage
 * disproved it.
 */
static void __init test_seq_buf(void)
{
	char buf[128];
	struct seq_buf s;

	seq_buf_init(&s, buf, sizeof(buf));
	check(seq_buf_puts(&s, "hello") == 0, "seq_buf: puts succeeds");
	check(seq_buf_used(&s) == 5, "seq_buf: puts advances len by strlen");
	check(memcmp(buf, "hello", 5) == 0, "seq_buf: puts writes the bytes");

	check(seq_buf_putc(&s, '!') == 0, "seq_buf: putc succeeds");
	check(buf[5] == '!', "seq_buf: putc writes the byte");

	/* Prove-can-fail: a buffer too small for what is written to it. */
	{
		char tiny[2];
		struct seq_buf t;

		seq_buf_init(&t, tiny, sizeof(tiny));
		check(seq_buf_puts(&t, "abcdef") == -1, "seq_buf: puts overflow is reported");
		check(seq_buf_has_overflowed(&t), "seq_buf: overflow flag is set");
	}

	seq_buf_init(&s, buf, sizeof(buf));
	{
		static const unsigned char mem[4] = { 0xde, 0xad, 0xbe, 0xef };

		check(seq_buf_putmem(&s, mem, sizeof(mem)) == 0, "seq_buf: putmem succeeds");
		check(memcmp(buf, mem, sizeof(mem)) == 0, "seq_buf: putmem writes the bytes");
	}

	seq_buf_init(&s, buf, sizeof(buf));
	{
		static const unsigned char mem[3] = { 0x01, 0x02, 0x03 };

		check(seq_buf_putmem_hex(&s, mem, sizeof(mem)) == 0, "seq_buf: putmem_hex succeeds");
		/* x86_64: little-endian, so bytes print highest-address-first --
		 * see seq_buf_rs.rs's own header comment on this. */
		check(strncmp(buf, "030201 ", 7) == 0,
		      "seq_buf: putmem_hex reverses byte order (this arch is little-endian)");
	}

	/* Real printk() call -- reachability only; dmesg content isn't
	 * asserted (correctness is the differential harness's job). */
	seq_buf_init(&s, buf, sizeof(buf));
	seq_buf_puts(&s, "libtest seq_buf_do_printk reachability line\n");
	seq_buf_do_printk(&s, KERN_INFO);
	check(true, "seq_buf: do_printk ran without fault");

	/* A real (if minimally constructed) struct seq_file. */
	{
		struct seq_file *m = kzalloc(sizeof(*m), GFP_KERNEL);
		char *mbuf = kmalloc(64, GFP_KERNEL);

		check(m && mbuf, "seq_buf: seq_file alloc succeeds");
		if (m && mbuf) {
			m->buf = mbuf;
			m->size = 64;
			seq_buf_init(&s, buf, sizeof(buf));
			seq_buf_puts(&s, "print_seq");
			check(seq_buf_print_seq(m, &s) == 0, "seq_buf: print_seq succeeds");
			check(m->count == 9 && memcmp(m->buf, "print_seq", 9) == 0,
			      "seq_buf: print_seq copies into the seq_file");
		}
		kfree(mbuf);
		kfree(m);
	}

	/* A real struct path -- this process's own fs root. */
	{
		struct path root;

		get_fs_root(current->fs, &root);
		seq_buf_init(&s, buf, sizeof(buf));
		check(seq_buf_path(&s, &root, "") >= 1, "seq_buf: path writes at least \"/\"");
		path_put(&root);
	}

	/* A real copy_to_user() call. Reachability only, deliberately on the
	 * failure path: this runs too early in boot for a real userspace
	 * mapping to copy INTO successfully (no process has execve()'d yet),
	 * so the address below hits copy_to_user()'s real access_ok()/
	 * page-fault machinery and fails, same as it would in the real
	 * kernel with no page mapped there -- correctness of the bounds and
	 * clamping logic is the differential harness's job. */
	seq_buf_init(&s, buf, sizeof(buf));
	seq_buf_puts(&s, "to_user reachability");
	check(seq_buf_to_user(&s, (void __user *)0x1000, 0, 4) == -EFAULT,
	      "seq_buf: to_user hits the real copy_to_user() path");

#if IS_ENABLED(CONFIG_BINARY_PRINTF)
	{
		u32 bin[8];
		int bin_len = make_bin_u32(bin, sizeof(bin), "%d-%s", 42, "x");

		check(bin_len > 0, "seq_buf: vbin_printf produces binary args");
		seq_buf_init(&s, buf, sizeof(buf));
		check(seq_buf_bprintf(&s, "%d-%s", bin) == 0, "seq_buf: bprintf succeeds");
		check(strncmp(buf, "42-x", 4) == 0, "seq_buf: bprintf reproduces the formatted text");
	}
#endif

	/* Real hex_dump_to_buffer() + the retained C seq_buf_printf(). */
	seq_buf_init(&s, buf, sizeof(buf));
	{
		static const unsigned char mem[4] = { 0xaa, 0xbb, 0xcc, 0xdd };

		check(seq_buf_hex_dump(&s, "", DUMP_PREFIX_NONE, 16, 1, mem, sizeof(mem), false) == 0,
		      "seq_buf: hex_dump succeeds");
		check(strstr(buf, "aa bb cc dd") != NULL, "seq_buf: hex_dump formats the bytes");
	}
}

/*
 * lib/iomap.c -> lib/iomap.c (retained: the ~15 real hardware-access
 * primitives this file forwards to, plus pci_iounmap() -- see that
 * file's own header comment) + lib/iomap_rs.rs (the IO_COND dispatch,
 * byte-swap/64-bit arithmetic, repeat-loop bookkeeping). Sabotage-
 * confirmed reachability, all 26 Rust entry points sabotaged at once
 * then peeled off one at a time as each one's panic showed up in dmesg
 * (a combined sweep only proves "at least one of these", since boot
 * halts at the first hit -- unlike lib/seq_buf.c's all-class-A result,
 * here each panic had to be removed and the kernel rebuilt to find the
 * next one): ioport_map(), ioread8(), iowrite8(), ioread32(),
 * ioread32_rep(), iowrite32_rep(), ioread16_rep() and iowrite32() are
 * class B on config-full -- real PCI/platform device probing during
 * this boot genuinely calls them. The other 18 are class A on both
 * configs (config-fast's clean boot with the same 18 still sabotaged
 * confirmed it there too, though the 8 class-B ones were not
 * independently re-sabotaged on config-fast -- bounded effort, and
 * config-full's confirmation already demonstrates the dispatch
 * mechanism itself is sound and reached).
 *
 * This proof caller uses a real kzalloc'd buffer as the "MMIO" cookie --
 * a plain mov instruction against ordinary RAM behaves identically to
 * one against a real ioremap()'d device for everything this file's own
 * logic does (it never touches the *contents* meaningfully, only
 * dispatches and byte-swaps). The 64-bit lo_hi vs hi_lo PIO ordering
 * variants are NOT distinguished by this test -- on the MMIO path all
 * four call the same readq()/writeq() thunk regardless of variant, so
 * this proves each is linked and reached, not that its ordering is
 * correct on the PIO path; that half is the differential harness's job,
 * deliberately, rather than writing to a real, possibly-live legacy I/O
 * port (0x80's page-register neighbors) from a boot-time self-test.
 */
static void __init test_iomap(void)
{
	void *mmio = kzalloc(64, GFP_KERNEL);
	unsigned char rep_dst[8], rep_src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	u64 v64;

	check(mmio != NULL, "iomap: mmio buffer alloc succeeds");
	if (!mmio)
		return;

	iowrite16(0x1234, mmio);
	check(ioread16(mmio) == 0x1234, "iomap: ioread16/iowrite16 round-trip");
	check(ioread16be(mmio) == 0x3412, "iomap: ioread16be byte-swaps");

	iowrite32(0xdeadbeef, mmio);
	check(ioread32be(mmio) == 0xefbeadde, "iomap: ioread32be byte-swaps");

	__iowrite64_lo_hi(0x0123456789abcdefULL, mmio);
	v64 = __ioread64_lo_hi(mmio);
	check(v64 == 0x0123456789abcdefULL, "iomap: __ioread64_lo_hi/__iowrite64_lo_hi round-trip");

	__iowrite64_hi_lo(0xfedcba9876543210ULL, mmio);
	v64 = __ioread64_hi_lo(mmio);
	check(v64 == 0xfedcba9876543210ULL, "iomap: __ioread64_hi_lo/__iowrite64_hi_lo round-trip");

	/* be write swaps to memory, be read swaps back out -- the round
	 * trip through the SAME "be" function returns the value unchanged,
	 * same as mmio_write64be()/mmio_read64be() in the pristine C. */
	__iowrite64be_lo_hi(0x1122334455667788ULL, mmio);
	v64 = __ioread64be_lo_hi(mmio);
	check(v64 == 0x1122334455667788ULL, "iomap: __ioread64be_lo_hi/__iowrite64be_lo_hi round-trip");

	__iowrite64be_hi_lo(0x1122334455667788ULL, mmio);
	v64 = __ioread64be_hi_lo(mmio);
	check(v64 == 0x1122334455667788ULL, "iomap: __ioread64be_hi_lo/__iowrite64be_hi_lo round-trip");

	/*
	 * "Note the __raw accesses" (the pristine C's own comment): these
	 * are string-I/O primitives for a FIXED device register, like a
	 * FIFO port -- every element goes to/from the SAME address, not a
	 * growing range of them. So iowrite8_rep() leaves only the LAST
	 * byte written at *mmio, not a copy of rep_src; and ioread8_rep()
	 * into a real, unchanging source reads that same repeated byte
	 * `count` times, not a run of memory. (Caught here first as an
	 * "*** ERROR ***" from a test that assumed a growing-buffer copy --
	 * the port's actual behavior matches the pristine C's
	 * mmio_outsb()/mmio_insb(), confirmed by re-reading them.)
	 */
	memset(mmio, 0, 64);
	iowrite8_rep(mmio, rep_src, sizeof(rep_src));
	check(*(unsigned char *)mmio == rep_src[sizeof(rep_src) - 1],
	      "iomap: iowrite8_rep leaves the last byte at the fixed register");
	memset(rep_dst, 0, sizeof(rep_dst));
	ioread8_rep(mmio, rep_dst, sizeof(rep_dst));
	check(rep_dst[0] == rep_src[sizeof(rep_src) - 1] &&
	      memcmp(rep_dst, rep_dst + 1, sizeof(rep_dst) - 1) == 0,
	      "iomap: ioread8_rep reads the same fixed register repeatedly");

	memset(mmio, 0, 64);
	iowrite16_rep(mmio, rep_src, sizeof(rep_src) / 2);
	check(ioread16(mmio) == ((u16 *)rep_src)[sizeof(rep_src) / 2 - 1],
	      "iomap: iowrite16_rep leaves the last word at the fixed register");

	/* No-op by design (pristine C's own comment: "Nothing to do") --
	 * reachability only. */
	ioport_unmap(mmio);
	check(true, "iomap: ioport_unmap ran without fault");

	kfree(mmio);
}

/*
 * lib/bug.c -> lib/bug.c (retained: report_bug()'s warn_rcu_enter()/
 * warn_rcu_exit() bracket, the CONFIG_MODULES-entangled struct module
 * list walk, generic_bug_clear_once()'s own RCU-guarded loop) +
 * lib/bug_rs.rs (report_bug_body() -- bug_addr()/bug_get_file_line()'s
 * relative-pointer arithmetic, find_bug()'s built-in-table search, the
 * warning/once/done flag bits, clear_once_table()). See lib/bug_rs.rs's
 * own module doc for why this file got more scrutiny than any other port
 * this session: report_bug() is called directly from the trap handler
 * (arch/x86/kernel/traps.c, arch/x86/mm/extable.c) for every ud2
 * bug/warning trap in the kernel, so this is the one port where "does it
 * compile and boot quietly" is not enough evidence -- a WARN has to actually
 * fire, through the ported code, and boot has to continue past it.
 *
 * Not previously reachable during this minimal boot at all: dmesg shows
 * no "WARNING:"/"cut here" line anywhere before this test runs (checked
 * directly), so report_bug()/find_bug() are class A here -- nothing in
 * this boot's own path happens to hit a WARN_ON(). Confirmed live below,
 * not just presumed: this IS the proof caller, not a supplement to one.
 */
/* noinline: a plain 2-iteration loop calling WARN_ON_ONCE(1) directly
 * gets fully unrolled at -O2 into two independent `ud2` instructions
 * (confirmed in build-full/lib/libtest.o's disassembly) -- two distinct
 * bug_entry structs, not the same one hit twice. Routing through a
 * real, non-inlined function call gives the compiler no way to
 * duplicate the `ud2` -- one call site, hit twice from two call sites
 * below, is what actually exercises BUGFLAG_DONE suppression. */
static noinline void __init warn_once_helper(void)
{
	WARN_ON_ONCE(1);
}

static void __init test_bug(void)
{
	/* A real WARN_ON(), through the real ud2 trap, through
	 * report_bug()'s Rust body, through the real __warn(). If any of
	 * bug_addr()'s relative-pointer arithmetic, find_bug()'s table
	 * search, or the flag-bit dispatch were wrong, this either would
	 * not print (find_bug returned NULL / wrong bug_trap_type) or would
	 * not return here at all (misclassified as BUG_TRAP_TYPE_BUG, which
	 * arch/x86/kernel/traps.c die()s on instead of continuing).
	 */
	WARN_ON(1);

	/* If we get here, report_bug_body() returned BUG_TRAP_TYPE_WARN and
	 * traps.c resumed execution exactly where it should. */
	check(true, "bug: WARN_ON(1) returned control to its caller");

	/* WARN_ON_ONCE()'s BUGFLAG_DONE suppression: one call site, hit
	 * twice, must print only once. A plain 2-iteration loop calling
	 * WARN_ON_ONCE(1) directly does NOT test this -- confirmed in
	 * build-full/lib/libtest.o's disassembly that -O2 fully unrolls a
	 * trivial 2-iteration loop into two separate `ud2` instructions
	 * (two independent bug_entry structs, both attributed to the same
	 * source line) -- so warn_once_helper() is routed through a real,
	 * non-inlined function instead, giving the compiler exactly one
	 * `ud2` to duplicate or not. Can't read dmesg from in-kernel to
	 * assert "printed once" directly, but the boot log for this exact
	 * run already shows it: one "WARNING: ... at lib/libtest.c" line at
	 * warn_once_helper()'s WARN_ON_ONCE, not two. */
	warn_once_helper();
	warn_once_helper();
	check(true, "bug: WARN_ON_ONCE(1) via warn_once_helper() x2 both returned control to their caller");
}

#if IS_ENABLED(CONFIG_ASN1)
/*
 * lib/asn1_decoder.c -> asn1_decoder_rs.rs. CONFIG_ASN1 is config-full
 * only. asn1_ber_decoder() is EXPORT_SYMBOL_GPL and has real callers
 * (X.509/PKCS7 cert parsing, RSA key parsing) but none of them run in
 * this boot: dmesg shows only "Asymmetric key parser 'x509' registered"
 * -- the parser TYPE is registered, nothing ever calls it, since
 * CONFIG_SYSTEM_TRUSTED_KEYS is empty and no module signature or
 * loaded certificate exists to parse. Confirmed empirically
 * (sabotage-and-reboot: made every successful parse report failure
 * instead -- clean boot, unchanged self-test count, no dmesg fault).
 * Genuinely class A.
 *
 * The bytecode here is copied verbatim from
 * build-full/crypto/rsapubkey.asn1.c (the real, compiled
 * RsaPubKey ::= SEQUENCE { n INTEGER, e INTEGER } grammar) -- not
 * invented -- with test-local action stubs standing in for the real
 * rsa_get_n()/rsa_get_e() (which pull in struct rsa_key and have
 * nothing to do with the decoder itself).
 */
struct test_asn1_rsakey {
	unsigned char n_seen, e_seen;
	unsigned long n, e;
};

static int test_asn1_get_n(void *context, size_t hdrlen, unsigned char tag,
			    const void *value, size_t vlen)
{
	struct test_asn1_rsakey *key = context;
	const unsigned char *v = value;
	unsigned long n = 0;

	key->n_seen = 1;
	for (size_t i = 0; i < vlen; i++)
		n = (n << 8) | v[i];
	key->n = n;
	return 0;
}

static int test_asn1_get_e(void *context, size_t hdrlen, unsigned char tag,
			    const void *value, size_t vlen)
{
	struct test_asn1_rsakey *key = context;
	const unsigned char *v = value;
	unsigned long e = 0;

	key->e_seen = 1;
	for (size_t i = 0; i < vlen; i++)
		e = (e << 8) | v[i];
	key->e = e;
	return 0;
}

static const asn1_action_t test_asn1_rsapubkey_actions[2] = {
	test_asn1_get_n,
	test_asn1_get_e,
};

/* Verbatim from build-full/crypto/rsapubkey.asn1.c. */
static const unsigned char test_asn1_rsapubkey_machine[] = {
	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SEQ),
	ASN1_OP_MATCH_ACT,
	_tag(UNIV, PRIM, INT),
	_action(0),
	ASN1_OP_MATCH_ACT,
	_tag(UNIV, PRIM, INT),
	_action(1),
	ASN1_OP_END_SEQ,
	ASN1_OP_COMPLETE,
};

static const struct asn1_decoder test_asn1_rsapubkey_decoder = {
	.machine = test_asn1_rsapubkey_machine,
	.machlen = sizeof(test_asn1_rsapubkey_machine),
	.actions = test_asn1_rsapubkey_actions,
};

static void __init test_asn1_decoder(void)
{
	struct test_asn1_rsakey key;
	int ret;

	/* SEQUENCE { INTEGER 0x010001 (65537), INTEGER 3 } */
	static const unsigned char valid[] = {
		0x30, 0x08,
		0x02, 0x03, 0x01, 0x00, 0x01,
		0x02, 0x01, 0x03,
	};
	memset(&key, 0, sizeof(key));
	ret = asn1_ber_decoder(&test_asn1_rsapubkey_decoder, &key, valid, sizeof(valid));
	check(ret == 0, "asn1_ber_decoder parses a valid RsaPubKey");
	check(key.n_seen && key.n == 65537, "asn1_ber_decoder extracts n = 65537");
	check(key.e_seen && key.e == 3, "asn1_ber_decoder extracts e = 3");

	/* Same, but truncated mid-integer -- must fail, not read past the end. */
	memset(&key, 0, sizeof(key));
	ret = asn1_ber_decoder(&test_asn1_rsapubkey_decoder, &key, valid, sizeof(valid) - 3);
	check(ret == -EBADMSG, "asn1_ber_decoder rejects a truncated RsaPubKey");

	/* Wrong outer tag (SET 0x31 instead of SEQUENCE 0x30). */
	static const unsigned char wrong_tag[] = {
		0x31, 0x08,
		0x02, 0x03, 0x01, 0x00, 0x01,
		0x02, 0x01, 0x03,
	};
	memset(&key, 0, sizeof(key));
	ret = asn1_ber_decoder(&test_asn1_rsapubkey_decoder, &key, wrong_tag, sizeof(wrong_tag));
	check(ret == -EBADMSG, "asn1_ber_decoder rejects a mismatched outer tag");
	check(!key.n_seen && !key.e_seen, "asn1_ber_decoder calls no actions on tag mismatch");
}
#else
static void __init test_asn1_decoder(void) { }
#endif

#if IS_ENABLED(CONFIG_INTERVAL_TREE)
/*
 * lib/interval_tree.c -> interval_tree_rs.rs. CONFIG_INTERVAL_TREE is
 * config-full only. interval_tree_insert/_remove/_iter_first/_iter_next
 * DO have real callers in this config (mm/interval_tree.c's
 * vma_interval_tree_* wrappers, used by every process's VMA tracking),
 * confirmed call-graph-reached -- but sabotage-and-reboot (making
 * interval_tree_insert a no-op, rebuilding, rebooting) produced no
 * observable failure in this minimal busybox boot: nothing here creates
 * enough VMA/rmap pressure to notice an empty interval tree. Same shape
 * as dql_init's finding above. A proof caller here regardless, per
 * GOALS.md's bar. interval_tree_span_iter_{first,next,advance} are not
 * covered -- CONFIG_INTERVAL_TREE_SPAN_ITER is unset in both of this
 * project's configs (only CONFIG_IOMMUFD selects it in 6.18.49), so
 * those three are not compiled here at all; see
 * interval_tree_rs.rs's own module doc.
 *
 * Four intervals inserted -- A=[10,20], B=[30,40], C=[15,25], D=[50,60]
 * -- and three queries hand-checked against them before any code was
 * read back: [18,32] should overlap A (10<=32 && 18<=20), C (15<=32 &&
 * 18<=25) and B (30<=32 && 18<=40), not D; [45,55] should overlap only
 * D; [0,5] should overlap nothing. Removing C and re-running the first
 * query should then drop it from the result.
 */
static void __init test_interval_tree(void)
{
	struct interval_tree_node a, b, c, d;
	struct interval_tree_node *node;
	struct rb_root_cached root = RB_ROOT_CACHED;
	unsigned int seen, count;

	a.start = 10; a.last = 20;
	b.start = 30; b.last = 40;
	c.start = 15; c.last = 25;
	d.start = 50; d.last = 60;
	interval_tree_insert(&a, &root);
	interval_tree_insert(&b, &root);
	interval_tree_insert(&c, &root);
	interval_tree_insert(&d, &root);

	seen = 0; count = 0;
	for (node = interval_tree_iter_first(&root, 18, 32); node;
	     node = interval_tree_iter_next(node, 18, 32)) {
		if (node == &a) seen |= 1;
		else if (node == &b) seen |= 2;
		else if (node == &c) seen |= 4;
		else if (node == &d) seen |= 8;
		count++;
	}
	check(count == 3 && seen == (1 | 2 | 4),
	      "interval_tree [18,32] overlaps exactly {A, B, C}");

	count = 0;
	for (node = interval_tree_iter_first(&root, 45, 55); node;
	     node = interval_tree_iter_next(node, 45, 55)) {
		check(node == &d, "interval_tree [45,55] overlap is D");
		count++;
	}
	check(count == 1, "interval_tree [45,55] overlaps exactly one node");

	check(interval_tree_iter_first(&root, 0, 5) == NULL,
	      "interval_tree [0,5] overlaps nothing");

	interval_tree_remove(&c, &root);
	seen = 0; count = 0;
	for (node = interval_tree_iter_first(&root, 18, 32); node;
	     node = interval_tree_iter_next(node, 18, 32)) {
		if (node == &a) seen |= 1;
		else if (node == &b) seen |= 2;
		count++;
	}
	check(count == 2 && seen == (1 | 2),
	      "interval_tree_remove(C): [18,32] now overlaps exactly {A, B}");
}
#else
static void __init test_interval_tree(void) { }
#endif

/*
 * lib/bitrev.c -> bitrev_rs.rs. The module is one exported ARRAY,
 * byte_rev_table; every function that uses it (__bitrev8, __bitrev16,
 * __bitrev32, __bitrev8x4) is a static inline in include/linux/bitrev.h.
 *
 * So this tests the table THROUGH those inlines, against a reversal computed
 * here by shifting -- never by reading the table, which would be the table
 * agreeing with itself. All 256 bytes, so it is exhaustive at that width;
 * the wider entry points are exhaustive over what they can reach, since each
 * is defined as two of the next size down.
 */
static void __init test_bitrev(void)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; i < 256 && ok; i++) {
		u8 want = 0, v = (u8)i;
		unsigned int b;

		for (b = 0; b < 8; b++)
			want = (u8)((want << 1) | ((v >> b) & 1));
		if (__bitrev8((u8)i) != want)
			ok = false;
	}
	check(ok, "__bitrev8 reverses all 256 bytes");

	/* __bitrev16 is two __bitrev8 with the halves swapped, and getting
	 * that swap backwards is the mistranslation this catches. 0x1234
	 * reverses to 0x2c48, which is not a palindrome in either half. */
	check(__bitrev16(0x1234) == 0x2c48, "__bitrev16 swaps the halves");
	check(__bitrev16(0x0000) == 0x0000 && __bitrev16(0xffff) == 0xffff,
	      "__bitrev16 at both ends");

	check(__bitrev32(0x12345678u) == 0x1e6a2c48u, "__bitrev32 reverses 32 bits");
	check(__bitrev32(0x00000001u) == 0x80000000u, "__bitrev32 moves bit 0 to bit 31");

	/* __bitrev8x4 reverses each byte in place rather than the word. */
	check(__bitrev8x4(0x12345678u) == 0x482c6a1eu,
	      "__bitrev8x4 reverses each byte without moving it");

	/* Every value is its own double-reversal. */
	ok = true;
	for (i = 0; i < 256 && ok; i++)
		if (__bitrev8(__bitrev8((u8)i)) != (u8)i)
			ok = false;
	check(ok, "__bitrev8 is its own inverse");
}

/*
 * lib/uuid.c -> uuid_rs.rs.
 *
 * THE VECTOR THAT MATTERS IS THE PERMUTATION. A UUID and a GUID are the same
 * sixteen bytes in two different orders, the C expresses the difference as
 * two index tables, and the whole failure mode of this module is applying the
 * wrong one -- which a round trip cannot see, because parse-then-print with a
 * consistently wrong table agrees with itself.
 *
 * So the expected bytes below were worked out from RFC 4122 and Microsoft's
 * GUID layout, not from running either implementation: the first three fields
 * are byte-swapped in a GUID and identical in a UUID, and 00112233-4455-6677
 * makes each swap visible.
 */
/*
 * lib/ctype.c -> ctype_rs.rs. One exported table, and every isalpha(),
 * isdigit(), isspace() and toupper() in the kernel indexes it.
 *
 * The ASCII half is checked against rules restated HERE, in C, from the
 * definitions of the classes -- not against the table, which would be the
 * table agreeing with itself. The Latin-1 half cannot be checked that way,
 * because its content IS a set of conventions rather than a rule, so it is
 * checked at the run boundaries and at the four values that are exceptions
 * to their runs: 0x80..0x9f classify as nothing, 0xa0 is a hard space, and
 * 0xd7 and 0xf7 are punctuation sitting inside the letter runs.
 */
/*
 * lib/hexdump.c -> hexdump_rs.rs.
 *
 * hex_dump_to_buffer() is covered far better by CONFIG_TEST_HEXDUMP, which is
 * upstream's own module and is enabled on both configs -- see rig/init. What
 * that test does NOT touch is hex_to_bin, hex2bin, bin2hex or the two tables,
 * so those are here.
 *
 * hex_to_bin is exhaustive over all 256 inputs, because it is branchless
 * arithmetic rather than a lookup: there is no "representative" input for a
 * shift-and-mask trick, and its comment in the C says it is on the path that
 * loads cryptographic keys.
 */
/*
 * lib/cmdline.c -> cmdline_rs.rs.
 *
 * get_option() and get_options() are covered by CONFIG_CMDLINE_KUNIT_TEST,
 * which is upstream's own and which FOUND TWO REAL DEFECTS in this port -- a
 * dropped `++cur` side effect and a `(*str)++` that did not write back. What
 * it does not touch is memparse(), next_arg() or parse_option_str(), so those
 * are here.
 *
 * next_arg() TERMINATES ITS INPUT IN PLACE, so every case needs a fresh
 * writable copy; a `const char *` would be a fault, not a test failure.
 */
/*
 * lib/llist.c -> llist_rs.rs.
 *
 * WHAT THESE VECTORS CANNOT SEE is the module's whole substance: the memory
 * ordering. A relaxed load where the C has an acquire gives identical answers
 * on x86-64, which orders load-load in hardware. Single-threaded vectors at
 * an initcall cannot reach that, and neither can a differential. What they DO
 * check is the shape of the list after each operation, which is where a
 * translation error lands.
 */
/*
 * lib/errseq.c -> errseq_rs.rs.
 *
 * The subtle behaviour is the SEEN flag driving the counter: errseq_set()
 * increments only when somebody has sampled since the last error, and a
 * sequence that dropped that condition would still report every error to a
 * single subscriber. So the vectors below use TWO subscribers with different
 * sample points, which is the arrangement the flag exists for.
 *
 * The error-refusal path is deliberately NOT exercised. It raises a kernel
 * warning, which taints the kernel and which rig/boot.sh counts as a fault in
 * the log -- so a test that triggered it would turn every boot red. That the
 * path exists at all in the port is checked instead by rig/guard-check.sh,
 * which reads the pristine C and demands an account of every guard.
 */
static void __init test_errseq(void)
{
	errseq_t eseq = 0;
	errseq_t a, b, old;

	/* An epoch value of 0 means "no error ever". */
	check(errseq_sample(&eseq) == 0, "errseq_sample of a fresh value is 0");
	check(errseq_check(&eseq, 0) == 0, "errseq_check finds nothing yet");

	a = errseq_sample(&eseq);
	old = errseq_set(&eseq, -EIO);
	check(old == 0, "errseq_set returns the previous value");
	check(errseq_check(&eseq, a) == -EIO, "errseq_check reports the error");
	check(errseq_check_and_advance(&eseq, &a) == -EIO,
	      "errseq_check_and_advance reports it once");
	check(errseq_check_and_advance(&eseq, &a) == 0,
	      "errseq_check_and_advance does not report it twice");

	/* A NEW subscriber sampling now must not see the old error, because
	 * the advance above set SEEN. */
	b = errseq_sample(&eseq);
	check(errseq_check_and_advance(&eseq, &b) == 0,
	      "a subscriber that arrives after the error is not told about it");

	/* But a second, different error must reach both. */
	errseq_set(&eseq, -ENOSPC);
	check(errseq_check_and_advance(&eseq, &a) == -ENOSPC,
	      "the first subscriber sees the second error");
	check(errseq_check_and_advance(&eseq, &b) == -ENOSPC,
	      "the second subscriber sees it too");

	/* A subscriber that samples while an error is UNSEEN is told about
	 * it -- errseq_sample returns 0 in that case for exactly this. */
	eseq = 0;
	errseq_set(&eseq, -EIO);
	a = errseq_sample(&eseq);
	check(a == 0, "sampling an unseen error yields the epoch");
	check(errseq_check_and_advance(&eseq, &a) == -EIO,
	      "a subscriber arriving before anyone looked IS told");

	/* Setting the same error twice with nobody looking must not move the
	 * counter -- that is the condition a mistranslation drops. */
	eseq = 0;
	errseq_set(&eseq, -EIO);
	old = eseq;
	errseq_set(&eseq, -EIO);
	check(eseq == old, "errseq_set does not bump the counter while unseen");

	/* ... and must move it once somebody has. */
	a = errseq_sample(&eseq);
	(void)errseq_check_and_advance(&eseq, &a);
	old = eseq;
	errseq_set(&eseq, -EIO);
	check(eseq != old, "errseq_set does bump the counter once seen");
}

static void __init test_llist(void)
{
	static struct llist_node n[4] __initdata;
	struct llist_head head;
	struct llist_node *p;
	unsigned int i;
	bool ok;

	init_llist_head(&head);
	check(llist_empty(&head), "llist starts empty");
	check(llist_del_first(&head) == NULL, "llist_del_first on empty is NULL");

	/* Newest first: add 0,1,2,3 and expect 3,2,1,0 back. */
	for (i = 0; i < ARRAY_SIZE(n); i++)
		llist_add(&n[i], &head);
	check(!llist_empty(&head), "llist is not empty after four adds");

	ok = true;
	for (i = ARRAY_SIZE(n); i-- > 0; ) {
		p = llist_del_first(&head);
		if (p != &n[i])
			ok = false;
	}
	check(ok, "llist_del_first returns nodes newest-first");
	check(llist_del_first(&head) == NULL, "llist is empty again");

	/* del_first_this only fires on the head. */
	init_llist_head(&head);
	llist_add(&n[0], &head);
	llist_add(&n[1], &head);
	check(!llist_del_first_this(&head, &n[0]),
	      "llist_del_first_this refuses a node that is not first");
	check(llist_del_first_this(&head, &n[1]),
	      "llist_del_first_this removes the head");
	check(llist_del_first_this(&head, &n[0]),
	      "llist_del_first_this removes what is now the head");
	check(!llist_del_first_this(&head, &n[0]),
	      "llist_del_first_this on empty is false");

	/* reverse_order on a detached chain. */
	init_llist_head(&head);
	for (i = 0; i < ARRAY_SIZE(n); i++)
		llist_add(&n[i], &head);
	p = llist_reverse_order(llist_del_all(&head));
	ok = true;
	for (i = 0; i < ARRAY_SIZE(n); i++) {
		if (p != &n[i])
			ok = false;
		p = p ? p->next : NULL;
	}
	check(ok && p == NULL, "llist_reverse_order reverses a whole chain");
	check(llist_reverse_order(NULL) == NULL, "llist_reverse_order of NULL");
}

/*
 * lib/debug_locks.c -> debug_locks_rs.rs.
 *
 * debug_locks_off() has a GLOBAL SIDE EFFECT -- it disables lock debugging
 * for the rest of the boot -- so this saves both variables, silences the
 * console path, exercises it, and puts them back. The silent path is used
 * deliberately: the loud one calls console_verbose(), which would raise the
 * log level permanently.
 */
static void __init test_debug_locks(void)
{
	int saved = debug_locks, saved_silent = debug_locks_silent;

	check(saved == 1, "debug_locks starts enabled");

	debug_locks_silent = 1;
	check(debug_locks_off() == 0,
	      "debug_locks_off returns 0 when silenced");
	check(debug_locks == 0, "debug_locks_off turned the flag off");
	check(debug_locks_off() == 0,
	      "debug_locks_off is idempotent once off");

	debug_locks = saved;
	debug_locks_silent = saved_silent;
	check(debug_locks == 1 && debug_locks_silent == 0,
	      "debug_locks restored for the rest of the boot");
}

/*
 * lib/iomap_copy.c -> iomap_copy_rs.rs. Ordinary memory stands in for MMIO:
 * the __iomem annotation is a sparse construct with no run-time meaning, and
 * these functions do not care what is behind the pointer.
 *
 * Only __ioread32_copy and __iowrite64_copy exist on x86-64 --
 * __iowrite32_copy comes from arch/x86/lib/iomap_copy_64.S.
 */
static void __init test_iomap_copy(void)
{
	static u32 src32[8] __initdata;
	static u32 dst32[10] __initdata;
	static u64 src64[4] __initdata;
	static u64 dst64[6] __initdata;
	unsigned int i;
	bool ok = true;

	for (i = 0; i < ARRAY_SIZE(src32); i++)
		src32[i] = 0xdeadbe00u + i;
	memset(dst32, 0xa5, sizeof(dst32));
	__ioread32_copy(dst32, (void __iomem *)src32, ARRAY_SIZE(src32));
	for (i = 0; i < ARRAY_SIZE(src32); i++)
		if (dst32[i] != src32[i])
			ok = false;
	check(ok, "__ioread32_copy copies every word");
	check(dst32[ARRAY_SIZE(src32)] == 0xa5a5a5a5u,
	      "__ioread32_copy writes no further than count");
	__ioread32_copy(dst32, (void __iomem *)src32, 0);
	check(true, "__ioread32_copy of zero words does not fault");

	ok = true;
	for (i = 0; i < ARRAY_SIZE(src64); i++)
		src64[i] = 0x0123456789ab0000ull + i;
	memset(dst64, 0x5a, sizeof(dst64));
	__iowrite64_copy((void __iomem *)dst64, src64, ARRAY_SIZE(src64));
	for (i = 0; i < ARRAY_SIZE(src64); i++)
		if (dst64[i] != src64[i])
			ok = false;
	check(ok, "__iowrite64_copy copies every quadword");
	check(dst64[ARRAY_SIZE(src64)] == 0x5a5a5a5a5a5a5a5aull,
	      "__iowrite64_copy writes no further than count");
	__iowrite64_copy((void __iomem *)dst64, src64, 0);
	check(true, "__iowrite64_copy of zero words does not fault");
}

static void __init test_cmdline(void)
{
	char buf[64];
	char *param, *val, *rest, *end;
	bool ok = true;
	unsigned int i;

	/* memparse: each suffix shifts by ten more bits than the last, and
	 * every suffix consumes exactly one character. */
	check(memparse("42", &end) == 42 && *end == '\0', "memparse of a bare number");
	check(memparse("1K", &end) == 1024 && *end == '\0', "memparse K");
	check(memparse("1k", &end) == 1024 && *end == '\0', "memparse k, lower case");
	check(memparse("1M", &end) == 1024ULL * 1024, "memparse M");
	check(memparse("1G", &end) == 1024ULL * 1024 * 1024, "memparse G");
	check(memparse("1T", &end) == 1ULL << 40, "memparse T");
	check(memparse("1P", &end) == 1ULL << 50, "memparse P");
	check(memparse("1E", &end) == 1ULL << 60, "memparse E");
	/* The suffix is consumed: a caller that keeps parsing must not see it. */
	check(memparse("8M,rest", &end) == 8ULL * 1024 * 1024 && !strcmp(end, ",rest"),
	      "memparse leaves retptr past the suffix");
	check(memparse("0x10", &end) == 16, "memparse takes the 0x base");
	check(memparse("9z", &end) == 9 && *end == 'z',
	      "memparse leaves an unknown suffix alone");

	/* parse_option_str: whole comma-separated entries only. */
	check(parse_option_str("a,bb,ccc", "bb"), "parse_option_str finds a middle entry");
	check(parse_option_str("a,bb,ccc", "a"), "parse_option_str finds the first");
	check(parse_option_str("a,bb,ccc", "ccc"), "parse_option_str finds the last");
	check(!parse_option_str("a,bb,ccc", "b"),
	      "parse_option_str does not match a prefix of an entry");
	check(!parse_option_str("abb", "bb"),
	      "parse_option_str does not match mid-entry");
	check(!parse_option_str("", "a"), "parse_option_str on an empty string");

	/* next_arg: param=val, quotes, and the in-place termination. */
	strscpy(buf, "foo=bar baz", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(!strcmp(param, "foo") && !strcmp(val, "bar") && !strcmp(rest, "baz"),
	      "next_arg splits param=val and returns the rest");

	strscpy(buf, "flag rest", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(!strcmp(param, "flag") && val == NULL && !strcmp(rest, "rest"),
	      "next_arg gives a NULL value when there is no =");

	strscpy(buf, "k=\"a b\" next", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(!strcmp(param, "k") && !strcmp(val, "a b") && !strcmp(rest, "next"),
	      "next_arg keeps a quoted value together and strips the quotes");

	/* A QUOTED NAME FOLLOWED BY '=' KEEPS ITS CLOSING QUOTE. I asserted
	 * `q u` here first, from reading the C, and was wrong: the quote is
	 * stripped only when the LAST character before the separator is one,
	 * and here that character is the value's `v`. Settled by
	 * port/test/cmdline/run.sh against the pristine C, not by re-reading. */
	strscpy(buf, "\"q u\"=v tail", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(!strcmp(param, "q u\"") && !strcmp(val, "v") && !strcmp(rest, "tail"),
	      "next_arg keeps the closing quote of a quoted name before =");

	/* Trailing spaces are chewed up, so a caller can loop on the result. */
	strscpy(buf, "a=1    b=2", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(!strcmp(rest, "b=2"), "next_arg skips the run of spaces after an arg");

	/* THE ODD ONE, and it is upstream's: `equals` doubles as the
	 * found-flag, so an argument BEGINNING with '=' is treated as having
	 * no value at all. Reproduced deliberately, not tidied. */
	strscpy(buf, "=v tail", sizeof(buf));
	rest = next_arg(buf, &param, &val);
	check(val == NULL && !strcmp(param, "=v"),
	      "next_arg treats a leading = as part of the name, as the C does");

	/* get_option's contract, at the boundaries the KUnit test also walks --
	 * kept here so a config without KUnit still checks something. */
	{
		char in[] = "1,2";
		char *p = in;
		int v = 0;

		check(get_option(&p, &v) == 2 && v == 1, "get_option: comma follows");
		check(get_option(&p, &v) == 1 && v == 2, "get_option: last value");
		check(get_option(&p, &v) == 0, "get_option: nothing left");
	}
	{
		char in[] = "-,";
		char *p = in;
		int v = 99;

		check(get_option(&p, &v) == 0,
		      "get_option: a hyphen with no digits is no integer");
	}
	{
		int ints[8];
		char in[] = "1-3,7";

		get_options(in, ARRAY_SIZE(ints), ints);
		ok = (ints[0] == 4 && ints[1] == 1 && ints[2] == 2 &&
		      ints[3] == 3 && ints[4] == 7);
		check(ok, "get_options expands a range and keeps going");
	}

	(void)i;
}

static void __init test_hexdump(void)
{
	static const u8 bin[] __initconst = { 0x00, 0x0f, 0x10, 0xa5, 0xff, 0x7b };
	char buf[16];
	u8 out[8];
	unsigned int i;
	bool ok = true;

	for (i = 0; i < 256; i++) {
		int want = -1;

		if (i >= '0' && i <= '9') want = i - '0';
		else if (i >= 'a' && i <= 'f') want = i - 'a' + 10;
		else if (i >= 'A' && i <= 'F') want = i - 'A' + 10;

		if (hex_to_bin(i) != want) { ok = false; break; }
	}
	check(ok, "hex_to_bin over all 256 byte values");

	check(hex_asc[0] == '0' && hex_asc[15] == 'f' && hex_asc[16] == '\0',
	      "hex_asc is the sixteen lower-case digits and a NUL");
	check(hex_asc_upper[10] == 'A' && hex_asc_upper[15] == 'F' &&
	      hex_asc_upper[16] == '\0',
	      "hex_asc_upper is upper case where it differs");

	memset(buf, 0x5a, sizeof(buf));
	check(bin2hex(buf, bin, 4) == buf + 8, "bin2hex returns the write end");
	check(!memcmp(buf, "000f10a5", 8), "bin2hex writes lower-case pairs");
	check(buf[8] == 0x5a, "bin2hex appends no NUL");

	memset(out, 0, sizeof(out));
	check(hex2bin(out, "000f10a5ff7b", 6) == 0, "hex2bin accepts good input");
	check(!memcmp(out, bin, 6), "hex2bin round-trips bin2hex");

	check(hex2bin(out, "00zz", 2) == -EINVAL, "hex2bin rejects a bad digit");
	check(hex2bin(out, "0", 0) == 0, "hex2bin of zero bytes succeeds");

	/* Upper case in, binary out: hex2bin takes either case. */
	memset(out, 0, sizeof(out));
	check(hex2bin(out, "0A5F", 2) == 0 && out[0] == 0x0a && out[1] == 0x5f,
	      "hex2bin accepts upper-case digits");
}

static void __init test_ctype(void)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; i < 128 && ok; i++) {
		bool up  = (i >= 'A' && i <= 'Z');
		bool low = (i >= 'a' && i <= 'z');
		bool dig = (i >= '0' && i <= '9');
		bool hex = dig || (i >= 'A' && i <= 'F') || (i >= 'a' && i <= 'f');
		bool ctl = (i < 32) || i == 127;
		bool spc = (i == ' ') || (i >= 9 && i <= 13);
		bool pun = !up && !low && !dig && !ctl && i != ' ';

		if (!!isupper(i)  != up)  ok = false;
		if (!!islower(i)  != low) ok = false;
		if (!!isdigit(i)  != dig) ok = false;
		if (!!isxdigit(i) != hex) ok = false;
		if (!!iscntrl(i)  != ctl) ok = false;
		if (!!isspace(i)  != spc) ok = false;
		if (!!ispunct(i)  != pun) ok = false;
		if (!!isalpha(i)  != (up || low)) ok = false;
		if (!!isalnum(i)  != (up || low || dig)) ok = false;
	}
	check(ok, "_ctype classifies all 128 ASCII characters");

	/* toupper/tolower are table lookups through the same array. */
	ok = true;
	for (i = 0; i < 128 && ok; i++) {
		if (isupper(i) && tolower(i) != (int)i + 32) ok = false;
		if (islower(i) && toupper(i) != (int)i - 32) ok = false;
		if (!isalpha(i) && (toupper(i) != (int)i || tolower(i) != (int)i))
			ok = false;
	}
	check(ok, "toupper and tolower agree with _ctype's case bits");

	/* Latin-1: the runs. */
	ok = true;
	for (i = 0x80; i <= 0x9f && ok; i++)
		if (isalpha(i) || iscntrl(i) || ispunct(i) || isspace(i))
			ok = false;
	check(ok, "_ctype gives 0x80..0x9f no class at all");

	check(isspace(0xa0) && !isspace(0xa1),
	      "_ctype makes 0xa0 a hard space and 0xa1 not");

	ok = true;
	for (i = 0xa1; i <= 0xbf && ok; i++)
		if (!ispunct(i)) ok = false;
	for (i = 0xc0; i <= 0xde && ok; i++)
		if (i != 0xd7 && !isupper(i)) ok = false;
	for (i = 0xdf; i <= 0xff && ok; i++)
		if (i != 0xf7 && !islower(i)) ok = false;
	check(ok, "_ctype's Latin-1 punctuation, upper and lower runs");

	check(ispunct(0xd7) && !isalpha(0xd7),
	      "_ctype makes 0xd7 punctuation inside the uppercase run");
	check(ispunct(0xf7) && !isalpha(0xf7),
	      "_ctype makes 0xf7 punctuation inside the lowercase run");
	check(islower(0xdf) && islower(0xff),
	      "_ctype makes sharp-s and y-diaeresis lower case");
}

static void __init test_uuid(void)
{
	static const char good[] __initconst =
		"00112233-4455-6677-8899-aabbccddeeff";
	static const u8 want_uuid[16] __initconst = {
		0x00,0x11,0x22,0x33, 0x44,0x55, 0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	static const u8 want_guid[16] __initconst = {
		0x33,0x22,0x11,0x00, 0x55,0x44, 0x77,0x66,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	static const char * const bad[] __initconst = {
		"00112233445566778899aabbccddeeff",     /* no hyphens */
		"00112233-4455-6677-8899-aabbccddeefg", /* 'g' is not hex */
		"00112233x4455-6677-8899-aabbccddeeff", /* hyphen 1 wrong */
		"00112233-4455x6677-8899-aabbccddeeff", /* hyphen 2 wrong */
		"00112233-4455-6677x8899-aabbccddeeff", /* hyphen 3 wrong */
		"00112233-4455-6677-8899xaabbccddeeff", /* hyphen 4 wrong */
		"-0112233-4455-6677-8899-aabbccddeeff", /* hyphen where hex goes */
		"",
	};
	uuid_t u; guid_t g;
	unsigned int i;
	bool ok = true;
	u8 r[16];

	check(uuid_is_valid(good), "uuid_is_valid accepts a well-formed string");
	for (i = 0; i < ARRAY_SIZE(bad); i++)
		if (uuid_is_valid(bad[i]))
			ok = false;
	check(ok, "uuid_is_valid rejects eight malformed strings");

	check(uuid_parse(good, &u) == 0, "uuid_parse accepts a good string");
	check(!memcmp(u.b, want_uuid, 16), "uuid_parse is big-endian throughout");

	check(guid_parse(good, &g) == 0, "guid_parse accepts a good string");
	check(!memcmp(g.b, want_guid, 16),
	      "guid_parse byte-swaps the first three fields");

	/* And they must NOT agree -- if the two tables had been transposed,
	 * or one used for both, every check above could still pass. */
	check(memcmp(u.b, g.b, 16) != 0,
	      "guid_parse and uuid_parse disagree, as they must");

	check(uuid_parse(bad[1], &u) == -EINVAL, "uuid_parse rejects bad hex");
	check(guid_parse(bad[2], &g) == -EINVAL, "guid_parse rejects a bad hyphen");

	/* The exported data symbols. */
	memset(r, 0, sizeof(r));
	check(!memcmp(&uuid_null, r, 16) && !memcmp(&guid_null, r, 16),
	      "uuid_null and guid_null are sixteen zero bytes");
	check(uuid_is_null(&uuid_null) && guid_is_null(&guid_null),
	      "uuid_is_null and guid_is_null read the exported nulls");

	/* Version and variant nibbles. THE VERSION IS AT A DIFFERENT BYTE in
	 * each, for the same reason the tables differ, and swapping them is
	 * the other mistranslation this module invites. */
	ok = true;
	for (i = 0; i < 8 && ok; i++) {
		uuid_gen(&u);
		guid_gen(&g);
		if ((u.b[6] & 0xf0) != 0x40 || (u.b[8] & 0xc0) != 0x80)
			ok = false;
		if ((g.b[7] & 0xf0) != 0x40 || (g.b[8] & 0xc0) != 0x80)
			ok = false;
	}
	check(ok, "uuid_gen stamps byte 6 and guid_gen stamps byte 7");

	ok = true;
	for (i = 0; i < 8 && ok; i++) {
		generate_random_uuid(r);
		if ((r[6] & 0xf0) != 0x40 || (r[8] & 0xc0) != 0x80)
			ok = false;
		generate_random_guid(r);
		if ((r[7] & 0xf0) != 0x40 || (r[8] & 0xc0) != 0x80)
			ok = false;
	}
	check(ok, "generate_random_uuid and _guid stamp their own bytes");
}

#if IS_ENABLED(CONFIG_UCS2_STRING)
static void __init test_ucs2(void)
{
	/* "Boot" then an e-acute (2-byte UTF-8) then a CJK ideograph
	 * (3-byte), so all three encoder branches run. */
	static const ucs2_char_t s[] __initconst = {
		'B', 'o', 'o', 't', 0x00e9, 0x4e2d, 0
	};
	static const u8 want[] __initconst = {
		'B', 'o', 'o', 't', 0xc3, 0xa9, 0xe4, 0xb8, 0xad
	};
	static ucs2_char_t d[8] __initdata;
	static u8 u[16] __initdata;
	unsigned long n;
	ssize_t r;

	check(ucs2_strlen(s) == 6, "ucs2_strlen");
	check(ucs2_strnlen(s, 3) == 3, "ucs2_strnlen stops at maxlength");
	check(ucs2_strnlen(s, 99) == 6, "ucs2_strnlen stops at the NUL");
	check(ucs2_strsize(s, 99) == 12, "ucs2_strsize is in bytes");
	check(ucs2_utf8size(s) == 9, "ucs2_utf8size counts 4 + 2 + 3");

	memset(u, 0xa5, sizeof(u));
	n = ucs2_as_utf8(u, s, sizeof(u));
	check(n == 9 && !memcmp(u, want, 9), "ucs2_as_utf8 encodes 1-, 2- and 3-byte forms");
	check(u[9] == 0, "and terminates when there is room");

	/* A budget that would split the three-byte character must stop
	 * before it, not truncate it. */
	memset(u, 0xa5, sizeof(u));
	n = ucs2_as_utf8(u, s, 8);
	check(n == 6, "ucs2_as_utf8 stops rather than splitting a character");

	/* Exactly enough for everything and no NUL: the C does not
	 * terminate, and callers rely on the returned length. */
	memset(u, 0xa5, sizeof(u));
	n = ucs2_as_utf8(u, s, 9);
	check(n == 9 && u[9] == 0xa5,
	      "ucs2_as_utf8 does not terminate when the buffer is exactly full");

	r = ucs2_strscpy(d, s, ARRAY_SIZE(d));
	check(r == 6 && d[6] == 0, "ucs2_strscpy copies and terminates");
	r = ucs2_strscpy(d, s, 4);
	check(r == -E2BIG && d[3] == 0, "ucs2_strscpy truncates and reports -E2BIG");
	check(ucs2_strscpy(d, s, 0) == -E2BIG, "ucs2_strscpy rejects a zero count");

	check(ucs2_strncmp(s, s, 99) == 0, "ucs2_strncmp of a string with itself");
	check(ucs2_strncmp(s, s, 0) == 0, "ucs2_strncmp of zero length");
	{
		static ucs2_char_t t[ARRAY_SIZE(s)] __initdata;

		memcpy(t, s, sizeof(t));
		t[2] = 'p';
		check(ucs2_strncmp(s, t, 99) < 0, "ucs2_strncmp orders by character");
		check(ucs2_strncmp(t, s, 99) > 0, "and is antisymmetric");
		check(ucs2_strncmp(s, t, 2) == 0, "and respects its length limit");
	}
}
#else
static void __init test_ucs2(void) { }
#endif

#if IS_ENABLED(CONFIG_MPILIB)
static void __init test_mpih(void)
{
	static const unsigned long a[3] __initconst = { ~0UL, 0, 1 };
	static const unsigned long b[3] __initconst = { 1, 0, 0 };
	static unsigned long r[4] __initdata;
	unsigned long cy;

	/* a is 2^128 + 2^64*0 + (2^64 - 1); adding 1 must carry all the way
	 * through the bottom limb and stop. */
	cy = mpihelp_add_n(r, a, b, 3);
	check(cy == 0 && r[0] == 0 && r[1] == 1 && r[2] == 1,
	      "mpihelp_add_n carries between limbs");

	cy = mpihelp_sub_n(r, b, a, 3);
	check(cy == 1, "mpihelp_sub_n borrows out of the top");

	/* THE CARRY THAT PROPAGATES THROUGH AN ALL-ONES LIMB. add_n adds the
	 * incoming carry to one addend first, and THAT addition can itself
	 * carry -- but only when the addend is ~0 and a carry is coming in.
	 * (2^128 - 1) + 1 is the smallest case that does it. Everything above
	 * passes with that carry deleted, which a prove-can-fail sabotage
	 * discovered by quietly succeeding. */
	{
		static const unsigned long ones[2] __initconst = { ~0UL, ~0UL };
		static const unsigned long one[2] __initconst = { 1, 0 };

		cy = mpihelp_add_n(r, one, ones, 2);
		check(cy == 1 && r[0] == 0 && r[1] == 0,
		      "mpihelp_add_n carries out of an all-ones limb");
	}

	/* ~0 * 2 = 2^65 - 2: low limb 0xff..fe, carry out 1. */
	cy = mpihelp_mul_1(r, a, 1, 2);
	check(cy == 1 && r[0] == ~1UL, "mpihelp_mul_1 returns the high half as carry");

	/* A full-width left shift by one, and back. */
	cy = mpihelp_lshift(r, a, 3, 1);
	check(cy == 0 && r[0] == ~1UL && r[1] == 1,
	      "mpihelp_lshift shifts bits across the limb boundary");
	cy = mpihelp_rshift(r, a, 3, 1);
	check(cy == (1UL << 63) && r[0] == (~0UL >> 1),
	      "mpihelp_rshift returns the bits shifted out");

	check(mpihelp_cmp(a, a, 3) == 0, "mpihelp_cmp of equal arrays");
	check(mpihelp_cmp(a, b, 3) == 1 && mpihelp_cmp(b, a, 3) == -1,
	      "mpihelp_cmp orders by the most significant differing limb");
}

/*
 * lib/crypto/mpi/mpi-add.c -> mpi_add_rs.rs. Neither mpi_add() nor
 * mpi_sub()/mpi_addm()/mpi_subm() is reached at boot in either of this
 * project's configs (CONFIG_MODULE_SIG is not set, so the compiled-in
 * X.509 certs this file's mpi_alloc()/mpi_free() ARE reached through are
 * only ever parsed, never verified) -- confirmed by sabotaging mpi_add()
 * to always return an error and reboot: boot stayed clean, certs still
 * "loaded" (parsing them never calls mpi_add), 599 self-tests still
 * passed. So this is class A and these vectors are the whole of
 * criterion 5 for it, same reason md5's were for HMAC-MD5.
 *
 * Values are small enough to verify by hand, same convention as
 * test_mpih() just above -- an external bignum oracle would be a bigger
 * dependency than the arithmetic it is checking.
 */
static MPI __init mk_mpi(int nlimbs, int sign, const unsigned long *limbs)
{
	MPI a = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	int i;

	if (!a)
		return NULL;
	for (i = 0; i < nlimbs; i++)
		a->d[i] = limbs[i];
	a->nlimbs = nlimbs;
	a->sign = sign;
	return a;
}

static void __init test_mpi_add(void)
{
	MPI w = mpi_alloc(4);
	bool ok = true;

	if (!w) {
		check(false, "mpi_add setup: mpi_alloc failed");
		return;
	}

	/* 1 + 1 = 2: the trivial same-sign, single-limb path. */
	{
		static const unsigned long one[1] = { 1 };
		MPI u = mk_mpi(1, 0, one), v = mk_mpi(1, 0, one);

		ok = u && v && !mpi_add(w, u, v);
		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 2,
		      "mpi_add: 1 + 1 = 2");
		mpi_free(u); mpi_free(v);
	}

	/* (~0) + 1 = 2^BITS_PER_LONG: same-sign add that carries a whole
	 * new limb into existence -- the wp[usize] = cy path. */
	{
		static const unsigned long allones[1] = { ~0UL };
		static const unsigned long one[1] = { 1 };
		MPI u = mk_mpi(1, 0, allones), v = mk_mpi(1, 0, one);

		ok = u && v && !mpi_add(w, u, v);
		check(ok && w->nlimbs == 2 && w->sign == 0
		      && w->d[0] == 0 && w->d[1] == 1,
		      "mpi_add: carrying out of the top limb grows nlimbs");
		mpi_free(u); mpi_free(v);
	}

	/* 5 - 3 = 2: mpi_sub()'s different-sign, equal-size path, via
	 * mpihelp_cmp() choosing which operand is larger. */
	{
		static const unsigned long five[1] = { 5 }, three[1] = { 3 };
		MPI u = mk_mpi(1, 0, five), v = mk_mpi(1, 0, three);

		ok = u && v && !mpi_sub(w, u, v);
		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 2,
		      "mpi_sub: 5 - 3 = 2");
		mpi_free(u); mpi_free(v);
	}

	/* 3 - 5 = -2: same path, operands swapped -- the sign of the
	 * result must flip, not just its magnitude. */
	{
		static const unsigned long five[1] = { 5 }, three[1] = { 3 };
		MPI u = mk_mpi(1, 0, three), v = mk_mpi(1, 0, five);

		ok = u && v && !mpi_sub(w, u, v);
		check(ok && w->nlimbs == 1 && w->sign == 1 && w->d[0] == 2,
		      "mpi_sub: 3 - 5 = -2 (magnitude 2, negative)");
		mpi_free(u); mpi_free(v);
	}

	/* 5 - 5 = 0: equal operands, different-sign path, must normalize
	 * away to zero limbs. */
	{
		static const unsigned long five[1] = { 5 };
		MPI u = mk_mpi(1, 0, five), v = mk_mpi(1, 0, five);

		ok = u && v && !mpi_sub(w, u, v);
		check(ok && w->nlimbs == 0, "mpi_sub: 5 - 5 = 0 normalizes to nlimbs=0");
		mpi_free(u); mpi_free(v);
	}

	/* 2^BITS_PER_LONG - 1: a two-limb minuend, one-limb subtrahend --
	 * the different-SIZE branch of mpi_sub() (mpihelp_sub(), not
	 * mpihelp_sub_n()+mpihelp_cmp()). */
	{
		static const unsigned long top[2] = { 0, 1 }; /* 2^BITS_PER_LONG */
		static const unsigned long one[1] = { 1 };
		MPI u = mk_mpi(2, 0, top), v = mk_mpi(1, 0, one);

		ok = u && v && !mpi_sub(w, u, v);
		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == ~0UL,
		      "mpi_sub: different-size operands take the direct-subtract path");
		mpi_free(u); mpi_free(v);
	}

	/* (7 + 5) mod 5 = 2, and (7 - 5) mod 5 = 2: both addm/subm reach
	 * the still-C mpi_mod() through the ?: tail call, and only when
	 * the add/sub half succeeds (criterion: this is unreachable if the
	 * ?: were backwards, which is exactly the class of bug the
	 * conditional-tail-call shape invites). */
	{
		static const unsigned long seven[1] = { 7 }, five[1] = { 5 };
		MPI u = mk_mpi(1, 0, seven), v = mk_mpi(1, 0, five);
		MPI m = mk_mpi(1, 0, five);

		ok = u && v && m && !mpi_addm(w, u, v, m);
		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 2,
		      "mpi_addm: (7 + 5) mod 5 = 2");
		mpi_free(u); mpi_free(v); mpi_free(m);
	}
	{
		static const unsigned long seven[1] = { 7 }, five[1] = { 5 };
		MPI u = mk_mpi(1, 0, seven), v = mk_mpi(1, 0, five);
		MPI m = mk_mpi(1, 0, five);

		ok = u && v && m && !mpi_subm(w, u, v, m);
		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 2,
		      "mpi_subm: (7 - 5) mod 5 = 2");
		mpi_free(u); mpi_free(v); mpi_free(m);
	}

	mpi_free(w);
}

static void __init test_mpi_sub_ui(void)
{
	MPI w = mpi_alloc(4);

	if (!w) {
		check(false, "mpi_sub_ui setup: mpi_alloc failed");
		return;
	}

	/* u == 0 (nlimbs == 0): the dedicated early-return path. */
	{
		MPI u = mpi_alloc(1);
		bool ok = u && !mpi_sub_ui(w, u, 5);

		check(ok && w->nlimbs == 1 && w->sign == 1 && w->d[0] == 5,
		      "mpi_sub_ui: 0 - 5 = -5");
		mpi_free(u);
	}

	/* u positive, u >= vval: the mpihelp_sub_1() branch. */
	{
		static const unsigned long seven[1] = { 7 };
		MPI u = mk_mpi(1, 0, seven);
		bool ok = u && !mpi_sub_ui(w, u, 3);

		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 4,
		      "mpi_sub_ui: 7 - 3 = 4");
		mpi_free(u);
	}

	/* u positive, single limb, u < vval: the dedicated "signs
	 * differ, exact comparison" branch (w->d[0] = vval - u->d[0]). */
	{
		static const unsigned long three[1] = { 3 };
		MPI u = mk_mpi(1, 0, three);
		bool ok = u && !mpi_sub_ui(w, u, 7);

		check(ok && w->nlimbs == 1 && w->sign == 1 && w->d[0] == 4,
		      "mpi_sub_ui: 3 - 7 = -4");
		mpi_free(u);
	}

	/* u already negative: the mpihelp_add_1() branch, magnitude grows. */
	{
		static const unsigned long five[1] = { 5 };
		MPI u = mk_mpi(1, 1, five); /* u = -5 */
		bool ok = u && !mpi_sub_ui(w, u, 3);

		check(ok && w->nlimbs == 1 && w->sign == 1 && w->d[0] == 8,
		      "mpi_sub_ui: -5 - 3 = -8");
		mpi_free(u);
	}

	/* Top limb becomes exactly zero after subtracting: nlimbs must
	 * shrink by one, not stay stale. */
	{
		static const unsigned long two_limbs[2] = { 0, 1 }; /* 2^BITS_PER_LONG */
		MPI u = mk_mpi(2, 0, two_limbs);
		bool ok = u && !mpi_sub_ui(w, u, 1);

		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == ~0UL,
		      "mpi_sub_ui: 2^BITS_PER_LONG - 1 shrinks nlimbs back to 1");
		mpi_free(u);
	}

	mpi_free(w);
}

/*
 * lib/crypto/mpi/mpih_mul_rs.rs -- none of its five real symbols is
 * EXPORT_SYMBOL, and neither mpi_mul() nor mpi_powm() (both still C,
 * both EXPORT_SYMBOL_GPL) is on any path X.509 certificate loading takes
 * at boot with CONFIG_MODULE_SIG unset -- confirmed by sabotaging
 * mpihelp_mul() to always return an error and reboot: boot stayed clean,
 * certs still "loaded", self-tests still passed. Class A, same as
 * mpi_add()/mpi_addm() above. Values from a real oracle (Python), not
 * hand-derived, per this project's own guard on that.
 */
static void __init test_mpi_mul(void)
{
	MPI w = mpi_alloc(8);

	if (!w) {
		check(false, "mpi_mul setup: mpi_alloc failed");
		return;
	}

	/* 7 * 5 = 35: the trivial single-limb path. */
	{
		static const unsigned long seven[1] = { 7 }, five[1] = { 5 };
		MPI u = mk_mpi(1, 0, seven), v = mk_mpi(1, 0, five);
		bool ok = u && v && !mpi_mul(w, u, v);

		check(ok && w->nlimbs == 1 && w->sign == 0 && w->d[0] == 35,
		      "mpi_mul: 7 * 5 = 35");
		mpi_free(u); mpi_free(v);
	}

	/* (2^70+5) * (2^70+7): two-limb operands on both sides, reaching
	 * mpihelp_mul's multi-limb schoolbook loop (vsize == 2), still well
	 * under KARATSUBA_THRESHOLD (16). Product independently computed:
	 * 0x400000000000000005 * 0x400000000000000007 =
	 * 0x100000000000000003000000000000000023, i.e. limbs
	 * [0x23, 0x300, 0x1000] little-endian.
	 */
	{
		static const unsigned long u_limbs[2] = { 5, 64 };
		static const unsigned long v_limbs[2] = { 7, 64 };
		MPI u = mk_mpi(2, 0, u_limbs), v = mk_mpi(2, 0, v_limbs);
		bool ok = u && v && !mpi_mul(w, u, v);

		check(ok && w->nlimbs == 3 && w->sign == 0 &&
		      w->d[0] == 0x23 && w->d[1] == 0x300 && w->d[2] == 0x1000,
		      "mpi_mul: (2^70+5) * (2^70+7), multi-limb operands");
		mpi_free(u); mpi_free(v);
	}

	mpi_free(w);
}

/*
 * mpi_powm() reaches mpih_sqr_n_basecase() (and, for large moduli,
 * mpih_sqr_n()/mpihelp_mul_karatsuba_case()) via its own repeated-
 * squaring loop whenever rsize < KARATSUBA_THRESHOLD, which every
 * modulus this small satisfies unconditionally.
 */
static void __init test_mpi_powm(void)
{
	/* 3^5 mod 7 = 5. */
	static const unsigned long base_l[1] = { 3 };
	static const unsigned long exp_l[1] = { 5 };
	static const unsigned long mod_l[1] = { 7 };
	MPI res = mpi_alloc(4);
	MPI base = mk_mpi(1, 0, base_l);
	MPI exp = mk_mpi(1, 0, exp_l);
	MPI mod = mk_mpi(1, 0, mod_l);
	bool ok = res && base && exp && mod && !mpi_powm(res, base, exp, mod);

	check(ok && res->nlimbs == 1 && res->sign == 0 && res->d[0] == 5,
	      "mpi_powm: 3^5 mod 7 = 5");
	mpi_free(res); mpi_free(base); mpi_free(exp); mpi_free(mod);
}

/*
 * lib/crypto/mpi/mpi_bit_rs.rs -- mpi_get_nbits/mpi_test_bit/mpi_set_bit/
 * mpi_rshift are all EXPORT_SYMBOL_GPL, but their only real-kernel
 * callers (crypto/rsa.c's mpi_test_bit/mpi_set_bit, gated behind
 * `fips_enabled`, which is off; crypto/dh.c's mpi_rshift, only reached
 * when a DH key is actually set up, which nothing does at boot) are not
 * on any path this boot takes -- confirmed by sabotaging each of
 * mpi_get_nbits and mpi_rshift in turn and rebooting: no change to X.509
 * loading or self-test count either time. Class A. Values are small
 * enough to verify by hand, same convention as test_mpih()/test_mpi_add()
 * above. mpi_normalize (not exported) is exercised transitively by
 * mpi_get_nbits's own call to it.
 */
static void __init test_mpi_bit(void)
{
	/* mpi_get_nbits: 0, 1, 255 (8 bits), 256 (9 bits), and a value
	 * whose top limb is 1 with the low limb nonzero (65 bits) -- the
	 * multi-limb path, and mpi_normalize() trimming a stale top limb
	 * along the way. */
	{
		MPI zero = mpi_alloc(1);
		check(zero && mpi_get_nbits(zero) == 0, "mpi_get_nbits: 0 has 0 bits");
		mpi_free(zero);
	}
	{
		static const unsigned long one[1] = { 1 };
		MPI a = mk_mpi(1, 0, one);
		check(a && mpi_get_nbits(a) == 1, "mpi_get_nbits: 1 has 1 bit");
		mpi_free(a);
	}
	{
		static const unsigned long v255[1] = { 255 };
		MPI a = mk_mpi(1, 0, v255);
		check(a && mpi_get_nbits(a) == 8, "mpi_get_nbits: 255 has 8 bits");
		mpi_free(a);
	}
	{
		static const unsigned long v256[1] = { 256 };
		MPI a = mk_mpi(1, 0, v256);
		check(a && mpi_get_nbits(a) == 9, "mpi_get_nbits: 256 has 9 bits");
		mpi_free(a);
	}
	{
		/* Top (real) limb 1, and a stale ZERO limb above it (nlimbs
		 * overstates the true size) that mpi_normalize() must trim
		 * away first -- mpi_normalize only ever trims a top limb
		 * that is exactly zero, never a nonzero one. */
		unsigned long two_limbs[3] = { 5, 1, 0 };
		MPI a = mk_mpi(3, 0, two_limbs);
		check(a && mpi_get_nbits(a) == BITS_PER_LONG + 1 && a->nlimbs == 2,
		      "mpi_get_nbits: 2^BITS_PER_LONG + 5 has BITS_PER_LONG+1 bits, normalizes nlimbs");
		mpi_free(a);
	}

	/* mpi_test_bit: 0b1010 = 10 -- bit 1 and bit 3 set, bit 0 and bit
	 * 2 clear; a bit past nlimbs entirely reads as clear too. */
	{
		static const unsigned long ten[1] = { 10 };
		MPI a = mk_mpi(1, 0, ten);
		bool ok = a && !mpi_test_bit(a, 0) && mpi_test_bit(a, 1) &&
			  !mpi_test_bit(a, 2) && mpi_test_bit(a, 3) &&
			  !mpi_test_bit(a, BITS_PER_LONG + 5);
		check(ok, "mpi_test_bit: 10 = 0b1010, bits 1 and 3 set");
		mpi_free(a);
	}

	/* mpi_set_bit: on zero, sets exactly that bit; a bit past the
	 * current single limb grows nlimbs and zeroes the newly-exposed
	 * limb first. */
	{
		MPI a = mpi_alloc(1);
		bool ok = a && !mpi_set_bit(a, 0);
		check(ok && a->nlimbs == 1 && a->d[0] == 1,
		      "mpi_set_bit: bit 0 of 0 sets it to 1");
		mpi_free(a);
	}
	{
		MPI a = mpi_alloc(1);
		bool ok = a && !mpi_set_bit(a, BITS_PER_LONG + 6);
		check(ok && a->nlimbs == 2 && a->d[0] == 0 &&
		      a->d[1] == (1UL << 6),
		      "mpi_set_bit: a bit past the first limb grows nlimbs, zeroing the gap");
		mpi_free(a);
	}

	/* mpi_rshift: 10 >> 1 = 5 (in-place, x == a); 10 >> 10 = 0
	 * (shifting entirely away); a two-limb value shifted by exactly
	 * BITS_PER_LONG bits (the nlimbs-only path, no mpihelp_rshift
	 * call) and by BITS_PER_LONG+1 (both nlimbs and a sub-limb shift),
	 * x != a (the copy path) in both. */
	{
		static const unsigned long ten[1] = { 10 };
		MPI a = mk_mpi(1, 0, ten);
		bool ok = a && !mpi_rshift(a, a, 1);
		check(ok && a->nlimbs == 1 && a->d[0] == 5,
		      "mpi_rshift: 10 >> 1 = 5, in place");
		mpi_free(a);
	}
	{
		static const unsigned long ten[1] = { 10 };
		MPI a = mk_mpi(1, 0, ten);
		bool ok = a && !mpi_rshift(a, a, 10);
		check(ok && a->nlimbs == 0, "mpi_rshift: 10 >> 10 = 0, in place");
		mpi_free(a);
	}
	{
		/* (2^BITS_PER_LONG + 7) >> BITS_PER_LONG == 1. */
		unsigned long two_limbs[2] = { 7, 1 };
		MPI a = mk_mpi(2, 0, two_limbs);
		MPI x = mpi_alloc(2);
		bool ok = a && x && !mpi_rshift(x, a, BITS_PER_LONG);
		check(ok && x->nlimbs == 1 && x->d[0] == 1,
		      "mpi_rshift: exact-limb shift, x != a");
		mpi_free(a); mpi_free(x);
	}
	{
		/* (2^(BITS_PER_LONG+1) + 2^BITS_PER_LONG + 7) >> (BITS_PER_LONG+1)
		 * == 1 -- both a whole-limb shift and a sub-limb
		 * mpihelp_rshift() call fire. */
		unsigned long two_limbs[2] = { 7, 3 };
		MPI a = mk_mpi(2, 0, two_limbs);
		MPI x = mpi_alloc(2);
		bool ok = a && x && !mpi_rshift(x, a, BITS_PER_LONG + 1);
		check(ok && x->nlimbs == 1 && x->d[0] == 1,
		      "mpi_rshift: whole-limb-plus-remainder shift, x != a");
		mpi_free(a); mpi_free(x);
	}
}

/*
 * lib/crypto/mpi/mpicoder_rs.rs -- mpi_read_raw_data/mpi_write_to_sgl/
 * mpi_read_raw_from_sgl are all class B: sabotaging each in turn broke
 * real X.509 certificate loading at boot ("Problem loading in-kernel
 * X.509 certificate", -ENOMEM / -EINVAL respectively) -- the kernel's
 * own X.509 verification calls crypto/rsa.c's rsa_set_pub_key() (which
 * calls mpi_read_raw_data()) and rsa_enc() (the RSA "verify" primitive,
 * which calls both mpi_read_raw_from_sgl() and mpi_write_to_sgl()) while
 * loading the compiled-in certificates, even with CONFIG_MODULE_SIG off.
 * mpi_read_from_buffer()/mpi_read_buffer()/mpi_get_buffer() are class A:
 * their only real caller, lib/digsig.c, is for module/kexec signature
 * verification (CONFIG_MODULE_SIG), confirmed off by sabotaging all
 * three together and finding no change to boot. Values are small enough
 * to verify by hand, same convention as test_mpih() above.
 */
static void __init test_mpicoder(void)
{
	/* mpi_read_from_buffer: a 2-byte big-endian bit-length prefix (13
	 * bits) followed by ceil(13/8)=2 raw bytes, msb first, for 0x1234. */
	{
		static const u8 buf[4] = { 0x00, 0x0d, 0x12, 0x34 };
		unsigned int nread = sizeof(buf);
		MPI a = mpi_read_from_buffer(buf, &nread);
		bool ok = a && !IS_ERR(a);

		check(ok && nread == 4 && a->nlimbs == 1 && a->sign == 0 &&
		      a->d[0] == 0x1234,
		      "mpi_read_from_buffer: 13-bit-prefixed 0x1234");
		if (ok)
			mpi_free(a);
	}
	{
		/* Too few bytes even for the length prefix itself. */
		static const u8 buf[1] = { 0x00 };
		unsigned int nread = sizeof(buf);
		MPI a = mpi_read_from_buffer(buf, &nread);

		check(IS_ERR(a) && PTR_ERR(a) == -EINVAL,
		      "mpi_read_from_buffer: fewer than 2 bytes is -EINVAL");
	}

	/* mpi_get_buffer (which calls mpi_read_buffer internally): 0x1234
	 * in a single limb has 6 leading zero bytes, so the returned
	 * buffer is exactly 2 bytes, msb first. */
	{
		static const unsigned long v[1] = { 0x1234 };
		MPI a = mk_mpi(1, 0, v);
		unsigned int nbytes = 0;
		int sign = -1;
		u8 *buf = a ? mpi_get_buffer(a, &nbytes, &sign) : NULL;
		bool ok = buf && nbytes == 2 && sign == 0 &&
			  buf[0] == 0x12 && buf[1] == 0x34;

		check(ok, "mpi_get_buffer: 0x1234 packs to {0x12, 0x34}");
		kfree(buf);
		mpi_free(a);
	}
	{
		/* Value 0: mpi_get_size() is 0, so mpi_get_buffer's own
		 * "if (!n) n++" path allocates 1 byte and mpi_read_buffer
		 * writes 0 bytes into it (nbytes == 0). */
		MPI a = mpi_alloc(1);
		unsigned int nbytes = 1;
		u8 *buf = a ? mpi_get_buffer(a, &nbytes, NULL) : NULL;

		check(buf && nbytes == 0, "mpi_get_buffer: 0 packs to an empty buffer");
		kfree(buf);
		mpi_free(a);
	}

	/* mpi_read_buffer directly: buf_len too small is -EOVERFLOW, and
	 * still reports the required size. */
	{
		static const unsigned long v[1] = { 0x1234 };
		MPI a = mk_mpi(1, 0, v);
		u8 buf[1];
		unsigned int nbytes = 0;
		int ret = a ? mpi_read_buffer(a, buf, sizeof(buf), &nbytes, NULL) : -ENOMEM;

		check(ret == -EOVERFLOW && nbytes == 2,
		      "mpi_read_buffer: buf_len too small is -EOVERFLOW, reports the real size");
		mpi_free(a);
	}
}
#else
static void __init test_mpih(void) { }
static void __init test_mpi_add(void) { }
static void __init test_mpi_sub_ui(void) { }
static void __init test_mpi_mul(void) { }
static void __init test_mpi_powm(void) { }
static void __init test_mpi_bit(void) { }
static void __init test_mpicoder(void) { }
#endif

#if IS_ENABLED(CONFIG_CHECK_SIGNATURE)
static void __init test_check_signature(void)
{
	/* check_signature() reads its window with readb(), so its argument is
	 * __iomem. There is no iomem window to hand it here, and on x86
	 * readb() of a RAM address is the plain load it would be anyway --
	 * so the cast is __force'd. That is a property of this TEST, not of
	 * the port: the port never assumes it, and calls the readb() helper
	 * for every byte exactly as the C did. */
	static const unsigned char win[] __initconst = {
		'R', 'u', 's', 't', 'y', 0x00, 0xff, 'L',
	};
	const volatile void __iomem *io = (const volatile void __iomem __force *)win;

	check(check_signature(io, win, sizeof(win)) == 1,
	      "check_signature matches the whole window");
	check(check_signature(io, win, 0) == 1,
	      "check_signature of a zero-length signature matches");

	/* Every mismatch position, including the last -- a body that stopped
	 * one byte early passes all the others. */
	for (unsigned int i = 0; i < sizeof(win); i++) {
		unsigned char sig[sizeof(win)];

		memcpy(sig, win, sizeof(sig));
		sig[i] ^= 0xff;
		check(check_signature(io, sig, sizeof(sig)) == 0,
		      "check_signature rejects a signature differing at one byte");
	}

	/* Prefixes match; the window walks forward from the pointer given. */
	check(check_signature(io, win, 4) == 1,
	      "check_signature matches a prefix");
	check(check_signature(io + 3, win + 3, 5) == 1,
	      "check_signature starts from the pointer it is given");
	check(check_signature(io + 1, win, sizeof(win) - 1) == 0,
	      "check_signature compares against the offset window, not the base");
}
#else
static void __init test_check_signature(void) { }
#endif

#if IS_ENABLED(CONFIG_ZLIB_INFLATE)
#include "libtest_zlib_generated.h"

/* Regenerate a vector's plaintext. The SAME rules the generator script uses;
 * if the two ever drift the vector fails, which is a test bug surfaced as a
 * test failure rather than a silent pass. */
static void __init lt_zgen(int kind, u8 *b, unsigned int n)
{
	static const u8 p3[3] __initconst = { 0x01, 0x02, 0x03 };
	static const u8 p7[7] __initconst = {
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	};
	static const char acgt[4] __initconst = { 'A', 'C', 'G', 'T' };
	unsigned int i, third;
	u32 s;

	switch (kind) {
	case 0:
		memset(b, 0x5a, n);
		return;
	case 1:
		for (i = 0; i < n; i++)
			b[i] = (i & 1) ? 0xad : 0xde;
		return;
	case 2:
		for (i = 0; i < n; i++)
			b[i] = p3[i % 3];
		return;
	case 3:
		for (i = 0; i < n; i++)
			b[i] = p7[i % 7];
		return;
	case 4:
		s = 12345;
		for (i = 0; i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = acgt[(s >> 16) & 3];
		}
		return;
	default:
		third = n / 3;
		lt_zgen(0, b, third);
		lt_zgen(2, b + third, third);
		lt_zgen(4, b + 2 * third, n - 2 * third);
		return;
	}
}

#define LT_ZMAX 32768

/* lib/zlib_inflate/inffast_rs.rs, reached through zlib_inflate().
 *
 * inflate_fast() is entered only when avail_in >= 6 and avail_out >= 258, so
 * the chunk sizes below are not decoration -- they are what puts the decoder
 * on the fast path at all. The last two vectors are fed in small pieces on
 * purpose: a match that reaches further back than this call's own output has
 * to be copied out of state->window, and those three window paths are
 * unreachable with one big output buffer.
 *
 * Correctness lives in port/test/zlib_inflate/, which compares this against
 * the pristine C over hundreds of thousands of streams. What this answers is
 * whether the Rust ran, here, in the kernel.
 */
static void __init test_zlib_inflate(void)
{
	struct z_stream_s *strm;
	void *ws;
	u8 *want, *got;
	unsigned int v;

	strm = kzalloc(sizeof(*strm), GFP_KERNEL);
	ws = kzalloc(zlib_inflate_workspacesize(), GFP_KERNEL);
	want = kmalloc(LT_ZMAX, GFP_KERNEL);
	got = kmalloc(LT_ZMAX, GFP_KERNEL);
	if (!strm || !ws || !want || !got) {
		check(false, "zlib_inflate test could not allocate");
		goto out;
	}

	for (v = 0; v < ARRAY_SIZE(lt_zvecs); v++) {
		const struct lt_zvec *z = &lt_zvecs[v];
		unsigned int inchunk, outchunk, ipos = 0, opos = 0;
		bool chunked = z->plain_len > 20000;
		int rc;

		if (z->plain_len > LT_ZMAX) {
			check(false, "zlib vector larger than the test buffer");
			continue;
		}

		inchunk = chunked ? 64 : z->comp_len;
		outchunk = chunked ? 300 : z->plain_len;

		lt_zgen(z->kind, want, z->plain_len);
		memset(got, 0, z->plain_len);
		memset(strm, 0, sizeof(*strm));
		strm->workspace = ws;

		rc = zlib_inflateInit2(strm, z->wbits);
		if (rc != Z_OK) {
			check(false, "zlib_inflateInit2 failed");
			continue;
		}

		for (;;) {
			if (strm->avail_in == 0 && ipos < z->comp_len) {
				unsigned int k = z->comp_len - ipos;

				if (k > inchunk)
					k = inchunk;
				strm->next_in = z->comp + ipos;
				strm->avail_in = k;
				ipos += k;
			}
			if (strm->avail_out == 0 && opos < z->plain_len) {
				unsigned int k = z->plain_len - opos;

				if (k > outchunk)
					k = outchunk;
				strm->next_out = got + opos;
				strm->avail_out = k;
				opos += k;
			}
			if (strm->avail_in == 0 && strm->avail_out == 0)
				break;

			rc = zlib_inflate(strm, Z_NO_FLUSH);
			if (rc != Z_OK)
				break;
			if (strm->avail_in == 0 && ipos == z->comp_len &&
			    strm->avail_out == 0 && opos == z->plain_len)
				break;
		}
		zlib_inflateEnd(strm);

		check(rc == Z_STREAM_END, z->note);
		check(strm->total_out == z->plain_len,
		      "zlib_inflate produced the expected length");
		check(memcmp(got, want, z->plain_len) == 0,
		      "zlib_inflate reproduced the plaintext");
	}

out:
	kfree(got);
	kfree(want);
	kfree(ws);
	kfree(strm);
}
#else
static void __init test_zlib_inflate(void) { }
#endif

#if IS_ENABLED(CONFIG_LZO_DECOMPRESS)
#include "libtest_lzo_generated.h"

/* The SAME rules port/test/lzo/gen_kernel_vectors.c uses. If the two drift,
 * the vector fails -- a test bug surfaced as a test failure, not a silent
 * pass. */
static void __init lt_lgen(int kind, u8 *b, unsigned int n)
{
	static const u8 p3[3] __initconst = { 0x01, 0x02, 0x03 };
	static const char acgt[4] __initconst = { 'A', 'C', 'G', 'T' };
	unsigned int i, third;
	u32 s = 12345;

	switch (kind) {
	case 0:
		memset(b, 0x5a, n);
		return;
	case 1:
		for (i = 0; i < n; i++)
			b[i] = (i & 1) ? 0xad : 0xde;
		return;
	case 2:
		for (i = 0; i < n; i++)
			b[i] = p3[i % 3];
		return;
	case 3:
		for (i = 0; i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = acgt[(s >> 16) & 3];
		}
		return;
	case 4:
		memset(b, 0, n);
		return;
	default:
		third = n / 3;
		lt_lgen(0, b, third);
		lt_lgen(2, b + third, third);
		lt_lgen(3, b + 2 * third, n - 2 * third);
		return;
	}
}

#define LT_LMAX 32768

/* lib/lzo/lzo1x_decompress_safe_rs.rs, reached through the exported C entry
 * symbol in lzo1x_decompress_safe.c.
 *
 * Correctness lives in port/test/lzo/, which compares this against the
 * pristine C over hundreds of thousands of streams. What this answers is
 * whether the Rust ran, here, in the kernel -- and the last two checks are
 * the error exits, because five of this function's six returns are failures
 * and a vector set of well-formed streams would never see one.
 */
static void __init test_lzo(void)
{
	u8 *want, *got;
	unsigned int v;

	want = kmalloc(LT_LMAX, GFP_KERNEL);
	got = kmalloc(LT_LMAX, GFP_KERNEL);
	if (!want || !got) {
		check(false, "lzo test could not allocate");
		goto out;
	}

	for (v = 0; v < ARRAY_SIZE(lt_lvecs); v++) {
		const struct lt_lvec *z = &lt_lvecs[v];
		size_t ol = z->plain_len;
		int rc;

		if (z->plain_len > LT_LMAX) {
			check(false, "lzo vector larger than the test buffer");
			continue;
		}
		lt_lgen(z->kind, want, z->plain_len);
		memset(got, 0, z->plain_len);

		rc = lzo1x_decompress_safe(z->comp, z->comp_len, got, &ol);
		check(rc == LZO_E_OK, z->note);
		check(ol == z->plain_len, "lzo produced the expected length");
		check(memcmp(got, want, z->plain_len) == 0,
		      "lzo reproduced the plaintext");
	}

	/* A truncated stream must be refused, not decoded. */
	{
		const struct lt_lvec *z = &lt_lvecs[0];
		size_t ol = LT_LMAX;

		check(lzo1x_decompress_safe(z->comp, z->comp_len / 2, got, &ol)
		      != LZO_E_OK, "lzo rejects a truncated stream");
	}
	/* So must an output buffer too small to hold the result. */
	{
		const struct lt_lvec *z = &lt_lvecs[0];
		size_t ol = 8;

		check(lzo1x_decompress_safe(z->comp, z->comp_len, got, &ol)
		      == LZO_E_OUTPUT_OVERRUN,
		      "lzo reports LZO_E_OUTPUT_OVERRUN on a short buffer");
	}
	/* And an input shorter than the three-byte minimum. */
	{
		size_t ol = LT_LMAX;

		check(lzo1x_decompress_safe(lt_lvecs[0].comp, 2, got, &ol)
		      == LZO_E_INPUT_OVERRUN,
		      "lzo reports LZO_E_INPUT_OVERRUN on a runt input");
	}

out:
	kfree(got);
	kfree(want);
}
#else
static void __init test_lzo(void) { }
#endif

#if IS_ENABLED(CONFIG_XZ_DEC) && IS_ENABLED(CONFIG_XZ_DEC_BCJ)
#include "libtest_xz_generated.h"

/* THE SAME RULES port/test/xz/gen_plain.c uses. If the two drift, the vectors
 * below decode correctly and are compared against a plaintext nothing
 * produced. gen-vectors.sh diffs these two copies on every run and refuses to
 * regenerate if they differ. */
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

#define LT_XMAX 4096

/* THE OUTPUT CHUNK SIZE IS THE AXIS, NOT A DETAIL. xz_dec_bcj_run() reaches
 * end-of-stream down two different paths depending on whether the last LZMA2
 * output landed in the caller's buffer or in the 16-byte straddle buffer, and
 * which one happens is decided entirely by how the caller sizes its output.
 *
 * Measured, not assumed: a sabotage that dropped the end-of-stream "everything
 * in temp is filtered" marking was caught by three of seven filters at one
 * chunk size and by NONE at another. Same code, same vectors, different
 * chunking. So every vector runs at all three.
 */
static const unsigned int lt_xout[] __initconst = { 37, 16, LT_XMAX };

/* lib/xz/xz_dec_bcj_rs.rs, reached through xz_dec_run().
 *
 * Seven .xz streams, one per BCJ filter, each produced by the real xz(1)
 * applying the FORWARD filter. Nothing in this project computed the expected
 * plaintext: it is what lt_xgen() generated before xz(1) ever saw it, so a
 * port and its oracle cannot agree here on a wrong answer.
 *
 * Correctness lives in port/test/xz/, which compares this against the
 * pristine C over hundreds of thousands of buffers. What this answers is
 * whether the Rust ran, here, in the kernel, on all seven filters.
 */
static void __init test_xz(void)
{
	struct xz_dec *dec;
	struct xz_buf b;
	u8 *want, *got;
	unsigned int v;

	want = kmalloc(LT_XMAX, GFP_KERNEL);
	got = kmalloc(LT_XMAX, GFP_KERNEL);
	dec = xz_dec_init(XZ_PREALLOC, 1 << 16);
	if (!want || !got || !dec) {
		check(false, "xz test could not allocate");
		goto out;
	}

	for (v = 0; v < ARRAY_SIZE(lt_xvecs); v++) {
		const struct lt_xvec *x = &lt_xvecs[v];
		unsigned int c;

		if (x->plain_len > LT_XMAX) {
			check(false, "xz vector larger than the test buffer");
			continue;
		}

		for (c = 0; c < ARRAY_SIZE(lt_xout); c++) {
			unsigned int chunk = lt_xout[c];
			unsigned int guard = 0;
			enum xz_ret ret = XZ_OK;

			lt_xgen(x->kind, want, x->plain_len);
			memset(got, 0, LT_XMAX);
			xz_dec_reset(dec);

			b.in = x->comp;
			b.in_pos = 0;
			b.in_size = x->comp_len;
			b.out = got;
			b.out_pos = 0;
			b.out_size = 0;

			while (guard++ < 4 * LT_XMAX / chunk + 16) {
				b.out_size = b.out_pos + chunk;
				if (b.out_size > LT_XMAX)
					b.out_size = LT_XMAX;

				ret = xz_dec_run(dec, &b);
				if (ret != XZ_OK)
					break;
				if (b.out_pos == LT_XMAX)
					break;
			}

			check(ret == XZ_STREAM_END, x->note);
			check(b.out_pos == x->plain_len,
			      "xz_dec_run produced the expected length");
			check(memcmp(got, want, x->plain_len) == 0,
			      "xz_dec_bcj reproduced the plaintext");
		}
	}

out:
	if (dec)
		xz_dec_end(dec);
	kfree(got);
	kfree(want);
}
#else
static void __init test_xz(void) { }
#endif

#if IS_ENABLED(CONFIG_LZ4_DECOMPRESS)
#include "libtest_lz4_generated.h"

/* THE SAME RULES port/test/lz4/gen_kernel_vectors.c uses. gen-vectors.sh
 * diffs these two copies on every run and refuses to regenerate if they
 * differ. */
/* LT_L4GEN_BEGIN */
static void lt_l4gen(int kind, u8 *b, unsigned int n)
{
	u32 s = 0x2468ace0u + (u32)kind * 2654435761u;
	unsigned int i;

	for (i = 0; i < n; i++) {
		s = s * 1103515245u + 12345u;
		switch (kind) {
		case 0:				/* incompressible */
			b[i] = (u8)(s >> 24);
			break;
		case 1:				/* long runs */
			b[i] = (u8)((i / 97) & 0xff);
			break;
		case 2:				/* short alphabet */
			b[i] = (u8)('a' + ((s >> 20) & 3));
			break;
		case 3:				/* back-references */
			if (i >= 64 && ((s >> 16) & 1))
				b[i] = b[i - 64];
			else
				b[i] = (u8)('A' + ((s >> 22) & 15));
			break;
		default:
			/* SMALL PERIODS 1..8, which is the only thing that
			 * reaches the offset < 8 match path and its
			 * inc32table/dec64table steps. Without this shape a
			 * sabotage of dec64table[4] passed every kernel
			 * vector. */
			b[i] = (u8)(0x30 + (i % (1 + (i / 512) % 8)));
			break;
		}
	}
}
/* LT_L4GEN_END */

#define LT_L4MAX 16384

/* lib/lz4/lz4_decompress_rs.rs, reached through the exported C entry symbols.
 *
 * Sixteen streams -- four plaintext shapes at four lengths -- produced by the
 * SYSTEM liblz4, so nothing in this project computed the expected plaintext.
 * LZ4 has no boot-path caller here (rig/boot.sh gzips the initramfs), so this
 * is the whole of criterion 5 for it.
 *
 * Correctness lives in port/test/lz4/, which compares this against the
 * pristine C over millions of blocks.
 */
static void __init test_lz4(void)
{
	u8 *want, *got;
	unsigned int v;

	want = kmalloc(LT_L4MAX, GFP_KERNEL);
	got = kmalloc(LT_L4MAX + 64, GFP_KERNEL);
	if (!want || !got) {
		check(false, "lz4 test could not allocate");
		goto out;
	}

	for (v = 0; v < ARRAY_SIZE(lt_l4vecs); v++) {
		const struct lt_l4vec *z = &lt_l4vecs[v];
		int rc;

		if (z->plain_len > LT_L4MAX) {
			check(false, "lz4 vector larger than the test buffer");
			continue;
		}

		lt_l4gen(z->kind, want, z->plain_len);

		memset(got, 0, z->plain_len);
		rc = LZ4_decompress_safe(z->comp, got, z->comp_len,
					 z->plain_len);
		check(rc == (int)z->plain_len,
		      "LZ4_decompress_safe produced the expected length");
		check(memcmp(got, want, z->plain_len) == 0,
		      "LZ4_decompress_safe reproduced the plaintext");

		/* The fast decoder: no input bound, exact output size. */
		memset(got, 0, z->plain_len);
		rc = LZ4_decompress_fast(z->comp, got, z->plain_len);
		check(rc == (int)z->comp_len,
		      "LZ4_decompress_fast consumed the whole stream");
		check(memcmp(got, want, z->plain_len) == 0,
		      "LZ4_decompress_fast reproduced the plaintext");

		/* Partial decoding, to half the output. */
		if (z->plain_len > 8) {
			unsigned int half = z->plain_len / 2;

			memset(got, 0, z->plain_len);
			rc = LZ4_decompress_safe_partial(z->comp, got,
					z->comp_len, half, z->plain_len);
			check(rc >= 0 && (unsigned int)rc >= half,
			      "LZ4_decompress_safe_partial reached the target");
			check(memcmp(got, want, half) == 0,
			      "LZ4_decompress_safe_partial reproduced the prefix");
		}
	}

	/* A truncated stream must be rejected, not decoded. */
	if (lt_l4vecs[3].comp_len > 8) {
		int rc = LZ4_decompress_safe(lt_l4vecs[3].comp, got,
					     lt_l4vecs[3].comp_len / 2,
					     lt_l4vecs[3].plain_len);

		check(rc < 0, "LZ4_decompress_safe rejects a truncated stream");
	}

out:
	kfree(got);
	kfree(want);
}
#else
static void __init test_lz4(void) { }
#endif

#if IS_ENABLED(CONFIG_ZSTD_DECOMPRESS)
/* The generator caps every plaintext at 8192 bytes; the slack is so a port
 * that decodes too MUCH has somewhere to write it and gets caught by the
 * length check rather than corrupting the heap. */
#define LT_ZBUF 16384
#include <linux/zstd.h>
#include "libtest_zstd_generated.h"

/* lib/zstd/common/entropy_common_rs.rs, reached through zstd_decompress_dctx().
 *
 * WHAT MAKES THIS WORTH BOOTING. The vectors were compressed by SYSTEM
 * libzstd, an implementation neither arm of port/test/zstd_entropy/ derives
 * from, so a bug the port and the pristine C SHARE would still show up here.
 * That is the one thing a differential structurally cannot do.
 *
 * WHICH CODE IT REACHES IS MEASURED, NOT HOPED FOR. The generator walks each
 * frame's block headers and refuses to emit unless enough blocks carry a
 * Compressed literals section -- 13 of 18 do -- because a frame using raw
 * literals never calls HUF_readStats and would never enter the ported file.
 * Every vector's per-block literal types are in the generated header's
 * comments.
 *
 * Correctness at the function level lives in port/test/zstd_entropy/, which
 * compares this against the pristine C. What this adds is that the KERNEL
 * executes the Rust and gets the right answer.
 */
static void __init test_zstd(void)
{
	void *ws = NULL;
	u8 *got = NULL;
	u8 *want = NULL;
	zstd_dctx *dctx;
	size_t wssize = zstd_dctx_workspace_bound();
	unsigned int i;

	ws   = kvzalloc(wssize, GFP_KERNEL);
	got  = kmalloc(LT_ZBUF, GFP_KERNEL);
	want = kmalloc(LT_ZBUF, GFP_KERNEL);
	if (!ws || !got || !want) {
		check(false, "zstd test could not allocate");
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(lt_zsvecs); i++) {
		const struct lt_zsvec *z = &lt_zsvecs[i];
		size_t rc;

		if (z->plain_len > LT_ZBUF) {
			check(false, "zstd vector larger than the test buffer");
			continue;
		}
		memcpy(want, z->plain, z->plain_len);
		memset(got, 0xA5, LT_ZBUF);

		dctx = zstd_init_dctx(ws, wssize);
		if (!dctx) {
			check(false, "zstd_init_dctx failed");
			goto out;
		}
		rc = zstd_decompress_dctx(dctx, got, LT_ZBUF,
					  z->comp, z->comp_len);
		if (zstd_is_error(rc)) {
			check(false, "zstd_decompress_dctx returned an error");
			continue;
		}
		check(rc == z->plain_len,
		      "zstd produced the expected length");
		check(rc == z->plain_len && memcmp(got, want, z->plain_len) == 0,
		      "zstd reproduced the plaintext");
	}

	/* A truncated frame must be rejected, not decoded. This is the path
	 * where HUF_readStats and FSE_readNCount see a short buffer, which is
	 * the half of them the success vectors never exercise. */
	for (i = 0; i < ARRAY_SIZE(lt_zsvecs); i++) {
		const struct lt_zsvec *z = &lt_zsvecs[i];
		size_t rc;

		dctx = zstd_init_dctx(ws, wssize);
		if (!dctx)
			break;
		rc = zstd_decompress_dctx(dctx, got, LT_ZBUF,
					  z->comp, z->comp_len / 2);
		check(zstd_is_error(rc) || rc != z->plain_len,
		      "zstd rejects a truncated frame");
	}

out:
	kfree(want);
	kfree(got);
	kvfree(ws);
}
#else
static void __init test_zstd(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_BZIP2)
#include <linux/decompress/bunzip2.h>

/*
 * lib/decompress_bunzip2.c has no separate lib/ decompressor to share --
 * unlike unlzo/unlz4/unxz/uninflate, which call out to an already-tested
 * lzo1x_decompress_safe()/lz4_decompress_safe()/zlib_inflate()/xz_dec_run(),
 * bunzip2()'s whole algorithm lives in this one file. Nothing else in
 * libtest.c exercises it, and this project's own initramfs is gzip (see
 * rig/boot.sh), so CONFIG_RD_BZIP2=y compiles this in but the real boot path
 * never calls it -- SCOPE.md class A, not B. This is its only proof.
 *
 * The vector: `bzip2 -1` of the 56-byte line below repeated 20 times (1080
 * bytes plain, 143 compressed) -- generated once by
 * port/test/decompress_bunzip2/run.sh's corpus and pasted here; correctness
 * across tens of thousands of cases against the pristine C is that
 * userspace differential's job, not this one's.
 */
static const u8 lt_bz2_comp[] = {
	0x42, 0x5a, 0x68, 0x31, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x7d, 0x0f,
	0x98, 0x7e, 0x00, 0x00, 0x6d, 0x9f, 0x80, 0x40, 0x03, 0x90, 0x00, 0x00,
	0x04, 0x10, 0x00, 0xbf, 0x27, 0xde, 0x70, 0x30, 0x00, 0xd8, 0x05, 0x34,
	0x68, 0x03, 0x40, 0x00, 0x14, 0xd1, 0xa0, 0x0d, 0x00, 0x00, 0x14, 0xaa,
	0xa3, 0xf5, 0x41, 0xe8, 0x8d, 0xea, 0x4f, 0x51, 0xea, 0x69, 0xe2, 0x9c,
	0x13, 0x04, 0xe0, 0x9b, 0x93, 0xdc, 0x9f, 0x44, 0xee, 0x4c, 0x93, 0xc1,
	0x3a, 0x09, 0xb9, 0x3f, 0x89, 0x82, 0x6c, 0x4d, 0x49, 0xb1, 0x3f, 0x09,
	0xa9, 0x3a, 0x93, 0x42, 0x6e, 0x4c, 0x93, 0xc0, 0x9b, 0x13, 0x92, 0x74,
	0x26, 0x49, 0xb1, 0x3b, 0x93, 0x24, 0xe4, 0x9a, 0x13, 0x72, 0x60, 0x9e,
	0xc4, 0xe0, 0x9f, 0x64, 0xc9, 0x30, 0x4e, 0xa2, 0x68, 0x4c, 0x13, 0x72,
	0x79, 0x13, 0x62, 0x70, 0x4e, 0x49, 0xea, 0x4d, 0x49, 0xfa, 0x4c, 0x13,
	0xfc, 0x5d, 0xc9, 0x14, 0xe1, 0x42, 0x41, 0xf4, 0x3e, 0x61, 0xf8,
};

static void __init lt_bunzip2_error(char *msg)
{
	pr_err("libtest: bunzip2: %s\n", msg);
}

static void __init test_bunzip2(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_bunzip2 self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *comp;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 64, GFP_KERNEL);
	comp = kmemdup(lt_bz2_comp, sizeof(lt_bz2_comp), GFP_KERNEL);
	if (!want || !got || !comp) {
		check(false, "bunzip2 test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 64);

	rc = bunzip2(comp, sizeof(lt_bz2_comp), NULL, NULL, got, NULL, lt_bunzip2_error);
	check(rc == 0, "bunzip2 returns success on a valid stream");
	check(memcmp(got, want, plain_len) == 0, "bunzip2 reproduced the plaintext");

	/* A truncated stream must be refused, not decoded as garbage. */
	{
		unsigned int half = sizeof(lt_bz2_comp) / 2;
		u8 *comp2 = kmemdup(lt_bz2_comp, half, GFP_KERNEL);

		if (comp2) {
			memset(got, 0, plain_len + 64);
			rc = bunzip2(comp2, half, NULL, NULL, got, NULL, lt_bunzip2_error);
			check(rc != 0, "bunzip2 rejects a truncated stream");
			kfree(comp2);
		} else {
			check(false, "bunzip2 truncated-stream test could not allocate");
		}
	}
out:
	kfree(comp);
	kfree(got);
	kfree(want);
}
#else
static void __init test_bunzip2(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_LZ4)
#include <linux/decompress/unlz4.h>

/*
 * lib/decompress_unlz4.c's own substance is the archive framing (magic +
 * length-prefixed chunks), not LZ4 block decompression -- that's already
 * covered by test_lz4() above. This project's initramfs is gzip (see
 * rig/boot.sh), so CONFIG_RD_LZ4=y compiles this in but the real boot path
 * never calls it -- SCOPE.md class A, same as bunzip2 above. This is its
 * only proof.
 *
 * The vector: a kernel-format archive (ARCHIVE_MAGICNUMBER + one 4096-byte
 * chunk) of the 53-byte line below repeated 20 times (1040 bytes plain, 74
 * archived) -- generated once by port/test/decompress_unlz4/'s corpus and
 * pasted here; correctness across the differential's plaintext/chunk-size
 * matrix is that userspace test's job, not this one's.
 */
static const u8 lt_unlz4_arc[] = {
	0x02, 0x21, 0x4c, 0x18, 0x42, 0x00, 0x00, 0x00, 0xff, 0x25, 0x52, 0x75,
	0x73, 0x74, 0x79, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x6c, 0x69,
	0x62, 0x2f, 0x64, 0x65, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73,
	0x5f, 0x75, 0x6e, 0x6c, 0x7a, 0x34, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x2d,
	0x74, 0x65, 0x73, 0x74, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x2e, 0x20, 0x34, 0x00, 0xff, 0xff, 0xff, 0xc7, 0x50, 0x6f, 0x61, 0x64,
	0x2e, 0x20,
};

static void __init lt_unlz4_error(char *msg)
{
	pr_err("libtest: unlz4: %s\n", msg);
}

static void __init test_unlz4(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_unlz4 self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_unlz4_arc, sizeof(lt_unlz4_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "unlz4 test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = unlz4(arc, sizeof(lt_unlz4_arc), NULL, NULL, got, NULL, lt_unlz4_error);
	check(rc == 0, "unlz4 returns success on a valid archive");
	check(memcmp(got, want, plain_len) == 0, "unlz4 reproduced the plaintext");

	/*
	 * No truncated-archive sub-test here, unlike bunzip2's: in buffer
	 * mode unlz4() trusts the embedded chunk length against
	 * LZ4_decompress_safe without checking it against the bytes actually
	 * left in the buffer -- inherited from upstream, not introduced by
	 * this port (port/test/decompress_unlz4/ compares against the C
	 * oracle on this exact question). Constructing a truncated case here
	 * would just be handing kmalloc'd memory a real out-of-bounds read
	 * at boot for no coverage gain.
	 */
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_unlz4(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_LZO)
#include <linux/decompress/unlzo.h>

/*
 * lib/decompress_unlzo.c's own substance is the LZOP header parsing and
 * block framing, not LZO block decompression -- that's already covered by
 * test_lzo() above. This project's initramfs is gzip (see rig/boot.sh), so
 * CONFIG_RD_LZO=y compiles this in but the real boot path never calls it --
 * SCOPE.md class A, same as bunzip2 and unlz4 above. This is its only
 * proof.
 *
 * The vector: a real `lzop -1` archive (generated via stdin, so the header
 * carries no embedded filename) of the 52-byte line below repeated 20
 * times (1040 bytes plain, 135 archived) -- generated once by
 * port/test/decompress_unlzo/'s corpus and pasted here; correctness across
 * that differential's plaintext/level/mode matrix is its job, not this
 * one's.
 */
static const u8 lt_unlzo_arc[] = {
	0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a, 0x10, 0x40, 0x20,
	0xa0, 0x09, 0x40, 0x02, 0x01, 0x03, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x81,
	0xa4, 0x6a, 0x9c, 0xdd, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x95,
	0x04, 0xee, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x51, 0xb7, 0x6e,
	0x8a, 0x70, 0x00, 0x22, 0x52, 0x75, 0x73, 0x74, 0x79, 0x20, 0x4c, 0x69,
	0x6e, 0x75, 0x78, 0x20, 0x6c, 0x69, 0x62, 0x2f, 0x64, 0x65, 0x63, 0x6f,
	0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x75, 0x6e, 0x6c, 0x7a, 0x6f,
	0x20, 0x73, 0x65, 0x6c, 0x66, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x20, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x20, 0x20, 0x00, 0x00, 0x00,
	0xae, 0xcc, 0x00, 0x0d, 0x66, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x20, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x20, 0x11, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
};

static void __init lt_unlzo_error(char *msg)
{
	pr_err("libtest: unlzo: %s\n", msg);
}

static void __init test_unlzo(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_unlzo self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_unlzo_arc, sizeof(lt_unlzo_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "unlzo test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = unlzo(arc, sizeof(lt_unlzo_arc), NULL, NULL, got, NULL, lt_unlzo_error);
	check(rc == 0, "unlzo returns success on a valid archive");
	check(memcmp(got, want, plain_len) == 0, "unlzo reproduced the plaintext");

	/*
	 * A truncated archive must be refused, not decoded as garbage.
	 * Unlike unlz4's wrapper, this one DOES check a block's declared
	 * length against what's actually left in the buffer before calling
	 * lzo1x_decompress_safe (decompress_unlzo.c: `if (in_len < src_len)
	 * ... goto exit_2`) -- an earlier version of this comment claimed
	 * otherwise, copied from unlz4's without rechecking it against this
	 * file, and adversarial review caught it. Safe here.
	 */
	{
		unsigned int half = sizeof(lt_unlzo_arc) / 2;
		u8 *arc2 = kmemdup(lt_unlzo_arc, half, GFP_KERNEL);

		if (arc2) {
			memset(got, 0, plain_len + 65536);
			rc = unlzo(arc2, half, NULL, NULL, got, NULL, lt_unlzo_error);
			check(rc != 0, "unlzo rejects a truncated archive");
			kfree(arc2);
		} else {
			check(false, "unlzo truncated-archive test could not allocate");
		}
	}
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_unlzo(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_XZ)
#include <linux/decompress/unxz.h>

/*
 * lib/decompress_unxz.c's own substance is picking single-call vs
 * multi-call mode and shuttling bytes through fill()/flush() -- the .xz
 * container format itself is entirely xz_dec_run()'s job, already covered
 * by lib/xz/'s own tests. This project's initramfs is gzip (see
 * rig/boot.sh), so CONFIG_RD_XZ=y compiles this in but the real boot path
 * never calls it -- SCOPE.md class A, same as bunzip2/unlz4/unlzo above.
 * This is its only proof.
 *
 * The vector: a real `xz -6 --check=crc32` stream (our kernels build
 * XZ_DEC_ANY_CHECK=n, which rejects any check type above CRC32 -- xz's own
 * default is CRC64) of the 51-byte line below repeated 20 times (1020
 * bytes plain, 132 archived) -- generated once by
 * port/test/decompress_unxz/'s corpus and pasted here; correctness across
 * that differential's plaintext/level/mode matrix is its job, not this
 * one's.
 */
static const u8 lt_unxz_arc[] = {
	0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36,
	0x04, 0xc0, 0x46, 0xfc, 0x07, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x66, 0x39, 0x3b, 0x86, 0xe0, 0x03, 0xfb, 0x00,
	0x3e, 0x5d, 0x00, 0x29, 0x1d, 0x4a, 0x67, 0x70, 0x15, 0xb7, 0xd5, 0x97,
	0xaf, 0xf2, 0x81, 0x34, 0xd6, 0xb2, 0x8f, 0x53, 0xd9, 0xc8, 0x03, 0x59,
	0xa2, 0x66, 0xf3, 0xd6, 0xe0, 0xd0, 0x1b, 0xa6, 0x45, 0x66, 0xef, 0x45,
	0xf1, 0x61, 0xd2, 0x0f, 0x06, 0xd3, 0x75, 0x25, 0x4d, 0x3c, 0xce, 0xb0,
	0xc9, 0xad, 0x98, 0xbb, 0xc5, 0xaa, 0xee, 0xf7, 0xf0, 0x6d, 0xc1, 0x82,
	0xcd, 0x70, 0xb4, 0xef, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x79, 0x95, 0x8a,
	0x00, 0x01, 0x5e, 0xfc, 0x07, 0x00, 0x00, 0x00, 0xbf, 0x38, 0xc2, 0xe5,
	0x3e, 0x30, 0x0d, 0x8b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
};

static void __init lt_unxz_error(char *msg)
{
	pr_err("libtest: unxz: %s\n", msg);
}

static void __init test_unxz(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_unxz self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_unxz_arc, sizeof(lt_unxz_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "unxz test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = unxz(arc, sizeof(lt_unxz_arc), NULL, NULL, got, NULL, lt_unxz_error);
	check(rc == 0, "unxz returns success on a valid stream");
	check(memcmp(got, want, plain_len) == 0, "unxz reproduced the plaintext");

	/*
	 * A truncated stream must be refused, not decoded as garbage.
	 *
	 * Recorded correction, found by adversarial review: an earlier
	 * version of this comment claimed this is safe because "xz_dec_run()
	 * owns all length/buffer trust" -- false in general. In single-call
	 * mode (fill == NULL && flush == NULL, exactly this call) unxz() sets
	 * b.out_size = usize::MAX, so xz_dec_run() enforces NO output bound
	 * at all; `got`'s real size is all that protects it, same as
	 * unlz4/unlzo's callers must size their own buffer. What actually
	 * makes truncating this specific vector safe: xz_dec_run() only ever
	 * writes as many bytes as it has genuinely decoded, and truncating
	 * the input at exactly half does not touch any of the length fields
	 * (block header's compressed/uncompressed sizes, the one LZMA2
	 * chunk's own length) -- all of which sit before the truncation
	 * point -- so decoding just runs out of INPUT and reports an error
	 * via the properly-enforced b.in_pos/b.in_size bound, never
	 * over-producing output past what it has actually decoded.
	 */
	{
		unsigned int half = sizeof(lt_unxz_arc) / 2;
		u8 *arc2 = kmemdup(lt_unxz_arc, half, GFP_KERNEL);

		if (arc2) {
			memset(got, 0, plain_len + 65536);
			rc = unxz(arc2, half, NULL, NULL, got, NULL, lt_unxz_error);
			check(rc != 0, "unxz rejects a truncated stream");
			kfree(arc2);
		} else {
			check(false, "unxz truncated-stream test could not allocate");
		}
	}
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_unxz(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_ZSTD)
#include <linux/decompress/unzstd.h>

/*
 * lib/decompress_unzstd.c's own substance is picking single-call vs
 * multi-call mode, tracking the frame's window size, and shuttling bytes
 * through fill()/flush() -- the .zst container format itself is entirely
 * the real zstd_* API's job (lib/zstd/, currently C behind those symbols,
 * see decompress_unzstd_rs.rs's module doc). This project's initramfs is
 * gzip (see rig/boot.sh), so CONFIG_RD_ZSTD=y compiles this in but the
 * real boot path never calls it -- SCOPE.md class A, same as
 * bunzip2/unlz4/unlzo/unxz above. This is its only proof.
 *
 * The vector: a real `zstd -19` stream (73 bytes archived) of the 53-byte
 * line below repeated 20 times (1060 bytes plain) -- generated once by
 * port/test/decompress_unzstd/'s corpus and pasted here; correctness
 * across that differential's plaintext/level/mode matrix is its job, not
 * this one's.
 */
static const u8 lt_unzstd_arc[] = {
	0x28, 0xb5, 0x2f, 0xfd, 0x64, 0x24, 0x03, 0xdd, 0x01, 0x00, 0x52, 0x43,
	0x0c, 0x11, 0xa0, 0x3d, 0x76, 0x0a, 0x7c, 0x8d, 0xe1, 0x94, 0x70, 0xc2,
	0xdf, 0x3f, 0x30, 0x8c, 0xaa, 0x53, 0x03, 0x1a, 0xd6, 0xb4, 0x96, 0xc6,
	0xe9, 0x3b, 0x3f, 0x48, 0xcd, 0xae, 0xfb, 0x3e, 0x19, 0x2c, 0xee, 0xfc,
	0xdc, 0x6a, 0x88, 0x57, 0x1c, 0xd5, 0x1a, 0x21, 0x53, 0x43, 0xe5, 0x3b,
	0x24, 0x01, 0x01, 0x00, 0xc5, 0x1e, 0x57, 0x0a, 0x0a, 0xa8, 0x3a, 0xc9,
	0x29,
};

static void __init lt_unzstd_error(char *msg)
{
	pr_err("libtest: unzstd: %s\n", msg);
}

static void __init test_unzstd(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_unzstd self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_unzstd_arc, sizeof(lt_unzstd_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "unzstd test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = unzstd(arc, sizeof(lt_unzstd_arc), NULL, NULL, got, NULL, lt_unzstd_error);
	check(rc == 0, "unzstd returns success on a valid stream");
	check(memcmp(got, want, plain_len) == 0, "unzstd reproduced the plaintext");

	/*
	 * A truncated stream must be refused, not decoded as garbage --
	 * VERIFIED, not assumed (the reasoning that would apply by analogy
	 * to unxz's truncation test turned out to need its own check: unxz's
	 * safety there comes from xz_dec_run() running out of INPUT because
	 * no length field sits after the truncation point; zstd's frame
	 * format is different enough -- decompress_single(), the buffer-mode
	 * path this call takes, does not call the streaming decoder at all).
	 *
	 * What actually makes it safe here: decompress_single()'s first
	 * step is `zstd_find_frame_compressed_size(in_buf, in_len)`, which
	 * has to walk every block in the frame to compute the frame's true
	 * total size -- a truncated input cannot contain a complete block
	 * sequence, so this call itself fails with an error and
	 * zstd_decompress_dctx() (the call that would actually write to
	 * `got`) is never reached. Confirmed empirically, not just reasoned
	 * about: a byte-by-byte truncation sweep of a real archive from 1
	 * byte short of complete down to 1 byte long, through this exact
	 * unzstd() call, rejected every single truncation and produced no
	 * observable output on any of them.
	 */
	{
		unsigned int half = sizeof(lt_unzstd_arc) / 2;
		u8 *arc2 = kmemdup(lt_unzstd_arc, half, GFP_KERNEL);

		if (arc2) {
			memset(got, 0, plain_len + 65536);
			rc = unzstd(arc2, half, NULL, NULL, got, NULL, lt_unzstd_error);
			check(rc != 0, "unzstd rejects a truncated stream");
			kfree(arc2);
		} else {
			check(false, "unzstd truncated-stream test could not allocate");
		}
	}
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_unzstd(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_GZIP)
#include <linux/decompress/inflate.h>

/*
 * Unlike the other five files in this decompressor family, gunzip() is
 * NOT class A: this project's initramfs really is gzip (rig/boot.sh), so
 * every boot already exercises gunzip() in fill/flush (streaming) mode --
 * see decompress_inflate_rs.rs's module doc. This test covers BUFFER mode
 * instead (fill=flush=NULL), which no real caller in this tree uses, for
 * the complementary reason every other file's libtest exists: real boot
 * traffic and this self-test now cover the two different call shapes
 * between them, neither alone.
 *
 * The vector: a real `gzip -9 -n` stream (84 bytes archived) of the
 * 55-byte line below repeated 20 times (1100 bytes plain) -- `-n` so the
 * header stays a fixed 10 bytes (no stored filename/mtime).
 */
static const u8 lt_gunzip_arc[] = {
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x0b, 0x2a,
	0x2d, 0x2e, 0xa9, 0x54, 0xf0, 0xc9, 0xcc, 0x2b, 0xad, 0x50, 0xc8, 0xc9,
	0x4c, 0xd2, 0x4f, 0x49, 0x4d, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d, 0x2e,
	0x8e, 0xcf, 0xcc, 0x4b, 0xcb, 0x49, 0x2c, 0x49, 0x55, 0x28, 0x4e, 0xcd,
	0x49, 0xd3, 0x2d, 0x49, 0x2d, 0x2e, 0x51, 0x28, 0x48, 0xac, 0xcc, 0xc9,
	0x4f, 0x4c, 0xd1, 0x53, 0x08, 0x1a, 0xd5, 0x35, 0xaa, 0x6b, 0x54, 0xd7,
	0x08, 0xd6, 0x05, 0x00, 0xc5, 0x9d, 0x02, 0xf2, 0x38, 0x04, 0x00, 0x00,
};

static void __init lt_gunzip_error(char *msg)
{
	pr_err("libtest: gunzip: %s\n", msg);
}

static void __init test_gunzip(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_inflate self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_gunzip_arc, sizeof(lt_gunzip_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "gunzip test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = gunzip(arc, sizeof(lt_gunzip_arc), NULL, NULL, got, NULL, lt_gunzip_error);
	check(rc == 0, "gunzip returns success on a valid stream");
	check(memcmp(got, want, plain_len) == 0, "gunzip reproduced the plaintext");

	/*
	 * A stream truncated at HALF must be refused. VERIFIED, not assumed
	 * by analogy to this file family's other truncation tests: measured
	 * with a byte-by-byte truncation sweep (a throwaway harness outside
	 * this file) that __gunzip() actually accepts truncations of up to
	 * 8 bytes short (this vector is 84 bytes; truncations down to 76
	 * still return success) -- because __gunzip() never validates the
	 * gzip trailer (4-byte CRC32 + 4-byte ISIZE) it skips over, and the
	 * DEFLATE stream itself signals its own end (the final-block bit)
	 * independently of that trailer. Truncating at HALF (42 of 84
	 * bytes) cuts well into the real compressed data, past where that
	 * "just missing the trailer" tolerance applies, and the same sweep
	 * confirmed rejection (via nofill()'s -1, "read error") holds for
	 * every truncation from 75 bytes down to 12.
	 */
	{
		unsigned int half = sizeof(lt_gunzip_arc) / 2;
		u8 *arc2 = kmemdup(lt_gunzip_arc, half, GFP_KERNEL);

		if (arc2) {
			memset(got, 0, plain_len + 65536);
			rc = gunzip(arc2, half, NULL, NULL, got, NULL, lt_gunzip_error);
			check(rc != 0, "gunzip rejects a truncated stream");
			kfree(arc2);
		} else {
			check(false, "gunzip truncated-stream test could not allocate");
		}
	}
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_gunzip(void) { }
#endif

#if IS_ENABLED(CONFIG_DECOMPRESS_LZMA)
#include <linux/decompress/unlzma.h>

/*
 * lib/decompress_unlzma.c's own substance is the LZMA range-coder
 * algorithm itself, entirely self-contained in that one file (see
 * decompress_unlzma_rs.rs's module doc for why the file stays pristine
 * even though this port replaces its logic). This project's initramfs is
 * gzip (see rig/boot.sh), so CONFIG_RD_LZMA=y compiles this in but the
 * real boot path never calls it -- SCOPE.md class A, same as the other
 * five decompressors in this family that aren't the boot format. This is
 * its only proof.
 *
 * The vector: a real `xz -F lzma -6` stream (83 bytes archived) of the
 * 53-byte line below repeated 20 times (1060 bytes plain) -- the legacy
 * "lzma_alone" format's 13-byte header (1-byte properties, 4-byte
 * little-endian dict size, 8-byte little-endian uncompressed size, here
 * the 0xFFFFFFFFFFFFFFFF "unknown" sentinel since this CLI doesn't know
 * the size upfront) is exactly what struct lzma_header expects.
 */
static const u8 lt_unlzma_arc[] = {
	0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x29, 0x1d, 0x4a, 0x67, 0x70, 0x15, 0xb7, 0xd5, 0x97, 0xaf,
	0xf2, 0x81, 0x34, 0xd6, 0xb2, 0x8f, 0x53, 0xd9, 0xc8, 0x03, 0x59, 0xa2,
	0x66, 0xf3, 0xd6, 0xe0, 0xd0, 0x1b, 0xa6, 0x45, 0x44, 0xcc, 0xaf, 0x1b,
	0xf5, 0xf1, 0xe4, 0x4b, 0x78, 0xb7, 0x39, 0x7d, 0xdb, 0xc8, 0xeb, 0xa2,
	0xf5, 0x53, 0x8f, 0x0d, 0xe5, 0x2c, 0x4a, 0x2e, 0x50, 0x45, 0xa0, 0x51,
	0x3e, 0x5a, 0x0c, 0x43, 0x9f, 0xff, 0xff, 0xae, 0x02, 0x00, 0x00,
};

static void __init lt_unlzma_error(char *msg)
{
	pr_err("libtest: unlzma: %s\n", msg);
}

static void __init test_unlzma(void)
{
	static const char unit[] = "Rusty Linux lib/decompress_unlzma self-test payload. ";
	const unsigned int unit_len = sizeof(unit) - 1;
	const unsigned int reps = 20;
	const unsigned int plain_len = unit_len * reps;
	u8 *want, *got, *arc;
	unsigned int i;
	int rc;

	want = kmalloc(plain_len, GFP_KERNEL);
	got = kmalloc(plain_len + 65536, GFP_KERNEL);
	arc = kmemdup(lt_unlzma_arc, sizeof(lt_unlzma_arc), GFP_KERNEL);
	if (!want || !got || !arc) {
		check(false, "unlzma test could not allocate");
		goto out;
	}
	for (i = 0; i < reps; i++)
		memcpy(want + i * unit_len, unit, unit_len);
	memset(got, 0, plain_len + 65536);

	rc = unlzma(arc, sizeof(lt_unlzma_arc), NULL, NULL, got, NULL, lt_unlzma_error);
	check(rc == 0, "unlzma returns success on a valid stream");
	check(memcmp(got, want, plain_len) == 0, "unlzma reproduced the plaintext");

	/*
	 * A stream truncated at HALF must be refused. VERIFIED, not assumed:
	 * measured with a byte-by-byte truncation sweep (a throwaway harness
	 * outside this file) that unlzma() tolerates truncations of up to 3
	 * bytes short (this vector is 83 bytes; truncations down to 80 still
	 * return success) -- the range coder's end-of-stream signal
	 * (`cst.rep0 == 0`, decoded from the compressed bit stream itself)
	 * can be reached slightly before the encoder's own trailing
	 * flush/padding bytes are consumed, the same shape as gunzip's
	 * 8-byte gzip-trailer tolerance for a different reason. Truncating
	 * at HALF (41 of 83 bytes) cuts well past that tolerance, into the
	 * real compressed data, and the same sweep confirmed rejection
	 * (nofill()'s -1, propagated as "unexpected EOF" -> the range
	 * coder's own error() call) holds for every truncation from 79
	 * bytes down to 1.
	 */
	{
		unsigned int half = sizeof(lt_unlzma_arc) / 2;
		u8 *arc2 = kmemdup(lt_unlzma_arc, half, GFP_KERNEL);

		if (arc2) {
			memset(got, 0, plain_len + 65536);
			rc = unlzma(arc2, half, NULL, NULL, got, NULL, lt_unlzma_error);
			check(rc != 0, "unlzma rejects a truncated stream");
			kfree(arc2);
		} else {
			check(false, "unlzma truncated-stream test could not allocate");
		}
	}
out:
	kfree(arc);
	kfree(got);
	kfree(want);
}
#else
static void __init test_unlzma(void) { }
#endif

static int __init libtest_init(void)
{
	test_base64();
	test_memweight();
	test_mac_pton();
	test_union_find();
	test_bcd();
	test_crc16();
	test_win_minmax();
	test_sort();
	test_bsearch();
	test_find_bit();
	test_list_sort();
	test_xxhash();
	test_earlycpio();
	test_plist();
	test_crc_ccitt();
	test_crc32();
	test_arc4();
	test_clz_ctz();
	test_chacha();
	test_md5();
	test_hmac_md5();
	test_crypto_xor();
	test_memneq();
	test_sha512();
	test_sha1();
	test_aes();
	test_errname();
	test_dql();
	test_ratelimit();
	test_flex_proportions();
	test_buildid();
	test_seq_buf();
	test_iomap();
	test_bug();
	test_asn1_decoder();
	test_interval_tree();
	test_bitrev();
	test_uuid();
	test_ctype();
	test_hexdump();
	test_cmdline();
	test_llist();
	test_debug_locks();
	test_iomap_copy();
	test_errseq();
	test_ucs2();
	test_check_signature();
	test_mpih();
	test_mpi_add();
	test_mpi_sub_ui();
	test_mpi_mul();
	test_mpi_powm();
	test_mpi_bit();
	test_mpicoder();
	test_zlib_inflate();
	test_lzo();
	test_xz();
	test_lz4();
	test_zstd();
	test_bunzip2();
	test_unlz4();
	test_unlzo();
	test_unxz();
	test_unzstd();
	test_gunzip();
	test_unlzma();

	pr_info("libtest: %u self-tests passed, %u failed\n", passed, failed);

	/* Same convention as lib/globtest.c: refuse to load on mismatch. */
	return failed ? -ECANCELED : 0;
}

static void __exit libtest_exit(void) { }

module_init(libtest_init);
module_exit(libtest_exit);

MODULE_DESCRIPTION("lib/ self-test for the Rust port");
MODULE_LICENSE("GPL");
