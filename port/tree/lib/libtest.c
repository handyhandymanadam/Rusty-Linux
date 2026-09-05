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
#include <linux/bsearch.h>
#include <linux/bcd.h>
#include <linux/bitrev.h>
#include <linux/uuid.h>
#include <linux/ctype.h>
#include <linux/llist.h>
#include <linux/debug_locks.h>
#include <linux/io.h>
#include <linux/errseq.h>
#include <crypto/arc4.h>
#include <crypto/chacha.h>
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
#else
static void __init test_mpih(void) { }
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
	test_list_sort();
	test_xxhash();
	test_earlycpio();
	test_plist();
	test_crc_ccitt();
	test_arc4();
	test_clz_ctz();
	test_chacha();
	test_crypto_xor();
	test_memneq();
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
	test_zlib_inflate();
	test_lzo();
	test_xz();
	test_lz4();
	test_zstd();

	pr_info("libtest: %u self-tests passed, %u failed\n", passed, failed);

	/* Same convention as lib/globtest.c: refuse to load on mismatch. */
	return failed ? -ECANCELED : 0;
}

static void __exit libtest_exit(void) { }

module_init(libtest_init);
module_exit(libtest_exit);

MODULE_DESCRIPTION("lib/ self-test for the Rust port");
MODULE_LICENSE("GPL");
