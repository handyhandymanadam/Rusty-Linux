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
#include <linux/notifier.h>
#include <linux/user_namespace.h>
#include <linux/highuid.h>
#include <linux/ratelimit.h>
#include <linux/flex_proportions.h>
#include <linux/interval_tree.h>
#include <linux/asn1_decoder.h>
#include <linux/asn1_ber_bytecode.h>
#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/internal/hash.h>
#include <crypto/sha3.h>
#include <crypto/acompress.h>
#include <linux/scatterlist.h>
#include <linux/rhashtable.h>
#include <linux/rcuref.h>
#include <linux/stackdepot.h>
#include <linux/sbitmap.h>
#include <linux/refcount.h>
#include <linux/lwq.h>
#include <linux/idr.h>
#include <linux/klist.h>
#include <linux/kobject.h>
#include <linux/logic_pio.h>
#include <linux/cpu_rmap.h>
#include <linux/radix-tree.h>
#include <linux/percpu-refcount.h>
#include <linux/bch.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/nls.h>
#ifdef CONFIG_X86
#include <asm/misc.h>
#include <asm/cmdline.h>
#include <asm/cpu.h>
#include <asm/insn.h>
#include <linux/time.h>
#include <linux/range.h>
#include <linux/timecounter.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/sysctl.h>
#include <linux/kallsyms.h>
#include <linux/fs_types.h>
#include <linux/stat.h>
#include <linux/inet.h>
#include <linux/cred.h>
#include <linux/parser.h>
#include <linux/prandom.h>
#include <linux/jiffies.h>
#include <linux/lockref.h>
#include <linux/kfifo.h>
#include <linux/genalloc.h>
#include <linux/maple_tree.h>
#include <linux/group_cpus.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/cpumask.h>
#include <net/netlink.h>
#include <asm/checksum.h>
#endif
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
#include <linux/vmalloc.h>
#include <linux/xxhash.h>
#include <linux/xz.h>
#include <linux/win_minmax.h>
#include <linux/zlib.h>
#include <linux/font.h>

/* lib/clz_ctz.c. These have no header -- the compiler knows them by name
 * and nothing in the kernel declares them. */
int __ctzsi2(int val);
int __clzsi2(int val);
int __clzdi2(u64 val);
int __ctzdi2(u64 val);

#if IS_BUILTIN(CONFIG_MPILIB) /* not IS_ENABLED: libtest is built-in, this can be =m (riscv defconfig) */
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

#if IS_BUILTIN(CONFIG_CRYPTO_LIB_MD5)	/* not IS_ENABLED: libtest is built-in, libmd5 can be =m (arm64 defconfig) */
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
static bool __init hmac_hash_builtin(const char *vec)
{
	return (!strcmp(vec, "hmac(md5)") && IS_BUILTIN(CONFIG_CRYPTO_MD5)) ||
	       (!strcmp(vec, "hmac(sha1)") && IS_BUILTIN(CONFIG_CRYPTO_SHA1)) ||
	       ((!strcmp(vec, "hmac(sha224)") || !strcmp(vec, "hmac(sha256)")) && IS_BUILTIN(CONFIG_CRYPTO_SHA256)) ||
	       ((!strcmp(vec, "hmac(sha384)") || !strcmp(vec, "hmac(sha512)")) && IS_BUILTIN(CONFIG_CRYPTO_SHA512)) ||
	       (!strncmp(vec, "hmac(sha3-", 10) && IS_BUILTIN(CONFIG_CRYPTO_SHA3));
}

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

#if IS_BUILTIN(CONFIG_CRYPTO_LIB_SHA512) /* not IS_ENABLED: libtest is built-in, this can be =m (riscv defconfig) */
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

#if IS_BUILTIN(CONFIG_CRYPTO_LIB_AES) /* not IS_ENABLED: libtest is built-in, this can be =m (riscv defconfig) */
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
	struct ratelimit_state rs;

	/* Not RATELIMIT_STATE_INIT(): that is for statics; on the stack its lock has no lockdep key and a
	 * PROVE_LOCKING kernel reports "trying to register non-static key" and turns lockdep OFF
	 * (found by the concurrency checker build, logs/concurrency-tooling.md). */
	ratelimit_state_init(&rs, 60 * HZ, 3);

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
#ifdef CONFIG_GENERIC_IOMAP	/* x86 sets it; arm64 does not, and has no __iowrite64_lo_hi etc. */
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
#endif /* CONFIG_GENERIC_IOMAP */

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

#if IS_BUILTIN(CONFIG_ASN1) /* not IS_ENABLED: libtest is built-in, this can be =m (riscv defconfig) */
/*
 * lib/asn1_decoder.c -> asn1_decoder_rs.rs. CONFIG_ASN1 is config-full
 * only.
 *
 * CORRECTED 2026-09-06 (panic-triage Group 2): this comment used to
 * claim asn1_ber_decoder() is "genuinely class A" here, reasoning only
 * from CONFIG_SYSTEM_TRUSTED_KEYS being empty and no module signature
 * to check. That reasoning missed a THIRD real caller this project
 * hadn't traced yet: net/wireless/reg.c's regulatory_init_db(), a
 * late_initcall unconditional whenever CONFIG_CFG80211=y specifically
 * -- built in, not =m (reg.c's late_initcall(regulatory_init_db) is
 * inside #ifndef MODULE; at =m the same call instead happens from
 * regulatory_init()'s #ifdef MODULE arm, only when cfg80211.ko actually
 * loads) -- true on config-full, and CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y +
 * CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y (both set here). It calls
 * load_builtin_regdb_keys() -> x509_load_certificate_list() with REAL
 * embedded certificate data (shipped_regdb_certs).
 *
 * CORRECTED AGAIN 2026-09-06 (adversarial review, same day): attribution,
 * not reachability. The three sabotage-and-reboot crashes below only
 * prove an X.509 parse happens somewhere at boot -- they do NOT
 * distinguish this caller from certs/system_keyring.c's own
 * load_system_certificate_list(), ALSO a late_initcall calling
 * x509_load_certificate_list() through the same three functions, and by
 * link order (certs/ before net/) it runs first. The actual
 * discriminator is dmesg line ordering: "Loading compiled-in X.509
 * certificates" (system_keyring.c, no "Loaded X.509 cert" line after --
 * its list is empty) precedes "cfg80211: Loading compiled-in X.509
 * certificates for regulatory database" followed by two real "Loaded
 * X.509 cert 'sforshee: ...'"/"'wens: ...'" lines -- before the later
 * "Direct firmware load for regulatory.db failed" (there is no
 * regulatory.db present to verify a signature against, so the
 * signature-VERIFICATION arithmetic, e.g. mpi_powm, is likely still not
 * reached -- only the DER-parsing chain: asn1_ber_decoder, look_up_OID,
 * mpi_read_raw_data for public-key construction). This attribution is
 * FRAGILE, not structural: it holds only because the compiled-in
 * trusted-keyring list happens to be empty on this config (no
 * CONFIG_MODULE_SIG key, no CONFIG_SYSTEM_TRUSTED_KEYS content) -- turn
 * module signing on with a real key and the same three sabotage crashes
 * fire identically while attribution silently flips to the system
 * keyring instead. So this chain is class B on config-full, not class A
 * (sabotage below now stands only as corroboration that the symbols are
 * reachable, not as attribution evidence) -- and CONFIG_ASN1 being off
 * on config-fast is itself a CONSEQUENCE, not an independent reason:
 * CFG80211_REQUIRE_SIGNED_REGDB's default y selects
 * SYSTEM_DATA_VERIFICATION (net/wireless/Kconfig), which pulls in
 * X509_CERTIFICATE_PARSER/ASN1 -- a select can't be declined -- so
 * CONFIG_CFG80211 being off on config-fast is what actually excludes
 * this chain there. Confirmed empirically either way
 * (`rig/uaccess-panic-check.sh build-fast` finds no asn1_decoder_rs.o,
 * oid_registry_rs.o, or any crypto mpi Rust object to even scan). The proof
 * caller below still earns its keep on config-full, where the code IS
 * built and this comment's own history is the reason why: an earlier
 * session's class-A claim here was wrong, and a real caller is what
 * caught it.
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

#if IS_BUILTIN(CONFIG_MPILIB) /* not IS_ENABLED: libtest is built-in, this can be =m (riscv defconfig) */
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

/* lib/zlib_deflate/deflate_rs.rs (the compressor) and, through it, deftree_rs.rs.
 *
 * Two kinds of check. The first is worked on paper: "abc" at level 0 is a
 * zlib header (78 da -- this kernel derives the level bits from (level-1)>>1
 * as an unsigned number, so level 0 gives 3, unlike zlib's 78 01), one final
 * stored block (01, LEN 0003, NLEN fffc, the three bytes) and the big-endian
 * Adler-32 of "abc" (s1 = 1+97+98+99 = 295 = 0x127, s2 = 98+196+295 = 589 =
 * 0x24d). The second is a round trip through the Rust inflater: eight
 * parameter sets (stored, fast, lazy, filtered, Huffman-only, raw, windows
 * from 512 bytes to 32 KiB) over 45000 bytes with repeats at every distance up
 * to 256, fed in 777-byte pieces and drained into 61-byte pieces, so the
 * window slide, the hash rebase and every "output full, call me again" return
 * is taken. Exact byte-for-byte equality with the C compressor is
 * port/test/deflate/'s job.
 */
#if IS_ENABLED(CONFIG_ZLIB_DEFLATE) && IS_ENABLED(CONFIG_ZLIB_INFLATE)
#define LT_ZD_N 45000
static void lt_zd_gen(u8 *p, unsigned int n)
{
	u32 x = 12345;
	unsigned int i;

	for (i = 0; i < n; i++) {
		x = x * 1103515245u + 12345u;
		if (i > 300 && ((x >> 16) % 5) == 0)
			p[i] = p[i - 1 - ((x >> 8) & 255)];
		else
			p[i] = 'a' + ((x >> 20) % 7);
	}
}

/* Compress @in (@n bytes) with the given parameters; returns the compressed length or -1. */
static int __init lt_zd_run(const u8 *in, unsigned int n, u8 *out, unsigned int outmax,
			    int level, int wbits, int memlevel, int strategy)
{
	struct z_stream_s *strm = kzalloc(sizeof(*strm), GFP_KERNEL);
	void *ws = vzalloc(zlib_deflate_workspacesize(wbits, memlevel));
	unsigned int ipos = 0, opos = 0;
	int rc, ret = -1;

	if (!strm || !ws)
		goto out;
	strm->workspace = ws;
	if (zlib_deflateInit2(strm, level, Z_DEFLATED, wbits, memlevel, strategy) != Z_OK)
		goto out;
	for (;;) {
		int flush;

		if (strm->avail_in == 0 && ipos < n) {
			unsigned int k = min(n - ipos, 777u);

			strm->next_in = in + ipos;
			strm->avail_in = k;
			ipos += k;
		}
		if (strm->avail_out == 0) {
			unsigned int k = min(outmax - opos, 61u);

			if (k == 0)
				break;
			strm->next_out = out + opos;
			strm->avail_out = k;
			opos += k;
		}
		flush = (ipos == n && strm->avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;
		rc = zlib_deflate(strm, flush);
		if (rc == Z_STREAM_END) {
			ret = strm->total_out;
			break;
		}
		if (rc != Z_OK && rc != Z_BUF_ERROR)
			break;
	}
	zlib_deflateEnd(strm);
out:
	vfree(ws);
	kfree(strm);
	return ret;
}

static void __init test_zlib_deflate(void)
{
	static const struct { int level, wbits, memlevel, strategy; } cfg[] = {
		{ 0, 15, 8, 0 }, { 1, 15, 8, 0 }, { 3, -15, 8, 0 }, { 6, 15, 8, 0 },
		{ 6, 12, 1, Z_FILTERED }, { 9, 15, 8, 0 }, { 6, 15, 8, Z_HUFFMAN_ONLY }, { 4, 9, 1, 0 },
	};
	static const u8 abc_stored[] = { 0x78, 0xda, 0x01, 0x03, 0x00, 0xfc, 0xff, 'a', 'b', 'c', 0x02, 0x4d, 0x01, 0x27 };
	u8 *in = kmalloc(LT_ZD_N, GFP_KERNEL), *comp = kmalloc(2 * LT_ZD_N, GFP_KERNEL);
	u8 *back = kmalloc(LT_ZD_N, GFP_KERNEL);
	struct z_stream_s *is = kzalloc(sizeof(*is), GFP_KERNEL);
	void *iws = kzalloc(zlib_inflate_workspacesize(), GFP_KERNEL);
	unsigned int c;
	int n;

	if (!in || !comp || !back || !is || !iws) {
		check(false, "zlib_deflate test could not allocate");
		goto out;
	}

	n = lt_zd_run("abc", 3, comp, 64, 0, 15, 8, 0);
	check(n == sizeof(abc_stored) && memcmp(comp, abc_stored, sizeof(abc_stored)) == 0,
	      "zlib_deflate level 0 \"abc\" is the stored-block stream worked out by hand");

	lt_zd_gen(in, LT_ZD_N);
	for (c = 0; c < ARRAY_SIZE(cfg); c++) {
		int clen = lt_zd_run(in, LT_ZD_N, comp, 2 * LT_ZD_N, cfg[c].level, cfg[c].wbits,
				     cfg[c].memlevel, cfg[c].strategy);
		int rc;

		check(clen > 0, "zlib_deflate finished the stream");
		if (clen <= 0)
			continue;
		if (cfg[c].level >= 1 && cfg[c].strategy != Z_HUFFMAN_ONLY)
			check(clen < LT_ZD_N * 3 / 4, "zlib_deflate compressed the repetitive input");
		memset(is, 0, sizeof(*is));
		memset(back, 0, LT_ZD_N);
		is->workspace = iws;
		is->next_in = comp;
		is->avail_in = clen;
		is->next_out = back;
		is->avail_out = LT_ZD_N;
		rc = zlib_inflateInit2(is, cfg[c].wbits);
		if (rc == Z_OK) {
			rc = zlib_inflate(is, Z_FINISH);
			zlib_inflateEnd(is);
		}
		check(rc == Z_STREAM_END && is->total_out == LT_ZD_N && memcmp(back, in, LT_ZD_N) == 0,
		      "zlib_deflate output inflates back to the input");
	}
out:
	kfree(iws);
	kfree(is);
	kfree(back);
	kfree(comp);
	kfree(in);
}
#else
static void __init test_zlib_deflate(void) { }
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

/* Output sink for the truncated-stream case: discards what bunzip2() hands it. */
static long __init lt_bz2_discard(void *buf, unsigned long len)
{
	return len;
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
#ifdef CONFIG_KASAN
		/*
		 * The upstream over-read (upstream/bunzip2-eof-overread, parked) is a 1-byte read past the end of the
		 * input, which a KASAN kernel reports on an exact-size allocation (found by the concurrency checker
		 * build: BUG: KASAN slab-out-of-bounds in get_next_block). Slack here keeps the test, and the known
		 * defect stays recorded where it is; every other KASAN report still fails the boot.
		 */
		u8 *comp2 = kzalloc(half + 64, GFP_KERNEL);

		if (comp2)
			memcpy(comp2, lt_bz2_comp, half);
#else
		u8 *comp2 = kmemdup(lt_bz2_comp, half, GFP_KERNEL);
#endif

		if (comp2) {
			/*
			 * Output goes through a flush callback, NOT into `got`: on a truncated stream the
			 * decoder reads past the end of the input (upstream bug, upstream/bunzip2-eof-overread)
			 * and decodes whatever follows, so a caller-supplied unbounded output buffer gets
			 * overrun (slub_debug=FZPU showed kmalloc-2k corruption on ~half of boots, while this
			 * test still printed 'passed'). Real in-tree callers pass a flush callback too.
			 */
			rc = bunzip2(comp2, half, NULL, lt_bz2_discard, NULL, NULL, lt_bunzip2_error);
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

/*
 * lib/vsprintf.c's vsscanf()/sscanf() -> lib/vsprintf_scan_rs.rs. No
 * upstream self-test exists for this pair (unlike test_xarray.c/
 * test_hexdump.c), and every real in-tree call site found by survey
 * (kernel/workqueue.c, kernel/sched/core.c, kernel/cgroup/cgroup.c,
 * ...) is a sysfs-store callback, never reached by this project's
 * minimal boot -- so without a self-test here, criterion 5 ("the Rust
 * symbol is present in vmlinux and reached") would have nothing to
 * stand on for this file. Correctness is already settled by
 * port/test/vsprintf_scan/'s real-va_list differential (50,000+
 * cases, two seeds); this is deliberately few and small, chosen for
 * what the C/Rust round-trip split specifically risks: the va_arg-
 * consumption-count parity on every %[ failure path (see
 * vsprintf_scan_rs.rs's module doc), and field_width/qualifier state
 * not leaking between specifiers in the same call.
 */
static void __init test_vsscanf(void)
{
	int d, d2;
	unsigned int u;
	long l;
	long long ll;
	signed char hh;
	short h;
	size_t z;
	char cbuf[8], sbuf[16];
	int n;

	check(sscanf("42", "%d", &d) == 1 && d == 42, "sscanf %%d");
	check(sscanf("-7", "%d", &d) == 1 && d == -7, "sscanf %%d negative");
	check(sscanf("2a", "%x", &u) == 1 && u == 0x2a, "sscanf %%x");
	check(sscanf("017", "%o", &u) == 1 && u == 15, "sscanf %%o");
	check(sscanf("0x1f", "%i", &d) == 1 && d == 0x1f, "sscanf %%i auto-detects 0x");
	check(sscanf("099", "%i", &d) == 1 && d == 0, "sscanf %%i auto-detects octal (0, stops before '9')");
	check(sscanf("notanumber", "%d", &d) == 0, "sscanf %%d rejects non-numeric input");

	/* Narrow field width against a longer digit run -- the exact shape
	 * of upstream commit 900fdc457376 ("lib: vsprintf: Fix handling of
	 * number field widths in vsscanf"), found during this port's own
	 * research pass. */
	check(sscanf("123456", "%3d", &d) == 1 && d == 123,
	      "sscanf %%3d stops at the field width, not the end of the digit run");

	/* Multiple specifiers, DIFFERING widths: the first must not leak
	 * its field_width into the second (a real historical bug class:
	 * "forgot to reset field_width between specifiers"). */
	check(sscanf("123456", "%3d%d", &d, &d2) == 2 && d == 123 && d2 == 456,
	      "sscanf %%3d%%d: the second specifier is not narrowed by the first's width");

	/* Every qualifier, through its own differently-sized destination. */
	check(sscanf("-5", "%hhd", &hh) == 1 && hh == -5, "sscanf %%hhd");
	check(sscanf("-5", "%hd", &h) == 1 && h == -5, "sscanf %%hd");
	check(sscanf("-5", "%ld", &l) == 1 && l == -5, "sscanf %%ld");
	check(sscanf("-5", "%lld", &ll) == 1 && ll == -5, "sscanf %%lld");
	check(sscanf("5", "%zd", &z) == 1 && z == 5, "sscanf %%zd");

	check(sscanf("hello world", "%7c", cbuf) == 1 && !memcmp(cbuf, "hello w", 7),
	      "sscanf %%7c copies exactly 7 characters, no NUL");
	check(sscanf("hi", "%c", cbuf) == 1 && cbuf[0] == 'h',
	      "sscanf %%c with no width defaults to 1");

	memset(sbuf, 'Z', sizeof(sbuf));
	check(sscanf("  hello world", "%s", sbuf) == 1 && !strcmp(sbuf, "hello"),
	      "sscanf %%s skips leading whitespace and stops at the next");

	/* %[: a real match, a negated set, and the two documented failure
	 * shapes (no width, no match) -- each of which still consumes its
	 * va_arg slot upstream, checked here by confirming the NEXT
	 * argument still reads correctly rather than whatever garbage a
	 * missed va_arg would leave behind. */
	memset(sbuf, 'Z', sizeof(sbuf));
	check(sscanf("abcxyz", "%3[abc]", sbuf) == 1 && !strcmp(sbuf, "abc"),
	      "sscanf %%3[abc] matches a positive set");
	memset(sbuf, 'Z', sizeof(sbuf));
	check(sscanf("xyzabc", "%3[^abc]", sbuf) == 1 && !strcmp(sbuf, "xyz"),
	      "sscanf %%3[^abc] matches a negated set");

	/*
	 * Both of these `return num` immediately on the %[ failure --
	 * upstream stops the WHOLE scan, never attempting the trailing
	 * %%d at all -- so the real thing under test is that %[ still
	 * consumed sbuf's va_arg slot before failing (asserted directly,
	 * by having a SECOND call reuse the very next stack slot and
	 * confirming it comes back correct rather than reading whatever
	 * %[ left behind).
	 */
	d = -1;
	check(sscanf("abc", "%[abc]%d", sbuf, &d) == 0 && d == -1,
	      "sscanf %%[abc] with no field width returns 0 immediately (va_arg still consumed)");
	check(sscanf("7", "%d", &d) == 1 && d == 7,
	      "a normal %%d call right after correctly reads its own argument (va_arg count was not thrown off)");

	d = -1;
	check(sscanf("xyz", "%3[abc]%d", sbuf, &d) == 0 && d == -1,
	      "sscanf %%3[abc] with no matching first character also returns 0 immediately");
	check(sscanf("9", "%d", &d) == 1 && d == 9,
	      "and a normal %%d call right after is likewise unaffected");

	check(sscanf("42abc", "%d%n", &d, &n) == 1 && d == 42 && n == 2,
	      "sscanf %%n reports the character count read so far");
	check(sscanf("50% off", "%d%% off", &d) == 1 && d == 50,
	      "sscanf %%%% matches a literal '%%' in the input");
	check(sscanf("id=7 name=x", "id=%d name=%1s", &d, sbuf) == 2 && d == 7 && sbuf[0] == 'x',
	      "sscanf mixes literal text with specifiers");

	d = -1;
	check(sscanf("1 2", "%*d %d", &d) == 1 && d == 2,
	      "sscanf %%*d skips a conversion without consuming a va_arg");
}

/*
 * lib/fonts/font_8x16.c -> lib/fonts/font_8x16_rs.rs. Pure data (one
 * 4096-byte glyph array, one exported struct font_desc, no functions
 * at all -- see that file's own module doc), so port/test/fonts/'s own
 * check is a byte-exact comparison against the pristine C, not a
 * differential. But like vsscanf, no in-scope caller reaches it during
 * this project's minimal boot (lib/fonts/fonts.c has no init call;
 * every real caller is driver code -- fbcon/vgacon -- which is out of
 * SCOPE.md's scope permanently), so without this, criterion 5 ("the
 * Rust symbol is present in vmlinux AND reached") would have nothing
 * to stand on here either. Only built when CONFIG_FONT_8x16 is on
 * (build-full/build-full-norust in this project, not build-fast/
 * build-norust).
 */
#if IS_ENABLED(CONFIG_FONT_8x16)
static void __init test_fonts(void)
{
	const struct font_desc *fd = find_font("VGA8x16");
	const unsigned char *data;

	check(fd != NULL, "find_font(\"VGA8x16\") finds the font");
	if (!fd)
		return;

	check(fd->width == 8 && fd->height == 16, "VGA8x16 is 8x16");
	check(fd->charcount == 256, "VGA8x16 has 256 characters");

	data = fd->data;

	/* Glyph 1, the classic CP437 smiley (U+263A) -- chosen because it
	 * is NOT all-zero and NOT a simple repeating pattern, so a byte
	 * transposed during the port's own script-based extraction (see
	 * font_8x16_rs.rs's module doc) would very likely show up here. */
	check(data[16 + 2] == 0x7e && data[16 + 3] == 0x81 && data[16 + 4] == 0xa5 &&
	      data[16 + 8] == 0x99 && data[16 + 11] == 0x7e,
	      "glyph 1 (smiley) matches the pristine bitmap");

	/* Glyph 'A' (0x41), read at its real ASCII-driven offset -- this is
	 * the shape a caller actually uses find_font()/font_desc.data for:
	 * indexing by character value, not by array position. */
	check(data[0x41 * 16 + 2] == 0x10 && data[0x41 * 16 + 5] == 0xc6 &&
	      data[0x41 * 16 + 7] == 0xfe,
	      "glyph 'A' matches the pristine bitmap, indexed by character value");

	/* The extra[]/FNTSIZE ABI detail (font_8x16_rs.rs's own module
	 * doc) -- reading backwards from data recovers FONTDATAMAX. */
	check(FNTSIZE(fd->data) == 4096,
	      "FNTSIZE reads back FONTDATAMAX via the real negative-offset ABI");
}
#else
static void __init test_fonts(void) { }
#endif

#ifdef CONFIG_X86
/*
 * arch/x86/lib/misc.c -> misc_rs.rs. num_digits() is reached at boot only when
 * a secondary CPU is brought up (smpboot.c announce_cpu()), which config-fast
 * does not do (1 CPU), so this is its criterion-5 caller there. Values from
 * the C definition: digits plus one for a sign; INT_MIN stays INT_MIN under
 * -fwrapv so it answers 2. The exhaustive 2^32 proof is port/test/misc/.
 */
static void __init test_num_digits(void)
{
	check(num_digits(0) == 1, "num_digits(0) == 1");
	check(num_digits(9) == 1 && num_digits(10) == 2, "num_digits(9)/(10) == 1/2");
	check(num_digits(-1) == 2 && num_digits(-10) == 3, "num_digits(-1)/(-10) == 2/3");
	check(num_digits(999999999) == 9 && num_digits(1000000000) == 10,
	      "num_digits(999999999)/(10^9) == 9/10");
	check(num_digits(INT_MAX) == 10, "num_digits(INT_MAX) == 10");
	check(num_digits(INT_MIN) == 2, "num_digits(INT_MIN) == 2 (wraps like the C)");
}
#else
static void __init test_num_digits(void) { }
#endif

#ifdef CONFIG_X86
/*
 * arch/x86/lib/cmdline.c -> cmdline_rs.rs (the two scanners; the entry points
 * stay C). Expected values come from the documented semantics (the comments
 * in the C: 1-based position of an entire word / length of the LAST
 * option=argument / -1 when absent), worked out by hand, plus a
 * self-consistency pass over the REAL boot command line with an independent
 * tokenizer written here.
 */
static void __init test_x86_cmdline(void)
{
	char buf[16];
	const char *w, *p;
	bool real_ok = true;
	int words = 0, ret;

	check(cmdline_find_option_bool("quiet noapic", "noapic") == 7, "cmdline bool: 'noapic' starts at position 7");
	check(cmdline_find_option_bool("quiet noapic", "quiet") == 1, "cmdline bool: first word is position 1");
	check(cmdline_find_option_bool("quiet noapic", "apic") == 0, "cmdline bool: a suffix of a word is not a match");
	check(cmdline_find_option_bool("cart", "car") == 0, "cmdline bool: a prefix of a word is not a match");
	check(cmdline_find_option_bool("  \tro", "ro") == 4, "cmdline bool: leading blanks counted (position 4)");
	check(cmdline_find_option_bool("quiet", "") == 0 && cmdline_find_option_bool("", "x") == 0, "cmdline bool: empty option / empty line");
	check(cmdline_find_option_bool(NULL, "x") == -1, "cmdline bool: NULL cmdline -> -1");
	memset(buf, 0xA5, sizeof(buf));
	check(cmdline_find_option("console=ttyS0 root=/dev/sda1 ro", "root", buf, sizeof(buf)) == 9 &&
	      !strcmp(buf, "/dev/sda1"), "cmdline opt: root=/dev/sda1 -> length 9, copied");
	check(cmdline_find_option("a=1 a=22", "a", buf, sizeof(buf)) == 2 && !strcmp(buf, "22"), "cmdline opt: the LAST of a repeated option wins");
	check(cmdline_find_option("x=abcdef", "x", buf, 4) == 6 && !strcmp(buf, "abc"), "cmdline opt: truncated to bufsize-1, full length returned");
	check(cmdline_find_option("x=", "x", buf, sizeof(buf)) == 0 && buf[0] == '\0', "cmdline opt: empty argument -> length 0");
	check(cmdline_find_option("xy=1", "x", buf, sizeof(buf)) == -1, "cmdline opt: 'x' does not match 'xy='");
	check(cmdline_find_option("quiet", "quiet", buf, sizeof(buf)) == -1, "cmdline opt: a word without '=' is not an argument option");
	check(cmdline_find_option(NULL, "x", buf, sizeof(buf)) == -1, "cmdline opt: NULL cmdline -> -1");

	/* the real boot command line: every word found where an independent scan says */
	for (w = boot_command_line; *w && words < 32; ) {
		const char *e;
		char key[24], word[40];
		int wl, kl = 0, vl, expect_vl = -1, bpos;

		while (*w && *w <= ' ')
			w++;
		if (!*w)
			break;
		for (e = w; *e && *e > ' '; e++)
			;
		wl = e - w;
		if (wl >= (int)sizeof(word)) {		/* long word: skip, keep the pass simple */
			w = e;
			continue;
		}
		memcpy(word, w, wl);
		word[wl] = '\0';
		bpos = (int)(w - boot_command_line) + 1;
		ret = cmdline_find_option_bool(boot_command_line, word);
		/* first occurrence of this exact word is at or before this one, and is that word */
		if (ret <= 0 || ret > bpos || strncmp(boot_command_line + ret - 1, word, wl) ||
		    (boot_command_line[ret - 1 + wl] && boot_command_line[ret - 1 + wl] > ' '))
			real_ok = false;
		for (p = w; p < e && *p != '='; p++)
			kl++;
		if (p < e && kl < (int)sizeof(key)) {	/* key=value: LAST value of that key, by a separate scan */
			const char *q;

			memcpy(key, w, kl);
			key[kl] = '\0';
			for (q = boot_command_line; *q; ) {
				const char *qe;

				while (*q && *q <= ' ')
					q++;
				for (qe = q; *qe && *qe > ' '; qe++)
					;
				if (qe - q > kl && !strncmp(q, key, kl) && q[kl] == '=')
					expect_vl = (int)(qe - q) - kl - 1;
				q = qe;
			}
			vl = cmdline_find_option(boot_command_line, key, buf, sizeof(buf));
			if (vl != expect_vl)
				real_ok = false;
		}
		words++;
		w = e;
	}
	check(words > 0 && real_ok, "cmdline: every word of the real boot command line is found where an independent scan says");
}
#else
static void __init test_x86_cmdline(void) { }
#endif

#ifdef CONFIG_X86
/*
 * arch/x86/lib/cpu.c -> cpu_rs.rs (x86_family/x86_model/x86_stepping, exported
 * by the Rust object). Signatures are real CPUID(1).EAX values of known parts
 * (Intel SDM / vendor docs, not the C): Sandy Bridge 0x206a7 (6, 0x2a, 7), Ivy
 * Bridge 0x306a9 (6, 0x3a, 9), Pentium 4 Northwood 0xf29 (0xf, 2, 9), AMD Zen 1
 * 0x800f12 (0x17, 1, 2), Zen 3 0xa20f10 (0x19, 0x21, 0), Zen 4 0xa60f12 (0x19,
 * 0x61, 2); and a family-5 signature whose extended-model bits must be ignored.
 */
static void __init test_x86_cpu(void)
{
	static const struct { u32 sig; u32 fam, model, step; } v[] __initconst = {
		{ 0x000206a7, 0x6, 0x2a, 0x7 }, { 0x000306a9, 0x6, 0x3a, 0x9 },
		{ 0x00000f29, 0xf, 0x2, 0x9 }, { 0x00800f12, 0x17, 0x1, 0x2 },
		{ 0x00a20f10, 0x19, 0x21, 0x0 }, { 0x00a60f12, 0x19, 0x61, 0x2 },
		{ 0x000f0543, 0x5, 0x4, 0x3 },
	};
	bool fam = true, model = true, step = true;
	int i;

	for (i = 0; i < ARRAY_SIZE(v); i++) {
		fam &= x86_family(v[i].sig) == v[i].fam;
		model &= x86_model(v[i].sig) == v[i].model;
		step &= x86_stepping(v[i].sig) == v[i].step;
	}
	check(fam, "x86_family of 7 known CPUID signatures");
	check(model, "x86_model of 7 known CPUID signatures (extended model only for family >= 6)");
	check(step, "x86_stepping of 7 known CPUID signatures");
	check(x86_family(0xffffffff) == 0x10e && x86_model(0xffffffff) == 0xff && x86_stepping(0xffffffff) == 0xf,
	      "all-ones signature: family 0x10e, model 0xff, stepping 0xf (no overflow)");
	check(x86_family(0) == 0 && x86_model(0) == 0 && x86_stepping(0) == 0, "zero signature");
}
#else
static void __init test_x86_cpu(void) { }
#endif

/*
 * kernel/time/timeconv.c -> timeconv_rs.rs. Dates from the proleptic Gregorian calendar
 * (checked with Python's datetime, not the C): 0 = Thu 1970-01-01; 951782400 = Tue 2000-02-29
 * (leap day, yday 59); 1000000000 = Sun 2001-09-09 01:46:40; -1 = Wed 1969-12-31 23:59:59;
 * 4102444800 = Fri 2100-01-01 (2100 is not a leap year); 253402300799 = Fri 9999-12-31 23:59:59.
 */
static bool __init tm_is(time64_t secs, int off, long year, int mon, int mday, int hour, int min, int sec, int wday, int yday)
{
	struct tm t;

	time64_to_tm(secs, off, &t);
	return t.tm_year == year && t.tm_mon == mon && t.tm_mday == mday && t.tm_hour == hour &&
	       t.tm_min == min && t.tm_sec == sec && t.tm_wday == wday && t.tm_yday == yday;
}

static void __init test_timeconv(void)
{
	check(tm_is(0, 0, 70, 0, 1, 0, 0, 0, 4, 0), "time64_to_tm(0) == Thu 1970-01-01 00:00:00");
	check(tm_is(951782400, 0, 100, 1, 29, 0, 0, 0, 2, 59), "time64_to_tm(951782400) == Tue 2000-02-29 (leap day)");
	check(tm_is(1000000000, 0, 101, 8, 9, 1, 46, 40, 0, 251), "time64_to_tm(1e9) == Sun 2001-09-09 01:46:40");
	check(tm_is(-1, 0, 69, 11, 31, 23, 59, 59, 3, 364), "time64_to_tm(-1) == Wed 1969-12-31 23:59:59");
	check(tm_is(4102444800LL, 0, 200, 0, 1, 0, 0, 0, 5, 0), "time64_to_tm(2100-01-01) == Fri");
	check(tm_is(253402300799LL, 0, 8099, 11, 31, 23, 59, 59, 5, 364), "time64_to_tm(9999-12-31 23:59:59)");
	check(tm_is(0, 3600, 70, 0, 1, 1, 0, 0, 4, 0), "time64_to_tm(0, +3600) == 01:00:00");
	check(tm_is(0, -1, 69, 11, 31, 23, 59, 59, 3, 364), "time64_to_tm(0, -1) == 1969-12-31 23:59:59");
}

/*
 * kernel/range.c -> range_rs.rs. Values are worked out by hand on paper (half-open ranges).
 */
static void __init test_range(void)
{
	struct range r[4] = {};
	int n;

	n = add_range(r, 4, 0, 10, 20);
	check(n == 1 && r[0].start == 10 && r[0].end == 20, "add_range appends [10,20)");
	check(add_range(r, 4, n, 5, 5) == 1, "add_range ignores an empty range");
	check(add_range(r, 4, 4, 1, 2) == 4, "add_range with no free slot returns the count unchanged");
	n = add_range_with_merge(r, 4, n, 30, 40);
	check(n == 2, "add_range_with_merge adds a disjoint range");
	n = add_range_with_merge(r, 4, n, 15, 35);
	check(n == 1 && r[0].start == 10 && r[0].end == 40 && r[1].end == 0, "add_range_with_merge [15,35) merges [10,20) and [30,40) into [10,40)");
	subtract_range(r, 4, 20, 30);
	check(r[0].start == 10 && r[0].end == 20 && r[1].start == 30 && r[1].end == 40, "subtract_range [20,30) splits [10,40)");
	subtract_range(r, 4, 0, 100);
	check(!r[0].end && !r[1].end, "subtract_range [0,100) removes everything");
	r[0].start = 0; r[0].end = 0; r[1].start = 30; r[1].end = 40; r[2].start = 0; r[2].end = 0; r[3].start = 10; r[3].end = 20;
	n = clean_sort_range(r, 4);
	check(n == 2 && r[0].start == 10 && r[0].end == 20 && r[1].start == 30 && r[1].end == 40, "clean_sort_range compacts and sorts");
	r[0].start = 7; r[0].end = 8; r[1].start = 3; r[1].end = 4;
	sort_range(r, 2);
	check(r[0].start == 3 && r[1].start == 7, "sort_range orders by start");
}

/*
 * kernel/time/timecounter.c -> timecounter_rs.rs. Counter ticks are 1.5 ns (mult 3, shift 1):
 * 10 ticks = 15 ns; the half nanosecond left over is carried in tc->frac, so 11 ticks = 16 ns in all.
 */
static u64 tc_ticks __initdata;

static u64 __init tc_read(struct cyclecounter *cc)
{
	return tc_ticks;
}

static void __init test_timecounter(void)
{
	struct cyclecounter cc = { .read = tc_read, .mask = CYCLECOUNTER_MASK(32), .mult = 3, .shift = 1 };
	struct timecounter tc;
	u64 t;

	tc_ticks = 0;
	timecounter_init(&tc, &cc, 1000);
	check(tc.cycle_last == 0 && tc.nsec == 1000 && tc.mask == 1 && tc.frac == 0, "timecounter_init fields");
	tc_ticks = 10;
	t = timecounter_read(&tc);
	check(t == 1015 && tc.frac == 0 && tc.cycle_last == 10, "timecounter_read after 10 ticks == 1015 ns");
	tc_ticks = 11;
	t = timecounter_read(&tc);
	check(t == 1016 && tc.frac == 1, "timecounter_read after 11 ticks == 1016 ns, 0.5 ns carried");
	check(timecounter_cyc2time(&tc, 21) == 1016 + 15, "timecounter_cyc2time 10 ticks ahead (30 + 1 carried >> 1 = 15)");
	check(timecounter_cyc2time(&tc, 1) == 1016 - 14, "timecounter_cyc2time 10 ticks behind (backwards path, 30 - 1 carried >> 1 = 14)");
	tc_ticks = 0xfffffff0ULL;   /* the 32-bit counter wraps: 0xfffffff0 -> 4 is 20 ticks */
	timecounter_init(&tc, &cc, 0);
	tc_ticks = 4;
	t = timecounter_read(&tc);
	check(t == 30, "timecounter_read across a 32-bit wrap: 20 ticks == 30 ns");
}

/*
 * fs/fs_types.c -> fs_types_rs.rs. Values from the dirent(3)/stat(2) definitions: DT_REG 8, DT_DIR 4,
 * DT_LNK 10, DT_CHR 2, DT_BLK 6, DT_FIFO 1, DT_SOCK 12; the on-disk FT_* numbering (ext2) is
 * 1 file, 2 dir, 3 chardev, 4 blockdev, 5 fifo, 6 socket, 7 symlink.
 */
static void __init test_fs_types(void)
{
	check(fs_ftype_to_dtype(1) == DT_REG && fs_ftype_to_dtype(2) == DT_DIR && fs_ftype_to_dtype(7) == DT_LNK &&
	      fs_ftype_to_dtype(3) == DT_CHR && fs_ftype_to_dtype(4) == DT_BLK && fs_ftype_to_dtype(5) == DT_FIFO &&
	      fs_ftype_to_dtype(6) == DT_SOCK && fs_ftype_to_dtype(0) == DT_UNKNOWN, "fs_ftype_to_dtype FT_* -> DT_*");
	check(fs_ftype_to_dtype(8) == DT_UNKNOWN && fs_ftype_to_dtype(~0u) == DT_UNKNOWN, "fs_ftype_to_dtype out of range == DT_UNKNOWN");
	check(fs_umode_to_ftype(S_IFREG | 0644) == 1 && fs_umode_to_ftype(S_IFDIR | 0755) == 2 && fs_umode_to_ftype(S_IFCHR) == 3 &&
	      fs_umode_to_ftype(S_IFBLK) == 4 && fs_umode_to_ftype(S_IFIFO) == 5 && fs_umode_to_ftype(S_IFSOCK) == 6 &&
	      fs_umode_to_ftype(S_IFLNK | 0777) == 7 && fs_umode_to_ftype(0) == 0, "fs_umode_to_ftype S_IF* -> FT_*");
	check(fs_umode_to_dtype(S_IFREG | 0644) == DT_REG && fs_umode_to_dtype(S_IFDIR) == DT_DIR && fs_umode_to_dtype(S_IFSOCK) == DT_SOCK &&
	      fs_umode_to_dtype(0) == DT_UNKNOWN, "fs_umode_to_dtype S_IF* -> DT_*");
}

#if IS_ENABLED(CONFIG_MULTIUSER)
/*
 * kernel/groups.c (sort/search half) -> groups_rs.rs. Worked on paper: sorting 40 7 100 3 7 gives
 * 3 7 7 40 100; the binary search then finds 40 and 3 and 100, and misses 0, 8 and 101.
 */
static void __init test_groups(void)
{
	static const u32 ids[] __initconst = { 40, 7, 100, 3, 7 };
	struct group_info *gi = groups_alloc(5);
	int i;

	if (!gi) {
		check(false, "groups_alloc(5)");
		return;
	}
	for (i = 0; i < 5; i++)
		gi->gid[i] = KGIDT_INIT(ids[i]);
	groups_sort(gi);
	check(__builtin_memcmp(&gi->gid[0], (u32[]){ 3, 7, 7, 40, 100 }, 20) == 0, "groups_sort sorts ascending");
	check(groups_search(gi, KGIDT_INIT(40)) && groups_search(gi, KGIDT_INIT(3)) && groups_search(gi, KGIDT_INIT(100)) &&
	      groups_search(gi, KGIDT_INIT(7)), "groups_search finds present gids");
	check(!groups_search(gi, KGIDT_INIT(0)) && !groups_search(gi, KGIDT_INIT(8)) && !groups_search(gi, KGIDT_INIT(101)),
	      "groups_search misses absent gids");
	check(!groups_search(NULL, KGIDT_INIT(3)), "groups_search(NULL list) == 0");
	groups_free(gi);
}
#else
static void __init test_groups(void) { }
#endif

#if IS_ENABLED(CONFIG_NET)
/*
 * net/core/utils.c (address parsing) -> utils_rs.rs. Addresses from RFC 4291 / RFC 5952 text:
 * 192.168.1.10 = c0 a8 01 0a; 2001:db8::1 = 20 01 0d b8, 10 zero bytes, 00 01; ::ffff:1.2.3.4 is the
 * IPv4-mapped form (00*10, ff ff, 01 02 03 04).
 */
static void __init test_net_utils(void)
{
	static const u8 v4[] __initconst = { 0xc0, 0xa8, 0x01, 0x0a };
	static const u8 v6a[] __initconst = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	static const u8 v6b[] __initconst = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };
	u8 a[16];
	const char *end;

	check(in4_pton("192.168.1.10", -1, a, -1, &end) == 1 && !memcmp(a, v4, 4) && *end == '\0', "in4_pton(192.168.1.10)");
	check(in4_pton("1.2.3.256", -1, a, -1, &end) == 0, "in4_pton rejects 256");
	check(in4_pton("1.2.3", -1, a, -1, &end) == 0, "in4_pton rejects three octets");
	check(in4_pton("10.0.0.1\n", -1, a, '\n', &end) == 1 && *end == '\n', "in4_pton stops at the delimiter");
	check(in6_pton("2001:db8::1", -1, a, -1, &end) == 1 && !memcmp(a, v6a, 16), "in6_pton(2001:db8::1)");
	check(in6_pton("::ffff:1.2.3.4", -1, a, -1, &end) == 1 && !memcmp(a, v6b, 16), "in6_pton(::ffff:1.2.3.4)");
	check(in6_pton("::1", -1, a, -1, &end) == 1 && a[15] == 1 && !a[0] && !a[14], "in6_pton(::1)");
	check(in6_pton("2001:db8:::1", -1, a, -1, &end) == 0 && in6_pton("12345::", -1, a, -1, &end) == 0, "in6_pton rejects ::: and a 5-digit group");
	check(in_aton("10.1.2.3") == htonl(0x0a010203), "in_aton(10.1.2.3)");
}
#else
static void __init test_net_utils(void) { }
#endif

/*
 * lib/parser.c -> parser_rs.rs. Worked on paper: "size=%d" matches "size=10" with arg "10" -> 10;
 * "mode=%o" matches "mode=777" -> 0777 = 511; "name=%s" captures the rest; the NULL-pattern entry is the
 * "nothing matched" token; "ff" in hex is 255; "0x10" with base 0 is 16.
 */
static void __init test_parser(void)
{
	static const match_table_t tab = {
		{ 1, "ro" }, { 2, "size=%d" }, { 3, "name=%s" }, { 4, "mode=%o" }, { 5, "w=%2s" }, { 0, NULL },
	};
	char s1[] = "size=10", s2[] = "mode=777", s3[] = "name=abc", s4[] = "ro", s5[] = "zzz", s6[] = "w=ab", s7[] = "size=", s8[] = "w=abcdef";
	substring_t args[MAX_OPT_ARGS];
	char buf[8];
	int v = 0;
	unsigned int u = 0;
	u64 q = 0;

	check(match_token(s1, tab, args) == 2 && args[0].from == s1 + 5 && args[0].to == s1 + 7 && match_int(&args[0], &v) == 0 && v == 10,
	      "match_token(size=10) -> token 2, arg 10");
	check(match_token(s2, tab, args) == 4 && match_octal(&args[0], &v) == 0 && v == 511, "match_token(mode=777) -> token 4, octal 511");
	check(match_token(s3, tab, args) == 3 && match_strlcpy(buf, &args[0], sizeof(buf)) == 3 && !strcmp(buf, "abc"), "match_token(name=abc) -> token 3, arg abc");
	check(match_token(s4, tab, args) == 1, "match_token(ro) -> token 1");
	check(match_token(s5, tab, args) == 0, "match_token(zzz) -> the NULL entry's token");
	check(match_token(s6, tab, args) == 5 && args[0].from == s6 + 2 && args[0].to == s6 + 4, "match_token(w=ab) matches w=%2s");
	check(match_token(s8, tab, args) == 0, "match_token(w=abcdef) does not match w=%2s (the width must reach the end)");
	check(match_token(s7, tab, args) == 0, "match_token(size=) does not match %d");
	args[0].from = "ff"; args[0].to = args[0].from + 2;
	check(match_hex(&args[0], &v) == 0 && v == 255, "match_hex(ff) == 255");
	args[0].from = "0x10"; args[0].to = args[0].from + 4;
	check(match_u64(&args[0], &q) == 0 && q == 16, "match_u64(0x10) == 16");
	args[0].from = "123"; args[0].to = args[0].from + 3;
	check(match_uint(&args[0], &u) == 0 && u == 123, "match_uint(123) == 123");
	args[0].from = "99999999999"; args[0].to = args[0].from + 11;
	check(match_int(&args[0], &v) == -ERANGE, "match_int(99999999999) == -ERANGE");
	args[0].from = "x"; args[0].to = args[0].from + 1;
	check(match_int(&args[0], &v) == -EINVAL, "match_int(x) == -EINVAL");
	check(match_wildcard("*.c", "main.c") && !match_wildcard("a?c", "abd") && match_wildcard("a*b*c", "aXXbYYc") && !match_wildcard("abc", "ab"),
	      "match_wildcard");
}

/*
 * lib/random32.c (generator) -> random32_rs.rs. The vectors are the four seed -> value pairs of the C file's own
 * boundary selftest table (generated there from the L'Ecuyer reference implementation): seed through the LCG
 * x * 69069 as the selftest does, ten warm-up steps, then one output.
 */
static void __init test_prandom(void)
{
	static const struct { u32 seed; u32 result; } v[] __initconst = {
		{ 1U, 3484351685U }, { 2U, 2623130059U }, { 3U, 3125133893U }, { 4U, 984847254U },
	};
	struct rnd_state st;
	u8 a[7], b[7];
	int i, j;
	bool ok = true;

	for (i = 0; i < ARRAY_SIZE(v); i++) {
		u32 x = v[i].seed * 69069U;

		st.s1 = __seed(x, 2U);
		x = st.s1 * 69069U;
		st.s2 = __seed(x, 8U);
		x = st.s2 * 69069U;
		st.s3 = __seed(x, 16U);
		x = st.s3 * 69069U;
		st.s4 = __seed(x, 128U);
		for (j = 0; j < 10; j++)
			prandom_u32_state(&st);
		ok &= prandom_u32_state(&st) == v[i].result;
	}
	check(ok, "prandom_u32_state matches the four published seed vectors");

	/* prandom_bytes_state emits successive outputs low byte first: 7 bytes = one whole word + 3 bytes of the next */
	st.s1 = 0x12345678; st.s2 = 0x9abcdef0; st.s3 = 0x0fedcba9; st.s4 = 0x87654321;
	{
		struct rnd_state c = st;
		u32 w0 = prandom_u32_state(&c), w1 = prandom_u32_state(&c);

		prandom_bytes_state(&st, a, sizeof(a));
		for (i = 0; i < 4; i++)
			b[i] = w0 >> (8 * i);
		for (i = 0; i < 3; i++)
			b[4 + i] = w1 >> (8 * i);
		check(!memcmp(a, b, sizeof(a)) && !memcmp(&st, &c, sizeof(st)), "prandom_bytes_state == successive outputs, low byte first");
	}
}

/*
 * kernel/time/time.c (conversions) -> time_rs.rs. Values worked on paper; the HZ-dependent ones are written in terms
 * of HZ (one second is HZ jiffies, 100 clock_t ticks, 1e9 ns).
 */
static void __init test_time_conv(void)
{
	struct timespec64 ts, a, b, r;
	struct __kernel_old_timeval tv;

	check(mktime64(1970, 1, 1, 0, 0, 0) == 0 && mktime64(2000, 2, 29, 0, 0, 0) == 951782400LL &&
	      mktime64(2001, 9, 9, 1, 46, 40) == 1000000000LL && mktime64(1969, 12, 31, 23, 59, 59) == -1,
	      "mktime64 known dates");
	check(mktime64(1970, 1, 1, 24, 0, 0) == 86400 && mktime64(1970, 1, 1, 0, 0, 60) == 60, "mktime64: 24:00:00 and a leap second");
	ts = ns_to_timespec64(1500000000LL);
	check(ts.tv_sec == 1 && ts.tv_nsec == 500000000, "ns_to_timespec64(1.5e9) == 1.5 s");
	ts = ns_to_timespec64(-1);
	check(ts.tv_sec == -1 && ts.tv_nsec == 999999999, "ns_to_timespec64(-1) == -1 s + 999999999 ns");
	ts = ns_to_timespec64(-1000000001LL);
	check(ts.tv_sec == -2 && ts.tv_nsec == 999999999, "ns_to_timespec64(-1000000001)");
	ts = ns_to_timespec64(0);
	check(ts.tv_sec == 0 && ts.tv_nsec == 0, "ns_to_timespec64(0)");
	tv = ns_to_kernel_old_timeval(1500000000LL);
	check(tv.tv_sec == 1 && tv.tv_usec == 500000, "ns_to_kernel_old_timeval(1.5e9)");
	tv = ns_to_kernel_old_timeval(-1);
	check(tv.tv_sec == -1 && tv.tv_usec == 999999, "ns_to_kernel_old_timeval(-1)");
	set_normalized_timespec64(&ts, 1, 2500000000LL);
	check(ts.tv_sec == 3 && ts.tv_nsec == 500000000, "set_normalized_timespec64(1, 2.5e9) == 3.5 s");
	set_normalized_timespec64(&ts, 5, -1);
	check(ts.tv_sec == 4 && ts.tv_nsec == 999999999, "set_normalized_timespec64(5, -1) == 4.999999999 s");
	a.tv_sec = 1; a.tv_nsec = 600000000; b.tv_sec = 2; b.tv_nsec = 700000000;
	r = timespec64_add_safe(a, b);
	check(r.tv_sec == 4 && r.tv_nsec == 300000000, "timespec64_add_safe(1.6, 2.7) == 4.3");
	a.tv_sec = TIME64_MAX; a.tv_nsec = 0; b.tv_sec = 1; b.tv_nsec = 0;
	r = timespec64_add_safe(a, b);
	check(r.tv_sec == TIME64_MAX && r.tv_nsec == 0, "timespec64_add_safe saturates at TIME64_MAX");
	check(jiffies_to_msecs(HZ) == 1000 && jiffies_to_usecs(HZ) == 1000000, "one second of jiffies is 1000 ms / 1e6 us");
	check(__msecs_to_jiffies(1000) == HZ && __usecs_to_jiffies(1000000) == HZ, "1000 ms / 1e6 us are HZ jiffies");
	check(__msecs_to_jiffies(1) == 1 && __usecs_to_jiffies(1) == 1, "the shortest timeouts round up to one jiffy");
	check(__msecs_to_jiffies(-1) == MAX_JIFFY_OFFSET, "a negative timeout is MAX_JIFFY_OFFSET");
	check(nsecs_to_jiffies64(1000000000ULL) == HZ && jiffies64_to_nsecs(HZ) == 1000000000ULL, "1e9 ns is HZ jiffies");
	check(jiffies64_to_msecs(HZ) == 1000, "jiffies64_to_msecs(HZ) == 1000");
	check(jiffies_to_clock_t(HZ) == 100 && clock_t_to_jiffies(100) == HZ, "HZ jiffies are 100 clock_t ticks");
	jiffies_to_timespec64(3 * HZ, &ts);
	check(ts.tv_sec == 3 && ts.tv_nsec == 0, "jiffies_to_timespec64(3 s)");
	ts.tv_sec = 3; ts.tv_nsec = 0;
	check(timespec64_to_jiffies(&ts) == 3 * HZ, "timespec64_to_jiffies(3 s) == 3*HZ");
	ts.tv_sec = 0; ts.tv_nsec = 1;
	check(timespec64_to_jiffies(&ts) == 1, "timespec64_to_jiffies(1 ns) rounds up to one jiffy");
	check(nsecs_to_jiffies(2000000000ULL) == 2 * HZ, "nsecs_to_jiffies(2 s)");
}

/*
 * lib/lockref.c (fast path) -> lockref_rs.rs. Single-threaded values worked on paper from the semantics in the header: a lockref
 * starts at count 1; get/get_not_zero/get_not_dead add one, put_return/put_or_lock take one off (put_or_lock refuses at
 * count <= 1 and then returns with the lock HELD), get_not_zero refuses at count <= 0, get_not_dead at count < 0 (dead = -128).
 */
static void __init test_lockref(void)
{
	struct lockref lr;

	lockref_init(&lr);
	check(lr.count == 1, "lockref_init: count 1");
	lockref_get(&lr);
	check(lr.count == 2, "lockref_get: 2");
	check(lockref_get_not_zero(&lr) && lr.count == 3, "lockref_get_not_zero at 2 -> 3");
	check(lockref_put_return(&lr) == 2 && lr.count == 2, "lockref_put_return at 3 -> 2");
	check(lockref_put_or_lock(&lr) && lr.count == 1, "lockref_put_or_lock at 2 -> 1, no lock taken");
	check(!lockref_put_or_lock(&lr) && lr.count == 1 && spin_is_locked(&lr.lock), "lockref_put_or_lock at 1 refuses and returns holding the lock");
	lockref_mark_dead(&lr);
	spin_unlock(&lr.lock);
	check(lr.count == -128 && !spin_is_locked(&lr.lock), "lockref_mark_dead: -128");
	check(!lockref_get_not_dead(&lr) && !lockref_get_not_zero(&lr) && lockref_put_return(&lr) == -1 && lr.count == -128,
	      "a dead lockref refuses get_not_dead / get_not_zero / put_return");
	lockref_init(&lr);
	lr.count = 0;
	check(!lockref_get_not_zero(&lr) && lr.count == 0 && lockref_get_not_dead(&lr) && lr.count == 1, "count 0: get_not_zero refuses, get_not_dead accepts");
	spin_lock(&lr.lock);
	check(lockref_put_return(&lr) == -1, "lockref_put_return with the lock held falls out with -1");
	spin_unlock(&lr.lock);
	lr.count = 1;
	spin_lock(&lr.lock);
	spin_unlock(&lr.lock);
	check(lockref_put_return(&lr) == 0 && lr.count == 0, "lockref_put_return at 1 -> 0");
}

/*
 * lib/kfifo.c (core) -> kfifo_rs.rs. Worked on paper. A 16-byte byte FIFO has mask 15; putting 6 then 20 bytes stores 6 + 10 (full);
 * peeking never consumes; taking 5 leaves out=5, and with in=16 the linear run from out is min(100, 11, 16 - 5) = 11 starting at 5; after
 * three more bytes wrap to offsets 0..2 the readable run is still capped by the end of the buffer. A size that is not a power of two
 * rounds down (17 -> 16, 3 -> 2); fewer than two elements is -EINVAL. Records carry a 1- or 2-byte length.
 */
static void __init test_kfifo(void)
{
	struct __kfifo f;
	u8 buf[32], out[32];
	u32 tail = 0;
	u32 e[8], eo[8];
	int i;

	check(__kfifo_init(&f, buf, 16, 1) == 0 && f.mask == 15 && f.esize == 1 && f.in == 0 && f.out == 0, "__kfifo_init(16 bytes) mask 15");
	check(__kfifo_init(&f, buf, 17, 1) == 0 && f.mask == 15, "__kfifo_init(17) rounds down to 16");
	check(__kfifo_init(&f, buf, 3, 1) == 0 && f.mask == 1, "__kfifo_init(3) rounds down to 2");
	check(__kfifo_init(&f, buf, 1, 1) == -EINVAL && f.mask == 0 && __kfifo_init(&f, buf, 0, 1) == -EINVAL, "__kfifo_init: fewer than two elements is -EINVAL");
	check(__kfifo_init(&f, buf, 32, 4) == 0 && f.mask == 7 && f.esize == 4, "__kfifo_init(32 bytes of 4-byte elements) mask 7");
	for (i = 0; i < 8; i++)
		e[i] = 0x01010101u * (i + 1);
	check(__kfifo_in(&f, e, 5) == 5 && f.in == 5 && __kfifo_in(&f, e, 8) == 3 && f.in == 8, "__kfifo_in: element FIFO takes 5 then only 3 of 8");
	check(__kfifo_out(&f, eo, 8) == 8 && !memcmp(eo, e, 20) && eo[5] == e[0] && f.out == 8, "__kfifo_out of 4-byte elements, in order, wrapping the source");
	check(__kfifo_init(&f, buf, 16, 1) == 0, "re-init 16 bytes");
	check(__kfifo_in(&f, "abcdef", 6) == 6 && f.in == 6, "__kfifo_in 6 bytes");
	check(__kfifo_in(&f, "0123456789ABCDEFGHIJ", 20) == 10 && f.in == 16, "__kfifo_in 20 bytes: only 10 fit");
	memset(out, 0, sizeof(out));
	check(__kfifo_out_peek(&f, out, 4) == 4 && !memcmp(out, "abcd", 4) && f.out == 0, "__kfifo_out_peek does not consume");
	check(__kfifo_out(&f, out, 5) == 5 && !memcmp(out, "abcde", 5) && f.out == 5, "__kfifo_out 5");
	check(__kfifo_out_linear(&f, &tail, 100) == 11 && tail == 5, "__kfifo_out_linear: run of 11 from offset 5");
	check(__kfifo_in(&f, "XYZ", 3) == 3 && f.in == 19, "__kfifo_in wraps to the start of the buffer");
	check(__kfifo_out_linear(&f, &tail, 100) == 11 && tail == 5, "__kfifo_out_linear stops at the end of the buffer");
	memset(out, 0, sizeof(out));
	check(__kfifo_out(&f, out, 100) == 14 && !memcmp(out, "f0123456789XYZ", 14), "__kfifo_out drains across the wrap, in order");
	check(f.in == f.out && __kfifo_out_linear(&f, NULL, 5) == 0, "empty again");
	/* records */
	check(__kfifo_init(&f, buf, 16, 1) == 0, "re-init for records");
	check(__kfifo_max_r(1000, 1) == 255 && __kfifo_max_r(70000, 2) == 65535 && __kfifo_max_r(10, 1) == 10, "__kfifo_max_r");
	check(__kfifo_in_r(&f, "hello", 5, 1) == 5 && f.in == 6 && __kfifo_len_r(&f, 1) == 5, "__kfifo_in_r: record of 5, 6 bytes used, len_r 5");
	check(__kfifo_in_r(&f, "wor", 3, 1) == 3 && f.in == 10, "second record");
	check(__kfifo_in_r(&f, "0123456789", 10, 1) == 0 && f.in == 10, "a record that does not fit is refused (0)");
	memset(out, 0, sizeof(out));
	check(__kfifo_out_peek_r(&f, out, 32, 1) == 5 && !memcmp(out, "hello", 5) && f.out == 0, "__kfifo_out_peek_r");
	check(__kfifo_out_linear_r(&f, &tail, 3, 1) == 3 && tail == 1, "__kfifo_out_linear_r caps at n, run starts after the prefix");
	check(__kfifo_out_r(&f, out, 2, 1) == 2 && f.out == 6, "__kfifo_out_r with a short buffer drops the rest of the record");
	__kfifo_skip_r(&f, 1);
	check(f.out == 10 && f.in == f.out && __kfifo_out_r(&f, out, 8, 1) == 0, "__kfifo_skip_r; empty FIFO gives 0");
	check(__kfifo_init(&f, buf, 32, 1) == 0 && __kfifo_in_r(&f, "abc", 3, 2) == 3 && f.in == 5 && __kfifo_len_r(&f, 2) == 3, "2-byte length prefix");
}

/* lib/genalloc.c -> genalloc_rs.rs: the lock-free bitmap helpers (reached by every gen_pool_alloc()/gen_pool_free()) and the five
 * allocation algorithms. Worked out on paper: a pool of 16-byte units (min_alloc_order 4) with one 2048-byte chunk at the made-up
 * address 0x10000 (never dereferenced) is 128 bits in two words.
 *   alloc 100 -> 7 units, bits 0-6, 0x10000     alloc 16 -> bit 7, 0x10070        free the 100: bits 0-6 clear again
 *   alloc 32 -> bits 0-1, 0x10000               alloc 48 -> bits 2-4, 0x10020     avail = 2048 - (32+48+16) = 1952
 *   first_fit_align(256): 1 unit, align_mask = ((256+15)>>4)-1 = 15, offset 0  -> bit 16, 0x10100
 *   fixed(0x200): offset_bit = 0x200>>4 = 32 -> bits 32-33, 0x10200; the same request again finds bit 34, not 32 -> fails (0)
 *   free runs now: 5-6 (2), 8-15 (8), 17-31 (15), 34-127 (94)
 *   best_fit 2 units -> the run of exactly 2: bit 5, 0x10050;  best_fit 3 units -> the run of 8: bit 8, 0x10080
 *   first_fit_order_align 5 units -> aligned to roundup_pow_of_two(5) = 8: bit 8 is taken, 16 is taken, 24 is free: 0x10180 */
#if IS_ENABLED(CONFIG_GENERIC_ALLOCATOR)
static void __init test_genalloc(void)
{
	struct gen_pool *pool = gen_pool_create(4, -1);
	struct genpool_data_align al = { .align = 256 };
	struct genpool_data_fixed fx = { .offset = 0x200 };
	unsigned long a1, a2, a3, a4, a5, a6, a7, a8, a9, a10;

	if (!pool) {
		check(false, "gen_pool_create");
		return;
	}
	check(gen_pool_add(pool, 0x10000, 2048, -1) == 0, "gen_pool_add of one 2048-byte chunk");
	a1 = gen_pool_alloc(pool, 100);
	a2 = gen_pool_alloc(pool, 16);
	check(a1 == 0x10000 && a2 == 0x10070, "first fit: 100 bytes -> 7 units at 0x10000, then 16 bytes at bit 7");
	gen_pool_free(pool, a1, 100);
	a3 = gen_pool_alloc(pool, 32);
	a4 = gen_pool_alloc(pool, 48);
	check(a3 == 0x10000 && a4 == 0x10020, "after the free, first fit reuses bits 0-1 and 2-4");
	check(gen_pool_avail(pool) == 1952 && gen_pool_size(pool) == 2048, "avail 1952 of 2048");
	a5 = gen_pool_alloc_algo(pool, 16, gen_pool_first_fit_align, &al);
	check(a5 == 0x10100, "first_fit_align(256): the next 16-unit boundary");
	a6 = gen_pool_alloc_algo(pool, 32, gen_pool_fixed_alloc, &fx);
	check(a6 == 0x10200, "fixed_alloc(0x200) gets exactly bits 32-33");
	check(gen_pool_alloc_algo(pool, 32, gen_pool_fixed_alloc, &fx) == 0, "fixed_alloc of the same place again fails");
	a7 = gen_pool_alloc_algo(pool, 32, gen_pool_best_fit, NULL);
	a8 = gen_pool_alloc_algo(pool, 48, gen_pool_best_fit, NULL);
	check(a7 == 0x10050 && a8 == 0x10080, "best_fit: the run of exactly 2, then the run of 8");
	a9 = gen_pool_alloc_algo(pool, 80, gen_pool_first_fit_order_align, NULL);
	check(a9 == 0x10180, "first_fit_order_align(5 units): aligned to 8, first free is bit 24");
	a10 = gen_pool_alloc(pool, 4096);
	check(a10 == 0, "an allocation larger than the pool fails");
	gen_pool_free(pool, a3, 32);
	gen_pool_free(pool, a4, 48);
	gen_pool_free(pool, a2, 16);
	gen_pool_free(pool, a5, 16);
	gen_pool_free(pool, a6, 32);
	gen_pool_free(pool, a7, 32);
	gen_pool_free(pool, a8, 48);
	gen_pool_free(pool, a9, 80);
	check(gen_pool_avail(pool) == 2048, "everything freed: avail back to 2048");
	gen_pool_destroy(pool);
}
#else
static void __init test_genalloc(void) { }
#endif

/* lib/nlattr.c -> nlattr_rs.rs: attribute parsing, policy validation and the read-only helpers. Worked out on paper: a stream of three
 * attributes, each header = 2-byte length + 2-byte type (little-endian), payload padded to 4:
 *   type 1 (NLA_U8):                 05 00 01 00  07 00 00 00        len 5 (header 4 + 1), padded to 8
 *   type 2 (NLA_U32, range 10..20):  08 00 02 00  0f 00 00 00        len 8, value 15
 *   type 3 (NLA_NUL_STRING, len 8):  08 00 03 00  'a' 'b' 'c' 00     len 8
 * 24 bytes in all. Parsing with the strict flags gives tb[1..3] = offsets 0, 8, 16 and tb[0] = NULL. The same stream with the U32 set to 25
 * is out of range: -ERANGE (-34), message "integer out of range", bad attribute at offset 8. A type-5 attribute (max type is 3) is -EINVAL
 * "Unknown attribute type". The policy's total size is 0 (UNSPEC) + 8 (U8: 4 + 1, padded) + 8 (U32: 4 + 4) + 12 (string of up to 8: 4 + 8) = 28. */
#if IS_ENABLED(CONFIG_NET)
static void __init test_nlattr(void)
{
	static const struct nla_policy pol[4] = {
		[1] = { .type = NLA_U8 },
		[2] = NLA_POLICY_RANGE(NLA_U32, 10, 20),
		[3] = { .type = NLA_NUL_STRING, .len = 8 },
	};
	u8 buf[40] __aligned(4) = {
		0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x03, 0x00, 'a', 'b', 'c', 0x00,
	};
	struct nlattr *tb[4];
	struct netlink_ext_ack ack = {};
	char dst[16];
	int rc;

	rc = __nla_parse(tb, 3, (struct nlattr *)buf, 24, pol, NL_VALIDATE_STRICT, &ack);
	check(rc == 0 && !tb[0] && tb[1] == (void *)buf && tb[2] == (void *)(buf + 8) && tb[3] == (void *)(buf + 16),
	      "nla_parse: three attributes land in tb[1..3]");
	check(rc == 0 && nla_get_u8(tb[1]) == 7 && nla_get_u32(tb[2]) == 15 && nla_strcmp(tb[3], "abc") == 0,
	      "nla_parse: payloads are 7, 15 and \"abc\"");
	check(nla_find((struct nlattr *)buf, 24, 3) == (void *)(buf + 16) && nla_find((struct nlattr *)buf, 24, 4) == NULL,
	      "nla_find: type 3 at offset 16, type 4 absent");
	check(nla_policy_len(pol, 4) == 28, "nla_policy_len is 0 + 8 + 8 + 12");
	check(nla_memcmp(tb[3], "abc\0", 4) == 0 && nla_memcmp(tb[3], "abd\0", 4) < 0, "nla_memcmp");
	check(nla_strscpy(dst, tb[3], sizeof(dst)) == 3 && !strcmp(dst, "abc") && dst[3] == 0 && dst[15] == 0,
	      "nla_strscpy: 3 bytes, zero padded");
	check(nla_strscpy(dst, tb[3], 3) == -E2BIG && !strcmp(dst, "ab"), "nla_strscpy: too small a buffer gives -E2BIG and \"ab\"");
	memset(dst, 0x55, sizeof(dst));
	check(nla_memcpy(dst, tb[2], 8) == 4 && dst[0] == 0x0f && dst[4] == 0 && dst[7] == 0, "nla_memcpy: 4 bytes then zero fill");

	buf[12] = 25;
	memset(&ack, 0, sizeof(ack));
	rc = __nla_parse(tb, 3, (struct nlattr *)buf, 24, pol, NL_VALIDATE_STRICT, &ack);
	check(rc == -ERANGE && ack._msg && !strcmp(ack._msg, "integer out of range") && ack.bad_attr == (void *)(buf + 8) &&
	      ack.policy == &pol[2], "out of range: -ERANGE, message, bad attribute and policy entry");

	buf[12] = 15;
	buf[16 + 2] = 5;		/* type 3 -> 5: beyond maxtype 3 */
	memset(&ack, 0, sizeof(ack));
	rc = __nla_parse(tb, 3, (struct nlattr *)buf, 24, pol, NL_VALIDATE_STRICT, &ack);
	check(rc == -EINVAL && ack._msg && !strcmp(ack._msg, "Unknown attribute type") && ack.bad_attr == (void *)(buf + 16),
	      "type 5 with strict flags: -EINVAL \"Unknown attribute type\"");
	rc = __nla_parse(tb, 3, (struct nlattr *)buf, 24, pol, 0, NULL);
	check(rc == 0 && !tb[3], "the same stream without strict flags: the unknown attribute is skipped");
}
#else
static void __init test_nlattr(void) { }
#endif

/* lib/assoc_array.c -> assoc_array_rs.rs. Worked out on paper: the first insert into an empty array goes to slot 0 of the root node,
 * and every later insert into a node with room takes the LAST free slot, so keys 0..15 land in slots 0, 15, 14, ..., 1 and iterate()
 * (slot order) reports 0, 15, 14, 13, ..., 2, 1. The 17th key forces a node split; after that the checks are invariants: every key is
 * found, deletes remove exactly what they name, gc() with a keep-odd-ids predicate leaves keys 5, 7, ..., 15 (key 5 was replaced by id 105),
 * keys sharing their low 10 bits make the tree build shortcuts and still find and delete correctly, and at the end every object has
 * been released exactly once (objects are reference counted the way the keyring's are: gc's iterator takes a reference for the copy it
 * builds, free_object() drops one). */
#if IS_ENABLED(CONFIG_ASSOCIATIVE_ARRAY)
#include <linux/assoc_array.h>
struct lt_aa_obj { unsigned long key; int id; int ref; };
static int lt_aa_allocs, lt_aa_freed;
static unsigned long lt_aa_chunk(const void *k, int level) { return level >= 64 ? 0 : *(const unsigned long *)k; }
static unsigned long lt_aa_obj_chunk(const void *o, int level) { return level >= 64 ? 0 : ((const struct lt_aa_obj *)o)->key; }
static bool lt_aa_cmp(const void *o, const void *k) { return ((const struct lt_aa_obj *)o)->key == *(const unsigned long *)k; }
static int lt_aa_diff(const void *o, const void *k)
{
	unsigned long x = ((const struct lt_aa_obj *)o)->key ^ *(const unsigned long *)k;

	return x ? __ffs(x) : -1;
}
static void lt_aa_free(void *o)
{
	struct lt_aa_obj *ob = o;

	if (--ob->ref == 0) {
		lt_aa_freed++;
		kfree(ob);
	}
}
static const struct assoc_array_ops lt_aa_ops = { lt_aa_chunk, lt_aa_obj_chunk, lt_aa_cmp, lt_aa_diff, lt_aa_free };
static int lt_aa_collect(const void *o, void *d)
{
	int **q = d;

	*(*q)++ = ((const struct lt_aa_obj *)o)->id;
	return 0;
}
static bool lt_aa_keep_odd(void *o, void *d)
{
	struct lt_aa_obj *ob = o;

	if (!(ob->id & 1))
		return false;
	ob->ref++;
	return true;
}
static bool lt_aa_put(struct assoc_array *a, unsigned long key, int id)
{
	struct lt_aa_obj *o = kzalloc(sizeof(*o), GFP_KERNEL);
	struct assoc_array_edit *e;

	if (!o)
		return false;
	o->key = key;
	o->id = id;
	o->ref = 1;
	lt_aa_allocs++;
	e = assoc_array_insert(a, &lt_aa_ops, &key, o);
	if (IS_ERR(e))
		return false;
	assoc_array_apply_edit(e);
	return true;
}
static bool lt_aa_del(struct assoc_array *a, unsigned long key)
{
	struct assoc_array_edit *e = assoc_array_delete(a, &lt_aa_ops, &key);

	if (IS_ERR_OR_NULL(e))
		return false;
	assoc_array_apply_edit(e);
	return true;
}
static int lt_aa_id(struct assoc_array *a, unsigned long key)
{
	struct lt_aa_obj *o = assoc_array_find(a, &lt_aa_ops, &key);

	return o ? o->id : -1;
}

static void __init test_assoc_array(void)
{
	static const int want[16] = { 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	struct assoc_array arr;
	int order[64], *q = order, i, ok;
	unsigned long k;

	assoc_array_init(&arr);
	for (i = 0; i < 16; i++)
		ok = lt_aa_put(&arr, i, i);
	check(ok && arr.nr_leaves_on_tree == 16, "assoc_array: 16 inserts fill the root node");
	assoc_array_iterate(&arr, lt_aa_collect, &q);
	check(q - order == 16 && !memcmp(order, want, sizeof(want)), "assoc_array_iterate: slot order 0, 15, 14, ..., 1");

	ok = lt_aa_put(&arr, 16, 16);
	for (i = 0, ok = ok && arr.nr_leaves_on_tree == 17; i <= 16; i++)
		ok = ok && lt_aa_id(&arr, i) == i;
	check(ok, "assoc_array: the 17th insert splits the node and every key is still found");
	check(lt_aa_id(&arr, 17) == -1 && lt_aa_id(&arr, 1UL << 40) == -1, "assoc_array_find: absent keys are not found");

	check(lt_aa_put(&arr, 5, 105) && arr.nr_leaves_on_tree == 17 && lt_aa_id(&arr, 5) == 105, "assoc_array_insert: same key replaces");
	rcu_barrier();
	check(lt_aa_freed == 1, "the replaced object is released after a grace period");

	for (i = 0, ok = 1; i < 4; i++)
		ok = ok && lt_aa_del(&arr, i);
	check(ok && arr.nr_leaves_on_tree == 13 && !lt_aa_del(&arr, 0), "assoc_array_delete: keys 0-3 go, a second delete of one finds nothing");
	for (i = 0, ok = 1; i < 17; i++)
		ok = ok && lt_aa_id(&arr, i) == (i < 4 ? -1 : i == 5 ? 105 : i);
	check(ok, "after the deletes exactly keys 4-16 remain");

	check(assoc_array_gc(&arr, &lt_aa_ops, lt_aa_keep_odd, NULL) == 0, "assoc_array_gc succeeds");
	rcu_barrier();
	q = order;
	assoc_array_iterate(&arr, lt_aa_collect, &q);
	for (i = 0, ok = 1; i < 17; i++)
		ok = ok && lt_aa_id(&arr, i) == ((i & 1) && i > 4 ? (i == 5 ? 105 : i) : -1);
	check(ok && q - order == 6 && arr.nr_leaves_on_tree == 6, "assoc_array_gc with keep-odd-ids: the 6 odd keys 5-15 remain, the even ones are gone");

	assoc_array_destroy(&arr, &lt_aa_ops);
	check(arr.root == NULL && lt_aa_allocs == lt_aa_freed, "assoc_array_destroy releases every remaining object, each exactly once");

	/* keys sharing their low 10 bits: shortcuts */
	lt_aa_allocs = lt_aa_freed = 0;
	assoc_array_init(&arr);
	for (i = 1, ok = 1; i <= 40; i++)
		ok = ok && lt_aa_put(&arr, (unsigned long)i << 10, i);
	for (i = 1; i <= 40; i++)
		ok = ok && lt_aa_id(&arr, (unsigned long)i << 10) == i;
	check(ok && arr.nr_leaves_on_tree == 40, "assoc_array: 40 keys that share their low 10 bits (shortcut paths) all found");
	for (i = 1, ok = 1; i <= 40; i++) {
		k = (unsigned long)i << 10;
		ok = ok && lt_aa_del(&arr, k) && lt_aa_id(&arr, k) == -1 && arr.nr_leaves_on_tree == 40 - i;
	}
	rcu_barrier();
	check(ok && arr.root == NULL && lt_aa_allocs == lt_aa_freed, "assoc_array: deleting them one by one empties the tree and releases all 40");
}
#else
static void __init test_assoc_array(void) { }
#endif

/* lib/group_cpus: upstream's guarantee is "all CPUs covered, none in two groups"; one group must be exactly the possible mask */
static void __init test_group_cpus(void)
{
	static const unsigned int want[] = { 1, 2, 3, 7 };
	unsigned int g, n, i, j, ok;
	struct cpumask *m, *all = kzalloc(cpumask_size(), GFP_KERNEL);

	if (!all)
		return;
	m = group_cpus_evenly(1, &n);
	check(m && n == 1 && cpumask_equal(&m[0], cpu_possible_mask), "group_cpus_evenly(1): one group holding every possible CPU");
	kfree(m);
	check(!group_cpus_evenly(0, &n), "group_cpus_evenly(0) is NULL");
	for (g = 0, ok = 1; g < ARRAY_SIZE(want); g++) {
		m = group_cpus_evenly(want[g], &n);
		if (!m || n < 1 || n > want[g]) {
			ok = 0;
			kfree(m);
			continue;
		}
		cpumask_clear(all);
		for (i = 0; i < n; i++) {
			ok = ok && !cpumask_empty(&m[i]);
			for (j = i + 1; j < n; j++)
				ok = ok && !cpumask_intersects(&m[i], &m[j]);
			cpumask_or(all, all, &m[i]);
		}
		ok = ok && cpumask_equal(all, cpu_possible_mask);
		kfree(m);
	}
	check(ok, "group_cpus_evenly(1, 2, 3, 7): 1..N non-empty groups, pairwise disjoint, union is the possible mask");
	kfree(all);
}


/* lib/rhashtable: expected values worked out on paper; the real header's inlines against the ported slow paths, the resize worker running
 * on its own, and nested bucket tables built by hand (the real code only makes one when a big non-blocking allocation fails) */
struct lt_rh {
	u32 key;
	u32 id;
	struct rhash_head node;
	struct rhlist_head lnode;
};
static const struct rhashtable_params lt_rh_p = {
	.head_offset = offsetof(struct lt_rh, node), .key_offset = offsetof(struct lt_rh, key),
	.key_len = sizeof(u32), .automatic_shrinking = true, .min_size = 4,
};
static const struct rhashtable_params lt_rhl_p = {
	.head_offset = offsetof(struct lt_rh, lnode), .key_offset = offsetof(struct lt_rh, key),
	.key_len = sizeof(u32), .automatic_shrinking = true, .min_size = 4,
};
static unsigned int lt_rh_freed __initdata;
static void __init lt_rh_free_fn(void *ptr, void *arg)
{
	lt_rh_freed++;
}

/* hash -> bucket in a hand-made nested table: fill the buckets in hashes[], then probe */
static void __init lt_rh_nested(unsigned int lg, const unsigned int *fill, unsigned int nfill, unsigned int miss_leaf, unsigned int empty_slot,
				unsigned int miss_mid)
{
	static const struct rhashtable_params p = { .head_offset = 0, .key_len = sizeof(u32), .key_offset = 0 };
	static struct rhash_head objs[8] __initdata;
	struct rhashtable ht;
	struct bucket_table *old, *t;
	struct rhash_lock_head __rcu **b;
	unsigned int i, ok = 1;
	void *top;

	if (rhashtable_init(&ht, &p)) {
		check(false, "rhashtable nested: init");
		return;
	}
	old = rcu_dereference_protected(ht.tbl, 1);
	t = kzalloc(sizeof(*t) + sizeof(t->buckets[0]), GFP_KERNEL);
	top = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!t || !top) {
		kfree(t);
		kfree(top);
		rhashtable_destroy(&ht);
		return;
	}
	t->size = 1U << lg;
	t->nest = (lg - 1) % (PAGE_SHIFT - ilog2(sizeof(void *))) + 1;
	INIT_LIST_HEAD(&t->walkers);
	RCU_INIT_POINTER(t->buckets[0], top);
	for (i = 0; i < nfill; i++) {
		b = rht_bucket_nested_insert(&ht, t, fill[i]);
		ok = ok && b && __rht_bucket_nested(t, fill[i]) == b && !*b;
		if (b) {
			objs[i].next = (struct rhash_head *)1UL;
			RCU_INIT_POINTER(*b, (struct rhash_lock_head *)&objs[i]);
		}
	}
	check(ok, "rhashtable nested: rht_bucket_nested_insert() makes every bucket and __rht_bucket_nested() finds the same one");
	for (i = 0, ok = 1; i < nfill; i++)
		ok = ok && rht_ptr_rcu(rht_bucket_nested(t, fill[i])) == &objs[i];
	check(ok, "rhashtable nested: rht_bucket_nested() returns the filled chains");
	check(!__rht_bucket_nested(t, miss_leaf) && rht_is_a_nulls(rht_ptr_rcu(rht_bucket_nested(t, miss_leaf))),
	      "rhashtable nested: a missing leaf is NULL / the empty static bucket");
	b = __rht_bucket_nested(t, empty_slot);
	check(b && !*b && rht_is_a_nulls(rht_ptr_rcu(rht_bucket_nested(t, empty_slot))), "rhashtable nested: an unfilled slot of an existing leaf is an empty bucket");
	if (miss_mid != ~0U)
		check(!__rht_bucket_nested(t, miss_mid), "rhashtable nested: a missing middle-level table is NULL");
	rcu_assign_pointer(ht.tbl, t);
	kvfree(old);
	lt_rh_freed = 0;
	rhashtable_free_and_destroy(&ht, lt_rh_free_fn, NULL);
	check(lt_rh_freed == nfill, "rhashtable nested: free_and_destroy() reaches every filled bucket and frees the pages");
}

static void __init test_rhashtable(void)
{
	enum { N = 200, M = 60 };
	static const unsigned int fill10[] __initconst = { 0, 4, 510, 1022 };
	static const unsigned int fill19[] __initconst = { 0, 2, 262144, 524286, 12344 };
	struct rhashtable ht;
	struct rhltable hl;
	struct lt_rh *o = kcalloc(N, sizeof(*o), GFP_KERNEL), *f;
	struct rhashtable_iter it;
	unsigned long *seen = bitmap_zalloc(N + 1, GFP_KERNEL);
	unsigned int i, ok, n;
	u32 key;
	struct rhlist_head *l, *pos;

	if (!o || !seen)
		goto out;
	if (rhashtable_init(&ht, &lt_rh_p)) {
		check(false, "rhashtable_init");
		goto out;
	}
	for (i = 0, ok = 1; i < N; i++) {
		o[i].key = i + 1;
		o[i].id = 1000 + i;
		ok = ok && !rhashtable_insert_fast(&ht, &o[i].node, lt_rh_p);
	}
	check(ok, "rhashtable_insert_fast(): 200 distinct keys all inserted (the table grows from 64 buckets on its own)");
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (f) {
		f->key = 5;
		check(rhashtable_lookup_insert_fast(&ht, &f->node, lt_rh_p) == -EEXIST, "rhashtable_lookup_insert_fast() of a present key is -EEXIST");
		kfree(f);
	}
	for (i = 0, ok = 1; i < N; i++) {
		key = i + 1;
		rcu_read_lock();
		f = rhashtable_lookup_fast(&ht, &key, lt_rh_p);
		ok = ok && f == &o[i];
		rcu_read_unlock();
	}
	check(ok, "rhashtable_lookup_fast(): every key finds its own object");
	key = N + 1;
	rcu_read_lock();
	check(!rhashtable_lookup_fast(&ht, &key, lt_rh_p), "rhashtable_lookup_fast(): an absent key is NULL");
	rcu_read_unlock();
	rhashtable_walk_enter(&ht, &it);
	rhashtable_walk_start(&it);
	n = 0;
	while ((f = rhashtable_walk_next(&it)) != NULL) {
		if (IS_ERR(f))
			continue;			/* a resize: the walk rewinds and entries repeat */
		__set_bit(f->key, seen);
		n++;
	}
	rhashtable_walk_stop(&it);
	rhashtable_walk_exit(&it);
	for (i = 1, ok = 1; i <= N; i++)
		ok = ok && test_bit(i, seen);
	check(ok && n >= N, "rhashtable_walk_*(): the walk sees every one of the 200 objects");
	for (i = 0, ok = 1; i < N; i += 2)
		ok = ok && !rhashtable_remove_fast(&ht, &o[i].node, lt_rh_p);
	check(ok, "rhashtable_remove_fast(): 100 objects removed (the table may shrink)");
	check(rhashtable_remove_fast(&ht, &o[0].node, lt_rh_p) == -ENOENT, "rhashtable_remove_fast() of a removed object is -ENOENT");
	for (i = 0, ok = 1; i < N; i++) {
		key = i + 1;
		rcu_read_lock();
		f = rhashtable_lookup_fast(&ht, &key, lt_rh_p);
		ok = ok && f == ((i & 1) ? &o[i] : NULL);
		rcu_read_unlock();
	}
	check(ok, "rhashtable_lookup_fast(): removed keys are gone, kept keys are still found");
	msleep(50);		/* let the shrink worker run on its own */
	lt_rh_freed = 0;
	rhashtable_free_and_destroy(&ht, lt_rh_free_fn, NULL);
	check(lt_rh_freed == N / 2, "rhashtable_free_and_destroy(): the callback runs for the 100 objects left");

	memset(o, 0, N * sizeof(*o));
	if (rhltable_init(&hl, &lt_rhl_p)) {
		check(false, "rhltable_init");
		goto out;
	}
	for (i = 0, ok = 1; i < M; i++) {
		o[i].key = i % 3;
		o[i].id = i;
		ok = ok && !rhltable_insert(&hl, &o[i].lnode, lt_rhl_p);
	}
	check(ok, "rhltable_insert(): 60 objects over 3 keys");
	for (key = 0, ok = 1; key < 4; key++) {
		n = 0;
		rcu_read_lock();
		l = rhltable_lookup(&hl, &key, lt_rhl_p);
		for (pos = l; pos; pos = rcu_dereference(pos->next))
			n++;
		rcu_read_unlock();
		ok = ok && n == (key < 3 ? 20 : 0);
	}
	check(ok, "rhltable_lookup(): 20 objects for each of keys 0, 1, 2 and none for key 3");
	for (i = 1, ok = 1; i < 30; i += 3)
		ok = ok && !rhltable_remove(&hl, &o[i].lnode, lt_rhl_p);
	key = 1;
	n = 0;
	rcu_read_lock();
	for (pos = rhltable_lookup(&hl, &key, lt_rhl_p); pos; pos = rcu_dereference(pos->next))
		n++;
	rcu_read_unlock();
	check(ok && n == 10, "rhltable_remove(): 10 of the 20 objects with key 1 removed, 10 left");
	lt_rh_freed = 0;
	rhltable_free_and_destroy(&hl, lt_rh_free_fn, NULL);
	check(lt_rh_freed == M - 10, "rhltable_free_and_destroy(): the callback runs for each of the 50 objects left, list members included");

	lt_rh_nested(10, fill10, ARRAY_SIZE(fill10), 1, 2, ~0U);
	lt_rh_nested(19, fill19, ARRAY_SIZE(fill19), 1, 1024, 4);
out:
	bitmap_free(seen);
	kfree(o);
}

/* lib/iov_iter: the ported bookkeeping (advance, revert, single_seg_count, alignment, gap_alignment, npages, restore); expected values worked out on paper */
static void __init test_iov_iter(void)
{
	unsigned long pg = __get_free_pages(GFP_KERNEL, 1);
	char *buf = (char *)pg;
	struct kvec kv[4];
	struct iovec uv[3];
	struct bio_vec bvs[2];
	struct iov_iter i, u, d, v, b;
	struct iov_iter_state st;
	struct page *p = alloc_page(GFP_KERNEL);

	if (!pg || !p)
		goto out;
	kv[0] = (struct kvec){ buf, 100 };
	kv[1] = (struct kvec){ buf + 4096, 0 };
	kv[2] = (struct kvec){ buf + 4100, 60 };
	kv[3] = (struct kvec){ buf + 8000, 192 };
	iov_iter_kvec(&i, ITER_DEST, kv, 4, 352);
	check(iov_iter_single_seg_count(&i) == 100, "iov_iter_single_seg_count(): the first kvec segment is 100");
	check((iov_iter_alignment(&i) & 0x1fff) == 0x1ffc, "iov_iter_alignment(kvec): OR of every base and length, low bits 0x1ffc");
	check(iov_iter_npages(&i, 100) == 3 && iov_iter_npages(&i, 2) == 2, "iov_iter_npages(kvec): 3 pages, capped at maxpages");
	iov_iter_advance(&i, 30);
	check(i.count == 322 && i.iov_offset == 30 && i.nr_segs == 4 && iov_iter_single_seg_count(&i) == 70, "iov_iter_advance(30): inside the first segment");
	iov_iter_advance(&i, 70);
	check(i.count == 252 && i.iov_offset == 0 && i.nr_segs == 2 && i.kvec == &kv[2] && iov_iter_single_seg_count(&i) == 60,
	      "iov_iter_advance(70): to the end of segment 0 skips the empty segment 1");
	iov_iter_advance(&i, 100);
	check(i.count == 152 && i.iov_offset == 40 && i.nr_segs == 1 && i.kvec == &kv[3] && iov_iter_single_seg_count(&i) == 152,
	      "iov_iter_advance(100): into the last segment, single_seg_count is the whole count");
	iov_iter_revert(&i, 41);
	check(i.count == 193 && i.iov_offset == 59 && i.nr_segs == 2 && i.kvec == &kv[2], "iov_iter_revert(41): back across a segment boundary");
	iov_iter_advance(&i, 1000000);
	check(i.count == 0, "iov_iter_advance(): clamped to the remaining count");

	iov_iter_ubuf(&u, ITER_DEST, (void __user *)0x1003, 5000);
	check(iov_iter_alignment(&u) == 0x138b && iov_iter_npages(&u, 10) == 2 && iov_iter_npages(&u, 1) == 1, "ubuf: alignment 0x138b, 2 pages (1 when capped)");
	iov_iter_advance(&u, 4000);
	check(u.count == 1000 && u.iov_offset == 4000, "iov_iter_advance(ubuf): offset and count");
	iov_iter_revert(&u, 4000);
	check(u.count == 5000 && u.iov_offset == 0, "iov_iter_revert(ubuf): back to the start");

	iov_iter_discard(&d, ITER_DEST, 1000);
	iov_iter_advance(&d, 300);
	iov_iter_revert(&d, 100);
	check(d.count == 800 && iov_iter_alignment(&d) == 0 && iov_iter_npages(&d, 10) == 0, "discard: advance 300, revert 100 -> 800, alignment 0, no pages");

	uv[0] = (struct iovec){ (void __user *)0x10000, 0x1000 };
	uv[1] = (struct iovec){ (void __user *)0x30000, 0x800 };
	uv[2] = (struct iovec){ (void __user *)0x50004, 0x100 };
	iov_iter_init(&v, ITER_DEST, uv, 3, 0x1900);
	check(iov_iter_gap_alignment(&v) == 0x71804, "iov_iter_gap_alignment(): OR of start | previous end between segments is 0x71804");
	/* restore on an iovec (a kvec makes upstream WARN, by its own parenthesisation) */
	st.iov_offset = v.iov_offset;
	st.count = v.count;
	st.nr_segs = v.nr_segs;
	iov_iter_advance(&v, 0x1900 - 0x100);
	check(v.nr_segs == 1 && v.__iov == &uv[2], "iov_iter_advance(iovec): to the last segment");
	iov_iter_restore(&v, &st);
	check(v.count == 0x1900 && v.iov_offset == 0 && v.nr_segs == 3 && v.__iov == &uv[0], "iov_iter_restore(): back to the state saved at the start, segment pointer and all");

	bvs[0] = (struct bio_vec){ p, 1000, 100 };
	bvs[1] = (struct bio_vec){ p, 4096, 0 };
	iov_iter_bvec(&b, ITER_DEST, bvs, 2, 5096);
	check(iov_iter_alignment(&b) == 0x13ec && iov_iter_npages(&b, 10) == 2, "bvec: alignment 0x13ec, 2 pages");
	iov_iter_advance(&b, 1500);
	check(b.count == 3596 && b.iov_offset == 500 && b.nr_segs == 1 && b.bvec == &bvs[1], "iov_iter_advance(bvec): into the second segment");
	iov_iter_revert(&b, 600);
	check(b.count == 4196 && b.iov_offset == 900 && b.nr_segs == 2 && b.bvec == &bvs[0], "iov_iter_revert(bvec): back into the first segment");
out:
	if (p)
		__free_page(p);
	if (pg)
		free_pages(pg, 1);
}

/* lib/rcuref: the non-warning paths, worked out on paper (saturation and imbalanced put() WARN by design and are covered in userspace) */
/* lib/refcount: the non-warning paths on paper; the saturation / underflow warnings are compared against upstream in port/test/refcount (a WARN here would trip the checker) */
static void __init test_refcount(void)
{
	refcount_t r;
	static DEFINE_MUTEX(m);
	static DEFINE_SPINLOCK(sp);
	unsigned long fl;

	refcount_set(&r, 1);
	check(refcount_dec_if_one(&r) && refcount_read(&r) == 0, "refcount_dec_if_one(): 1 -> 0 succeeds");
	refcount_set(&r, 2);
	check(!refcount_dec_if_one(&r) && refcount_read(&r) == 2, "refcount_dec_if_one(): 2 is left alone");
	refcount_set(&r, 3);
	check(refcount_dec_not_one(&r) && refcount_read(&r) == 2 && refcount_dec_not_one(&r) && refcount_read(&r) == 1,
	      "refcount_dec_not_one(): 3 -> 2 -> 1");
	check(!refcount_dec_not_one(&r) && refcount_read(&r) == 1, "refcount_dec_not_one(): the last reference is not dropped");
	refcount_set(&r, REFCOUNT_SATURATED);
	check(refcount_dec_not_one(&r) && refcount_read(&r) == REFCOUNT_SATURATED, "refcount_dec_not_one(): a saturated count stays saturated and reports true");
	refcount_set(&r, 2);
	check(!refcount_dec_and_mutex_lock(&r, &m) && refcount_read(&r) == 1 && !mutex_is_locked(&m), "refcount_dec_and_mutex_lock(): 2 -> 1, mutex not taken");
	check(refcount_dec_and_mutex_lock(&r, &m) && refcount_read(&r) == 0 && mutex_is_locked(&m), "refcount_dec_and_mutex_lock(): the last put returns holding the mutex");
	mutex_unlock(&m);
	refcount_set(&r, 2);
	check(!refcount_dec_and_lock(&r, &sp) && refcount_read(&r) == 1, "refcount_dec_and_lock(): 2 -> 1, lock not held");
	check(refcount_dec_and_lock(&r, &sp) && refcount_read(&r) == 0 && spin_is_locked(&sp), "refcount_dec_and_lock(): the last put returns holding the spinlock");
	spin_unlock(&sp);
	refcount_set(&r, 1);
	check(refcount_dec_and_lock_irqsave(&r, &sp, &fl) && refcount_read(&r) == 0, "refcount_dec_and_lock_irqsave(): the last put returns holding the lock, irqs off");
	spin_unlock_irqrestore(&sp, fl);
}

struct lwq_tn { struct lwq_node n; int v; };

/* lib/lwq: FIFO order worked out on paper: llist pushes at the head, the consumer takes `new`, reverses it into `ready`, and hands entries out one by one */
static void __init test_lwq(void)
{
	struct lwq q;
	struct lwq_tn a = { .v = 1 }, b = { .v = 2 }, c = { .v = 3 }, d = { .v = 4 }, e = { .v = 5 };
	struct lwq_tn *t;
	struct llist_node *l;
	int order[6], n = 0;

	lwq_init(&q);
	check(lwq_empty(&q) && !lwq_dequeue(&q, struct lwq_tn, n) && !lwq_dequeue_all(&q), "lwq: an empty queue dequeues nothing");
	check(lwq_enqueue(&a.n, &q) && !lwq_enqueue(&b.n, &q) && !lwq_enqueue(&c.n, &q) && !lwq_empty(&q),
	      "lwq_enqueue(): true only for the entry that finds the queue empty");
	t = lwq_dequeue(&q, struct lwq_tn, n);
	check(t == &a, "lwq_dequeue(): first in, first out (a)");
	t = lwq_dequeue(&q, struct lwq_tn, n);
	check(t == &b, "lwq_dequeue(): second (b), served from the ready list");
	lwq_enqueue(&d.n, &q);
	t = lwq_dequeue(&q, struct lwq_tn, n);
	check(t == &c, "lwq_dequeue(): the ready list is drained (c) before the newer entry");
	t = lwq_dequeue(&q, struct lwq_tn, n);
	check(t == &d && lwq_empty(&q) && !lwq_dequeue(&q, struct lwq_tn, n), "lwq_dequeue(): then the new entry (d), and the queue is empty again");

	lwq_enqueue(&a.n, &q);
	lwq_enqueue(&b.n, &q);
	lwq_enqueue(&c.n, &q);
	lwq_dequeue(&q, struct lwq_tn, n);			/* a: ready = b -> c */
	lwq_enqueue(&d.n, &q);
	lwq_enqueue(&e.n, &q);
	l = lwq_dequeue_all(&q);
	for (; l; l = l->next)
		order[n++] = container_of(l, struct lwq_tn, n.node)->v;
	check(n == 4 && order[0] == 2 && order[1] == 3 && order[2] == 4 && order[3] == 5 && lwq_empty(&q),
	      "lwq_dequeue_all(): ready (b, c) then the new entries in arrival order (d, e), queue empty afterwards");
}

/* lib/idr (IDA half): worked out on paper. Fresh IDA: ids 0,1,2 come out in order; freeing 1 makes it the next one; find_first sees the lowest used id at or above min.
 * A value entry holds 63 bits, so id 63 is the first one that needs a real bitmap (bit 63 of chunk 0); asking for exactly [63,63] twice gives 63 then -ENOSPC. 1024 ids
 * fill chunk 0, so the next free id is 1024. Arguments above INT_MAX are -ENOSPC (min) or clamp (max); max < min is -ENOSPC. ida_destroy() empties it.
 * (Found a real bug on its first run: xarray_rs.rs hard-coded __GFP_BITS_SHIFT, so the free mark of a C-initialised IDA was never seen and the first id was 1024.) */
static void __init test_ida(void)
{
	struct ida ida;
	int i, a, b, c, d, e, f, g = 0, h;

	ida_init(&ida);
	a = ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL);
	b = ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL);
	c = ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL);
	check(a == 0 && b == 1 && c == 2, "ida_alloc_range(): 0, 1, 2 in order");
	ida_free(&ida, 1);
	d = ida_alloc_range(&ida, 0, 10, GFP_KERNEL);
	check(d == 1, "ida_alloc_range(): a freed id is handed out again");
	check(ida_find_first_range(&ida, 0, UINT_MAX) == 0 && ida_find_first_range(&ida, 1, UINT_MAX) == 1 &&
	      ida_find_first_range(&ida, 3, UINT_MAX) == -ENOENT &&
	      ida_find_first_range(&ida, 0x80000000u, UINT_MAX) == -EINVAL, "ida_find_first_range(): lowest used id >= min, -ENOENT past the end, -EINVAL for min > INT_MAX");
	e = ida_alloc_range(&ida, 63, 63, GFP_KERNEL);
	f = ida_alloc_range(&ida, 63, 63, GFP_KERNEL);
	check(e == 63 && f == -ENOSPC, "ida_alloc_range(): id 63 (first bit outside a value entry) once, then -ENOSPC");
	check(ida_find_first_range(&ida, 4, UINT_MAX) == 63 && ida_find_first_range(&ida, 64, UINT_MAX) == -ENOENT, "ida_find_first_range(): finds the id kept in a real bitmap");
	check(ida_alloc_range(&ida, 0x80000000u, UINT_MAX, GFP_KERNEL) == -ENOSPC && ida_alloc_range(&ida, 10, 5, GFP_KERNEL) == -ENOSPC,
	      "ida_alloc_range(): min > INT_MAX and max < min are -ENOSPC");
	ida_free(&ida, 63);
	for (i = 0; i < 1021; i++)
		g = ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL);		/* 3..1023 */
	h = ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL);
	check(g == 1023 && h == 1024, "ida_alloc_range(): chunk 0 holds ids 0..1023, the next id is 1024");
	ida_free(&ida, 500);
	check(ida_alloc_range(&ida, 0, UINT_MAX, GFP_KERNEL) == 500 && ida_alloc_range(&ida, 0, 1500, GFP_KERNEL) == 1025,
	      "ida_alloc_range(): a full chunk is skipped, a freed id in it is found again");
	check(ida_find_first_range(&ida, 1024, UINT_MAX) == 1024, "ida_find_first_range(): second chunk");
	ida_destroy(&ida);
	check(ida_is_empty(&ida) && ida_find_first_range(&ida, 0, UINT_MAX) == -ENOENT, "ida_destroy(): empties the IDA");
}

/* lib/klist: worked out on paper. Add 1 at the tail, 2 at the tail, 0 at the head, 3 behind 1, 4 before 2: order 0 1 3 4 2. An iterator holds a reference on its current node, so
 * deleting that node marks it dead but keeps it linked and calls no put() until the iterator moves on; dead nodes are skipped. */
struct kl_tn { struct klist_node n; int id; };
static int kl_gets __initdata, kl_puts __initdata, kl_put_last __initdata;
static void __init kl_get(struct klist_node *n) { kl_gets++; }
static void __init kl_put(struct klist_node *n) { kl_puts++; kl_put_last = container_of(n, struct kl_tn, n)->id; }

static void __init test_klist(void)
{
	static struct kl_tn t[5] __initdata = { { .id = 0 }, { .id = 1 }, { .id = 2 }, { .id = 3 }, { .id = 4 } };
	struct klist k;
	struct klist_iter it;
	struct klist_node *n;
	int order[8], cnt = 0;

	klist_init(&k, kl_get, kl_put);
	klist_add_tail(&t[1].n, &k);
	klist_add_tail(&t[2].n, &k);
	klist_add_head(&t[0].n, &k);
	klist_add_behind(&t[3].n, &t[1].n);
	klist_add_before(&t[4].n, &t[2].n);
	check(kl_gets == 5 && klist_node_attached(&t[0].n),
	      "klist_add_*(): get() called once per node, nodes are attached");
	klist_iter_init(&k, &it);
	while ((n = klist_next(&it)))
		order[cnt++] = container_of(n, struct kl_tn, n)->id;
	klist_iter_exit(&it);
	check(cnt == 5 && order[0] == 0 && order[1] == 1 && order[2] == 3 && order[3] == 4 && order[4] == 2, "klist_next(): order 0 1 3 4 2");
	cnt = 0;
	klist_iter_init(&k, &it);
	while ((n = klist_prev(&it)))
		order[cnt++] = container_of(n, struct kl_tn, n)->id;
	klist_iter_exit(&it);
	check(cnt == 5 && order[0] == 2 && order[1] == 4 && order[2] == 3 && order[3] == 1 && order[4] == 0, "klist_prev(): order 2 4 3 1 0");
	klist_iter_init_node(&k, &it, &t[3].n);
	klist_del(&t[3].n);
	check(klist_node_attached(&t[3].n) && kl_puts == 0, "klist_del(): the iterator's reference keeps the node linked, no put() yet");
	n = klist_next(&it);
	check(n && container_of(n, struct kl_tn, n)->id == 4 && kl_puts == 1 && kl_put_last == 3 && !klist_node_attached(&t[3].n),
	      "klist_next(): leaves the dead node (put(3) now, unlinked) and goes to 4");
	klist_iter_exit(&it);
	klist_del(&t[0].n);
	check(kl_puts == 2 && kl_put_last == 0 && !klist_node_attached(&t[0].n), "klist_del(): no iterator, the node goes at once");
	klist_remove(&t[1].n);
	check(kl_puts == 3 && kl_put_last == 1 && !klist_node_attached(&t[1].n), "klist_remove(): returns once the node is gone");
	cnt = 0;
	klist_iter_init(&k, &it);
	while ((n = klist_next(&it)))
		order[cnt++] = container_of(n, struct kl_tn, n)->id;
	klist_iter_exit(&it);
	check(cnt == 2 && order[0] == 4 && order[1] == 2, "klist_next(): 4 and 2 are left");
	klist_del(&t[4].n);
	klist_del(&t[2].n);
	check(kl_puts == 5, "klist_del(): all five put()s done");
}

/* lib/radix-tree: worked out on paper. One entry sits directly in the root; a second at index 64 needs a 2-level tree (64 slots per node), 4096 a third level. Lookup returns what was
 * inserted, inserting at a used index is -EEXIST, gang lookups return entries in index order, a tag set on one index shows on that index only and on the root, and deleting
 * everything empties the tree (tags included). */
static void __init test_radix_tree(void)
{
	static int a[6] __initdata;
	RADIX_TREE(rt, GFP_KERNEL);
	void *res[8];
	void __rcu **slots[8];
	unsigned long big = ~0UL;

	check(radix_tree_insert(&rt, 0, &a[0]) == 0 && radix_tree_lookup(&rt, 0) == &a[0] && !radix_tree_lookup(&rt, 1), "radix_tree_insert(): a single entry at index 0");
	check(radix_tree_insert(&rt, 0, &a[1]) == -EEXIST, "radix_tree_insert(): a used index is -EEXIST");
	check(radix_tree_insert(&rt, 64, &a[1]) == 0 && radix_tree_lookup(&rt, 64) == &a[1] && radix_tree_lookup(&rt, 0) == &a[0], "radix_tree_insert(): index 64 grows the tree to two levels");
	check(radix_tree_insert(&rt, 4096, &a[2]) == 0 && radix_tree_lookup(&rt, 4096) == &a[2] && radix_tree_lookup(&rt, 64) == &a[1], "radix_tree_insert(): index 4096 grows it to three");
	check(radix_tree_gang_lookup(&rt, res, 0, 8) == 3 && res[0] == &a[0] && res[1] == &a[1] && res[2] == &a[2], "radix_tree_gang_lookup(): 3 entries in index order");
	check(radix_tree_gang_lookup(&rt, res, 1, 8) == 2 && res[0] == &a[1] && radix_tree_gang_lookup(&rt, res, 0, 2) == 2, "radix_tree_gang_lookup(): start index and max items honoured");
	check(radix_tree_tag_set(&rt, 64, 1) == &a[1] && radix_tree_tag_get(&rt, 64, 1) == 1 && radix_tree_tag_get(&rt, 0, 1) == 0 && radix_tree_tag_get(&rt, 64, 0) == 0 &&
	      radix_tree_tagged(&rt, 1) && !radix_tree_tagged(&rt, 0), "radix_tree_tag_set(): tag 1 on index 64 only, and on the root");
	check(radix_tree_gang_lookup_tag(&rt, res, 0, 8, 1) == 1 && res[0] == &a[1] && radix_tree_gang_lookup_tag_slot(&rt, slots, 0, 8, 1) == 1 && *slots[0] == &a[1] &&
	      radix_tree_gang_lookup_tag(&rt, res, 0, 8, 0) == 0, "radix_tree_gang_lookup_tag(): only the tagged entry");
	check(radix_tree_tag_clear(&rt, 64, 1) == &a[1] && !radix_tree_tagged(&rt, 1) && radix_tree_tag_get(&rt, 64, 1) == 0, "radix_tree_tag_clear(): the root's tag goes with the last tagged entry");
	check(radix_tree_delete_item(&rt, 4096, &a[3]) == NULL && radix_tree_lookup(&rt, 4096) == &a[2], "radix_tree_delete_item(): a different item deletes nothing");
	check(radix_tree_delete(&rt, 4096) == &a[2] && !radix_tree_lookup(&rt, 4096) && radix_tree_lookup(&rt, 64) == &a[1], "radix_tree_delete(): returns the entry, the others stay");
	check(radix_tree_insert(&rt, big, &a[4]) == 0 && radix_tree_lookup(&rt, big) == &a[4] && radix_tree_lookup(&rt, big - 1) == NULL, "radix_tree_insert(): index ULONG_MAX");
	check(radix_tree_delete(&rt, big) == &a[4] && radix_tree_delete(&rt, 64) == &a[1] && radix_tree_delete(&rt, 0) == &a[0] && !radix_tree_lookup(&rt, 0) &&
	      radix_tree_gang_lookup(&rt, res, 0, 8) == 0 && !radix_tree_delete(&rt, 0), "radix_tree_delete(): everything out, the tree is empty again");
}

/* lib/kobject: worked out on paper. Under /sys/kernel: "libtest_ko" (a kobject_create_and_add), a kset "libtest_ks" inside it, a kobject "x/y" added to the kset (the '/' becomes '!'),
 * and a plain kobject "k2" with its own ktype. Paths are the names joined by '/' from the top. */
static int ko_released __initdata;
static void __init ko_release(struct kobject *kobj) { ko_released++; }
static const struct kobj_type ko_ktype __initconst = { .release = ko_release, .sysfs_ops = &kobj_sysfs_ops };

static void __init test_kobject(void)
{
	static struct kobject k2 __initdata, k3 __initdata;
	struct kobject *top, *mid, *got;
	struct kset *ks;
	char *path;
	int r;

	top = kobject_create_and_add("libtest_ko", kernel_kobj);
	check(top && kref_read(&top->kref) == 1 && top->parent == kernel_kobj, "kobject_create_and_add(): one reference, parent is /sys/kernel");
	if (!top)
		return;
	path = kobject_get_path(top, GFP_KERNEL);
	check(path && !strcmp(path, "/kernel/libtest_ko"), "kobject_get_path(): /kernel/libtest_ko");
	kfree(path);
	ks = kset_create_and_add("libtest_ks", NULL, top);
	check(ks && ks->kobj.parent == top && kref_read(&top->kref) == 2, "kset_create_and_add(): the kset holds a reference on its parent");
	if (!ks) {
		kobject_put(top);
		return;
	}
	k3.kset = ks;
	r = kobject_init_and_add(&k3, &ko_ktype, NULL, "x/%s", "y");
	check(r == 0 && !strcmp(kobject_name(&k3), "x!y") && k3.parent == &ks->kobj && kref_read(&ks->kobj.kref) == 3,
	      "kobject_init_and_add(): '/' in the name becomes '!', the kset is the parent, and holds two references (parent + member)");
	path = kobject_get_path(&k3, GFP_KERNEL);
	check(path && !strcmp(path, "/kernel/libtest_ko/libtest_ks/x!y"), "kobject_get_path(): four levels");
	kfree(path);
	got = kset_find_obj(ks, "x!y");
	check(got == &k3 && kref_read(&k3.kref) == 2, "kset_find_obj(): finds the member and takes a reference");
	kobject_put(got);
	check(!kset_find_obj(ks, "nope"), "kset_find_obj(): NULL for an unknown name");
	r = kobject_init_and_add(&k2, &ko_ktype, top, "%s", "k2");
	check(r == 0 && k2.parent == top && kref_read(&top->kref) == 3, "kobject_init_and_add(): plain child of libtest_ko");
	kobject_get(&k2);
	r = kobject_rename(&k2, "k2b");
	path = kobject_get_path(&k2, GFP_KERNEL);
	check(r == 0 && path && !strcmp(path, "/kernel/libtest_ko/k2b") && kref_read(&k2.kref) == 2, "kobject_rename(): the path follows and no reference leaks");
	kfree(path);
	r = kobject_rename(&k2, "libtest_ks");
	check(r == -EEXIST, "kobject_rename(): a sibling with that name is -EEXIST");
	r = kobject_move(&k2, &ks->kobj);
	path = kobject_get_path(&k2, GFP_KERNEL);
	check(r == 0 && path && !strcmp(path, "/kernel/libtest_ko/libtest_ks/k2b") && k2.parent == &ks->kobj && kref_read(&top->kref) == 2,
	      "kobject_move(): new path, the old parent's reference is dropped");
	kfree(path);
	mid = kobject_get(&k2);
	kobject_del(&k2);
	check(!k2.state_in_sysfs && k2.parent == NULL && kref_read(&k2.kref) == 3 && ko_released == 0, "kobject_del(): out of sysfs, parent dropped, object still alive");
	check(kobject_get_unless_zero(mid) == mid, "kobject_get_unless_zero(): takes a reference on a live object");
	kobject_put(mid);
	kobject_put(mid);
	kobject_put(mid);
	check(ko_released == 0, "kobject_put(): not released while a reference is left");
	kobject_put(&k2);
	check(ko_released == 1, "kobject_put(): last reference calls release()");
	kobject_put(&k3);
	check(ko_released == 2 && kref_read(&ks->kobj.kref) == 1 && kref_read(&top->kref) == 2, "kobject_put(): the member leaves the kset and gives its references back");
	kset_unregister(ks);
	check(kref_read(&top->kref) == 1, "kset_unregister(): the kset is gone and so is its reference on libtest_ko");
	kobject_put(top);
	check(!kobject_get_unless_zero(NULL), "kobject_get_unless_zero(NULL): NULL");
	check(!kobj_ns_type_registered(KOBJ_NS_TYPE_NONE) && !kobj_ns_type_registered(KOBJ_NS_TYPES), "kobj_ns_type_registered(): none and out-of-range are not registered");
	{
		static const struct kobj_ns_type_operations bad __initconst = { .type = KOBJ_NS_TYPE_NONE };
		static const struct kobj_ns_type_operations bad2 __initconst = { .type = KOBJ_NS_TYPES };

		check(kobj_ns_type_register(&bad) == -EINVAL && kobj_ns_type_register(&bad2) == -EINVAL, "kobj_ns_type_register(): none and out-of-range are -EINVAL");
	}
}

/* lib/kobject_uevent: kobject_synth_uevent() on a kobject that is a member of a kset (an uevent needs a kset up the parent chain). A valid action alone, or with a UUID and
 * KEY=VALUE pairs, is sent (0); an unknown action word or a bad UUID/pair is -EINVAL. */
static void __init test_kobject_uevent(void)
{
	static const char ok[] = "change 0123abcd-4567-89ab-cdef-0123456789ab K1=v1 K2=v2\n";
	static const char baduuid[] = "change 0123abcd-4567-89ab-cdef-0123456789a\n";
	static const char badpair[] = "add 0123abcd-4567-89ab-cdef-0123456789ab K1\n";
	static struct kobject m __initdata;
	struct kset *ks = kset_create_and_add("libtest_ue", NULL, kernel_kobj);

	if (!ks) {
		check(0, "test_kobject_uevent(): kset_create_and_add");
		return;
	}
	m.kset = ks;
	if (kobject_init_and_add(&m, &ko_ktype, NULL, "m")) {
		check(0, "test_kobject_uevent(): kobject_init_and_add");
		kobject_put(&m);
		kset_unregister(ks);
		return;
	}
	check(kobject_synth_uevent(&m, "change\n", 7) == 0, "kobject_synth_uevent(): a bare action is sent");
	check(kobject_synth_uevent(&m, ok, sizeof(ok) - 1) == 0, "kobject_synth_uevent(): action, UUID and two KEY=VALUE pairs are sent");
	check(kobject_synth_uevent(&m, "bogus", 5) == -EINVAL && kobject_synth_uevent(&m, "ad", 2) == -EINVAL && kobject_synth_uevent(&m, "\n", 1) == -EINVAL,
	      "kobject_synth_uevent(): an unknown, short or empty action is -EINVAL");
	check(kobject_synth_uevent(&m, baduuid, sizeof(baduuid) - 1) == -EINVAL, "kobject_synth_uevent(): a UUID one character short is -EINVAL");
	check(kobject_synth_uevent(&m, badpair, sizeof(badpair) - 1) == -EINVAL, "kobject_synth_uevent(): a KEY with no =VALUE is -EINVAL");
	kobject_put(&m);
	kset_unregister(ks);
}

/* lib/argv_split: worked out on paper. Whitespace is the kernel's isspace(), which includes 0xa0: "  a\tb\xa0c \n" is three words. */
static void __init test_argv_split(void)
{
	int argc = -1;
	char **v = argv_split(GFP_KERNEL, "  a\tb\xa0" "c \n", &argc);

	check(v && argc == 3 && !strcmp(v[0], "a") && !strcmp(v[1], "b") && !strcmp(v[2], "c") && v[3] == NULL, "argv_split(): three words around tab, 0xa0, space and newline, NULL-terminated");
	if (v)
		argv_free(v);
	v = argv_split(GFP_KERNEL, "", &argc);
	check(v && argc == 0 && v[0] == NULL, "argv_split(): the empty string is no words");
	if (v)
		argv_free(v);
	v = argv_split(GFP_KERNEL, " \t ", NULL);
	check(v && v[0] == NULL, "argv_split(): only whitespace is no words, and argcp may be NULL");
	if (v)
		argv_free(v);
	v = argv_split(GFP_KERNEL, "one", &argc);
	check(v && argc == 1 && !strcmp(v[0], "one") && v[1] == NULL, "argv_split(): one word");
	if (v)
		argv_free(v);
}

/* kernel/time/ntp: a read-only adjtimex() (modes 0) reports the NTP state without changing it. At this point of boot nothing has synchronised the clock: STA_UNSYNC is set, so the
 * result is TIME_ERROR; precision is 1 and the tolerance MAXFREQ_SCALED / PPM_SCALE = (500000 << 32) / (1000 << 16) = 32768000; the tick is USER_TICK_USEC (10000 with USER_HZ 100);
 * the PLL time constant starts at 2; the microsecond field is below 10^6 unless STA_NANO is set. */
static void __init test_ntp(void)
{
	struct __kernel_timex tx = {};
	int r = do_adjtimex(&tx);

	check(r == TIME_ERROR && (tx.status & STA_UNSYNC), "do_adjtimex(): an unsynchronised clock reports TIME_ERROR with STA_UNSYNC");
	check(tx.precision == 1 && tx.tolerance == 32768000, "do_adjtimex(): precision 1 and tolerance 32768000");
	check(tx.tick == 10000 && tx.constant == 2, "do_adjtimex(): the tick is 10000 us and the PLL time constant 2");
	check((tx.status & STA_NANO) || (tx.time.tv_usec >= 0 && tx.time.tv_usec < 1000000), "do_adjtimex(): the microsecond field is a microsecond field");
	check(tx.maxerror > 0 && tx.maxerror <= 16000000 && tx.esterror > 0 && tx.esterror <= 16000000, "do_adjtimex(): the error estimates are within the phase limit");
}

/* kernel/time/clocksource: the mult/shift pairs worked out on paper. 32768 Hz to ns: 10^9 / 32768 * 2^17 = 4 * 10^9, below 2^32 (shift 18 would not fit). 1 GHz to ns over 10 s:
 * 10 * 10^9 >> 32 = 2, two bits, so mult must stay below 2^30 and the ratio is 1: mult 2^29, shift 29. max_nsecs with mult = 2^24, shift 24, no adjustment and a 64-bit mask:
 * ULLONG_MAX / 2^24 = 2^40 - 1 cycles, which are as many ns, halved. __clocksource_update_freq_scale() on a private 24 kHz source with scale 1000 and a 56-bit mask. */
static void __init test_clocksource(void)
{
	u32 mult = 0, shift = 0;
	u64 cyc = 0, ns;
	struct clocksource cs = { .name = "libtest-cs", .mask = (1ULL << 56) - 1 };

	clocks_calc_mult_shift(&mult, &shift, 32768, 1000000000, 600);
	check(mult == 4000000000u && shift == 17, "clocks_calc_mult_shift(32768 Hz -> ns, 600 s): mult 4e9, shift 17");
	clocks_calc_mult_shift(&mult, &shift, 1000000000, 1000000000, 10);
	check(mult == (1u << 29) && shift == 29, "clocks_calc_mult_shift(1 GHz -> ns, 10 s): mult 2^29, shift 29");
	clocks_calc_mult_shift(&mult, &shift, 3579545, 1000000000, 3600);
	check(mult == 585871109u && shift == 21, "clocks_calc_mult_shift(3.579545 MHz -> ns, 3600 s): mult 585871109, shift 21");

	ns = clocks_calc_max_nsecs(1u << 24, 24, 0, ~0ULL, &cyc);
	check(ns == (1ULL << 39) - 1 && cyc == (1ULL << 40) - 1, "clocks_calc_max_nsecs(2^24, 24, 0, ~0): 2^39 - 1 ns from 2^40 - 1 cycles");
	ns = clocks_calc_max_nsecs(1u << 24, 24, 0, 0xffffffffULL, NULL);
	check(ns == 0xffffffffULL >> 1, "clocks_calc_max_nsecs() with a 32-bit mask: the mask limits it, halved");

	__clocksource_update_freq_scale(&cs, 1000, 24000);
	check(cs.mult == 699050667u && cs.shift == 24 && cs.maxadj == 76895573u, "__clocksource_update_freq_scale(24 kHz): mult 699050667, shift 24, maxadj 11 %");
	check(cs.max_cycles == 0x588fe9dc0ULL && cs.max_idle_ns == 440795202592ULL, "__clocksource_update_freq_scale(24 kHz): max_cycles and max_idle_ns");
	check(cs.max_raw_delta == 0xdffffffffffffdULL && cs.uncertainty_margin >= 2 * 62000, "__clocksource_update_freq_scale(24 kHz): max_raw_delta 0.875 of the mask, margin floored");
}

/* kernel/time/clockevents: clockevent_delta2ns() on a private device. mult = 2^20 at shift 20 is one tick per ns: 5000 ticks are 5000 ns. mult 3 at shift 1 is 1.5 ticks per ns: 2000
 * ticks are 2000 * 2 / 3 = 1333.33 ns, rounded up to 1334 so the way back (1334 * 3 >> 1 = 2001) is not short. Fewer than 1000 ns is raised to 1000. A latch whose shift overflows 64 bits
 * saturates the product at 2^64 - 1, and (2^64 - 1) / 2^20 = 2^44 - 1. */
static void __init test_clockevents(void)
{
	struct clock_event_device ev = { .mult = 1u << 20, .shift = 20 };

	check(clockevent_delta2ns(5000, &ev) == 5000, "clockevent_delta2ns(5000 ticks at 1 tick/ns): 5000 ns");
	check(clockevent_delta2ns(10, &ev) == 1000, "clockevent_delta2ns(10 ticks): raised to 1000 ns");
	ev.mult = 3;
	ev.shift = 1;
	check(clockevent_delta2ns(2000, &ev) == 1334, "clockevent_delta2ns(2000 ticks at 1.5 ticks/ns): 1334 ns, rounded up");
	ev.mult = 1u << 20;
	ev.shift = 40;
	check(clockevent_delta2ns(1UL << 30, &ev) == (1ULL << 44) - 1, "clockevent_delta2ns(): a latch whose shift overflows saturates the product");
}

/* kernel/time/timer: round_jiffies() and round_jiffies_up() on this CPU (the skew is 3 jiffies per CPU number, added before rounding and removed after). With k the CPU number and a
 * target 20 s ahead whose skewed value is a whole second plus rem: rem below a quarter second rounds down to the second (j - rem), rem of exactly a quarter second or more rounds up
 * (j - rem + HZ), and round_jiffies_up() always rounds up. A rounded value that would not be in the future is not used: the original comes back. */
static void __init test_timer(void)
{
	unsigned long base, j, cpu_skew;
	int cpu;

	preempt_disable();
	cpu = smp_processor_id();
	cpu_skew = cpu * 3;
	base = (jiffies / HZ + 20) * HZ;

	j = base + 5 - cpu_skew;
	check(round_jiffies(j) == j - 5, "round_jiffies(): 5 jiffies after a second rounds down");
	check(round_jiffies_up(j) == j - 5 + HZ, "round_jiffies_up(): 5 jiffies after a second rounds up");
	j = base + HZ / 4 - cpu_skew;
	check(round_jiffies(j) == j - HZ / 4 + HZ, "round_jiffies(): a quarter second after a second rounds up");
	j = base + HZ / 4 - 1 - cpu_skew;
	check(round_jiffies(j) == j - (HZ / 4 - 1), "round_jiffies(): just under a quarter second rounds down");
	j = base - cpu_skew;
	check(round_jiffies(j) == j && round_jiffies_up(j) == j + HZ, "round_jiffies(): an exact second stays, round_jiffies_up() moves it a second on");
	j = (jiffies / HZ - 5) * HZ + HZ / 4 - cpu_skew;
	check(round_jiffies(j) == j, "round_jiffies(): a target whose rounded value is in the past comes back unchanged");
	preempt_enable();
}

/* kernel/sysctl: the integer handlers on private tables with kernel buffers. Writing "  12 -3\n" to a two-int table stores 12 and -3; reading gives "12\t-3\n" (the separator is a tab, the
 * line ends in a newline). "0x10" is 16 (base 0), "-0" is 0, a third number beyond the table is ignored. proc_dointvec_minmax() refuses a value outside [extra1, extra2] and leaves the
 * variable alone. proc_dointvec_jiffies() stores seconds times HZ and reads them back as seconds. A number with more than 20 digits is refused, 4294967296 does not fit an unsigned. A read
 * into a 3-byte buffer is cut after "12\t". */
static void __init test_sysctl(void)
{
	int iv[2] = { 0, 0 }, one = 0, lo = 1, hi = 10, jf = 0;
	unsigned int uv = 0;
	unsigned long lv = 0;
	struct ctl_table t2 = { .procname = "t2", .data = iv, .maxlen = sizeof(iv) };
	struct ctl_table t1 = { .procname = "t1", .data = &one, .maxlen = sizeof(one), .extra1 = &lo, .extra2 = &hi };
	struct ctl_table tj = { .procname = "tj", .data = &jf, .maxlen = sizeof(jf) };
	struct ctl_table tu = { .procname = "tu", .data = &uv, .maxlen = sizeof(uv) };
	struct ctl_table tl = { .procname = "tl", .data = &lv, .maxlen = sizeof(lv) };
	char w1[] = "  12 -3\n", w2[] = "0x10 -0 7", w3[] = "11", w4[] = "5\n", w5[] = "4294967296", w6[] = "123456789012345678901", w7[] = "4294967295", w8[] = "99\n", out[16];
	size_t len;
	loff_t pos;
	int r;

	len = sizeof(w1) - 1; pos = 0;
	r = proc_dointvec(&t2, 1, w1, &len, &pos);
	check(r == 0 && iv[0] == 12 && iv[1] == -3 && len == sizeof(w1) - 1, "proc_dointvec(write \"  12 -3\\n\"): 12 and -3");
	memset(out, 0, sizeof(out)); len = sizeof(out); pos = 0;
	r = proc_dointvec(&t2, 0, out, &len, &pos);
	check(r == 0 && len == 6 && !memcmp(out, "12\t-3\n", 6), "proc_dointvec(read): \"12<TAB>-3<NL>\"");
	memset(out, 0, sizeof(out)); len = 3; pos = 0;
	r = proc_dointvec(&t2, 0, out, &len, &pos);
	check(r == 0 && len == 3 && !memcmp(out, "12\t", 3), "proc_dointvec(read into 3 bytes): cut after \"12<TAB>\"");
	len = sizeof(w2) - 1; pos = 0;
	r = proc_dointvec(&t2, 1, w2, &len, &pos);
	check(r == 0 && iv[0] == 16 && iv[1] == 0, "proc_dointvec(write \"0x10 -0 7\"): 16 and 0, the third number ignored");

	len = sizeof(w3) - 1; pos = 0;
	r = proc_dointvec_minmax(&t1, 1, w3, &len, &pos);
	check(r == -EINVAL && one == 0, "proc_dointvec_minmax(write 11, range 1..10): -EINVAL and unchanged");
	len = sizeof(w4) - 1; pos = 0;
	r = proc_dointvec_minmax(&t1, 1, w4, &len, &pos);
	check(r == 0 && one == 5, "proc_dointvec_minmax(write 5): stored");

	len = sizeof(w4) - 1; pos = 0;
	r = proc_dointvec_jiffies(&tj, 1, w4, &len, &pos);
	check(r == 0 && jf == 5 * HZ, "proc_dointvec_jiffies(write 5): 5 * HZ");
	memset(out, 0, sizeof(out)); len = sizeof(out); pos = 0;
	r = proc_dointvec_jiffies(&tj, 0, out, &len, &pos);
	check(r == 0 && len == 2 && !memcmp(out, "5\n", 2), "proc_dointvec_jiffies(read): \"5<NL>\"");

	len = sizeof(w5) - 1; pos = 0;
	r = proc_douintvec(&tu, 1, w5, &len, &pos);
	check(r == -EINVAL && uv == 0, "proc_douintvec(write 4294967296): -EINVAL");
	len = sizeof(w7) - 1; pos = 0;
	r = proc_douintvec(&tu, 1, w7, &len, &pos);
	check(r == 0 && uv == 4294967295u, "proc_douintvec(write 4294967295): stored");
	len = sizeof(w6) - 1; pos = 0;
	r = proc_doulongvec_minmax(&tl, 1, w6, &len, &pos);
	check(r == -EINVAL && lv == 0, "proc_doulongvec_minmax(write 21 digits): -EINVAL");
	len = sizeof(w8) - 1; pos = 0;
	r = proc_doulongvec_minmax(&tl, 1, w8, &len, &pos);
	memset(out, 0, sizeof(out)); len = sizeof(out); pos = 0;
	r |= proc_doulongvec_minmax(&tl, 0, out, &len, &pos);
	check(r == 0 && lv == 99 && len == 3 && !memcmp(out, "99\n", 3), "proc_doulongvec_minmax: write 99, read \"99<NL>\"");
}

/* kernel/kallsyms on the real tables of this kernel: a function's name looks up its own address; an address a few bytes into it resolves back to the name with that offset and a size larger
 * than the offset; a name that does not exist gives 0; names are found through the binary search for a second, different function too. */
static void __init test_kallsyms(void)
{
	unsigned long a = (unsigned long)kallsyms_lookup_name, b = (unsigned long)sprint_symbol, size = 0, off = 0;
	char buf[KSYM_SYMBOL_LEN];

	check(kallsyms_lookup_name("kallsyms_lookup_name") == a, "kallsyms_lookup_name(\"kallsyms_lookup_name\") is the function's address");
	check(kallsyms_lookup_name("sprint_symbol") == b, "kallsyms_lookup_name(\"sprint_symbol\") is the function's address");
	check(kallsyms_lookup_name("no_such_symbol_in_this_kernel_xyz") == 0, "kallsyms_lookup_name(): an absent name gives 0");
	check(kallsyms_lookup_size_offset(a + 4, &size, &off) && off == 4 && size > 4, "kallsyms_lookup_size_offset(function + 4): offset 4, size above 4");
	sprint_symbol(buf, a + 4);
	check(!strncmp(buf, "kallsyms_lookup_name+0x4/0x", 27), "sprint_symbol(function + 4): \"kallsyms_lookup_name+0x4/0x...\"");
	sprint_symbol_no_offset(buf, b);
	check(!strcmp(buf, "sprint_symbol"), "sprint_symbol_no_offset(function): its name");
}

#ifdef CONFIG_AUDIT
/* kernel/auditfilter (full config only): the rule comparators and the path helpers, worked out by hand. Operator numbers are the Audit_* enum: equal 0, not_equal 1, bitmask 2, bittest 3, lt 4,
 * gt 5, le 6, ge 7. parent_len() keeps the slash that ends the parent: "/a/b/c" has parent "/a/b/" (5), "/a/b///" has "/a/" (3), a name without a slash has none (0), "/" has itself (1).
 * audit_compare_dname_path() compares the last component, ignoring trailing slashes: 0 is a match. */
extern int audit_comparator(u32 left, u32 op, u32 right);
extern int parent_len(const char *path);
extern int audit_compare_dname_path(const struct qstr *dname, const char *path, int parentlen);
static void __init test_auditfilter(void)
{
	struct qstr b = QSTR_INIT("b", 1), c = QSTR_INIT("c", 1);

	check(audit_comparator(3, 4, 5) && !audit_comparator(5, 4, 5) && audit_comparator(5, 6, 5) && !audit_comparator(6, 6, 5), "audit_comparator(): lt and le");
	check(audit_comparator(6, 5, 5) && !audit_comparator(5, 5, 5) && audit_comparator(5, 7, 5) && !audit_comparator(4, 7, 5), "audit_comparator(): gt and ge");
	check(audit_comparator(7, 0, 7) && !audit_comparator(7, 1, 7) && audit_comparator(7, 1, 8), "audit_comparator(): equal and not equal");
	check(audit_comparator(6, 2, 2) == 2 && !audit_comparator(4, 2, 2) && audit_comparator(7, 3, 6) && !audit_comparator(5, 3, 6) && !audit_comparator(1, 99, 1), "audit_comparator(): bitmask, bittest, unknown operator");
	check(parent_len("/a/b/c") == 5 && parent_len("/a/b///") == 3 && parent_len("name") == 0 && parent_len("/") == 1 && parent_len("") == 0, "parent_len(): the parent keeps its slash");
	check(audit_compare_dname_path(&b, "/a/b", -1) == 0 && audit_compare_dname_path(&b, "/a/b//", -1) == 0 && audit_compare_dname_path(&b, "/a/b", 3) == 0, "audit_compare_dname_path(): the last component matches");
	check(audit_compare_dname_path(&c, "/a/b", -1) != 0 && audit_compare_dname_path(&b, "/a/bb", -1) != 0 && audit_compare_dname_path(&b, "", -1) != 0, "audit_compare_dname_path(): a different name does not");
}
#endif

#ifdef CONFIG_EXT4_FS
/* fs/ext4/hash: ext4fs_dirhash() on a private directory inode. The empty name leaves the default seed untouched, so its hashes are worked out on paper: half-MD4 returns word 1 and word 2
 * (0xefcdab89 with the low bit cleared, 0x98badcfe), TEA returns word 0 and word 1 (0x67452301 cleared, 0xefcdab89). The others were taken from the C file on the same inputs
 * (the unsigned and signed versions agree on ASCII and differ on "\xe9t\xe9"). */
struct libtest_dx_hash_info { u32 hash; u32 minor_hash; int hash_version; u32 *seed; };
extern int ext4fs_dirhash(const struct inode *dir, const char *name, int len, struct libtest_dx_hash_info *hinfo);
static struct inode libtest_dir __initdata;
static struct super_block libtest_sb __initdata;
static void __init test_ext4_hash(void)
{
	static const struct { int ver; const char *name; u32 hash, minor; } t[] = {
		{ 1, "", 0xefcdab88, 0x98badcfe }, { 2, "", 0x67452300, 0xefcdab89 }, { 4, "", 0xefcdab88, 0x98badcfe }, { 5, "", 0x67452300, 0xefcdab89 },
		{ 0, "hello", 0x32252546, 0 }, { 3, "hello", 0x32252546, 0 }, { 1, "hello", 0x1746da32, 0x420013b5 }, { 2, "hello", 0x6f5bb1a8, 0x231917c2 },
		{ 1, "a.longer.filename.with.more.than.sixteen.characters.txt", 0x2046da16, 0x2167e1bc }, { 2, "a.longer.filename.with.more.than.sixteen.characters.txt", 0xf64db99e, 0x1ca333db },
		{ 0, "\xe9t\xe9", 0xcbfc35a2, 0 }, { 3, "\xe9t\xe9", 0xe3870ba0, 0 }, { 1, "\xe9t\xe9", 0x54289c74, 0xabf34552 }, { 4, "\xe9t\xe9", 0x050ac262, 0x416d5e12 },
	};
	int i, bad = 0;

	libtest_dir.i_sb = &libtest_sb;
	for (i = 0; i < ARRAY_SIZE(t); i++) {
		struct libtest_dx_hash_info h = { .hash_version = t[i].ver };
		int r = ext4fs_dirhash(&libtest_dir, t[i].name, strlen(t[i].name), &h);

		if (r || h.hash != t[i].hash || h.minor_hash != t[i].minor) {
			pr_err("libtest: ext4fs_dirhash(version %d, \"%s\") gave %d %08x %08x\n", t[i].ver, t[i].name, r, h.hash, h.minor_hash);
			bad++;
		}
	}
	check(bad == 0, "ext4fs_dirhash(): legacy, half-MD4 and TEA, signed and unsigned, on 14 inputs");
}
#endif

#ifdef CONFIG_SECURITY_SELINUX
/* security/selinux/ss/ebitmap: the extensible bitmap on private bitmaps (the node cache is set up by SELinux's init before libtest). The serialised form of {0, 1, 70, 500} is worked
 * out on paper: header (map size 64, last bit rounded up to 512, 3 nodes) then {start 0, map 0x3}, {start 64, map 1 << 6}, {start 448, map 1 << 52}; reading it back rounds the high bit
 * up to a multiple of 384 (768). The hashes and the high bits after clearing came from the C file on the same inputs (the C-only builds check them too). */
#include "../security/selinux/ss/ebitmap.h"
struct policy_file { char *data; size_t len; };
static void __init test_ebitmap(void)
{
	static const u32 bits[] = { 0, 1, 70, 500 }, off[] = { 2, 69, 71, 499, 501, 767, 768 }, big[] = { 0, 1, 63, 64, 383, 384, 800, 100000 };
	static const unsigned char want[48] = { 0x40, 0, 0, 0, 0, 2, 0, 0, 3, 0, 0, 0,  0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,  0x40, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0,
						0xc0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0 };
	struct ebitmap a, c, d, r, m, b;
	struct policy_file fp;
	unsigned char buf[100];
	unsigned int i;
	int bad = 0;

	ebitmap_init(&a); ebitmap_init(&c); ebitmap_init(&d); ebitmap_init(&b);
	for (i = 0; i < ARRAY_SIZE(bits); i++)
		bad += ebitmap_set_bit(&a, bits[i], 1) != 0;
	bad += a.highbit != 768;
	for (i = 0; i < ARRAY_SIZE(bits); i++)
		bad += ebitmap_get_bit(&a, bits[i]) != 1;
	for (i = 0; i < ARRAY_SIZE(off); i++)
		bad += ebitmap_get_bit(&a, off[i]) != 0;
	check(bad == 0, "ebitmap: set_bit / get_bit on {0, 1, 70, 500}: high bit 768, neighbours clear");

	check(ebitmap_hash(&a, 0) == 0x16d3b784 && ebitmap_hash(&a, 0x12345678) == 0x492e67b0 && ebitmap_hash(&c, 0) == 0x049396b8 && ebitmap_hash(&c, 0x12345678) == 0xf338518d,
	      "ebitmap_hash(): {0, 1, 70, 500} and the empty bitmap under two seeds");

	memset(buf, 0xaa, sizeof(buf));
	fp.data = (char *)buf; fp.len = sizeof(buf);
	bad = ebitmap_write(&a, &fp) != 0 || fp.len != sizeof(buf) - 48 || memcmp(buf, want, 48) || buf[48] != 0xaa;
	fp.data = (char *)buf; fp.len = 47;
	bad += ebitmap_write(&a, &fp) != -EINVAL;
	fp.data = (char *)buf; fp.len = 11;
	bad += ebitmap_write(&a, &fp) != -EINVAL;
	check(bad == 0, "ebitmap_write(): 48 bytes as worked out on paper; 47 and 11 bytes of room fail with -EINVAL");

	fp.data = (char *)want; fp.len = 48;
	bad = ebitmap_read(&r, &fp) != 0 || fp.len != 0 || r.highbit != 768 || !ebitmap_equal(&a, &r) || !ebitmap_contains(&r, &a, 0);
	ebitmap_destroy(&r);
	{	/* a stream of map size 32, a truncated one and one with an empty map */
		static const unsigned char m32[12] = { 32, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0 };
		static const unsigned char emap[24] = { 64, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };

		fp.data = (char *)m32; fp.len = 12;
		bad += ebitmap_read(&r, &fp) != -EINVAL || r.node || r.highbit;
		fp.data = (char *)want; fp.len = 36;
		bad += ebitmap_read(&r, &fp) != -EINVAL || r.node || r.highbit;
		fp.data = (char *)emap; fp.len = 24;
		bad += ebitmap_read(&r, &fp) != -EINVAL || r.node || r.highbit;
	}
	check(bad == 0, "ebitmap_read(): the written stream gives an equal bitmap (high bit 768); map size 32, a truncated stream and an empty map give -EINVAL and leave nothing");

	ebitmap_set_bit(&c, 1, 1); ebitmap_set_bit(&c, 70, 1);
	ebitmap_set_bit(&d, 1, 1); ebitmap_set_bit(&d, 71, 1);
	bad = ebitmap_contains(&a, &c, 0) != 1 || ebitmap_contains(&a, &c, 70) != 1 || ebitmap_contains(&a, &c, 69) != 0 || ebitmap_contains(&a, &d, 0) != 0 || ebitmap_contains(&c, &a, 0) != 0;
	bad += ebitmap_equal(&a, &c) || ebitmap_cpy(&m, &a) != 0 || !ebitmap_equal(&a, &m) || m.highbit != 768;
	bad += ebitmap_and(&r, &a, &d) != 0 || !ebitmap_get_bit(&r, 1) || ebitmap_get_bit(&r, 70) || ebitmap_get_bit(&r, 71) || r.highbit != 384;
	ebitmap_destroy(&m); ebitmap_destroy(&r);
	check(bad == 0, "ebitmap_contains() with and without a last-bit limit, ebitmap_equal(), ebitmap_cpy(), ebitmap_and()");

	bad = 0;
	for (i = 0; i < ARRAY_SIZE(big); i++)
		bad += ebitmap_set_bit(&b, big[i], 1) != 0;
	bad += b.highbit != 100224;
	ebitmap_set_bit(&b, 100000, 0);
	bad += b.highbit != 1152 || ebitmap_hash(&b, 0) != 0x730ba452;
	ebitmap_set_bit(&b, 800, 0);
	bad += b.highbit != 768 || ebitmap_hash(&b, 0) != 0x0c8fad4e;
	ebitmap_set_bit(&b, 384, 0);
	bad += b.highbit != 384 || !ebitmap_get_bit(&b, 383) || ebitmap_get_bit(&b, 384) || ebitmap_hash(&b, 0) != 0x5d91e8d9;
	ebitmap_set_bit(&b, 383, 0); ebitmap_set_bit(&b, 64, 0); ebitmap_set_bit(&b, 63, 0); ebitmap_set_bit(&b, 1, 0);
	bad += b.highbit != 384 || !b.node;
	ebitmap_set_bit(&b, 0, 0);
	bad += b.highbit != 0 || b.node;
	check(bad == 0, "ebitmap_set_bit(): clearing the last bit of a node drops the node and lowers the high bit (100224, 1152, 768, 384, 0)");
	ebitmap_destroy(&a); ebitmap_destroy(&c); ebitmap_destroy(&d); ebitmap_destroy(&b);
	check(!a.node && !a.highbit && !b.node, "ebitmap_destroy(): leaves an empty bitmap");
}
#endif

#ifdef CONFIG_ETHTOOL_NETLINK
/* net/ethtool/bitset: the u32-bitmap helpers and the bitset attribute size, all worked out on paper (and equal to the C file's results on the same inputs). Attribute sizes use
 * nla_total_size() = (payload + 4) rounded up to 4: a list bitset of {0, 2} in compact form is nest(list flag 8 + size 8 + value 8) = 28; verbose it adds two bit nests of 12 (index 8)
 * inside a bits nest of 28, so 48; with the names "x" and "abcd" the nests grow to 20 and 24 and the total is 68; as a value/mask pair 0b101 / 0b111 it is 60. */
#ifdef CONFIG_RUST
bool ethnl_bitmap32_not_zero(const u32 *map, unsigned int start, unsigned int end);
void ethnl_bitmap32_clear(u32 *dst, unsigned int start, unsigned int end, bool *mod);
void ethnl_bitmap32_update(u32 *dst, unsigned int nbits, const u32 *value, const u32 *mask, bool *mod);
bool ethnl_bitmap32_equal(const u32 *map1, const u32 *map2, unsigned int nbits);
#endif
int ethnl_bitset32_size(const u32 *val, const u32 *mask, unsigned int nbits, const char (*const names)[32], bool compact);
static void __init test_ethtool_bitset(void)
{
	u32 v[1] = { 5 }, mk[1] = { 7 };
	static const char names[3][32] = { "x", "", "abcd" };
#ifdef CONFIG_RUST	/* the C file keeps these helpers static */
	u32 m[3] = { ~0u, ~0u, ~0u }, w = ~0u, z[3] = { 0x100, 0, 0x80000000 }, d[2] = { 0xf0f0f0f0, 0 }, d2[2] = { 1, 2 }, val[2] = { ~0u, ~0u }, msk[2] = { 0xffff, 1 };
	u32 e1[2] = { 0x1ff, 5 }, e2[2] = { 0x1ff, 0xd };
	bool mod = false;
	int bad;

	ethnl_bitmap32_clear(m, 4, 70, &mod);
	bad = m[0] != 0x0000000f || m[1] != 0 || m[2] != 0xffffffc0 || !mod;
	mod = false;
	ethnl_bitmap32_clear(m, 4, 70, &mod);
	bad += mod;
	mod = false;
	ethnl_bitmap32_clear(&w, 8, 16, &mod);
	bad += w != 0xffff00ff || !mod;
	check(bad == 0, "ethnl_bitmap32_clear(): bits 4..69 of three words, a second clear changes nothing, bits 8..15 of one word");

	check(!ethnl_bitmap32_not_zero(z, 0, 8) && ethnl_bitmap32_not_zero(z, 0, 9) && !ethnl_bitmap32_not_zero(z, 9, 64) && !ethnl_bitmap32_not_zero(z, 9, 95) &&
	      ethnl_bitmap32_not_zero(z, 9, 96) && !ethnl_bitmap32_not_zero(z, 40, 50), "ethnl_bitmap32_not_zero(): bits 8 and 95 found exactly when the interval covers them");

	mod = false;
	ethnl_bitmap32_update(d, 40, val, msk, &mod);
	bad = d[0] != 0xf0f0ffff || d[1] != 1 || !mod;
	mod = false;
	ethnl_bitmap32_update(d2, 36, val, NULL, &mod);
	bad += d2[0] != 0xffffffff || d2[1] != 0xf || !mod;
	check(bad == 0, "ethnl_bitmap32_update(): value / mask pair over 40 bits, and no mask over 36 bits");

	check(ethnl_bitmap32_equal(e1, e2, 32) && ethnl_bitmap32_equal(e1, e2, 34) && !ethnl_bitmap32_equal(e1, e2, 36) && ethnl_bitmap32_equal(e1, e2, 31) && ethnl_bitmap32_equal(e1, e2, 0),
	      "ethnl_bitmap32_equal(): only the first nbits count");
#endif

	check(ethnl_bitset32_size(v, NULL, 3, NULL, true) == 28 && ethnl_bitset32_size(v, mk, 3, NULL, true) == 28 && ethnl_bitset32_size(v, NULL, 3, NULL, false) == 48 &&
	      ethnl_bitset32_size(v, NULL, 3, names, false) == 68 && ethnl_bitset32_size(v, mk, 3, NULL, false) == 60, "ethnl_bitset32_size(): compact 28 / 28, verbose 48, with names 68, value/mask 60");
}
#endif

#ifdef CONFIG_UNICODE
/* fs/unicode/utf8-norm: normalization through utf8-core.c on the shipped tables, worked out on paper from the Unicode data: e-acute (U+00E9) decomposes to e + U+0301; the
 * canonical combining classes are 230 for U+0301 and 220 for U+0323, so "a U+0301 U+0323" is reordered to "a U+0323 U+0301"; the Hangul syllables U+AC00 and U+AC01 decompose by
 * arithmetic into U+1100 U+1161 (and U+11A8); the case fold of U+00C4 is a + U+0308 (decomposed); a stray continuation byte is not UTF-8 text. */
#include <linux/unicode.h>
static void __init test_utf8_norm(void)
{
	struct unicode_map *um = utf8_load(UTF8_LATEST);
	unsigned char out[32];
	struct qstr q, q2;
	int bad = 0, n;

	if (IS_ERR(um)) {
		check(false, "utf8_load(UTF8_LATEST) gave a map");
		return;
	}
#define NORM(str, fn, want, wantlen) do {					\
		q = (struct qstr)QSTR_INIT(str, strlen(str));			\
		n = fn(um, &q, out, sizeof(out));				\
		if (n != (wantlen) || memcmp(out, want, wantlen + 1))		\
			bad++;							\
	} while (0)
	NORM("\xc3\xa9", utf8_normalize, "e\xcc\x81", 3);
	NORM("a\xcc\x81\xcc\xa3", utf8_normalize, "a\xcc\xa3\xcc\x81", 5);
	NORM("\xea\xb0\x80", utf8_normalize, "\xe1\x84\x80\xe1\x85\xa1", 6);
	NORM("\xea\xb0\x81", utf8_normalize, "\xe1\x84\x80\xe1\x85\xa1\xe1\x86\xa8", 9);
	NORM("Plain ASCII", utf8_normalize, "Plain ASCII", 11);
	NORM("\xc3\x84", utf8_casefold, "a\xcc\x88", 3);
	NORM("Stra\xc3\x9f" "e", utf8_casefold, "strasse", 7);
	check(bad == 0, "utf8_normalize() / utf8_casefold(): e-acute, reordered accents, two Hangul syllables, ASCII, A-diaeresis and sharp s");

	q = (struct qstr)QSTR_INIT("\x80z", 2);
	n = utf8_normalize(um, &q, out, sizeof(out));
	q = (struct qstr)QSTR_INIT("\xc3\xa9", 2);
	bad = n != -EINVAL || utf8_normalize(um, &q, out, 3) != -EINVAL || utf8_normalize(um, &q, out, 4) != 3;
	check(bad == 0, "utf8_normalize(): a stray continuation byte and a destination too small give -EINVAL; exactly enough room works");

	q = (struct qstr)QSTR_INIT("\xc3\xa9", 2);
	q2 = (struct qstr)QSTR_INIT("e\xcc\x81", 3);
	bad = utf8_strncmp(um, &q, &q2) != 0 || utf8_strncasecmp(um, &q, &q2) != 0;
	q2 = (struct qstr)QSTR_INIT("E\xcc\x81", 3);
	bad += utf8_strncmp(um, &q, &q2) != 1 || utf8_strncasecmp(um, &q, &q2) != 0;
	q = (struct qstr)QSTR_INIT("\xea\xb0\x80", 3);
	q2 = (struct qstr)QSTR_INIT("\xe1\x84\x80\xe1\x85\xa1", 6);
	bad += utf8_strncmp(um, &q, &q2) != 0;
	check(bad == 0, "utf8_strncmp() / utf8_strncasecmp(): composed equals decomposed, case differs only for the folding compare, Hangul syllable equals its jamo");

	{	/* the case-folded hash is the same for every spelling of a text, differs between texts, and a string that is not UTF-8 is refused without touching the hash */
		struct qstr h1 = QSTR_INIT("\xc3\x84", 2), h2 = QSTR_INIT("a\xcc\x88", 3), h3 = QSTR_INIT("\xc3\xa4", 2), h4 = QSTR_INIT("b", 1), h5 = QSTR_INIT("\x80", 1);
		int r1 = utf8_casefold_hash(um, NULL, &h1), r2 = utf8_casefold_hash(um, NULL, &h2), r3 = utf8_casefold_hash(um, NULL, &h3), r4 = utf8_casefold_hash(um, NULL, &h4);

		h5.hash = 0x1234;
		bad = r1 || r2 || r3 || r4 || h1.hash != h2.hash || h1.hash != h3.hash || h1.hash == h4.hash || utf8_casefold_hash(um, NULL, &h5) != -EINVAL || h5.hash != 0x1234;
		check(bad == 0, "utf8_casefold_hash(): A-diaeresis, a + U+0308 and a-diaeresis hash alike, b differently, a lone continuation byte gives -EINVAL and leaves the hash alone");
	}
	utf8_unload(um);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX
/* security/selinux/ss/avtab: the access vector table on private tables and a private policydb (version 34, 6 types, 4 classes; avtab.h and policydb.h cannot be included from lib/ --
 * they need the generated flask.h -- so the policydb is a zeroed buffer with the three fields avtab reads stored at the offsets avtab_glue.c asserts). The one-entry stream {key (1, 2, 3, ALLOWED), data 0xabcd}
 * is worked out on paper: entry count 1, then the four 16-bit key fields 1 2 3 1, then the 32-bit datum (little endian, 16 bytes); an extended-permission entry adds the specifier and
 * driver bytes and 8 words (46 bytes). The old format (version < 20) packs the key, a bit set of access vector kinds and one datum per kind into one entry: {6 items, 1, 2, 3,
 * ALLOWED | AUDITALLOW, 0x100, 0x200} gives ALLOWED 0x100 and AUDITALLOW 0x200. Slot counts: 2 rules -> 2, 8 -> 4, 100 -> 32, 1000 -> 256, huge -> 65536. */
struct avtab_key { u16 source_type, target_type, target_class, specified; };
struct avtab_extended_perms { u8 specified, driver; struct { u32 p[8]; } perms; };
struct avtab_datum { union { u32 data; struct avtab_extended_perms *xperms; } u; };
struct avtab_node { struct avtab_key key; struct avtab_datum datum; struct avtab_node *next; };
struct avtab { struct avtab_node **htable; u32 nel, nslot, mask; };
#define AVTAB_ALLOWED 0x1
#define AVTAB_AUDITALLOW 0x2
#define AVTAB_AUDITDENY 0x4
#define AVTAB_XPERMS_ALLOWED 0x100
#define AVTAB_ENABLED 0x8000
void avtab_init(struct avtab *h);
int avtab_alloc(struct avtab *h, u32 nrules);
void avtab_destroy(struct avtab *h);
int avtab_read(struct avtab *a, struct policy_file *fp, void *pol);
int avtab_write(void *p, struct avtab *a, struct policy_file *fp);
struct avtab_node *avtab_insert_nonunique(struct avtab *h, const struct avtab_key *key, const struct avtab_datum *datum);
struct avtab_node *avtab_search_node(struct avtab *h, const struct avtab_key *key);
struct avtab_node *avtab_search_node_next(struct avtab_node *node, u16 specified);
static char lt_pol[608] __aligned(8) __initdata;
#define LT_POL_VERS    592	/* offsetof(struct policydb, policyvers) */
#define LT_POL_CLASSES 48	/* p_classes.nprim */
#define LT_POL_TYPES   96	/* p_types.nprim */
static void __init lt_pol_set(unsigned int vers, unsigned int ntypes, unsigned int nclasses)
{
	*(unsigned int *)(lt_pol + LT_POL_VERS) = vers;
	*(unsigned int *)(lt_pol + LT_POL_TYPES) = ntypes;
	*(unsigned int *)(lt_pol + LT_POL_CLASSES) = nclasses;
}
static void __init test_avtab(void)
{
	static const unsigned char one[16] = { 1, 0, 0, 0,  1, 0, 2, 0, 3, 0, 1, 0,  0xcd, 0xab, 0, 0 };
	static const unsigned char dupl[28] = { 2, 0, 0, 0,  1, 0, 2, 0, 3, 0, 1, 0,  0xcd, 0xab, 0, 0,  1, 0, 2, 0, 3, 0, 1, 0,  0xef, 0xbe, 0, 0 };
	static const unsigned char badtype[16] = { 1, 0, 0, 0,  9, 0, 2, 0, 3, 0, 1, 0,  0xcd, 0xab, 0, 0 };
	static const unsigned char oldfmt[32] = { 1, 0, 0, 0,  6, 0, 0, 0,  1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,  3, 0, 0, 0,  0, 1, 0, 0,  0, 2, 0, 0 };
	static const u32 sizes[][2] = { { 0, 0 }, { 1, 2 }, { 3, 2 }, { 4, 2 }, { 5, 2 }, { 7, 2 }, { 8, 4 }, { 100, 32 }, { 1000, 256 }, { 200000, 65536 } };
	struct avtab t, t2;
	struct avtab_key k = { .source_type = 1, .target_type = 2, .target_class = 3, .specified = AVTAB_ALLOWED };
	struct avtab_datum d = { .u.data = 0xabcd };
	struct avtab_extended_perms x = { .specified = 1, .driver = 2 };
	struct avtab_node *n, *n2;
	struct policy_file fp;
	unsigned char buf[100];
	unsigned int i, s;
	int bad = 0;

	lt_pol_set(34, 6, 4);
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		avtab_init(&t);
		bad += avtab_alloc(&t, sizes[i][0]) != 0 || t.nslot != sizes[i][1] || t.mask != (sizes[i][1] ? sizes[i][1] - 1 : 0) || t.nel != 0;
		avtab_destroy(&t);
		bad += t.nslot || t.nel || t.mask || t.htable;
	}
	check(bad == 0, "avtab_alloc(): 0, 1, 3, 4, 5, 7, 8, 100, 1000 and 200000 rules give 0, 2, 2, 2, 2, 2, 4, 32, 256 and 65536 slots; destroy resets the table");

	avtab_init(&t);
	bad = avtab_search_node(&t, &k) != NULL || avtab_insert_nonunique(&t, &k, &d) != NULL;
	avtab_alloc(&t, 8);
	n = avtab_insert_nonunique(&t, &k, &d);
	bad += !n || t.nel != 1 || avtab_search_node(&t, &k) != n || n->datum.u.data != 0xabcd;
	d.u.data = 0x1234;
	n2 = avtab_insert_nonunique(&t, &k, &d);
	bad += !n2 || n2 == n || t.nel != 2 || avtab_search_node(&t, &k) != n2 || avtab_search_node_next(n2, AVTAB_ALLOWED) != n || avtab_search_node_next(n, AVTAB_ALLOWED) != NULL;
	k.specified = AVTAB_AUDITALLOW;
	bad += avtab_search_node(&t, &k) != NULL;
	k.specified = AVTAB_ALLOWED | AVTAB_ENABLED;
	bad += avtab_search_node(&t, &k) == NULL;
	k.specified = AVTAB_ALLOWED; k.target_class = 4;
	bad += avtab_search_node(&t, &k) != NULL;
	k.target_class = 3;
	check(bad == 0, "avtab_insert_nonunique() / avtab_search_node() / avtab_search_node_next(): same key twice (newest first), other specifier or class not found, the enabled flag ignored, empty table");

	avtab_destroy(&t);
	avtab_alloc(&t, 1);
	bad = 0;
	for (i = 0; i < 24; i++) {
		struct avtab_key kk = { .source_type = 1 + (i * 7) % 5, .target_type = 1 + (i * 3) % 4, .target_class = 1 + i % 3, .specified = AVTAB_ALLOWED };

		bad += !avtab_insert_nonunique(&t, &kk, &d);
	}
	bad += t.nel != 24 || t.nslot != 2;
	for (s = 0; s < t.nslot; s++)
		for (n = t.htable[s]; n && n->next; n = n->next)
			bad += n->key.source_type > n->next->key.source_type || (n->key.source_type == n->next->key.source_type && (n->key.target_type > n->next->key.target_type ||
			       (n->key.target_type == n->next->key.target_type && n->key.target_class > n->next->key.target_class)));
	check(bad == 0, "avtab_insert_nonunique(): 24 keys in a 2-slot table stay sorted by (source, target, class) inside each chain");
	avtab_destroy(&t);

	avtab_init(&t);
	avtab_alloc(&t, 4);
	d.u.data = 0xabcd;
	avtab_insert_nonunique(&t, &k, &d);
	memset(buf, 0xaa, sizeof(buf));
	fp.data = (char *)buf; fp.len = sizeof(buf);
	bad = avtab_write(lt_pol, &t, &fp) != 0 || fp.len != sizeof(buf) - 16 || memcmp(buf, one, 16) || buf[16] != 0xaa;
	fp.data = (char *)buf; fp.len = 15;
	bad += avtab_write(lt_pol, &t, &fp) != -EINVAL;
	avtab_init(&t2);
	fp.data = (char *)one; fp.len = 16;
	bad += avtab_read(&t2, &fp, lt_pol) != 0 || fp.len != 0 || t2.nel != 1 || !(n = avtab_search_node(&t2, &k)) || n->datum.u.data != 0xabcd;
	avtab_destroy(&t2);
	check(bad == 0, "avtab_write() / avtab_read(): the 16-byte stream worked out on paper both ways; 15 bytes of room fail with -EINVAL");

	avtab_destroy(&t);
	avtab_alloc(&t, 4);
	k.specified = AVTAB_XPERMS_ALLOWED;
	x.perms.p[0] = 0x11; x.perms.p[7] = 0x88;
	d.u.xperms = &x;
	avtab_insert_nonunique(&t, &k, &d);
	memset(buf, 0xaa, sizeof(buf));
	fp.data = (char *)buf; fp.len = sizeof(buf);
	bad = avtab_write(lt_pol, &t, &fp) != 0 || fp.len != sizeof(buf) - 46 || buf[4] != 1 || buf[10] != 0 || buf[11] != 1 || buf[12] != 1 || buf[13] != 2 || buf[14] != 0x11 || buf[42] != 0x88;
	avtab_init(&t2);
	fp.data = (char *)buf; fp.len = 46;
	bad += avtab_read(&t2, &fp, lt_pol) != 0 || !(n = avtab_search_node(&t2, &k)) || n->datum.u.xperms == &x || n->datum.u.xperms->driver != 2 || n->datum.u.xperms->perms.p[0] != 0x11 ||
	       n->datum.u.xperms->perms.p[7] != 0x88;
	avtab_destroy(&t2); avtab_destroy(&t);
	check(bad == 0, "avtab: an extended-permission entry is 46 bytes (specifier, driver, 8 words) and reads back as a private copy");

	avtab_init(&t2);
	fp.data = (char *)dupl; fp.len = 28;
	bad = avtab_read(&t2, &fp, lt_pol) != -EEXIST || t2.nslot || t2.nel;
	fp.data = (char *)badtype; fp.len = 16;
	bad += avtab_read(&t2, &fp, lt_pol) != -EINVAL || t2.nslot;
	fp.data = (char *)one; fp.len = 10;
	bad += avtab_read(&t2, &fp, lt_pol) != -EINVAL || t2.nslot;
	fp.data = (char *)one; fp.len = 3;
	bad += avtab_read(&t2, &fp, lt_pol) != -EINVAL;
	lt_pol_set(19, 6, 4);
	fp.data = (char *)oldfmt; fp.len = 32;
	k.specified = AVTAB_ALLOWED;
	bad += avtab_read(&t2, &fp, lt_pol) != 0 || t2.nel != 2 || !(n = avtab_search_node(&t2, &k)) || n->datum.u.data != 0x100;
	k.specified = AVTAB_AUDITALLOW;
	bad += !(n = avtab_search_node(&t2, &k)) || n->datum.u.data != 0x200;
	lt_pol_set(34, 6, 4);
	avtab_destroy(&t2);
	check(bad == 0, "avtab_read(): a duplicate key gives -EEXIST, an invalid type, a truncated entry and a truncated count -EINVAL and leave no table; the pre-version-20 combined entry gives two nodes");
}
#endif

#ifdef CONFIG_SECURITY_SELINUX
/* security/selinux/ss/hashtab + symtab: private tables. The symbol hash is djb2a, so with 4 slots "a" lands in slot 0 (177604 & 3), "" in slot 1 (5381 & 3), "ab", "ba" and "c" in slot 2
 * (5860902, 5861062, 177606), "b" in slot 3 (177607): a chain is kept sorted by strcmp(), so inserting c, ba, ab gives ab, ba, c. A size hint is rounded up to a power of two
 * (5 -> 8) and stored in 32 bits (0x80000001 -> 0 slots). */
#include "../security/selinux/ss/symtab.h"
static int lt_apply(void *k, void *d, void *args) { unsigned long *sum = args; *sum = *sum * 10 + (unsigned long)d; return (unsigned long)d == 3 ? 9 : 0; }
static int lt_copy(struct hashtab_node *nw, const struct hashtab_node *o, void *args)
{
	int *left = args;

	if ((*left)-- == 0)
		return -EINVAL;
	nw->key = o->key; nw->datum = (void *)((unsigned long)o->datum + 100);
	return 0;
}
static int lt_destroyed;
static int lt_destroy(void *k, void *d, void *args) { lt_destroyed++; return 0; }
static void __init test_hashtab(void)
{
	static const struct { u32 hint, size; } sz[] = { { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 4 }, { 5, 8 }, { 100, 128 }, { 0x80000001u, 0 },  };
	struct symtab st;
	struct hashtab h, h2;
	struct hashtab_node *n;
	unsigned long sum = 0;
	int bad = 0, left;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sz); i++) {
		if (sz[i].hint > 1000000 && sz[i].hint != 0x80000001u)
			continue;
		bad += hashtab_init(&h, sz[i].hint) != 0 || h.size != sz[i].size || h.nel || (sz[i].size ? !h.htable : !!h.htable);
		hashtab_destroy(&h);
		bad += h.htable != NULL;
	}
	check(bad == 0, "hashtab_init(): size hints 0, 1, 2, 3, 5, 100 and 2^31+1 give 0, 1, 2, 4, 8, 128 and 0 slots; destroy clears the table pointer");

	bad = symtab_init(&st, 0) != 0 || symtab_insert(&st, "a", (void *)1) != -EINVAL || symtab_search(&st, "a") != NULL;
	st.nprim = 5;
	bad += symtab_init(&st, 3) != 0 || st.nprim != 0 || st.table.size != 4;
	bad += symtab_insert(&st, "c", (void *)3) || symtab_insert(&st, "ba", (void *)2) || symtab_insert(&st, "ab", (void *)1) || symtab_insert(&st, "a", (void *)4) ||
	       symtab_insert(&st, "b", (void *)5) || symtab_insert(&st, "", (void *)6);
	bad += symtab_insert(&st, "ba", (void *)9) != -EEXIST || st.table.nel != 6;
	check(bad == 0, "symtab_init() / symtab_insert(): size 0 refuses, six names go in, a repeated name gives -EEXIST");

	bad = symtab_search(&st, "a") != (void *)4 || symtab_search(&st, "b") != (void *)5 || symtab_search(&st, "ab") != (void *)1 || symtab_search(&st, "ba") != (void *)2 ||
	      symtab_search(&st, "c") != (void *)3 || symtab_search(&st, "") != (void *)6 || symtab_search(&st, "d") != NULL || symtab_search(&st, "aa") != NULL;
	bad += !st.table.htable[0] || strcmp(st.table.htable[0]->key, "a") || !st.table.htable[1] || strcmp(st.table.htable[1]->key, "") || !st.table.htable[3] || strcmp(st.table.htable[3]->key, "b");
	n = st.table.htable[2];
	bad += !n || strcmp(n->key, "ab") || !n->next || strcmp(n->next->key, "ba") || !n->next->next || strcmp(n->next->next->key, "c") || n->next->next->next;
	check(bad == 0, "symtab_search(): finds every name, misses unknown ones; slots 0, 1, 3 hold a, \"\", b and slot 2 holds ab, ba, c in strcmp order");

	hashtab_map(&st.table, lt_apply, &sum);
	bad = sum == 0;
	sum = 0;
	bad += hashtab_map(&st.table, lt_apply, &sum) != 9;
	check(bad == 0, "hashtab_map(): the walk stops at the first callback that returns non-zero and passes that value on");

	left = 100;
	bad = hashtab_duplicate(&h2, &st.table, lt_copy, lt_destroy, &left) != 0 || h2.size != 4 || h2.nel != 6 || !h2.htable[2] || strcmp(h2.htable[2]->key, "ab") ||
	      h2.htable[2]->datum != (void *)101 || h2.htable[2]->next->datum != (void *)102 || h2.htable[2]->next->next->datum != (void *)103 || h2.htable[2]->next->next->next;
	hashtab_destroy(&h2);
	lt_destroyed = 0;
	left = 4;
	bad += hashtab_duplicate(&h2, &st.table, lt_copy, lt_destroy, &left) != -ENOMEM || h2.htable || h2.size || h2.nel || lt_destroyed != 4;
	check(bad == 0, "hashtab_duplicate(): copies all six nodes in order; a copy failing on the fifth undoes the four made (destroy callback 4 times) and leaves the target zeroed");

	hashtab_destroy(&st.table);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX
/* security/selinux/ss/conditional: boolean-controlled rules on a hand-built policydb (zeroed 608-byte buffer; the offsets conditional_glue.c asserts). Booleans a = 1 (value 1) and b = 0 (value 2);
 * three conditional nodes (node 0 starts in state 1, node 1 in -1, node 2 in 0, so the first evaluation changes all of them): node 0 = !a with true rule (1,1,1) ALLOWED 0x5 and false rule ALLOWED 0x6; node 1 = a && b with true rule (2,2,2) AUDITALLOW 0x70 and false rule AUDITDENY 0xff0;
 * node 2 = the lone operator OR, which is undefined (-1) and enables nothing. Rules start disabled. With a = 1, b = 0: node 0 is false (rule 0x6 on), node 1 false (auditdeny
 * mask 0xff0 on); with a = 0 node 0 turns true (0x5); with a = b = 1 node 1 turns true (auditallow 0x70). The written list is 4 + 56 + 64 + 24 = 148 bytes. */
struct lt_av_decision { u32 allowed, auditallow, auditdeny, seqno, flags; };
int cond_read_bool(void *p, struct symtab *s, struct policy_file *fp);
int cond_init_bool_indexes(void *p);
int cond_index_bool(void *key, void *datum, void *datap);
int cond_destroy_bool(void *key, void *datum, void *p);
int cond_read_list(void *p, struct policy_file *fp);
void evaluate_cond_nodes(void *p);
void cond_compute_av(struct avtab *ctab, struct avtab_key *key, struct lt_av_decision *avd, void *xperms);
int cond_write_list(void *p, struct policy_file *fp);
int cond_policydb_dup(void *new, const void *orig);
void cond_policydb_destroy_dup(void *p);
void cond_policydb_destroy(void *p);
static char lt_cp[608] __aligned(8) __initdata, lt_cp2[608] __aligned(8) __initdata, lt_cp3[608] __aligned(8) __initdata;
static unsigned char lt_cbuf[512] __initdata;
static void __init lt_put32(unsigned char **b, u32 v) { memcpy(*b, &v, 4); *b += 4; }
static void __init lt_put16(unsigned char **b, u16 v) { memcpy(*b, &v, 2); *b += 2; }
static void __init lt_putrule(unsigned char **b, u16 src, u16 spec, u32 data) { lt_put16(b, src); lt_put16(b, src); lt_put16(b, src); lt_put16(b, spec); lt_put32(b, data); }
static void __init lt_cond_set_bool(char *pol, int idx, int state)
{
	struct { u32 value; int state; } **arr = *(void **)(pol + 376);

	arr[idx]->state = state;
}
static void __init test_conditional(void)
{
	struct symtab *sym = (struct symtab *)(lt_cp + 128);
	struct avtab *ctab = (struct avtab *)(lt_cp + 384);
	struct avtab_key k0 = { 1, 1, 1, AVTAB_ALLOWED }, k1 = { 2, 2, 2, AVTAB_AUDITALLOW }, k2 = { 2, 2, 2, AVTAB_AUDITDENY };
	struct lt_av_decision avd;
	struct policy_file fp;
	unsigned char *b = lt_cbuf;
	unsigned char bad1[16] = { 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 'x', 0, 0, 0 };
	int bad = 0;
	u32 listlen;

	/* the booleans */
	*(u32 *)(lt_cp + 304) = 8;	/* te_avtab.nel, which sizes the conditional avtab */
	*(unsigned int *)(lt_cp + 592) = 34;
	*(u32 *)(lt_cp + 96) = 6;	/* p_types.nprim */
	*(u32 *)(lt_cp + 48) = 4;	/* p_classes.nprim */
	bad += symtab_init(sym, 2) != 0;
	*(u32 *)(lt_cp + 144) = 2;	/* p_bools.nprim (symtab_init cleared it) */
	lt_put32(&b, 1); lt_put32(&b, 1); lt_put32(&b, 1); *b++ = 'a';
	lt_put32(&b, 2); lt_put32(&b, 0); lt_put32(&b, 1); *b++ = 'b';
	fp.data = (char *)lt_cbuf; fp.len = 13;
	bad += cond_read_bool(lt_cp, sym, &fp) != 0 || fp.len != 0;
	fp.data = (char *)lt_cbuf + 13; fp.len = 13;
	bad += cond_read_bool(lt_cp, sym, &fp) != 0;
	fp.data = (char *)bad1; fp.len = 13;
	bad += cond_read_bool(lt_cp, sym, &fp) != -EINVAL;
	*(void **)(lt_cp + 240) = kcalloc(2, sizeof(char *), GFP_KERNEL);
	bad += cond_init_bool_indexes(lt_cp) != 0 || hashtab_map(&sym->table, cond_index_bool, lt_cp) != 0 || sym->table.nel != 2;
	check(bad == 0, "conditional: two booleans read from a stream (a third with state 2 is refused with -EINVAL) and indexed by value");

	/* the conditional list */
	b = lt_cbuf;
	lt_put32(&b, 3);
	lt_put32(&b, 1); lt_put32(&b, 2); lt_put32(&b, 1); lt_put32(&b, 1); lt_put32(&b, 2); lt_put32(&b, 0);		/* node 0: cur 1, !a */
	lt_put32(&b, 1); lt_putrule(&b, 1, AVTAB_ALLOWED, 0x5); lt_put32(&b, 1); lt_putrule(&b, 1, AVTAB_ALLOWED, 0x6);
	lt_put32(&b, 0xffffffffu); lt_put32(&b, 3); lt_put32(&b, 1); lt_put32(&b, 1); lt_put32(&b, 1); lt_put32(&b, 2); lt_put32(&b, 4); lt_put32(&b, 0);	/* node 1: a && b */
	lt_put32(&b, 1); lt_putrule(&b, 2, AVTAB_AUDITALLOW, 0x70); lt_put32(&b, 1); lt_putrule(&b, 2, AVTAB_AUDITDENY, 0xff0);
	lt_put32(&b, 0); lt_put32(&b, 1); lt_put32(&b, 3); lt_put32(&b, 0); lt_put32(&b, 0); lt_put32(&b, 0);			/* node 2: OR */
	listlen = b - lt_cbuf;
	fp.data = (char *)lt_cbuf; fp.len = listlen;
	bad = cond_read_list(lt_cp, &fp) != 0 || fp.len != 0 || *(u32 *)(lt_cp + 416) != 3 || ctab->nel != 4;
	check(bad == 0, "cond_read_list(): three nodes with four rules read, rules inserted into the conditional avtab");

	/* evaluation and decisions */
	memset(&avd, 0, sizeof(avd)); avd.auditdeny = 0xffffffffu;
	cond_compute_av(ctab, &k0, &avd, NULL);
	bad = avd.allowed != 0;
	evaluate_cond_nodes(lt_cp);
	cond_compute_av(ctab, &k0, &avd, NULL);
	cond_compute_av(ctab, &k1, &avd, NULL);
	cond_compute_av(ctab, &k2, &avd, NULL);
	bad += avd.allowed != 0x6 || avd.auditallow != 0 || avd.auditdeny != 0xff0;
	lt_cond_set_bool(lt_cp, 0, 0);
	evaluate_cond_nodes(lt_cp);
	memset(&avd, 0, sizeof(avd)); avd.auditdeny = 0xffffffffu;
	cond_compute_av(ctab, &k0, &avd, NULL);
	bad += avd.allowed != 0x5;
	lt_cond_set_bool(lt_cp, 0, 1); lt_cond_set_bool(lt_cp, 1, 1);
	evaluate_cond_nodes(lt_cp);
	memset(&avd, 0, sizeof(avd)); avd.auditdeny = 0xffffffffu;
	cond_compute_av(ctab, &k0, &avd, NULL);
	cond_compute_av(ctab, &k1, &avd, NULL);
	cond_compute_av(ctab, &k2, &avd, NULL);
	bad += avd.allowed != 0x6 || avd.auditallow != 0x70 || avd.auditdeny != 0xffffffffu;
	check(bad == 0, "evaluate_cond_nodes() / cond_compute_av(): rules switch with the booleans (!a, a && b), disabled rules and the undefined lone OR contribute nothing");

	/* write, duplicate */
	memset(lt_cbuf, 0xaa, sizeof(lt_cbuf));
	fp.data = (char *)lt_cbuf; fp.len = sizeof(lt_cbuf);
	bad = cond_write_list(lt_cp, &fp) != 0 || fp.len != sizeof(lt_cbuf) - 148 || lt_cbuf[148] != 0xaa || lt_cbuf[0] != 3;
	fp.data = (char *)lt_cbuf; fp.len = 147;
	bad += cond_write_list(lt_cp, &fp) != -EINVAL;
	bad += cond_policydb_dup(lt_cp2, lt_cp) != 0 || *(u32 *)(lt_cp2 + 416) != 3 || *(u32 *)(lt_cp2 + 144) != 2;
	if (!bad) {
		lt_cond_set_bool(lt_cp2, 0, 0);
		evaluate_cond_nodes(lt_cp2);
		memset(&avd, 0, sizeof(avd));
		cond_compute_av((struct avtab *)(lt_cp2 + 384), &k0, &avd, NULL);
		bad += avd.allowed != 0x5;
		memset(&avd, 0, sizeof(avd));
		cond_compute_av(ctab, &k0, &avd, NULL);
		bad += avd.allowed != 0x6;
	}
	cond_policydb_destroy_dup(lt_cp2);
	check(bad == 0, "cond_write_list() / cond_policydb_dup(): 148 bytes (147 refused), the duplicate has its own booleans (changing one there leaves the original's rules alone)");

	hashtab_map(&sym->table, cond_destroy_bool, NULL);
	hashtab_destroy(&sym->table);
	kfree(*(void **)(lt_cp + 240));
	cond_policydb_destroy(lt_cp);
	(void)lt_cp3;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX
/* security/selinux/ss/mls: the MLS part of a security context on a hand-built policydb (zeroed buffer, the offsets mls_glue.c asserts). Sensitivities s0..s2 (values 1..3) and categories c0..c9
 * (values 1..10), every level datum holding all ten categories. "s0:c0.c3,c5-s1:c1,c2,c4" is parsed, measured (':' counts) and printed back: a run of three or more categories prints as a.b, one
 * or two as separate names. The user (id 1) may hold s0 .. s2. */
struct lt_lv { u32 sens; struct ebitmap cat; };
struct lt_ctx { u32 user, role, type, len; struct lt_lv lv[2]; char *str; };
int mls_compute_context_len(void *p, void *c);
void mls_sid_to_context(void *p, void *c, char **s);
int mls_level_isvalid(void *p, void *l);
int mls_range_isvalid(void *p, void *r);
int mls_context_isvalid(void *p, void *c);
int mls_context_to_sid(void *p, char oldc, char *s, void *c, void *sidtab, u32 def_sid);
int mls_range_set(void *c, void *r);
int mls_setup_user_range(void *p, void *from, void *user, void *to);
int mls_convert_context(void *oldp, void *newp, void *oldc, void *newc);
int mls_compute_sid(void *p, void *s, void *t, u16 tclass, u32 specified, void *n, bool sock);
static char lt_mp[640] __aligned(8) __initdata, lt_ud[96] __aligned(8) __initdata, lt_cl[72] __aligned(8) __initdata;
static void __init lt_lvset(struct lt_lv *l, u32 sens, u32 mask)
{
	int i;

	l->sens = sens;
	for (i = 0; i < 32; i++)
		if (mask & (1u << i))
			ebitmap_set_bit(&l->cat, i, 1);
}
static void __init lt_ctxfree(struct lt_ctx *c)
{
	ebitmap_destroy(&c->lv[0].cat); ebitmap_destroy(&c->lv[1].cat);
	memset(c, 0, sizeof(*c));
}
static bool __init lt_lvis(struct lt_lv *l, u32 sens, u32 mask)
{
	int i;

	if (l->sens != sens)
		return false;
	for (i = 0; i < 32; i++)
		if (!!ebitmap_get_bit(&l->cat, i) != !!(mask & (1u << i)))
			return false;
	return true;
}
static void __init test_mls(void)
{
	static char *lnames[3] = { "s0", "s1", "s2" }, *cnames[10] = { "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9" };
	struct symtab *lev = (struct symtab *)(lt_mp + 152), *cats = (struct symtab *)(lt_mp + 176);
	static struct { struct lt_lv level; unsigned char isalias; } ld[3] __initdata;
	static struct { u32 value; unsigned char isalias; } cd[10] __initdata;
	static void *uarr[1], *carr[1];
	struct lt_ctx a = {}, b = {}, t = {}, n = {}, f = {}, u = {};
	struct lt_lv *ur = (struct lt_lv *)(lt_ud + 24), *udef = (struct lt_lv *)(lt_ud + 72);
	char s1[] = "s0:c0.c3,c5-s1:c1,c2,c4", s2[] = "s1:c2", s3[] = "s9", s4[] = "s0:c3.c1", s5[] = "s0:c1.c1", s6[] = "s0:zz", out[64], *o;
	int i, bad = 0, len;

	*(int *)lt_mp = 1;				/* mls_enabled */
	bad += symtab_init(lev, 4) != 0 || symtab_init(cats, 16) != 0;
	for (i = 0; i < 3; i++) {
		ld[i].level.sens = i + 1;
		ebitmap_set_bit(&ld[i].level.cat, 0, 1);
		lt_lvset(&ld[i].level, i + 1, 0x3ff);
		bad += symtab_insert(lev, lnames[i], &ld[i]) != 0;
	}
	for (i = 0; i < 10; i++) {
		cd[i].value = i + 1;
		bad += symtab_insert(cats, cnames[i], &cd[i]) != 0;
	}
	*(u32 *)(lt_mp + 168) = 3;			/* p_levels.nprim */
	*(u32 *)(lt_mp + 192) = 10;			/* p_cats.nprim */
	*(u32 *)(lt_mp + 120) = 1;			/* p_users.nprim */
	*(u32 *)(lt_mp + 48) = 1;			/* p_classes.nprim */
	*(char ***)(lt_mp + 200 + 6 * 8) = lnames;
	*(char ***)(lt_mp + 200 + 7 * 8) = cnames;
	*(void ***)(lt_mp + 264) = carr;		/* class_val_to_struct */
	*(void ***)(lt_mp + 280) = uarr;		/* user_val_to_struct */
	*(u16 *)(lt_mp + 598) = 5;			/* process_class */
	uarr[0] = lt_ud; carr[0] = lt_cl;
	lt_lvset(&ur[0], 1, 0); lt_lvset(&ur[1], 3, 0x3ff); lt_lvset(udef, 2, 0x3ff);
	check(bad == 0, "mls: hand-built policy (three sensitivities, ten categories, one user)");

	bad = mls_context_to_sid(lt_mp, ':', s1, &a, NULL, 0) != 0 || !lt_lvis(&a.lv[0], 1, 0x2f) || !lt_lvis(&a.lv[1], 2, 0x16);
	len = mls_compute_context_len(lt_mp, &a);
	o = out; mls_sid_to_context(lt_mp, &a, &o); *o = 0;
	bad += strcmp(out, ":s0:c0.c3,c5-s1:c1,c2,c4") || o - out != len || len != 24;
	bad += mls_context_to_sid(lt_mp, ':', s2, &b, NULL, 0) != 0 || !lt_lvis(&b.lv[0], 2, 0x4) || !lt_lvis(&b.lv[1], 2, 0x4);
	len = mls_compute_context_len(lt_mp, &b);
	o = out; mls_sid_to_context(lt_mp, &b, &o); *o = 0;
	bad += strcmp(out, ":s1:c2") || o - out != len || len != 6;
	check(bad == 0, "mls_context_to_sid() / mls_compute_context_len() / mls_sid_to_context(): a range and a single level are parsed (c0.c3 expands to four bits), measured and printed back");

	bad = mls_context_to_sid(lt_mp, ':', s3, &f, NULL, 0) != -EINVAL;
	lt_ctxfree(&f);
	bad += mls_context_to_sid(lt_mp, ':', s4, &f, NULL, 0) != -EINVAL;
	lt_ctxfree(&f);
	{ char c5[] = "s0:c1.c1"; (void)s5; bad += mls_context_to_sid(lt_mp, ':', c5, &f, NULL, 0) != -EINVAL; }
	lt_ctxfree(&f);
	bad += mls_context_to_sid(lt_mp, ':', s6, &f, NULL, 0) != -EINVAL;
	lt_ctxfree(&f);
	bad += mls_context_to_sid(lt_mp, 0, s6, &f, NULL, 0) != -EINVAL;
	*(int *)lt_mp = 0;
	bad += mls_context_to_sid(lt_mp, ':', s6, &f, NULL, 0) != -EINVAL || mls_context_to_sid(lt_mp, 0, s6, &f, NULL, 0) != 0 || mls_context_to_sid(lt_mp, ':', s6, &f, NULL, 7) != 0;
	bad += mls_compute_context_len(lt_mp, &a) != 0 || mls_context_isvalid(lt_mp, &f) != 1;
	*(int *)lt_mp = 1;
	check(bad == 0, "mls_context_to_sid(): an unknown sensitivity or category, a backwards or empty range and a missing field without default are refused; with MLS off only a given field is");

	lt_ctxfree(&f);
	lt_lvset(&f.lv[0], 1, 0x1); lt_lvset(&f.lv[1], 2, 0x3);
	bad = mls_level_isvalid(lt_mp, &f.lv[0]) != 1 || mls_range_isvalid(lt_mp, &f.lv) != 1;
	f.lv[0].sens = 0;
	bad += mls_level_isvalid(lt_mp, &f.lv[0]) != 0;
	f.lv[0].sens = 4;
	bad += mls_level_isvalid(lt_mp, &f.lv[0]) != 0;
	f.lv[0].sens = 3;
	bad += mls_level_isvalid(lt_mp, &f.lv[0]) != 1 || mls_range_isvalid(lt_mp, &f.lv) != 0;	/* low s2 above high s1 */
	ebitmap_set_bit(&f.lv[1].cat, 10, 1);
	bad += mls_level_isvalid(lt_mp, &f.lv[1]) != 0;						/* category 10 is not in the policy */
	lt_ctxfree(&f);
	check(bad == 0, "mls_level_isvalid() / mls_range_isvalid(): sensitivity 0 and 4 and category 10 refused, a low level above the high one refused");

	lt_lvset(&f.lv[0], 2, 0x4); lt_lvset(&f.lv[1], 3, 0x6); f.user = 1; f.role = 2;
	bad = mls_context_isvalid(lt_mp, &f) != 1;
	f.user = 2;
	bad += mls_context_isvalid(lt_mp, &f) != 0;
	f.role = 1;
	bad += mls_context_isvalid(lt_mp, &f) != 1;
	f.role = 2; f.user = 1;
	lt_ctxfree(&f); f.user = 1; f.role = 2;
	lt_lvset(&ur[0], 2, 0); lt_lvset(&f.lv[0], 1, 0); lt_lvset(&f.lv[1], 1, 0);
	bad += mls_context_isvalid(lt_mp, &f) != 0;				/* low below the user's low */
	lt_ctxfree(&f);
	ur[0].sens = 1;
	check(bad == 0, "mls_context_isvalid(): in the user's range, an unknown user, the object_r role (no user check), a range below the user's");

	bad = mls_range_set(&n, a.lv) != 0 || !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 2, 0x16);
	lt_ctxfree(&n);
	lt_lvset(&f.lv[0], 1, 0); lt_lvset(&f.lv[1], 3, 0x3ff); f.user = 0;
	bad += mls_setup_user_range(lt_mp, &f, lt_ud, &u) != 0 || u.lv[0].sens != 2 || u.lv[1].sens != 3;	/* default level, clearance of fromcon */
	lt_ctxfree(&f); memset(&u, 0, sizeof(u));
	lt_lvset(&f.lv[0], 3, 0); lt_lvset(&f.lv[1], 3, 0);
	ur[1].sens = 2; udef->sens = 1;
	bad += mls_setup_user_range(lt_mp, &f, lt_ud, &u) != -EINVAL;
	ur[1].sens = 3; udef->sens = 2;
	*(int *)lt_mp = 0;
	bad += mls_setup_user_range(lt_mp, &f, lt_ud, &u) != 0 || u.lv[0].sens != 0;
	*(int *)lt_mp = 1;
	lt_ctxfree(&f);
	check(bad == 0, "mls_range_set() / mls_setup_user_range(): the user's default level and the lower clearance chosen, -EINVAL when no level fits, nothing with MLS off");

	bad = mls_convert_context(lt_mp, lt_mp, &a, &n) != 0 || !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 2, 0x16);
	lt_ctxfree(&n);
	check(bad == 0, "mls_convert_context(): levels and categories mapped by name into the same policy");

	lt_lvset(&t.lv[0], 2, 0x200); lt_lvset(&t.lv[1], 2, 0x200);
	bad = mls_compute_sid(lt_mp, &a, &t, 3, 0x20, &n, false) != 0 || !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 1, 0x2f);		/* member: source low */
	lt_ctxfree(&n);
	bad += mls_compute_sid(lt_mp, &a, &t, 5, 0x40, &n, false) != 0 || !lt_lvis(&n.lv[1], 2, 0x16);						/* change, process class: both */
	lt_ctxfree(&n);
	bad += mls_compute_sid(lt_mp, &a, &t, 3, 0x40, &n, false) != 0 || !lt_lvis(&n.lv[1], 1, 0x2f);					/* change, other class: low */
	lt_ctxfree(&n);
	bad += mls_compute_sid(lt_mp, &a, &t, 3, 0x40, &n, true) != 0 || !lt_lvis(&n.lv[1], 2, 0x16);						/* change, socket: both */
	lt_ctxfree(&n);
	bad += mls_compute_sid(lt_mp, &a, &t, 5, 0x10, &n, false) != 0 || !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 2, 0x16);		/* transition, no default range: falls into change */
	lt_ctxfree(&n);
	bad += mls_compute_sid(lt_mp, &a, &t, 3, 0x1, &n, false) != -EINVAL;
	check(bad == 0, "mls_compute_sid(): member, change (process class, other class, socket) and the transition fall-through");

	for (i = 1; i <= 7; i++) {
		lt_cl[67] = i;
		bad = mls_compute_sid(lt_mp, &a, &t, 1, 0x10, &n, false);
		switch (i) {
		case 1: bad |= !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 1, 0x2f); break;
		case 2: bad |= !lt_lvis(&n.lv[0], 2, 0x16) || !lt_lvis(&n.lv[1], 2, 0x16); break;
		case 3: bad |= !lt_lvis(&n.lv[0], 1, 0x2f) || !lt_lvis(&n.lv[1], 2, 0x16); break;
		case 4: case 5: case 6: bad |= !lt_lvis(&n.lv[0], 2, 0x200) || !lt_lvis(&n.lv[1], 2, 0x200); break;
		case 7: bad |= !lt_lvis(&n.lv[0], 2, 0) || !lt_lvis(&n.lv[1], 2, 0); break;
		}
		lt_ctxfree(&n);
		if (bad) {
			pr_err("libtest: mls default_range %d wrong\n", i);
			break;
		}
	}
	check(bad == 0, "mls_compute_sid(): each class default range (source low / high / both, target low / high / both, greatest lower bound and least upper bound)");

	lt_ctxfree(&a); lt_ctxfree(&b); lt_ctxfree(&t); lt_ctxfree(&u);
	ebitmap_destroy(&ur[0].cat); ebitmap_destroy(&ur[1].cat); ebitmap_destroy(&udef->cat);
	for (i = 0; i < 3; i++)
		ebitmap_destroy(&ld[i].level.cat);
	hashtab_destroy(&lev->table); hashtab_destroy(&cats->table);
}
#endif

#if defined(CONFIG_TCP_CONG_CUBIC) && defined(CONFIG_RUST)
/* net/ipv4/tcp_cubic: the cube root and the window-growth rule, called directly (upstream keeps both static, so there is no C-only arm of this test). Cube roots: exact for perfect
 * cubes up to 10^9 (8 -> 2, 27 -> 3, 1000 -> 10, 10^6 -> 100, 10^9 -> 1000) and 63 rounds up to 4; the others came from the C function. The update: at 1000 Hz with the standard
 * scales (c = 41 * 10, beta_scale 15), the first call starts an epoch at the current window with no maximum known (K = 0, target = window, so the growth counter is the 20 cap);
 * 2000 jiffies later the target is only 3 above a window of 100, so the cap holds again; after a reduction to window 100 with a maximum of 200 the plateau is K = 6451 away
 * and the target does not exceed the window, so the counter is 100 * window = 10000; a call in the next jiffy with the same window changes nothing. */
struct lt_bictcp { u32 cnt, last_max_cwnd, last_cwnd, last_time, bic_origin_point, bic_K, delay_min, epoch_start, ack_cnt, tcp_cwnd; };
u32 rust_cubic_root(u64 a);
void rust_bictcp_update(struct lt_bictcp *ca, u32 cwnd, u32 acked, u32 now, u32 hz, u64 delay_jiffies, int tcp_friendliness, u32 cube_rtt_scale, u32 beta_scale, u64 cube_factor);
static void __init test_tcp_cubic(void)
{
	static const struct { u64 a; u32 root; } t[] = {
		{ 0, 0 }, { 1, 1 }, { 7, 2 }, { 8, 2 }, { 27, 3 }, { 63, 4 }, { 64, 4 }, { 125, 5 }, { 1000, 10 }, { 1000000, 100 }, { 1000000000ULL, 1000 },
		{ 1ULL << 40, 10323 }, { 1ULL << 63, 2098142 }, { 12345678901234ULL, 23109 },
	};
	struct lt_bictcp ca = {};
	u64 factor = (1ULL << 40) / 410;
	u32 now = 5000;
	unsigned int i;
	int bad = 0;

	for (i = 0; i < ARRAY_SIZE(t); i++)
		bad += rust_cubic_root(t[i].a) != t[i].root;
	check(bad == 0, "tcp_cubic: cube root of 0, 1, 7, 8, 27, 63, 64, 125, 10^3, 10^6, 10^9, 2^40, 2^63 and 12345678901234");

	rust_bictcp_update(&ca, 100, 10, now, 1000, 0, 1, 410, 15, factor);
	bad = ca.cnt != 20 || ca.epoch_start != 5000 || ca.bic_origin_point != 100 || ca.bic_K || ca.tcp_cwnd != 100 || ca.ack_cnt != 10;
	now += 2000;
	rust_bictcp_update(&ca, 100, 10, now, 1000, 0, 1, 410, 15, factor);
	bad += ca.cnt != 20;
	ca.epoch_start = 0; ca.last_max_cwnd = 200;
	now += 1000;
	rust_bictcp_update(&ca, 100, 5, now, 1000, 0, 1, 410, 15, factor);
	bad += ca.cnt != 10000 || ca.bic_K != 6451 || ca.bic_origin_point != 200;
	now += 1;
	rust_bictcp_update(&ca, 100, 5, now, 1000, 0, 1, 410, 15, factor);
	bad += ca.cnt != 10000;
	check(bad == 0, "tcp_cubic: bictcp_update() starts an epoch (cap 20), keeps the cap, plateaus at K = 6451 with a counter of 10000 after a reduction, and ignores the next jiffy");
}
#endif

#if defined(CONFIG_TCP_CONG_BIC) && defined(CONFIG_RUST)
/* net/ipv4/tcp_bic: the window-growth rule, the reduction and the delayed-ACK ratio, called directly (upstream keeps them static). Defaults: low window 14, max increment 16, smooth part 20,
 * beta 819, fast convergence on, HZ 1000, delayed ACK 32 (two packets per ACK). above the low window cnt is worked out on paper as (raw << 4) / 32: window 10 (not above 14) returns early with cnt = 10 (no scaling); window 100 with no maximum:
 * raw 100 / 16 = 6 -> 3; with maximum 120: distance (120 - 100) / 4 = 5, raw 100 / 5 = 20 -> 10; maximum 102 (distance 0): raw 100 * 20 / 4 = 500 -> 250; window 130 with maximum 120 (past 124,
 * below 168): raw 130 * 3 / 10 = 39 -> 19; maximum 50: raw 130 / 16 = 8 -> 4; maximum 1000 (distance 225 above 16): raw 6 -> 3; window 1000 with no maximum: raw 62 capped at 20 -> 10.
 * Reduction from 200 with maximum 300: fast convergence gives maximum 200 * 1843 / 2048 = 179 and threshold 200 * 819 / 1024 = 159; with maximum 100 the maximum becomes 200; windows of 14 and
 * below halve (7, 5) with a floor of 2. ACK samples: 2 packets keep 32, 10 give 40, 0 then give 38. */
struct lt_bic { u32 cnt, last_max_cwnd, last_cwnd, last_time, epoch_start, delayed_ack; };
void rust_bic_update(struct lt_bic *ca, u32 cwnd, u32 now, u32 hz, int low_window, int max_increment, int smooth_part);
u32 rust_bic_ssthresh(struct lt_bic *ca, u32 cwnd, int fast_convergence, int beta, int low_window);
void rust_bic_acked(struct lt_bic *ca, u32 pkts_acked);
static void __init test_tcp_bic(void)
{
	static const struct { u32 cwnd, lmax, cnt; } t[] = {
		{ 10, 0, 10 }, { 100, 0, 3 }, { 100, 120, 10 }, { 100, 102, 250 }, { 100, 100, 250 }, { 130, 120, 19 }, { 130, 50, 4 }, { 100, 1000, 3 }, { 1000, 0, 10 },
	};
	struct lt_bic ca = { .delayed_ack = 32 };
	u32 now = 5000;
	unsigned int i;
	int bad = 0;

	rust_bic_update(&ca, 10, now, 1000, 14, 16, 20);
	bad += ca.cnt != 10 || ca.epoch_start != 5000 || ca.last_cwnd != 10 || ca.last_time != 5000;
	rust_bic_update(&ca, 10, now + 10, 1000, 14, 16, 20);
	bad += ca.last_time != 5000;
	for (i = 0; i < ARRAY_SIZE(t); i++) {
		now += 100;
		ca.last_max_cwnd = t[i].lmax;
		rust_bic_update(&ca, t[i].cwnd, now, 1000, 14, 16, 20);
		if (ca.cnt != t[i].cnt) {
			pr_err("libtest: tcp_bic window %u maximum %u gave cnt %u, expected %u\n", t[i].cwnd, t[i].lmax, ca.cnt, t[i].cnt);
			bad++;
		}
	}
	check(bad == 0, "tcp_bic: bictcp_update() starts an epoch, skips a call within 1/32 s at the same window, and sets cnt for the low window, binary search, smooth part, slow start, linear and capped cases");

	ca.epoch_start = 77; ca.last_max_cwnd = 300;
	bad = rust_bic_ssthresh(&ca, 200, 1, 819, 14) != 159 || ca.last_max_cwnd != 179 || ca.epoch_start != 0;
	ca.last_max_cwnd = 100;
	bad += rust_bic_ssthresh(&ca, 200, 1, 819, 14) != 159 || ca.last_max_cwnd != 200;
	ca.last_max_cwnd = 300;
	bad += rust_bic_ssthresh(&ca, 200, 0, 819, 14) != 159 || ca.last_max_cwnd != 200;
	bad += rust_bic_ssthresh(&ca, 14, 1, 819, 14) != 7 || rust_bic_ssthresh(&ca, 10, 1, 819, 14) != 5 || rust_bic_ssthresh(&ca, 2, 1, 819, 14) != 2;
	check(bad == 0, "tcp_bic: the reduction gives 159 from 200, lowers the maximum by fast convergence (179) or sets it to the window, halves small windows with a floor of 2");

	ca.delayed_ack = 32;
	rust_bic_acked(&ca, 2);
	bad = ca.delayed_ack != 32;
	rust_bic_acked(&ca, 10);
	bad += ca.delayed_ack != 40;
	rust_bic_acked(&ca, 0);
	bad += ca.delayed_ack != 38;
	check(bad == 0, "tcp_bic: the delayed-ACK ratio keeps 32 for two packets, rises to 40 for ten and falls to 38 for none");
}
#endif

#if defined(CONFIG_TCP_CONG_ILLINOIS) && defined(CONFIG_RUST)
/* net/ipv4/tcp_illinois: the RTT sampling, the once-per-RTT alpha / beta, the window increase and the reduction, called directly (upstream keeps them static). Defaults: window threshold 15,
 * theta 5. Samples: 3 packets with 1000 us set the minimum, maximum, count and sum; a negative sample only records the packet count; a sample of 5000000 us is clamped to 3355443.
 * Delay profile base 1000, maximum 11000 (dm 10000: low threshold 100, beta thresholds 1000 and 8000): average delay 50 never left the low zone, so alpha is the maximum 1280 and beta the
 * minimum 8; 5000 gives alpha = 9900 * 1280 / (9900 + 4900 * 1242 / 38) = 74 and beta = (8 * 8000 - 32 * 1000 + 24 * 5000) / 7000 = 21; back at 60 alpha stays 74 for four rounds and
 * the fifth, with rtt_low at theta, restores 1280; 9000 gives beta 32. A window of 10 (below 15) gives the Reno values 128 and 32. Increase: with 50 packets counted at alpha 1280 and
 * window 100 the delta is 50 * 1280 >> 7 = 500 so the window grows by 500 / 100 = 5 (or is clamped); the next ACK counts one packet. Reduction: 100 with beta 32 -> 50, with 8 -> 88, 2 -> 2. */
struct lt_ill { u64 sum_rtt; u16 cnt_rtt; u32 base_rtt, max_rtt, end_seq, alpha, beta; u16 acked; u8 rtt_above, rtt_low; };
void rust_ill_acked(struct lt_ill *ca, u32 pkts_acked, s32 rtt_us);
void rust_ill_update_params(struct lt_ill *ca, u32 cwnd, u32 snd_nxt, int win_thresh, int theta);
int rust_ill_ai(struct lt_ill *ca, u32 *cwnd, u32 *cnt, u32 clamp);
u32 rust_ill_ssthresh(const struct lt_ill *ca, u32 cwnd);
static void __init test_tcp_illinois(void)
{
	struct lt_ill ca = { .alpha = 1280, .beta = 32, .base_rtt = 0x7fffffff };
	u32 cwnd, cnt;
	int bad, i;

	rust_ill_acked(&ca, 3, 1000);
	bad = ca.acked != 3 || ca.base_rtt != 1000 || ca.max_rtt != 1000 || ca.cnt_rtt != 1 || ca.sum_rtt != 1000;
	rust_ill_acked(&ca, 2, -5);
	bad += ca.acked != 2 || ca.cnt_rtt != 1 || ca.sum_rtt != 1000;
	rust_ill_acked(&ca, 1, 5000000);
	bad += ca.max_rtt != 3355443 || ca.cnt_rtt != 2 || ca.sum_rtt != 1000 + 3355443 || ca.base_rtt != 1000;
	check(bad == 0, "tcp_illinois: RTT samples set minimum, maximum, count and sum, a negative sample only records the packets, a huge one is clamped to 3355443");

	memset(&ca, 0, sizeof(ca)); ca.alpha = 1280; ca.beta = 32;
#define LT_ILL_ROUND(da) do { ca.base_rtt = 1000; ca.max_rtt = 11000; ca.cnt_rtt = 1; ca.sum_rtt = 1000 + (da); rust_ill_update_params(&ca, 20, 777, 15, 5); } while (0)
	LT_ILL_ROUND(50);
	bad = ca.alpha != 1280 || ca.beta != 8 || ca.end_seq != 777 || ca.cnt_rtt != 0 || ca.sum_rtt != 0 || ca.rtt_above;
	LT_ILL_ROUND(5000);
	bad += ca.alpha != 74 || ca.beta != 21 || !ca.rtt_above;
	for (i = 0; i < 4; i++) {
		LT_ILL_ROUND(60);
		bad += ca.alpha != 74 || ca.rtt_low != i + 1;
	}
	LT_ILL_ROUND(60);
	bad += ca.alpha != 1280 || ca.rtt_above || ca.rtt_low;
	LT_ILL_ROUND(9000);
	bad += ca.beta != 32;
	ca.base_rtt = 1000; ca.max_rtt = 11000; ca.cnt_rtt = 1; ca.sum_rtt = 6000;
	rust_ill_update_params(&ca, 10, 5, 15, 5);
	bad += ca.alpha != 128 || ca.beta != 32 || ca.end_seq != 5;
	check(bad == 0, "tcp_illinois: update_params() gives alpha 1280 / beta 8 at low delay, 74 / 21 at 5000, holds alpha for four good rounds, beta 32 at high delay, and the Reno values below the window threshold");

	ca.alpha = 1280; ca.acked = 50; cwnd = 100; cnt = 0;
	bad = rust_ill_ai(&ca, &cwnd, &cnt, 1000) != 1 || cwnd != 105 || cnt != 0 || ca.acked != 1;
	bad += rust_ill_ai(&ca, &cwnd, &cnt, 1000) != 0 || cwnd != 105 || cnt != 1;
	ca.acked = 50; cwnd = 100; cnt = 0;
	bad += rust_ill_ai(&ca, &cwnd, &cnt, 102) != 1 || cwnd != 102;
	ca.beta = 32;
	bad += rust_ill_ssthresh(&ca, 100) != 50 || rust_ill_ssthresh(&ca, 2) != 2;
	ca.beta = 8;
	bad += rust_ill_ssthresh(&ca, 100) != 88;
	check(bad == 0, "tcp_illinois: the window grows by 5 from 100 after 50 packets at alpha 1280 (clamp 102 applies), the next ACK counts one; the reduction gives 50, 88 and the floor 2");
}
#endif

#if defined(CONFIG_TCP_CONG_HTCP) && defined(CONFIG_RUST)
/* net/ipv4/tcp_htcp: the measurements, beta / alpha, the window increase and the reduction, called directly (upstream keeps them static), at HZ 1000 (20 ms = 20 jiffies, 10 ms = 10).
 * RTT samples: the first of 30 jiffies sets minimum and maximum to 30; 45 raises the maximum (within 20 of it), 60 as well (within 20 of 45), 100 does not (beyond 65). Throughput: 10 packets
 * counted at window 10 (threshold 10 - 1 = 9) after 10000 jiffies give 10 * 1000 / 10000 = 1; just after a back-off (20 jiffies since congestion, under 3 minimum RTTs) 20 packets in 100
 * jiffies set minB = maxB = Bi = 200; later 40 packets in 100 jiffies give 400 and Bi = (3 * 200 + 400) / 4 = 250, which raises maxB; Recovery clears the count. Beta (bandwidth switch
 * off): the first call has no mode switch yet and gives 64 with the switch set; minimum 90 / maximum 100 gives 115 clamped to 102, 70 / 100 gives 89, 10 / 100 (not above 10 ms) gives 64;
 * the maximum then fades to 70 + 30 * 95 / 100 = 98. Bandwidth switch on: maxB 500 against an old 100 is outside [4/5, 6/5] -> 64 and no mode switch; 500 against 500 passes. Alpha with
 * beta 89: one second since congestion gives factor 1, alpha 2 * 39 = 78; three seconds gives factor 1 + (10 * 2000 + 1000) / 1000 = 22, alpha 1716; with RTT scaling at minimum 70 the scale is
 * 8000 / 700 = 11 and the factor 22 * 8 / 11 = 16, alpha 1248. Increase: counter 3 below the threshold only counts; 100 packets at alpha 128 and window 100 raise it to 101 (or not at the clamp).
 * Reduction: 100 at beta 89 -> 69, 2 -> 2. */
struct lt_htcp { u32 alpha; u8 beta, modeswitch; u16 pkts_acked; u32 packetcount, minRTT, maxRTT, last_cong, undo_last_cong, undo_maxRTT, undo_old_maxB, minB, maxB, old_maxB, Bi, lasttime; };
void rust_htcp_throughput(struct lt_htcp *ca, u32 pkts_acked, int has_rtt, u32 rtt_jiffies, u8 ca_state, u32 now, u32 jiffies32, u32 cwnd, u32 hz, u32 ms20, int use_bandwidth_switch);
void rust_htcp_alpha_update(struct lt_htcp *ca, u32 jiffies32, u32 hz, int use_rtt_scaling);
void rust_htcp_param_update(struct lt_htcp *ca, int use_bandwidth_switch, int use_rtt_scaling, u32 jiffies32, u32 hz, u32 ms10);
u32 rust_htcp_ssthresh(const struct lt_htcp *ca, u32 cwnd);
int rust_htcp_ai(struct lt_htcp *ca, u32 *cwnd, u32 *cnt, u32 clamp, u32 jiffies32, u32 hz, int use_rtt_scaling);
static void __init test_tcp_htcp(void)
{
	struct lt_htcp ca = { .alpha = 128, .beta = 64, .pkts_acked = 1 };
	u32 cwnd, cnt;
	int bad;

	rust_htcp_throughput(&ca, 5, 1, 30, 0, 10000, 10000, 10, 1000, 20, 1);
	bad = ca.minRTT != 30 || ca.maxRTT != 30 || ca.pkts_acked != 5 || ca.packetcount != 5 || ca.lasttime != 0;
	rust_htcp_throughput(&ca, 5, 1, 45, 0, 10000, 10000, 10, 1000, 20, 1);
	bad += ca.maxRTT != 45 || ca.minRTT != 30 || ca.packetcount != 0 || ca.lasttime != 10000 || ca.Bi != 0;
	rust_htcp_throughput(&ca, 0, 1, 60, 0, 10000, 10000, 10, 1000, 20, 1);
	bad += ca.maxRTT != 60;
	rust_htcp_throughput(&ca, 0, 1, 100, 0, 10000, 10000, 10, 1000, 20, 1);
	bad += ca.maxRTT != 60;
	check(bad == 0, "tcp_htcp: RTT samples set the minimum, raise the maximum only within 20 jiffies of it; ten packets in 10000 jiffies is 1 per second and moves the time stamp");

	ca.last_cong = 10080; ca.packetcount = 20;
	rust_htcp_throughput(&ca, 0, 0, 0, 0, 10100, 10100, 10, 1000, 20, 1);
	bad = ca.minB != 200 || ca.maxB != 200 || ca.Bi != 200 || ca.packetcount != 0 || ca.lasttime != 10100;
	ca.last_cong = 0; ca.packetcount = 40;
	rust_htcp_throughput(&ca, 0, 0, 0, 1, 10200, 10200, 10, 1000, 20, 1);
	bad += ca.Bi != 250 || ca.maxB != 250 || ca.minB != 200 || ca.lasttime != 10200;
	ca.packetcount = 33;
	rust_htcp_throughput(&ca, 1, 0, 0, 3, 10300, 10300, 10, 1000, 20, 1);
	bad += ca.packetcount != 0 || ca.lasttime != 10300;
	check(bad == 0, "tcp_htcp: after a back-off the bandwidth estimates restart at 200, later ones average (250) and raise the maximum, Recovery clears the packet count");

	memset(&ca, 0, sizeof(ca)); ca.alpha = 128; ca.beta = 64; ca.minRTT = 70; ca.maxRTT = 100;
	ca.minRTT = 10; rust_htcp_param_update(&ca, 0, 0, 1000, 1000, 10);
	bad = ca.beta != 64 || ca.modeswitch != 1;
	ca.minRTT = 90; rust_htcp_param_update(&ca, 0, 0, 1000, 1000, 10);
	bad += ca.beta != 102;
	ca.minRTT = 70; ca.maxRTT = 100; rust_htcp_param_update(&ca, 0, 0, 1000, 1000, 10);
	bad += ca.beta != 89 || ca.maxRTT != 98 || ca.alpha != 78;
	ca.minRTT = 10; ca.maxRTT = 100; rust_htcp_param_update(&ca, 0, 0, 1000, 1000, 10);
	bad += ca.beta != 64 || ca.modeswitch != 1;
	ca.minRTT = 70; ca.maxRTT = 100; ca.beta = 89; ca.last_cong = 0;
	rust_htcp_alpha_update(&ca, 3000, 1000, 0);
	bad += ca.alpha != 1716;
	rust_htcp_alpha_update(&ca, 3000, 1000, 1);
	bad += ca.alpha != 1248;
	ca.maxB = 500; ca.old_maxB = 100; ca.modeswitch = 1;
	rust_htcp_param_update(&ca, 1, 0, 1000, 1000, 10);
	bad += ca.beta != 64 || ca.modeswitch != 0 || ca.old_maxB != 500;
	ca.minRTT = 70; ca.maxRTT = 100; ca.modeswitch = 1;
	rust_htcp_param_update(&ca, 1, 0, 1000, 1000, 10);
	bad += ca.beta != 89;
	check(bad == 0, "tcp_htcp: beta 64 / 102 (clamped) / 89, the maximum RTT fades to 98, alpha 78 / 1716 / 1248 with and without RTT scaling, the bandwidth switch forces 64 outside 4/5..6/5");

	ca.alpha = 128; ca.pkts_acked = 3; cwnd = 100; cnt = 0;
	bad = rust_htcp_ai(&ca, &cwnd, &cnt, 1000, 1000, 1000, 0) != 0 || cnt != 3 || cwnd != 100 || ca.pkts_acked != 1;
	cnt = 100;
	bad += rust_htcp_ai(&ca, &cwnd, &cnt, 1000, 1000, 1000, 0) != 1 || cwnd != 101 || cnt != 0;
	cnt = 101; cwnd = 100; ca.alpha = 128;
	bad += rust_htcp_ai(&ca, &cwnd, &cnt, 100, 1000, 1000, 0) != 0 || cwnd != 100 || cnt != 0;
	ca.beta = 89;
	bad += rust_htcp_ssthresh(&ca, 100) != 69 || rust_htcp_ssthresh(&ca, 2) != 2;
	check(bad == 0, "tcp_htcp: the counter only counts below the threshold, the window grows by one at it (not at the clamp, which still resets the counter); the reduction gives 69 and the floor 2");
}
#endif

#ifdef CONFIG_RUST
/* kernel/sched/pelt: the load-tracking arithmetic, called directly on a private struct sched_avg (the helpers are static in upstream's pelt.c, which is included into build_policy.c, so this
 * test needs the Rust arm). The decay table is kernel/sched/sched-pelt.h's (y^n * 2^32 for n < 32, y^32 = 1/2). A first call 100 units after the start with no load only records the 100
 * units of the open period; 1024 units later at full load the sums gain the contribution of one period -- 924 units decayed by y = 904, plus the open 100 = 1004, so load_sum = 1024 *
 * 1004, runnable_sum = that << 10, util_sum = 1004 << 10, and the averages divide by 46718 + 100 (22486 and 21); 32 periods of idleness halve the sums; less than one unit of time
 * changes nothing, and a clock that went backwards only resets the time stamp. */
struct lt_sched_avg { u64 last_update_time, load_sum, runnable_sum; u32 util_sum, period_contrib; unsigned long load_avg, runnable_avg, util_avg; unsigned int util_est; };
int rust_pelt_update_load_sum(u64 now, struct lt_sched_avg *sa, unsigned long load, unsigned long runnable, int running, const u32 *inv);
void rust_pelt_update_load_avg(struct lt_sched_avg *sa, unsigned long load);
static void __init test_pelt(void)
{
	static const u32 inv[32] = {
	0xffffffff, 0xfa83b2da, 0xf5257d14, 0xefe4b99a,
	0xeac0c6e6, 0xe5b906e6, 0xe0ccdeeb, 0xdbfbb796,
	0xd744fcc9, 0xd2a81d91, 0xce248c14, 0xc9b9bd85,
	0xc5672a10, 0xc12c4cc9, 0xbd08a39e, 0xb8fbaf46,
	0xb504f333, 0xb123f581, 0xad583ee9, 0xa9a15ab4,
	0xa5fed6a9, 0xa2704302, 0x9ef5325f, 0x9b8d39b9,
	0x9837f050, 0x94f4efa8, 0x91c3d373, 0x8ea4398a,
	0x8b95c1e3, 0x88980e80, 0x85aac367, 0x82cd8698
	};
	struct lt_sched_avg sa = {};
	u64 now = 100ULL << 10, last;
	int bad;

	bad = rust_pelt_update_load_sum(now, &sa, 0, 0, 0, inv) != 0 || sa.period_contrib != 100 || sa.load_sum || sa.util_sum;
	now += 1024ULL << 10;
	bad += rust_pelt_update_load_sum(now, &sa, 1024, 1024, 1, inv) != 1;
	rust_pelt_update_load_avg(&sa, 1024);
	bad += sa.load_sum != 1028096 || sa.runnable_sum != 1052770304ULL || sa.util_sum != 1028096 || sa.period_contrib != 100 || sa.load_avg != 22486 || sa.runnable_avg != 22486 || sa.util_avg != 21;
	check(bad == 0, "pelt: an idle update only opens the period; a full-load period adds 1004 units to the load, runnable and util sums (averages 22486, 22486, 21)");

	now += (32 * 1024ULL) << 10;
	bad = rust_pelt_update_load_sum(now, &sa, 0, 0, 0, inv) != 1;
	rust_pelt_update_load_avg(&sa, 1024);
	bad += sa.load_sum != 514047 || sa.runnable_sum != 526385151ULL || sa.util_sum != 514047 || sa.load_avg != 11243 || sa.runnable_avg != 11243 || sa.util_avg != 10;
	check(bad == 0, "pelt: 32 idle periods halve the sums (514047, 526385151, 514047) and the averages (11243, 11243, 10)");

	last = sa.last_update_time;
	bad = rust_pelt_update_load_sum(now + 500, &sa, 1024, 1024, 1, inv) != 0 || sa.last_update_time != last;
	bad += rust_pelt_update_load_sum(now - (1 << 20), &sa, 1024, 1024, 1, inv) != 0 || sa.last_update_time != now - (1 << 20);
	check(bad == 0, "pelt: less than one unit of time changes nothing; a clock that went backwards resets the time stamp and returns 0");
}
#endif

/* kernel/sched/loadavg: calc_load_n() on the three real decay factors (EXP_1 1884, EXP_5 2014, EXP_15 2037 over a 2048 fixed point), worked out on paper: n = 0 leaves the load alone,
 * n = 1 is one step (8192 * 1884 / 2048 = 7536 exactly; 4096 * (2048 - 1884) / 2048 = 328 exactly), a load held constant stays, and 12 five-second steps of idleness bring a load of 4.0 to
 * about 4 / e = 1.47 (3004 of 2048, the fixed-point rounding of 3013); the exact figures for the others came from the C file. */
#include <linux/sched/loadavg.h>
static void __init test_loadavg(void)
{
	static const struct { unsigned long load, exp, active; unsigned int n; unsigned long want; } t[] = {
		{ 8192, 1884, 0, 0, 8192 }, { 8192, 1884, 0, 1, 7536 }, { 8192, 1884, 0, 12, 3004 }, { 8192, 2014, 0, 60, 3024 }, { 0, 1884, 4096, 12, 2594 }, { 0, 1884, 4096, 1, 328 },
		{ 4096, 2037, 4096, 100, 4096 }, { 1000, 1884, 3000, 3, 1444 }, { 5, 1884, 0, 2, 4 }, { 8192, 1884, 8192, 5, 8192 },
	};
	int bad = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(t); i++)
		bad += calc_load_n(t[i].load, t[i].exp, t[i].active, t[i].n) != t[i].want;
	check(bad == 0, "calc_load_n(): ten cases over the 1, 5 and 15 minute factors (n = 0, one step, a minute of idleness, a held load, loads rising from zero)");
}

/* kernel/sched/cputime: cputime_adjust() on private structures, worked out on paper. The tick-sampled split is scaled to the exactly accounted runtime and neither part may go backwards:
 * (stime 3, utime 7, runtime 100) -> user 70, system 30; then (10, 10, 200) -> 100/100; then (1, 99, 250) would give system 2 but must stay 100 -> user 150; then (99, 1, 300) gives system
 * 297 but user may not fall below 150 -> 150/150; a runtime of 150 (below the previous sum) changes nothing; a sample with no system ticks counts all new time as user but system stays 150
 * -> user 250; a sample with no user ticks gives system 500 but user stays 250 -> 250/250. */
#include <linux/sched/types.h>
#include <linux/sched/cputime.h>
static void __init test_cputime(void)
{
	static const struct { u64 stime, utime, rtime, ut, st; } t[] = {
		{ 3, 7, 100, 70, 30 }, { 10, 10, 200, 100, 100 }, { 1, 99, 250, 150, 100 }, { 99, 1, 300, 150, 150 }, { 99, 1, 150, 150, 150 }, { 0, 5, 400, 250, 150 }, { 5, 0, 500, 250, 250 },
	};
	struct prev_cputime prev = {};
	int bad = 0;
	unsigned int i;

	raw_spin_lock_init(&prev.lock);
	for (i = 0; i < ARRAY_SIZE(t); i++) {
		struct task_cputime cur = { .stime = t[i].stime, .utime = t[i].utime, .sum_exec_runtime = t[i].rtime };
		u64 ut = 1, st = 2;

		cputime_adjust(&cur, &prev, &ut, &st);
		if (ut != t[i].ut || st != t[i].st || prev.utime != ut || prev.stime != st)
			bad++;
	}
	check(bad == 0, "cputime_adjust(): seven samples scale the tick split to the runtime, never let user or system go backwards, and ignore a runtime below the previous sum");
}

/* fs/fs_parser: __fs_parse() on a specification table, worked out on paper. A flag "a" gives its option with boolean true; "nob" matches the flag "b" (which allows the "no" form) as
 * negated, "noa" matches nothing (a does not allow it); "n" takes a number in any C base ("0x20" 32, "0755" 493, junk refused), "h" an octal number ("17" 15, "9" refused), the enum "e" the table
 * x = 5, y = 7, the bool "t" the names of bool_names, the string "s" refuses an empty value; an unknown name gives -ENOPARAM and a string given to a flag -EINVAL. */
#include <linux/fs_parser.h>
static const struct constant_table lt_enum[] = { { "x", 5 }, { "y", 7 }, { } };
static const struct fs_parameter_spec lt_specs[] = {
	fsparam_flag("a", 1), fsparam_flag_no("b", 2), fsparam_u32("n", 3), fsparam_u32oct("h", 4), fsparam_enum("e", 5, lt_enum), fsparam_bool("t", 6), fsparam_string("s", 7), { }
};
static int __init lt_parse(const char *key, enum fs_value_type type, const char *value, struct fs_parse_result *res)
{
	struct p_log log = { .prefix = "libtest" };
	struct fs_parameter param = { .key = key, .type = type, .string = (char *)value };

	return __fs_parse(&log, lt_specs, &param, res);
}
static void __init test_fs_parser(void)
{
	struct fs_parse_result r;
	int bad;

	bad = lookup_constant(bool_names, "yes", -1) != 1 || lookup_constant(bool_names, "false", -1) != 0 || lookup_constant(bool_names, "maybe", -1) != -1 || lookup_constant(lt_enum, "y", 0) != 7;
	check(bad == 0, "lookup_constant(): yes -> 1, false -> 0, an unknown name gives the default, the enum table is searched by name");

	bad = lt_parse("a", fs_value_is_flag, NULL, &r) != 1 || r.negated || !r.boolean;
	bad += lt_parse("nob", fs_value_is_flag, NULL, &r) != 2 || !r.negated || r.boolean;
	bad += lt_parse("noa", fs_value_is_flag, NULL, &r) != -ENOPARAM || lt_parse("zz", fs_value_is_flag, NULL, &r) != -ENOPARAM;
	bad += lt_parse("a", fs_value_is_string, "x", &r) != -EINVAL;
	check(bad == 0, "__fs_parse(): flags (true), the \"no\" form of a flag that allows it (negated), the \"no\" form of one that does not and unknown names (-ENOPARAM), a value given to a flag (-EINVAL)");

	bad = lt_parse("n", fs_value_is_string, "0x20", &r) != 3 || r.uint_32 != 32;
	bad += lt_parse("n", fs_value_is_string, "0755", &r) != 3 || r.uint_32 != 493;
	bad += lt_parse("n", fs_value_is_string, "abc", &r) != -EINVAL || lt_parse("n", fs_value_is_string, "4294967296", &r) != -EINVAL;
	bad += lt_parse("h", fs_value_is_string, "17", &r) != 4 || r.uint_32 != 15 || lt_parse("h", fs_value_is_string, "9", &r) != -EINVAL;
	bad += lt_parse("n", fs_value_is_blob, "0", &r) != -EINVAL;
	check(bad == 0, "__fs_parse(): numbers in base 0 (0x20 = 32, 0755 = 493) and octal (17 = 15, 9 refused), junk and overflow and the wrong value type refused");

	bad = lt_parse("e", fs_value_is_string, "y", &r) != 5 || r.uint_32 != 7;
	bad += lt_parse("e", fs_value_is_string, "z", &r) != -EINVAL;
	bad += lt_parse("t", fs_value_is_string, "yes", &r) != 6 || !r.boolean;
	bad += lt_parse("t", fs_value_is_string, "no", &r) != 6 || r.boolean;
	bad += lt_parse("t", fs_value_is_string, "maybe", &r) != -EINVAL;
	bad += lt_parse("s", fs_value_is_string, "dir", &r) != 7 || lt_parse("s", fs_value_is_string, "", &r) != -EINVAL;
	check(bad == 0, "__fs_parse(): enum (y = 7), bool (yes, no, maybe refused) and string (empty refused) parameters");
}

#if defined(CONFIG_EFI_PARTITION) && defined(CONFIG_RUST)
/* block/partitions/efi: the GPT checks, called directly on hand-built structures (upstream's are static). A protective MBR has the 0xaa55 signature and a record of type 0xEE starting at LBA 1
 * (result 1); another record type makes it hybrid (2); a bad signature or no MBR gives 0. A GPT header passes with signature "EFI PART", a size from 92 up to the block size, a CRC over
 * the header taken with the CRC field zeroed, its own LBA, usable range on the disk and 128-byte entries; a failed CRC leaves the field zeroed as the C code does. compare_gpts() counts
 * the fields in which the primary and alternate headers differ (each also against the end of the disk), and labels keep 7 bits with '!' for control characters. */
#include <linux/crc32.h>
int rust_efi_is_pmbr_valid(const u8 *mbr);
int rust_efi_gpt_header_check(u8 *gpt, u64 lba, u64 lastlba, u32 ssz);
int rust_efi_is_pte_valid(const u8 *pte, u64 lastlba);
int rust_efi_compare_gpts(const u8 *pgpt, const u8 *agpt, u64 lastlba);
void rust_efi_utf16_le_to_7bit(const u16 *in, u32 size, u8 *out);
static void __init lt_gpt_fix(u8 *h)
{
	u32 crc;

	memset(h + 16, 0, 4);
	crc = crc32_le(~0, h, 92) ^ ~0;
	memcpy(h + 16, &crc, 4);
}
static void __init lt_put(u8 *b, int off, u64 v, int n) { memcpy(b + off, &v, n); }
static void __init test_efi_part(void)
{
	static u8 mbr[512] __initdata, h[512] __initdata, h2[512] __initdata, pte[128] __initdata;
	u8 out[16];
	int bad;

	memset(mbr, 0, sizeof(mbr));
	lt_put(mbr, 510, 0xaa55, 2);
	mbr[446 + 4] = 0xEE; lt_put(mbr, 446 + 8, 1, 4);
	bad = rust_efi_is_pmbr_valid(mbr) != 1;
	mbr[462 + 4] = 0x83;
	bad += rust_efi_is_pmbr_valid(mbr) != 2;
	mbr[462 + 4] = 0;
	lt_put(mbr, 446 + 8, 2, 4);
	bad += rust_efi_is_pmbr_valid(mbr) != 0 || rust_efi_is_pmbr_valid(NULL) != 0;
	lt_put(mbr, 446 + 8, 1, 4); lt_put(mbr, 510, 0xaa54, 2);
	bad += rust_efi_is_pmbr_valid(mbr) != 0;
	check(bad == 0, "efi: a protective MBR (1), a hybrid one (2), starting at LBA 2, a wrong signature and no MBR (0)");

	memset(h, 0, sizeof(h));
	lt_put(h, 0, 0x5452415020494645ULL, 8); lt_put(h, 12, 92, 4); lt_put(h, 24, 1, 8); lt_put(h, 32, 999, 8); lt_put(h, 40, 34, 8); lt_put(h, 48, 966, 8); lt_put(h, 72, 2, 8);
	lt_put(h, 80, 128, 4); lt_put(h, 84, 128, 4);
	lt_gpt_fix(h);
	memcpy(h2, h, sizeof(h));
	bad = rust_efi_gpt_header_check(h2, 1, 999, 512) != 0 || memcmp(h, h2, 92);
	memcpy(h2, h, sizeof(h)); h2[3] ^= 1;
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 1;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 12, 600, 4); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 2;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 12, 91, 4); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 3;
	memcpy(h2, h, sizeof(h)); h2[40] ^= 1;
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 4 || memcmp(h2 + 16, "\0\0\0\0", 4);
	memcpy(h2, h, sizeof(h)); lt_put(h2, 24, 2, 8); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 5;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 40, 1000, 8); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 6;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 48, 1000, 8); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 7;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 48, 33, 8); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 8;
	memcpy(h2, h, sizeof(h)); lt_put(h2, 84, 256, 4); lt_gpt_fix(h2);
	bad += rust_efi_gpt_header_check(h2, 1, 999, 512) != 9;
	check(bad == 0, "efi: a valid header passes with its bytes intact; signature, size above the block, size below 92, CRC (field left zeroed), own LBA, usable range and entry size each fail");

	memset(pte, 0, sizeof(pte));
	bad = rust_efi_is_pte_valid(pte, 999) != 0;
	pte[0] = 1; lt_put(pte, 32, 100, 8); lt_put(pte, 40, 200, 8);
	bad += rust_efi_is_pte_valid(pte, 999) != 1 || rust_efi_is_pte_valid(pte, 199) != 0 || rust_efi_is_pte_valid(pte, 100) != 0;
	memcpy(h2, h, sizeof(h));
	bad += rust_efi_compare_gpts(h, h2, 999) != 3;	/* h2 is a copy of the primary: its own LBA is 1 and its alternate 999, so the two cross checks and "alternate header not at the end" fire */
	lt_put(h2, 24, 999, 8); lt_put(h2, 32, 1, 8);
	bad += rust_efi_compare_gpts(h, h2, 999) != 0;
	lt_put(h2, 40, 35, 8); h2[56] ^= 1; lt_put(h2, 80, 64, 4);
	bad += rust_efi_compare_gpts(h, h2, 999) != 3 || rust_efi_compare_gpts(NULL, h2, 999) != 0;
	check(bad == 0, "efi: null type GUID and entries off the disk are invalid; compare_gpts() counts 3, 0 and 3 differences for three header pairs");

	{
		static const u16 lab[6] = { 'A', 'b', 0x00e9, 0x0001, 0, 'z' };

		memset(out, 0xaa, sizeof(out));
		rust_efi_utf16_le_to_7bit(lab, 6, out);
		check(!memcmp(out, "Abi!\0z\0", 7) && out[7] == 0xaa, "efi: a label keeps the low 7 bits (0xe9 -> 'i'), control characters become '!', NUL stays, and the terminator is written at the end");
	}
}
#endif

/* kernel/ucount: worked out on paper on a private two-level chain u1 (namespace ns1) -> u0 (namespace ns0, the top). A count is charged to every level from the start up; the limit
 * checked at a level is the one of the namespace of the level below it (the first level has no limit). */
static void __init test_ucount(void)
{
	static struct user_namespace ns0 __initdata, ns1 __initdata;
	static struct ucounts u0 __initdata, u1 __initdata;
	long r;

	u0.ns = &ns0; ns0.ucounts = NULL; rcuref_init(&u0.count, 5);
	u1.ns = &ns1; ns1.ucounts = &u0; rcuref_init(&u1.count, 5);
	ns1.rlimit_max[UCOUNT_RLIMIT_NPROC] = 2;
	ns1.rlimit_max[UCOUNT_RLIMIT_MSGQUEUE] = 1;
	r = inc_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1);
	check(r == 1 && atomic_long_read(&u1.rlimit[UCOUNT_RLIMIT_NPROC]) == 1 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_NPROC]) == 1, "inc_rlimit_ucounts(): every level is charged and the first level's new value is returned");
	r = inc_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1);
	check(r == 2, "inc_rlimit_ucounts(): the second charge is at the limit of 2 and still succeeds");
	r = inc_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1);
	check(r == LONG_MAX && atomic_long_read(&u1.rlimit[UCOUNT_RLIMIT_NPROC]) == 3 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_NPROC]) == 3, "inc_rlimit_ucounts(): the third charge exceeds the upper level's limit, returns LONG_MAX and stays charged");
	check(is_rlimit_overlimit(&u1, UCOUNT_RLIMIT_NPROC, 2) && is_rlimit_overlimit(&u1, UCOUNT_RLIMIT_NPROC, 10), "is_rlimit_overlimit(): over the caller's limit at the first level, and over the namespace limit at the upper level");
	check(!dec_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1) && !dec_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1) && dec_rlimit_ucounts(&u1, UCOUNT_RLIMIT_NPROC, 1), "dec_rlimit_ucounts(): true only when the first level reaches zero");
	check(!is_rlimit_overlimit(&u1, UCOUNT_RLIMIT_NPROC, 0), "is_rlimit_overlimit(): nothing charged is not over any limit");
	r = inc_rlimit_get_ucounts(&u1, UCOUNT_RLIMIT_MSGQUEUE, false);
	check(r == 1 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 1, "inc_rlimit_get_ucounts(): the first charge takes a reference on each level and returns 1");
	r = inc_rlimit_get_ucounts(&u1, UCOUNT_RLIMIT_MSGQUEUE, false);
	check(r == 0 && atomic_long_read(&u1.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 1 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 1, "inc_rlimit_get_ucounts(): over the upper level's limit of 1 is refused and fully undone");
	r = inc_rlimit_get_ucounts(&u1, UCOUNT_RLIMIT_MSGQUEUE, true);
	check(r == 2 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 2, "inc_rlimit_get_ucounts(): override_rlimit ignores the namespace limits");
	dec_rlimit_put_ucounts(&u1, UCOUNT_RLIMIT_MSGQUEUE);
	dec_rlimit_put_ucounts(&u1, UCOUNT_RLIMIT_MSGQUEUE);
	check(atomic_long_read(&u1.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 0 && atomic_long_read(&u0.rlimit[UCOUNT_RLIMIT_MSGQUEUE]) == 0, "dec_rlimit_put_ucounts(): both charges are removed from every level");
	atomic_long_set(&u1.ucount[UCOUNT_USER_NAMESPACES], 2);
	atomic_long_set(&u0.ucount[UCOUNT_USER_NAMESPACES], 1);
	dec_ucount(&u1, UCOUNT_USER_NAMESPACES);
	check(atomic_long_read(&u1.ucount[UCOUNT_USER_NAMESPACES]) == 1 && atomic_long_read(&u0.ucount[UCOUNT_USER_NAMESPACES]) == 0, "dec_ucount(): every level loses one");
}

/* kernel/resource: worked out on paper, on a private root [0x1000, 0x1fff] (IORESOURCE_MEM) holding a [0x1100, 0x11ff] and b [0x1300, 0x13ff]. */
static void __init test_resource(void)
{
	static struct resource root __initdata = { .name = "t", .start = 0x1000, .end = 0x1fff, .flags = IORESOURCE_MEM };
	static struct resource a __initdata = { .name = "a", .start = 0x1100, .end = 0x11ff, .flags = IORESOURCE_MEM };
	static struct resource b __initdata = { .name = "b", .start = 0x1300, .end = 0x13ff, .flags = IORESOURCE_MEM };
	static struct resource c __initdata = { .name = "c", .start = 0x1180, .end = 0x1280, .flags = IORESOURCE_MEM };
	static struct resource d __initdata = { .name = "d", .start = 0x1120, .end = 0x113f, .flags = IORESOURCE_MEM };
	static struct resource e __initdata = { .name = "e", .start = 0x0f00, .end = 0x10ff, .flags = IORESOURCE_MEM };
	static struct resource g __initdata = { .name = "g", .start = 0x1000, .end = 0x1fff, .flags = IORESOURCE_MEM };
	static struct resource f __initdata = { .name = "f", .flags = IORESOURCE_MEM | IORESOURCE_BUSY };
	static struct resource h __initdata = { .name = "h", .flags = IORESOURCE_MEM | IORESOURCE_BUSY };
	static struct resource i __initdata = { .name = "i", .flags = IORESOURCE_MEM | IORESOURCE_BUSY };
	static struct resource j __initdata = { .name = "j", .flags = IORESOURCE_MEM | IORESOURCE_BUSY };

	check(request_resource(&root, &a) == 0 && request_resource(&root, &b) == 0 && root.child == &a && a.sibling == &b && a.parent == &root, "request_resource(): two disjoint ranges are linked in address order under the root");
	check(request_resource_conflict(&root, &c) == &a && c.parent == NULL, "request_resource_conflict(): a range overlapping a is refused and a is the conflict");
	check(request_resource(&root, &e) == -EBUSY && request_resource_conflict(&root, &e) == &root, "request_resource(): a range outside the root conflicts with the root itself");
	check(insert_resource(&root, &d) == 0 && d.parent == &a && a.child == &d, "insert_resource(): a range inside a goes below a");
	check(insert_resource(&root, &g) == 0 && root.child == &g && g.child == &a && a.parent == &g && b.parent == &g && a.child == &d, "insert_resource(): a range covering a and b becomes their parent");
	check(remove_resource(&g) == 0 && root.child == &a && a.parent == &root && b.parent == &root && g.parent == NULL, "remove_resource(): the children move back up");
	check(allocate_resource(&root, &f, 0x100, 0x1000, 0x1fff, 0x100, NULL, NULL) == 0 && f.start == 0x1000 && f.end == 0x10ff && root.child == &f && f.sibling == &a, "allocate_resource(): the first gap that fits, aligned, below a");
	check(allocate_resource(&root, &h, 0x100, 0x1000, 0x1fff, 0x100, NULL, NULL) == 0 && h.start == 0x1200 && h.end == 0x12ff && a.sibling == &h && h.sibling == &b, "allocate_resource(): the next gap is between a and b");
	check(allocate_resource(&root, &i, 0x200, 0x1000, 0x1fff, 0x100, NULL, NULL) == 0 && i.start == 0x1400 && i.end == 0x15ff, "allocate_resource(): 0x200 does not fit in the gaps and goes after b");
	check(allocate_resource(&root, &j, 0x100, 0x1000, 0x10ff, 0x100, NULL, NULL) == -EBUSY && j.parent == NULL, "allocate_resource(): no gap within the maximum is -EBUSY");
	check(adjust_resource(&h, 0x1200, 0x80) == 0 && h.end == 0x127f && adjust_resource(&h, 0x1200, 0x200) == -EBUSY && h.end == 0x127f, "adjust_resource(): shrinking is fine, growing into b is -EBUSY");
	check(adjust_resource(&a, 0x1130, 0xd0) == -EBUSY && a.start == 0x1100, "adjust_resource(): a range that no longer holds its child is -EBUSY");
	h.flags |= IORESOURCE_SIZEALIGN;
	check(resource_alignment(&h) == 0x80 && resource_alignment(&f) == 0, "resource_alignment(): size-aligned gives the size, otherwise 0");
	check(release_resource(&h) == 0 && h.parent == NULL && a.sibling == &b, "release_resource(): the range leaves the list");
}

/* kernel/notifier: worked out on paper. Higher priority runs first; a new block goes before the first block with a strictly lower priority, so after its equals. A callback returning
 * NOTIFY_STOP (or NOTIFY_BAD) ends the chain. The robust call runs the down value over the blocks already called except the one that stopped it. */
static char nt_log[64] __initdata;
static int nt_n __initdata;
static int __init nt_a(struct notifier_block *nb, unsigned long a, void *d) { nt_log[nt_n++] = 'a'; return NOTIFY_OK; }
static int __init nt_b(struct notifier_block *nb, unsigned long a, void *d) { nt_log[nt_n++] = a == 1 ? 'B' : 'b'; return a == 1 ? NOTIFY_BAD : NOTIFY_OK; }
static int __init nt_c(struct notifier_block *nb, unsigned long a, void *d) { nt_log[nt_n++] = 'c'; return NOTIFY_STOP; }
static int __init nt_d(struct notifier_block *nb, unsigned long a, void *d) { nt_log[nt_n++] = 'd'; return NOTIFY_DONE; }
static void __init test_notifier(void)
{
	static struct raw_notifier_head rh __initdata = RAW_NOTIFIER_INIT(rh);
	static struct notifier_block na __initdata = { .notifier_call = nt_a, .priority = 5 };
	static struct notifier_block nb __initdata = { .notifier_call = nt_b, .priority = 10 };
	static struct notifier_block nc __initdata = { .notifier_call = nt_c, .priority = 1 };
	static struct notifier_block nd __initdata = { .notifier_call = nt_d, .priority = 5 };
	static struct notifier_block ne __initdata = { .notifier_call = nt_a, .priority = 5 };
	static struct atomic_notifier_head ah __initdata = ATOMIC_NOTIFIER_INIT(ah);
	int r;

	check(raw_notifier_chain_register(&rh, &na) == 0 && raw_notifier_chain_register(&rh, &nb) == 0 && raw_notifier_chain_register(&rh, &nc) == 0, "raw_notifier_chain_register(): three blocks register");
	nt_n = 0;
	r = raw_notifier_call_chain(&rh, 0, NULL);
	nt_log[nt_n] = 0;
	check(r == (NOTIFY_STOP) && !strcmp(nt_log, "bac"), "raw_notifier_call_chain(): priority 10, 5, 1 order, and the last block's NOTIFY_STOP is the result");
	check(raw_notifier_chain_register(&rh, &nd) == 0, "raw_notifier_chain_register(): a block with the same priority as one in the chain registers");
	nt_n = 0;
	raw_notifier_call_chain(&rh, 0, NULL);
	nt_log[nt_n] = 0;
	check(!strcmp(nt_log, "badc"), "raw_notifier_call_chain(): equal priorities run in registration order (the newer one after its equals)");
	check(raw_notifier_chain_register(&rh, &ne) == 0 && raw_notifier_chain_unregister(&rh, &ne) == 0 && raw_notifier_chain_unregister(&rh, &ne) == -ENOENT, "raw_notifier_chain_unregister(): a block leaves once, a second time is -ENOENT");
	nt_n = 0;
	r = raw_notifier_call_chain_robust(&rh, 1, 2, NULL);
	nt_log[nt_n] = 0;
	check(r == NOTIFY_BAD && !strcmp(nt_log, "B"), "raw_notifier_call_chain_robust(): the first block stops the chain on the up value, so nothing is called down");
	nt_n = 0;
	r = raw_notifier_call_chain(&rh, 0, NULL);
	nt_log[nt_n] = 0;
	check(r == NOTIFY_STOP && !strcmp(nt_log, "badc"), "raw_notifier_call_chain(): the chain is unchanged by the failed robust call");
	nt_n = 0;
	r = raw_notifier_call_chain_robust(&rh, 0, 9, NULL);
	nt_log[nt_n] = 0;
	check(r == NOTIFY_STOP && !strcmp(nt_log, "badcbad"), "raw_notifier_call_chain_robust(): the last block stops the chain on the up value and the down call re-runs the first three, not the one that stopped");
	check(raw_notifier_chain_unregister(&rh, &nb) == 0 && raw_notifier_chain_unregister(&rh, &na) == 0 && raw_notifier_chain_unregister(&rh, &nd) == 0 && raw_notifier_chain_unregister(&rh, &nc) == 0, "raw_notifier_chain_unregister(): all four leave");
	nt_n = 0;
	r = raw_notifier_call_chain(&rh, 0, NULL);
	check(r == NOTIFY_DONE && nt_n == 0, "raw_notifier_call_chain(): an empty chain is NOTIFY_DONE");
	check(atomic_notifier_chain_register_unique_prio(&ah, &na) == 0 && atomic_notifier_chain_register_unique_prio(&ah, &nd) == -EBUSY && atomic_notifier_chain_register(&ah, &nd) == 0, "atomic_notifier_chain_register_unique_prio(): a second block at the same priority is -EBUSY");
	nt_n = 0;
	r = atomic_notifier_call_chain(&ah, 0, NULL);
	nt_log[nt_n] = 0;
	check(!strcmp(nt_log, "ad") && r == NOTIFY_DONE, "atomic_notifier_call_chain(): both blocks run, the last result is returned");
	check(atomic_notifier_chain_unregister(&ah, &na) == 0 && atomic_notifier_chain_unregister(&ah, &nd) == 0 && atomic_notifier_call_chain_is_empty(&ah), "atomic_notifier_chain_unregister(): both leave and the chain is empty");
}

#ifdef CONFIG_USER_NS
#ifdef CONFIG_RUST
int rust_userns_parse(char *kbuf, struct uid_gid_map *new_map);
int rust_userns_remap(struct uid_gid_map *new_map, struct uid_gid_map *parent_map);
int rust_userns_sort(struct uid_gid_map *map);
static int __init un_build(const char *text, struct uid_gid_map *map, struct uid_gid_map *parent)
{
	char *k = kstrdup(text, GFP_KERNEL);
	int r = k ? rust_userns_parse(k, map) : -ENOMEM;

	if (r == 0 && parent)
		r = rust_userns_remap(map, parent);
	if (r == 0)
		r = rust_userns_sort(map);
	kfree(k);
	return r;
}
static void __init un_free(struct uid_gid_map *m)
{
	if (m->nr_extents > UID_GID_MAP_MAX_BASE_EXTENTS) {
		kfree(m->forward);
		kfree(m->reverse);
	}
	memset(m, 0, sizeof(*m));
}
#endif

/* kernel/user_namespace.c: worked out on paper. A namespace map "0 1000 5" sends ns ids 0..4 to kernel ids 1000..1004; "4294967295 ..." and wrapping counts are invalid. */
static void __init test_user_namespace(void)
{
	struct user_namespace *ns = kzalloc(sizeof(*ns), GFP_KERNEL);

	check(ns != NULL, "user_namespace: test namespace allocated");
	if (!ns)
		return;
	check(__kuid_val(make_kuid(&init_user_ns, 1234)) == 1234 && from_kuid(&init_user_ns, KUIDT_INIT(77)) == 77, "make_kuid()/from_kuid(): init_user_ns maps ids to themselves");
	check(!uid_valid(make_kuid(ns, 3)) && from_kuid(ns, KUIDT_INIT(3)) == (uid_t)-1, "make_kuid()/from_kuid(): a namespace without a map has no mapping");
	/* A map built by hand: ns 10..19 -> kernel 500..509, ns 100..100 -> kernel 7. */
	ns->uid_map.extent[0] = (struct uid_gid_extent){ .first = 10, .lower_first = 500, .count = 10 };
	ns->uid_map.extent[1] = (struct uid_gid_extent){ .first = 100, .lower_first = 7, .count = 1 };
	ns->uid_map.nr_extents = 2;
	check(__kuid_val(make_kuid(ns, 10)) == 500 && __kuid_val(make_kuid(ns, 19)) == 509 && __kuid_val(make_kuid(ns, 100)) == 7, "make_kuid(): ids at both ends of an extent and the single-id extent map");
	check(!uid_valid(make_kuid(ns, 9)) && !uid_valid(make_kuid(ns, 20)) && !uid_valid(make_kuid(ns, 101)), "make_kuid(): ids just outside the extents have no mapping");
	check(from_kuid(ns, KUIDT_INIT(500)) == 10 && from_kuid(ns, KUIDT_INIT(509)) == 19 && from_kuid(ns, KUIDT_INIT(7)) == 100 && from_kuid(ns, KUIDT_INIT(510)) == (uid_t)-1, "from_kuid(): the way back, ends included");
	check(from_kuid_munged(ns, KUIDT_INIT(510)) == overflowuid && from_kuid_munged(ns, KUIDT_INIT(501)) == 11, "from_kuid_munged(): no mapping gives overflowuid");
	check(map_id_range_up(&ns->uid_map, 500, 10) == 10 && map_id_range_up(&ns->uid_map, 500, 11) == (u32)-1 && map_id_range_up(&ns->uid_map, 505, 5) == 15, "map_id_range_up(): a range must lie inside one extent");
#ifdef CONFIG_RUST
	{
		struct uid_gid_map m = {}, par = {};
		char *k;
		int i, n, bad = 0;

		check(un_build("0 1000 5\n", &m, NULL) == 0 && m.nr_extents == 1 && map_id_down(&m, 4) == 1004 && map_id_down(&m, 5) == (u32)-1 && map_id_up(&m, 1003) == 3 && map_id_up(&m, 999) == (u32)-1, "map_write parse: one line maps ns 0..4 to 1000..1004");
		un_free(&m);
		check(un_build("0 100 1000", &par, NULL) == 0, "map_write parse: no trailing newline is fine");
		check(un_build("  5\t10 3 \n 20 30   4\n", &m, &par) == 0 && m.nr_extents == 2 && map_id_down(&m, 20) == 130 && map_id_up(&m, 112) == 7 && map_id_down(&m, 7) == 112 && map_id_down(&m, 8) == (u32)-1, "map_write: mixed blanks are fine, lower ids go through the parent map (10+100=110)");
		un_free(&m);
		check(un_build("5 10 3\n\n20 30 4\n", &m, NULL) == -EINVAL, "map_write parse: a blank line in the middle is -EINVAL");
		un_free(&m);
		check(un_build("0 5000 10", &m, &par) == -EPERM, "map_write remap: lower ids outside the parent map are -EPERM");
		un_free(&m);
		check(un_build("1 1 1\n1 2 1\n", &m, NULL) == -EINVAL, "map_write parse: overlapping ns ids are -EINVAL");
		un_free(&m);
		check(un_build("1 1 1\n2 1 1\n", &m, NULL) == -EINVAL, "map_write parse: overlapping kernel ids are -EINVAL");
		un_free(&m);
		check(un_build("1 1 0\n", &m, NULL) == -EINVAL && un_build("4294967295 1 1", &m, NULL) == -EINVAL && un_build("1 4294967295 1", &m, NULL) == -EINVAL && un_build("4294967290 1 6", &m, NULL) == -EINVAL, "map_write parse: zero count, id -1 and wrapping extents are -EINVAL");
		un_free(&m);
		check(un_build("1 1", &m, NULL) == -EINVAL && un_build("1 1 1 1", &m, NULL) == -EINVAL && un_build("1 1 1x", &m, NULL) == -EINVAL && un_build("a 1 1", &m, NULL) == -EINVAL && un_build("", &m, NULL) == -EINVAL && un_build("\n", &m, NULL) == -EINVAL, "map_write parse: missing, extra and non-numeric fields and empty text are -EINVAL");
		un_free(&m);
		/* 340 lines are the most there can be; the 341st is refused. */
		k = kmalloc(341 * 16, GFP_KERNEL);
		if (k) {
			for (n = 0, i = 0; i < 341; i++)
				n += scnprintf(k + n, 16, "%d %d 1%s", 340 - i, i * 3, i == 340 ? "" : "\n");
			check(un_build(k, &m, NULL) == -EINVAL, "map_write parse: 341 lines are too many");
			un_free(&m);
			for (n = 0, i = 0; i < 340; i++)
				n += scnprintf(k + n, 16, "%d %d 1%s", 339 - i, i * 3, i == 339 ? "" : "\n");
			check(un_build(k, &m, NULL) == 0 && m.nr_extents == 340, "map_write parse: 340 lines are accepted and sorted");
			for (i = 0; i < 340; i++)
				if (map_id_down(&m, 339 - i) != i * 3 || map_id_up(&m, i * 3) != 339 - i)
					bad++;
			check(bad == 0 && map_id_down(&m, 340) == (u32)-1 && map_id_up(&m, 1) == (u32)-1 && map_id_up(&m, 1020) == (u32)-1, "binary search over 340 extents (forward and reverse arrays) finds every id and nothing else");
			un_free(&m);
			kfree(k);
		}
		un_free(&par);
	}
#endif
	kfree(ns);
}
#endif

/* lib/logic_pio: worked out on paper (x86: no indirect PIO, MMIO_UPPER_LIMIT = IO_SPACE_LIMIT = 0xffff). MMIO ranges are laid out back to back from logical 0: A (hw 0x1000, size 0x100)
 * gets io 0, B (hw 0x2000, size 0x200) gets io 0x100; C overlapping A is -EFAULT; A again is -EEXIST; a size of 0xff00 would end past 0xffff but 64K cannot be reserved either: -E2BIG. */
static void __init test_logic_pio(void)
{
	static struct fwnode_handle fa __initdata, fb __initdata, fc __initdata, fd __initdata;
	static struct logic_pio_hwaddr a __initdata = { .fwnode = &fa, .hw_start = 0x1000, .size = 0x100, .flags = LOGIC_PIO_CPU_MMIO };
	static struct logic_pio_hwaddr b __initdata = { .fwnode = &fb, .hw_start = 0x2000, .size = 0x200, .flags = LOGIC_PIO_CPU_MMIO };
	static struct logic_pio_hwaddr c __initdata = { .fwnode = &fc, .hw_start = 0x10f0, .size = 0x20, .flags = LOGIC_PIO_CPU_MMIO };
	static struct logic_pio_hwaddr d __initdata = { .fwnode = &fd, .hw_start = 0x3000, .size = 0xff00, .flags = LOGIC_PIO_CPU_MMIO };
	static struct logic_pio_hwaddr e __initdata = { .fwnode = &fd, .hw_start = 0x4000, .size = 0x10, .flags = LOGIC_PIO_INDIRECT };

	check(logic_pio_register_range(&a) == 0 && a.io_start == 0 && logic_pio_register_range(&b) == 0 && b.io_start == 0x100, "logic_pio_register_range(): MMIO ranges are laid out back to back");
	check(logic_pio_register_range(&c) == -EFAULT && logic_pio_register_range(&a) == -EEXIST, "logic_pio_register_range(): an overlap is -EFAULT, the same node again -EEXIST");
	check(logic_pio_register_range(&d) == -E2BIG && logic_pio_register_range(&e) == -EINVAL && logic_pio_register_range(NULL) == -EINVAL, "logic_pio_register_range(): too big -E2BIG, indirect without ops and NULL -EINVAL");
	check(find_io_range_by_fwnode(&fb) == &b && !find_io_range_by_fwnode(&fc), "find_io_range_by_fwnode(): finds B, not the unregistered C");
	check(logic_pio_to_hwaddr(0x10) == 0x1010 && logic_pio_to_hwaddr(0x100) == 0x2000 && logic_pio_to_hwaddr(0x2ff) == 0x21ff && logic_pio_to_hwaddr(0x300) == (resource_size_t)~0,
	      "logic_pio_to_hwaddr(): inside A and B, ~0 just past B");
	check(logic_pio_trans_cpuaddr(0x1010) == 0x10 && logic_pio_trans_cpuaddr(0x20ff) == 0x1ff && logic_pio_trans_cpuaddr(0x1100) == ~0UL && logic_pio_trans_cpuaddr(0x0fff) == ~0UL,
	      "logic_pio_trans_cpuaddr(): inside A and B, ~0UL just outside");
	check(logic_pio_trans_hwaddr(&fb, 0x2010, 0x10) == ~0UL, "logic_pio_trans_hwaddr(): an MMIO range is not an indirect one: ~0UL");
	logic_pio_unregister_range(&a);
	logic_pio_unregister_range(&b);
	check(!find_io_range_by_fwnode(&fa) && !find_io_range_by_fwnode(&fb), "logic_pio_unregister_range(): both gone");
}

#ifdef CONFIG_CPU_RMAP
/* lib/cpu_rmap: worked out on paper. Three objects; after an update with an affinity of CPU 0 alone, CPU 0 maps to that object at distance 0, and the other objects keep a
 * larger distance; the table is full after three adds (-ENOSPC); more than 0xffff objects is refused. */
static void __init test_cpu_rmap(void)
{
	static int o[4] __initdata;
	struct cpu_rmap *rmap = alloc_cpu_rmap(3, GFP_KERNEL);
	int i0, i1, i2;

	check(rmap && rmap->size == 3, "alloc_cpu_rmap(): three objects");
	if (!rmap)
		return;
	check(rmap->near[0].index == 0 && rmap->near[0].dist == CPU_RMAP_DIST_INF, "alloc_cpu_rmap(): CPUs start on a rota at infinite distance");
	i0 = cpu_rmap_add(rmap, &o[0]);
	i1 = cpu_rmap_add(rmap, &o[1]);
	i2 = cpu_rmap_add(rmap, &o[2]);
	check(i0 == 0 && i1 == 1 && i2 == 2 && cpu_rmap_add(rmap, &o[3]) == -ENOSPC && rmap->obj[1] == &o[1], "cpu_rmap_add(): indices 0 1 2, then -ENOSPC");
	check(cpu_rmap_update(rmap, 2, cpumask_of(0)) == 0 && rmap->near[0].index == 2 && rmap->near[0].dist == 0,
	      "cpu_rmap_update(): the CPU in the affinity mask maps to the object at distance 0");
	check(cpu_rmap_update(rmap, 1, cpumask_of(0)) == 0 && rmap->near[0].index == 1 && rmap->near[0].dist == 0, "cpu_rmap_update(): a later update takes the CPU over");
	check(!alloc_cpu_rmap(0x10000, GFP_KERNEL), "alloc_cpu_rmap(): more than 0xffff objects is refused");
	check(cpu_rmap_put(rmap) == 1, "cpu_rmap_put(): the last reference frees it");
}
#endif

/* lib/memcat_p: [a b] + [c] = [a b c], empty arrays on either side, both empty. */
static void __init test_memcat_p(void)
{
	static int v[3] __initdata;
	void *a[] = { &v[0], &v[1], NULL }, *b[] = { &v[2], NULL }, *e[] = { NULL };
	void **r = __memcat_p(a, b);

	check(r && r[0] == &v[0] && r[1] == &v[1] && r[2] == &v[2] && r[3] == NULL, "__memcat_p(): [a b] + [c] is [a b c], NULL-terminated");
	kfree(r);
	r = __memcat_p(e, b);
	check(r && r[0] == &v[2] && r[1] == NULL, "__memcat_p(): an empty first array");
	kfree(r);
	r = __memcat_p(a, e);
	check(r && r[0] == &v[0] && r[1] == &v[1] && r[2] == NULL, "__memcat_p(): an empty second array");
	kfree(r);
	r = __memcat_p(e, e);
	check(r && r[0] == NULL, "__memcat_p(): two empty arrays is an empty array");
	kfree(r);
}

/* lib/dec_and_lock: 2 -> 1 without the lock (0), 1 -> 0 returns 1 with the lock held; the irqsave and raw variants too; a counter that another CPU raised between the fast
 * path and the lock (modelled by a counter of 1 whose fast path is refused: cannot be forced here) is covered by the userspace differential. */
static void __init test_dec_and_lock(void)
{
	static DEFINE_SPINLOCK(sl);
	static DEFINE_RAW_SPINLOCK(rl);
	atomic_t a = ATOMIC_INIT(2);
	unsigned long flags;

	check(!_atomic_dec_and_lock(&a, &sl) && atomic_read(&a) == 1 && !spin_is_locked(&sl), "_atomic_dec_and_lock(): 2 -> 1 returns 0 and takes no lock");
	check(_atomic_dec_and_lock(&a, &sl) == 1 && atomic_read(&a) == 0 && spin_is_locked(&sl), "_atomic_dec_and_lock(): 1 -> 0 returns 1 with the lock held");
	spin_unlock(&sl);
	atomic_set(&a, 2);
	check(!_atomic_dec_and_lock_irqsave(&a, &sl, &flags) && atomic_read(&a) == 1 && !spin_is_locked(&sl), "_atomic_dec_and_lock_irqsave(): 2 -> 1 returns 0");
	check(_atomic_dec_and_lock_irqsave(&a, &sl, &flags) == 1 && atomic_read(&a) == 0 && spin_is_locked(&sl), "_atomic_dec_and_lock_irqsave(): 1 -> 0 returns 1 with the lock held");
	spin_unlock_irqrestore(&sl, flags);
	atomic_set(&a, 2);
	check(!_atomic_dec_and_raw_lock(&a, &rl) && _atomic_dec_and_raw_lock(&a, &rl) == 1 && atomic_read(&a) == 0 && raw_spin_is_locked(&rl), "_atomic_dec_and_raw_lock(): 2 -> 1 -> 0, locked at the end");
	raw_spin_unlock(&rl);
	atomic_set(&a, 1);
	check(_atomic_dec_and_raw_lock_irqsave(&a, &rl, &flags) == 1 && atomic_read(&a) == 0 && raw_spin_is_locked(&rl), "_atomic_dec_and_raw_lock_irqsave(): 1 -> 0 returns 1 with the lock held");
	raw_spin_unlock_irqrestore(&rl, flags);
	atomic_set(&a, 0);
	check(!_atomic_dec_and_lock(&a, &sl) && atomic_read(&a) == -1 && !spin_is_locked(&sl), "_atomic_dec_and_lock(): 0 -> -1 returns 0 (the counter was not 1)");
}

/* lib/bch: properties that hold for any correct BCH code, plus one vector computed by the original C. BCH(m=13, t=4): n = 8191, 13 is prime so every
 * cyclotomic coset has 13 elements and the generator polynomial has degree m*t = 52, i.e. 52 parity bits in 7 bytes. */
static void __init test_bch(void)
{
	static u8 data[40] __initdata, aligned[40] __initdata, bad[40] __initdata, ecc[8] __initdata, ecc2[8] __initdata, rec[8] __initdata;
	struct bch_control *bch = bch_init(13, 4, 0, false), *bsw = bch_init(13, 4, 0, true);
	unsigned int errloc[8], i;
	int r;
	u8 *p = data + 1;		/* deliberately unaligned */

	if (!bch || !bsw) {
		check(false, "bch_init(13, 4)");
		bch_free(bch);
		bch_free(bsw);
		return;
	}
	check(bch->m == 13 && bch->t == 4 && bch->n == 8191 && bch->ecc_bits == 52 && bch->ecc_bytes == 7,
	      "bch_init(13, 4): n = 8191, 52 parity bits in 7 bytes");
	check(!bch_init(4, 1, 0, false) && !bch_init(13, 0, 0, false) && !bch_init(13, 65, 0, false) && !bch_init(8, 40, 0, false) && !bch_init(8, 2, 0x11b, false),
	      "bch_init(): m < 5, t < 1, t > 64, m*t >= 2^m - 1 and a non-primitive polynomial are refused");
	for (i = 0; i < 32; i++)
		p[i] = i * 7 + 3;
	memcpy(aligned + 4, p, 32);

	memset(ecc, 0, sizeof(ecc));
	bch_encode(bch, aligned + 4, 0, ecc);
	check(!ecc[0] && !ecc[1] && !ecc[2] && !ecc[3] && !ecc[4] && !ecc[5] && !ecc[6], "bch_encode(): no data, no parity (the code is linear)");
	memset(ecc, 0, sizeof(ecc));
	bch_encode(bch, aligned + 4, 32, ecc);
	memset(ecc2, 0, sizeof(ecc2));
	bch_encode(bch, p, 32, ecc2);
	check(!memcmp(ecc, ecc2, 7), "bch_encode(): the same parity for aligned and unaligned data");
	memset(ecc2, 0, sizeof(ecc2));
	bch_encode(bch, aligned + 4, 13, ecc2);
	bch_encode(bch, aligned + 4 + 13, 19, ecc2);
	check(!memcmp(ecc, ecc2, 7), "bch_encode(): incremental encoding (13 + 19 bytes) equals one pass over 32");
	check(ecc[0] == 0x23 && ecc[1] == 0xcd && ecc[2] == 0xc5 && ecc[3] == 0x24 && ecc[4] == 0xd4 && ecc[5] == 0xd2 && ecc[6] == 0xf0,
	      "bch_encode(): parity of the 32-byte test pattern equals the one the original C produced");

	r = bch_decode(bch, aligned + 4, 32, ecc, NULL, NULL, errloc);
	check(r == 0, "bch_decode(): an intact codeword has no errors");
	memcpy(bad, aligned + 4, 32);
	bad[0] ^= 0x20;
	bad[10] ^= 0x01;
	bad[31] ^= 0x80;
	r = bch_decode(bch, bad, 32, ecc, NULL, NULL, errloc);
	check(r == 3, "bch_decode(): three flipped data bits are found");
	if (r == 3) {
		int seen = 0;

		for (i = 0; i < 3; i++) {
			seen |= errloc[i] == 5 ? 1 : 0;		/* data[0] bit 5 */
			seen |= errloc[i] == 80 ? 2 : 0;	/* data[10] bit 0 */
			seen |= errloc[i] == 255 ? 4 : 0;	/* data[31] bit 7 */
		}
		check(seen == 7, "bch_decode(): the locations are 5, 80 and 255 (byte * 8 + bit, bit 0 = least significant)");
		for (i = 0; i < 3; i++)
			bad[errloc[i] / 8] ^= 1 << (errloc[i] % 8);
		check(!memcmp(bad, aligned + 4, 32), "bch_decode(): flipping the reported bits restores the data");
	}
	memcpy(rec, ecc, 7);
	rec[3] ^= 0x10;
	r = bch_decode(bch, aligned + 4, 32, rec, NULL, NULL, errloc);
	check(r == 1 && errloc[0] >= 8 * 32 && errloc[0] < 8 * 32 + 52, "bch_decode(): a flipped parity bit is reported beyond the data");
	memcpy(bad, aligned + 4, 32);
	for (i = 0; i < 5; i++)
		bad[i * 6] ^= 0x04;
	r = bch_decode(bch, bad, 32, ecc, NULL, NULL, errloc);
	check(r != 5 && (r < 0 ? r == -EBADMSG : r <= 4), "bch_decode(): five errors exceed t = 4 and are never reported as five");
	check(bch_decode(bch, aligned + 4, 1020, ecc, NULL, NULL, errloc) == -EINVAL && bch_decode(bch, NULL, 32, ecc, NULL, NULL, errloc) == -EINVAL,
	      "bch_decode(): a length that does not fit and missing data are -EINVAL");

	memset(ecc2, 0, sizeof(ecc2));
	bch_encode(bsw, aligned + 4, 32, ecc2);
	memcpy(bad, aligned + 4, 32);
	bad[7] ^= 0x02;
	r = bch_decode(bsw, bad, 32, ecc2, NULL, NULL, errloc);
	check(r == 1 && errloc[0] == 7 * 8 + 1, "bch with swap_bits: one flipped bit is found at byte 7, bit 1");
	bch_free(bch);
	bch_free(bsw);
}

static int prtest_release __initdata, prtest_confirm __initdata;
static void __init prtest_release_fn(struct percpu_ref *ref) { prtest_release++; }
static void __init prtest_confirm_fn(struct percpu_ref *ref) { prtest_confirm++; }

/* lib/percpu-refcount: the lifecycle on paper -- percpu mode, kill (drop the initial reference, switch to atomic after a grace period, confirm), the last put
 * releasing, reinit, and the atomic / dead start modes. The release callback may run from the RCU callback, hence rcu_barrier() before looking. */
static void __init test_percpu_ref(void)
{
	struct percpu_ref r;

	prtest_release = prtest_confirm = 0;
	if (percpu_ref_init(&r, prtest_release_fn, PERCPU_REF_ALLOW_REINIT, GFP_KERNEL)) {
		check(false, "percpu_ref_init()");
		return;
	}
	check(!percpu_ref_is_dying(&r) && !percpu_ref_is_zero(&r), "percpu_ref_init(): live, percpu mode, one reference");
	percpu_ref_get(&r);
	percpu_ref_get_many(&r, 2);
	percpu_ref_put(&r);
	check(percpu_ref_tryget_live(&r) && !percpu_ref_is_zero(&r), "percpu_ref: gets and puts in percpu mode, tryget_live succeeds");
	percpu_ref_put_many(&r, 3);				/* back to the one initial reference */
	percpu_ref_kill_and_confirm(&r, prtest_confirm_fn);	/* drops it: the ref is dying, switching to atomic after a grace period */
	check(percpu_ref_is_dying(&r), "percpu_ref_kill_and_confirm(): dying");
	rcu_barrier();
	check(prtest_confirm == 1 && prtest_release == 1 && percpu_ref_is_zero(&r), "after the grace period: confirmed once, released once (the last put), zero");
	check(!percpu_ref_tryget_live(&r), "percpu_ref_tryget_live() fails on a dead ref");
	percpu_ref_reinit(&r);
	check(!percpu_ref_is_dying(&r) && !percpu_ref_is_zero(&r) && percpu_ref_tryget_live(&r), "percpu_ref_reinit(): live again with one reference");
	percpu_ref_put(&r);
	percpu_ref_kill(&r);
	rcu_barrier();
	check(prtest_release == 2 && percpu_ref_is_zero(&r), "killed a second time: released a second time");
	percpu_ref_exit(&r);

	prtest_release = 0;
	if (percpu_ref_init(&r, prtest_release_fn, PERCPU_REF_INIT_ATOMIC, GFP_KERNEL)) {
		check(false, "percpu_ref_init(ATOMIC)");
		return;
	}
	percpu_ref_get(&r);
	percpu_ref_put(&r);
	check(!percpu_ref_is_zero(&r) && prtest_release == 0, "PERCPU_REF_INIT_ATOMIC: atomic from the start, one reference");
	percpu_ref_kill(&r);					/* already atomic: the final put releases synchronously */
	check(prtest_release == 1 && percpu_ref_is_zero(&r), "kill in atomic mode releases at once");
	percpu_ref_exit(&r);

	if (percpu_ref_init(&r, prtest_release_fn, PERCPU_REF_INIT_DEAD, GFP_KERNEL)) {
		check(false, "percpu_ref_init(DEAD)");
		return;
	}
	check(percpu_ref_is_dying(&r) && percpu_ref_is_zero(&r) && !percpu_ref_tryget_live(&r), "PERCPU_REF_INIT_DEAD: starts dead with zero references");
	percpu_ref_resurrect(&r);
	check(!percpu_ref_is_dying(&r) && percpu_ref_tryget_live(&r), "percpu_ref_resurrect(): live again");
	percpu_ref_put(&r);
	prtest_release = 0;
	percpu_ref_kill(&r);
	rcu_barrier();
	percpu_ref_exit(&r);
}

static void __init test_rcuref(void)
{
	rcuref_t r;

	rcuref_init(&r, 1);
	check(rcuref_read(&r) == 1 && !rcuref_is_dead(&r), "rcuref_init(1): one reference");
	check(rcuref_get(&r) && rcuref_read(&r) == 2, "rcuref_get(): two references");
	check(!rcuref_put(&r) && rcuref_read(&r) == 1, "rcuref_put(): not the last");
	check(rcuref_put(&r) && rcuref_read(&r) == 0 && rcuref_is_dead(&r), "rcuref_put(): the last put reports true (slow path marks it dead)");
	check(!rcuref_get(&r) && rcuref_is_dead(&r), "rcuref_get() on a dead count fails (slow path) and keeps it dead");
	rcuref_init(&r, 3);
	check(!rcuref_put(&r) && !rcuref_put(&r) && rcuref_put(&r) && rcuref_is_dead(&r), "three references: the third put is the last");
}

/* lib/stackdepot: dedup, fetch, extra bits and the refcounted lifecycle (free -> freelist -> reuse after a grace period); expected values worked out on paper */
static void __init test_stackdepot(void)
{
	static unsigned long e1[3] __initdata = { 0x1001, 0x1002, 0x1003 };
	static unsigned long e2[3] __initdata = { 0x1001, 0x1002, 0x1004 };
	static unsigned long e3[2] __initdata = { 0x2001, 0x2002 };
	depot_stack_handle_t h1, h2, h3, hx, hg, hg2, hn, taken[64];
	int k, j;
	bool gp_done;
	unsigned long *out;
	unsigned int n;

	if (stack_depot_init()) {
		check(false, "stack_depot_init()");
		return;
	}
	h1 = stack_depot_save(e1, 3, GFP_KERNEL);
	h2 = stack_depot_save(e1, 3, GFP_KERNEL);
	h3 = stack_depot_save(e2, 3, GFP_KERNEL);
	check(h1 && h1 == h2 && h3 && h3 != h1, "stack_depot_save(): a repeated trace gets the same handle, a different trace another one");
	check(!stack_depot_save(e1, 0, GFP_KERNEL), "stack_depot_save(): zero entries is handle 0");
	n = stack_depot_fetch(h1, &out);
	check(n == 3 && out && out[0] == 0x1001 && out[1] == 0x1002 && out[2] == 0x1003, "stack_depot_fetch(): the three frames come back");
	n = stack_depot_fetch(h3, &out);
	check(n == 3 && out && out[2] == 0x1004, "stack_depot_fetch(): the second trace is distinct");
	check(stack_depot_fetch(0, &out) == 0 && !out, "stack_depot_fetch(0): nothing");
	hx = stack_depot_set_extra_bits(h1, 5);
	check(stack_depot_get_extra_bits(hx) == 5 && stack_depot_get_extra_bits(h1) == 0 && !stack_depot_set_extra_bits(0, 5),
	      "stack_depot_set_extra_bits()/get_extra_bits(): five extra bits ride in the handle, handle 0 stays 0");
	n = stack_depot_fetch(hx, &out);
	check(n == 3 && out && out[0] == 0x1001, "stack_depot_fetch(): a handle with extra bits still finds the record");
	check(stack_depot_save_flags(e1, 3, GFP_KERNEL, STACK_DEPOT_FLAG_CAN_ALLOC) == h1, "stack_depot_save_flags(): a persistent record is found without GET");

	hg = stack_depot_save_flags(e3, 2, GFP_KERNEL, STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
	hg2 = stack_depot_save_flags(e3, 2, GFP_KERNEL, STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
	check(hg && hg == hg2 && hg != h1, "stack_depot_save_flags(GET): the second GET of the same trace finds the record (count 2)");
	stack_depot_put(hg);
	n = stack_depot_fetch(hg, &out);
	check(n == 2 && out && out[0] == 0x2001, "stack_depot_put(): one put leaves the record in place");
	stack_depot_put(hg);			/* count 0: unlinked and put on the freelist with an RCU cookie */
	/* synchronize_rcu() alone does not guarantee a grace period: this runs early in boot, where it can return without one elapsing, and then the freed
	 * record's cookie (get_state_synchronize_rcu() at put time) does not poll as done and depot_pop_free() rightly refuses to reuse it. Found 2026-10-26 by
	 * dumping the freelist (record present, poll=0). Whether a grace period passes here depends on boot timing (it stopped doing so once the XArray mark
	 * bits were fixed), identically for the C and the Rust stackdepot. So: reuse is required only when a cookie taken after the put polls as done. */
	{
		unsigned long cookie = get_state_synchronize_rcu();

		synchronize_rcu();
		gp_done = poll_state_synchronize_rcu(cookie);
	}
	for (k = 0; k < 8; k++) {
		static unsigned long ek[4] __initdata;

		ek[0] = 0x3001 + 0x100 * k; ek[1] = ek[0] + 1; ek[2] = ek[0] + 2; ek[3] = ek[0] + 3;
		hn = stack_depot_save_flags(ek, 4, GFP_KERNEL, STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
		taken[k] = hn;
		n = stack_depot_fetch(hn, &out);
		check(hn && n == 4 && out && out[0] == ek[0] && out[3] == ek[3], "a GET trace saved after the last put holds its own frames");
		if (hn == hg)
			break;
	}
	if (gp_done)
		check(k < 8 && hn == hg, "after the last put and a grace period the freed record is reused for a later GET trace");
	for (j = 0; j < 8 && j <= k; j++)
		stack_depot_put(taken[j]);
}

static int sbtest_woken __initdata;
static int __init sbtest_wake_fn(struct wait_queue_entry *wq, unsigned int mode, int sync, void *key)
{
	sbtest_woken++;
	return 1;
}

/* lib/sbitmap: expected values worked out on paper with round-robin bitmaps (no random hints): depth 20, 8 bits per word => words of 8, 8 and 4 bits */
static void __init test_sbitmap(void)
{
	struct sbitmap sb;
	struct sbitmap_queue sbq;
	struct sbq_wait w;
	static const int shallow_want[] __initconst = { 0, 1, 2, 3, 8, 9, 10, 11, 16, 17, -1 };
	int tags[4], i, ok;
	unsigned long mask;
	unsigned int off;

	if (sbitmap_init_node(&sb, 20, 3, GFP_KERNEL, NUMA_NO_NODE, true, true)) {
		check(false, "sbitmap_init_node()");
		return;
	}
	check(sb.depth == 20 && sb.shift == 3 && sb.map_nr == 3 && sbitmap_weight(&sb) == 0 && !sbitmap_any_bit_set(&sb),
	      "sbitmap_init_node(): depth 20 in 8-bit words is 3 words, nothing set");
	ok = 1;
	for (i = 0; i < 19; i++)
		ok &= sbitmap_get(&sb) == i;
	check(ok, "sbitmap_get() round robin: bits 0..18 in order");
	check(sbitmap_get(&sb) == 19, "sbitmap_get(): after bit 18 the hint wraps to 0 and the last free bit, 19, is found");
	check(sbitmap_get(&sb) == -1 && sbitmap_get(&sb) == -1, "sbitmap_get(): a full map gives -1");
	check(sbitmap_weight(&sb) == 20 && sbitmap_any_bit_set(&sb), "sbitmap_weight(): 20 busy");
	sbitmap_put(&sb, 5);
	check(sbitmap_weight(&sb) == 19 && sbitmap_test_bit(&sb, 5), "sbitmap_put(): a deferred clear leaves the bit in word but out of weight");
	check(sbitmap_get(&sb) == 5, "sbitmap_get(): the allocator folds the deferred clear and hands bit 5 out again");
	sbitmap_put(&sb, 19);
	sbitmap_resize(&sb, 12);			/* folds every deferred clear, then depth 12 = words of 8 and 4 */
	check(sb.depth == 12 && sb.map_nr == 2 && !sbitmap_test_bit(&sb, 19) && sbitmap_weight(&sb) == 12,
	      "sbitmap_resize(): depth 12 is 2 words, the pending clear of bit 19 was folded, bits 0..11 still busy");
	sbitmap_free(&sb);

	/* shallow: depth 20, shallow_depth 10 allows 4 + 4 + 2 bits of the three words */
	if (sbitmap_queue_init_node(&sbq, 20, 3, true, GFP_KERNEL, NUMA_NO_NODE)) {
		check(false, "sbitmap_queue_init_node()");
		return;
	}
	check(sbq.wake_batch == 2 && sbq.min_shallow_depth == UINT_MAX, "sbitmap_queue_init_node(): wake_batch = 20 / 8 = 2");
	sbitmap_queue_min_shallow_depth(&sbq, 10);	/* callers must declare the smallest shallow depth they will use (else a WARN) */
	check(sbq.min_shallow_depth == 10 && sbq.wake_batch == 1, "sbitmap_queue_min_shallow_depth(10): wake_batch = min(20, 10) / 8 = 1");
	ok = 1;
	for (i = 0; i < ARRAY_SIZE(shallow_want); i++)
		ok &= sbitmap_queue_get_shallow(&sbq, 10) == shallow_want[i];
	check(ok, "sbitmap_queue_get_shallow(10): bits 0-3, 8-11, 16-17 and then -1");
	sbitmap_queue_clear(&sbq, 9, 0);
	check(sbitmap_weight(&sbq.sb) == 9, "sbitmap_queue_clear(): weight 10 -> 9");
	check(sbitmap_queue_get_shallow(&sbq, 10) == 9, "sbitmap_queue_get_shallow(): the cleared bit 9 comes back");
	sbitmap_queue_recalculate_wake_batch(&sbq, 4);
	check(sbq.wake_batch == 1, "sbitmap_queue_recalculate_wake_batch(4 users): (20 + 3) / 4 = 5, 5 / 8 = 0, clamped to 1");
	sbitmap_queue_min_shallow_depth(&sbq, 16);
	check(sbq.min_shallow_depth == 16 && sbq.wake_batch == 2, "sbitmap_queue_min_shallow_depth(16): wake_batch = min(20, 16) / 8 = 2");
	sbitmap_queue_resize(&sbq, 100);
	check(sbq.sb.depth == 100 && sbq.sb.map_nr == 13 && sbq.wake_batch == 2, "sbitmap_queue_resize(100): 13 words, wake_batch = min(100, 16) / 8 = 2");
	sbitmap_queue_free(&sbq);

	/* batch allocation: depth 16 in two words of 8, random hints => check the invariants */
	if (sbitmap_queue_init_node(&sbq, 16, 3, false, GFP_KERNEL, NUMA_NO_NODE)) {
		check(false, "sbitmap_queue_init_node(16)");
		return;
	}
	mask = __sbitmap_queue_get_batch(&sbq, 4, &off);
	check(mask == 0xf && (off == 0 || off == 8) && sbitmap_weight(&sbq.sb) == 4,
	      "__sbitmap_queue_get_batch(4): the lowest four free bits of one empty word, mask 0xf, offset 0 or 8");
	for (i = 0; i < 4; i++)
		tags[i] = off + i;
	sbitmap_queue_clear_batch(&sbq, 0, tags, 4);
	check(sbitmap_weight(&sbq.sb) == 0, "sbitmap_queue_clear_batch(): the four bits are free again");
	/* wake-up: one waiter on ws[0], wake_batch forced to 1 => the first completion wakes it and advances wake_index to 1 */
	sbitmap_queue_recalculate_wake_batch(&sbq, 100);
	init_waitqueue_func_entry(&w.wait, sbtest_wake_fn);
	w.sbq = NULL;
	sbitmap_add_wait_queue(&sbq, &sbq.ws[0], &w);
	w.wait.flags |= WQ_FLAG_EXCLUSIVE;		/* add_wait_queue() clears it; only exclusive waiters count as woken, which ends the scan early */
	check(atomic_read(&sbq.ws_active) == 1 && sbq.wake_batch == 1, "sbitmap_add_wait_queue(): one active waiter, wake_batch 1");
	sbtest_woken = 0;
	sbitmap_queue_wake_up(&sbq, 1);
	check(sbtest_woken == 1 && atomic_read(&sbq.wake_index) == 1 && atomic_read(&sbq.completion_cnt) == 1 && atomic_read(&sbq.wakeup_cnt) == 1,
	      "sbitmap_queue_wake_up(1): wakes the waiter, wake_index 0 -> 1, completion_cnt 1, wakeup_cnt 1");
	sbitmap_del_wait_queue(&w);
	check(atomic_read(&sbq.ws_active) == 0, "sbitmap_del_wait_queue(): no active waiters");
	sbitmap_queue_free(&sbq);
}

/* lib/scatterlist: expected values worked out on paper; real pages, the real header's inlines, the kernel's own kmap flavours */
static void __init test_scatterlist(void)
{
	struct sg_table t, t2;
	struct scatterlist *sg;
#ifdef CONFIG_SGL_ALLOC
	struct scatterlist *sgl, *last;
	struct sg_page_iter pi;
	struct sg_mapping_iter mi;
#endif
	struct page *pgs[6], *blk;
	struct sg_append_table ap = {};
	unsigned int n __maybe_unused = 0, i, cnt, ok;
	u8 *src = kmalloc(10000, GFP_KERNEL), *dst = kzalloc(10000, GFP_KERNEL);

	if (!src || !dst)
		goto out;
	for (i = 0; i < 10000; i++)
		src[i] = (u8)(i * 7 + 3);

#ifdef CONFIG_SGL_ALLOC
	/* three pages: 10000 bytes = 4096 + 4096 + 1808 */
	sgl = sgl_alloc(10000, GFP_KERNEL, &n);
	check(sgl && n == 3 && sg_nents(sgl) == 3, "sgl_alloc(10000): 3 entries");
	if (sgl) {
		check(sg_nents_for_len(sgl, 0) == 0 && sg_nents_for_len(sgl, 1) == 1 && sg_nents_for_len(sgl, 4096) == 1 &&
		      sg_nents_for_len(sgl, 4097) == 2 && sg_nents_for_len(sgl, 10000) == 3 && sg_nents_for_len(sgl, 10001) == -EINVAL,
		      "sg_nents_for_len: 0, 1, 4096, 4097, 10000 and 10001 bytes");
		last = sg_last(sgl, 3);
		check(last == sg_next(sg_next(sgl)) && sg_is_last(last) && last->length == 1808, "sg_last: third entry, 1808 bytes");
		check(sg_copy_from_buffer(sgl, 3, src, 10000) == 10000 && sg_copy_to_buffer(sgl, 3, dst, 10000) == 10000 &&
		      !memcmp(src, dst, 10000), "sg_copy_from_buffer then sg_copy_to_buffer: 10000 bytes round-trip");
		memset(dst, 0, 10000);
		check(sg_pcopy_to_buffer(sgl, 3, dst, 5000, 4000) == 5000 && !memcmp(dst, src + 4000, 5000) && dst[5000] == 0,
		      "sg_pcopy_to_buffer: skip 4000, copy 5000 across a page boundary");
		check(sg_pcopy_to_buffer(sgl, 3, dst, 100, 10000) == 0 && sg_pcopy_to_buffer(sgl, 3, dst, 100, 9950) == 50,
		      "sg_pcopy_to_buffer: skip at the end copies nothing, 50 bytes before it copies 50");
		check(sg_zero_buffer(sgl, 3, 3000, 3000) == 3000, "sg_zero_buffer: 3000 bytes from 3000");
		memset(dst, 0xff, 10000);
		sg_copy_to_buffer(sgl, 3, dst, 10000);
		for (i = 0, ok = 1; i < 10000; i++)
			ok = ok && dst[i] == ((i >= 3000 && i < 6000) ? 0 : (u8)(i * 7 + 3));
		check(ok, "sg_zero_buffer: exactly bytes 3000..5999 are zero");
		for (cnt = 0, __sg_page_iter_start(&pi, sgl, 3, 0); __sg_page_iter_next(&pi);)
			cnt++;
		check(cnt == 3, "page iterator over 3 entries visits 3 pages");
		for (cnt = 0, ok = 1, sg_miter_start(&mi, sgl, 3, SG_MITER_LOCAL | SG_MITER_FROM_SG); sg_miter_next(&mi); cnt++)
			ok = ok && mi.length == (cnt == 2 ? 1808 : 4096);
		sg_miter_stop(&mi);
		check(cnt == 3 && ok, "sg_miter: 4096, 4096, 1808 bytes");
		sgl_free(sgl);
	}
#endif

	/* a chained table: 300 entries are 128 + 128 + 44 plus two chain links */
	check(!sg_alloc_table(&t, 300, GFP_KERNEL), "sg_alloc_table(300)");
	check(t.nents == 300 && t.orig_nents == 300 && sg_nents(t.sgl) == 300, "sg_alloc_table(300): header and sg_nents are 300");
	for (cnt = 0, ok = 1, sg = t.sgl; sg; sg = sg_next(sg), cnt++)
		ok = ok && !sg_is_chain(sg) && (sg_is_last(sg) == (cnt == 299));
	check(cnt == 300 && ok, "sg_alloc_table(300): 300 data entries, only the last one ends the list");
	sg_free_table(&t);
	check(!t.sgl, "sg_free_table clears sgl");
	check(sg_alloc_table(&t, 0, GFP_KERNEL) == -EINVAL, "sg_alloc_table(0) is -EINVAL");

	/* from pages: 4 contiguous pages merge into one entry, 2 more elsewhere do not */
	blk = alloc_pages(GFP_KERNEL, 2);
	pgs[4] = alloc_page(GFP_KERNEL);
	pgs[5] = alloc_page(GFP_KERNEL);
	if (blk && pgs[4] && pgs[5]) {
		for (i = 0; i < 4; i++)
			pgs[i] = blk + i;
		check(!sg_alloc_table_from_pages_segment(&t, pgs, 4, 100, 4 * 4096 - 100, UINT_MAX, GFP_KERNEL) && t.nents == 1 &&
		      t.sgl->offset == 100 && t.sgl->length == 4 * 4096 - 100, "sg_alloc_table_from_pages: 4 contiguous pages are one entry");
		sg_free_table(&t);
		check(!sg_alloc_table_from_pages_segment(&t, pgs, 4, 0, 4 * 4096, 2 * 4096, GFP_KERNEL) && t.nents == 2 &&
		      t.sgl->length == 2 * 4096 && sg_next(t.sgl)->length == 2 * 4096, "sg_alloc_table_from_pages: max_segment 8192 splits it in two");
		sg_free_table(&t);
		pgs[2] = pgs[4];
		check(!sg_alloc_table_from_pages_segment(&t2, pgs, 3, 0, 3 * 4096 - 5, UINT_MAX, GFP_KERNEL) && t2.nents == 2 &&
		      t2.sgl->length == 2 * 4096 && sg_next(t2.sgl)->length == 4096 - 5, "sg_alloc_table_from_pages: a gap makes a second entry, size trims the last");
		sg_free_table(&t2);
		/* append: the second call continues the first entry when its page follows */
		pgs[0] = blk; pgs[1] = blk + 1;
		check(!sg_alloc_append_table_from_pages(&ap, pgs, 2, 0, 2 * 4096, UINT_MAX, 2, GFP_KERNEL) && ap.sgt.nents == 1,
		      "sg_alloc_append_table_from_pages: first call, 2 pages, 2 left");
		pgs[0] = blk + 2; pgs[1] = blk + 3;
		check(!sg_alloc_append_table_from_pages(&ap, pgs, 2, 0, 2 * 4096, UINT_MAX, 0, GFP_KERNEL) && ap.sgt.nents == 1 &&
		      ap.sgt.sgl->length == 4 * 4096 && sg_is_last(ap.prv), "sg_alloc_append_table_from_pages: the second call merges into the first entry and ends the list");
		sg_free_append_table(&ap);
	}
	if (blk)
		__free_pages(blk, 2);
	if (pgs[4])
		__free_page(pgs[4]);
	if (pgs[5])
		__free_page(pgs[5]);
out:
	kfree(src);
	kfree(dst);
}

/* lib/maple_tree: expected values worked out on paper (ranges: 10-11 v1, 12-14 v3, 15-19 v1, 20 v2). */
static void __init test_maple_tree(void)
{
	struct maple_tree mt, mt2, dup;
	unsigned long idx, start, n, sum;
	void *v1 = xa_mk_value(1), *v2 = xa_mk_value(2), *v3 = xa_mk_value(3);
	int i, ok;

	mt_init(&mt);
	ok = !mtree_store_range(&mt, 10, 19, v1, GFP_KERNEL);
	check(ok && mtree_load(&mt, 10) == v1 && mtree_load(&mt, 19) == v1 && !mtree_load(&mt, 9) && !mtree_load(&mt, 20),
	      "mtree_store_range: 10-19 holds v1, 9 and 20 are empty");
	check(mtree_insert(&mt, 15, v2, GFP_KERNEL) == -EEXIST && !mtree_insert(&mt, 20, v2, GFP_KERNEL) && mtree_load(&mt, 20) == v2,
	      "mtree_insert: inside an existing range is -EEXIST, 20 is free");
	check(!mtree_store_range(&mt, 12, 14, v3, GFP_KERNEL) && mtree_load(&mt, 11) == v1 && mtree_load(&mt, 12) == v3 &&
	      mtree_load(&mt, 14) == v3 && mtree_load(&mt, 15) == v1, "storing 12-14 splits the range: v1 | v3 | v1");

	idx = 0;
	ok = mt_find(&mt, &idx, ULONG_MAX) == v1 && idx == 12;
	ok = ok && mt_find(&mt, &idx, ULONG_MAX) == v3 && idx == 15;
	ok = ok && mt_find(&mt, &idx, ULONG_MAX) == v1 && idx == 20;
	ok = ok && mt_find(&mt, &idx, ULONG_MAX) == v2 && idx == 21;
	ok = ok && !mt_find(&mt, &idx, ULONG_MAX);
	check(ok, "mt_find walks v1 (10-11), v3, v1, v2 and sets the index one past each range");

	check(mtree_erase(&mt, 13) == v3 && !mtree_load(&mt, 12) && !mtree_load(&mt, 14) && mtree_load(&mt, 11) == v1 && mtree_load(&mt, 15) == v1,
	      "mtree_erase of 13 returns v3 and clears the whole range 12-14");
	idx = 12;
	check(mt_find(&mt, &idx, ULONG_MAX) == v1 && idx == 20, "mt_find from an empty slot skips to the next entry (15-19)");
	check(!mt_find(&mt, &idx, 19), "mt_find: an index past the maximum finds nothing");

	mt_init_flags(&dup, mt.ma_flags);
	check(!mtree_dup(&mt, &dup, GFP_NOWAIT) && mtree_load(&dup, 11) == v1 && mtree_load(&dup, 20) == v2 && !mtree_load(&dup, 13),
	      "mtree_dup: the copy holds the same entries");
	mtree_destroy(&dup);
	mtree_destroy(&mt);
	check(!mt.ma_root, "mtree_destroy empties the tree");

	mt_init_flags(&mt2, MT_FLAGS_ALLOC_RANGE);
	ok = !mtree_alloc_range(&mt2, &start, v1, 5, 10, 100, GFP_KERNEL) && start == 10;
	ok = ok && !mtree_alloc_range(&mt2, &start, v2, 5, 10, 100, GFP_KERNEL) && start == 15;
	ok = ok && !mtree_alloc_rrange(&mt2, &start, v3, 5, 10, 100, GFP_KERNEL) && start == 96;
	check(ok && mtree_load(&mt2, 12) == v1 && mtree_load(&mt2, 19) == v2 && mtree_load(&mt2, 100) == v3 && !mtree_load(&mt2, 95),
	      "mtree_alloc_range gives 10 then 15, mtree_alloc_rrange the top gap 96-100");
	ok = mtree_alloc_range(&mt2, &start, v1, 200, 10, 100, GFP_KERNEL) == -EINVAL;
	check(ok, "mtree_alloc_range: a size larger than the window is -EINVAL");
	mtree_destroy(&mt2);

	/* 300 single-index entries: forces splits through several levels, then erases the odd ones */
	mt_init(&mt);
	for (i = 0, ok = 1; i < 300; i++)
		ok = ok && !mtree_store(&mt, (unsigned long)i * 3, xa_mk_value(i + 5), GFP_KERNEL);
	for (i = 0; i < 300; i++)
		ok = ok && mtree_load(&mt, (unsigned long)i * 3) == xa_mk_value(i + 5) && !mtree_load(&mt, (unsigned long)i * 3 + 1);
	check(ok, "300 entries at every third index are all found, and the gaps between are empty");
	for (i = 1; i < 300; i += 2)
		ok = ok && mtree_erase(&mt, (unsigned long)i * 3) == xa_mk_value(i + 5);
	for (idx = 0, n = 0, sum = 0; ; ) {
		void *e = mt_find(&mt, &idx, ULONG_MAX);

		if (!e)
			break;
		n++;
		sum += xa_to_value(e);
	}
	/* even i in 0..298: 150 entries, values i+5 -> sum = 2*(0+..+149) + 150*5 = 22350 + 750 */
	check(ok && n == 150 && sum == 23100, "after erasing the odd 150, mt_find visits exactly the other 150 (value sum 23100)");
	mtree_destroy(&mt);
}

#if IS_ENABLED(CONFIG_INSTRUCTION_DECODER) && defined(CONFIG_X86_64)
/*
 * arch/x86/lib/insn.c + inat.c -> insn_rs.rs. Reached through the public decoder
 * entry insn_decode(). Lengths and fields are from the Intel SDM encodings, not the C:
 * 90 nop; 48 89 e5 mov %rsp,%rbp; e8 rel32 call; 0f 1f 44 00 00 nopl; 66 0f 1f 44 00 00
 * (operand size 2); c5 f8 77 vzeroupper (2-byte VEX); 48 b8 imm64 movabs; 8b 05 disp32
 * RIP-relative; 67 prefix makes addresses 4 bytes; f3 0f 1e fa endbr64; 62 f1 7c 48 28 c1
 * vmovaps %zmm1,%zmm0 (EVEX, 4 prefix bytes).
 */
static void __init test_x86_insn(void)
{
	static const u8 nop[] __initconst = { 0x90 };
	static const u8 mov[] __initconst = { 0x48, 0x89, 0xe5 };
	static const u8 call[] __initconst = { 0xe8, 0x01, 0x00, 0x00, 0x00 };
	static const u8 nopl[] __initconst = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	static const u8 nopw[] __initconst = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	static const u8 vzu[] __initconst = { 0xc5, 0xf8, 0x77 };
	static const u8 movabs[] __initconst = { 0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8 };
	static const u8 rip[] __initconst = { 0x8b, 0x05, 0x78, 0x56, 0x34, 0x12 };
	static const u8 a32[] __initconst = { 0x67, 0x8b, 0x00 };
	static const u8 endbr[] __initconst = { 0xf3, 0x0f, 0x1e, 0xfa };
	static const u8 evex[] __initconst = { 0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc1 };
	struct insn insn;

	check(insn_decode(&insn, nop, sizeof(nop), INSN_MODE_64) == 0 && insn.length == 1, "insn_decode(90) length 1");
	check(insn_decode(&insn, mov, sizeof(mov), INSN_MODE_64) == 0 && insn.length == 3 &&
	      insn.rex_prefix.nbytes == 1 && insn.opnd_bytes == 8, "insn_decode(48 89 e5): length 3, REX.W -> 8-byte operands");
	check(insn_decode(&insn, call, sizeof(call), INSN_MODE_64) == 0 && insn.length == 5 &&
	      insn.immediate.value == 1 && insn.immediate.nbytes == 4, "insn_decode(e8 rel32): length 5, rel32 == 1");
	check(insn_decode(&insn, nopl, sizeof(nopl), INSN_MODE_64) == 0 && insn.length == 5 && insn.sib.got, "insn_decode(0f 1f 44 00 00): length 5 with SIB");
	check(insn_decode(&insn, nopw, sizeof(nopw), INSN_MODE_64) == 0 && insn.length == 6 && insn.opnd_bytes == 2,
	      "insn_decode(66 0f 1f ...): length 6, 2-byte operands");
	check(insn_decode(&insn, vzu, sizeof(vzu), INSN_MODE_64) == 0 && insn.length == 3 && insn.vex_prefix.nbytes == 2,
	      "insn_decode(c5 f8 77 vzeroupper): length 3, 2-byte VEX");
	check(insn_decode(&insn, movabs, sizeof(movabs), INSN_MODE_64) == 0 && insn.length == 10 && insn.immediate1.value == 0x04030201 &&
	      insn.immediate2.value == 0x08070605, "insn_decode(movabs imm64): length 10, both halves");
	check(insn_decode(&insn, rip, sizeof(rip), INSN_MODE_64) == 0 && insn.length == 6 && insn_rip_relative(&insn) &&
	      insn.displacement.value == 0x12345678, "insn_decode(8b 05 disp32): RIP-relative, disp 0x12345678");
	check(insn_decode(&insn, a32, sizeof(a32), INSN_MODE_64) == 0 && insn.length == 3 && insn.addr_bytes == 4,
	      "insn_decode(67 8b 00): 4-byte addresses");
	check(insn_decode(&insn, endbr, sizeof(endbr), INSN_MODE_64) == 0 && insn.length == 4, "insn_decode(f3 0f 1e fa endbr64) length 4");
	check(insn_decode(&insn, evex, sizeof(evex), INSN_MODE_64) == 0 && insn.length == 6 && insn.vex_prefix.nbytes == 4,
	      "insn_decode(62 f1 7c 48 28 c1 vmovaps zmm): length 6, EVEX");
	check(insn_decode(&insn, call, 2, INSN_MODE_64) == -ENODATA, "insn_decode(truncated call) == -ENODATA");
	check(insn_decode(&insn, nopl, sizeof(nopl), INSN_MODE_KERN) == 0 && insn.length == 5 && insn.x86_64,
	      "insn_decode_kernel mode: 64-bit decoding");
}
#else
static void __init test_x86_insn(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_HMAC)
/*
 * crypto/hmac.c -> hmac_glue.c + hmac_rs.rs (the ipad/opad derivation, called from both hmac_setkey() and
 * hmac_setkey_ahash()). The proof caller drives the REAL template through the crypto API by algorithm name:
 * shash (crypto_alloc_shash("hmac(X)"): hmac_setkey) and ahash (crypto_alloc_ahash: hmac_setkey_ahash), for
 * md5, sha1 (only if built: config-full has CONFIG_CRYPTO_SHA1 off), sha224, sha256, sha384, sha512 and sha3-*.
 * NOTE: crypto_alloc_shash("hmac(sha256)") does NOT reach crypto/hmac.c: sha256.c registers "hmac-sha256-lib"
 * under that cra_name (same for md5/sha224/sha384/sha512), found by printing the driver name. The template is
 * reached by the explicit "hmac-shash(X)" instances and by "hmac(sha3-*)" (sha3 has no built-in HMAC); the ahash
 * path (hmac_setkey_ahash) only by "hmac(sha3-*)", which crypto_alloc_ahash() instantiates from the template.
 * Vectors: RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-2) cases 1-7 (keys of 131 and 80 bytes exercise the digest-the-key
 * path before the pads), plus key lengths 0, 1, bs-1, bs, bs+1, 2*bs; every digest from python3 hmac/hashlib
 * (port/test/hmac/gen_vectors.py), not from the kernel. Each vector runs one-shot digest, update in 1..7-byte
 * pieces, and export / import / finish; and once more through ahash.
 */
struct hmac_vec { const char *alg; u8 kk, kv; u16 kl; u8 mk, mv; u16 ml; const char *msg, *want; };

static void __init hmac_fill_key(u8 *b, u8 kind, u8 val, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		b[i] = kind == 0 ? val : kind == 1 ? i + 1 : i * 7 + 3;
}

static void __init hmac_fill_msg(u8 *b, u8 kind, u8 val, unsigned int n, const char *s)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		b[i] = kind == 0 ? val : kind == 2 ? i * 13 + 1 : s[i];
}

/* bit0: one-shot digest ok, bit1: pieces ok, bit2: export/import ok */
static unsigned int __init hmac_shash_run(struct crypto_shash *tfm, const u8 *key, unsigned int kl,
					  const u8 *msg, unsigned int ml, const u8 *want, unsigned int dl)
{
	SHASH_DESC_ON_STACK(d1, tfm);
	SHASH_DESC_ON_STACK(d2, tfm);
	u8 out[HASH_MAX_DIGESTSIZE], *state;
	unsigned int i, n, r = 0, half = ml / 2;

	if (crypto_shash_setkey(tfm, key, kl))
		return 0;
	state = kmalloc(crypto_shash_statesize(tfm), GFP_KERNEL);
	if (!state)
		return 0;
	d1->tfm = tfm;
	d2->tfm = tfm;
	if (!crypto_shash_digest(d1, msg, ml, out) && !memcmp(out, want, dl))
		r |= 1;
	memset(out, 0, sizeof(out));
	if (!crypto_shash_init(d1)) {
		for (i = 0; i < ml; i += n) {
			n = min(i % 7 + 1, ml - i);
			if (crypto_shash_update(d1, msg + i, n))
				break;
		}
		if (i >= ml && !crypto_shash_final(d1, out) && !memcmp(out, want, dl))
			r |= 2;
	}
	memset(out, 0, sizeof(out));
	if (!crypto_shash_init(d1) && !crypto_shash_update(d1, msg, half) && !crypto_shash_export(d1, state) &&
	    !crypto_shash_import(d2, state) && !crypto_shash_update(d2, msg + half, ml - half) &&
	    !crypto_shash_final(d2, out) && !memcmp(out, want, dl))
		r |= 4;
	shash_desc_zero(d1);
	shash_desc_zero(d2);
	kfree(state);
	return r;
}

static bool __init hmac_ahash_run(const char *alg, const u8 *key, unsigned int kl, const u8 *msg, unsigned int ml,
				  const u8 *want, unsigned int dl)
{
	DECLARE_CRYPTO_WAIT(wait);
	struct crypto_ahash *tfm = crypto_alloc_ahash(alg, 0, 0);
	struct ahash_request *req;
	u8 out[HASH_MAX_DIGESTSIZE];
	bool ok = false;

	if (IS_ERR(tfm))
		return false;
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (req && !crypto_ahash_setkey(tfm, key, kl)) {
		ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
		ahash_request_set_virt(req, msg, out, ml);
		ok = !crypto_wait_req(crypto_ahash_digest(req), &wait) && !memcmp(out, want, dl);
	}
	ahash_request_free(req);
	crypto_free_ahash(tfm);
	return ok;
}

static void __init crypto_free_shash_if_ok(struct crypto_shash *tfm)
{
	if (!IS_ERR(tfm))
		crypto_free_shash(tfm);
}

static void __init test_hmac(void)
{
	/* GENERATED by port/test/hmac/gen_vectors.py (python3 hmac/hashlib; RFC 2202 and RFC 4231 cases) -- do not edit */
	static const struct hmac_vec hv[] __initconst = {
		{ "hmac(md5)", 0, 0x0b, 16, 3, 0x00, 8, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d" },
		{ "hmac(md5)", 0, 0xaa, 16, 0, 0xdd, 50, "", "56be34521d144c88dbb8c733f0e8b3f6" },
		{ "hmac(md5)", 1, 0x00, 25, 0, 0xcd, 50, "", "697eaf0aca3a3aea3a75164746ffaa79" },
		{ "hmac(md5)", 0, 0x0c, 16, 3, 0x00, 20, "Test With Truncation", "56461ef2342edc00f9bab995690efd4c" },
		{ "hmac(md5)", 0, 0xaa, 80, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" },
		{ "hmac(md5)", 0, 0xaa, 80, 3, 0x00, 73, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "6f630fad67cda0ee1fb1f562db3aa53e" },
		{ "hmac(sha1)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00" },
		{ "hmac(sha1)", 0, 0xaa, 20, 0, 0xdd, 50, "", "125d7342b9ac11cd91a39af48aa17b4f63f175d3" },
		{ "hmac(sha1)", 1, 0x00, 25, 0, 0xcd, 50, "", "4c9007f4026250c6bc8414f9bf50c86c2d7235da" },
		{ "hmac(sha1)", 0, 0x0c, 20, 3, 0x00, 20, "Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" },
		{ "hmac(sha1)", 0, 0xaa, 80, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e95705637ce8a3b55ed402112" },
		{ "hmac(sha1)", 0, 0xaa, 80, 3, 0x00, 73, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" },
		{ "hmac(sha224)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22" },
		{ "hmac(sha224)", 0, 0xaa, 20, 0, 0xdd, 50, "", "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea" },
		{ "hmac(sha224)", 1, 0x00, 25, 0, 0xcd, 50, "", "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a" },
		{ "hmac(sha224)", 0, 0x0c, 20, 3, 0x00, 20, "Test With Truncation", "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c" },
		{ "hmac(sha224)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e" },
		{ "hmac(sha224)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1" },
		{ "hmac(sha256)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
		{ "hmac(sha256)", 0, 0xaa, 20, 0, 0xdd, 50, "", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
		{ "hmac(sha256)", 1, 0x00, 25, 0, 0xcd, 50, "", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
		{ "hmac(sha256)", 0, 0x0c, 20, 3, 0x00, 20, "Test With Truncation", "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5" },
		{ "hmac(sha256)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
		{ "hmac(sha256)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
		{ "hmac(sha384)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" },
		{ "hmac(sha384)", 0, 0xaa, 20, 0, 0xdd, 50, "", "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27" },
		{ "hmac(sha384)", 1, 0x00, 25, 0, 0xcd, 50, "", "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb" },
		{ "hmac(sha384)", 0, 0x0c, 20, 3, 0x00, 20, "Test With Truncation", "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea" },
		{ "hmac(sha384)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952" },
		{ "hmac(sha384)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e" },
		{ "hmac(sha512)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" },
		{ "hmac(sha512)", 0, 0xaa, 20, 0, 0xdd, 50, "", "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" },
		{ "hmac(sha512)", 1, 0x00, 25, 0, 0xcd, 50, "", "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd" },
		{ "hmac(sha512)", 0, 0x0c, 20, 3, 0x00, 20, "Test With Truncation", "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b" },
		{ "hmac(sha512)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" },
		{ "hmac(sha512)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" },
		{ "hmac(sha3-224)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7" },
		{ "hmac(sha3-224)", 0, 0xaa, 20, 0, 0xdd, 50, "", "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a" },
		{ "hmac(sha3-224)", 1, 0x00, 25, 0, 0xcd, 50, "", "a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb" },
		{ "hmac(sha3-224)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f" },
		{ "hmac(sha3-224)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0" },
		{ "hmac(sha3-256)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb" },
		{ "hmac(sha3-256)", 0, 0xaa, 20, 0, 0xdd, 50, "", "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207" },
		{ "hmac(sha3-256)", 1, 0x00, 25, 0, 0xcd, 50, "", "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7" },
		{ "hmac(sha3-256)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b" },
		{ "hmac(sha3-256)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123" },
		{ "hmac(sha3-384)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd" },
		{ "hmac(sha3-384)", 0, 0xaa, 20, 0, 0xdd, 50, "", "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e" },
		{ "hmac(sha3-384)", 1, 0x00, 25, 0, 0xcd, 50, "", "3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984da2d0f9449b3ba8425ec7fb8c31bc136" },
		{ "hmac(sha3-384)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc" },
		{ "hmac(sha3-384)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5a900edce01f5f61e2f408cdf2fd3e7e8" },
		{ "hmac(sha3-512)", 0, 0x0b, 20, 3, 0x00, 8, "Hi There", "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e" },
		{ "hmac(sha3-512)", 0, 0xaa, 20, 0, 0xdd, 50, "", "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03" },
		{ "hmac(sha3-512)", 1, 0x00, 25, 0, 0xcd, 50, "", "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d" },
		{ "hmac(sha3-512)", 0, 0xaa, 131, 3, 0x00, 54, "Test Using Larger Than Block-Size Key - Hash Key First", "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4" },
		{ "hmac(sha3-512)", 0, 0xaa, 131, 3, 0x00, 152, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba" },
		{ "hmac(md5)", 2, 0x00, 0, 2, 0x00, 100, "", "f8613becbc05a8f5fb570b2fe03d995b" },
		{ "hmac(md5)", 2, 0x00, 1, 2, 0x00, 100, "", "e24408dc469f5c252208bce96815b43a" },
		{ "hmac(md5)", 2, 0x00, 63, 2, 0x00, 100, "", "06ab2c1dc7cc04f2348b291f0a8a5315" },
		{ "hmac(md5)", 2, 0x00, 64, 2, 0x00, 100, "", "b43fc8adc094baa344a20fca19c46489" },
		{ "hmac(md5)", 2, 0x00, 65, 2, 0x00, 100, "", "3fe4a13f96445e6802c5c704b09ca4b0" },
		{ "hmac(md5)", 2, 0x00, 128, 2, 0x00, 100, "", "f1cd154e85a3ac7edffe5f05ef0e5954" },
		{ "hmac(sha1)", 2, 0x00, 0, 2, 0x00, 100, "", "18f03101d092b9aeeab8aa76f0569cf53e035984" },
		{ "hmac(sha1)", 2, 0x00, 1, 2, 0x00, 100, "", "9b9e5721911362e6cafe363d4feaba13be40132b" },
		{ "hmac(sha1)", 2, 0x00, 63, 2, 0x00, 100, "", "a3f0a04debfd63e1214e3385f4922730d771aeca" },
		{ "hmac(sha1)", 2, 0x00, 64, 2, 0x00, 100, "", "90e7b30579c78f8c833c9d769bf960e3f3af10d8" },
		{ "hmac(sha1)", 2, 0x00, 65, 2, 0x00, 100, "", "d3cc567f5f44e64af67cd0f9dcb90f6e7eff282e" },
		{ "hmac(sha1)", 2, 0x00, 128, 2, 0x00, 100, "", "722393989655ee2d359896cc6b5b9310008a2338" },
		{ "hmac(sha224)", 2, 0x00, 0, 2, 0x00, 100, "", "9f4430097326ff814020160ed44eef5d4bcfd44648c80fa233a3c890" },
		{ "hmac(sha224)", 2, 0x00, 1, 2, 0x00, 100, "", "27039dd4496a636c313e20d24d0078e6e12ebe3d2a43018894a8c87d" },
		{ "hmac(sha224)", 2, 0x00, 63, 2, 0x00, 100, "", "d9a3b2b6234597b024370e1da54b1a38b20e0ed025dfc474734473ee" },
		{ "hmac(sha224)", 2, 0x00, 64, 2, 0x00, 100, "", "0387f0753d87fe01a2bc82d01ef1cfe69c6accfeaba1608ea088c8bc" },
		{ "hmac(sha224)", 2, 0x00, 65, 2, 0x00, 100, "", "5e6b518365e66f956f2e3251db2638d0b9b0bd86fdc12b97990d5151" },
		{ "hmac(sha224)", 2, 0x00, 128, 2, 0x00, 100, "", "c585ea2b33bbf05ead2a49ac6e75da07a424d522f7f9dd1d0b5f5dbc" },
		{ "hmac(sha256)", 2, 0x00, 0, 2, 0x00, 100, "", "71fb112d99e52f5fe1ed690dc36dbeb876ac77f5a1cbd9a82e59b9782746f519" },
		{ "hmac(sha256)", 2, 0x00, 1, 2, 0x00, 100, "", "24638bceee0ff3336adf2310b23a636f2aa60dfe978901fcbc2883c226585167" },
		{ "hmac(sha256)", 2, 0x00, 63, 2, 0x00, 100, "", "1171baa40a0f7a429454cda5b7d584a96b47bb38d3ae12d58c3da85bab8015a5" },
		{ "hmac(sha256)", 2, 0x00, 64, 2, 0x00, 100, "", "bcbaf21ef09af73f1f3751d0ca0417cd7b96c5e15e9e99705833b61440f30cee" },
		{ "hmac(sha256)", 2, 0x00, 65, 2, 0x00, 100, "", "0c1df03568e0a49ffc26bb67696ca4145bcee9628be0efb86482111d9225251c" },
		{ "hmac(sha256)", 2, 0x00, 128, 2, 0x00, 100, "", "3b44a030dd92e1001bc560d7791fc8914b514dc49af58b8ebd87927dee453c6f" },
		{ "hmac(sha384)", 2, 0x00, 0, 2, 0x00, 100, "", "7796cf687312290b0fea1be451bc421ec799a163d50107709988e294feab14080861a27a76c4ec60cd005357e78e8269" },
		{ "hmac(sha384)", 2, 0x00, 1, 2, 0x00, 100, "", "823d031bcb6db2ad2f7711f89df95c0e771bea04e2da523653c37ad7f819c630b01e42feffefb42a26e75b6f805bf454" },
		{ "hmac(sha384)", 2, 0x00, 127, 2, 0x00, 100, "", "df7c135a07ae1e58fb21d42f44759753526af48c342aeb7948a0d3281c2dfbd62f689693ffe7b20ac06e4b82b16c186b" },
		{ "hmac(sha384)", 2, 0x00, 128, 2, 0x00, 100, "", "61eb5e96d33b7032c1dc07b8af7aba84ce9db6c39b80d945b388ed70bc6970d3e092a5f3e8a24ea7309d0f9ffcc84618" },
		{ "hmac(sha384)", 2, 0x00, 129, 2, 0x00, 100, "", "e6d4e38ffee13918b88a74cac8ed4747adab9a2e60af1717198b02719dc5470f23149a9917f9349156ac37f639d2e989" },
		{ "hmac(sha384)", 2, 0x00, 256, 2, 0x00, 100, "", "ba415fb1260f8bdb657f99233419c32c2ff49f1282e49b3ff45ff90897a78e83cc80b0ff3dbe397db93dd5c3adaa0527" },
		{ "hmac(sha512)", 2, 0x00, 0, 2, 0x00, 100, "", "1e45db3c4696b968859f71cda81425bca852f247a34b02570c251fae4e010138a5a411dd564a98388057f199321608f5ae19ea37c5f1df5940a511f21ed4f2e5" },
		{ "hmac(sha512)", 2, 0x00, 1, 2, 0x00, 100, "", "04d12a65ef8ee7aa844b95c5de93ff06fabfa48dbaddf1815318c6d574ea81af952dced3311f6b115703cb0cbd71a363048ca6da86d0c5772dbb1bb71f3c1176" },
		{ "hmac(sha512)", 2, 0x00, 127, 2, 0x00, 100, "", "cf2b8bb2c576e94cc259fb7ffd4f903b8bb2b9f7bc58599bc9c4c149bdc4ee2864c87f1682a60a300c414b68b529711e86961033a69c56e5c8ffc8418bbff62e" },
		{ "hmac(sha512)", 2, 0x00, 128, 2, 0x00, 100, "", "02d114bed5f42ddd8277115db3c7cb7cd6348f4bf1539958c3ff9f1dbc42c31fa219e2fcc3f347bddb17b8c944f94b0921443338e4a5bd91d1bc446de135c5a6" },
		{ "hmac(sha512)", 2, 0x00, 129, 2, 0x00, 100, "", "f08814fec98bd91445c235307c8f81f721619f0d0950d9c33d3f67a673072695003b304819a34b94a28e1858dd3d14614d477a15d7291a61563fbe5de57b190f" },
		{ "hmac(sha512)", 2, 0x00, 256, 2, 0x00, 100, "", "f197ca48725f1fe553eeea940c0056a59430433b0ff68de8982d613873f105499c91aa87564ccc6b64f86349c7e746a39ab7d1ef31be688ff03defaba89e335f" },
		{ "hmac(sha3-224)", 2, 0x00, 0, 2, 0x00, 100, "", "a1db677424bc86549b5b997847fba6b805c81f81dec7ba0637f19286" },
		{ "hmac(sha3-224)", 2, 0x00, 1, 2, 0x00, 100, "", "f2d697e161ecb759d2b358e5ad86c4e200352b89fc3449e9e1a1d56b" },
		{ "hmac(sha3-224)", 2, 0x00, 143, 2, 0x00, 100, "", "11b5913a937dca7b7ac0c0d66aa9edcb34ada29cdd5f5f8f895fb8db" },
		{ "hmac(sha3-224)", 2, 0x00, 144, 2, 0x00, 100, "", "ba846b03203dbe5426e78abd71a248cfe122bcaf303eefa8ad8114f7" },
		{ "hmac(sha3-224)", 2, 0x00, 145, 2, 0x00, 100, "", "13ceb8c8f2e0c8445bab78d529a2b32f204b9d8feaed95355459ed52" },
		{ "hmac(sha3-224)", 2, 0x00, 288, 2, 0x00, 100, "", "57a320b0cd35fc526570480557c5fb40e9bf4f64045538255b9e7b11" },
		{ "hmac(sha3-256)", 2, 0x00, 0, 2, 0x00, 100, "", "a175b7501e9b5b9bf59cf402e88176401fd5e0fec221170c29cfb9da2f162c5b" },
		{ "hmac(sha3-256)", 2, 0x00, 1, 2, 0x00, 100, "", "7a151acc3e0fece48bbd475c3f2c5c04a5083da647bed705cb73c5ea338189fa" },
		{ "hmac(sha3-256)", 2, 0x00, 135, 2, 0x00, 100, "", "15bf44b0f580f539f6a109267d2c6afeea34483127b8fb32a58ca1bb425a61d2" },
		{ "hmac(sha3-256)", 2, 0x00, 136, 2, 0x00, 100, "", "4e07a11bfcda5e9b085c117c298b2835559484fffd2c55892d99ede7bbbdb2fd" },
		{ "hmac(sha3-256)", 2, 0x00, 137, 2, 0x00, 100, "", "e943ea9f93351d2df0ef134ce8fafe41ee6935f8e285c23bfc4ac4e8c8ec3c2e" },
		{ "hmac(sha3-256)", 2, 0x00, 272, 2, 0x00, 100, "", "738f2acef90a13a5f0791660a3d9726094776874469ffcbca1a71bb07dcfa29a" },
		{ "hmac(sha3-384)", 2, 0x00, 0, 2, 0x00, 100, "", "b5c390fc30e7831aa0dc346832249b7795aeeea7051cf6a5fcb1957c3752f5287e4d0cd03767abb4d68a8b21ed6f62d3" },
		{ "hmac(sha3-384)", 2, 0x00, 1, 2, 0x00, 100, "", "baf9f8936a58e0e8c85c3b4be221b83b70aba84cee5c533ebc629777b39f63abd9d87d53c090883cfc73860936b83113" },
		{ "hmac(sha3-384)", 2, 0x00, 103, 2, 0x00, 100, "", "35728c8727ee1a2dfe54b6c208594008ef4579be388c9ccfd7cfbe7100500ab9854a92a6a5d9ef709f295224d91056ec" },
		{ "hmac(sha3-384)", 2, 0x00, 104, 2, 0x00, 100, "", "131a1b50d673fc7309d83abbef5d9d3f66f7bc41a32143d2206e2ceb112b328314896697333e94699fec03bca3a8258c" },
		{ "hmac(sha3-384)", 2, 0x00, 105, 2, 0x00, 100, "", "0348ca997861645cff8856d11a9d54e3b2514e43c22d1d527a55f976fa828c02919c38000952f77fc5edfb15de7b1214" },
		{ "hmac(sha3-384)", 2, 0x00, 208, 2, 0x00, 100, "", "dc2db469ea0cc0ac9eab4206b80aeebc0ad11bdc6d5a567c9c67778ce46ff36895d5773e6150e3c7a24c01354b6907ee" },
		{ "hmac(sha3-512)", 2, 0x00, 0, 2, 0x00, 100, "", "b40eb05173c7257f7cc24b6250f2b459f513715a112a0957518755601c2813a4108b21903eb747ab35020d5b57133e8ce46c0e16433b2849d0d4b3b9a1d1fcad" },
		{ "hmac(sha3-512)", 2, 0x00, 1, 2, 0x00, 100, "", "890df78583126a89d4c4e4b7384c8c7aa642bbc22c83701f35cd529c767321e0f93974feaa9ad56a2b991aec0562138c41507c371569a89d1e9eba3ed686228c" },
		{ "hmac(sha3-512)", 2, 0x00, 71, 2, 0x00, 100, "", "9c478cbcc06a8e8db90b57c52a8b84db3b1eba57b19af186987b0c6ae85918cb0d22085f8056554964aa64eaa02efa954a12e4b7dd9992c974a7ed3637866ee9" },
		{ "hmac(sha3-512)", 2, 0x00, 72, 2, 0x00, 100, "", "0a812e75ab9c8d3f81bbf56b35ae03f229111f4572460392065792044cb95db695f08d1ed1847699bbbc169e07ff380cea5b12d11380b5363cef280e841d23fb" },
		{ "hmac(sha3-512)", 2, 0x00, 73, 2, 0x00, 100, "", "72d9a756730c588dfe9735cecc81abc123c598fb2b77831c740352d29b55edf7d239be1a1fd9b89e2a1454decb291c3161403f5824f0e7cdd37277d411dbbe21" },
		{ "hmac(sha3-512)", 2, 0x00, 144, 2, 0x00, 100, "", "c32d2bdc867242566e40e982146b77def920b46aba6e66162ab081e71ea268f2279d3f717f2b95bd132d32427bfe131a5302bbfb3c5893678f5ad8a683fe6662" },
	};
	static const struct { const char *alg, *want; } hjefe[] __initconst = {
		{ "hmac(md5)", "750c783e6ab0b503eaa86e310a5db738" },
		{ "hmac(sha1)", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" },
		{ "hmac(sha224)", "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44" },
		{ "hmac(sha256)", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
		{ "hmac(sha384)", "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" },
		{ "hmac(sha512)", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" },
		{ "hmac(sha3-224)", "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66" },
		{ "hmac(sha3-256)", "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5" },
		{ "hmac(sha3-384)", "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a" },
		{ "hmac(sha3-512)", "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024" },
	};
	static u8 key[320] __initdata, msg[160] __initdata, want[HASH_MAX_DIGESTSIZE] __initdata;
	/*
	 * vector name; name that makes the template instantiate; instance to allocate (its driver name); ahash too.
	 * "hmac-shash(X)" instantiates the instance cra_name "hmac(X)" / driver "hmac-shash(X-lib)" (crypto_inst_setname
	 * in __hmac_create_shash); the alloc of the trigger name itself then fails, which is expected, and the instance
	 * is allocated by its driver name. hmac(sha3-224/256) cannot be ahash: their statesize exceeds HASH_MAX_STATESIZE.
	 */
	static const struct { const char *vec, *trigger, *inst; bool ahash; } algs[] __initconst = {
		{ "hmac(md5)", "hmac-shash(md5)", "hmac-shash(md5-lib)", false },
		{ "hmac(sha1)", "hmac-shash(sha1)", "hmac-shash(sha1-lib)", false },
		{ "hmac(sha224)", "hmac-shash(sha224)", "hmac-shash(sha224-lib)", false },
		{ "hmac(sha256)", "hmac-shash(sha256)", "hmac-shash(sha256-lib)", false },
		{ "hmac(sha384)", "hmac-shash(sha384)", "hmac-shash(sha384-lib)", false },
		{ "hmac(sha512)", "hmac-shash(sha512)", "hmac-shash(sha512-lib)", false },
		{ "hmac(sha3-224)", NULL, "hmac(sha3-224)", false }, { "hmac(sha3-256)", NULL, "hmac(sha3-256)", false },
		{ "hmac(sha3-384)", NULL, "hmac(sha3-384)", true }, { "hmac(sha3-512)", NULL, "hmac(sha3-512)", true },
	};
	unsigned int cnt[ARRAY_SIZE(algs)][5] = { };	/* per alg: vectors, shash digest, pieces, export/import, ahash */
	struct crypto_shash *tfms[ARRAY_SIZE(algs)];
	unsigned int a, v, dl, r;
	char name[48];

	for (a = 0; a < ARRAY_SIZE(algs); a++) {
		if (algs[a].trigger)
			crypto_free_shash_if_ok(crypto_alloc_shash(algs[a].trigger, 0, 0));
		tfms[a] = crypto_alloc_shash(algs[a].inst, 0, 0);
	}
	for (v = 0; v < ARRAY_SIZE(hv) + ARRAY_SIZE(hjefe); v++) {
		const char *alg, *w, *m = NULL;
		unsigned int kl, ml;

		if (v < ARRAY_SIZE(hv)) {
			alg = hv[v].alg;
			kl = hv[v].kl;
			ml = hv[v].ml;
			w = hv[v].want;
			hmac_fill_key(key, hv[v].kk, hv[v].kv, kl);
			hmac_fill_msg(msg, hv[v].mk, hv[v].mv, ml, hv[v].msg);
		} else {	/* RFC 2202 / 4231 case 2 */
			alg = hjefe[v - ARRAY_SIZE(hv)].alg;
			w = hjefe[v - ARRAY_SIZE(hv)].want;
			memcpy(key, "Jefe", 4);
			kl = 4;
			m = "what do ya want for nothing?";
			ml = strlen(m);
			memcpy(msg, m, ml);
		}
		for (a = 0; a < ARRAY_SIZE(algs) && strcmp(alg, algs[a].vec); a++)
			;
		dl = strlen(w) / 2;
		if (a == ARRAY_SIZE(algs) || IS_ERR(tfms[a]) || hex2bin(want, w, dl))
			continue;
		cnt[a][0]++;
		r = hmac_shash_run(tfms[a], key, kl, msg, ml, want, dl);
		cnt[a][1] += !!(r & 1);
		cnt[a][2] += !!(r & 2);
		cnt[a][3] += !!(r & 4);
		if (algs[a].ahash)
			cnt[a][4] += hmac_ahash_run(algs[a].inst, key, kl, msg, ml, want, dl);
	}
	for (a = 0; a < ARRAY_SIZE(algs); a++) {
		if (IS_ERR(tfms[a])) {
			/* an instance may be absent only when its hash is not built in (config-full has CONFIG_CRYPTO_SHA1 off; the arm64 fast config has no SHA1/SHA512) */
			check(!hmac_hash_builtin(algs[a].vec), "hmac template instances available for every hash that is built in");
			continue;
		}
		check(cnt[a][0] > 0, "hmac vectors ran");
		/* the instance really is the template's: its driver name starts "hmac" and is not a library "hmac-X-lib" one (a template
		 * instance is named hmac...(base driver)) */
		check(!strncmp(crypto_tfm_alg_driver_name(crypto_shash_tfm(tfms[a])), "hmac", 4) &&
		      strchr(crypto_tfm_alg_driver_name(crypto_shash_tfm(tfms[a])), '('),
		      "hmac instance is crypto/hmac.c's template, not a library hmac");
		snprintf(name, sizeof(name), "%s shash digest, %u RFC/python vectors", algs[a].inst, cnt[a][0]);
		check(cnt[a][1] == cnt[a][0], name);
		snprintf(name, sizeof(name), "%s shash update in 1..7-byte pieces", algs[a].inst);
		check(cnt[a][2] == cnt[a][0], name);
		snprintf(name, sizeof(name), "%s shash export/import/final", algs[a].inst);
		check(cnt[a][3] == cnt[a][0], name);
		if (algs[a].ahash) {
			snprintf(name, sizeof(name), "%s ahash digest (hmac_setkey_ahash)", algs[a].inst);
			check(cnt[a][4] == cnt[a][0], name);
		}
		crypto_free_shash(tfms[a]);
	}
}
#else
static void __init test_hmac(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_CMAC) && IS_BUILTIN(CONFIG_CRYPTO_AES)
/*
 * crypto/cmac.c -> cmac_glue.c + cmac_rs.rs (subkey derivation K1/K2 by GF(2^128) doubling, and the final-block
 * xor with the 0x80 pad and K1 or K2). Driven through the crypto API: crypto_alloc_shash("cmac(aes)") has no
 * library twin, so it is crypto/cmac.c's template instance (checked: its driver name starts "cmac("), with AES-128,
 * AES-192 and AES-256 (block size 16, the GF(2^128) arm). The 8-byte-block arm (cmac(des3_ede)) is NOT reached:
 * CONFIG_CRYPTO_DES is off in config-full. Vectors: the NIST SP 800-38B Appendix D examples (message lengths 0, 16,
 * 40, 64: K1 is used for the lengths that are a multiple of 16, K2 for 40) and 13 more lengths per key that cover
 * every tail (1..15 bytes, full blocks, more than 4 blocks); every MAC computed by OpenSSL, not by the kernel
 * (port/test/cmac/gen_vectors.py asserts the NIST published values). Each vector: one-shot digest, update in
 * 1..7-byte pieces then final, setkey twice (a different key first), export/import is not supported by cmac.
 */
struct cmac_vec { u8 kb, msgkind; u16 ml; const char *mac; };
static const struct cmac_vec cmac_vecs[] __initconst = {
	{ 16, 0, 0, "bb1d6929e95937287fa37d129b756746" },
	{ 16, 0, 16, "070a16b46b4d4144f79bdd9dd04a287c" },
	{ 16, 0, 40, "dfa66747de9ae63030ca32611497c827" },
	{ 16, 0, 64, "51f0bebf7e3b9d92fc49741779363cfe" },
	{ 16, 1, 1, "0c37b47629c8964456af83b6717811bb" },
	{ 16, 1, 7, "b757abb3a54896ff2452a9341f1bc0ab" },
	{ 16, 1, 8, "c2661c5cdd5985e49c493dc0d2daaba3" },
	{ 16, 1, 15, "80d28056c4865d802b252bf4f9bc2658" },
	{ 16, 1, 17, "f8a9453440d91c239239af1fc876a8e1" },
	{ 16, 1, 31, "e041338a1fab40787497c961328b1f36" },
	{ 16, 1, 32, "b08bb6669f0de82598dbf0498cb0c362" },
	{ 16, 1, 33, "4cb4ac5499efc7c8f6c5937e1b1eefc2" },
	{ 16, 1, 47, "e20b6d2b7eb2f663722d597dbdd46dc1" },
	{ 16, 1, 48, "6bd0f3ae3639a8f27189f597b3eeb9a5" },
	{ 16, 1, 63, "b7cc78769fb74bff395b844a60a2b5e1" },
	{ 16, 1, 65, "63c9e5c9246280c95bc4e20474ab49bc" },
	{ 16, 1, 100, "ca097f02d7109d2cffa995dddc3c9db9" },
	{ 24, 0, 0, "d17ddf46adaacde531cac483de7a9367" },
	{ 24, 0, 16, "9e99a7bf31e710900662f65e617c5184" },
	{ 24, 0, 40, "8a1de5be2eb31aad089a82e6ee908b0e" },
	{ 24, 0, 64, "a1d5df0eed790f794d77589659f39a11" },
	{ 24, 1, 1, "cdb49ee1a5102a5a977e4794d09db930" },
	{ 24, 1, 7, "c6065690cd8c6f24c7367d488464720c" },
	{ 24, 1, 8, "67e9b55485b31c23736b2175c6ad9865" },
	{ 24, 1, 15, "dc88549578370e604462f34ced2cfc53" },
	{ 24, 1, 17, "f72568e2f49ecb3bece6406f63546ade" },
	{ 24, 1, 31, "04a01c81784d4c87cee52749745c0598" },
	{ 24, 1, 32, "5d62cf47ab654064bd715e8f661fadb3" },
	{ 24, 1, 33, "c537ae391aad702e58b72e50c976f51a" },
	{ 24, 1, 47, "8f14830d2fb1555ad6e1459d5d2b68f3" },
	{ 24, 1, 48, "597a78824b7d2e633afdd68ef2996195" },
	{ 24, 1, 63, "683b08337f249aa2b1ab233e5ee47c83" },
	{ 24, 1, 65, "19f69fab70a3093d27fe6fffabfdb141" },
	{ 24, 1, 100, "4263cbaf9ff3599c19fa77dc12ff1111" },
	{ 32, 0, 0, "028962f61b7bf89efc6b551f4667d983" },
	{ 32, 0, 16, "28a7023f452e8f82bd4bf28d8c37c35c" },
	{ 32, 0, 40, "aaf3d8f1de5640c232f5b169b9c911e6" },
	{ 32, 0, 64, "e1992190549f6ed5696a2c056c315410" },
	{ 32, 1, 1, "4b2dbba27d717cf8eb0de4a9edb768b2" },
	{ 32, 1, 7, "0b052a63c9a860feea4f20679810bc99" },
	{ 32, 1, 8, "de667b654913eb11ff764edf55b86e21" },
	{ 32, 1, 15, "c45ba5f1cadb7128f246572e12499832" },
	{ 32, 1, 17, "627880c45e4db7b0b8f5e47ba4420859" },
	{ 32, 1, 31, "2d98f0eaa4513d4d37d9166a01b405db" },
	{ 32, 1, 32, "8742959baf782e7aa511d3bed3aba0fb" },
	{ 32, 1, 33, "f1919c3eac63b89115ac97e5b11a517d" },
	{ 32, 1, 47, "b33c8a3f14369d57a6cf54da792e863a" },
	{ 32, 1, 48, "8561dcea68734e0117e1b328c2364da2" },
	{ 32, 1, 63, "240ae8a6b16f6bc27d994ee33dbc7763" },
	{ 32, 1, 65, "29e1e2ee57e91402fbe7ce9241cf8805" },
	{ 32, 1, 100, "6b658185c70f7fc67f0ac78a537b9255" },
};

static void __init cmac_hex(u8 *dst, const char *s, unsigned int n)
{
	if (hex2bin(dst, s, n))
		check(false, "cmac test vector hex is valid");
}

static void __init test_cmac(void)
{
	static const char *const keyhex[3] __initconst = {
		"2b7e151628aed2a6abf7158809cf4f3c",
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	};
	static const char nist_msg[] __initconst =
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	struct crypto_shash *tfm;
	u8 key[32], other[32], msg[128], want[16], out[16];
	unsigned int v, i, n, oneshot = 0, pieces = 0, total = 0, k;
	bool named;

	tfm = crypto_alloc_shash("cmac(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		check(false, "cmac(aes) can be allocated");
		return;
	}
	named = !strncmp(crypto_tfm_alg_driver_name(crypto_shash_tfm(tfm)), "cmac(", 5);
	check(named, "cmac(aes) is crypto/cmac.c's template instance (driver name cmac(...))");
	check(crypto_shash_blocksize(tfm) == 16 && crypto_shash_digestsize(tfm) == 16, "cmac(aes): block and digest size 16");
	cmac_hex(msg, nist_msg, 64);
	for (v = 0; v < ARRAY_SIZE(cmac_vecs); v++) {
		const struct cmac_vec *c = &cmac_vecs[v];
		SHASH_DESC_ON_STACK(d, tfm);

		k = c->kb == 16 ? 0 : c->kb == 24 ? 1 : 2;
		cmac_hex(key, keyhex[k], c->kb);
		cmac_hex(want, c->mac, 16);
		if (c->msgkind)
			for (i = 0; i < c->ml; i++)
				msg[i] = (i * 29 + 5) & 0xff;
		else
			cmac_hex(msg, nist_msg, 64);
		total++;
		memset(other, 0x5a, sizeof(other));
		d->tfm = tfm;
		/* setkey twice: a different key first, then the real one (the subkeys must be rederived) */
		if (crypto_shash_setkey(tfm, other, c->kb) || crypto_shash_setkey(tfm, key, c->kb))
			continue;
		if (!crypto_shash_digest(d, msg, c->ml, out) && !memcmp(out, want, 16))
			oneshot++;
		memset(out, 0, sizeof(out));
		if (!crypto_shash_init(d)) {
			for (i = 0; i < c->ml; i += n) {
				n = min(i % 7 + 1, c->ml - i);
				if (crypto_shash_update(d, msg + i, n))
					break;
			}
			if (i >= c->ml && !crypto_shash_final(d, out) && !memcmp(out, want, 16))
				pieces++;
		}
		shash_desc_zero(d);
	}
	check(oneshot == total, "cmac(aes) one-shot digest: 51 vectors, AES-128/192/256 (NIST SP 800-38B + OpenSSL)");
	check(pieces == total, "cmac(aes) update in 1..7-byte pieces then final: 51 vectors");
	crypto_free_shash(tfm);
}
#else
static void __init test_cmac(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_CTR) && IS_BUILTIN(CONFIG_CRYPTO_AES)
/*
 * crypto/ctr.c -> ctr_glue.c + ctr_rs.rs (the counter-mode block loops: segment, in-place and final block, and the
 * RFC 3686 counter block). Driven through the crypto API: crypto_alloc_skcipher("ctr(aes)") has no library twin
 * (CONFIG_CRYPTO_AES_NI_INTEL is off in config-full), so it is crypto/ctr.c's template instance over aes-generic
 * (checked: its driver name starts "ctr("), and "rfc3686(ctr(aes))" the rfc3686 template over it ("rfc3686(").
 * Vectors: NIST SP 800-38A F.5.1/F.5.3/F.5.5 (AES-128/192/256 CTR, the published 64-byte ciphertexts, and prefixes of
 * them for the final-block path), plus counters that carry out of the low 32 bits and wrap the whole 128-bit block,
 * every ciphertext computed by `openssl enc` (port/test/ctr/gen_vectors.py asserts the NIST and RFC 3686 published
 * values); RFC 3686 section 6 vectors #1-#3 (published) and six computed ones with 192/256-bit keys. Each vector:
 * (A) one request out of place, (B) one request in place, (C)/(D) the same split into requests of 16/32/48 bytes then
 * the rest with the IV carried between requests (the final partial block is only in the last request: the walk
 * continues from the counter the previous request left in the IV, so non-final pieces are whole blocks).
 * rfc3686 is only run as one request (A, B): each rfc3686 request restarts its counter at 1 by definition, so
 * carrying the IV across requests does not apply to it.
 * NOT reached: ciphers with 8-byte blocks (DES is off), and an async cipher.
 */
struct ctr_vec { u8 kb, ivk, mk, ml; const char *ct; };
struct rfc3686_vec { const char *key, *nonce, *iv; u8 ptk, ml; const char *ct; };
/* ctr(aes): { key bytes, iv kind (0 NIST f0..ff, 1 carries out of the low 32 bits, 2 all 0xff), message kind (0 NIST prefix, 1 pattern), length, ciphertext } */
static const struct ctr_vec ctr_vecs[] __initconst = {
	{ 16, 0, 0, 64, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" },
	{ 16, 0, 0, 33, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5a" },
	{ 16, 0, 1, 1, "e9" },
	{ 16, 0, 1, 15, "e9aee02fe1f6cf601fd831318be03a" },
	{ 16, 0, 1, 16, "e9aee02fe1f6cf601fd831318be03a5c" },
	{ 16, 0, 1, 17, "e9aee02fe1f6cf601fd831318be03a5ce3" },
	{ 16, 0, 1, 100, "e9aee02fe1f6cf601fd831318be03a5ce3d973102e15d2c3a57a80c3cd1e1826cfee1c8461bf643f331e0fff16a4571c9d0e965319f7bb868970a66fc482a0d6f56f3864ad5c621edd22571331f57efa4dab0b36c447c215eed0e6cc0c0742d3dedbb345" },
	{ 16, 1, 0, 64, "633e3fa130ca6717f4ae606a9cb408ee139a4ab85772d5de62df811d333d72a5de3082d2379dec3b57868c898ff4ad8f125a7a4792bc6972491deaecc6fe2ca4" },
	{ 16, 1, 0, 33, "633e3fa130ca6717f4ae606a9cb408ee139a4ab85772d5de62df811d333d72a5de" },
	{ 16, 1, 1, 1, "0d" },
	{ 16, 1, 1, 15, "0dddbe1f671c4b51f099393f8e5984" },
	{ 16, 1, 1, 16, "0dddbe1f671c4b51f099393f8e59847c" },
	{ 16, 1, 1, 17, "0dddbe1f671c4b51f099393f8e59847c68" },
	{ 16, 1, 1, 48, "0dddbe1f671c4b51f099393f8e59847c6845cfc30017fae241b219a547dc977c4b3a41688df75b5a3fd78a7494e0c438" },
	{ 16, 1, 1, 100, "0dddbe1f671c4b51f099393f8e59847c6845cfc30017fae241b219a547dc977c4b3a41688df75b5a3fd78a7494e0c4389157f1cea4f5d125b94c3c23f17c109ca620890e3b6dd078d4a9c247c7bed74308f5603811c857594c5ae1e6e02a32a131c3d3eb" },
	{ 16, 2, 0, 64, "e13338e36cb71962e00d020b4cedbd86d3dae15b04bb352fa0f59febfcb4da3e67da610697ed5aae4b0fa7a0dd783d2961a00ab697367915d23c754bd99e2899" },
	{ 16, 2, 0, 33, "e13338e36cb71962e00d020b4cedbd86d3dae15b04bb352fa0f59febfcb4da3e67" },
	{ 16, 2, 1, 1, "8f" },
	{ 16, 2, 1, 15, "8fd0b95d3b613524e43a5b5e5e0031" },
	{ 16, 2, 1, 16, "8fd0b95d3b613524e43a5b5e5e003114" },
	{ 16, 2, 1, 17, "8fd0b95d3b613524e43a5b5e5e003114a8" },
	{ 16, 2, 1, 48, "8fd0b95d3b613524e43a5b5e5e003114a805642053de1a138398075388553fe7f2d0a2bc2d87edcf235ea15dc66c549e" },
	{ 16, 2, 1, 100, "8fd0b95d3b613524e43a5b5e5e003114a805642053de1a138398075388553fe7f2d0a2bc2d87edcf235ea15dc66c549ee2ad813fa17fc142226da384ee1c14a103fe0057cc032ab19952ac1ddab77a7d9f4e78c1f5981cd2b444f99eaf4c9ad40a2ac71b" },
	{ 24, 0, 0, 64, "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050" },
	{ 24, 0, 0, 33, "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e" },
	{ 24, 0, 1, 1, "74" },
	{ 24, 0, 1, 15, "745f129a408430e44b1c5d0cec93e2" },
	{ 24, 0, 1, 16, "745f129a408430e44b1c5d0cec93e299" },
	{ 24, 0, 1, 17, "745f129a408430e44b1c5d0cec93e29972" },
	{ 24, 0, 1, 100, "745f129a408430e44b1c5d0cec93e29972dcbc975dc3d5d3f6a15a7e802f6b4d8b3c71d16b817111b9ec1b9b4d34c240cc752c7fe4d1b10faac60c236f448c680d7033abbbe20d25851b87e6d4f8ff51cb3136de28941cf6df1e6b5a3d279bc7c6e5ec01" },
	{ 24, 1, 0, 64, "ae0ea4969e62819707a86c5f94f8354979be03f0ea4dfeeb6931b187257cc6c0c1a83dc6a6453f36bb0987acfd9773888fc95a19a63c6778eac6661a4fc38cd6" },
	{ 24, 1, 0, 33, "ae0ea4969e62819707a86c5f94f8354979be03f0ea4dfeeb6931b187257cc6c0c1" },
	{ 24, 1, 1, 1, "c0" },
	{ 24, 1, 1, 15, "c0ed2528c9b4add1039f350a8615b9" },
	{ 24, 1, 1, 16, "c0ed2528c9b4add1039f350a8615b9db" },
	{ 24, 1, 1, 17, "c0ed2528c9b4add1039f350a8615b9db02" },
	{ 24, 1, 1, 48, "c0ed2528c9b4add1039f350a8615b9db0261868bbd28d1d74a5c293f519d231954a2fe7c1c2f8857d3588151e6831a3f" },
	{ 24, 1, 1, 100, "c0ed2528c9b4add1039f350a8615b9db0261868bbd28d1d74a5c293f519d231954a2fe7c1c2f8857d3588151e6831a3f0cc4d1909075df2f1a97b0d57841b0eee5bbcae8e52dcc575a167ba68b101569dda1a5bd48ab226e373e7ca35fe3cc45c588afb4" },
	{ 24, 2, 0, 64, "5cc38fab30b6ac67dcc21e7b012ecf988c68a7d957ab090f01c44e62afc2df1ace7bdea8029039ebaa295a1424fe45d2564eee85c2fa2fd2ce79369e8d55bc73" },
	{ 24, 2, 0, 33, "5cc38fab30b6ac67dcc21e7b012ecf988c68a7d957ab090f01c44e62afc2df1ace" },
	{ 24, 2, 1, 1, "32" },
	{ 24, 2, 1, 15, "32200e1567608021d8f5472e13c343" },
	{ 24, 2, 1, 16, "32200e1567608021d8f5472e13c3430a" },
	{ 24, 2, 1, 17, "32200e1567608021d8f5472e13c3430af7" },
	{ 24, 2, 1, 48, "32200e1567608021d8f5472e13c3430af7b722a200ce263322a9d6dadb233ac35b711d12b8fa8e8ac2785ce93fea2c65" },
	{ 24, 2, 1, 100, "32200e1567608021d8f5472e13c3430af7b722a200ce263322a9d6dadb233ac35b711d12b8fa8e8ac2785ce93fea2c65d543650cf4b397853e28e051bad7804bf5151d91e7bb13e0ce3ffbc02edbbb48fe751d80060c8b87178ad8bc8c6c78f2654432dc" },
	{ 32, 0, 0, 64, "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" },
	{ 32, 0, 0, 33, "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b" },
	{ 32, 0, 1, 1, "0e" },
	{ 32, 0, 1, 15, "0efd42ad2081a5e3b390ac51a91e5e" },
	{ 32, 0, 1, 16, "0efd42ad2081a5e3b390ac51a91e5eba" },
	{ 32, 0, 1, 17, "0efd42ad2081a5e3b390ac51a91e5eba8f" },
	{ 32, 0, 1, 100, "0efd42ad2081a5e3b390ac51a91e5eba8f9c66b11a079aa6e9e97128be2b101cbe03f36018575e2d802111473690f13a5cc44e04803315f1e3930bc772fb7d9ece15807c60aafa82fabd69984871184f59d928eee9a0cb6391b8fc1154142e65fccc4cc0" },
	{ 32, 1, 0, 64, "261ad4acbc9f5ae0d878394574577aa61e6f60c17cf66fd6779ee3b604575c43839b9de1b9eb69c618239e298bd984546b20d9e362028f7ecd597e107546d827" },
	{ 32, 1, 0, 33, "261ad4acbc9f5ae0d878394574577aa61e6f60c17cf66fd6779ee3b604575c4383" },
	{ 32, 1, 1, 1, "48" },
	{ 32, 1, 1, 15, "48f95512eb4976a6dc4f601066baf6" },
	{ 32, 1, 1, 16, "48f95512eb4976a6dc4f601066baf634" },
	{ 32, 1, 1, 17, "48f95512eb4976a6dc4f601066baf63465" },
	{ 32, 1, 1, 48, "48f95512eb4976a6dc4f601066baf63465b0e5ba2b9340ea54f37b0e70b6b99a16915e5b0381dea7707298d490cdede3" },
	{ 32, 1, 1, 100, "48f95512eb4976a6dc4f601066baf63465b0e5ba2b9340ea54f37b0e70b6b99a16915e5b0381dea7707298d490cdede3e82d526a544b37293d08a8df42c4e41fa446dee5d95fa1a515e220643a11f739db90910a2dea242948a8375b1c7ab2c512645ebb" },
	{ 32, 2, 0, 64, "50fd97c3e61abb4873fb78df1e8e77e64b457cd68accda4a89fa236c06bf2605a1dd021ba826fb0a252c6dc9b434030be1910794ac1349c2d4cd7bf39da5ff03" },
	{ 32, 2, 0, 33, "50fd97c3e61abb4873fb78df1e8e77e64b457cd68accda4a89fa236c06bf2605a1" },
	{ 32, 2, 1, 1, "3e" },
	{ 32, 2, 1, 15, "3e1e167db1cc970e77cc218a0c63fb" },
	{ 32, 2, 1, 16, "3e1e167db1cc970e77cc218a0c63fb74" },
	{ 32, 2, 1, 17, "3e1e167db1cc970e77cc218a0c63fb7430" },
	{ 32, 2, 1, 48, "3e1e167db1cc970e77cc218a0c63fb74309af9addda9f576aa97bbd4725ec3dc34d7c1a1124c4c6b4d7d6b34af206abc" },
	{ 32, 2, 1, 100, "3e1e167db1cc970e77cc218a0c63fb74309af9addda9f576aa97bbd4725ec3dc34d7c1a1124c4c6b4d7d6b34af206abc629c8c1d9a5af195249cad3caa27c33b0d6f43711fe0f675b833d292355c63d614a941244d9f9aa2a4a5aa4f8ff0a7dccd452349" },
};
/* rfc3686(ctr(aes)): { key bytes (without nonce), nonce, iv, plaintext kind (0 = "Single block msg", 1 = 00 01 02 ..), length, ciphertext } */
static const struct rfc3686_vec rfc3686_vecs[] __initconst = {
	{ "ae6852f8121067cc4bf7a5765577f39e", "00000030", "0000000000000000", 0, 16, "e4095d4fb7a7b3792d6175a3261311b8" },
	{ "7e24067817fae0d743d6ce1f32539163", "006cb6db", "c0543b59da48d90b", 1, 32, "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28" },
	{ "7691be035e5020a8ac6e618529f9a0dc", "00e0017b", "27777f3f4a1786f0", 1, 36, "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f" },
	{ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "e0a1b2c3", "0102030405060708", 1, 16, "13b46d0d13c63d42dcf910dbbcc84d71" },
	{ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "e0a1b2c3", "0102030405060708", 1, 36, "13b46d0d13c63d42dcf910dbbcc84d717c571e78bd6562d45bdb59d54f9ba758cd2c255f" },
	{ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "e0a1b2c3", "0102030405060708", 1, 50, "13b46d0d13c63d42dcf910dbbcc84d717c571e78bd6562d45bdb59d54f9ba758cd2c255f1a91e5faa13bc27c00c47f036996" },
	{ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "e0a1b2c3", "0102030405060708", 1, 16, "dc308305f0fc1c7ffe5ab2678d848a17" },
	{ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "e0a1b2c3", "0102030405060708", 1, 36, "dc308305f0fc1c7ffe5ab2678d848a17b78a937ae5423f8beea1f23dd60cc97a1ce869bf" },
	{ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "e0a1b2c3", "0102030405060708", 1, 50, "dc308305f0fc1c7ffe5ab2678d848a17b78a937ae5423f8beea1f23dd60cc97a1ce869bf1dca694176ca16dd2524fe13f4ab" },
};

static void __init ctr_hex(u8 *dst, const char *s, unsigned int n)
{
	if (hex2bin(dst, s, n))
		check(false, "ctr test vector hex is valid");
}

/* one request over [off, off + len) of the buffers; src/dst separate (dst != NULL) or in place */
static int __init ctr_req(struct crypto_skcipher *tfm, u8 *iv, u8 *src, u8 *dst, unsigned int len)
{
	DECLARE_CRYPTO_WAIT(wait);
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct scatterlist s, d;
	int err;

	if (!req)
		return -ENOMEM;
	sg_init_one(&s, src, len);
	sg_init_one(&d, dst ? dst : src, len);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &s, &d, len, iv);
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);
	return err;
}

/* run one vector four ways; returns a bitmask of the ways that matched `want` (bit 0 = A ... bit 3 = D) */
static unsigned int __init ctr_run(struct crypto_skcipher *tfm, const u8 *iv0, const u8 *msg, const u8 *want, unsigned int len, unsigned int ivs,
					 unsigned int nmodes)
{
	u8 *iv = kmalloc(16, GFP_KERNEL), *in = kmalloc(len + 1, GFP_KERNEL), *out = kmalloc(len + 1, GFP_KERNEL);
	unsigned int mask = 0, mode, off, n, piece;

	if (!iv || !in || !out)
		goto done;
	for (mode = 0; mode < nmodes; mode++) {
		bool inplace = mode & 1, split = mode & 2;

		memcpy(iv, iv0, ivs);
		memcpy(in, msg, len);
		memset(out, 0xA5, len);
		piece = 0;
		for (off = 0; off < len; off += n) {
			n = split && len - off > 16 ? 16 * (1 + piece++ % 3) : len - off;
			if (n > len - off)
				n = len - off;
			if (ctr_req(tfm, iv, in + off, inplace ? NULL : out + off, n))
				break;
		}
		if (off >= len && !memcmp(inplace ? in : out, want, len))
			mask |= 1u << mode;
	}
done:
	kfree(iv); kfree(in); kfree(out);
	return mask;
}

static void __init test_ctr(void)
{
	static const char *const keyhex[3] __initconst = {
		"2b7e151628aed2a6abf7158809cf4f3c",
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	};
	static const char nist_msg[] __initconst =
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	static const char nist_iv[] __initconst = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	struct crypto_skcipher *tfm, *rfc;
	u8 key[40], iv[16], msg[128], want[128];
	unsigned int v, k, i, m, ways[4] = { 0, 0, 0, 0 }, total = 0, rways[4] = { 0, 0, 0, 0 }, rtotal = 0;

	tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		check(false, "ctr(aes) can be allocated");
		return;
	}
	check(!strncmp(crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), "ctr(", 4),
	      "ctr(aes) is crypto/ctr.c's template instance (driver name ctr(...))");
	check(crypto_skcipher_ivsize(tfm) == 16 && crypto_skcipher_blocksize(tfm) == 1 && crypto_skcipher_chunksize(tfm) == 16,
	      "ctr(aes): iv size 16, stream block size 1, chunk size 16");
	for (v = 0; v < ARRAY_SIZE(ctr_vecs); v++) {
		const struct ctr_vec *c = &ctr_vecs[v];

		k = c->kb == 16 ? 0 : c->kb == 24 ? 1 : 2;
		ctr_hex(key, keyhex[k], c->kb);
		switch (c->ivk) {
		case 0: ctr_hex(iv, nist_iv, 16); break;
		case 1: for (i = 0; i < 12; i++) iv[i] = i; iv[12] = iv[13] = iv[14] = 0xff; iv[15] = 0xfe; break;
		default: memset(iv, 0xff, 16);
		}
		if (c->mk == 0)
			ctr_hex(msg, nist_msg, c->ml);
		else
			for (i = 0; i < c->ml; i++)
				msg[i] = (i * 29 + 5) & 0xff;
		ctr_hex(want, c->ct, c->ml);
		if (crypto_skcipher_setkey(tfm, key, c->kb))
			continue;
		total++;
		m = ctr_run(tfm, iv, msg, want, c->ml, 16, 4);
		for (i = 0; i < 4; i++)
			ways[i] += !!(m & (1u << i));
	}
	check(ways[0] == total, "ctr(aes) one request, out of place: AES-128/192/256 NIST F.5 + carry/wrap counters (OpenSSL)");
	check(ways[1] == total, "ctr(aes) one request, in place");
	check(ways[2] == total, "ctr(aes) 16/32/48-byte requests with the IV carried, out of place");
	check(ways[3] == total, "ctr(aes) 16/32/48-byte requests with the IV carried, in place");
	crypto_free_skcipher(tfm);

	rfc = crypto_alloc_skcipher("rfc3686(ctr(aes))", 0, 0);
	if (IS_ERR(rfc)) {
		check(false, "rfc3686(ctr(aes)) can be allocated");
		return;
	}
	check(!strncmp(crypto_tfm_alg_driver_name(crypto_skcipher_tfm(rfc)), "rfc3686(", 8),
	      "rfc3686(ctr(aes)) is crypto/ctr.c's rfc3686 template instance");
	check(crypto_skcipher_ivsize(rfc) == 8, "rfc3686(ctr(aes)): iv size 8");
	for (v = 0; v < ARRAY_SIZE(rfc3686_vecs); v++) {
		const struct rfc3686_vec *c = &rfc3686_vecs[v];
		unsigned int kb = strlen(c->key) / 2;

		ctr_hex(key, c->key, kb);
		ctr_hex(key + kb, c->nonce, 4);		/* the nonce is the last 4 bytes of the key */
		ctr_hex(iv, c->iv, 8);
		if (c->ptk == 0)
			memcpy(msg, "Single block msg", 16);
		else
			for (i = 0; i < c->ml; i++)
				msg[i] = i;
		ctr_hex(want, c->ct, c->ml);
		if (crypto_skcipher_setkey(rfc, key, kb + 4))
			continue;
		rtotal++;
		m = ctr_run(rfc, iv, msg, want, c->ml, 8, 2);
		for (i = 0; i < 2; i++)
			rways[i] += !!(m & (1u << i));
	}
	check(rways[0] == rtotal, "rfc3686(ctr(aes)) out of place: RFC 3686 vectors #1-#3 (published) + 6 with 192/256-bit keys (OpenSSL)");
	check(rways[1] == rtotal, "rfc3686(ctr(aes)) in place");
	check(crypto_skcipher_setkey(rfc, key, 3) == -EINVAL, "rfc3686: a key shorter than the 4-byte nonce is -EINVAL");
	crypto_free_skcipher(rfc);
}
#else
static void __init test_ctr(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_AES) && (IS_BUILTIN(CONFIG_CRYPTO_ECB) || IS_BUILTIN(CONFIG_CRYPTO_CBC))
/*
 * crypto/ecb.c -> ecb_glue.c + ecb_rs.rs (the whole-block loop and the remainder / -EINVAL rule of crypto_ecb_crypt) and
 * crypto/cbc.c -> cbc_glue.c + cbc_rs.rs (the four chaining loops). Both are lskcipher templates with no library twin:
 * crypto_alloc_lskcipher("ecb(aes)") is crypto/ecb.c's cipher-based instance over aes-generic (CONFIG_CRYPTO_AES_NI_INTEL is
 * off in config-full), and "cbc(aes)" is cbc over "ecb(aes)" (lskcipher_alloc_instance_simple wraps a plain cipher name in
 * ecb), so cbc's chaining runs on top of ecb_rs as well. A check asserts the driver names start "ecb(" / "cbc(".
 * Vectors: NIST SP 800-38A F.1.1/F.1.3/F.1.5 (ECB) and F.2.1/F.2.3/F.2.5 (CBC), AES-128/192/256, the published 64-byte
 * ciphertexts and prefixes of them, plus pattern messages of 16..160 bytes and a second CBC IV (all 0xff); every
 * ciphertext computed by `openssl enc` (port/test/ecb/gen_vectors.py asserts the NIST published values).
 * Each vector runs eight ways: through the lskcipher API (what crypto_ecb_encrypt2 / crypto_cbc_encrypt are called by,
 * flags = FINAL) encrypt and decrypt, out of place and in place; and through the skcipher wrapper
 * (crypto_alloc_skcipher: skcipher_walk over scatterlists, so non-FINAL calls with the IV carried by the wrapper)
 * encrypt in place as one request, decrypt out of place as one request, encrypt as 16/32/48-byte pieces, decrypt as pieces.
 * Also: a length that is not a multiple of the block size is -EINVAL through the lskcipher API (the `rem && final` rule).
 * NOT reached: 8-byte-block ciphers (DES is off), async ciphers, an lskcipher (non-cipher) child of cbc.
 */
struct bm_vec { u8 kb, ivk, mk; u16 ml; const char *ct; };

static void __init bm_hex(u8 *dst, const char *s, unsigned int n)
{
	if (hex2bin(dst, s, n))
		check(false, "ecb/cbc test vector hex is valid");
}

static void __init bm_setup(const struct bm_vec *v, u8 *key, u8 *iv, u8 *msg, u8 *want)
{
	static const char *const keyhex[3] __initconst = {
		"2b7e151628aed2a6abf7158809cf4f3c",
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	};
	static const char nist_msg[] __initconst =
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	unsigned int i;

	bm_hex(key, keyhex[v->kb == 16 ? 0 : v->kb == 24 ? 1 : 2], v->kb);
	if (v->ivk == 0)
		for (i = 0; i < 16; i++)
			iv[i] = i;
	else
		memset(iv, 0xff, 16);
	if (v->mk == 0)
		bm_hex(msg, nist_msg, v->ml);
	else
		for (i = 0; i < v->ml; i++)
			msg[i] = (i * 29 + 5) & 0xff;
	bm_hex(want, v->ct, v->ml);
}

/* one lskcipher call over len bytes (iv may be NULL for ecb); in place copies `in` to `out` first */
static int __init bm_l(struct crypto_lskcipher *tfm, bool enc, bool inplace, const u8 *in, u8 *out, unsigned int len, u8 *iv)
{
	if (inplace) {
		memcpy(out, in, len);
		in = out;
	}
	return enc ? crypto_lskcipher_encrypt(tfm, in, out, len, iv) : crypto_lskcipher_decrypt(tfm, in, out, len, iv);
}

/* one skcipher request over [src, src + len) -> dst (dst NULL: in place) */
static int __init bm_req(struct crypto_skcipher *tfm, bool enc, u8 *iv, u8 *src, u8 *dst, unsigned int len)
{
	DECLARE_CRYPTO_WAIT(wait);
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct scatterlist s, d;
	int err;

	if (!req)
		return -ENOMEM;
	sg_init_one(&s, src, len);
	sg_init_one(&d, dst ? dst : src, len);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &s, &d, len, iv);
	err = crypto_wait_req(enc ? crypto_skcipher_encrypt(req) : crypto_skcipher_decrypt(req), &wait);
	skcipher_request_free(req);
	return err;
}

/* run one vector eight ways; returns a bitmask of the ways that gave the expected bytes */
static unsigned int __init bm_run(struct crypto_lskcipher *lt, struct crypto_skcipher *st, const u8 *iv0, const u8 *msg, const u8 *want, unsigned int len,
				  unsigned int ivs)
{
	u8 *iv = kmalloc(16, GFP_KERNEL), *buf = kmalloc(len + 1, GFP_KERNEL), *out = kmalloc(len + 1, GFP_KERNEL);
	unsigned int mask = 0, way, off, n, piece;

	if (!iv || !buf || !out)
		goto done;
	for (way = 0; way < 8; way++) {
		bool enc = way == 0 || way == 1 || way == 4 || way == 6;
		const u8 *in = enc ? msg : want, *exp = enc ? want : msg;
		bool inplace = way == 1 || way == 3 || way == 4;
		int err = 0;

		memcpy(iv, iv0, 16);
		memset(out, 0xA5, len);
		if (way < 4) {
			memcpy(buf, in, len);	/* kmalloc'd: the aligned (direct) lskcipher path */
			err = bm_l(lt, enc, inplace, buf, out, len, ivs ? iv : NULL);
		} else if (way < 6) {
			/* skcipher, one request */
			memcpy(buf, in, len);
			err = bm_req(st, enc, iv, buf, inplace ? NULL : out, len);
		} else {
			/* skcipher, 16/32/48-byte pieces then the rest; the IV is carried between requests (non-FINAL calls) */
			memcpy(buf, in, len);
			piece = 0;
			for (off = 0; off < len; off += n) {
				n = len - off > 16 ? 16 * (1 + piece++ % 3) : len - off;
				if (n > len - off)
					n = len - off;
				err = bm_req(st, enc, iv, buf + off, out + off, n);
				if (err)
					break;
			}
		}
		if (!err && !memcmp(way >= 4 && inplace ? buf : out, exp, len))
			mask |= 1u << way;
	}
done:
	kfree(iv); kfree(buf); kfree(out);
	return mask;
}

/* the whole battery for one mode ("ecb" or "cbc") */
static void __init bm_test(const char *alg, const struct bm_vec *vecs, unsigned int nvec, unsigned int ivs)
{
	struct crypto_lskcipher *lt;
	struct crypto_skcipher *st;
	u8 *work = kmalloc(32 + 16 + 160 + 160 + 48, GFP_KERNEL);		/* kmalloc'd, so every pointer is aligned */
	u8 *key = work, *iv = work + 32, *msg = work + 48, *want = work + 208, *tmp = work + 368;
	unsigned int v, w, ways[8] = { 0 }, total = 0, m;
	bool l_ok;
	char full[16];

	if (!work) {
		check(false, "ecb/cbc test buffer can be allocated");
		return;
	}
	snprintf(full, sizeof(full), "%s(aes)", alg);	/* the template needs an inner cipher: "ecb(aes)", "cbc(aes)" */
	lt = crypto_alloc_lskcipher(full, 0, 0);
	if (IS_ERR(lt)) {
		check(false, "lskcipher can be allocated");
		goto out_free;
	}
	st = crypto_alloc_skcipher(full, 0, 0);
	if (IS_ERR(st)) {
		check(false, "skcipher wrapper can be allocated");
		crypto_free_lskcipher(lt);
		goto out_free;
	}
	check(!strncmp(crypto_tfm_alg_driver_name(crypto_lskcipher_tfm(lt)), alg, 3) &&
	      crypto_tfm_alg_driver_name(crypto_lskcipher_tfm(lt))[3] == '(',
	      "the lskcipher is the crypto/ecb.c or cbc.c template instance (driver name ecb(...) / cbc(...))");
	check(crypto_lskcipher_blocksize(lt) == 16 && crypto_lskcipher_ivsize(lt) == ivs, "block size 16, iv size 16 (cbc) / 0 (ecb)");
	for (v = 0; v < nvec; v++) {
		bm_setup(&vecs[v], key, iv, msg, want);
		if (crypto_lskcipher_setkey(lt, key, vecs[v].kb) || crypto_skcipher_setkey(st, key, vecs[v].kb))
			continue;
		total++;
		m = bm_run(lt, st, iv, msg, want, vecs[v].ml, ivs);
		for (w = 0; w < 8; w++)
			ways[w] += !!(m & (1u << w));
	}
	check(total == nvec, "every ecb/cbc vector key is accepted");
	check(ways[0] == total, "lskcipher encrypt out of place: AES-128/192/256 NIST SP 800-38A + OpenSSL vectors");
	check(ways[1] == total, "lskcipher encrypt in place");
	check(ways[2] == total, "lskcipher decrypt out of place");
	check(ways[3] == total, "lskcipher decrypt in place");
	check(ways[4] == total, "skcipher wrapper encrypt in place, one request");
	check(ways[5] == total, "skcipher wrapper decrypt out of place, one request");
	check(ways[6] == total, "skcipher wrapper encrypt in 16/32/48-byte pieces, IV carried between requests");
	check(ways[7] == total, "skcipher wrapper decrypt in 16/32/48-byte pieces, IV carried between requests");
	/* a length that is not a multiple of the block size is -EINVAL (rem && FINAL), whatever the data */
	bm_setup(&vecs[0], key, iv, msg, want);
	l_ok = !crypto_lskcipher_setkey(lt, key, vecs[0].kb);
	memset(tmp, 0x5a, 48);
	check(l_ok && crypto_lskcipher_encrypt(lt, tmp, tmp, 17, ivs ? iv : NULL) == -EINVAL, "lskcipher encrypt of 17 bytes is -EINVAL");
	check(l_ok && crypto_lskcipher_decrypt(lt, tmp, tmp, 31, ivs ? iv : NULL) == -EINVAL, "lskcipher decrypt of 31 bytes is -EINVAL");
	check(l_ok && !crypto_lskcipher_encrypt(lt, tmp, tmp, 0, ivs ? iv : NULL), "lskcipher encrypt of 0 bytes is 0");
	crypto_free_skcipher(st);
	crypto_free_lskcipher(lt);
out_free:
	kfree(work);
}
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_ECB) && IS_BUILTIN(CONFIG_CRYPTO_AES)
/* ecb(aes) vectors: generated by port/test/ecb/gen_vectors.py ecb */
/* ecb(aes): { key bytes, iv kind (0 NIST 00..0f, 1 all 0xff; unused by ecb), message kind (0 NIST prefix, 1 pattern), length, ciphertext } */
static const struct bm_vec ecb_vecs[] __initconst = {
	{ 16, 0, 0, 64, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4" },
	{ 16, 0, 0, 32, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf" },
	{ 16, 0, 0, 16, "3ad77bb40d7a3660a89ecaf32466ef97" },
	{ 16, 0, 0, 48, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed030688" },
	{ 16, 0, 1, 16, "450d45fc59265121c457f3821147acef" },
	{ 16, 0, 1, 48, "450d45fc59265121c457f3821147acef4f91d39b52d82b0c856bd55d29a2d7742434d5df210c6437ace57fc4282f8f88" },
	{ 16, 0, 1, 80, "450d45fc59265121c457f3821147acef4f91d39b52d82b0c856bd55d29a2d7742434d5df210c6437ace57fc4282f8f88aab7d0fee0b30b70d31eaf13f20a49894da4f7d6649912cac0d1303a1a8960e3" },
	{ 16, 0, 1, 160, "450d45fc59265121c457f3821147acef4f91d39b52d82b0c856bd55d29a2d7742434d5df210c6437ace57fc4282f8f88aab7d0fee0b30b70d31eaf13f20a49894da4f7d6649912cac0d1303a1a8960e3bba0624c4d0c46ed0479578eabb44377729d5db9a5a5199edeb0c5f3b6bc250624eb161f9c7a3e8fc16ede9656fc69bc996368af7a1723e721fcf486e532fc31fd6169cbb1f43dd797696bfd3e2f0598" },
	{ 24, 0, 0, 64, "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e" },
	{ 24, 0, 0, 32, "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef" },
	{ 24, 0, 0, 16, "bd334f1d6e45f25ff712a214571fa5cc" },
	{ 24, 0, 0, 48, "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e" },
	{ 24, 0, 1, 16, "b439905afcd1e4d619eca4c7dbe60bd8" },
	{ 24, 0, 1, 48, "b439905afcd1e4d619eca4c7dbe60bd8aae5595cd620d4741a4f3f6b6fe4d583fa2bad665a7775b9adf736658ce9a327" },
	{ 24, 0, 1, 80, "b439905afcd1e4d619eca4c7dbe60bd8aae5595cd620d4741a4f3f6b6fe4d583fa2bad665a7775b9adf736658ce9a3276464c149bfa3fd3043cae359230ca183d78f935a7120e203431ffea16dfcd259" },
	{ 24, 0, 1, 160, "b439905afcd1e4d619eca4c7dbe60bd8aae5595cd620d4741a4f3f6b6fe4d583fa2bad665a7775b9adf736658ce9a3276464c149bfa3fd3043cae359230ca183d78f935a7120e203431ffea16dfcd2598fe4299742ed637b9ed21f3b747dc9c5c5b4dcdabda29e1ff57254b51d34d6cc7288ab2d783654bdceaa477d84778735142bf2be711147d9c14c22bca86d3468f77f0cb4e1249c4699be868953b60fbf" },
	{ 32, 0, 0, 64, "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7" },
	{ 32, 0, 0, 32, "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870" },
	{ 32, 0, 0, 16, "f3eed1bdb5d2a03c064b5a7e3db181f8" },
	{ 32, 0, 0, 48, "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d" },
	{ 32, 0, 1, 16, "b6ae3247b9c149989d5f0f7ab3676ab0" },
	{ 32, 0, 1, 48, "b6ae3247b9c149989d5f0f7ab3676ab0e711a259359df7ebe78e6d98c8d67cd28319e4cf7d396184f454da9c88391950" },
	{ 32, 0, 1, 80, "b6ae3247b9c149989d5f0f7ab3676ab0e711a259359df7ebe78e6d98c8d67cd28319e4cf7d396184f454da9c8839195086b271751fb36de470f0da013088c8e98027ae5f6089ba067bc947b16ed86b4e" },
	{ 32, 0, 1, 160, "b6ae3247b9c149989d5f0f7ab3676ab0e711a259359df7ebe78e6d98c8d67cd28319e4cf7d396184f454da9c8839195086b271751fb36de470f0da013088c8e98027ae5f6089ba067bc947b16ed86b4ebb73c426e594cdf55868cb6a4d8c53d06710c2bfac957a32fd70af8ef485584844afc95e06de5718a228ba2e6aa27088777bd6b8420f7c4599af1ca44bddd332e9088e51b6fc9f218250864d97d8a5c1" },
};

static void __init test_ecb(void)
{
	bm_test("ecb", ecb_vecs, ARRAY_SIZE(ecb_vecs), 0);
}
#else
static void __init test_ecb(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_CBC) && IS_BUILTIN(CONFIG_CRYPTO_ECB) && IS_BUILTIN(CONFIG_CRYPTO_AES)
/* cbc(aes) vectors: generated by port/test/ecb/gen_vectors.py cbc */
/* cbc(aes): { key bytes, iv kind (0 NIST 00..0f, 1 all 0xff; unused by ecb), message kind (0 NIST prefix, 1 pattern), length, ciphertext } */
static const struct bm_vec cbc_vecs[] __initconst = {
	{ 16, 0, 0, 64, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" },
	{ 16, 0, 0, 32, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2" },
	{ 16, 0, 0, 16, "7649abac8119b246cee98e9b12e9197d" },
	{ 16, 0, 0, 48, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516" },
	{ 16, 0, 1, 16, "ff0b5896c4f3a8ca967e9b6a9759116f" },
	{ 16, 0, 1, 48, "ff0b5896c4f3a8ca967e9b6a9759116f3285c5fdc6e09144fc16cdb1c7228591855c9be1dcf2f0cc0016bd02c327404b" },
	{ 16, 0, 1, 80, "ff0b5896c4f3a8ca967e9b6a9759116f3285c5fdc6e09144fc16cdb1c7228591855c9be1dcf2f0cc0016bd02c327404b726a9b9fee0be6865cef61c1e477dbceb8ab227c60ccf8997c7557aa7cad1bb9" },
	{ 16, 0, 1, 160, "ff0b5896c4f3a8ca967e9b6a9759116f3285c5fdc6e09144fc16cdb1c7228591855c9be1dcf2f0cc0016bd02c327404b726a9b9fee0be6865cef61c1e477dbceb8ab227c60ccf8997c7557aa7cad1bb9add3b44f984106759ec276a5d526ed58dcf0e6af06876750a68a016f4497b98df6da74d6d40380b4b0a694bac2e8fb56aae7589b420161cb5672afebef710565c44b972f19285aa32b320d27a7133048" },
	{ 16, 1, 1, 16, "cd9c2d5f10bf877bab73e73aeed51f99" },
	{ 16, 1, 1, 48, "cd9c2d5f10bf877bab73e73aeed51f9952c443110c91a931da380f72dfa5a2841df161be8c9c872b45a81e18d576b593" },
	{ 16, 1, 1, 80, "cd9c2d5f10bf877bab73e73aeed51f9952c443110c91a931da380f72dfa5a2841df161be8c9c872b45a81e18d576b593f0d80b18bd11e03d081b4e7e9f7e7f948216b75da24828e0e8b2678d0733fc57" },
	{ 16, 1, 1, 160, "cd9c2d5f10bf877bab73e73aeed51f9952c443110c91a931da380f72dfa5a2841df161be8c9c872b45a81e18d576b593f0d80b18bd11e03d081b4e7e9f7e7f948216b75da24828e0e8b2678d0733fc5732a839206ac9b89cec506eff3d9b5949dfff14bf21d0faa38fd1717f262e901d1b2f630dce2e5162808c1b233ff3bfe833c2d4e6980eedb55f473351777e464e43b617ece95cdb2117ce98d9ac46f015" },
	{ 24, 0, 0, 64, "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd" },
	{ 24, 0, 0, 32, "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a" },
	{ 24, 0, 0, 16, "4f021db243bc633d7178183a9fa071e8" },
	{ 24, 0, 0, 48, "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e0" },
	{ 24, 0, 1, 16, "baf62808e525cf5ac3a8e38fc7dea128" },
	{ 24, 0, 1, 48, "baf62808e525cf5ac3a8e38fc7dea1280de823701d11e925bc5d5ee90dd2da71d643affe73421cf2ef92a6001695af93" },
	{ 24, 0, 1, 80, "baf62808e525cf5ac3a8e38fc7dea1280de823701d11e925bc5d5ee90dd2da71d643affe73421cf2ef92a6001695af935d8ca3dc282f194b0ef92435cccf3da26797e75895ab9af88613e53eae01da6a" },
	{ 24, 0, 1, 160, "baf62808e525cf5ac3a8e38fc7dea1280de823701d11e925bc5d5ee90dd2da71d643affe73421cf2ef92a6001695af935d8ca3dc282f194b0ef92435cccf3da26797e75895ab9af88613e53eae01da6a2d8e1aec229bab64a5180f43f19c3d3d4d0ad303f4b3dde5e4f0c250d9a4ea380e2d6dd724a51d58350939c85a5dde6b414cbb6ebd60647b909b87f799a2d6ecb37b4736df69b7ae2b7931a56c6cbe63" },
	{ 24, 1, 1, 16, "ec5267adbb8a3cc6a45afcf6f2f9805a" },
	{ 24, 1, 1, 48, "ec5267adbb8a3cc6a45afcf6f2f9805a156ac9bbf2065cdb622f7dcd1b15a3a66244ca85a90b719bd304548a3890380a" },
	{ 24, 1, 1, 80, "ec5267adbb8a3cc6a45afcf6f2f9805a156ac9bbf2065cdb622f7dcd1b15a3a66244ca85a90b719bd304548a3890380a9ce5acacb21c6f085eda4a2f3cd39978804666000c242a860668e6861469d0a1" },
	{ 24, 1, 1, 160, "ec5267adbb8a3cc6a45afcf6f2f9805a156ac9bbf2065cdb622f7dcd1b15a3a66244ca85a90b719bd304548a3890380a9ce5acacb21c6f085eda4a2f3cd39978804666000c242a860668e6861469d0a15c665d765317319833045759b843e1958c198e35032f4605cbf07e80f037d615884ddf11e2794446c5e785a8353a03790f7c983959d965bd180f41c5fac268af13f181037f619b5cb0f959cfd2029033" },
	{ 32, 0, 0, 64, "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b" },
	{ 32, 0, 0, 32, "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d" },
	{ 32, 0, 0, 16, "f58c4c04d6e5f1ba779eabfb5f7bfbd6" },
	{ 32, 0, 0, 48, "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461" },
	{ 32, 0, 1, 16, "d40a78db75045dd4515981f3362a57e4" },
	{ 32, 0, 1, 48, "d40a78db75045dd4515981f3362a57e41bc1c40cbc76cd3fb5ef2ff6e8d1f050bd627cab377625354bef00eacc18f202" },
	{ 32, 0, 1, 80, "d40a78db75045dd4515981f3362a57e41bc1c40cbc76cd3fb5ef2ff6e8d1f050bd627cab377625354bef00eacc18f2029843fe482f63da47a1cbca2a9bcc7a335b1730d4867e4ae1362e416ba8be7348" },
	{ 32, 0, 1, 160, "d40a78db75045dd4515981f3362a57e41bc1c40cbc76cd3fb5ef2ff6e8d1f050bd627cab377625354bef00eacc18f2029843fe482f63da47a1cbca2a9bcc7a335b1730d4867e4ae1362e416ba8be73483b3c3ef28547a4cb02fcaa5450901811fd9fc37f8ab16867dddfe4b2f92ca6ae82e8c918a0f8482977d5526aad827abbea8ab8c6526467e3ca502fb9e92fba49069febbf819c9ae5d8b376787485436a" },
	{ 32, 1, 1, 16, "aa19e4248a7005450de621ab50baa299" },
	{ 32, 1, 1, 48, "aa19e4248a7005450de621ab50baa299b95296b46573ab9194a53e4c75dc06b648b61c9ad2c23a78e2c76e334b9a1a44" },
	{ 32, 1, 1, 80, "aa19e4248a7005450de621ab50baa299b95296b46573ab9194a53e4c75dc06b648b61c9ad2c23a78e2c76e334b9a1a444634b30d26d4e65bff088ba8f225ebe9af7a36ad51ad46653c5731956ca8e131" },
	{ 32, 1, 1, 160, "aa19e4248a7005450de621ab50baa299b95296b46573ab9194a53e4c75dc06b648b61c9ad2c23a78e2c76e334b9a1a444634b30d26d4e65bff088ba8f225ebe9af7a36ad51ad46653c5731956ca8e131e349e79cc58598400502b21a185cb3b1c03deeaff64720fb987cbb338b9bcd48493400cc7eededc0265e79edc0c3d311b0e5e62db1aaa7873c5dd5c59933bffd1e0b7e3c09692dd61fcb158ce152a631" },
};

static void __init test_cbc(void)
{
	bm_test("cbc", cbc_vecs, ARRAY_SIZE(cbc_vecs), 16);
}
#else
static void __init test_cbc(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_RSA)
/*
 * crypto/rsa_helper.c -> rsa_helper_glue.c + rsa_helper_rs.rs (the eight ASN.1 field callbacks rsa_get_n/e/d/p/q/dp/dq/qinv)
 * and crypto/rsa.c -> rsa_glue.c + rsa_rs.rs (test_rsa() below: RSAEP / RSADP-CRT, payload range, sizes). Driven through the crypto API: crypto_alloc_akcipher("rsa") is
 * crypto/rsa.c's "rsa-generic"; crypto_akcipher_set_pub_key / set_priv_key hand the BER key to rsa_parse_pub_key /
 * rsa_parse_priv_key, whose generated decoder tables call rsa_get_n/e (public key) and rsa_get_n/e/d/p/q/dp/dq/qinv (private
 * key) for each INTEGER. Keys: 2048- and 1024-bit PKCS#1 RSAPublicKey / RSAPrivateKey DER made with `openssl genrsa`, and the
 * textbook-RSA vectors computed with python integers and cross-checked with `openssl pkeyutl` raw RSA
 * (port/test/rsa/gen_vectors.py; the table is that script's output). A parsed key is observed through
 * crypto_akcipher_maxsize() (the modulus size read back from the stored n), and through the encrypt/decrypt vectors, which
 * only come out right if every field was stored with the right pointer and length.
 * Crafted keys reach the error returns: a truncated key (the decoder fails), an exponent longer than the modulus
 * (rsa_get_e -EINVAL), a prime longer than the modulus (rsa_get_p -EINVAL), an empty modulus (rsa_get_n), and a 1100-bit
 * modulus (parses; rsa_set_pub_key rejects the size, 18 limbs = 1152 bits).
 * NOT reached: the FIPS arm of rsa_get_n (CONFIG_CRYPTO_FIPS is unset in both configs).
 */
struct rsa_vec { const char *m, *c; };
/* rsa test data: generated by port/test/rsa/gen_vectors.py (openssl genrsa; python big integers; openssl raw RSA cross-check) */
static const char rsa_k2048_pub[] __initconst = "3082010a0282010100bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ef0203010001";
static const char rsa_k2048_priv[] __initconst = "308204a30201000282010100bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ef020301000102820100196214fadd813f91a00e06a49b1a2b65aef739f4a941b06a4ee8c322003b265929c75208f49d31f41905bb6d086b0bcc20749f989208dd3265706d72b5dd928b9587ce51d95eaf59ec4477d943cec756c7ad8d6aa9706f1a02300fb36fd8a6e08c5245cf62268081200798fabd67d22fd6f0c3ef9c52bb52689b2bd1362d02fec09a4cfd0bfcd490b4a016dadaa2476bbaee94b1ea3be860ac29c6e1247d228d5f33404670d3150c6f07c7c8a41eeb4c6b1691635db4bb2d2d3290a0560b4b149f29fcb35ff8bcced52c07c7eaf6950e67512bcee99484b36b6f9e12d6afa339e60f142d9898b0ec06e0f13d2a781d3dbbbe8d0d12c9184e5872a023f520f15502818100e2ce58da56f641f3800d7af85a0035fd7e5c900b932a4758ec56e4a0bcf669fa021a941d78a31cb83486dbe9a1ec9de57916fdb965bafa87e1894d6e00e08c7449d90e10182b07292a0016db1ad1ee99b7999b449b8a50ae1b811cdbf91f6fde3f9afe3a6a0390227be5732a0a188ff8f798817545670bcb2998f7666d7310bb02818100d3a69f8ff9468a6bc79dd613c688581c1031e88195910e14a1a8ab7504196856a5ae46c48d2ba29ad1e6ed34cb33b39518bdeeea1fa9d20837f0e2f01e617ef42edc50b87789793357854a3f47e4d062a258825cc6c4c2ea9c009372fadfe99d8b52f7b32af83179ed2f6b91b55bc4f66676c018a69e5945a04c53074f75875d02818100af55a60ae4bf6b2cbb09b0cedd84dc3823bf9afbd7c10f7706fe05b0dd6401796cb6ef59f930dfbae7a079d19b84386c75b7f85da2ef714e2a64e29eefbea7d61e60d6264b08b8787227af83a2b0382c4d6b4a4537992dd5eb1d5d1a10f4e49e83bd665bf228defc499b8ff427e9e5232b0592cefde03395d38a957771954a91028180113e02c3bce00548d083483c6631175479f146eabf9f88911fb658f97873057001a157fc8d2f9fd892ff081603f3db4e6b2c95f916c943e60d809f4c467d54d559b7f30f84157bfd35c5130e62b1fe53fabbd12af3ba75d29d10e2f23c03dfc948df6274832ca30336d2652602ab4e3970917e06c414245baaba6d0d2c68fbb502818010515885130f907a8a47b9ef884e318c5ae99472bc9407ff2e560107280f249a24d942f3a6b1df80ac3b750c91fc58e5e9a9bb2a3f0099e416c4a396fec8f022e68601eee4deefba8c9f335e9db12c5c236158ca803abf24f24a83ba11c32fb2ffd152b05f8d400b2ba16c3b0ac0b8c25be7fa3aa3aa27acb5f19db83a96a51b";
static const char rsa_k2048_n[] __initconst = "bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ef";
static const struct rsa_vec rsa_k2048_vecs[] __initconst = {
	{ "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
	  "a79b2f5b2ac62a29c9cc551dae7b242389ec0f32846f57a390afc1cabc84f66b1fd247a1381b504588afc7c8e1bb0a6aaaae58583c89b8c691b5e7ef421234304c19a35f3754733d255de807ecbd02f5f255e32bd7ad9debc84f934ca91702d3b4be9c2d9656624158fc3a752a0e7724be13b6bb82180d6054a2453c2966e258b676eff2f687c1a7af602fc56fbd4f9d7bf1002b1091d8cb301ae4fd8a93f83015aa920444a95c50d92392cb0d336a653a7f35a5a2ca3760de62631bc4fdfe2b9f027c52a8e9e3748686ccca3780b0a255881fc47a78ae083ee93ad95a1eac922089195c7be077f40965f46974f9a3543c6a18b3ad70b6381790ede238f1c90f" },
	{ "bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ed",
	  "13e8830c1fc7a3559671446edb3e8cd1b19ede24cb4323c7b06e18a150099ae1ff8b8aa406b426dee58a434a163c3173768dec4f777014ace3afd2fcae698b61208329d85deaaa5032445f08e72f48a1643aa0e1cd6d3fe94998baf1dbbd2996c04ac1f4c79645bc79876a4010b9d0c1c7ebc3626c666a53064b8c3b07969fed00c5e18c8414501e3312d49a585a4d2ff1f566469033247e99b25f6e3e99b83c4b701eedcd31bbd08f7e9c337c4eb5934f8b0e269704655ddfa762eb99c0f5e03e1f52c05eddcbccc85ca2b6065174b0cca2fc9c2d688c5fddc82144f8957564dcacfb0f0567eaa3c3f1b14a3032fa258e2eb65e3e5ad415812493e89224e7e0" },
	{ "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2cfec092643607d9ab7d4f10e2b4865829fbcd9f613304d6a87a4c1defb1835526f8ca9c6e3001d3a577491aecbe8",
	  "8ce7ae7f92c217347cb194bdf554334a5ffa444c012387cc2b62a0baefc963e52f8ad18a79d6735f76ccc55408a103e63b9fa4a7646bae3ff45382bbd3887858cefc1ef3fac9f9415cff105b01b2fd1d5e802a0eea31cc63e5047fa80ba83a501b538ace107be765fd99fcf3bc4698a985791ad025728d3b7b6fdf220a641074065cbe11b43c9483c288b293a9a0f2011045edb13e5564f2bd4c5ccbd297acf0e814eedd4b41ce93c8293bc767f9870928d12208d813afd212eba9213db8f3b2348bb2474013ccfa4f19334394db9ecd7e8fff264dedbd643c781d029123f0087a968f478e1468ef0e8a3c119229bf867e4714f875a675f06cf45250ee6ea51a" },
	{ "0d549be22970b7fe458cd31a61a8ef367dc40b5299e0276eb5fc438ad1185fa6ed347bc2095097de256cb3fa4188cf165da4eb3279c0074e95dc236ab1f83f86cd145ba2e93077be054c93da2168aff63d84cb1259a0e72e75bc034a91d81f66adf43b82c910579ee52c73ba01488fd61d64abf23980c70e559ce32a71b8ff468dd41b62a9f0377ec50c539ae1286fb6fd448bd21960a7ee357cc30a5198df266db4fb4289d0175ea5ec337ac1084f96dd246bb2f94087ce155ca3ea3178bf064d94db2269b0f73e85cc135aa1e82f76bd044b92d92067aef53c83ca11589fe62d74bb024990d71e65acf33a81c80f569de42b72b900478ed51c63aaf1387fc6",
	  "4217af79f31f96be3fff8d2f42a392ff58fe1848457ec1c1a1029567e3a5cd2079cd5709104f00df668eec1c40a48f4b567dfa2fc64d6b2b4764aad728cf599e14cf3e57b4062bf4c889da041a7a6165168f9922f3abd7602fcc326010b86399cd71080c9be70eb781ae7806c926af3dcfae3ce31ec6e4d5821113a36bc81dd4dfc37bb4666520523690e5c02d1ab3209fc727f857561b7cbb7a98806bdf1c8c2424308fc9db2118f7194a0c4a4c8abfca03e26adaf102a0f0f7ad9b6134aa8bb994c778558b787e47fbaea25bfa5e2095fe8b3567433550752f99d3a43dbe684f084f96385e54ea79174f123de207f8b41245edeb644ae201ac1d5009fb750d" },
};
static const char rsa_k1024_pub[] __initconst = "30818902818100bde44bbe6aecb42dfc440b0bc504162a45620bbab94f40860909442e186b2eb8f6cbf9479083786323a7fa787034221d3dd4cd7a40e93e97382012ec270c5ce2e012a26e18255d25bbce7ebab81fd8543b66c62b479522dc2c717e159f0503388bc7e9307637caa6cc750ba0bc2f71bc8ad3cdda97f1ddc30f771ffa782744470203010001";
static const char rsa_k1024_priv[] __initconst = "3082025d02010002818100bde44bbe6aecb42dfc440b0bc504162a45620bbab94f40860909442e186b2eb8f6cbf9479083786323a7fa787034221d3dd4cd7a40e93e97382012ec270c5ce2e012a26e18255d25bbce7ebab81fd8543b66c62b479522dc2c717e159f0503388bc7e9307637caa6cc750ba0bc2f71bc8ad3cdda97f1ddc30f771ffa78274447020301000102818100a30cb1210accbe95b1c3773c9ee9b862897afb99545ec18795a0b843604240371feadadbe1319220865049183b37f886e53da145b510d1e6a4919dcdda659a26d5c09f44f5617923e22f16cbc0f1a61f5fbb23c672c87521e03f57d751d9a6aa15468ad317c5a8fb8c737b2ecfbfe892426b6ee0806dc3e7ad460ff1a6e0cba1024100e66ccfa3774d5224c66cac54b56caeab63a6569c4c2f4501ab7d8790500e5323a6ae956583e9ff4df867e407b1b777b50d10ca21f59db3666a8f1ad157876f37024100d2f7caad749e6226f17bc8d75a0d805f69fb014cda009647556f10b783f095be1f6e5edcdd0038bb9730fda4aec79f9ddf100388f60af9c1746ac3bf8eeebb71024037aa219f03bb1215003a5087462cb325843532c71f406c13333268055cd199140bb8312f0ce7025dfb9c5d61de74cbde5901ad52f6dad9f3ebda16486c34b391024100af93d893599e4353e3e0407bb20fd08a183af58f0f5433bdf48575e535a2b20d443d6827eaaa378d303c6eac7365e21ad2bd92239799f4d8a35a03c5d6602b9102405b7cdcd4882d2c254818e471641cabd0f7d07ce1dd092c4c023361f66dc94d67e16e76c9c8db419ab13701ad9893ef52585d85f38294ed815ee937bb9af52bda";
static const char rsa_k1024_n[] __initconst = "bde44bbe6aecb42dfc440b0bc504162a45620bbab94f40860909442e186b2eb8f6cbf9479083786323a7fa787034221d3dd4cd7a40e93e97382012ec270c5ce2e012a26e18255d25bbce7ebab81fd8543b66c62b479522dc2c717e159f0503388bc7e9307637caa6cc750ba0bc2f71bc8ad3cdda97f1ddc30f771ffa78274447";
static const struct rsa_vec rsa_k1024_vecs[] __initconst = {
	{ "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
	  "9933f8f377ce82a8697dac5ffadcb0a41eac9d2d1de148df44845e5bdc42712f7866ab2d564f6f9bee11d3ca54ce2d5dfbe235151e9440e29f5efefa89004aeef56ab839be219bed7159aafccfcf7cf9705e882b0cb9181474081d4035b7ebce25f2adf07570fd63f3a578c3dedfbb157c9e51c39b53ac75b2ecc2e26f628533" },
	{ "bde44bbe6aecb42dfc440b0bc504162a45620bbab94f40860909442e186b2eb8f6cbf9479083786323a7fa787034221d3dd4cd7a40e93e97382012ec270c5ce2e012a26e18255d25bbce7ebab81fd8543b66c62b479522dc2c717e159f0503388bc7e9307637caa6cc750ba0bc2f71bc8ad3cdda97f1ddc30f771ffa78274445",
	  "24b052caf31e318592c65eabca27658626b56e8d9b6df7a6c484e5d23c28bd897e654e1a3a3408c7359626ae1b65f4bf41f298652254fdb498c113f19e0c11f3eaa7ea345a03c1384a74d3bde8505b5acb083e003adc0ac7b86960d5694d176a65d53b4000c6cd42d8cf92dcdd4fb6a70e357c16fc9e314d5c8a5d1808c4bf14" },
	{ "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b68",
	  "b526151ce16f32aef3ca50654dfeb280785fff5b38cfafaf61c8d265008a2aae3e6dc8cdd0a7fb657f871603e9a2a3e0b4d0f52e7e17cb7bb7103c995d3c3c24d3bec77bb6a6d53c5d49de8c5789157938d2d539b17999dab3b3bc3970eb693b89427eacd029f3f25ba69c49cbc50a88fb60c2ade46358463b78651ed2327705" },
	{ "0d549be22970b7fe458cd31a61a8ef367dc40b5299e0276eb5fc438ad1185fa6ed347bc2095097de256cb3fa4188cf165da4eb3279c0074e95dc236ab1f83f86cd145ba2e93077be054c93da2168aff63d84cb1259a0e72e75bc034a91d81f66adf43b82c910579ee52c73ba01488fd61d64abf23980c70e559ce32a71b8ff46",
	  "244fdfaac2e7bf57f051659c8595e16052d294eb1fc0e415a638acfd9ead9677ca3f8006983a3e659179808f289bb670fa1da25da28544b1621011ef7d0c60dbf4fab6439fb2931bc32943a5f3bbb2707fef52cbe73df7c27be12ecb52d181bf1e0570d464cb355e38ceab676f5b898e5e859a6c40d605eb10edd4d3566af102" },
};
static const char rsa_pub_truncated[] __initconst = "3082010a0282010100bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ef";
static const char rsa_pub_e_longer_than_n[] __initconst = "3082020b0282010100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02820102010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char rsa_priv_p_longer_than_n[] __initconst = "308205250201000282010100bb83b2674a8dcd7f603d998c89b9b0f53b8aed574fb27b6b411dda6c0c8e914d1f5dd2453ecf77246e3a0b12f7f73bde213c44a7b3f9cd737565baebf07bbf916c9ccd37953f1d8d57a24710d3ec4b975690840da51addd511e84e3e84d42c6a75095e225deca7fdd283a4b53ac847e685ff7a1dee7e77b35aedd17730fd8245b73cd17f7a9c11c5e273045fc8179ccd6de66671a0c4fd49c9cd446bc92db06c611ab0f211db182168a22efe89821ff88a0a43cc39ce9cbebe09c6075ebef40bdd21cf1307c7af414ee36f803dd22553222b1c60a7e13a681cb15c1e52b421f6fd36146b81486297cd57a5b3a52c9d79ca98cf11ebcb8a4d98b581cacb16b0ef020301000102820100196214fadd813f91a00e06a49b1a2b65aef739f4a941b06a4ee8c322003b265929c75208f49d31f41905bb6d086b0bcc20749f989208dd3265706d72b5dd928b9587ce51d95eaf59ec4477d943cec756c7ad8d6aa9706f1a02300fb36fd8a6e08c5245cf62268081200798fabd67d22fd6f0c3ef9c52bb52689b2bd1362d02fec09a4cfd0bfcd490b4a016dadaa2476bbaee94b1ea3be860ac29c6e1247d228d5f33404670d3150c6f07c7c8a41eeb4c6b1691635db4bb2d2d3290a0560b4b149f29fcb35ff8bcced52c07c7eaf6950e67512bcee99484b36b6f9e12d6afa339e60f142d9898b0ec06e0f13d2a781d3dbbbe8d0d12c9184e5872a023f520f1550282010201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002818100d3a69f8ff9468a6bc79dd613c688581c1031e88195910e14a1a8ab7504196856a5ae46c48d2ba29ad1e6ed34cb33b39518bdeeea1fa9d20837f0e2f01e617ef42edc50b87789793357854a3f47e4d062a258825cc6c4c2ea9c009372fadfe99d8b52f7b32af83179ed2f6b91b55bc4f66676c018a69e5945a04c53074f75875d02818100af55a60ae4bf6b2cbb09b0cedd84dc3823bf9afbd7c10f7706fe05b0dd6401796cb6ef59f930dfbae7a079d19b84386c75b7f85da2ef714e2a64e29eefbea7d61e60d6264b08b8787227af83a2b0382c4d6b4a4537992dd5eb1d5d1a10f4e49e83bd665bf228defc499b8ff427e9e5232b0592cefde03395d38a957771954a91028180113e02c3bce00548d083483c6631175479f146eabf9f88911fb658f97873057001a157fc8d2f9fd892ff081603f3db4e6b2c95f916c943e60d809f4c467d54d559b7f30f84157bfd35c5130e62b1fe53fabbd12af3ba75d29d10e2f23c03dfc948df6274832ca30336d2652602ab4e3970917e06c414245baaba6d0d2c68fbb502818010515885130f907a8a47b9ef884e318c5ae99472bc9407ff2e560107280f249a24d942f3a6b1df80ac3b750c91fc58e5e9a9bb2a3f0099e416c4a396fec8f022e68601eee4deefba8c9f335e9db12c5c236158ca803abf24f24a83ba11c32fb2ffd152b05f8d400b2ba16c3b0ac0b8c25be7fa3aa3aa27acb5f19db83a96a51b";
static const char rsa_pub_n_empty[] __initconst = "300702000203010001";
static const char rsa_pub_1100_bit[] __initconst = "30819202818a0cea8f3cde783b5c92a601313ba718f8410c7bbf9e1f936b45133d418fefab46744209a6530a85e889c37976d6f1460fa80720bf223eaad9cfdef45f194ef0e3a32c739d5643202f06b92349332d28cc5e3a51c8e3a0249327d2938bdff9d5401f6518f9d429fb9ca173bcecc6b3bcd9c3b7390afa7c6560b986c6f2cdfbf9193b6f4e6c338e88338bbd0203010001";

static u8 *__init rsa_unhex(const char *s, unsigned int *len)
{
	unsigned int n = strlen(s) / 2;
	u8 *b = kmalloc(n ? n : 1, GFP_KERNEL);

	if (!b || hex2bin(b, s, n)) {
		kfree(b);
		return NULL;
	}
	*len = n;
	return b;
}

/* set one key (pub or priv) from a hex DER string; returns the key function's result, or -ENOMEM */
static int __init rsa_setkey(struct crypto_akcipher *tfm, bool pub, const char *hex)
{
	unsigned int len;
	u8 *b = rsa_unhex(hex, &len);
	int ret;

	if (!b)
		return -ENOMEM;
	ret = pub ? crypto_akcipher_set_pub_key(tfm, b, len) : crypto_akcipher_set_priv_key(tfm, b, len);
	kfree(b);
	return ret;
}

static void __init test_rsa_helper(void)
{
	struct crypto_akcipher *tfm = crypto_alloc_akcipher("rsa", 0, 0);

	if (IS_ERR(tfm)) {
		check(false, "rsa can be allocated");
		return;
	}
	check(rsa_setkey(tfm, true, rsa_k2048_pub) == 0, "rsa_parse_pub_key: a 2048-bit RSAPublicKey is accepted (rsa_get_n, rsa_get_e)");
	check(crypto_akcipher_maxsize(tfm) == 256, "the parsed 2048-bit public key has a 256-byte modulus (rsa_get_n stored n and its length)");
	check(rsa_setkey(tfm, false, rsa_k2048_priv) == 0, "rsa_parse_priv_key: a 2048-bit RSAPrivateKey is accepted (rsa_get_n/e/d/p/q/dp/dq/qinv)");
	check(crypto_akcipher_maxsize(tfm) == 256, "the parsed 2048-bit private key has a 256-byte modulus");
	check(rsa_setkey(tfm, true, rsa_k1024_pub) == 0 && crypto_akcipher_maxsize(tfm) == 128, "a 1024-bit public key replaces the old key: 128-byte modulus");
	check(rsa_setkey(tfm, false, rsa_k1024_priv) == 0 && crypto_akcipher_maxsize(tfm) == 128, "a 1024-bit private key: 128-byte modulus");
	check(rsa_setkey(tfm, true, rsa_pub_truncated) != 0, "a truncated public key is rejected");
	check(rsa_setkey(tfm, true, rsa_pub_e_longer_than_n) == -EINVAL, "rsa_get_e: an exponent longer than the modulus is -EINVAL");
	check(rsa_setkey(tfm, false, rsa_priv_p_longer_than_n) == -EINVAL, "rsa_get_p: a prime longer than the modulus is -EINVAL");
	check(rsa_setkey(tfm, true, rsa_pub_n_empty) != 0, "rsa_get_n: an empty modulus is rejected");
	check(rsa_setkey(tfm, true, rsa_pub_1100_bit) == -EINVAL, "a 1100-bit modulus parses but its size (1152 bits) is -EINVAL");
	/* after the failures above the tfm still takes a good key */
	check(rsa_setkey(tfm, true, rsa_k2048_pub) == 0 && crypto_akcipher_maxsize(tfm) == 256, "a good key is accepted again after rejected ones");
	crypto_free_akcipher(tfm);
}

/* big-endian add of a small delta to a len-byte number (carry propagates; wraps silently: only used on values far from 2^len) */
static void __init rsa_be_add(u8 *b, unsigned int len, int delta)
{
	int i;

	if (delta >= 0) {
		unsigned int c = delta;

		for (i = len - 1; i >= 0 && c; i--) {
			c += b[i];
			b[i] = c & 0xff;
			c >>= 8;
		}
	} else {
		unsigned int c = -delta;

		for (i = len - 1; i >= 0 && c; i--) {
			unsigned int v = b[i];

			b[i] = (v - c) & 0xff;
			c = v < c ? 1 : 0;
		}
	}
}

/* encrypt (pub tfm) or decrypt (priv tfm) len bytes of hex `in` into a dlen-byte buffer; returns the sync call's result, the output in `out` */
static int __init rsa_op(struct crypto_akcipher *tfm, bool enc, const u8 *in, unsigned int slen, u8 *out, unsigned int dlen)
{
	return enc ? crypto_akcipher_sync_encrypt(tfm, in, slen, out, dlen) : crypto_akcipher_sync_decrypt(tfm, in, slen, out, dlen);
}

/* the vectors of one key: encrypt with the public key, decrypt with the private key, and the range / size rules */
static void __init rsa_one_key(const char *pubhex, const char *privhex, const char *nhex, const struct rsa_vec *vecs, unsigned int nvec, unsigned int bits)
{
	struct crypto_akcipher *pub = crypto_alloc_akcipher("rsa", 0, 0), *priv = crypto_alloc_akcipher("rsa", 0, 0);
	unsigned int k = bits / 8, i, enc_ok = 0, dec_ok = 0, encpriv_ok = 0, nlen;
	u8 *n = NULL, *m = NULL, *c = NULL, *out = NULL, *tmp = NULL;

	if (IS_ERR(pub) || IS_ERR(priv)) {
		check(false, "rsa can be allocated");
		goto out;
	}
	n = rsa_unhex(nhex, &nlen);
	m = kmalloc(k + 8, GFP_KERNEL);
	c = kmalloc(k + 8, GFP_KERNEL);
	out = kmalloc(k + 8, GFP_KERNEL);
	tmp = kmalloc(k + 8, GFP_KERNEL);
	if (!n || !m || !c || !out || !tmp || nlen != k) {
		check(false, "rsa test buffers");
		goto out;
	}
	check(rsa_setkey(pub, true, pubhex) == 0 && rsa_setkey(priv, false, privhex) == 0, "rsa: public and private key load");
	check(crypto_akcipher_maxsize(pub) == k && crypto_akcipher_maxsize(priv) == k, "rsa: max size is the modulus size (rsa_max_size)");
	for (i = 0; i < nvec; i++) {
		if (hex2bin(m, vecs[i].m, k) || hex2bin(c, vecs[i].c, k))
			continue;
		memset(out, 0xA5, k + 8);
		enc_ok += !rsa_op(pub, true, m, k, out, k) && !memcmp(out, c, k);
		memset(out, 0xA5, k + 8);
		dec_ok += rsa_op(priv, false, c, k, out, k) >= 0 && !memcmp(out, m, k);
		memset(out, 0xA5, k + 8);
		encpriv_ok += !rsa_op(priv, true, m, k, out, k) && !memcmp(out, c, k);
	}
	check(enc_ok == nvec, "rsa encrypt (RSAEP, c = m^e mod n) with the public key: 4 textbook vectors (python ints + openssl)");
	check(dec_ok == nvec, "rsa decrypt (RSADP with the CRT) with the private key: 4 textbook vectors");
	check(encpriv_ok == nvec, "rsa encrypt with the private key (it carries n and e) gives the same ciphertext");
	if (!hex2bin(m, vecs[0].m, k) && !hex2bin(c, vecs[0].c, k)) {
		/* a longer destination is left-padded with zeros; a shorter source (leading zeros dropped) gives the same number */
		memset(out, 0xA5, k + 3);
		check(rsa_op(pub, true, m, k, out, k + 3) == 0 && !memcmp(out, "\0\0\0", 3) && !memcmp(out + 3, c, k), "rsa encrypt into a larger buffer: zero-padded on the left");
		tmp[0] = 2;		/* vecs[0] is m = 2: the one-byte source {2} is the same number as the k-byte one */
		check(rsa_op(pub, true, tmp, 1, out, k) == 0 && !memcmp(out, c, k), "rsa encrypt of a one-byte source reads it as the number it holds (2)");
		/* a destination one byte short for a full-size result is -EOVERFLOW (mpi_write_to_sgl) */
		check(c[0] == 0 || rsa_op(pub, true, m, k, out, k - 1) == -EOVERFLOW, "rsa encrypt into a buffer one byte too small is -EOVERFLOW");
	}
	/* payload range: 1 < x < n - 1; 0, 1, n - 1, n, n + 1 are -EINVAL for both directions */
	{
		static const int deltas[] = { -2, -1, 0, 1 };
		unsigned int d, bad_enc = 0, bad_dec = 0, ok_enc = 0;

		memset(tmp, 0, k);
		bad_enc += rsa_op(pub, true, tmp, k, out, k) == -EINVAL;			/* 0 */
		bad_dec += rsa_op(priv, false, tmp, k, out, k) == -EINVAL;
		tmp[k - 1] = 1;
		bad_enc += rsa_op(pub, true, tmp, k, out, k) == -EINVAL;			/* 1 */
		bad_dec += rsa_op(priv, false, tmp, k, out, k) == -EINVAL;
		tmp[k - 1] = 2;
		ok_enc += rsa_op(pub, true, tmp, k, out, k) == 0;				/* 2 is the smallest accepted */
		for (d = 0; d < ARRAY_SIZE(deltas); d++) {
			memcpy(tmp, n, k);
			rsa_be_add(tmp, k, deltas[d]);							/* n - 2, n - 1, n, n + 1 */
			if (d == 0) {
				ok_enc += rsa_op(pub, true, tmp, k, out, k) == 0;			/* n - 2 is the largest accepted */
			} else {
				bad_enc += rsa_op(pub, true, tmp, k, out, k) == -EINVAL;
				bad_dec += rsa_op(priv, false, tmp, k, out, k) == -EINVAL;
			}
		}
		check(bad_enc == 5, "rsa encrypt: 0, 1, n - 1, n, n + 1 are -EINVAL (rsa_check_payload)");
		check(bad_dec == 5, "rsa decrypt: 0, 1, n - 1, n, n + 1 are -EINVAL");
		check(ok_enc == 2, "rsa encrypt: 2 and n - 2 are accepted (1 < x < n - 1)");
	}
	/* decrypt with only the public key (no d) and with no key at all */
	{
		struct crypto_akcipher *none = crypto_alloc_akcipher("rsa", 0, 0);

		memset(tmp, 0, k);
		tmp[k - 1] = 5;
		check(rsa_op(pub, false, tmp, k, out, k) == -EINVAL, "rsa decrypt with a public-only key is -EINVAL (no d)");
		if (!IS_ERR(none)) {
			check(rsa_op(none, true, tmp, k, out, k) == -EINVAL && rsa_op(none, false, tmp, k, out, k) == -EINVAL, "rsa encrypt / decrypt with no key set is -EINVAL");
			crypto_free_akcipher(none);
		}
	}
out:
	kfree(n); kfree(m); kfree(c); kfree(out); kfree(tmp);
	if (!IS_ERR_OR_NULL(pub))
		crypto_free_akcipher(pub);
	if (!IS_ERR_OR_NULL(priv))
		crypto_free_akcipher(priv);
}

static void __init test_rsa(void)
{
	rsa_one_key(rsa_k2048_pub, rsa_k2048_priv, rsa_k2048_n, rsa_k2048_vecs, ARRAY_SIZE(rsa_k2048_vecs), 2048);
	rsa_one_key(rsa_k1024_pub, rsa_k1024_priv, rsa_k1024_n, rsa_k1024_vecs, ARRAY_SIZE(rsa_k1024_vecs), 1024);
}
#else
static void __init test_rsa_helper(void) { }
static void __init test_rsa(void) { }
#endif

#ifdef CONFIG_X86_64
static u32 __init __maybe_unused fold16(u32 x)
{
	x = (x & 0xffff) + (x >> 16);
	return (x & 0xffff) + (x >> 16);
}

static bool __init __maybe_unused same_ones16(u32 a, u32 b)
{
	return a % 65535 == b % 65535;	/* 0 and 0xffff are the same ones' complement number */
}
#endif

/* CONFIG_GENERIC_CSUM (selected by x86 under KASAN/KMSAN): lib/checksum.c is built instead of csum_partial_rs.rs,
 * and its raw 32-bit values differ from the arch version's, which this test asserts. */
#if defined(CONFIG_X86_64) && !defined(CONFIG_GENERIC_CSUM)
/*
 * arch/x86/lib/csum-partial_64.c -> csum_partial_rs.rs (csum_partial,
 * ip_compute_csum, exported by the Rust object). The network stack reaches
 * these constantly, but the rig has no network, so this is the proof caller.
 * Oracles that are not the C: the RFC 1071 section 3 worked example, the
 * widely published IPv4 header 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8
 * 00c7, and a byte-at-a-time RFC 1071 sum written here (16-bit little-endian
 * words, wide accumulator, fold) compared as ones' complement numbers (0 and
 * 0xffff are the same number), over lengths 0..300 at 16 alignments, on
 * pseudo-random and all-0xff data, with and without an initial sum.
 */
static u32 __init csum_ref(const u8 *p, int len, u32 init)
{
	u64 acc = (u64)(init & 0xffff) + (init >> 16);
	int i;

	for (i = 0; i + 1 < len; i += 2)
		acc += p[i] | ((u64)p[i + 1] << 8);
	if (len & 1)
		acc += p[len - 1];
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return acc;
}

static void __init test_x86_csum(void)
{
	static u8 buf[320 + 16] __initdata;
	static const u8 rfc[8] __initconst = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
	static const u8 hdr[20] __initconst = {
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
	static u8 h2[20] __initdata;
	bool ip_ok = true, part_ok = true, ones_ok = true, init_ok = true;
	u32 x = 0x12345678;
	int len, al, i;

	/* RFC 1071: the ones' complement sum of the 8 bytes is 0xddf2, so the checksum field is 0x220d (network order) */
	check(ip_compute_csum(rfc, 8) == (__force __sum16)htons(0x220d), "RFC 1071 example: checksum of 00 01 f2 03 f4 f5 f6 f7 is 220d");
	check(ip_compute_csum(hdr, 20) == 0, "IPv4 header with its checksum in place folds to 0");
	memcpy(h2, hdr, 20);
	h2[10] = h2[11] = 0;
	check(ip_compute_csum(h2, 20) == (__force __sum16)htons(0xb861), "IPv4 header with a zeroed checksum field yields b861");

	for (i = 0; i < (int)sizeof(buf); i++) {
		x = x * 1664525 + 1013904223;
		buf[i] = x >> 24;
	}
	for (al = 0; al < 16; al++) {
		for (len = 0; len <= 300; len++) {
			u32 init = (len * 0x01010101u) ^ (al * 0x00ff00ffu);

			ip_ok &= same_ones16((u16)~ip_compute_csum(buf + al, len), csum_ref(buf + al, len, 0));
			part_ok &= same_ones16(fold16(csum_partial(buf + al, len, 0)), csum_ref(buf + al, len, 0));
			init_ok &= same_ones16(fold16(csum_partial(buf + al, len, init)), csum_ref(buf + al, len, init));
		}
	}
	memset(buf, 0xff, sizeof(buf));
	for (al = 0; al < 16; al++)
		for (len = 0; len <= 300; len++)
			ones_ok &= same_ones16(fold16(csum_partial(buf + al, len, 0xffffffff)), csum_ref(buf + al, len, 0xffffffff)) &&
				   same_ones16(fold16(csum_partial(buf + al, len, 0)), csum_ref(buf + al, len, 0));
	check(ip_ok, "ip_compute_csum == RFC 1071 reference, lengths 0..300 x 16 alignments (pseudo-random data)");
	check(part_ok, "csum_partial == RFC 1071 reference, lengths 0..300 x 16 alignments");
	check(init_ok, "csum_partial with an initial sum == reference, lengths 0..300 x 16 alignments");
	check(ones_ok, "csum_partial on all-0xff data (every adc carries) == reference");
	/* the raw 32-bit value, not just its class: nonzero data that sums to zero gives 0xffffffff, all-zero gives 0 */
	check(csum_partial(buf, 80, 0) == 0xffffffffu, "80 bytes of 0xff: raw value 0xffffffff (the C's representation of zero)");
	memset(buf, 0, 80);
	check(csum_partial(buf, 80, 0) == 0 && csum_partial(buf, 0, 0xdeadbeef) == 0xdeadbeefu && csum_partial(NULL, 0, 7) == 7,
	      "zero data gives 0; len 0 returns the initial sum, NULL included");
}
#else
static void __init test_x86_csum(void) { }
#endif

#if IS_ENABLED(CONFIG_NLS_UTF8)
/*
 * fs/nls/nls_utf8.c -> nls_utf8_rs.rs. CONFIG_NLS_UTF8 is config-full only.
 * Reached through the registry: load_nls("utf8") finds the table the Rust
 * owns (initcall order checked: init_nls_utf8 precedes libtest_init, both
 * level 6). Values are from the UTF-8 definition (RFC 3629), not the C:
 * U+00E9 = c3 a9, U+20AC = e2 82 ac, U+D800 is a surrogate (never encodable),
 * U+1F600 does not fit a 16-bit wchar_t.
 */
static void __init test_nls_utf8(void)
{
	static const u8 e_acute[] __initconst = { 0xc3, 0xa9 };
	static const u8 euro[] __initconst = { 0xe2, 0x82, 0xac };
	static const u8 grin[] __initconst = { 0xf0, 0x9f, 0x98, 0x80 };
	static const u8 bad[] __initconst = { 0xc3, 0x28 };
	struct nls_table *t = load_nls("utf8");
	u8 out[8];
	wchar_t w;

	check(t != NULL && !strcmp(t->charset, "utf8"), "load_nls(\"utf8\") finds the Rust-owned table");
	if (!t)
		return;
	check(t->charset2lower[0x41] == 0x41 && t->charset2upper[0xff] == 0xff,
	      "nls utf8 identity case tables");
	check(t->uni2char(0x41, out, 4) == 1 && out[0] == 'A', "uni2char(U+0041) == 'A'");
	check(t->uni2char(0xe9, out, 4) == 2 && !memcmp(out, e_acute, 2), "uni2char(U+00E9) == c3 a9");
	check(t->uni2char(0x20ac, out, 4) == 3 && !memcmp(out, euro, 3), "uni2char(U+20AC) == e2 82 ac");
	check(t->uni2char(0xd800, out, 4) == -EINVAL && out[0] == '?', "uni2char(surrogate) == -EINVAL, '?'");
	check(t->uni2char(0x41, out, 0) == -ENAMETOOLONG, "uni2char(boundlen 0) == -ENAMETOOLONG");
	check(t->uni2char(0xe9, out, 1) == -EINVAL, "uni2char(U+00E9, boundlen 1) == -EINVAL");
	check(t->char2uni(e_acute, 2, &w) == 2 && w == 0xe9, "char2uni(c3 a9) == U+00E9");
	check(t->char2uni(euro, 3, &w) == 3 && w == 0x20ac, "char2uni(e2 82 ac) == U+20AC");
	check(t->char2uni(bad, 2, &w) == -EINVAL && w == '?', "char2uni(c3 28) == -EINVAL, '?'");
	check(t->char2uni(grin, 4, &w) == -EINVAL && w == '?', "char2uni(U+1F600) too wide -> -EINVAL, '?'");
	unload_nls(t);
}
#else
static void __init test_nls_utf8(void) { }
#endif

#if IS_ENABLED(CONFIG_NLS)
/*
 * fs/nls/nls_base.c (conversion half) -> nls_base_rs.rs. CONFIG_NLS is config-full only.
 * Called directly (no registry needed). Values are from the UTF-8/UTF-16 definitions
 * (RFC 3629, RFC 2781), not the C: U+00E9 = c3 a9, U+20AC = e2 82 ac, U+1F600 = f0 9f 98 80
 * = surrogate pair d83d de00; c0 80 is an overlong NUL; ed a0 80 encodes a surrogate.
 */
static void __init test_nls_base(void)
{
	static const u8 s_e[] __initconst = { 0xc3, 0xa9 };
	static const u8 s_grin[] __initconst = { 0xf0, 0x9f, 0x98, 0x80 };
	static const u8 s_over[] __initconst = { 0xc0, 0x80 };
	static const u8 s_sur[] __initconst = { 0xed, 0xa0, 0x80 };
	static const u8 s_mix[] __initconst = { 'A', 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80 };
	static const u8 s_bad[] __initconst = { 'A', 0xc3, 0x28 };
	static const wchar_t w_mix[] __initconst = { 0x41, 0x20ac, 0xd83d, 0xde00 };
	static const wchar_t w_lone[] __initconst = { 0x41, 0xdc00, 0x42, 0xd83d, 0x43, 0 };
	unicode_t u = 0;
	u8 out[16];
	wchar_t w[8];

	check(utf8_to_utf32(s_e, 2, &u) == 2 && u == 0xe9, "utf8_to_utf32(c3 a9) == U+00E9");
	check(utf8_to_utf32(s_grin, 4, &u) == 4 && u == 0x1f600, "utf8_to_utf32(f0 9f 98 80) == U+1F600");
	check(utf8_to_utf32(s_over, 2, &u) == -EILSEQ, "utf8_to_utf32(overlong c0 80) == -EILSEQ");
	check(utf8_to_utf32(s_sur, 3, &u) == -EILSEQ, "utf8_to_utf32(ed a0 80 surrogate) == -EILSEQ");
	check(utf8_to_utf32(s_mix + 1, 2, &u) == -EOVERFLOW, "utf8_to_utf32(truncated e2 82) == -EOVERFLOW");
	memset(out, 0, sizeof(out));
	check(utf32_to_utf8(0x20ac, out, 8) == 3 && out[0] == 0xe2 && out[1] == 0x82 && out[2] == 0xac,
	      "utf32_to_utf8(U+20AC) == e2 82 ac");
	check(utf32_to_utf8(0x1f600, out, 8) == 4 && !memcmp(out, s_grin, 4), "utf32_to_utf8(U+1F600) == f0 9f 98 80");
	check(utf32_to_utf8(0xd800, out, 8) == -EILSEQ && utf32_to_utf8(0x110000, out, 8) == -EILSEQ,
	      "utf32_to_utf8(surrogate / > U+10FFFF) == -EILSEQ");
	check(utf32_to_utf8(0x20ac, out, 2) == -EOVERFLOW, "utf32_to_utf8(U+20AC, maxout 2) == -EOVERFLOW");
	check(utf32_to_utf8(0x20ac, NULL, 8) == 0, "utf32_to_utf8(NULL out) == 0");
	check(utf8s_to_utf16s(s_mix, sizeof(s_mix), UTF16_LITTLE_ENDIAN, w, 8) == 4 &&
	      !memcmp(w, w_mix, sizeof(w_mix)), "utf8s_to_utf16s(A, euro, U+1F600) -> 41 20ac d83d de00");
	check(utf8s_to_utf16s(s_mix, sizeof(s_mix), UTF16_BIG_ENDIAN, w, 8) == 4 &&
	      w[1] == cpu_to_be16(0x20ac) && w[3] == cpu_to_be16(0xde00), "utf8s_to_utf16s big endian");
	check(utf8s_to_utf16s(s_mix, sizeof(s_mix), UTF16_LITTLE_ENDIAN, w, 3) == 2,
	      "utf8s_to_utf16s: a surrogate pair that does not fit is left out");
	check(utf8s_to_utf16s(s_bad, sizeof(s_bad), UTF16_LITTLE_ENDIAN, w, 8) == -EINVAL,
	      "utf8s_to_utf16s(bad sequence) == -EINVAL");
	check(utf16s_to_utf8s(w_mix, 4, UTF16_LITTLE_ENDIAN, out, 16) == 8 && !memcmp(out, s_mix, 8),
	      "utf16s_to_utf8s(41 20ac d83d de00) == the 8 bytes");
	check(utf16s_to_utf8s(w_lone, 6, UTF16_LITTLE_ENDIAN, out, 16) == 3 &&
	      out[0] == 'A' && out[1] == 'B' && out[2] == 'C', "utf16s_to_utf8s skips lone surrogates");
	check(utf16s_to_utf8s(w_mix, 4, UTF16_LITTLE_ENDIAN, out, 5) == 4, "utf16s_to_utf8s stops when the next character does not fit");
}
#else
static void __init test_nls_base(void) { }
#endif

#if IS_ENABLED(CONFIG_NLS_ASCII)
/*
 * fs/nls/nls_ascii.c -> nls_ascii_rs.rs. CONFIG_NLS_ASCII is config-full only.
 * Reached through the registry: load_nls("ascii") finds the table the Rust
 * owns (init_nls_ascii precedes libtest_init, both level 6 -- checked in nm).
 * Values are from the ASCII definition: 7-bit, A-Z <-> a-z, nothing above
 * 0x7f maps. One inherited quirk, kept for parity with Linux: byte 0x00 has
 * no mapping (charset2uni[0] == 0 doubles as "unmapped"), so char2uni(0) is
 * -EINVAL, and so is uni2char(U+0000).
 */
static void __init test_nls_ascii(void)
{
	static const u8 hi[] __initconst = { 0x80 };
	static const u8 z[] __initconst = { 0x00 };
	static const u8 a[] __initconst = { 'a' };
	struct nls_table *t = load_nls("ascii");
	u8 out[4] = { 0xA5, 0xA5, 0xA5, 0xA5 };
	wchar_t w = 0xBEEF;

	check(t != NULL && !strcmp(t->charset, "ascii"), "load_nls(\"ascii\") finds the Rust-owned table");
	if (!t)
		return;
	check(t->charset2lower['A'] == 'a' && t->charset2lower['Z'] == 'z' && t->charset2lower['a'] == 'a' &&
	      t->charset2lower['@'] == '@' && t->charset2lower['['] == '[', "nls ascii lower table");
	check(t->charset2upper['a'] == 'A' && t->charset2upper['z'] == 'Z' && t->charset2upper['A'] == 'A' &&
	      t->charset2upper['`'] == '`' && t->charset2upper['{'] == '{', "nls ascii upper table");
	check(t->uni2char('A', out, 4) == 1 && out[0] == 'A' && out[1] == 0xA5, "uni2char(U+0041) == 'A', one byte");
	check(t->uni2char(0x7f, out, 1) == 1 && out[0] == 0x7f, "uni2char(U+007F) == 0x7f");
	check(t->uni2char(0x80, out, 4) == -EINVAL, "uni2char(U+0080) == -EINVAL");
	check(t->uni2char(0xe9, out, 4) == -EINVAL, "uni2char(U+00E9) == -EINVAL");
	check(t->uni2char(0x0141, out, 4) == -EINVAL, "uni2char(U+0141) == -EINVAL (page 01 absent)");
	check(t->uni2char(0x0000, out, 4) == -EINVAL, "uni2char(U+0000) == -EINVAL (kernel quirk, kept)");
	check(t->uni2char('A', out, 0) == -ENAMETOOLONG, "uni2char(boundlen 0) == -ENAMETOOLONG");
	check(t->char2uni(a, 1, &w) == 1 && w == 'a', "char2uni('a') == U+0061");
	check(t->char2uni(hi, 1, &w) == -EINVAL && w == 0, "char2uni(0x80) == -EINVAL, *uni = 0");
	check(t->char2uni(z, 1, &w) == -EINVAL, "char2uni(0x00) == -EINVAL (kernel quirk, kept)");
	unload_nls(t);
}
#else
static void __init test_nls_ascii(void) { }
#endif

#if IS_ENABLED(CONFIG_NLS_ISO8859_1)
/*
 * fs/nls/nls_iso8859-1.c -> nls_iso8859_1_rs.rs. CONFIG_NLS_ISO8859_1 is
 * config-full only. Through the registry: load_nls("iso8859-1"). Values are
 * from the ISO 8859-1 definition (byte == code point U+0000..U+00FF; A0..FF
 * are the Latin-1 letters, C0..DE upper case with +0x20 lower case except D7
 * "x"), not from the C. Kept Linux quirk: byte 0x00 / U+0000 have no mapping.
 */
static void __init test_nls_iso8859_1(void)
{
	static const u8 e_acute[] __initconst = { 0xe9 };
	static const u8 c1[] __initconst = { 0x80 };
	static const u8 yuml[] __initconst = { 0xff };
	static const u8 z[] __initconst = { 0x00 };
	struct nls_table *t = load_nls("iso8859-1");
	u8 out[4] = { 0xA5, 0xA5, 0xA5, 0xA5 };
	wchar_t w = 0xBEEF;

	check(t != NULL && !strcmp(t->charset, "iso8859-1"), "load_nls(\"iso8859-1\") finds the Rust-owned table");
	if (!t)
		return;
	check(t->charset2lower['A'] == 'a' && t->charset2lower[0xc0] == 0xe0 && t->charset2lower[0xde] == 0xfe &&
	      t->charset2lower[0xd7] == 0xd7 && t->charset2lower[0xe0] == 0xe0, "nls iso8859-1 lower table");
	check(t->charset2upper['z'] == 'Z' && t->charset2upper[0xe0] == 0xc0 && t->charset2upper[0xfe] == 0xde &&
	      t->charset2upper[0xf7] == 0xf7 && t->charset2upper[0xc0] == 0xc0, "nls iso8859-1 upper table");
	check(t->uni2char('A', out, 4) == 1 && out[0] == 'A' && out[1] == 0xA5, "uni2char(U+0041) == 'A', one byte");
	check(t->uni2char(0xe9, out, 4) == 1 && out[0] == 0xe9, "uni2char(U+00E9) == 0xe9");
	check(t->uni2char(0xff, out, 1) == 1 && out[0] == 0xff, "uni2char(U+00FF) == 0xff");
	check(t->uni2char(0x80, out, 4) == 1 && out[0] == 0x80, "uni2char(U+0080) == 0x80");
	check(t->uni2char(0x20ac, out, 4) == -EINVAL, "uni2char(U+20AC) == -EINVAL (page 20 absent)");
	check(t->uni2char(0x0100, out, 4) == -EINVAL, "uni2char(U+0100) == -EINVAL (page 01 absent)");
	check(t->uni2char(0x0000, out, 4) == -EINVAL, "uni2char(U+0000) == -EINVAL (kernel quirk, kept)");
	check(t->uni2char('A', out, 0) == -ENAMETOOLONG, "uni2char(boundlen 0) == -ENAMETOOLONG");
	check(t->char2uni(e_acute, 1, &w) == 1 && w == 0xe9, "char2uni(0xe9) == U+00E9");
	check(t->char2uni(c1, 1, &w) == 1 && w == 0x80, "char2uni(0x80) == U+0080");
	check(t->char2uni(yuml, 1, &w) == 1 && w == 0xff, "char2uni(0xff) == U+00FF");
	check(t->char2uni(z, 1, &w) == -EINVAL && w == 0, "char2uni(0x00) == -EINVAL, *uni = 0 (kernel quirk, kept)");
	unload_nls(t);
}
#else
static void __init test_nls_iso8859_1(void) { }
#endif

#if IS_ENABLED(CONFIG_NLS_CODEPAGE_437)
/*
 * fs/nls/nls_cp437.c -> nls_cp437_rs.rs. CONFIG_NLS_CODEPAGE_437 is config-full
 * only. Through the registry: load_nls("cp437"). Values are from the IBM
 * code page 437 definition (the same table Python's cp437 codec uses), not
 * from the C: 0x80 C-cedilla U+00C7, 0x81 u-diaeresis U+00FC, 0xE1 sharp s
 * U+00DF, 0xE3 pi U+03C0, 0xB0 light shade U+2591, 0xC4 box line U+2500, 0xFB
 * square root U+221A, 0xFE black square U+25A0, 0x9E peseta U+20A7, 0xA9
 * reversed not U+2310, 0x9F florin U+0192. These span all seven Unicode pages
 * the table has (00 01 03 20 22 23 25). Kept quirk: byte 0x00 / U+0000 unmapped.
 */
static void __init test_nls_cp437(void)
{
	static const struct { u8 b; u16 u; } m[] __initconst = {
		{ 0x41, 0x0041 }, { 0x80, 0x00c7 }, { 0x81, 0x00fc }, { 0xe1, 0x00df },
		{ 0x9f, 0x0192 }, { 0xe3, 0x03c0 }, { 0x9e, 0x20a7 }, { 0xfb, 0x221a },
		{ 0xa9, 0x2310 }, { 0xb0, 0x2591 }, { 0xc4, 0x2500 }, { 0xfe, 0x25a0 },
	};
	static const u8 z[] __initconst = { 0x00 };
	struct nls_table *t = load_nls("cp437");
	u8 out[4];
	wchar_t w;
	bool u2c = true, c2u = true;
	int i;

	check(t != NULL && !strcmp(t->charset, "cp437"), "load_nls(\"cp437\") finds the Rust-owned table");
	if (!t)
		return;
	for (i = 0; i < ARRAY_SIZE(m); i++) {
		u8 in[1] = { m[i].b };

		memset(out, 0xA5, sizeof(out));
		if (t->uni2char(m[i].u, out, 4) != 1 || out[0] != m[i].b || out[1] != 0xA5)
			u2c = false;
		w = 0xBEEF;
		if (t->char2uni(in, 1, &w) != 1 || w != m[i].u)
			c2u = false;
	}
	check(u2c, "nls cp437 uni2char over 12 code points across all 7 pages");
	check(c2u, "nls cp437 char2uni over the same 12 bytes");
	check(t->charset2lower['A'] == 'a' && t->charset2lower[0x80] == 0x87 && t->charset2lower[0x9a] == 0x81,
	      "nls cp437 lower table (C-cedilla -> c-cedilla, U-diaeresis -> u-diaeresis)");
	check(t->charset2upper['a'] == 'A' && t->charset2upper[0x87] == 0x80 && t->charset2upper[0x81] == 0x9a,
	      "nls cp437 upper table");
	check(t->uni2char(0x00a4, out, 4) == -EINVAL, "uni2char(U+00A4) == -EINVAL (not in cp437)");
	check(t->uni2char(0x0100, out, 4) == -EINVAL, "uni2char(U+0100) == -EINVAL (page 01, empty slot)");
	check(t->uni2char(0x0200, out, 4) == -EINVAL, "uni2char(U+0200) == -EINVAL (page 02 absent)");
	check(t->uni2char(0x0000, out, 4) == -EINVAL, "uni2char(U+0000) == -EINVAL (kernel quirk, kept)");
	check(t->uni2char('A', out, 0) == -ENAMETOOLONG, "uni2char(boundlen 0) == -ENAMETOOLONG");
	w = 0xBEEF;
	check(t->char2uni(z, 1, &w) == -EINVAL && w == 0, "char2uni(0x00) == -EINVAL, *uni = 0 (kernel quirk, kept)");
	unload_nls(t);
}
#else
static void __init test_nls_cp437(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_MD5)	/* not IS_ENABLED: libtest is built-in, crypto md5 can be =m (arm64 defconfig) */
/*
 * crypto/md5.c -> md5_shash_rs.rs (+ md5_glue.c). CONFIG_CRYPTO_MD5 is
 * config-full only. Through the crypto API, by DRIVER name so it is our
 * "md5-lib"/"hmac-md5-lib" and not some other md5 implementation. Digests are
 * RFC 1321 / RFC 2202 values; the export blob layout is the one documented in
 * crypto/md5.c: the library context with bytecount rounded down to a block,
 * then one byte of remainder. Needs md5_zero_message_hash too (exported data).
 */
static void __init test_md5_shash(void)
{
	static const u8 want_abc[MD5_DIGEST_SIZE] __initconst = {
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
	};
	static const u8 key1[16] __initconst = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};
	static const u8 want_hmac1[MD5_DIGEST_SIZE] __initconst = {
		0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
		0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
	};
	static const u8 abc[3] __initconst = { 'a', 'b', 'c' };
	static const u8 hithere[8] __initconst = "Hi There";
	static u8 long_msg[67] __initdata;
	struct crypto_shash *tfm;
	u8 out[MD5_DIGEST_SIZE], ref[MD5_DIGEST_SIZE];
	u8 state[sizeof(struct md5_ctx) + 1];
	u64 bc;
	int i;

	check(md5_zero_message_hash[0] == 0xd4 && md5_zero_message_hash[15] == 0x7e, "md5_zero_message_hash ends d4..7e");
	md5(NULL, 0, ref);
	check(!memcmp(md5_zero_message_hash, ref, MD5_DIGEST_SIZE), "md5_zero_message_hash == md5(\"\")");

	tfm = crypto_alloc_shash("md5-lib", 0, 0);
	check(!IS_ERR(tfm), "crypto_alloc_shash(\"md5-lib\")");
	if (!IS_ERR(tfm)) {
		SHASH_DESC_ON_STACK(desc, tfm);

		desc->tfm = tfm;
		check(crypto_shash_digest(desc, abc, sizeof(abc), out) == 0 && !memcmp(out, want_abc, sizeof(out)),
		      "shash md5-lib digest(\"abc\") matches RFC 1321");
		/* export after 3 bytes: remainder byte 3, block-aligned bytecount 0 */
		crypto_shash_init(desc);
		crypto_shash_update(desc, abc, sizeof(abc));
		check(crypto_shash_statesize(tfm) == sizeof(state), "md5 statesize == sizeof(md5_ctx) + 1");
		memset(state, 0xee, sizeof(state));
		check(crypto_shash_export(desc, state) == 0 && state[sizeof(struct md5_ctx)] == 3, "md5 export: remainder byte == 3");
		memcpy(&bc, state + offsetof(struct md5_ctx, bytecount), sizeof(bc));
		check(bc == 0, "md5 export: bytecount rounded down to 0");
		/* import into a fresh state, finish, compare */
		crypto_shash_init(desc);
		check(crypto_shash_import(desc, state) == 0, "md5 import");
		check(crypto_shash_final(desc, out) == 0 && !memcmp(out, want_abc, sizeof(out)),
		      "md5 export/import/final reproduces digest(\"abc\")");
		/* 67 bytes: block boundary crossed, bytecount 64 + remainder 3 */
		for (i = 0; i < sizeof(long_msg); i++)
			long_msg[i] = 'a' + i % 26;
		md5(long_msg, sizeof(long_msg), ref);
		crypto_shash_init(desc);
		crypto_shash_update(desc, long_msg, sizeof(long_msg));
		crypto_shash_export(desc, state);
		memcpy(&bc, state + offsetof(struct md5_ctx, bytecount), sizeof(bc));
		check(bc == 64 && state[sizeof(struct md5_ctx)] == 3, "md5 export of 67 bytes: bytecount 64, remainder 3");
		crypto_shash_init(desc);
		crypto_shash_import(desc, state);
		crypto_shash_final(desc, out);
		check(!memcmp(out, ref, sizeof(out)), "md5 import of the 67-byte state finishes to md5(67 bytes)");
		crypto_free_shash(tfm);
	}

	tfm = crypto_alloc_shash("hmac-md5-lib", 0, 0);
	check(!IS_ERR(tfm), "crypto_alloc_shash(\"hmac-md5-lib\")");
	if (!IS_ERR(tfm)) {
		SHASH_DESC_ON_STACK(desc, tfm);

		desc->tfm = tfm;
		check(crypto_shash_setkey(tfm, key1, sizeof(key1)) == 0, "hmac-md5-lib setkey");
		check(crypto_shash_digest(desc, hithere, sizeof(hithere), out) == 0 && !memcmp(out, want_hmac1, sizeof(out)),
		      "shash hmac-md5-lib matches RFC 2202 case 1");
		crypto_free_shash(tfm);
	}
}
#else
static void __init test_md5_shash(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_SHA256) /* not IS_ENABLED: libtest is built-in, the crypto API can be =m (riscv defconfig) */
/*
 * crypto/sha256.c -> sha256_shash_rs.rs (+ sha256_glue.c). CONFIG_CRYPTO_SHA256
 * is config-full only. Through the crypto API, by DRIVER name ("sha224-lib",
 * "sha256-lib"), so it is this file's registration and not another sha2
 * implementation. Digests are the FIPS 180-4 / NIST example values ("abc" and
 * the empty message). The export blob is the library context with bytecount
 * rounded down to a block plus one byte of remainder (105 bytes); the core
 * blob is the first 40 bytes (state + bytecount). The two exported
 * *_zero_message_hash tables stay C data in sha256_glue.c; read back here.
 */
static void __init test_sha256_shash(void)
{
	static const struct {
		const char *drv;
		unsigned int ds;
		const char *abc, *empty;
		const u8 *zero;
	} v[] __initconst = {
		{ "sha224-lib", SHA224_DIGEST_SIZE,
		  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
		  "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		  sha224_zero_message_hash },
		{ "sha256-lib", SHA256_DIGEST_SIZE,
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		  sha256_zero_message_hash },
	};
	static u8 msg[130] __initdata;
	u8 out[SHA256_DIGEST_SIZE], want[SHA256_DIGEST_SIZE], ref[SHA256_DIGEST_SIZE];
	u8 state[105], blob2[105];
	u64 bc;
	int i, k;

	for (i = 0; i < sizeof(msg); i++)
		msg[i] = 'a' + i % 26;

	for (k = 0; k < ARRAY_SIZE(v); k++) {
		struct crypto_shash *tfm = crypto_alloc_shash(v[k].drv, 0, 0);
		unsigned int ds = v[k].ds;
		char what[96];

		snprintf(what, sizeof(what), "crypto_alloc_shash(\"%s\")", v[k].drv);
		check(!IS_ERR(tfm), what);
		/* the exported data table, independent of the crypto API */
		snprintf(what, sizeof(what), "%s zero_message_hash == FIPS digest of \"\"", v[k].drv);
		check(hex2bin(want, v[k].empty, ds) == 0 && !memcmp(v[k].zero, want, ds), what);
		if (IS_ERR(tfm))
			continue;
		{
			SHASH_DESC_ON_STACK(desc, tfm);
			SHASH_DESC_ON_STACK(desc2, tfm);

			desc->tfm = tfm;
			desc2->tfm = tfm;
			snprintf(what, sizeof(what), "%s digest(\"abc\") matches FIPS 180-4", v[k].drv);
			check(hex2bin(want, v[k].abc, ds) == 0 &&
			      crypto_shash_digest(desc, "abc", 3, out) == 0 && !memcmp(out, want, ds), what);
			snprintf(what, sizeof(what), "%s digest(\"\") matches FIPS 180-4", v[k].drv);
			check(hex2bin(want, v[k].empty, ds) == 0 &&
			      crypto_shash_digest(desc, NULL, 0, out) == 0 && !memcmp(out, want, ds), what);
			check(crypto_shash_statesize(tfm) == sizeof(state), "sha2 shash statesize == 105");

			/* export after "abc": remainder byte 3, bytecount rounded down to 0 */
			crypto_shash_init(desc);
			crypto_shash_update(desc, "abc", 3);
			memset(state, 0xee, sizeof(state));
			check(crypto_shash_export(desc, state) == 0 && state[104] == 3, "sha2 export: remainder byte == 3");
			memcpy(&bc, state + 32, sizeof(bc));
			check(bc == 0, "sha2 export: bytecount rounded down to 0");
			/* import into a second desc, finish: FIPS "abc" */
			crypto_shash_init(desc2);
			check(crypto_shash_import(desc2, state) == 0, "sha2 import");
			memset(out, 0, sizeof(out));
			snprintf(what, sizeof(what), "%s export/import/final reproduces digest(\"abc\")", v[k].drv);
			check(hex2bin(want, v[k].abc, ds) == 0 && crypto_shash_final(desc2, out) == 0 &&
			      !memcmp(out, want, ds), what);

			/* 67 bytes: bytecount 64, remainder 3; and 130 bytes: bytecount 128, remainder 2 */
			for (i = 0; i < 2; i++) {
				unsigned int len = i ? 130 : 67;

				if (k)
					sha256(msg, len, ref);
				else
					sha224(msg, len, ref);
				crypto_shash_init(desc);
				crypto_shash_update(desc, msg, len);
				crypto_shash_export(desc, state);
				memcpy(&bc, state + 32, sizeof(bc));
				check(bc == (i ? 128 : 64) && state[104] == (i ? 2 : 3),
				      "sha2 export of 67/130 bytes: block-aligned bytecount + remainder");
				crypto_shash_init(desc2);
				crypto_shash_import(desc2, state);
				memset(out, 0, sizeof(out));
				crypto_shash_final(desc2, out);
				check(!memcmp(out, ref, ds), "sha2 import of the exported state finishes to the one-shot digest");
				/* re-export the imported state: the same blob (import(export) is the identity) */
				crypto_shash_init(desc2);
				crypto_shash_import(desc2, state);
				memset(blob2, 0x11, sizeof(blob2));
				crypto_shash_export(desc2, blob2);
				check(!memcmp(blob2, state, sizeof(state)), "sha2 export(import(blob)) == blob");
			}

			/* export_core/import_core: block-aligned position only (buf is not carried) */
			crypto_shash_init(desc);
			crypto_shash_update(desc, msg, 64);
			memset(state, 0xee, sizeof(state));
			check(crypto_shash_export_core(desc, state) == 0, "sha2 export_core");
			memcpy(&bc, state + 32, sizeof(bc));
			check(bc == 64, "sha2 export_core: bytecount == 64");
			for (i = 40; i < sizeof(state) && state[i] == 0xee; i++)
				;
			check(i == sizeof(state), "sha2 export_core writes exactly 40 bytes");
			crypto_shash_init(desc2);
			check(crypto_shash_import_core(desc2, state) == 0, "sha2 import_core");
			crypto_shash_update(desc2, msg + 64, 3);
			if (k)
				sha256(msg, 67, ref);
			else
				sha224(msg, 67, ref);
			memset(out, 0, sizeof(out));
			check(crypto_shash_final(desc2, out) == 0 && !memcmp(out, ref, ds),
			      "sha2 export_core/import_core/update(3)/final == one-shot of 67 bytes");
		}
		crypto_free_shash(tfm);
	}
}
#else
static void __init test_sha256_shash(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_SHA512) /* not IS_ENABLED: libtest is built-in, the crypto API can be =m (riscv defconfig) */
/*
 * crypto/sha512.c -> sha512_shash_rs.rs (+ sha512_glue.c). CONFIG_CRYPTO_SHA512
 * is config-full only. Through the crypto API, by DRIVER name ("sha384-lib",
 * "sha512-lib"), so it is this file's registration and not another sha2
 * implementation. Digests are the FIPS 180-4 / NIST example values ("abc" and
 * the empty message). The export blob is the library context with bytecount
 * (bytecount_lo) rounded down to a block plus one byte of remainder (209 bytes); the core
 * blob is the first 80 bytes (state + both bytecount words). The two exported
 * *_zero_message_hash tables stay C data in sha512_glue.c; read back here.
 */
static void __init test_sha512_shash(void)
{
	static const struct {
		const char *drv;
		unsigned int ds;
		const char *abc, *empty;
		const u8 *zero;
	} v[] __initconst = {
		{ "sha384-lib", SHA384_DIGEST_SIZE,
		  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		  "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		  sha384_zero_message_hash },
		{ "sha512-lib", SHA512_DIGEST_SIZE,
		  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		  sha512_zero_message_hash },
	};
	static u8 msg[270] __initdata;
	u8 out[SHA512_DIGEST_SIZE], want[SHA512_DIGEST_SIZE], ref[SHA512_DIGEST_SIZE];
	static u8 state[209], blob2[209] __initdata;
	u64 bc;
	int i, k;

	for (i = 0; i < sizeof(msg); i++)
		msg[i] = 'a' + i % 26;

	for (k = 0; k < ARRAY_SIZE(v); k++) {
		struct crypto_shash *tfm = crypto_alloc_shash(v[k].drv, 0, 0);
		unsigned int ds = v[k].ds;
		char what[96];

		snprintf(what, sizeof(what), "crypto_alloc_shash(\"%s\")", v[k].drv);
		check(!IS_ERR(tfm), what);
		/* the exported data table, independent of the crypto API */
		snprintf(what, sizeof(what), "%s zero_message_hash == FIPS digest of \"\"", v[k].drv);
		check(hex2bin(want, v[k].empty, ds) == 0 && !memcmp(v[k].zero, want, ds), what);
		if (IS_ERR(tfm))
			continue;
		{
			SHASH_DESC_ON_STACK(desc, tfm);
			SHASH_DESC_ON_STACK(desc2, tfm);

			desc->tfm = tfm;
			desc2->tfm = tfm;
			snprintf(what, sizeof(what), "%s digest(\"abc\") matches FIPS 180-4", v[k].drv);
			check(hex2bin(want, v[k].abc, ds) == 0 &&
			      crypto_shash_digest(desc, "abc", 3, out) == 0 && !memcmp(out, want, ds), what);
			snprintf(what, sizeof(what), "%s digest(\"\") matches FIPS 180-4", v[k].drv);
			check(hex2bin(want, v[k].empty, ds) == 0 &&
			      crypto_shash_digest(desc, NULL, 0, out) == 0 && !memcmp(out, want, ds), what);
			check(crypto_shash_statesize(tfm) == sizeof(state), "sha2 shash statesize == 209");

			/* export after "abc": remainder byte 3, bytecount rounded down to 0 */
			crypto_shash_init(desc);
			crypto_shash_update(desc, "abc", 3);
			memset(state, 0xee, sizeof(state));
			check(crypto_shash_export(desc, state) == 0 && state[208] == 3, "sha2 export: remainder byte == 3");
			memcpy(&bc, state + 64, sizeof(bc));
			check(bc == 0, "sha2 export: bytecount rounded down to 0");
			/* import into a second desc, finish: FIPS "abc" */
			crypto_shash_init(desc2);
			check(crypto_shash_import(desc2, state) == 0, "sha2 import");
			memset(out, 0, sizeof(out));
			snprintf(what, sizeof(what), "%s export/import/final reproduces digest(\"abc\")", v[k].drv);
			check(hex2bin(want, v[k].abc, ds) == 0 && crypto_shash_final(desc2, out) == 0 &&
			      !memcmp(out, want, ds), what);

			/* 131 bytes: bytecount_lo 128, remainder 3; and 260 bytes: 256, remainder 4 */
			for (i = 0; i < 2; i++) {
				unsigned int len = i ? 260 : 131;

				if (k)
					sha512(msg, len, ref);
				else
					sha384(msg, len, ref);
				crypto_shash_init(desc);
				crypto_shash_update(desc, msg, len);
				crypto_shash_export(desc, state);
				memcpy(&bc, state + 72, sizeof(bc));
				check(bc == 0, "sha512 export: bytecount_hi == 0 (not touched)");
				memcpy(&bc, state + 64, sizeof(bc));
				check(bc == (i ? 256 : 128) && state[208] == (i ? 4 : 3),
				      "sha2 export of 131/260 bytes: block-aligned bytecount + remainder");
				crypto_shash_init(desc2);
				crypto_shash_import(desc2, state);
				memset(out, 0, sizeof(out));
				crypto_shash_final(desc2, out);
				check(!memcmp(out, ref, ds), "sha2 import of the exported state finishes to the one-shot digest");
				/* re-export the imported state: the same blob (import(export) is the identity) */
				crypto_shash_init(desc2);
				crypto_shash_import(desc2, state);
				memset(blob2, 0x11, sizeof(blob2));
				crypto_shash_export(desc2, blob2);
				check(!memcmp(blob2, state, sizeof(state)), "sha2 export(import(blob)) == blob");
			}

			/* export_core/import_core: block-aligned position only (buf is not carried) */
			crypto_shash_init(desc);
			crypto_shash_update(desc, msg, 128);
			memset(state, 0xee, sizeof(state));
			check(crypto_shash_export_core(desc, state) == 0, "sha2 export_core");
			memcpy(&bc, state + 64, sizeof(bc));
			check(bc == 128, "sha2 export_core: bytecount_lo == 128");
			for (i = 80; i < sizeof(state) && state[i] == 0xee; i++)
				;
			check(i == sizeof(state), "sha2 export_core writes exactly 80 bytes");
			crypto_shash_init(desc2);
			check(crypto_shash_import_core(desc2, state) == 0, "sha2 import_core");
			crypto_shash_update(desc2, msg + 128, 3);
			if (k)
				sha512(msg, 131, ref);
			else
				sha384(msg, 131, ref);
			memset(out, 0, sizeof(out));
			check(crypto_shash_final(desc2, out) == 0 && !memcmp(out, ref, ds),
			      "sha2 export_core/import_core/update(3)/final == one-shot of 131 bytes");
		}
		crypto_free_shash(tfm);
	}
}
#else
static void __init test_sha512_shash(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_SHA3) /* not IS_ENABLED: libtest is built-in, the crypto API can be =m (riscv defconfig) */
/*
 * crypto/sha3_generic.c -> sha3_rs.rs (+ sha3_glue.c). CONFIG_CRYPTO_SHA3 is
 * config-full only. Through the crypto API by DRIVER name ("sha3-*-generic"),
 * so it is this file's registration and not some other sha3. Expected digests
 * are hashlib's (FIPS 202 values): "abc", the empty message, and 200 bytes
 * 'a'+i%26 (crosses the rate of every variant: 144/136/104/72), once as one
 * digest() and once as init + 7-byte update()s + final().
 */
static void __init test_sha3_shash(void)
{
	static const struct {
		const char *drv;
		unsigned int ds;
		const char *abc, *m200;
	} v[] __initconst = {
		{ "sha3-224-generic", SHA3_224_DIGEST_SIZE,
		  "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
		  "faef764b43b451554e0b831ac4ad5c2e609998488283d8e1e3cdbb74" },
		{ "sha3-256-generic", SHA3_256_DIGEST_SIZE,
		  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		  "f3c63d149a59bcbe2a640d3a974b121722069e9371bbdc436d724504deb8bb92" },
		{ "sha3-384-generic", SHA3_384_DIGEST_SIZE,
		  "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
		  "837390c78668cf6d2bd4f538eac61d491764c1ee3faec5e29788dffee31cd055de00021968792f9056fd95be9ffcb688" },
		{ "sha3-512-generic", SHA3_512_DIGEST_SIZE,
		  "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
		  "3b884f3a958f913d7af685aaaa0ec67a0d8aa952131aff26eed269ff44b48e989bbea5ab62a81aff245c2e3128f484bdb0397b1eb9402c1407dd12ec89d9590f" },
	};
	static const char want256_empty[] __initconst =
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
	static u8 msg[200] __initdata;
	u8 out[SHA3_512_DIGEST_SIZE], want[SHA3_512_DIGEST_SIZE];
	int i, j;

	for (i = 0; i < sizeof(msg); i++)
		msg[i] = 'a' + i % 26;

	for (i = 0; i < ARRAY_SIZE(v); i++) {
		struct crypto_shash *tfm = crypto_alloc_shash(v[i].drv, 0, 0);
		char what[80];

		snprintf(what, sizeof(what), "crypto_alloc_shash(\"%s\")", v[i].drv);
		check(!IS_ERR(tfm), what);
		if (IS_ERR(tfm))
			continue;
		{
			SHASH_DESC_ON_STACK(desc, tfm);

			desc->tfm = tfm;
			snprintf(what, sizeof(what), "%s digest(\"abc\")", v[i].drv);
			check(hex2bin(want, v[i].abc, v[i].ds) == 0 &&
			      crypto_shash_digest(desc, "abc", 3, out) == 0 &&
			      !memcmp(out, want, v[i].ds), what);
			snprintf(what, sizeof(what), "%s digest(200 bytes)", v[i].drv);
			check(hex2bin(want, v[i].m200, v[i].ds) == 0 &&
			      crypto_shash_digest(desc, msg, sizeof(msg), out) == 0 &&
			      !memcmp(out, want, v[i].ds), what);
			/* init + 7-byte updates + final: update() returns the remainder to the shash layer */
			crypto_shash_init(desc);
			for (j = 0; j < sizeof(msg); j += 7)
				crypto_shash_update(desc, msg + j, min_t(int, 7, sizeof(msg) - j));
			memset(out, 0, sizeof(out));
			snprintf(what, sizeof(what), "%s init/update(7)/final == one-shot", v[i].drv);
			check(crypto_shash_final(desc, out) == 0 && !memcmp(out, want, v[i].ds), what);
			if (i == 1) {
				check(hex2bin(want, want256_empty, 32) == 0 &&
				      crypto_shash_digest(desc, NULL, 0, out) == 0 &&
				      !memcmp(out, want, 32), "sha3-256-generic digest(\"\") (finup with no data)");
			}
		}
		crypto_free_shash(tfm);
	}

	/* crypto_sha3_init() is the one exported symbol (plain EXPORT_SYMBOL) */
	{
		struct crypto_shash *tfm = crypto_alloc_shash("sha3-256-generic", 0, 0);

		if (!IS_ERR(tfm)) {
			SHASH_DESC_ON_STACK(desc, tfm);
			struct sha3_state *sctx = shash_desc_ctx(desc);

			desc->tfm = tfm;
			memset(sctx->st, 0xee, sizeof(sctx->st));
			check(crypto_sha3_init(desc) == 0, "crypto_sha3_init() returns 0");
			for (j = 0; j < ARRAY_SIZE(sctx->st) && !sctx->st[j]; j++)
				;
			check(j == ARRAY_SIZE(sctx->st), "crypto_sha3_init() zeroes all 25 lanes");
			crypto_free_shash(tfm);
		}
	}
}
#else
static void __init test_sha3_shash(void) { }
#endif

#if IS_ENABLED(CONFIG_CRYPTO_LZO)
/*
 * crypto/lzo.c -> lzo_rs.rs (+ lzo_glue.c). CONFIG_CRYPTO_LZO is config-full
 * only. Through the acomp front end (which wraps the scomp), by DRIVER name so
 * it is this file's registration. __lzo_compress()/__lzo_decompress() are
 * reached by: a round trip of a compressible 1 KiB buffer (success path: the
 * output length is written back), a truncated compressed stream and an output
 * buffer that is too small (failure path: every non-LZO_E_OK becomes -EINVAL,
 * and the caller's length is not trusted afterwards).
 */
static int __init scomp_run(struct crypto_acomp *tfm, bool comp, void *in, unsigned int ilen,
			    void *out, unsigned int *olen)
{
	struct scatterlist sin, sout;
	struct acomp_req *req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	req = acomp_request_alloc(tfm);
	if (!req)
		return -ENOMEM;
	sg_init_one(&sin, in, ilen);
	sg_init_one(&sout, out, *olen);
	acomp_request_set_params(req, &sin, &sout, ilen, *olen);
	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	ret = crypto_wait_req(comp ? crypto_acomp_compress(req) : crypto_acomp_decompress(req), &wait);
	*olen = req->dlen;
	acomp_request_free(req);
	return ret;
}

static void __init test_scomp_lzo(const char *drv)
{
	struct crypto_acomp *tfm = crypto_alloc_acomp(drv, 0, 0);
	u8 *src = kmalloc(1024, GFP_KERNEL), *comp = kmalloc(2048, GFP_KERNEL), *out = kmalloc(1024, GFP_KERNEL);
	unsigned int clen = 2048, olen = 1024, small = 100, i;
	char what[80];
	int ret;

	snprintf(what, sizeof(what), "crypto_alloc_acomp(\"%s\")", drv);
	check(!IS_ERR(tfm) && src && comp && out, what);
	if (IS_ERR(tfm) || !src || !comp || !out)
		goto out;

	for (i = 0; i < 1024; i++)
		src[i] = (i / 37) % 2 ? 'x' : 'a' + i % 26;

	snprintf(what, sizeof(what), "%s compress of a compressible 1 KiB buffer succeeds", drv);
	ret = scomp_run(tfm, true, src, 1024, comp, &clen);
	check(ret == 0 && clen > 0 && clen < 1024, what);
	if (ret)
		goto out;
	snprintf(what, sizeof(what), "%s compress into a 10-byte buffer fails with -EINVAL", drv);
	olen = 10;
	ret = scomp_run(tfm, true, src, 1024, out, &olen);
	check(ret == -EINVAL, what);
	snprintf(what, sizeof(what), "%s decompress restores the 1 KiB buffer", drv);
	olen = 1024;
	memset(out, 0, 1024);
	ret = scomp_run(tfm, false, comp, clen, out, &olen);
	check(ret == 0 && olen == 1024 && !memcmp(out, src, 1024), what);
	snprintf(what, sizeof(what), "%s decompress into a 100-byte buffer fails with -EINVAL", drv);
	ret = scomp_run(tfm, false, comp, clen, out, &small);
	check(ret == -EINVAL, what);
	snprintf(what, sizeof(what), "%s decompress of a truncated stream fails with -EINVAL", drv);
	olen = 1024;
	ret = scomp_run(tfm, false, comp, clen / 2, out, &olen);
	check(ret == -EINVAL, what);
out:
	if (!IS_ERR_OR_NULL(tfm))
		crypto_free_acomp(tfm);
	kfree(src);
	kfree(comp);
	kfree(out);
}

static void __init test_lzo_scomp(void)
{
	test_scomp_lzo("lzo-scomp");
	/* crypto/lzo-rle.c -> lzorle_rs.rs (+ lzorle_glue.c): same cases, its own compressor */
	test_scomp_lzo("lzo-rle-scomp");
}
#else
static void __init test_lzo_scomp(void) { }
#endif

#if IS_BUILTIN(CONFIG_CRYPTO_GHASH) /* not IS_ENABLED: libtest is built-in, the crypto API can be =m (riscv defconfig) */
/*
 * crypto/ghash-generic.c -> ghash_rs.rs (+ ghash_glue.c). CONFIG_CRYPTO_GHASH
 * is config-full only. Through the crypto API by DRIVER name ("ghash-generic").
 * Expected values: GCM spec (McGrew & Viega) Test Case 2 -- H = 66e94bd4...,
 * X = C || len block -> f38cbb1a... -- and two more computed with a
 * bit-by-bit NIST SP 800-38D reference (port/test/ghash_generic/vectors.py).
 * The 53-byte message ends in a partial block (the zero-padded finup path);
 * re-keying exercises the free-the-old-table path of setkey.
 */
static void __init test_ghash_shash(void)
{
	static const char h_tc2[] __initconst = "66e94bd4ef8a2c3b884cfa59ca342b2e";
	static const char x_tc2[] __initconst =
		"0388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080";
	static const char want_tc2[] __initconst = "f38cbb1ad69223dcc3457ae5b6b0f885";
	static const char want_m53_tc2[] __initconst = "5229a704e71f92511975574b69233168";
	static const char want_m53_k2[] __initconst = "d8d73c8c4802466fc0ce95dcec505acc";
	static const u8 k2[16] __initconst = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	static u8 m53[53] __initdata;
	struct crypto_shash *tfm;
	u8 h[16], x[32], want[16], out[16], zero[16] = {};
	int i;

	for (i = 0; i < sizeof(m53); i++)
		m53[i] = 'a' + i % 26;

	tfm = crypto_alloc_shash("ghash-generic", 0, 0);
	check(!IS_ERR(tfm), "crypto_alloc_shash(\"ghash-generic\")");
	if (IS_ERR(tfm))
		return;
	{
		SHASH_DESC_ON_STACK(desc, tfm);

		desc->tfm = tfm;
		check(hex2bin(h, h_tc2, 16) == 0 && hex2bin(x, x_tc2, 32) == 0 && hex2bin(want, want_tc2, 16) == 0,
		      "ghash test vector hex decodes");
		check(crypto_shash_setkey(tfm, h, 15) == -EINVAL, "ghash setkey with a 15-byte key is -EINVAL");
		check(crypto_shash_setkey(tfm, h, 17) == -EINVAL, "ghash setkey with a 17-byte key is -EINVAL");
		check(crypto_shash_setkey(tfm, h, 16) == 0, "ghash setkey(H)");
		check(crypto_shash_digest(desc, x, 32, out) == 0 && !memcmp(out, want, 16),
		      "ghash matches GCM spec test case 2");
		check(hex2bin(want, want_m53_tc2, 16) == 0 &&
		      crypto_shash_digest(desc, m53, sizeof(m53), out) == 0 && !memcmp(out, want, 16),
		      "ghash of 53 bytes (partial final block)");
		crypto_shash_init(desc);
		for (i = 0; i < sizeof(m53); i += 5)
			crypto_shash_update(desc, m53 + i, min_t(int, 5, sizeof(m53) - i));
		memset(out, 0, sizeof(out));
		check(crypto_shash_final(desc, out) == 0 && !memcmp(out, want, 16),
		      "ghash init/update(5)/final == one-shot");
		check(crypto_shash_digest(desc, NULL, 0, out) == 0 && !memcmp(out, zero, 16),
		      "ghash of the empty message is 0");
		check(crypto_shash_setkey(tfm, k2, 16) == 0, "ghash re-key (frees the old table)");
		check(hex2bin(want, want_m53_k2, 16) == 0 &&
		      crypto_shash_digest(desc, m53, sizeof(m53), out) == 0 && !memcmp(out, want, 16),
		      "ghash of 53 bytes under the second key");
	}
	crypto_free_shash(tfm);	/* cra_exit frees the table */
}
#else
static void __init test_ghash_shash(void) { }
#endif

#if IS_REACHABLE(CONFIG_CRYPTO_LIB_GF128MUL)
#include <crypto/gf128mul.h>
/*
 * lib/crypto/gf128mul.c -> gf128mul_rs.rs (+ gf128mul_glue.c). Called DIRECTLY:
 * the shash "ghash-generic" reaches only gf128mul_init_4k_lle()/_4k_lle(), so
 * this is what makes gf128mul_lle(), the 64k_bbe table and gf128mul_x8_ble()
 * reached in the boot kernel. Expected values come from an independent
 * bit-by-bit Python reference (NIST SP 800-38D Algorithm 1 for the lle
 * product; carry-less multiply mod x^128+x^7+x^2+x+1 for bbe; x * x^8 for
 * x8_ble), never from the code under test. Entry 5 of v[] is GCM spec test
 * case 2's first GHASH step (H * X1). All values are memory-order hex bytes.
 */
static const struct { const char *a, *b, *lle, *bbe; } gf_v[] __initconst = {
	{ "00000000000000000000000000000000", "01434be3ebf87ed69c1bbf9c0735c9c9",
	  "00000000000000000000000000000000", "00000000000000000000000000000000" },
	{ "ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff",
	  "f402aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5555555555555555555555555555402f" },
	{ "80000000000000000000000000000000", "80000000000000000000000000000000",
	  "80000000000000000000000000000000", "c0000000000000000000000000001067" },
	{ "00000000000000000000000000000001", "d77a0cb424b63937ea0cf04256be1d97",
	  "57d6fbb4af138f2714bb5b26d9c7d005", "d77a0cb424b63937ea0cf04256be1d97" },
	{ "66e94bd4ef8a2c3b884cfa59ca342b2e", "0388dace60b6a392f328c2b971b2fe78",
	  "5e2ec746917062882c85b0685353deb7", "519fa38ac731568e9c1eb21731167f1c" },
	{ "00000000000000000000000000000080", "010000000000000000000000000000e1",
	  "0000000000000000000000000000a803", "80000000000000000000000000007080" },
	{ "1b5a878b864b214d49d773ab7f6f0e52", "4c55a76c841f30cf632003f79ec97f27",
	  "332d40fc19d53b024f703e2d9717462d", "ce404ba4be23ac1b4189b43b15f44ef2" },
	{ "79e011a8aa14971704afe3150d0631f9", "1fc93d1bcae69e40f86ef6f36072281a",
	  "ecf3d7c40c3c61a8478d9738a75de8df", "83c1c2636a28c473843fba2562a8ca47" },
	{ "20890445c1b3c37ae04cbc47a24877d3", "0e841b5c82fa89e89ea9a660d3e62d19",
	  "15bf9a6e847796eff259e34a4c0aaca0", "57887298b916304457e34185c6c705f1" },
};
static const struct { const char *x, *want; } gf_x8[] __initconst = {
	{ "00000000000000000000000000000000", "00000000000000000000000000000000" },
	{ "ffffffffffffffffffffffffffffffff", "7d82ffffffffffffffffffffffffffff" },
	{ "01000000000000000000000000000000", "00010000000000000000000000000000" },
	{ "00000000000000000000000000000080", "80430000000000000000000000000000" },
	{ "000000000000000000000000000000ff", "7d7d0000000000000000000000000000" },
	{ "2b8fc1acd27ba63966f9a88f43990fd5", "ab438fc1acd27ba63966f9a88f43990f" },
	{ "ff1ab27dce3fd0248339283b8c2ccd4d", "63d81ab27dce3fd0248339283b8c2ccd" },
	{ "af7f34575ace04a593c33555a8cc2a09", "bfab7f34575ace04a593c33555a8cc2a" },
	{ "9b3e84401f830f2f283d4a82573242e3", "29e83e84401f830f2f283d4a82573242" },
};

static void __init test_gf128mul(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(gf_v); i++) {
		be128 a, b, want_lle, want_bbe, r;
		struct gf128mul_4k *t4;
		struct gf128mul_64k *t64;
		bool ok = hex2bin((u8 *)&a, gf_v[i].a, 16) == 0 && hex2bin((u8 *)&b, gf_v[i].b, 16) == 0 &&
			  hex2bin((u8 *)&want_lle, gf_v[i].lle, 16) == 0 &&
			  hex2bin((u8 *)&want_bbe, gf_v[i].bbe, 16) == 0;

		check(ok, "gf128mul vector hex decodes");
		if (!ok)
			continue;

		r = a;
		gf128mul_lle(&r, &b);
		check(!memcmp(&r, &want_lle, 16), "gf128mul_lle matches the NIST bitwise product");

		t4 = gf128mul_init_4k_lle(&b);
		check(t4 != NULL, "gf128mul_init_4k_lle");
		if (t4) {
			r = a;
			gf128mul_4k_lle(&r, t4);
			check(!memcmp(&r, &want_lle, 16), "gf128mul_4k_lle matches the NIST bitwise product");
			gf128mul_free_4k(t4);
		}

		t64 = gf128mul_init_64k_bbe(&b);
		check(t64 != NULL, "gf128mul_init_64k_bbe");
		if (t64) {
			r = a;
			gf128mul_64k_bbe(&r, t64);
			check(!memcmp(&r, &want_bbe, 16), "gf128mul_64k_bbe matches the bitwise bbe product");
			gf128mul_free_64k(t64);
		}
	}

	for (i = 0; i < ARRAY_SIZE(gf_x8); i++) {
		le128 x, want, r;

		check(hex2bin((u8 *)&x, gf_x8[i].x, 16) == 0 && hex2bin((u8 *)&want, gf_x8[i].want, 16) == 0,
		      "gf128mul_x8_ble vector hex decodes");
		gf128mul_x8_ble(&r, &x);
		check(!memcmp(&r, &want, 16), "gf128mul_x8_ble matches x * x^8");
		gf128mul_x8_ble(&x, &x);	/* in place */
		check(!memcmp(&x, &want, 16), "gf128mul_x8_ble in place");
	}
}
#else
static void __init test_gf128mul(void) { }
#endif

#if IS_REACHABLE(CONFIG_CRYPTO_AES)
#include <crypto/internal/cipher.h>
/*
 * crypto/aes_generic.c -> aes_generic_rs.rs (+ aes_generic_glue.c). Through the crypto
 * API by DRIVER name ("aes-generic"; priority 100, so a plain "aes" lookup could
 * return an accelerated implementation). Expected values are the FIPS-197 text
 * (Appendix B, C.1, C.2, C.3), not the code under test; the table read-back
 * constants are column contributions computed from the FIPS-197 S-box and
 * (Inv)MixColumns matrix by an independent script. crypto_ft_tab/crypto_it_tab stay C data
 * and are read directly; the private last-round tables are reached through every
 * encrypt/decrypt below. crypto_cipher_encrypt_one() takes (tfm, dst, src): the
 * dst == src call is the in-place case.
 */
static void __init test_aes_generic(void)
{
	static const struct {
		const char *key, *pt, *ct;
		unsigned int klen;
	} v[] __initconst = {
		{ "2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
		  "3925841d02dc09fbdc118597196a0b32", 16 },
		{ "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
		  "69c4e0d86a7b0430d8cdb78070b4c55a", 16 },
		{ "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff",
		  "dda97ca4864cdfe06eaf70a0ec0d7191", 24 },
		{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		  "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089", 32 },
	};
	static const u8 badk[40] __initconst = { 1, 2, 3 };
	struct crypto_cipher *tfm;
	u8 key[32], pt[16], ct[16], out[16];
	int i;

	check(crypto_ft_tab[0][0] == 0xa56363c6 && crypto_ft_tab[1][0] == 0x6363c6a5 &&
	      crypto_ft_tab[2][0] == 0x63c6a563 && crypto_ft_tab[3][0] == 0xc6a56363,
	      "crypto_ft_tab[k][0] are the MixColumns columns times S[0] = 0x63");
	check(crypto_ft_tab[0][255] == 0x3a16162c && crypto_ft_tab[2][0x53] == 0xedc12ced &&
	      crypto_ft_tab[3][1] == 0xf8847c7c, "crypto_ft_tab spot entries (S[0xff] = 0x16, S[0x53] = 0xed, S[1] = 0x7c)");
	check(crypto_it_tab[0][0] == 0x50a7f451 && crypto_it_tab[1][0] == 0xa7f45150 &&
	      crypto_it_tab[2][0] == 0xf45150a7 && crypto_it_tab[3][0] == 0x5150a7f4,
	      "crypto_it_tab[k][0] are the InvMixColumns columns times Si[0] = 0x52");
	check(crypto_it_tab[0][255] == 0x4257b8d0 && crypto_it_tab[3][1] == 0x7e536541,
	      "crypto_it_tab spot entries");

	tfm = crypto_alloc_cipher("aes-generic", 0, 0);
	check(!IS_ERR(tfm), "crypto_alloc_cipher(\"aes-generic\")");
	if (IS_ERR(tfm))
		return;
	check(crypto_cipher_blocksize(tfm) == 16, "aes-generic block size is 16");
	for (i = 0; i < ARRAY_SIZE(v); i++) {
		check(hex2bin(key, v[i].key, v[i].klen) == 0 && hex2bin(pt, v[i].pt, 16) == 0 &&
		      hex2bin(ct, v[i].ct, 16) == 0, "aes test vector hex decodes");
		check(crypto_cipher_setkey(tfm, key, v[i].klen) == 0, "aes setkey with a valid key length");
		memset(out, 0, sizeof(out));
		crypto_cipher_encrypt_one(tfm, out, pt);
		check(!memcmp(out, ct, 16), "aes-generic encrypt matches the FIPS-197 vector");
		memset(out, 0, sizeof(out));
		crypto_cipher_decrypt_one(tfm, out, ct);
		check(!memcmp(out, pt, 16), "aes-generic decrypt matches the FIPS-197 vector");
		memcpy(out, pt, 16);
		crypto_cipher_encrypt_one(tfm, out, out);
		check(!memcmp(out, ct, 16), "aes-generic in-place encrypt matches the FIPS-197 vector");
		crypto_cipher_decrypt_one(tfm, out, out);
		check(!memcmp(out, pt, 16), "aes-generic in-place decrypt restores the plaintext");
	}
	check(crypto_cipher_setkey(tfm, badk, 0) == -EINVAL, "aes setkey with a 0-byte key is -EINVAL");
	check(crypto_cipher_setkey(tfm, badk, 15) == -EINVAL, "aes setkey with a 15-byte key is -EINVAL");
	check(crypto_cipher_setkey(tfm, badk, 17) == -EINVAL, "aes setkey with a 17-byte key is -EINVAL");
	check(crypto_cipher_setkey(tfm, badk, 31) == -EINVAL, "aes setkey with a 31-byte key is -EINVAL");
	check(crypto_cipher_setkey(tfm, badk, 33) == -EINVAL, "aes setkey with a 33-byte key is -EINVAL");
	/* re-key on the same tfm: C.3 (256-bit), C.1 (128-bit), C.2 (192-bit) */
	for (i = 0; i < 3; i++) {
		static const u8 order[3] __initconst = { 3, 1, 2 };
		int j = order[i];

		check(hex2bin(key, v[j].key, v[j].klen) == 0 && hex2bin(pt, v[j].pt, 16) == 0 &&
		      hex2bin(ct, v[j].ct, 16) == 0, "aes re-key vector hex decodes");
		check(crypto_cipher_setkey(tfm, key, v[j].klen) == 0, "aes re-key");
		crypto_cipher_encrypt_one(tfm, out, pt);
		check(!memcmp(out, ct, 16), "aes encrypt after re-key matches the FIPS-197 vector");
		crypto_cipher_decrypt_one(tfm, out, ct);
		check(!memcmp(out, pt, 16), "aes decrypt after re-key matches the FIPS-197 vector");
	}
	crypto_free_cipher(tfm);
}
#else
static void __init test_aes_generic(void) { }
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
#ifdef CONFIG_GENERIC_IOMAP
	test_iomap();
#endif
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
	test_zlib_deflate();
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
	test_vsscanf();
	test_fonts();
	test_num_digits();
	test_x86_cmdline();
	test_x86_cpu();
	test_x86_insn();
	test_timeconv();
	test_range();
	test_timecounter();
	test_fs_types();
	test_groups();
	test_net_utils();
	test_parser();
	test_prandom();
	test_time_conv();
	test_lockref();
	test_kfifo();
	test_genalloc();
	test_nlattr();
	test_assoc_array();
	test_maple_tree();
	test_group_cpus();
	test_scatterlist();
	test_rhashtable();
	test_iov_iter();
	test_refcount();
	test_percpu_ref();
	test_bch();
	test_lwq();
	test_ida();
	test_klist();
	test_kobject();
	test_kobject_uevent();
	test_argv_split();
	test_notifier();
	test_resource();
	test_ucount();
	test_ntp();
	test_clocksource();
	test_clockevents();
	test_timer();
	test_sysctl();
	test_kallsyms();
#ifdef CONFIG_EXT4_FS
	test_ext4_hash();
#endif
#ifdef CONFIG_SECURITY_SELINUX
	test_ebitmap();
	test_avtab();
	test_hashtab();
	test_conditional();
	test_mls();
#endif
#ifdef CONFIG_ETHTOOL_NETLINK
	test_ethtool_bitset();
#endif
#if defined(CONFIG_TCP_CONG_CUBIC) && defined(CONFIG_RUST)
	test_tcp_cubic();
#endif
#if defined(CONFIG_TCP_CONG_BIC) && defined(CONFIG_RUST)
	test_tcp_bic();
#endif
#if defined(CONFIG_TCP_CONG_ILLINOIS) && defined(CONFIG_RUST)
	test_tcp_illinois();
#endif
#if defined(CONFIG_TCP_CONG_HTCP) && defined(CONFIG_RUST)
	test_tcp_htcp();
#endif
#ifdef CONFIG_RUST
	test_pelt();
#endif
	test_loadavg();
	test_cputime();
	test_fs_parser();
#if defined(CONFIG_EFI_PARTITION) && defined(CONFIG_RUST)
	test_efi_part();
#endif
#ifdef CONFIG_UNICODE
	test_utf8_norm();
#endif
#ifdef CONFIG_AUDIT
	test_auditfilter();
#endif
#ifdef CONFIG_USER_NS
	test_user_namespace();
#endif
	test_memcat_p();
	test_dec_and_lock();
	test_logic_pio();
#ifdef CONFIG_CPU_RMAP
	test_cpu_rmap();
#endif
	test_radix_tree();
	test_rcuref();
	test_stackdepot();
	test_sbitmap();
	test_x86_csum();
	test_hmac();
	test_cmac();
	test_ctr();
	test_ecb();
	test_cbc();
	test_rsa_helper();
	test_rsa();
	test_nls_utf8();
	test_nls_base();
	test_nls_ascii();
	test_nls_iso8859_1();
	test_nls_cp437();
	test_md5_shash();
	test_sha256_shash();
	test_sha512_shash();
	test_sha3_shash();
	test_lzo_scomp();
	test_ghash_shash();
	test_gf128mul();
	test_aes_generic();

	pr_info("libtest: %u self-tests passed, %u failed\n", passed, failed);

	/* Same convention as lib/globtest.c: refuse to load on mismatch. */
	return failed ? -ECANCELED : 0;
}

static void __exit libtest_exit(void) { }

module_init(libtest_init);
module_exit(libtest_exit);

MODULE_DESCRIPTION("lib/ self-test for the Rust port");
MODULE_LICENSE("GPL");
