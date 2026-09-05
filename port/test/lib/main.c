/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential test for the top-level lib/ ports: base64, memweight,
 * mac_pton, union_find. The C bodies in ref_lib.c are the oracle; the Rust
 * is what changes if they disagree.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

int ref_base64_encode(const uint8_t *src, int srclen, char *dst);
int ref_base64_decode(const char *src, int srclen, uint8_t *dst);
size_t ref_memweight(const void *ptr, size_t bytes);
bool ref_mac_pton(const char *s, uint8_t *mac);

int rust_base64_encode(const uint8_t *src, int srclen, char *dst);
int rust_base64_decode(const char *src, int srclen, uint8_t *dst);
size_t rust_memweight(const void *ptr, size_t bytes);
bool rust_mac_pton(const char *s, uint8_t *mac);

struct ref_uf_node { struct ref_uf_node *parent; unsigned int rank; };
struct ref_uf_node *ref_uf_find(struct ref_uf_node *node);
void ref_uf_union(struct ref_uf_node *a, struct ref_uf_node *b);
struct ref_uf_node *uf_find(struct ref_uf_node *node);
void uf_union(struct ref_uf_node *a, struct ref_uf_node *b);

unsigned ref_bcd2bin(unsigned char val);
unsigned char ref_bin2bcd(unsigned val);
unsigned _bcd2bin(unsigned char val);
unsigned char _bin2bcd(unsigned val);

struct ref_minmax_sample { uint32_t t, v; };
struct ref_minmax { struct ref_minmax_sample s[3]; };
uint32_t ref_minmax_running_max(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas);
uint32_t ref_minmax_running_min(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas);
uint32_t rust_minmax_running_max(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas);
uint32_t rust_minmax_running_min(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas);

uint16_t ref_crc16(uint16_t crc, const uint8_t *p, size_t len);
uint16_t rust_crc16(uint16_t crc, const uint8_t *p, size_t len);

/* The sort/bsearch oracles are the PRISTINE kernel sources, compiled --
 * see README. These are their moved-aside names. */
typedef int (*cmp_func_t)(const void *a, const void *b);
typedef int (*cmp_r_func_t)(const void *a, const void *b, const void *priv);
typedef void (*swap_func_t)(void *a, void *b, int size);
typedef void (*swap_r_func_t)(void *a, void *b, int size, const void *priv);

void ref_sort_r(void *base, size_t num, size_t size, cmp_r_func_t cmp,
		swap_r_func_t swap, const void *priv);
void ref_sort(void *base, size_t num, size_t size, cmp_func_t cmp, swap_func_t swap);
void ref_sort_nonatomic(void *base, size_t num, size_t size, cmp_func_t cmp,
			swap_func_t swap);

/* The same pristine lib/sort.c compiled for x86-64 -- CONFIG_64BIT and
 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS set. See ref_sort_x86.c and
 * logs/floor.md criterion 8. */
void ref64_sort(void *base, size_t num, size_t size, cmp_func_t cmp, swap_func_t swap);
void ref64_sort_r(void *base, size_t num, size_t size, cmp_r_func_t cmp,
		  swap_r_func_t swap, const void *priv);
void *ref_bsearch(const void *key, const void *base, size_t num, size_t size,
		  cmp_func_t cmp);

void rust_sort_r(void *base, size_t num, size_t size, const void *cmp,
		 const void *swap, const void *priv, bool may_schedule,
		 bool efficient_unaligned);
void *rust_bsearch(const void *key, const void *base, size_t num, size_t size,
		   cmp_func_t cmp);

struct list_head { struct list_head *next, *prev; };
typedef int (*list_cmp_func_t)(void *, const struct list_head *,
			       const struct list_head *);
void ref_list_sort(void *priv, struct list_head *head, list_cmp_func_t cmp);
void rust_list_sort(void *priv, struct list_head *head, list_cmp_func_t cmp);

struct xxh32_state {
	uint32_t total_len_32, large_len, v1, v2, v3, v4, mem32[4], memsize;
};
struct xxh64_state {
	uint64_t total_len, v1, v2, v3, v4, mem64[4];
	uint32_t memsize;
};
uint32_t ref_xxh32(const void *input, size_t len, uint32_t seed);
uint64_t ref_xxh64(const void *input, size_t len, uint64_t seed);
void ref_xxh64_reset(struct xxh64_state *s, uint64_t seed);
int ref_xxh64_update(struct xxh64_state *s, const void *input, size_t len);
uint64_t ref_xxh64_digest(const struct xxh64_state *s);
void ref_xxh32_reset(struct xxh32_state *s, uint32_t seed);
void ref_xxh32_copy_state(struct xxh32_state *d, const struct xxh32_state *s);
void ref_xxh64_copy_state(struct xxh64_state *d, const struct xxh64_state *s);

uint32_t rust_xxh32(const void *input, size_t len, uint32_t seed);
uint64_t rust_xxh64(const void *input, size_t len, uint64_t seed);
void rust_xxh64_reset(struct xxh64_state *s, uint64_t seed);
int rust_xxh64_update(struct xxh64_state *s, const void *input, size_t len);
uint64_t rust_xxh64_digest(const struct xxh64_state *s);
void rust_xxh32_reset(struct xxh32_state *s, uint32_t seed);
void rust_xxh32_copy_state(struct xxh32_state *d, const struct xxh32_state *s);
void rust_xxh64_copy_state(struct xxh64_state *d, const struct xxh64_state *s);

#define MAX_CPIO_FILE_NAME 18
struct cpio_data { void *data; size_t size; char name[MAX_CPIO_FILE_NAME]; };
struct cpio_data ref_find_cpio_data(const char *path, void *data, size_t len, long *off);
struct cpio_data find_cpio_data(const char *path, void *data, size_t len, long *off);

struct plist_head { struct list_head node_list; };
struct plist_node { int prio; struct list_head prio_list, node_list; };
void ref_plist_add(struct plist_node *n, struct plist_head *h);
void ref_plist_del(struct plist_node *n, struct plist_head *h);
void ref_plist_requeue(struct plist_node *n, struct plist_head *h);
void rust_plist_add(struct plist_node *n, struct plist_head *h);
void rust_plist_del(struct plist_node *n, struct plist_head *h);
void rust_plist_requeue(struct plist_node *n, struct plist_head *h);

struct arc4_ctx { uint32_t S[256]; uint32_t x, y; };
int ref_arc4_setkey(struct arc4_ctx *c, const uint8_t *k, unsigned int n);
void ref_arc4_crypt(struct arc4_ctx *c, uint8_t *out, const uint8_t *in, unsigned int n);
int rust_arc4_setkey(struct arc4_ctx *c, const uint8_t *k, unsigned int n);
void rust_arc4_crypt(struct arc4_ctx *c, uint8_t *out, const uint8_t *in, unsigned int n);

int ref_ctzsi2(int v); /* not used; clz_ctz has no separate oracle -- see below */

uint16_t ref_crc_ccitt(uint16_t crc, const uint8_t *b, size_t len);
uint16_t rust_crc_ccitt(uint16_t crc, const uint8_t *b, size_t len, const uint16_t *tab);

int rust_ctzsi2(int v);
int rust_clzsi2(int v);
int rust_clzdi2(uint64_t v);
int rust_ctzdi2(uint64_t v);

struct chacha_state { uint32_t x[16]; };
void ref_chacha_block_generic(struct chacha_state *s, uint8_t *out, int n);
void ref_hchacha_block_generic(const struct chacha_state *s, uint32_t *out, int n);
void rust_chacha_block_generic(struct chacha_state *s, uint8_t *out, int n);
void rust_hchacha_block_generic(const struct chacha_state *s, uint32_t *out, int n);

/* lib/crypto/chacha_block_generic_rs.rs calls this; in the kernel it is
 * memzero_explicit() via chacha_zeroize_state(). */
void rust_chacha_zeroize_state(struct chacha_state *s) { memset(s, 0, sizeof(*s)); }

void ref_crypto_xor(uint8_t *dst, const uint8_t *s1, const uint8_t *s2, unsigned int len);
void rust_crypto_xor(uint8_t *dst, const uint8_t *s1, const uint8_t *s2,
		     unsigned int len, bool eff_unaligned, bool is64);

typedef uint16_t ucs2_char_t;
unsigned long ref_ucs2_strnlen(const ucs2_char_t *s, size_t maxlength);
unsigned long ref_ucs2_strlen(const ucs2_char_t *s);
unsigned long ref_ucs2_strsize(const ucs2_char_t *d, unsigned long maxlength);
ssize_t ref_ucs2_strscpy(ucs2_char_t *dst, const ucs2_char_t *src, size_t count);
int ref_ucs2_strncmp(const ucs2_char_t *a, const ucs2_char_t *b, size_t len);
unsigned long ref_ucs2_utf8size(const ucs2_char_t *src);
unsigned long ref_ucs2_as_utf8(uint8_t *dest, const ucs2_char_t *src, unsigned long maxlength);
unsigned long rust_ucs2_strnlen(const ucs2_char_t *s, size_t maxlength);
unsigned long rust_ucs2_strlen(const ucs2_char_t *s);
unsigned long rust_ucs2_strsize(const ucs2_char_t *d, unsigned long maxlength);
ssize_t rust_ucs2_strscpy(ucs2_char_t *dst, const ucs2_char_t *src, size_t count);
int rust_ucs2_strncmp(const ucs2_char_t *a, const ucs2_char_t *b, size_t len);
unsigned long rust_ucs2_utf8size(const ucs2_char_t *src);
unsigned long rust_ucs2_as_utf8(uint8_t *dest, const ucs2_char_t *src, unsigned long maxlength);

typedef unsigned long mpi_limb_t;
mpi_limb_t mpihelp_mul_1(mpi_limb_t *res, const mpi_limb_t *s1, int n, mpi_limb_t s2);
mpi_limb_t mpihelp_addmul_1(mpi_limb_t *res, const mpi_limb_t *s1, int n, mpi_limb_t s2);
mpi_limb_t mpihelp_submul_1(mpi_limb_t *res, const mpi_limb_t *s1, int n, mpi_limb_t s2);
mpi_limb_t mpihelp_add_n(mpi_limb_t *res, const mpi_limb_t *s1, const mpi_limb_t *s2, int n);
mpi_limb_t mpihelp_sub_n(mpi_limb_t *res, const mpi_limb_t *s1, const mpi_limb_t *s2, int n);
mpi_limb_t mpihelp_lshift(mpi_limb_t *wp, const mpi_limb_t *up, int n, unsigned int cnt);
mpi_limb_t mpihelp_rshift(mpi_limb_t *wp, const mpi_limb_t *up, int n, unsigned int cnt);
int mpihelp_cmp(const mpi_limb_t *a, const mpi_limb_t *b, int n);

/* lib/earlycpio_rs.rs calls this; in the kernel it is a pr_warn(). */
void rust_earlycpio_warn_long_name(const char *name) { (void)name; }

/* lib/sort_rs.rs calls this; in the kernel it is cond_resched(). */
void rust_sort_cond_resched(void) { }

/* lib/check_signature_rs.rs calls this; in the kernel it is rust/helpers/io.c,
 * which is readb() plus the architecture's ordering barriers. Here it is the
 * plain load, matching shim/linux/io.h -- see the note there on why the
 * barriers are out of this test's scope and how the ordering is settled. */
unsigned char rust_helper_readb(const volatile void *addr)
{
	return *(const volatile unsigned char *)addr;
}

int ref_check_signature(const volatile void *io_addr,
			const unsigned char *signature, int length);
int rust_check_signature(const volatile void *io_addr,
			 const unsigned char *signature, int length);

static unsigned long checked, mismatches;

static void fail(const char *fmt, ...)
{
	va_list ap;

	if (mismatches < 20) {
		__builtin_va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		__builtin_va_end(ap);
	}
	mismatches++;
}

static uint64_t rnd_state = 0xc0ffee123456789ULL;

static uint64_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 7;
	rnd_state ^= rnd_state << 17;
	return rnd_state;
}

/* ---- base64 ---------------------------------------------------------- */

static void cmp_encode(const uint8_t *src, int len)
{
	char a[512], b[512];
	int na, nb;

	memset(a, 0xa5, sizeof(a));
	memset(b, 0x5a, sizeof(b));
	na = ref_base64_encode(src, len, a);
	nb = rust_base64_encode(src, len, b);

	checked++;
	if (na != nb || memcmp(a, b, na > 0 ? na : 0)) {
		fail("base64_encode(len=%d): C n=%d rust n=%d\n", len, na, nb);
		return;
	}
	/* Nothing past the returned length may be touched. */
	checked++;
	if (nb >= 0 && b[nb] != 0x5a)
		fail("base64_encode(len=%d) wrote past its return value\n", len);
}

static void cmp_decode(const char *src, int len)
{
	uint8_t a[512], b[512];
	int na, nb;

	memset(a, 0xa5, sizeof(a));
	memset(b, 0x5a, sizeof(b));
	na = ref_base64_decode(src, len, a);
	nb = rust_base64_decode(src, len, b);

	checked++;
	if (na != nb || (na > 0 && memcmp(a, b, na))) {
		fail("base64_decode(\"%.*s\"): C n=%d rust n=%d\n", len, src, na, nb);
		return;
	}
	checked++;
	if (nb > 0 && b[nb] != 0x5a)
		fail("base64_decode wrote past its return value\n");
}

static void stage_base64(unsigned long rounds)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	/* A wider alphabet than base64's, so invalid input is exercised too. */
	static const char wide[] =
		"ABCZaz09+/= !-_\n\t";
	uint8_t buf[96];
	char enc[512];
	unsigned long before = checked;
	int len;

	/* Every length up to 96, so every padding case and every group
	 * boundary is hit. */
	for (len = 0; len <= 96; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (uint8_t)(i * 37 + len);
		cmp_encode(buf, len);

		/* And the encoding of it must decode back. */
		int n = ref_base64_encode(buf, len, enc);

		cmp_decode(enc, n);
	}
	printf("  base64 lengths    %lu cases  (every length 0..96, encode and decode)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		len = rnd() % 64;
		for (int j = 0; j < len; j++)
			buf[j] = (uint8_t)rnd();
		cmp_encode(buf, len);

		/* Valid-alphabet strings, mostly decodable. */
		len = rnd() % 64;
		for (int j = 0; j < len; j++)
			enc[j] = alphabet[rnd() % (sizeof(alphabet) - 1)];
		cmp_decode(enc, len);

		/* And strings that are mostly not. */
		len = rnd() % 16;
		for (int j = 0; j < len; j++)
			enc[j] = wide[rnd() % (sizeof(wide) - 1)];
		cmp_decode(enc, len);
	}
	printf("  base64 fuzz       %lu cases  (random bytes, valid and invalid strings)\n",
	       checked - before);

	/* Every single byte as a decoder input: the accept/reject boundary. */
	before = checked;
	for (int c = 0; c < 256; c++) {
		char one[2] = { (char)c, 0 };

		cmp_decode(one, 1);
		char two[3] = { 'A', (char)c, 0 };

		cmp_decode(two, 2);
	}
	printf("  base64 bytes      %lu cases  (every byte value as decoder input)\n",
	       checked - before);
}

/* ---- memweight ------------------------------------------------------- */

static void stage_memweight(unsigned long rounds)
{
	/* Over-aligned, so every offset within a long can be tested. */
	static uint8_t buf[1024] __attribute__((aligned(64)));
	unsigned long before = checked;

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)(i * 173 + 11);

	/* Every start offset and every length up to 80: this is exactly where
	 * the C's three-phase aligned walk changes shape and the Rust's
	 * single popcount loop does not. */
	for (size_t off = 0; off < 72; off++)
		for (size_t len = 0; len <= 80; len++) {
			size_t a = ref_memweight(buf + off, len);
			size_t b = rust_memweight(buf + off, len);

			checked++;
			if (a != b)
				fail("memweight(+%zu, %zu): C=%zu rust=%zu\n", off, len, a, b);
		}
	printf("  memweight offsets %lu cases  (every offset 0..71 x every length 0..80)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds / 8; i++) {
		size_t off = rnd() % 512, len = rnd() % 512;
		size_t a, b;

		for (size_t j = 0; j < 8; j++)
			buf[(rnd() % sizeof(buf))] = (uint8_t)rnd();

		a = ref_memweight(buf + off, len);
		b = rust_memweight(buf + off, len);
		checked++;
		if (a != b)
			fail("memweight(+%zu, %zu): C=%zu rust=%zu\n", off, len, a, b);
	}
	printf("  memweight fuzz    %lu cases\n", checked - before);
}

/* ---- mac_pton -------------------------------------------------------- */

static void cmp_mac(const char *s)
{
	uint8_t a[8], b[8];
	bool ra, rb;

	memset(a, 0xa5, sizeof(a));
	memset(b, 0xa5, sizeof(b));
	ra = ref_mac_pton(s, a);
	rb = rust_mac_pton(s, b);

	checked += 2;
	if (ra != rb)
		fail("mac_pton(\"%s\"): C=%d rust=%d\n", s, ra, rb);
	else if (memcmp(a, b, sizeof(a)))
		fail("mac_pton(\"%s\") wrote different bytes (rc=%d)\n", s, ra);
}

static void stage_mac(unsigned long rounds)
{
	static const char chars[] = "0123456789abcdefABCDEFgG:-. \0x";
	char s[24];
	unsigned long before = checked;

	cmp_mac("");
	cmp_mac("0");
	cmp_mac("00:1a:2b:cd:ef:ff");
	cmp_mac("00:1A:2B:CD:EF:FF");
	cmp_mac("00:1a:2b:cd:ef:f");
	cmp_mac("00:1a:2b:cd:ef");
	cmp_mac("00-1a-2b-cd-ef-ff");
	cmp_mac("gg:1a:2b:cd:ef:ff");
	cmp_mac("00:1a:2b:cd:ef:ff:aa");
	cmp_mac("::::::::::::::::");

	/* Truncations of a valid address at every length: the C decides with
	 * strnlen up front, the Rust decides as it walks. This is where those
	 * two ways of getting the same answer would part company. */
	for (int n = 0; n <= 17; n++) {
		memcpy(s, "00:1a:2b:cd:ef:ff", 17);
		s[n] = '\0';
		cmp_mac(s);
	}
	printf("  mac_pton fixed    %lu cases  (incl. every truncation of a valid address)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		int len = rnd() % 20;
		int j;

		for (j = 0; j < len; j++)
			s[j] = chars[rnd() % (sizeof(chars) - 1)];
		s[j] = '\0';
		cmp_mac(s);
	}
	printf("  mac_pton fuzz     %lu cases\n", checked - before);
}

/* ---- union_find ------------------------------------------------------ */

#define UF_N 64

static void stage_union_find(unsigned long rounds)
{
	struct ref_uf_node ra[UF_N], rb[UF_N];
	unsigned long before = checked;

	for (unsigned long round = 0; round < rounds / 100 + 1; round++) {
		for (int i = 0; i < UF_N; i++) {
			ra[i].parent = &ra[i]; ra[i].rank = 0;
			rb[i].parent = &rb[i]; rb[i].rank = 0;
		}

		for (int op = 0; op < 256; op++) {
			int i = rnd() % UF_N, j = rnd() % UF_N;

			if (rnd() & 1) {
				ref_uf_union(&ra[i], &ra[j]);
				uf_union(&rb[i], &rb[j]);
			} else {
				/* find compresses paths, so the two forests
				 * must be driven identically or their shapes
				 * diverge even when the sets agree */
				ref_uf_find(&ra[i]);
				uf_find(&rb[i]);
			}

			/* Same partition AND same tree shape: parent index
			 * and rank, node for node. Comparing only the sets
			 * would not notice a broken path compression. */
			checked++;
			for (int k = 0; k < UF_N; k++) {
				if (ra[k].parent - ra != rb[k].parent - rb ||
				    ra[k].rank != rb[k].rank) {
					fail("union_find diverged at node %d after op %d\n", k, op);
					return;
				}
			}
		}
	}
	printf("  union_find        %lu cases  (random union/find, forests compared node by node)\n",
	       checked - before);
}

/* ---- sort and bsearch ------------------------------------------------ */

/* The C's sentinel tags, from lib/sort.c. sort() smuggles a non-_r callback
 * pair through priv and marks it with these; they are compared, never
 * called. */
#define SWAP_WRAPPER ((const void *)3)
#define CMP_WRAPPER  ((const void *)0)

struct wrapper { cmp_func_t cmp; swap_func_t swap; };

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return (x > y) - (x < y);
}

static int cmp_u32_r(const void *a, const void *b, const void *priv)
{
	(void)priv;
	return cmp_u32(a, b);
}

/* A comparison on the first byte only, so that many elements compare equal
 * and the heap's tie-breaking is exercised rather than avoided. */
static int cmp_first_byte(const void *a, const void *b)
{
	return (int)*(const uint8_t *)a - (int)*(const uint8_t *)b;
}

static unsigned long swap_calls;

/* A custom swap, which forces the SWAP_WRAPPER / callback path instead of
 * the three built-in strategies. */
static void swap_custom(void *a, void *b, int size)
{
	uint8_t t;

	swap_calls++;
	for (int i = 0; i < size; i++) {
		t = ((uint8_t *)a)[i];
		((uint8_t *)a)[i] = ((uint8_t *)b)[i];
		((uint8_t *)b)[i] = t;
	}
}

static void swap_custom_r(void *a, void *b, int size, const void *priv)
{
	(void)priv;
	swap_custom(a, b, size);
}

static void cmp_sorted(const uint8_t *a, const uint8_t *b, size_t num, size_t size,
		       const char *what)
{
	checked++;
	if (memcmp(a, b, num * size))
		fail("%s: arrays differ (num=%zu size=%zu)\n", what, num, size);
}

static void stage_sort(unsigned long rounds)
{
	/* Over-aligned with room to offset, so unaligned bases are reachable. */
	static uint8_t ba[8192] __attribute__((aligned(64)));
	static uint8_t bb[8192] __attribute__((aligned(64)));
	static const size_t sizes[] = { 1, 2, 3, 4, 5, 7, 8, 12, 16, 24 };
	unsigned long before = checked;

	/* logs/floor.md criterion 8. sort.c forks on CONFIG_64BIT and
	 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS; our kernels set both. The
	 * Rust takes that fork as a RUNTIME argument, so one Rust build serves
	 * both arms, but the C needs two compilations. eff=1 pairs ref64_*
	 * (x86-64, what we ship) with the Rust's efficient path; eff=0 pairs
	 * ref_* (32-bit, slow unaligned) with its generic path.
	 *
	 * Both pairs run so that neither Rust path is code no test executes.
	 * Note what this does NOT buy: measured 2026-09-03, sabotaging
	 * sort_rs.rs to ignore efficient_unaligned entirely still PASSED,
	 * because both strategies sort correctly. This differential cannot see
	 * a mispairing. rig/config-fidelity.sh is what guards that. */
	for (int eff = 1; eff >= 0; eff--) {
		for (unsigned si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
			size_t size = sizes[si];

			for (size_t num = 0; num <= 40; num++)
				for (size_t off = 0; off < 8; off++) {
					size_t bytes = num * size;

					for (size_t i = 0; i < bytes; i++)
						ba[off + i] = bb[off + i] = (uint8_t)rnd();

					/* sort(): the _CMP_WRAPPER / SWAP_WRAPPER path
					 * with the built-in swap chosen by alignment */
					if (eff)
						ref64_sort(ba + off, num, size, cmp_first_byte, NULL);
					else
						ref_sort(ba + off, num, size, cmp_first_byte, NULL);
					{
						struct wrapper w = { cmp_first_byte, NULL };

						rust_sort_r(bb + off, num, size, CMP_WRAPPER,
							    SWAP_WRAPPER, &w, false, eff);
					}
					cmp_sorted(ba + off, bb + off, num, size,
						   eff ? "sort() [x86-64]" : "sort() [generic]");

					/* and again with a custom swap, which takes the
					 * callback path instead */
					for (size_t i = 0; i < bytes; i++)
						ba[off + i] = bb[off + i] = (uint8_t)rnd();
					if (eff)
						ref64_sort(ba + off, num, size, cmp_first_byte, swap_custom);
					else
						ref_sort(ba + off, num, size, cmp_first_byte, swap_custom);
					{
						struct wrapper w = { cmp_first_byte, swap_custom };

						rust_sort_r(bb + off, num, size, CMP_WRAPPER,
							    SWAP_WRAPPER, &w, false, eff);
					}
					cmp_sorted(ba + off, bb + off, num, size,
						   eff ? "sort() custom swap [x86-64]"
						       : "sort() custom swap [generic]");
				}
		}
	}
	printf("  sort shapes       %lu cases  (10 element sizes x 0..40 elements x 8 offsets,\n"
	       "                              built-in and custom swap, BOTH configurations)\n",
	       checked - before);

	/* sort_r(): the direct callback path, on u32s, plus an independent
	 * sortedness check that does not consult the C at all. */
	before = checked;
	for (int eff = 1; eff >= 0; eff--)
	for (unsigned long i = 0; i < rounds / 20 + 1; i++) {
		size_t num = rnd() % 512;

		for (size_t j = 0; j < num; j++) {
			uint32_t v = (uint32_t)rnd();

			memcpy(ba + j * 4, &v, 4);
			memcpy(bb + j * 4, &v, 4);
		}
		if (eff)
			ref64_sort_r(ba, num, 4, cmp_u32_r, NULL, NULL);
		else
			ref_sort_r(ba, num, 4, cmp_u32_r, NULL, NULL);
		rust_sort_r(bb, num, 4, (const void *)cmp_u32_r, NULL, NULL, false, eff);
		cmp_sorted(ba, bb, num, 4, eff ? "sort_r() [x86-64]" : "sort_r() [generic]");

		checked++;
		for (size_t j = 1; j < num; j++) {
			uint32_t p, q;

			memcpy(&p, bb + (j - 1) * 4, 4);
			memcpy(&q, bb + j * 4, 4);
			if (p > q) {
				fail("sort_r() left element %zu out of order\n", j);
				break;
			}
		}
	}
	printf("  sort_r fuzz       %lu cases  (u32 arrays to 512 elements, plus an\n"
	       "                              independent sortedness check, BOTH configurations)\n",
	       checked - before);

	/* A custom swap_r, and may_schedule, so every dispatch arm is hit. */
	before = checked;
	for (int eff = 1; eff >= 0; eff--)
	for (unsigned long i = 0; i < rounds / 100 + 1; i++) {
		size_t num = rnd() % 64;

		for (size_t j = 0; j < num * 4; j++)
			ba[j] = bb[j] = (uint8_t)rnd();
		if (eff)
			ref64_sort_r(ba, num, 4, cmp_u32_r, swap_custom_r, NULL);
		else
			ref_sort_r(ba, num, 4, cmp_u32_r, swap_custom_r, NULL);
		rust_sort_r(bb, num, 4, (const void *)cmp_u32_r,
			    (const void *)swap_custom_r, NULL, true, eff);
		cmp_sorted(ba, bb, num, 4, eff ? "sort_r() custom swap_r, may_schedule [x86-64]"
					       : "sort_r() custom swap_r, may_schedule [generic]");
	}
	printf("  sort_r callbacks  %lu cases  (custom swap_r and may_schedule, BOTH configurations)\n",
	       checked - before);
}

static void stage_bsearch(unsigned long rounds)
{
	static uint32_t arr[1024];
	unsigned long before = checked;

	for (unsigned long i = 0; i < rounds / 10 + 1; i++) {
		size_t num = rnd() % 64;
		uint32_t key;
		void *ra, *rb;

		for (size_t j = 0; j < num; j++)
			arr[j] = (uint32_t)(rnd() % 128);
		ref_sort(arr, num, 4, cmp_u32, NULL);

		/* Keys that are present and keys that are not, both. */
		key = (rnd() & 1) && num ? arr[rnd() % num] : (uint32_t)(rnd() % 160);

		ra = ref_bsearch(&key, arr, num, 4, cmp_u32);
		rb = rust_bsearch(&key, arr, num, 4, cmp_u32);

		checked++;
		if (ra != rb) {
			fail("bsearch(num=%zu, key=%u): C=%p rust=%p\n", num, key, ra, rb);
			continue;
		}
		/* Independent of the C: a hit must point at a matching
		 * element inside the array, a miss must mean it is absent. */
		checked++;
		if (rb) {
			if ((uint8_t *)rb < (uint8_t *)arr ||
			    (uint8_t *)rb >= (uint8_t *)arr + num * 4 ||
			    *(uint32_t *)rb != key)
				fail("bsearch returned a bad hit\n");
		} else {
			for (size_t j = 0; j < num; j++)
				if (arr[j] == key) {
					fail("bsearch missed a present key %u\n", key);
					break;
				}
		}
	}
	printf("  bsearch           %lu cases  (present and absent keys, hit verified\n"
	       "                              in range and by value)\n",
	       checked - before);
}

/* ---- list_sort -------------------------------------------------------- */

/*
 * Each element carries a key AND the index it was created at, so STABILITY
 * can be checked rather than assumed: equal keys must come out in their
 * original order. A merge sort that lost stability would still be sorted,
 * and a comparison of the two arms alone would still agree if both lost it.
 */
struct lnode {
	struct list_head list;
	uint32_t key;
	uint32_t seq;
};

static unsigned long list_cmp_calls;

static int lcmp(void *priv, const struct list_head *a, const struct list_head *b)
{
	const struct lnode *x = (const struct lnode *)a;
	const struct lnode *y = (const struct lnode *)b;

	(void)priv;
	list_cmp_calls++;
	return (x->key > y->key) - (x->key < y->key);
}

static void build(struct lnode *n, struct list_head *head, size_t num,
		  const uint32_t *keys)
{
	head->next = head;
	head->prev = head;
	for (size_t i = 0; i < num; i++) {
		n[i].key = keys[i];
		n[i].seq = (uint32_t)i;
		n[i].list.prev = head->prev;
		n[i].list.next = head;
		head->prev->next = &n[i].list;
		head->prev = &n[i].list;
	}
}

static void stage_list_sort(unsigned long rounds)
{
	static struct lnode na[1024], nb[1024];
	static uint32_t keys[1024];
	struct list_head ha, hb;
	unsigned long before = checked;

	for (unsigned long i = 0; i < rounds / 20 + 1; i++) {
		size_t num = rnd() % 300;
		/* A narrow key range on purpose: lots of ties, so stability
		 * and the "take a on equal" rule are actually exercised. */
		uint32_t range = 1 + (uint32_t)(rnd() % 8);

		for (size_t j = 0; j < num; j++)
			keys[j] = (uint32_t)(rnd() % range);

		build(na, &ha, num, keys);
		build(nb, &hb, num, keys);

		ref_list_sort(NULL, &ha, lcmp);
		rust_list_sort(NULL, &hb, lcmp);

		/* Same order, element for element, by key AND by seq. */
		checked++;
		{
			struct list_head *pa = ha.next, *pb = hb.next;
			size_t seen = 0;
			bool bad = false;

			while (pa != &ha && pb != &hb) {
				const struct lnode *xa = (const struct lnode *)pa;
				const struct lnode *xb = (const struct lnode *)pb;

				if (xa->key != xb->key || xa->seq != xb->seq) {
					fail("list_sort diverged at position %zu (num=%zu)\n",
					     seen, num);
					bad = true;
					break;
				}
				pa = pa->next;
				pb = pb->next;
				seen++;
			}
			if (!bad && (pa != &ha || pb != &hb))
				fail("list_sort produced lists of different length (num=%zu)\n", num);
		}

		/* Independent of the C: sorted, stable, and still a
		 * well-formed circular doubly-linked list with every element
		 * present exactly once. */
		checked += 3;
		{
			struct list_head *p = hb.next, *prev = &hb;
			size_t seen = 0;
			const struct lnode *last = NULL;

			while (p != &hb && seen <= num) {
				const struct lnode *x = (const struct lnode *)p;

				if (p->prev != prev) {
					fail("list_sort left a broken prev link at %zu\n", seen);
					break;
				}
				if (last && (x->key < last->key ||
					     (x->key == last->key && x->seq < last->seq))) {
					fail("list_sort output is unsorted or unstable at %zu\n",
					     seen);
					break;
				}
				last = x;
				prev = p;
				p = p->next;
				seen++;
			}
			if (seen != num)
				fail("list_sort lost elements: %zu of %zu (num=%zu)\n",
				     seen, num, num);
			else if (hb.prev != prev)
				fail("list_sort did not close the circle\n");
		}
	}

	/* Fixed shapes: empty, one, two, already sorted, reversed, all equal.
	 * The empty and single-element cases return before any merge runs. */
	{
		static const struct { size_t num; const char *what; } shapes[] = {
			{ 0, "empty" }, { 1, "one" }, { 2, "two" }, { 3, "three" },
			{ 64, "already sorted" }, { 64, "reversed" }, { 64, "all equal" },
		};

		for (unsigned si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
			size_t num = shapes[si].num;

			for (size_t j = 0; j < num; j++) {
				if (si == 4)
					keys[j] = (uint32_t)j;
				else if (si == 5)
					keys[j] = (uint32_t)(num - j);
				else if (si == 6)
					keys[j] = 7;
				else
					keys[j] = (uint32_t)(rnd() % 4);
			}
			build(na, &ha, num, keys);
			build(nb, &hb, num, keys);
			ref_list_sort(NULL, &ha, lcmp);
			rust_list_sort(NULL, &hb, lcmp);

			checked++;
			{
				struct list_head *pa = ha.next, *pb = hb.next;

				while (pa != &ha && pb != &hb) {
					if (((const struct lnode *)pa)->seq !=
					    ((const struct lnode *)pb)->seq) {
						fail("list_sort %s: diverged\n", shapes[si].what);
						break;
					}
					pa = pa->next;
					pb = pb->next;
				}
			}
		}
	}
	printf("  list_sort         %lu cases  (ties everywhere; order, stability,\n"
	       "                              prev links and element count all checked)\n",
	       checked - before);
}

/* ---- xxhash ----------------------------------------------------------- */

static void stage_xxhash(unsigned long rounds)
{
	static uint8_t buf[4096] __attribute__((aligned(64)));
	unsigned long before = checked;

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)(i * 251 + 13);

	/* Every length up to 600 at several offsets: 600 covers four full
	 * 32-byte blocks plus every possible tail, and the offsets make the
	 * reads unaligned, which is what get_unaligned_le64 is for. */
	for (size_t off = 0; off < 8; off++)
		for (size_t len = 0; len <= 600; len++) {
			uint32_t s32 = (uint32_t)(len * 2654435761u + off);
			uint64_t s64 = s32 * 0x9e3779b97f4a7c15ULL;

			checked += 2;
			if (ref_xxh32(buf + off, len, s32) != rust_xxh32(buf + off, len, s32))
				fail("xxh32(off=%zu len=%zu) differs\n", off, len);
			if (ref_xxh64(buf + off, len, s64) != rust_xxh64(buf + off, len, s64))
				fail("xxh64(off=%zu len=%zu) differs\n", off, len);
		}
	printf("  xxh32/64 lengths  %lu cases  (every length 0..600 at 8 offsets)\n",
	       checked - before);

	/* A zero length with a NULL pointer: the C accepts it, and it is the
	 * case that made the Rust use a slice rather than pointer walking. */
	before = checked;
	checked += 2;
	if (ref_xxh32(NULL, 0, 0) != rust_xxh32(NULL, 0, 0))
		fail("xxh32(NULL, 0) differs\n");
	if (ref_xxh64(NULL, 0, 0) != rust_xxh64(NULL, 0, 0))
		fail("xxh64(NULL, 0) differs\n");

	/* The streaming API, fed in RANDOM CHUNKS, which is the whole point:
	 * a digest must not depend on how the input was split. Every chunk
	 * boundary exercises the mem64 carry-over path that one-shot xxh64
	 * never touches. */
	for (unsigned long i = 0; i < rounds / 20 + 1; i++) {
		struct xxh64_state sa, sb;
		size_t total = rnd() % 1000;
		size_t pos = 0;
		uint64_t seed = rnd();
		uint64_t da, db;

		ref_xxh64_reset(&sa, seed);
		rust_xxh64_reset(&sb, seed);

		checked++;
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("xxh64_reset produced different state\n");

		while (pos < total) {
			size_t chunk = 1 + (rnd() % 70);

			if (pos + chunk > total)
				chunk = total - pos;
			ref_xxh64_update(&sa, buf + pos, chunk);
			rust_xxh64_update(&sb, buf + pos, chunk);
			pos += chunk;

			checked++;
			if (memcmp(&sa, &sb, sizeof(sa))) {
				fail("xxh64_update diverged at %zu of %zu\n", pos, total);
				break;
			}
		}

		da = ref_xxh64_digest(&sa);
		db = rust_xxh64_digest(&sb);
		checked++;
		if (da != db)
			fail("xxh64_digest differs (total=%zu)\n", total);

		/* Independent of the C: streaming a buffer in pieces must
		 * equal hashing it in one go. Neither arm is consulted. */
		checked++;
		if (db != rust_xxh64(buf, total, seed))
			fail("streamed xxh64 != one-shot xxh64 (total=%zu)\n", total);
	}
	printf("  xxh64 streaming   %lu cases  (random chunk splits; state compared after\n"
	       "                              every update, and streamed == one-shot)\n",
	       checked - before);

	/* NULL input must be rejected, and the state must be untouched. */
	before = checked;
	{
		struct xxh64_state sa, sb;

		ref_xxh64_reset(&sa, 1);
		rust_xxh64_reset(&sb, 1);
		checked += 2;
		if (ref_xxh64_update(&sa, NULL, 10) != rust_xxh64_update(&sb, NULL, 10))
			fail("xxh64_update(NULL) return differs\n");
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("xxh64_update(NULL) touched the state differently\n");
	}

	/* reset and copy_state, which are the two trivial ones and therefore
	 * the two nobody would notice were broken. */
	{
		struct xxh32_state a32, b32, c32, d32;
		struct xxh64_state a64, b64, c64, d64;

		for (uint32_t seed = 0; seed < 64; seed++) {
			ref_xxh32_reset(&a32, seed * 2654435761u);
			rust_xxh32_reset(&b32, seed * 2654435761u);
			checked++;
			if (memcmp(&a32, &b32, sizeof(a32)))
				fail("xxh32_reset(%u) differs\n", seed);

			ref_xxh64_reset(&a64, seed);
			rust_xxh64_reset(&b64, seed);
			checked++;
			if (memcmp(&a64, &b64, sizeof(a64)))
				fail("xxh64_reset(%u) differs\n", seed);

			memset(&c32, 0xa5, sizeof(c32));
			memset(&d32, 0x5a, sizeof(d32));
			ref_xxh32_copy_state(&c32, &a32);
			rust_xxh32_copy_state(&d32, &a32);
			checked++;
			if (memcmp(&c32, &d32, sizeof(c32)))
				fail("xxh32_copy_state differs\n");

			memset(&c64, 0xa5, sizeof(c64));
			memset(&d64, 0x5a, sizeof(d64));
			ref_xxh64_copy_state(&c64, &a64);
			rust_xxh64_copy_state(&d64, &a64);
			checked++;
			if (memcmp(&c64, &d64, sizeof(c64)))
				fail("xxh64_copy_state differs\n");
		}
	}
	printf("  xxh reset/copy    %lu cases  (NULL rejection, reset and copy_state)\n",
	       checked - before);
}

/* ---- earlycpio -------------------------------------------------------- */

/*
 * Build a newc cpio archive by hand. The parser is the thing under test, so
 * the archive builder must not share any code with it -- this writes the
 * eight-character hex fields directly.
 */
static size_t cpio_add(uint8_t *out, size_t off, const char *name,
		       const void *body, size_t bodylen, unsigned mode)
{
	size_t namesize = strlen(name) + 1;
	static const char hex[] = "0123456789ABCDEF";
	unsigned fields[14];
	size_t i, j;

	memset(fields, 0, sizeof(fields));
	fields[0] = 0x070701;		/* C_MAGIC */
	fields[2] = mode;		/* C_MODE */
	fields[7] = (unsigned)bodylen;	/* C_FILESIZE */
	fields[12] = (unsigned)namesize;/* C_NAMESIZE */

	/* magic is six characters, the other thirteen fields are eight */
	for (i = 0; i < 14; i++) {
		size_t w = i ? 8 : 6;

		for (j = 0; j < w; j++)
			out[off + j] = hex[(fields[i] >> (4 * (w - 1 - j))) & 0xf];
		off += w;
	}
	memcpy(out + off, name, namesize);
	off += namesize;
	off = (off + 3) & ~(size_t)3;
	memcpy(out + off, body, bodylen);
	off += bodylen;
	off = (off + 3) & ~(size_t)3;
	return off;
}

static void cmp_cpio(const char *path, uint8_t *arc, size_t len, const char *what)
{
	struct cpio_data a, b;
	long oa = -12345, ob = -12345;

	a = ref_find_cpio_data(path, arc, len, &oa);
	b = find_cpio_data(path, arc, len, &ob);

	checked += 2;
	if (a.data != b.data || a.size != b.size ||
	    memcmp(a.name, b.name, MAX_CPIO_FILE_NAME))
		fail("find_cpio_data(%s) [%s]: data %p/%p size %zu/%zu name \"%.18s\"/\"%.18s\"\n",
		     path, what, a.data, b.data, a.size, b.size, a.name, b.name);
	if (oa != ob)
		fail("find_cpio_data(%s) [%s]: nextoff %ld vs %ld\n", path, what, oa, ob);
}

static void stage_earlycpio(unsigned long rounds)
{
	static uint8_t arc[8192];
	static uint8_t body[512];
	unsigned long before = checked;
	size_t end;

	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(i * 7 + 1);

	/* A well-formed archive with several members, one of which has a name
	 * longer than MAX_CPIO_FILE_NAME so the truncation path is hit. */
	memset(arc, 0, sizeof(arc));
	end = 0;
	end = cpio_add(arc, end, "kernel/x86/microcode/GenuineIntel.bin", body, 100, 0100644);
	end = cpio_add(arc, end, "kernel/x86/microcode/AuthenticAMD.bin", body, 33, 0100644);
	end = cpio_add(arc, end, "adir/", body, 0, 0040755);
	end = cpio_add(arc, end, "short", body, 7, 0100644);
	end = cpio_add(arc, end, "TRAILER!!!", body, 0, 0100644);

	cmp_cpio("kernel/x86/microcode/GenuineIntel.bin", arc, end, "exact");
	cmp_cpio("kernel/x86/microcode/", arc, end, "directory prefix");
	cmp_cpio("kernel/x86/microcode/AuthenticAMD.bin", arc, end, "second member");
	cmp_cpio("short", arc, end, "short name");
	cmp_cpio("adir/", arc, end, "a directory, which must NOT match");
	cmp_cpio("nope", arc, end, "absent");
	cmp_cpio("", arc, end, "empty path");

	/* Every truncation of the archive: a parser that walks off the end of
	 * a short buffer is the failure this function's overrun checks exist
	 * to prevent, and the two arms must agree about where they give up. */
	for (size_t n = 0; n <= end; n++)
		cmp_cpio("kernel/x86/microcode/", arc, n, "truncated");

	/* Leading NUL padding, which the C skips four bytes at a time. */
	memset(arc, 0, sizeof(arc));
	end = cpio_add(arc, 8, "pad/file", body, 20, 0100644);
	cmp_cpio("pad/", arc, end, "leading padding");
	printf("  earlycpio shapes  %lu cases  (members, prefixes, every truncation,\n"
	       "                              padding)\n", checked - before);

	/* Corrupted archives. Every single-byte corruption of a valid one:
	 * bad magic, bad hex, absurd sizes. Both arms must reject or accept
	 * identically, and neither may read outside the buffer -- which is
	 * what the guard page below is for. */
	before = checked;
	for (unsigned long i = 0; i < rounds / 10 + 1; i++) {
		memset(arc, 0, sizeof(arc));
		end = 0;
		end = cpio_add(arc, end, "kernel/x86/microcode/GenuineIntel.bin", body, 100, 0100644);
		end = cpio_add(arc, end, "second/file", body, 40, 0100644);

		for (int k = 0; k < 3; k++)
			arc[rnd() % end] = (uint8_t)rnd();

		cmp_cpio("kernel/x86/microcode/", arc, end, "corrupted");
		cmp_cpio("second/", arc, end, "corrupted");
	}
	printf("  earlycpio corrupt %lu cases  (random byte corruption of valid archives)\n",
	       checked - before);
}

/* ---- plist ------------------------------------------------------------ */

#define PL_N 24

struct plset {
	struct plist_head head;
	struct plist_node n[PL_N];
	bool linked[PL_N];
};

static void pl_init(struct plset *p)
{
	p->head.node_list.next = &p->head.node_list;
	p->head.node_list.prev = &p->head.node_list;
	for (int i = 0; i < PL_N; i++) {
		p->n[i].prio = 0;
		p->n[i].prio_list.next = p->n[i].prio_list.prev = &p->n[i].prio_list;
		p->n[i].node_list.next = p->n[i].node_list.prev = &p->n[i].node_list;
		p->linked[i] = false;
	}
}

/* Walk node_list and record the node indices in order, plus whether each is
 * on prio_list. Comparing THAT rather than the return values is the point:
 * plist's whole correctness is which nodes head a priority bucket, and every
 * one of these functions returns void. */
static size_t pl_snapshot(struct plset *p, int *order, bool *onprio)
{
	struct list_head *l = p->head.node_list.next;
	size_t k = 0;

	while (l != &p->head.node_list && k < PL_N + 4) {
		struct plist_node *nd = (struct plist_node *)
			((char *)l - offsetof(struct plist_node, node_list));
		int idx = (int)(nd - p->n);

		order[k] = idx;
		onprio[k] = nd->prio_list.next != &nd->prio_list;
		k++;
		l = l->next;
	}
	return k;
}

static void stage_plist(unsigned long rounds)
{
	static struct plset a, b;
	unsigned long before = checked;
	int oa[PL_N + 4], ob[PL_N + 4];
	bool pa[PL_N + 4], pb[PL_N + 4];

	for (unsigned long round = 0; round < rounds / 20 + 1; round++) {
		/* A narrow priority range so ties -- the whole reason
		 * prio_list exists -- happen constantly. */
		int range = 1 + (int)(rnd() % 5);

		bool saw_requeue = false;

		pl_init(&a);
		pl_init(&b);

		for (int op = 0; op < 120; op++) {
			int i = (int)(rnd() % PL_N);
			bool requeued = false;
			int what = (int)(rnd() % 3);
			size_t ka, kb;

			if (what == 0 && !a.linked[i]) {
				int prio = (int)(rnd() % range);

				a.n[i].prio = prio;
				b.n[i].prio = prio;
				ref_plist_add(&a.n[i], &a.head);
				rust_plist_add(&b.n[i], &b.head);
				a.linked[i] = b.linked[i] = true;
			} else if (what == 1 && a.linked[i]) {
				ref_plist_del(&a.n[i], &a.head);
				rust_plist_del(&b.n[i], &b.head);
				a.linked[i] = b.linked[i] = false;
			} else if (what == 2 && a.linked[i]) {
				ref_plist_requeue(&a.n[i], &a.head);
				rust_plist_requeue(&b.n[i], &b.head);
				requeued = true;
				saw_requeue = true;
			} else {
				continue;
			}

			ka = pl_snapshot(&a, oa, pa);
			kb = pl_snapshot(&b, ob, pb);

			checked++;
			if (ka != kb || memcmp(oa, ob, ka * sizeof(oa[0])) ||
			    memcmp(pa, pb, ka * sizeof(pa[0]))) {
				fail("plist diverged after op %d (round %lu)\n", op, round);
				return;
			}

			/* The two arms must always agree. The INVARIANTS
			 * below are only asserted when no requeue has run
			 * on this list, because plist_requeue() in 6.18.49
			 * can genuinely leave the list unsorted -- see
			 * stage_plist_requeue_bug(). Skipping them there is
			 * not papering over a port defect: both arms
			 * produce the same wrong answer, which is the
			 * behaviour callers have today.
			 *
			 * Independent of the C: two invariants, neither of
			 * which any return value could reveal, because all
			 * three functions return void.
			 *
			 *  1. node_list is in non-increasing priority order.
			 *  2. the prio_list RING, walked from the first
			 *     node, visits exactly the first node of each
			 *     distinct priority run -- in order.
			 *
			 * The second is what plist exists for, and it is
			 * easy to state wrongly: a lone node heading the
			 * ring is SELF-LINKED, so list_empty() is true of
			 * it. Checking "is this node on prio_list" per node
			 * therefore reports the first node as off. The
			 * first version of this check did exactly that and
			 * failed on a one-element list while both arms
			 * agreed perfectly. Walk the ring instead. */
			if (requeued || saw_requeue)
				continue;
			checked += 2;
			{
				int want[PL_N + 4];
				size_t nwant = 0, nring = 0;
				struct list_head *r, *ring0;
				bool bad = false;

				for (size_t k = 0; k < kb; k++) {
					struct plist_node *nd = &b.n[ob[k]];

					if (k && b.n[ob[k - 1]].prio > nd->prio) {
						fail("plist out of priority order at %zu\n", k);
						return;
					}
					if (k == 0 || b.n[ob[k - 1]].prio != nd->prio)
						want[nwant++] = ob[k];
				}

				if (kb) {
					ring0 = &b.n[ob[0]].prio_list;
					r = ring0;
					do {
						struct plist_node *nd = (struct plist_node *)
							((char *)r - offsetof(struct plist_node,
									      prio_list));

						if (nring >= nwant ||
						    (int)(nd - b.n) != want[nring]) {
							bad = true;
							break;
						}
						nring++;
						r = r->next;
					} while (r != ring0 && nring <= PL_N + 2);
				}

				if (bad || nring != nwant) {
					fail("plist prio_list ring has %zu buckets, expected %zu\n",
					     nring, nwant);
					return;
				}
			}
		}
	}
	printf("  plist             %lu cases  (add/del/requeue with constant ties;\n"
	       "                              order AND prio_list bucket membership)\n",
	       checked - before);
}

/*
 * A BUG IN lib/plist.c, 6.18.49 -- pinned here so the port is not "fixed"
 * into disagreeing with the kernel it has to match.
 *
 * plist_requeue() is meant to move a node to the end of its own priority
 * run. When the node heads the LAST priority bucket, it instead lands at the
 * head of the whole list, leaving the plist unsorted:
 *
 *     [A(p0) B(p1) C(p1)]  requeue(B)  ->  [B(p1) A(p0) C(p1)]
 *
 * The mechanism: prio_list is a HEADLESS circular ring of bucket-leading
 * nodes. plist_requeue() takes a shortcut --
 *
 *     if (!list_empty(&iter->prio_list)) {
 *             iter = list_entry(iter->prio_list.next, ...);
 *             node_next = &iter->node_list;
 *             goto queue;
 *     }
 *
 * -- and from the last bucket, `prio_list.next` wraps to the FIRST bucket,
 * so node_next points at the head of the list rather than at the end. The
 * plist_for_each_continue() fallback below it computes the right answer
 * (&head->node_list); the shortcut is what is wrong.
 *
 * With any bucket after it, requeue is correct.
 *
 * NOT FIXED IN THE PORT. GOALS.md §5's first question is "can anything
 * outside observe the difference", and the answer is yes: the list order
 * changes. Callers -- mm/swapfile.c is the only one in tree -- get this
 * behaviour today. Recorded rather than corrected, and flagged in STATUS.md
 * as something to take upstream.
 */
static void stage_plist_requeue_bug(void)
{
	struct plset a, b;
	int oa[PL_N + 4], ob[PL_N + 4];
	bool pa[PL_N + 4], pb[PL_N + 4];
	size_t ka, kb;
	unsigned long before = checked;

	pl_init(&a);
	pl_init(&b);
	for (int i = 0; i < 3; i++) {
		a.n[i].prio = b.n[i].prio = i ? 1 : 0;
		ref_plist_add(&a.n[i], &a.head);
		rust_plist_add(&b.n[i], &b.head);
	}

	ref_plist_requeue(&a.n[1], &a.head);
	rust_plist_requeue(&b.n[1], &b.head);

	ka = pl_snapshot(&a, oa, pa);
	kb = pl_snapshot(&b, ob, pb);

	checked += 2;
	if (ka != 3 || kb != 3 || memcmp(oa, ob, 3 * sizeof(oa[0])))
		fail("plist_requeue last-bucket: arms disagree\n");
	/* The buggy order, asserted on purpose. If this ever starts failing,
	 * the kernel was fixed and the port must follow -- it is not a
	 * regression in the Rust. */
	if (!(ob[0] == 1 && ob[1] == 0 && ob[2] == 2))
		fail("plist_requeue last-bucket: expected the known-buggy order"
		     " [1 0 2], got [%d %d %d] -- check whether upstream fixed it\n",
		     ob[0], ob[1], ob[2]);

	printf("  plist requeue bug %lu cases  (the 6.18.49 last-bucket bug, pinned)\n",
	       checked - before);
}

/* ---- arc4, crc-ccitt, clz_ctz ----------------------------------------- */

static void stage_arc4(unsigned long rounds)
{
	static uint8_t pt[4096], ca[4096], cb[4096], key[256];
	struct arc4_ctx sa, sb;
	unsigned long before = checked;

	/* RFC 6229's first ARC4 test vector, from outside this tree: a
	 * 40-bit key of 01 02 03 04 05 gives this keystream at offset 0. */
	{
		static const uint8_t k[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
		static const uint8_t want[16] = {
			0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
			0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
		};
		uint8_t zeros[16] = { 0 }, ks[16];

		rust_arc4_setkey(&sb, k, 5);
		rust_arc4_crypt(&sb, ks, zeros, 16);
		checked++;
		if (memcmp(ks, want, 16))
			fail("arc4 does not match the RFC 6229 test vector\n");
	}

	for (unsigned long i = 0; i < rounds / 20 + 1; i++) {
		unsigned int klen = 1 + (unsigned int)(rnd() % 64);
		unsigned int len = (unsigned int)(rnd() % 1024);

		for (unsigned int j = 0; j < klen; j++)
			key[j] = (uint8_t)rnd();
		for (unsigned int j = 0; j < len; j++)
			pt[j] = (uint8_t)rnd();

		ref_arc4_setkey(&sa, key, klen);
		rust_arc4_setkey(&sb, key, klen);
		checked++;
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("arc4_setkey(klen=%u) produced different state\n", klen);

		/* Encrypt in one go... */
		ref_arc4_crypt(&sa, ca, pt, len);
		rust_arc4_crypt(&sb, cb, pt, len);
		checked += 2;
		if (memcmp(ca, cb, len))
			fail("arc4_crypt(len=%u) differs\n", len);
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("arc4_crypt(len=%u) left different state\n", len);

		/* ...and in random chunks, which must give the same
		 * ciphertext: the state carries across calls. */
		ref_arc4_setkey(&sa, key, klen);
		rust_arc4_setkey(&sb, key, klen);
		{
			unsigned int pos = 0;

			while (pos < len) {
				unsigned int chunk = 1 + (unsigned int)(rnd() % 100);

				if (pos + chunk > len)
					chunk = len - pos;
				ref_arc4_crypt(&sa, ca + pos, pt + pos, chunk);
				rust_arc4_crypt(&sb, cb + pos, pt + pos, chunk);
				pos += chunk;
			}
		}
		checked += 2;
		if (memcmp(ca, cb, len))
			fail("arc4_crypt chunked (len=%u) differs\n", len);
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("arc4_crypt chunked left different state\n");

		/* Independent of the C: decrypting must give the plaintext
		 * back, and IN PLACE, which is how callers use it. */
		rust_arc4_setkey(&sb, key, klen);
		rust_arc4_crypt(&sb, cb, cb, len);
		checked++;
		if (memcmp(cb, pt, len))
			fail("arc4 in-place round trip failed (len=%u)\n", len);
	}
	printf("  arc4              %lu cases  (RFC 6229 vector, chunked == one-shot,\n"
	       "                              in-place round trip)\n", checked - before);
}

/* The CRC-CCITT table lives in the C and is EXPORT_SYMBOL, so the Rust is
 * handed a pointer to it. Here the oracle's copy is what both arms use. */
extern const uint16_t crc_ccitt_table[256];

static void stage_crc_ccitt(unsigned long rounds)
{
	static uint8_t buf[2048];
	unsigned long before = checked;

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)(i * 131 + 17);

	/* The kernel's crc_ccitt is the REFLECTED variant, poly 0x8408. With
	 * a zero seed that is CRC-16/KERMIT, whose published check value for
	 * "123456789" is 0x2189 -- a number from the catalogue of
	 * parametrised CRCs, outside this tree, so a table that was wrong in
	 * both arms could not agree with it.
	 *
	 * The first version of this vector used 0x29B1, which is
	 * CRC-16/CCITT-FALSE: same name, different polynomial direction. The
	 * check failed and the port was right. Sixth time. */
	checked++;
	if (rust_crc_ccitt(0, (const uint8_t *)"123456789", 9, crc_ccitt_table) != 0x2189)
		fail("crc_ccitt(0, \"123456789\") != 0x2189 (CRC-16/KERMIT)\n");

	for (size_t len = 0; len <= sizeof(buf); len++) {
		checked++;
		if (ref_crc_ccitt(0xffff, buf, len) !=
		    rust_crc_ccitt(0xffff, buf, len, crc_ccitt_table))
			fail("crc_ccitt(len=%zu) differs\n", len);
	}
	for (unsigned long i = 0; i < rounds; i++) {
		size_t len = rnd() % sizeof(buf);
		uint16_t seed = (uint16_t)rnd();

		buf[rnd() % sizeof(buf)] = (uint8_t)rnd();
		checked++;
		if (ref_crc_ccitt(seed, buf, len) !=
		    rust_crc_ccitt(seed, buf, len, crc_ccitt_table))
			fail("crc_ccitt(seed=%04x len=%zu) differs\n", seed, len);
	}
	printf("  crc-ccitt         %lu cases  (catalogue check value, every length, fuzz)\n",
	       checked - before);
}

/*
 * clz_ctz has no compiled oracle: its C bodies are one line each over __ffs
 * and fls, which are arch inlines with no userspace equivalent to compile
 * against. The reference here is the definition itself -- __builtin_ctz and
 * __builtin_clz -- which is a better oracle than the kernel's wrapper anyway.
 */
static void stage_clz_ctz(void)
{
	unsigned long before = checked;

	for (int k = 0; k < 32; k++) {
		uint32_t v = 1u << k;

		for (uint32_t d = 0; d < 3; d++) {
			uint32_t x = v + d - 1;

			if (!x)
				continue;
			checked += 2;
			if (rust_ctzsi2((int)x) != __builtin_ctz(x))
				fail("__ctzsi2(%u) wrong\n", x);
			if (rust_clzsi2((int)x) != __builtin_clz(x))
				fail("__clzsi2(%u) wrong\n", x);
		}
	}
	for (int k = 0; k < 64; k++) {
		uint64_t v = 1ull << k;

		for (uint64_t d = 0; d < 3; d++) {
			uint64_t x = v + d - 1;

			if (!x)
				continue;
			checked += 2;
			if (rust_ctzdi2(x) != __builtin_ctzll(x))
				fail("__ctzdi2(%llu) wrong\n", (unsigned long long)x);
			if (rust_clzdi2(x) != __builtin_clzll(x))
				fail("__clzdi2(%llu) wrong\n", (unsigned long long)x);
		}
	}

	/* The documented divergence: the C is undefined at zero (__ffs on
	 * x86 is bsf, which leaves its destination unchanged); the Rust
	 * returns the width. Asserted so the divergence is pinned rather
	 * than merely written down. */
	checked += 4;
	if (rust_ctzsi2(0) != 32)
		fail("__ctzsi2(0) should be 32 in the Rust\n");
	if (rust_ctzdi2(0) != 64)
		fail("__ctzdi2(0) should be 64 in the Rust\n");
	if (rust_clzsi2(0) != 32)
		fail("__clzsi2(0) should be 32\n");
	if (rust_clzdi2(0) != 64)
		fail("__clzdi2(0) should be 64\n");

	printf("  clz_ctz           %lu cases  (against __builtin_ctz/clz, not the C wrapper)\n",
	       checked - before);
}

/* ---- chacha ----------------------------------------------------------- */

static void stage_chacha(unsigned long rounds)
{
	unsigned long before = checked;
	struct chacha_state sa, sb;
	uint8_t oa[64], ob[64];
	uint32_t ha[8], hb[8];

	/* RFC 8439 §2.3.2, the worked ChaCha20 block example. The state is
	 * the standard constants, key 00..1f, counter 1, nonce 09 00 00 00
	 * 4a 00 00 00 00 00 00 00 -- and the first output word is 0xe4e7f110.
	 * Published outside this tree, so a permutation wrong in both arms
	 * could not agree with it. */
	{
		static const uint32_t init[16] = {
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
			0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
			0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
			0x00000001, 0x09000000, 0x4a000000, 0x00000000
		};
		uint32_t w0;

		memcpy(sb.x, init, sizeof(init));
		rust_chacha_block_generic(&sb, ob, 20);
		/* ob[] is a BYTE STREAM and chacha serialises its words
		 * little-endian, so the word must be reassembled from the
		 * bytes. A memcpy() into a uint32_t here read it in NATIVE
		 * order, which is the same thing only on a little-endian host:
		 * measured on s390x 2026-09-04 it gave 0x10f1e7e4, the correct
		 * bytes 10 f1 e7 e4 read backwards, and failed a vector the
		 * port had in fact matched. The port was right; this line was
		 * the last little-endian assumption left in this driver. */
		w0 = (uint32_t)ob[0] | ((uint32_t)ob[1] << 8) |
		     ((uint32_t)ob[2] << 16) | ((uint32_t)ob[3] << 24);
		checked++;
		if (w0 != 0xe4e7f110u)
			fail("chacha20 RFC 8439 block: first word 0x%08x, expected 0xe4e7f110\n", w0);
		checked++;
		if (sb.x[12] != 2)
			fail("chacha_block_generic did not increment the counter\n");
	}

	for (unsigned long i = 0; i < rounds / 4 + 1; i++) {
		int nr = (rnd() & 1) ? 20 : 12;

		for (int j = 0; j < 16; j++)
			sa.x[j] = sb.x[j] = (uint32_t)rnd();

		ref_chacha_block_generic(&sa, oa, nr);
		rust_chacha_block_generic(&sb, ob, nr);
		checked += 2;
		if (memcmp(oa, ob, 64))
			fail("chacha_block_generic(nrounds=%d) differs\n", nr);
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("chacha_block_generic(nrounds=%d) left different state\n", nr);

		for (int j = 0; j < 16; j++)
			sa.x[j] = sb.x[j] = (uint32_t)rnd();
		ref_hchacha_block_generic(&sa, ha, nr);
		rust_hchacha_block_generic(&sb, hb, nr);
		checked += 2;
		if (memcmp(ha, hb, sizeof(ha)))
			fail("hchacha_block_generic(nrounds=%d) differs\n", nr);
		if (memcmp(&sa, &sb, sizeof(sa)))
			fail("hchacha_block_generic touched the input state\n");
	}
	printf("  chacha            %lu cases  (RFC 8439 block, 12 and 20 rounds,\n"
	       "                              block and hchacha, state compared too)\n",
	       checked - before);
}

/* ---- __crypto_xor ------------------------------------------------------ */

static void stage_crypto_xor(unsigned long rounds)
{
	static uint8_t a[1024], b[1024], da[1024], db[1024] __attribute__((aligned(64)));
	unsigned long before = checked;

	for (size_t i = 0; i < sizeof(a); i++) {
		a[i] = (uint8_t)(i * 61 + 3);
		b[i] = (uint8_t)(i * 17 + 200);
	}

	/* Every length and every relative offset of the three pointers: the
	 * chunk width the function picks depends entirely on how they line
	 * up, so this is the whole of its behaviour. Both flags are passed
	 * as the x86-64 values, matching what the oracle was compiled with;
	 * the arch-dependent path is exercised separately below. */
	for (size_t od = 0; od < 8; od++)
		for (size_t o1 = 0; o1 < 8; o1++)
			for (size_t len = 0; len <= 40; len++) {
				memset(da, 0xa5, sizeof(da));
				memset(db, 0x5a, sizeof(db));
				ref_crypto_xor(da + od, a + o1, b, (unsigned)len);
				rust_crypto_xor(db + od, a + o1, b, (unsigned)len, true, true);
				checked += 2;
				if (memcmp(da + od, db + od, len))
					fail("__crypto_xor(od=%zu o1=%zu len=%zu) differs\n",
					     od, o1, len);
				if (da[od + len] != 0xa5 || db[od + len] != 0x5a)
					fail("__crypto_xor wrote past len\n");
			}
	printf("  crypto_xor shapes %lu cases  (8 dst offsets x 8 src offsets x lengths 0..40)\n",
	       checked - before);

	/* The relalign path, which x86-64 never takes. Passing
	 * efficient_unaligned=false makes the Rust run the byte-wise
	 * alignment walk and the narrowed chunk widths -- the code that
	 * would otherwise be ported and never executed anywhere. Checked
	 * against the same answers, because the RESULT must not depend on
	 * the chunk width. */
	before = checked;
	for (unsigned long i = 0; i < rounds / 4 + 1; i++) {
		size_t od = rnd() % 16, o1 = rnd() % 16, o2 = rnd() % 16;
		size_t len = rnd() % 300;

		memset(da, 0, sizeof(da));
		memset(db, 0, sizeof(db));
		rust_crypto_xor(da + od, a + o1, b + o2, (unsigned)len, true, true);
		rust_crypto_xor(db + od, a + o1, b + o2, (unsigned)len, false, true);
		checked++;
		if (memcmp(da + od, db + od, len))
			fail("__crypto_xor: the relalign path disagrees with the fast one"
			     " (od=%zu o1=%zu o2=%zu len=%zu)\n", od, o1, o2, len);

		/* And 32-bit, which drops the 8-byte chunks. */
		memset(db, 0, sizeof(db));
		rust_crypto_xor(db + od, a + o1, b + o2, (unsigned)len, true, false);
		checked++;
		if (memcmp(da + od, db + od, len))
			fail("__crypto_xor: the 32-bit path disagrees\n");
	}
	printf("  crypto_xor arches %lu cases  (the relalign and 32-bit paths x86-64\n"
	       "                              never takes, checked against the fast one)\n",
	       checked - before);

	/* In place, which is how callers use it. Independent of the C. */
	before = checked;
	for (unsigned long i = 0; i < rounds / 20 + 1; i++) {
		size_t len = rnd() % 256;

		memcpy(da, a, len);
		rust_crypto_xor(da, da, b, (unsigned)len, true, true);
		rust_crypto_xor(da, da, b, (unsigned)len, true, true);
		checked++;
		if (memcmp(da, a, len))
			fail("__crypto_xor in place does not round-trip (len=%zu)\n", len);
	}
	printf("  crypto_xor place  %lu cases  (in-place double XOR round trip)\n",
	       checked - before);
}

/* ---- check_signature --------------------------------------------------- */

static void stage_check_signature(unsigned long rounds)
{
	/* The two buffers stand in for the MMIO window and the signature
	 * block. Both oracle and port read them through a plain load here;
	 * see shim/linux/io.h. */
	static unsigned char win[256], sig[256];
	unsigned long before = checked;

	/* Exhaustive over the shape that matters: for every length up to 64
	 * and every position within it, a window that matches the signature
	 * everywhere EXCEPT at that position. That walks the mismatch through
	 * every index, which is what an off-by-one in the loop breaks, and it
	 * is the case a "compare the whole block" rewrite would get wrong. */
	for (unsigned len = 0; len <= 64; len++) {
		for (unsigned i = 0; i < sizeof(sig); i++)
			sig[i] = win[i] = (unsigned char)(i * 37 + 11);

		checked++;
		if (ref_check_signature(win, sig, (int)len) !=
		    rust_check_signature(win, sig, (int)len))
			fail("check_signature(len=%u) all-match differs\n", len);

		for (unsigned pos = 0; pos < len; pos++) {
			unsigned char save = win[pos];

			win[pos] = (unsigned char)(save ^ 0xff);
			checked++;
			if (ref_check_signature(win, sig, (int)len) !=
			    rust_check_signature(win, sig, (int)len))
				fail("check_signature(len=%u, mismatch at %u) differs\n",
				     len, pos);
			win[pos] = save;
		}
	}

	/* Then fuzz, with the window and signature drawn so that short
	 * matching prefixes are common -- a uniform random pair mismatches at
	 * byte 0 almost always and never exercises the loop. */
	for (unsigned long r = 0; r < rounds; r++) {
		unsigned len = rnd() % (unsigned)sizeof(sig);
		unsigned prefix = len ? rnd() % (len + 1) : 0;

		for (unsigned i = 0; i < sizeof(sig); i++) {
			sig[i] = (unsigned char)rnd();
			win[i] = i < prefix ? sig[i] : (unsigned char)rnd();
		}

		checked++;
		if (ref_check_signature(win, sig, (int)len) !=
		    rust_check_signature(win, sig, (int)len))
			fail("check_signature(len=%u, prefix=%u) differs\n", len, prefix);

		/* Offset starts too: the C walks io_addr forward, so a body
		 * that indexed from the base rather than the given pointer
		 * would still pass everything above. */
		if (len && prefix) {
			unsigned off = rnd() % (sizeof(sig) - len);

			checked++;
			if (ref_check_signature(win + off, sig + off, (int)len) !=
			    rust_check_signature(win + off, sig + off, (int)len))
				fail("check_signature(off=%u, len=%u) differs\n", off, len);
		}
	}
	printf("  check_signature   %lu cases  (every mismatch position to len 64, fuzz, offset starts)\n",
	       checked - before);

	/* NOT compared against the oracle, because this is the one place the
	 * port deliberately differs. The C's `while (length--)` on a negative
	 * length reads some two billion bytes off the end of the window; the
	 * Rust returns 1, the same as the empty signature. Asserted rather
	 * than diffed. See lib/check_signature_rs.rs. */
	if (rust_check_signature(win, sig, -1) != 1 ||
	    rust_check_signature(win, sig, -1000000) != 1)
		fail("check_signature(negative length) should be the documented 1\n");
	printf("  check_signature   negative length returns 1 (documented divergence, not diffed)\n");
}

/* ---- ucs2_string ------------------------------------------------------- */

static void stage_ucs2(unsigned long rounds)
{
	static ucs2_char_t a[128], b[128];
	static uint8_t ua[512], ub[512];
	static ucs2_char_t da[128], db[128];
	unsigned long before = checked;

	for (unsigned long i = 0; i < rounds / 4 + 1; i++) {
		size_t n = rnd() % 40;
		size_t maxlen = rnd() % 48;

		/* A mix of ASCII, two-byte and three-byte code points, so
		 * every branch of the UTF-8 encoder runs, plus the odd
		 * embedded NUL. */
		for (size_t j = 0; j < 64; j++) {
			uint32_t r = (uint32_t)rnd();

			switch (r % 4) {
			case 0: a[j] = (ucs2_char_t)(r % 0x80); break;
			case 1: a[j] = (ucs2_char_t)(0x80 + r % (0x800 - 0x80)); break;
			case 2: a[j] = (ucs2_char_t)(0x800 + r % (0x10000 - 0x800)); break;
			default: a[j] = (ucs2_char_t)(r % 4 == 3 && (r >> 8) % 8 == 0 ? 0
						      : (r % 0x10000)); break;
			}
		}
		a[n] = 0;
		memcpy(b, a, sizeof(a));

		checked += 4;
		if (ref_ucs2_strnlen(a, maxlen) != rust_ucs2_strnlen(a, maxlen))
			fail("ucs2_strnlen(maxlen=%zu) differs\n", maxlen);
		if (ref_ucs2_strlen(a) != rust_ucs2_strlen(a))
			fail("ucs2_strlen differs\n");
		if (ref_ucs2_strsize(a, maxlen) != rust_ucs2_strsize(a, maxlen))
			fail("ucs2_strsize(maxlen=%zu) differs\n", maxlen);
		if (ref_ucs2_utf8size(a) != rust_ucs2_utf8size(a))
			fail("ucs2_utf8size differs\n");

		/* strscpy at every count, including the truncating ones. */
		for (size_t count = 1; count <= 48; count++) {
			ssize_t ra, rb;

			memset(da, 0xa5, sizeof(da));
			memset(db, 0x5a, sizeof(db));
			ra = ref_ucs2_strscpy(da, a, count);
			rb = rust_ucs2_strscpy(db, a, count);
			checked += 2;
			if (ra != rb)
				fail("ucs2_strscpy(count=%zu): %zd vs %zd\n", count, ra, rb);
			else {
				/* Only the bytes it actually WROTE may be
				 * compared. On success it stops at the NUL
				 * and leaves the rest of the buffer alone --
				 * comparing all `count` elements compares
				 * two different poison patterns, which is
				 * what the first version of this check did. */
				size_t wrote = ra >= 0 ? (size_t)ra + 1 : count;

				if (memcmp(da, db, wrote * sizeof(da[0])))
					fail("ucs2_strscpy(count=%zu) wrote differently\n", count);
			}
		}

		/* as_utf8 at every destination size, which is where the
		 * "stop rather than split a character" logic lives. */
		for (size_t m = 0; m <= 96; m++) {
			unsigned long la, lb;

			memset(ua, 0xa5, sizeof(ua));
			memset(ub, 0x5a, sizeof(ub));
			la = ref_ucs2_as_utf8(ua, a, m);
			lb = rust_ucs2_as_utf8(ub, a, m);
			checked += 2;
			if (la != lb)
				fail("ucs2_as_utf8(max=%zu): %lu vs %lu\n", m, la, lb);
			else if (memcmp(ua, ub, la))
				fail("ucs2_as_utf8(max=%zu) wrote differently\n", m);

			/* Independent of the C: the output must be valid
			 * UTF-8 and must never exceed the budget. */
			checked++;
			if (lb > m)
				fail("ucs2_as_utf8 wrote %lu bytes into %zu\n", lb, m);
			else {
				size_t k = 0;

				while (k < lb) {
					uint8_t c = ub[k];
					size_t need = c < 0x80 ? 1 :
						      (c & 0xe0) == 0xc0 ? 2 :
						      (c & 0xf0) == 0xe0 ? 3 : 0;

					if (!need || k + need > lb) {
						fail("ucs2_as_utf8 emitted invalid UTF-8\n");
						break;
					}
					for (size_t t = 1; t < need; t++)
						if ((ub[k + t] & 0xc0) != 0x80) {
							fail("ucs2_as_utf8 bad continuation\n");
							need = 0;
							break;
						}
					if (!need)
						break;
					k += need;
				}
			}
		}

		/* strncmp: equal strings, and every single-character edit. */
		for (size_t k = 0; k < 8; k++) {
			size_t pos = rnd() % 40;
			size_t len = rnd() % 48;
			int ra, rb;

			memcpy(b, a, sizeof(a));
			b[pos] = (ucs2_char_t)rnd();
			ra = ref_ucs2_strncmp(a, b, len);
			rb = rust_ucs2_strncmp(a, b, len);
			checked++;
			if (ra != rb)
				fail("ucs2_strncmp(len=%zu) %d vs %d\n", len, ra, rb);
		}
	}
	printf("  ucs2_string       %lu cases  (all seven functions; as_utf8 output also\n"
	       "                              checked for being valid UTF-8 within budget)\n",
	       checked - before);
}

/* ---- mpi limb primitives ----------------------------------------------- */

/*
 * NO COMPILED ORACLE HERE, and that is on purpose. These eight functions are
 * one-line-per-limb arithmetic, and an INDEPENDENT reference -- schoolbook
 * bignum arithmetic on __uint128_t, written here, sharing no code with
 * either arm -- is a stronger check than the C they came from. A mistake
 * both the C and the port made would agree with the C and disagree with
 * this.
 */
#define MPI_N 12

static void mpi_rand(mpi_limb_t *v, size_t n)
{
	for (size_t i = 0; i < n; i++)
		v[i] = (mpi_limb_t)rnd();
}

static void stage_mpih(unsigned long rounds)
{
	mpi_limb_t a[MPI_N], b[MPI_N], r[MPI_N + 1], want[MPI_N + 1];
	unsigned long before = checked;

	for (unsigned long round = 0; round < rounds / 4 + 1; round++) {
		int n = 1 + (int)(rnd() % MPI_N);
		mpi_limb_t k = (mpi_limb_t)rnd();
		mpi_limb_t cy, cw;

		mpi_rand(a, MPI_N);
		mpi_rand(b, MPI_N);

		/* mul_1: res = a * k, carry out. */
		cy = mpihelp_mul_1(r, a, n, k);
		{
			__uint128_t c = 0;

			for (int i = 0; i < n; i++) {
				__uint128_t p = (__uint128_t)a[i] * k + c;

				want[i] = (mpi_limb_t)p;
				c = p >> 64;
			}
			cw = (mpi_limb_t)c;
		}
		checked++;
		if (cy != cw || memcmp(r, want, n * sizeof(r[0])))
			fail("mpihelp_mul_1(n=%d) differs from the independent reference\n", n);

		/* addmul_1: res += a * k. */
		memcpy(r, b, sizeof(b));
		memcpy(want, b, sizeof(b));
		cy = mpihelp_addmul_1(r, a, n, k);
		{
			__uint128_t c = 0;

			for (int i = 0; i < n; i++) {
				__uint128_t p = (__uint128_t)a[i] * k + c + want[i];

				want[i] = (mpi_limb_t)p;
				c = p >> 64;
			}
			cw = (mpi_limb_t)c;
		}
		checked++;
		if (cy != cw || memcmp(r, want, n * sizeof(r[0])))
			fail("mpihelp_addmul_1(n=%d) differs\n", n);

		/* submul_1: res -= a * k, borrow out. */
		memcpy(r, b, sizeof(b));
		memcpy(want, b, sizeof(b));
		cy = mpihelp_submul_1(r, a, n, k);
		{
			__uint128_t borrow = 0;

			for (int i = 0; i < n; i++) {
				__uint128_t p = (__uint128_t)a[i] * k + borrow;
				mpi_limb_t low = (mpi_limb_t)p;
				mpi_limb_t x = want[i];

				want[i] = x - low;
				borrow = (p >> 64) + (want[i] > x ? 1 : 0);
			}
			cw = (mpi_limb_t)borrow;
		}
		checked++;
		if (cy != cw || memcmp(r, want, n * sizeof(r[0])))
			fail("mpihelp_submul_1(n=%d) differs\n", n);

		/* add_n / sub_n against 128-bit accumulation. */
		cy = mpihelp_add_n(r, a, b, n);
		{
			__uint128_t c = 0;

			for (int i = 0; i < n; i++) {
				__uint128_t t = (__uint128_t)a[i] + b[i] + c;

				want[i] = (mpi_limb_t)t;
				c = t >> 64;
			}
			cw = (mpi_limb_t)c;
		}
		checked++;
		if (cy != cw || memcmp(r, want, n * sizeof(r[0])))
			fail("mpihelp_add_n(n=%d) differs\n", n);

		cy = mpihelp_sub_n(r, a, b, n);
		{
			mpi_limb_t borrow = 0;

			for (int i = 0; i < n; i++) {
				mpi_limb_t y = b[i] + borrow;
				mpi_limb_t b1 = y < borrow;
				mpi_limb_t d = a[i] - y;

				want[i] = d;
				borrow = b1 + (d > a[i]);
			}
			cw = borrow;
		}
		checked++;
		if (cy != cw || memcmp(r, want, n * sizeof(r[0])))
			fail("mpihelp_sub_n(n=%d) differs\n", n);

		/* Independent again: a + b - b == a. */
		{
			mpi_limb_t t[MPI_N];

			mpihelp_add_n(t, a, b, n);
			mpihelp_sub_n(r, t, b, n);
			checked++;
			if (memcmp(r, a, n * sizeof(a[0])))
				fail("mpihelp add_n then sub_n does not round-trip\n");
		}

		/* lshift / rshift: cnt is 1..63, as the callers guarantee. */
		{
			unsigned int cnt = 1 + (unsigned int)(rnd() % 63);
			mpi_limb_t out;

			out = mpihelp_lshift(r, a, n, cnt);
			{
				cw = a[n - 1] >> (64 - cnt);
				for (int i = n - 1; i >= 1; i--)
					want[i] = (a[i] << cnt) | (a[i - 1] >> (64 - cnt));
				want[0] = a[0] << cnt;
			}
			checked++;
			if (out != cw || memcmp(r, want, n * sizeof(r[0])))
				fail("mpihelp_lshift(n=%d cnt=%u) differs\n", n, cnt);

			out = mpihelp_rshift(r, a, n, cnt);
			{
				cw = a[0] << (64 - cnt);
				for (int i = 0; i < n - 1; i++)
					want[i] = (a[i] >> cnt) | (a[i + 1] << (64 - cnt));
				want[n - 1] = a[n - 1] >> cnt;
			}
			checked++;
			if (out != cw || memcmp(r, want, n * sizeof(r[0])))
				fail("mpihelp_rshift(n=%d cnt=%u) differs\n", n, cnt);

			/* Independent: shifting left then right must restore
			 * everything the left shift did not push out. */
			mpihelp_lshift(want, a, n, cnt);
			mpihelp_rshift(r, want, n, cnt);
			checked++;
			for (int i = 0; i < n; i++) {
				mpi_limb_t expect = a[i];

				if (i == n - 1)
					expect &= ~(mpi_limb_t)0 >> cnt;
				if (r[i] != expect) {
					fail("lshift then rshift lost bits at limb %d\n", i);
					break;
				}
			}
		}

		/* cmp: against itself, and against every single-limb edit. */
		checked++;
		if (mpihelp_cmp(a, a, n) != 0)
			fail("mpihelp_cmp(a, a) != 0\n");
		{
			int pos = (int)(rnd() % n);

			memcpy(r, a, sizeof(a));
			r[pos] ^= (mpi_limb_t)1 << (rnd() % 64);
			checked += 2;
			if (mpihelp_cmp(a, r, n) != -mpihelp_cmp(r, a, n))
				fail("mpihelp_cmp is not antisymmetric\n");
			if (mpihelp_cmp(a, r, n) != (a[pos] > r[pos] ? 1 : -1))
				fail("mpihelp_cmp did not order by the top differing limb\n");
		}
	}
	printf("  mpi limbs         %lu cases  (against an INDEPENDENT __uint128_t\n"
	       "                              reference, not the C they came from)\n",
	       checked - before);
}

/* ---- main ------------------------------------------------------------ */


int main(int argc, char **argv)
{
	unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 0) : 200000;
	unsigned long before;

	printf("lib/ differential: C bodies (oracle) vs the Rust\n");
	stage_base64(rounds);
	stage_memweight(rounds);
	stage_mac(rounds);
	stage_union_find(rounds);
	stage_check_signature(rounds);

	/* bcd: the whole input domain of both functions, no sampling. */
	before = checked;
	for (unsigned v = 0; v < 256; v++) {
		checked++;
		if (ref_bcd2bin((unsigned char)v) != _bcd2bin((unsigned char)v))
			fail("_bcd2bin(0x%02x) differs\n", v);
	}
	for (unsigned v = 0; v < 100000; v++) {
		checked++;
		if (ref_bin2bcd(v) != _bin2bcd(v))
			fail("_bin2bcd(%u) differs\n", v);
	}
	printf("  bcd exhaustive    %lu cases  (every _bcd2bin input, _bin2bcd 0..99999)\n",
	       checked - before);

	/* crc16: every single byte walks every table entry, then every length
	 * up to 512, then fuzz with random seeds. */
	before = checked;
	{
		uint8_t b[512];

		for (unsigned i = 0; i < 256; i++) {
			uint8_t one = (uint8_t)i;

			checked++;
			if (ref_crc16(0, &one, 1) != rust_crc16(0, &one, 1))
				fail("crc16 of byte 0x%02x differs -- generated table is wrong\n", i);
		}
		for (unsigned i = 0; i < sizeof(b); i++)
			b[i] = (uint8_t)(i * 91 + 7);
		for (unsigned len = 0; len <= sizeof(b); len++) {
			checked++;
			if (ref_crc16(0xffff, b, len) != rust_crc16(0xffff, b, len))
				fail("crc16(len=%u) differs\n", len);
		}
		for (unsigned long i = 0; i < rounds; i++) {
			unsigned len = rnd() % sizeof(b);
			uint16_t seed = (uint16_t)rnd();

			b[rnd() % sizeof(b)] = (uint8_t)rnd();
			checked++;
			if (ref_crc16(seed, b, len) != rust_crc16(seed, b, len))
				fail("crc16(seed=%04x, len=%u) differs\n", seed, len);
		}
	}
	printf("  crc16             %lu cases  (every table entry, every length 0..512, fuzz)\n",
	       checked - before);

	/* win_minmax: drive both trackers with the same random stream and
	 * compare the whole struct after every step, not just the return
	 * value. The 2nd and 3rd choices are the algorithm; a port that got
	 * only s[0] right would pass a return-value comparison for a long
	 * time. Timestamps deliberately start near the u32 wrap. */
	before = checked;
	for (unsigned long round = 0; round < rounds / 200 + 1; round++) {
		struct ref_minmax a = {}, b = {};
		uint32_t win = 1 + (uint32_t)(rnd() % 1000);
		uint32_t t = (uint32_t)(rnd() & 1 ? 0xfffff000u : 0);
		int is_max = rnd() & 1;

		for (int step = 0; step < 200; step++) {
			uint32_t meas = (uint32_t)(rnd() % 64);
			uint32_t ra, rb;

			t += (uint32_t)(rnd() % 400);
			if (is_max) {
				ra = ref_minmax_running_max(&a, win, t, meas);
				rb = rust_minmax_running_max(&b, win, t, meas);
			} else {
				ra = ref_minmax_running_min(&a, win, t, meas);
				rb = rust_minmax_running_min(&b, win, t, meas);
			}

			checked++;
			if (ra != rb || memcmp(&a, &b, sizeof(a))) {
				fail("win_minmax diverged at step %d (win=%u, %s)\n",
				     step, win, is_max ? "max" : "min");
				break;
			}
		}
	}
	printf("  win_minmax        %lu cases  (whole struct compared each step, wrapping clocks)\n",
	       checked - before);

	stage_sort(rounds);
	stage_list_sort(rounds);
	stage_xxhash(rounds);
	stage_earlycpio(rounds);
	stage_plist(rounds);
	stage_plist_requeue_bug();
	stage_arc4(rounds);
	stage_crc_ccitt(rounds);
	stage_clz_ctz();
	stage_chacha(rounds);
	stage_crypto_xor(rounds);
	stage_ucs2(rounds);
	stage_mpih(rounds);
	stage_bsearch(rounds);

	printf("\n  checked      %lu\n  mismatches   %lu\n", checked, mismatches);
	if (mismatches) {
		printf("\nFAIL\n");
		return 1;
	}
	printf("\nPASS\n");
	return 0;
}
