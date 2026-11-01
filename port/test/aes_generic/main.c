/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/aes_generic.c.
 *   subject  = the real glue slice (aes_generic_glue.c: ft/it data + thunks) + the Rust
 *              crypto_aes_rs_encrypt/decrypt (aes_generic_rs.rs)
 *   ref      = the PRISTINE crypto_aes_encrypt/decrypt (+ its four tables)
 *   oracle B = an independent FIPS-197 implementation below (S-box from the field
 *              definition by brute-force inverse search, byte-wise SubBytes/ShiftRows/
 *              MixColumns/AddRoundKey, its own key expansion and tables)
 * The key schedule in the ctx comes from the REAL aes_expandkey (the Rust of
 * lib/crypto/aes_rs.rs, compiled into the same probe crate). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32;
struct ctx { u32 key_enc[60]; u32 key_dec[60]; u32 key_length; };
int aes_expandkey(struct ctx *, const u8 *, unsigned);
void subj_enc(struct ctx *, u8 *, const u8 *); void subj_dec(struct ctx *, u8 *, const u8 *);
int subj_setkey(struct ctx *, const u8 *, unsigned);
void ref_enc(struct ctx *, u8 *, const u8 *); void ref_dec(struct ctx *, u8 *, const u8 *);
u32 subj_ft(unsigned, unsigned), subj_it(unsigned, unsigned);
u32 ref_ft(unsigned, unsigned), ref_it(unsigned, unsigned), ref_fl(unsigned, unsigned), ref_il(unsigned, unsigned);
u32 aesgen_probe_fl(unsigned, unsigned), aesgen_probe_il(unsigned, unsigned);
u32 aesgen_probe_sbox(unsigned), aesgen_probe_isbox(unsigned);
extern const u8 crypto_aes_sbox[256]; /* the lib/crypto/aes_rs.rs table */

static unsigned long long checks, fails;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
#define CHECK(c, ...) do { checks++; if (!(c)) FAIL(__VA_ARGS__); } while (0)
static int poison_out(void) { return getenv("AESGEN_PROVE_CAN_FAIL") != NULL; }
static int poison_basis(void) { return getenv("AESGEN_PROVE_BASIS_CAN_FAIL") != NULL; }

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static void fill(void *p, size_t n) { u8 *b = p; while (n--) *b++ = (u8)rnd(); }

/* ------------------------- oracle B: FIPS-197 ------------------------- */
static unsigned POLY = 0x11b; /* x^8+x^4+x^3+x+1 (poison: 0x11d) */
static u8 gm(u8 a, u8 b)
{
	unsigned p = 0, x = a;
	for (; b; b >>= 1) { if (b & 1) p ^= x; x <<= 1; if (x & 0x100) x ^= POLY; }
	return (u8)p;
}
static u8 rol8(u8 v, int n) { return (u8)((v << n) | (v >> (8 - n))); }
static u8 SB[256], ISB[256];
static void oracle_init(void)
{
	if (poison_basis()) POLY = 0x11d;
	for (unsigned x = 0; x < 256; x++) {
		u8 y = 0;
		if (x) { for (unsigned c = 1; c < 256; c++) if (gm((u8)x, (u8)c) == 1) { y = (u8)c; break; } }
		SB[x] = y ^ rol8(y, 1) ^ rol8(y, 2) ^ rol8(y, 3) ^ rol8(y, 4) ^ 0x63;
	}
	for (unsigned x = 0; x < 256; x++) ISB[SB[x]] = (u8)x;
}
static void o_expand(const u8 *key, unsigned nk, u8 w[60][4], unsigned *nr)
{
	*nr = nk + 6;
	u8 rcon = 1;
	for (unsigned i = 0; i < nk; i++) memcpy(w[i], key + 4 * i, 4);
	for (unsigned i = nk; i < 4 * (*nr + 1); i++) {
		u8 t[4]; memcpy(t, w[i - 1], 4);
		if (i % nk == 0) {
			u8 t0 = t[0]; t[0] = SB[t[1]] ^ rcon; t[1] = SB[t[2]]; t[2] = SB[t[3]]; t[3] = SB[t0];
			rcon = gm(rcon, 2);
		} else if (nk > 6 && i % nk == 4) {
			for (int j = 0; j < 4; j++) t[j] = SB[t[j]];
		}
		for (int j = 0; j < 4; j++) w[i][j] = w[i - nk][j] ^ t[j];
	}
}
static void add_rk(u8 s[16], u8 w[60][4], unsigned r) { for (int c = 0; c < 4; c++) for (int i = 0; i < 4; i++) s[4 * c + i] ^= w[4 * r + c][i]; }
static void sub_bytes(u8 s[16], const u8 *box) { for (int i = 0; i < 16; i++) s[i] = box[s[i]]; }
static void shift_rows(u8 s[16], int inv)
{
	u8 t[16];
	for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++)
		t[4 * c + r] = s[4 * (inv ? (c - r + 4) % 4 : (c + r) % 4) + r];
	memcpy(s, t, 16);
}
static void mix_columns(u8 s[16], int inv)
{
	static const u8 M[4][4] = { {2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2} };
	static const u8 IM[4][4] = { {14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14} };
	u8 t[16];
	for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) {
		u8 v = 0;
		for (int k = 0; k < 4; k++) v ^= gm((inv ? IM : M)[r][k], s[4 * c + k]);
		t[4 * c + r] = v;
	}
	memcpy(s, t, 16);
}
static void o_enc(const u8 *key, unsigned klen, const u8 *in, u8 *out)
{
	u8 w[60][4], s[16]; unsigned nr;
	o_expand(key, klen / 4, w, &nr); memcpy(s, in, 16); add_rk(s, w, 0);
	for (unsigned r = 1; r <= nr; r++) {
		sub_bytes(s, SB); shift_rows(s, 0); if (r != nr) mix_columns(s, 0); add_rk(s, w, r);
	}
	memcpy(out, s, 16);
}
static void o_dec(const u8 *key, unsigned klen, const u8 *in, u8 *out)
{
	u8 w[60][4], s[16]; unsigned nr;
	o_expand(key, klen / 4, w, &nr); memcpy(s, in, 16); add_rk(s, w, nr);
	for (unsigned r = nr; r-- > 0;) {
		shift_rows(s, 1); sub_bytes(s, ISB); add_rk(s, w, r); if (r != 0) mix_columns(s, 1);
	}
	memcpy(out, s, 16);
}
/* tables from the FIPS-197 column definition. tab[k][x]: the byte at row k of a column
 * contributes (column k of the (inverse) MixColumns matrix) * S[x] to the output column. */
static u32 o_ft(unsigned k, unsigned x)
{
	static const u8 M[4][4] = { {2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2} };
	u32 v = 0; for (int r = 0; r < 4; r++) v |= (u32)gm(M[r][k], SB[x]) << (8 * r); return v;
}
static u32 o_it(unsigned k, unsigned x)
{
	static const u8 IM[4][4] = { {14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14} };
	u32 v = 0; for (int r = 0; r < 4; r++) v |= (u32)gm(IM[r][k], ISB[x]) << (8 * r); return v;
}
static u32 o_fl(unsigned k, unsigned x) { return (u32)SB[x] << (8 * k); }
static u32 o_il(unsigned k, unsigned x) { return (u32)ISB[x] << (8 * k); }

/* ------------------------------ checks ------------------------------ */
static int hexval(int c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void unhex(const char *h, u8 *o, size_t n) { for (size_t i = 0; i < n; i++) o[i] = (u8)(hexval(h[2 * i]) * 16 + hexval(h[2 * i + 1])); }

static void tables(void)
{
	unsigned long n = 0;
	for (unsigned k = 0; k < 4; k++) for (unsigned x = 0; x < 256; x++) {
		u32 ft = o_ft(k, x), it = o_it(k, x), fl = o_fl(k, x), il = o_il(k, x);
		CHECK(subj_ft(k, x) == ft, "glue ft[%u][%u]=%08x oracle %08x\n", k, x, subj_ft(k, x), ft);
		CHECK(subj_it(k, x) == it, "glue it[%u][%u]=%08x oracle %08x\n", k, x, subj_it(k, x), it);
		CHECK(ref_ft(k, x) == ft && ref_it(k, x) == it, "pristine ft/it[%u][%u] vs oracle\n", k, x);
		CHECK(ref_fl(k, x) == fl && ref_il(k, x) == il, "pristine fl/il[%u][%u] vs oracle\n", k, x);
		CHECK(aesgen_probe_fl(k, x) == ref_fl(k, x), "rust fl[%u][%u]=%08x pristine %08x\n", k, x, aesgen_probe_fl(k, x), ref_fl(k, x));
		CHECK(aesgen_probe_il(k, x) == ref_il(k, x), "rust il[%u][%u]=%08x pristine %08x\n", k, x, aesgen_probe_il(k, x), ref_il(k, x));
		CHECK(aesgen_probe_fl(k, x) == fl && aesgen_probe_il(k, x) == il, "rust fl/il[%u][%u] vs oracle\n", k, x);
		CHECK(subj_ft(k, x) == ref_ft(k, x) && subj_it(k, x) == ref_it(k, x), "glue ft/it[%u][%u] vs pristine\n", k, x);
		n++;
	}
	for (unsigned x = 0; x < 256; x++) {
		CHECK(aesgen_probe_sbox(x) == SB[x] && aesgen_probe_isbox(x) == ISB[x], "rust sbox/isbox[%u] vs oracle\n", x);
		CHECK(crypto_aes_sbox[x] == SB[x], "lib/crypto crypto_aes_sbox[%u] vs oracle\n", x);
	}
	printf("tables: %lu (k,x) positions x 4 tables (ft,it,fl,il) x 3 implementations checked exhaustively\n", n);
}

struct kv { const char *name, *key, *pt, *ct; };
static const struct kv FIPS[] = {
	{ "App.B  AES-128", "2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32" },
	{ "C.1    AES-128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a" },
	{ "C.2    AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191" },
	{ "C.3    AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089" },
};

static void out_poison(u8 *o) { if (poison_out()) o[5] ^= 1; }

static void fips(void)
{
	for (unsigned v = 0; v < sizeof FIPS / sizeof FIPS[0]; v++) {
		u8 key[32], pt[16], ct[16], o[16], o2[16], o3[16]; struct ctx c; unsigned kl = (unsigned)strlen(FIPS[v].key) / 2;
		unhex(FIPS[v].key, key, kl); unhex(FIPS[v].pt, pt, 16); unhex(FIPS[v].ct, ct, 16);
		CHECK(subj_setkey(&c, key, kl) == 0, "%s set_key\n", FIPS[v].name);
		CHECK(c.key_length == kl, "%s key_length\n", FIPS[v].name);
		o_enc(key, kl, pt, o3); CHECK(!memcmp(o3, ct, 16), "%s: oracle B encrypt != FIPS text\n", FIPS[v].name);
		o_dec(key, kl, ct, o3); CHECK(!memcmp(o3, pt, 16), "%s: oracle B decrypt != FIPS text\n", FIPS[v].name);
		subj_enc(&c, o, pt); out_poison(o); CHECK(!memcmp(o, ct, 16), "%s: glue+Rust encrypt != FIPS text\n", FIPS[v].name);
		subj_dec(&c, o, ct); CHECK(!memcmp(o, pt, 16), "%s: glue+Rust decrypt != FIPS text\n", FIPS[v].name);
		ref_enc(&c, o2, pt); CHECK(!memcmp(o2, ct, 16), "%s: pristine encrypt != FIPS text\n", FIPS[v].name);
		ref_dec(&c, o2, ct); CHECK(!memcmp(o2, pt, 16), "%s: pristine decrypt != FIPS text\n", FIPS[v].name);
		memcpy(o, pt, 16); subj_enc(&c, o, o); CHECK(!memcmp(o, ct, 16), "%s: in-place encrypt\n", FIPS[v].name);
		subj_dec(&c, o, o); CHECK(!memcmp(o, pt, 16), "%s: in-place decrypt\n", FIPS[v].name);
	}
	/* bad key lengths: set_key must be -EINVAL (-22) like the pristine one */
	{
		struct ctx c; u8 key[40]; fill(key, sizeof key);
		static const unsigned bad[] = { 0, 1, 15, 17, 23, 25, 31, 33, 40 };
		for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(subj_setkey(&c, key, bad[i]) == -22, "set_key(%u) != -EINVAL\n", bad[i]);
	}
	printf("fips: Appendix B and C.1/C.2/C.3, encrypt+decrypt+in-place, oracle/pristine/glue+Rust all equal the FIPS text; bad key lengths -> -EINVAL\n");
}

static void random_cases(unsigned long n)
{
	static const unsigned kls[3] = { 16, 24, 32 };
	unsigned long iter;
	for (iter = 0; iter < n; iter++) {
		u8 key[32], blk[16], inb[64], oa[64], ob[64], oo[16], ct[16]; struct ctx c; unsigned kl = kls[rnd() % 3], nk, ioff = rnd() & 7, ooff = rnd() & 7; int inplace = (rnd() & 3) == 0;
		fill(key, sizeof key); fill(blk, 16);
		if (iter % 7 == 0) memset(blk, 0, 16);
		if (iter % 11 == 0) memset(key, (int)(rnd() & 0xff) , sizeof key);
		if (aes_expandkey(&c, key, kl) != 0) { FAIL("aes_expandkey failed\n"); return; }
		nk = kl / 4;
		/* the oracle's own schedule must equal the real aes_expandkey's key_enc */
		{ u8 w[60][4]; unsigned nr; o_expand(key, nk, w, &nr); for (unsigned i = 0; i < 4 * (nr + 1); i++) { u32 v; memcpy(&v, w[i], 4); CHECK(v == c.key_enc[i], "oracle key schedule word %u != aes_expandkey (key %u bytes)\n", i, kl); } }
		for (int dir = 0; dir < 2; dir++) {
			void (*sf)(struct ctx *, u8 *, const u8 *) = dir ? subj_dec : subj_enc, (*rf)(struct ctx *, u8 *, const u8 *) = dir ? ref_dec : ref_enc;
			/* unaligned in/out (offsets 0..7); canaries around out catch a stray write */
			memset(inb, 0x5a, sizeof inb); memcpy(inb + ioff, blk, 16);
			memset(oa, 0xa5, sizeof oa); memset(ob, 0xa5, sizeof ob);
			if (dir) o_dec(key, kl, blk, oo); else o_enc(key, kl, blk, oo);
			sf(&c, oa + 16 + ooff, inb + ioff); out_poison(oa + 16 + ooff);
			rf(&c, ob + 16 + ooff, inb + ioff);
			CHECK(!memcmp(oa + 16 + ooff, ob + 16 + ooff, 16), "%s: glue+Rust != pristine (key %u, in+%u out+%u)\n", dir ? "decrypt" : "encrypt", kl, ioff, ooff);
			CHECK(!memcmp(oa + 16 + ooff, oo, 16), "%s: glue+Rust != oracle B (key %u)\n", dir ? "decrypt" : "encrypt", kl);
			CHECK(!memcmp(ob + 16 + ooff, oo, 16), "%s: pristine != oracle B (key %u)\n", dir ? "decrypt" : "encrypt", kl);
			{ u8 can[64]; memset(can, 0xa5, sizeof can); memcpy(can + 16 + ooff, oa + 16 + ooff, 16);
			  CHECK(!memcmp(oa, can, 16 + ooff) && !memcmp(oa + 32 + ooff, can + 32 + ooff, 32 - ooff), "%s wrote outside its 16 bytes\n", dir ? "decrypt" : "encrypt");
			  CHECK(!memcmp(inb + ioff, blk, 16), "%s changed its input\n", dir ? "decrypt" : "encrypt"); }
			if (dir == 0) memcpy(ct, oo, 16);
			/* in place (same pointer, unaligned) */
			if (inplace) {
				memset(inb, 0x5a, sizeof inb); memcpy(inb + ioff, blk, 16); memcpy(oa, inb, sizeof oa);
				sf(&c, inb + ioff, inb + ioff); out_poison(inb + ioff);
				CHECK(!memcmp(inb + ioff, oo, 16), "%s in place != oracle B (key %u)\n", dir ? "decrypt" : "encrypt", kl);
				CHECK(!memcmp(inb, oa, ioff) && !memcmp(inb + ioff + 16, oa + ioff + 16, 64 - ioff - 16), "%s in place wrote outside\n", dir ? "decrypt" : "encrypt");
			}
		}
		{ u8 rt[16]; subj_dec(&c, rt, ct); CHECK(!memcmp(rt, blk, 16), "decrypt(encrypt(x)) != x (key %u)\n", kl); }
	}
}

/* key_length values aes_expandkey never writes: both read key words inside the 60-word
 * arrays (int-signed compares), so the pristine C and the Rust must still agree. */
static void odd_key_lengths(void)
{
	static const u32 kls[] = { 0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 64, 100, 255, 0x7fffffff, 0x80000000u, 0xffffffffu };
	unsigned long n = 0;
	for (unsigned i = 0; i < sizeof kls / sizeof kls[0]; i++) for (int rep = 0; rep < 200; rep++) {
		struct ctx c; u8 blk[16], a[16], b[16];
		fill(&c, sizeof c); c.key_length = kls[i]; fill(blk, 16);
		subj_enc(&c, a, blk); ref_enc(&c, b, blk); out_poison(a); CHECK(!memcmp(a, b, 16), "encrypt key_length=%u differs\n", kls[i]);
		subj_dec(&c, a, blk); ref_dec(&c, b, blk); CHECK(!memcmp(a, b, 16), "decrypt key_length=%u differs\n", kls[i]);
		n++;
	}
	printf("odd key_length (17 values incl. 0, 2^31, 2^32-1) x 200 random 60-word schedules: %lu enc+dec pairs vs pristine\n", n);
}

int main(int argc, char **argv)
{
	unsigned long n = argc > 1 ? strtoul(argv[1], 0, 10) : 1000000;
	oracle_init();
	tables();
	fips();
	odd_key_lengths();
	random_cases(n);
	printf("%llu comparisons, %llu failures (%lu random (key,block) cases, each enc+dec, 3 key sizes, aligned/unaligned/in-place)\n", checks, fails, n);
	return fails ? 1 : 0;
}
