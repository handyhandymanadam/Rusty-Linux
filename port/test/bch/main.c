/* bch differential: the same case stream drives pristine lib/bch.c (ARM_REF) or bch_glue.c over bch_rs.rs (ARM_RS). Each case builds a code with bch_init (many (m, t,
 * polynomial, swap_bits) combinations, some invalid, some with a failing allocation), then encodes (random lengths, alignments, incremental splits) and decodes (random
 * bit errors in data and ecc, every calling convention). Everything observable is printed: return values, ecc bytes, error locations, a hash of every table, leaks.
 * usage: t SHARD   (env BC_N cases per shard, BC_PROVE=1 poisons the Rust arm) */
#include "kshim.h"
#include <asm/byteorder.h>
#include SRC

int warn_count, alloc_fail_in; long live_allocs;

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 33) % n : 0; }
static unsigned long long fnv(const void *p, size_t n) { const unsigned char *c = p; unsigned long long h = 1469598103934665603ULL; while (n--) { h ^= *c++; h *= 1099511628211ULL; } return h; }

static void dump_ctl(struct bch_control *b)
{
	unsigned words = (b->m * b->t + 31) / 32;
	printf("  ctl m=%u n=%u t=%u bits=%u bytes=%u swap=%d pow=%016llx log=%016llx mod8=%016llx xi=%016llx\n", b->m, b->n, b->t, b->ecc_bits, b->ecc_bytes, b->swap_bits,
	       fnv(b->a_pow_tab, (b->n + 1) * 2), fnv(b->a_log_tab, (b->n + 1) * 2), fnv(b->mod8_tab, words * 1024 * 4), fnv(b->xi_tab, b->m * 4));
}

static void hexl(const char *tag, const unsigned char *p, unsigned n) { printf(" %s=", tag); for (unsigned i = 0; i < n; i++) printf("%02x", p[i]); }

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("BC_N") ? atol(getenv("BC_N")) : 5000;
	static const int ts[] = { 1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 24, 32, 48, 64 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long cs = 0; cs < n; cs++) {
		int m = 5 + rnd(11), t = ts[rnd(14)];
		unsigned poly = 0; bool sw = rnd(2);
		unsigned pr = rnd(10);
		if (pr == 0) poly = 0x11b;		/* degree 8, not primitive */
		else if (pr == 1) poly = 0x12b;		/* degree 8, primitive */
		else if (pr == 2) poly = (1u << m) | 3;	/* degree m, usually not primitive */
		else if (pr == 3) poly = 0x29;		/* degree 5 */
		if (rnd(25) == 0) { m = 4 + rnd(14); t = rnd(70) - 2; }	/* out-of-range m and t */
		alloc_fail_in = rnd(15) == 0 ? 1 + rnd(14) : 0;
		long before = live_allocs;
		struct bch_control *b = bch_init(m, t, poly, sw);
		alloc_fail_in = 0;
		printf("case %ld init m=%d t=%d poly=%x sw=%d -> %d warn=%d\n", cs, m, t, poly, sw, b != NULL, warn_count);
		if (!b) { printf("  leak=%ld\n", live_allocs - before); continue; }
		dump_ctl(b);
		unsigned maxbytes = (b->n - b->ecc_bits) / 8;
		for (int rep = 0; rep < 4; rep++) {
			unsigned len = rnd(5) == 0 ? rnd(8) : rnd(maxbytes < 300 ? maxbytes + 1 : 301);
			if (len > maxbytes) len = maxbytes;
			unsigned off = rnd(4);
			unsigned char *buf = malloc(len + 8 + 4), *data = buf + off;
			unsigned char ecc[200], ecc2[200], rec[200], x[200], calc[200];
			for (unsigned i = 0; i < len; i++) data[i] = rnd(rnd(3) ? 256 : 4);
			memset(ecc, 0, sizeof(ecc));
			bch_encode(b, data, len, ecc);
			hexl("ecc", ecc, b->ecc_bytes);
			/* incremental: split anywhere, continue from the partial parity */
			unsigned sp = len ? rnd(len + 1) : 0;
			memset(ecc2, 0, sizeof(ecc2));
			bch_encode(b, data, sp, ecc2); bch_encode(b, data + sp, len - sp, ecc2);
			printf(" len=%u off=%u split_same=%d", len, off, !memcmp(ecc, ecc2, b->ecc_bytes));
			/* ecc == NULL variant leaves the result in the internal buffer */
			bch_encode(b, data, len, NULL);
			printf(" internal=%016llx\n", fnv(b->ecc_buf, ((b->m * b->t + 31) / 32) * 4));
			/* inject errors */
			unsigned nbits = len * 8 + b->ecc_bits;
			int ne = rnd(6) == 0 ? 0 : rnd(b->t + 3);
			unsigned char *bad = malloc(len + 1); memcpy(bad, data, len); memcpy(rec, ecc, b->ecc_bytes);
			printf("  flips:");
			for (int e = 0; e < ne && nbits; e++) {
				unsigned p = rnd(nbits);
				if (p < len * 8) bad[p / 8] ^= 1 << (p % 8); else { unsigned q = p - len * 8; rec[q / 8] ^= 1 << (7 - q % 8); }
				printf(" %u", p);
			}
			printf("\n");
			unsigned int errloc[200]; int r;
			for (int mode = 0; mode < 5; mode++) {
				memset(errloc, 0, sizeof(errloc));
				switch (mode) {
				case 0: r = bch_decode(b, bad, len, rec, NULL, NULL, errloc); break;
				case 1: memset(calc, 0, sizeof(calc)); bch_encode(b, bad, len, calc); r = bch_decode(b, NULL, len, rec, calc, NULL, errloc); break;
				case 2: memset(calc, 0, sizeof(calc)); bch_encode(b, bad, len, calc);
					for (unsigned i = 0; i < b->ecc_bytes; i++) x[i] = calc[i] ^ rec[i];
					r = bch_decode(b, NULL, len, NULL, x, NULL, errloc); break;
				case 3: { /* syndromes from an earlier decode of the same codeword */
					unsigned synbuf[130]; r = bch_decode(b, bad, len, rec, NULL, NULL, errloc); memcpy(synbuf, b->syn, 2 * b->t * 4);
					memset(errloc, 0, sizeof(errloc)); r = bch_decode(b, NULL, len, NULL, NULL, synbuf, errloc); break; }
				default: r = bch_decode(b, NULL, len, rec, NULL, NULL, errloc); break;	/* missing data: -EINVAL */
				}
				printf("  dec%d -> %d", mode, r);
				if (r > 0) { printf(" loc:"); for (int i = 0; i < r; i++) printf(" %u", errloc[i]); }
				printf("\n");
			}
			/* syndromes handed over directly (the hardware-syndrome entry point): random values, and the exact syndromes of k chosen error locations */
			for (int sm = 0; sm < 6; sm++) {
				unsigned synv[130]; unsigned sl = (sm & 1) ? maxbytes : rnd(maxbytes + 1);
				if (sm < 2) {
					for (unsigned i = 0; i < 2 * b->t; i++) synv[i] = rnd(b->n + 1);
					printf("  synR%d", sm);
				} else {
					int k = rnd(b->t + 3); memset(synv, 0, sizeof(synv));
					printf("  synS%d k=%d at", sm, k);
					for (int e = 0; e < k; e++) {
						unsigned long long pos = rnd(sm >= 4 && e > 0 ? 3 : b->n);	/* sm >= 4 repeats positions: they cancel */
						if (sm >= 4 && e > 0) pos = (e * 7 + sm) % 3;
						printf(" %llu", pos);
						for (unsigned j = 0; j < 2 * b->t; j++) synv[j] ^= b->a_pow_tab[(pos * (j + 1)) % b->n];
					}
				}
				memset(errloc, 0, sizeof(errloc));
				r = bch_decode(b, NULL, sl, NULL, NULL, synv, errloc);
				printf(" len=%u -> %d", sl, r);
				if (r > 0) { printf(" loc:"); for (int i = 0; i < r; i++) printf(" %u", errloc[i]); }
				printf("\n");
			}
			/* an oversize length */
			printf("  big -> %d\n", bch_decode(b, bad, maxbytes + 1, rec, NULL, NULL, errloc));
			free(buf); free(bad);
		}
		bch_free(b);
		printf("  leak=%ld warn=%d\n", live_allocs - before, warn_count);
	}
	bch_free(NULL);
#ifdef ARM_RS
	if (getenv("BC_PROVE")) printf("poison\n");
#endif
	return 0;
}
