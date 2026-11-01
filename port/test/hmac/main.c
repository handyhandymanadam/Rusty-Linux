/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the pad derivation of crypto/hmac.c: the pristine C statements (c_derive_pads, sliced out of
 * the unmodified file by extract.py) against hmac_rs_derive_pads, for EVERY block size 1..256 and EVERY keylen
 * 0..bs, over random keys (and all-zero / all-0xff keys). Both pads sit inside a larger buffer with guard bytes
 * before and after (0xA5, checked untouched), and on top of that the pads are placed flush against PROT_NONE
 * pages so one byte read or written outside [0,bs) is a SIGSEGV. Whole-buffer comparison C == Rust, plus an
 * INDEPENDENT oracle (RFC 2104: ipad = key padded with zeros ^ 0x36, opad = ... ^ 0x5c) that shares nothing with
 * either arm.   usage: main [shard nshards] ; HMAC_PROVE_CAN_FAIL=1 poisons one Rust byte. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
typedef uint8_t u8;
void c_derive_pads(u8 *, u8 *, int, unsigned int);
void hmac_rs_derive_pads(u8 *, u8 *, int, unsigned int);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
#define G 16
static unsigned long long n, fails; static int poison;

int main(int argc, char **argv)
{
	unsigned shard = argc > 2 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	long pg = 4096; poison = getenv("HMAC_PROVE_CAN_FAIL") != NULL;
	u8 *m = mmap(0, 6 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	/* layout: [guard][pad A pages][guard] [guard][pad B pages][guard]: A/B regions are 1 page each, flush at the END,
	 * so pad+bs ends at a PROT_NONE page; and the buffer is also checked at the START via G guard bytes. */
	mprotect(m, pg, PROT_NONE); mprotect(m + 2 * pg, pg, PROT_NONE); mprotect(m + 3 * pg, pg, PROT_NONE); mprotect(m + 5 * pg, pg, PROT_NONE);
	u8 *regA = m + pg, *regB = m + 4 * pg;
	for (int bs = 1 + shard; bs <= 256; bs += nsh) {
		for (int keylen = 0; keylen <= bs; keylen++) {
			for (int rep = 0; rep < 6; rep++) {
				u8 key[256], ipc[256], opc[256], ipr[256], opr[256];
				for (int i = 0; i < 256; i++) key[i] = rep == 0 ? 0 : rep == 1 ? 0xff : (u8)rnd();
				/* C arm: pads flush at the end of region A / B regions (separate pages), prefilled with garbage */
				u8 *ia = regA + pg - bs, *oa = regB + pg - bs;
				for (int i = 0; i < bs; i++) { ia[i] = (u8)rnd(); oa[i] = (u8)rnd(); }
				u8 gi[G], go[G]; /* guard bytes before the pads (same pages) */
				if (bs + G <= pg) { memset(ia - G, 0xA5, G); memset(oa - G, 0xA5, G); memcpy(gi, ia - G, G); memcpy(go, oa - G, G); }
				memcpy(ia, key, keylen);
				u8 ia0[256], oa0[256]; memcpy(ia0, ia, bs); memcpy(oa0, oa, bs);
				c_derive_pads(ia, oa, bs, keylen);
				memcpy(ipc, ia, bs); memcpy(opc, oa, bs);
				if (bs + G <= pg && (memcmp(ia - G, gi, G) || memcmp(oa - G, go, G))) { fails++; fprintf(stderr, "C arm wrote before pad (harness)\n"); }
				/* Rust arm: same starting bytes, same placement */
				memcpy(ia, ia0, bs); memcpy(oa, oa0, bs);
				if (bs + G <= pg) { memset(ia - G, 0xA5, G); memset(oa - G, 0xA5, G); }
				hmac_rs_derive_pads(ia, oa, bs, keylen);
				memcpy(ipr, ia, bs); memcpy(opr, oa, bs);
				if (poison && bs == 64 && keylen == 20 && rep == 2) ipr[3] ^= 1;
				int bad = bs + G <= pg && (memcmp(ia - G, gi, G) || memcmp(oa - G, go, G));
				for (int i = 0; i < bs; i++) {   /* the independent oracle */
					u8 k = i < keylen ? key[i] : 0;
					if (ipr[i] != (u8)(k ^ 0x36) || opr[i] != (u8)(k ^ 0x5c)) bad = 1;
				}
				n += 2;
				if (bad || memcmp(ipc, ipr, bs) || memcmp(opc, opr, bs)) {
					if (fails++ < 10) fprintf(stderr, "MISMATCH bs=%d keylen=%d rep=%d\n", bs, keylen, rep);
					if (poison) { puts("poisoned Rust result detected"); return 1; }
				}
			}
		}
	}
	printf("shard %u/%u: %llu comparisons (pads: C vs Rust vs RFC 2104 oracle, flush against PROT_NONE + guard bytes), %llu failure(s)\n", shard, nsh, n, fails);
	return fails ? 1 : 0;
}
