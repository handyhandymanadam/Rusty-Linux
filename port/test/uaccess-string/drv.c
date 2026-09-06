/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Differential test for lib/strnlen_user.c / lib/strncpy_from_user.c's
 * word-at-a-time bodies, moved to Rust (strnlen_user_rs.rs /
 * strncpy_from_user_rs.rs) behind a retained C entry that keeps the
 * STAC/CLAC bracket at its original per-call granularity. See either
 * retained C file's header comment and logs/porting-hazards.md, "raw
 * uaccess", for the full account.
 *
 * TWO ARMS, ONE FAULT KNOB. Both the pristine C's own do_strnlen_user()/
 * do_strncpy_from_user() (linked in here as strnlen_user_c_ref()/
 * strncpy_from_user_c_ref(), the EXPORT_SYMBOL renamed via -D to avoid
 * clashing with the real one) AND the real, shipped port/tree/lib/
 * {strnlen_user,strncpy_from_user}.c (unrenamed -- these ARE the files the
 * kernel builds) call unsafe_get_user() through shim/linux/uaccess.h's
 * SAME macro, driven by the single g_fault_at knob below. That is what
 * makes "does the fault-recovery path behave identically" a real
 * comparison rather than two different simulations.
 *
 * INDEPENDENT ORACLE, SCOPED. When a real NUL exists strictly before
 * `count` and no fault is injected, the returned length is unambiguous
 * from the buffer content alone (found strictly before any word-boundary
 * overshoot could matter) -- checked directly against both arms below.
 * The "hit count with no NUL" and any faulting case are cross-arm-only
 * (matching the mpi_powm Guard-12 precedent this session: a real algorithm
 * behaviour -- word-at-a-time's documented overshoot past `count` -- is
 * not something an independent byte-scan oracle can predict without
 * reimplementing the SWAR logic it exists to check).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../common/difftest.h"

extern long strnlen_user_c_ref(const char *str, long count);
extern long strnlen_user(const char *str, long count);
extern long strncpy_from_user_c_ref(char *dst, const char *src, long count);
extern long strncpy_from_user(char *dst, const char *src, long count);

const unsigned char *g_fault_at;

#define FRONT_PAD 16
#define LEN_MAX   200
#define BACK_PAD  48
#define TOTAL     (FRONT_PAD + LEN_MAX + BACK_PAD)

static uint32_t rng_state;

static uint32_t xorshift32(void)
{
	uint32_t x = rng_state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	rng_state = x;
	return x;
}

static uint32_t rnd(uint32_t bound)
{
	return bound ? xorshift32() % bound : 0;
}

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 10) : 30000;
	int prove_can_fail = getenv("UACCESS_PROVE_CAN_FAIL") != NULL;
	unsigned char *base;
	unsigned long i;
	unsigned long strnlen_oracle_checks = 0, strncpy_oracle_checks = 0;

	rng_state = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) : 20260905u;
	if (rng_state == 0)
		rng_state = 1;

	base = malloc(TOTAL);
	if (!base) {
		fprintf(stderr, "out of memory\n");
		return 2;
	}

	for (i = 0; i < runs && dt_fails < dt_maxfails; i++) {
		/* Varies str's own word alignment (malloc's return is always
		 * 16-byte aligned on this glibc, so a FIXED offset here would
		 * make `align` -- do_strnlen_user's own backward-alignment
		 * distance -- always 0 and never exercise that codepath or
		 * the arithmetic hanging off it. FRONT_PAD leaves 16 bytes of
		 * margin, comfortably more than the up-to-7-byte misalignment
		 * plus the up-to-7-byte backward read it causes. */
		unsigned char *str = base + FRONT_PAD + rnd(8);
		unsigned long len = rnd(LEN_MAX + 1);
		int has_nul = rnd(10) < 7;
		unsigned long nul_pos = has_nul ? rnd(len + 1) : 0;
		int has_fault = rnd(2) == 0;
		long fault_index = 0;
		long count;
		long real_nul;
		unsigned long j;

		for (j = 0; j < TOTAL; j++)
			base[j] = (unsigned char)xorshift32();

		/* Safety sentinel: guarantees a real terminator well within the
		 * allocation regardless of `has_nul`, so an un-faulted, no-NUL
		 * test case can never run the word-at-a-time overshoot off the
		 * end of this allocation. FRONT_PAD/BACK_PAD leave 16+ bytes of
		 * margin on both sides of it for that overshoot (bounded to
		 * under one word, 8 bytes, past the last read start). */
		str[len + 16] = 0;
		if (has_nul)
			str[nul_pos] = 0;

		if (has_fault) {
			/* Allow a few bytes before `str` too, to exercise
			 * do_strnlen_user's initial backward-aligned read
			 * faulting. Clamped well inside the allocation. */
			fault_index = (long)rnd(len + 24) - 8;
			g_fault_at = str + fault_index;
		} else {
			g_fault_at = NULL;
		}

		count = (long)rnd((unsigned long)(len + 17));

		/* The TRUE first zero byte, found by scanning -- not the
		 * `nul_pos` this iteration deliberately placed. Random fill
		 * can and does produce an EARLIER incidental zero byte before
		 * `nul_pos` (roughly 1/256 per byte, so common over ~100+
		 * bytes); both arms correctly report THAT position, and an
		 * oracle built from `nul_pos` alone disagreed with both of
		 * them identically -- a bug in this test, not the port
		 * (confirmed: cross-arm agreement never failed, only this
		 * oracle's own assumption did). Scan up to the sentinel at
		 * len+16 inclusive, which is always a real terminator. */
		{
			unsigned long k;

			real_nul = -1;
			for (k = 0; k <= len + 16; k++) {
				if (str[k] == 0) {
					real_nul = (long)k;
					break;
				}
			}
		}

		/* --- strnlen_user --- */
		{
			long ref = strnlen_user_c_ref((const char *)str, count);
			long rs = strnlen_user((const char *)str, count);

			if (prove_can_fail)
				rs ^= 1;

			dt_checks++;
			if (ref != rs) {
				char d[128];
				snprintf(d, sizeof d,
					 "len=%lu nul=%d@%lu fault=%d@%ld count=%ld ref=%ld rs=%ld",
					 len, has_nul, nul_pos, has_fault, fault_index,
					 count, ref, rs);
				dt_fail(i, "strnlen_user", d);
			} else if (!has_fault && real_nul >= 0 && real_nul < count) {
				long expected = real_nul + 1;

				strnlen_oracle_checks++;
				dt_checks++;
				if (ref != expected) {
					char d[128];
					snprintf(d, sizeof d,
						 "len=%lu nul_pos=%lu count=%ld ref=%ld expected=%ld",
						 len, nul_pos, count, ref, expected);
					dt_fail(i, "strnlen_user vs independent oracle", d);
				}
			}
		}

		/* --- strncpy_from_user --- */
		{
			struct dt_buf dc, drs;
			long ref, rs;

			dt_buf_init(&dc, count > 0 ? (size_t)count : 0, 0xC0);
			dt_buf_init(&drs, count > 0 ? (size_t)count : 0, 0xC0);
			dt_buf_poison(&dc);
			dt_buf_poison(&drs);

			ref = strncpy_from_user_c_ref((char *)dc.p, (const char *)str, count);
			rs = strncpy_from_user((char *)drs.p, (const char *)str, count);

			if (prove_can_fail)
				rs ^= 1;

			dt_checks++;
			if (ref != rs) {
				char d[160];
				snprintf(d, sizeof d,
					 "len=%lu nul=%d@%lu fault=%d@%ld count=%ld ref=%ld rs=%ld",
					 len, has_nul, nul_pos, has_fault, fault_index,
					 count, ref, rs);
				dt_fail(i, "strncpy_from_user ret", d);
			}

			dt_cmp_buf(i, "strncpy_from_user", "dst", &dc, &drs);

			if (!has_fault && real_nul >= 0 && real_nul < count && ref >= 0) {
				long expected = real_nul;

				strncpy_oracle_checks++;
				dt_checks++;
				if (ref != expected ||
				    memcmp(dc.p, str, (size_t)real_nul) != 0 ||
				    dc.p[real_nul] != 0) {
					char d[160];
					snprintf(d, sizeof d,
						 "len=%lu real_nul=%ld count=%ld ref=%ld expected=%ld",
						 len, real_nul, count, ref, expected);
					dt_fail(i, "strncpy_from_user vs independent oracle", d);
				}
			}

			free(dc.base);
			free(drs.base);
		}
	}

	free(base);

	printf("uaccess-string: %lu cases, %lu checks, %lu fails "
	       "(%lu strnlen + %lu strncpy independent-oracle checks)\n",
	       i, dt_checks, dt_fails, strnlen_oracle_checks, strncpy_oracle_checks);

	return dt_fails ? 1 : 0;
}
