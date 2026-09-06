/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Differential test for lib/ratelimit.c -> lib/ratelimit_rs.rs.
 *
 * THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied -- so is
 * the retained C thunk (lib/ratelimit.c: rust_ratelimit_warn_once(),
 * rust_ratelimit_trylock_irqsave()/unlock_irqrestore()). Only the ORACLE
 * side is the pristine C, renamed via -D to avoid colliding with the real,
 * unrenamed ___ratelimit() the Rust side calls into.
 *
 * jiffies is the ONE shared knob (shim.c) driving both arms' time -- same
 * shape as the uaccess harness's g_fault_at. Neither arm's spinlock/atomic
 * shims reproduce real concurrency (single-threaded test; see shim/linux/
 * {spinlock,atomic}.h) -- what this harness verifies is ___ratelimit()'s
 * own arithmetic and control flow, not the qspinlock algorithm or atomic_t
 * ordering, which neither arm reimplements.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <linux/ratelimit_types.h>

extern int ratelimit_c_ref(struct ratelimit_state *rs, const char *func);

extern volatile unsigned long jiffies;
extern char g_printk_buf[256];
extern int g_printk_calls;

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

static unsigned long dt_fails, dt_checks;

static void dt_fail(unsigned long scenario, unsigned long call, const char *what,
		    const char *detail)
{
	fprintf(stderr, "MISMATCH scenario %lu call %lu: %s: %s\n", scenario, call, what, detail);
	if (++dt_fails >= 20) {
		fprintf(stderr, "too many mismatches, stopping\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	unsigned long scenarios = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
	int prove_can_fail = getenv("RATELIMIT_PROVE_CAN_FAIL") != NULL;
	unsigned long s;

	rng_state = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) : 20260906u;
	if (rng_state == 0)
		rng_state = 1;

	for (s = 0; s < scenarios && dt_fails < 20; s++) {
		struct ratelimit_state rs_c, rs_rs;
		int interval, burst;
		unsigned long calls = rnd(40) + 1;
		unsigned long c;

		/* Edge cases (negative/zero interval or burst) alongside the
		 * ordinary case -- ___ratelimit()'s "never/always limit"
		 * branch is a real, separate control path. */
		switch (rnd(4)) {
		case 0:
			interval = (int)rnd(20) - 5; /* can be negative */
			burst = (int)rnd(20) - 5;
			break;
		case 1:
			interval = 0;
			burst = (int)rnd(10) - 2;
			break;
		default:
			interval = (int)rnd(50) + 1;
			burst = (int)rnd(8) + 1;
			break;
		}

		memset(&rs_c, 0, sizeof rs_c);
		memset(&rs_rs, 0, sizeof rs_rs);
		rs_c.interval = rs_rs.interval = interval;
		rs_c.burst = rs_rs.burst = burst;

		jiffies = rnd(1000000);

		for (c = 0; c < calls && dt_fails < 20; c++) {
			int ref, rs;
			char printk_c[256], printk_rs[256];
			int calls_c, calls_rs;

			/* Advance time unevenly: sometimes nothing, sometimes
			 * past several intervals -- both matter to the
			 * window-reset branch. */
			jiffies += rnd(4) ? rnd(interval > 0 ? (unsigned)interval * 3 + 1 : 50)
					   : 0;

			g_printk_calls = 0;
			ref = ratelimit_c_ref(&rs_c, "test");
			calls_c = g_printk_calls;
			memcpy(printk_c, g_printk_buf, sizeof printk_c);

			g_printk_calls = 0;
			rs = ___ratelimit(&rs_rs, "test");
			calls_rs = g_printk_calls;
			memcpy(printk_rs, g_printk_buf, sizeof printk_rs);

			if (prove_can_fail)
				rs ^= 1;

			dt_checks++;
			if (ref != rs) {
				char d[128];

				snprintf(d, sizeof d,
					 "interval=%d burst=%d jiffies=%lu ref=%d rs=%d",
					 interval, burst, jiffies, ref, rs);
				dt_fail(s, c, "___ratelimit return", d);
				continue;
			}

			dt_checks++;
			if (memcmp(&rs_c, &rs_rs, sizeof rs_c) != 0) {
				dt_fail(s, c, "ratelimit_state", "byte content differs");
				continue;
			}

			dt_checks++;
			if (calls_c != calls_rs || (calls_c && strcmp(printk_c, printk_rs) != 0)) {
				char d[600];

				snprintf(d, sizeof d, "calls ref=%d rs=%d | ref=\"%s\" rs=\"%s\"",
					 calls_c, calls_rs, printk_c, printk_rs);
				dt_fail(s, c, "printk_deferred", d);
			}
		}
	}

	printf("ratelimit: %lu scenarios, %lu checks, %lu fails\n", s, dt_checks, dt_fails);

	return dt_fails ? 1 : 0;
}
