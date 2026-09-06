/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Differential test for lib/flex_proportions.c -> lib/flex_proportions_rs.rs.
 *
 * THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied -- so is
 * the retained C thunk (lib/flex_proportions.c: rust_flexprop_lock_irqsave()/
 * unlock_irqrestore()/lock_init()). Only the ORACLE side is the pristine C,
 * renamed via -D.
 *
 * fprop_new_period() ITSELF cannot be called here at all: its real, shipped
 * Rust body executes genuine cli/sti (core::arch::asm!, matching
 * arch_local_irq_save()/restore() exactly) -- privileged instructions that
 * fault immediately in userspace (ring 3). flex_proportions_rs.rs splits the
 * irq-save-protected body into fprop_new_period_locked() for exactly this
 * reason (see that file's own doc comment) -- a real, #[no_mangle] symbol,
 * not a test-only stub, called from fprop_new_period() in the same place its
 * own body used to occupy. This harness calls THAT directly, doing the
 * caller-side percpu_counter_sum()+early-return dance itself (the same shim
 * percpu_counter_sum() both arms already use) rather than the outer wrapper.
 * The real, assembled fprop_new_period() -- irq-save and all -- is verified
 * by sabotage-and-reboot in ring 0 instead, where cli/sti are not a problem.
 * Every OTHER function here calls the real, unrenamed Rust symbol directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <linux/flex_proportions.h>

extern int fprop_global_init_c_ref(struct fprop_global *p, gfp_t gfp);
extern void fprop_global_destroy_c_ref(struct fprop_global *p);
extern bool fprop_new_period_c_ref(struct fprop_global *p, int periods);
extern int fprop_local_init_percpu_c_ref(struct fprop_local_percpu *pl, gfp_t gfp);
extern void fprop_local_destroy_percpu_c_ref(struct fprop_local_percpu *pl);
extern void fprop_add_percpu_c_ref(struct fprop_global *p, struct fprop_local_percpu *pl, long nr);
extern void fprop_add_percpu_max_c_ref(struct fprop_global *p, struct fprop_local_percpu *pl,
					int max_frac, long nr);
extern void fprop_fraction_percpu_c_ref(struct fprop_global *p, struct fprop_local_percpu *pl,
					 unsigned long *numerator, unsigned long *denominator);

/* Real, unrenamed Rust symbols. */
extern void fprop_new_period_locked(struct fprop_global *p, int periods, long long events);

unsigned int nr_cpu_ids = 4;

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

static long rnd_signed(long bound)
{
	return (long)rnd((uint32_t)(2 * bound)) - bound;
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

static void cmp_globals(unsigned long s, unsigned long c, struct fprop_global *gc,
			struct fprop_global *gr)
{
	dt_checks++;
	if (memcmp(gc, gr, sizeof *gc) != 0)
		dt_fail(s, c, "fprop_global", "byte content differs");
}

static void cmp_locals(unsigned long s, unsigned long c, struct fprop_local_percpu *lc,
		       struct fprop_local_percpu *lr)
{
	dt_checks++;
	if (memcmp(lc, lr, sizeof *lc) != 0)
		dt_fail(s, c, "fprop_local_percpu", "byte content differs");
}

int main(int argc, char **argv)
{
	unsigned long scenarios = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
	int prove_can_fail = getenv("FLEXPROP_PROVE_CAN_FAIL") != NULL;
	unsigned long s;

	rng_state = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) : 20260906u;
	if (rng_state == 0)
		rng_state = 1;

	for (s = 0; s < scenarios && dt_fails < 20; s++) {
		struct fprop_global gc, gr;
		struct fprop_local_percpu lc, lr;
		unsigned long calls = rnd(30) + 1;
		unsigned long c;

		fprop_global_init_c_ref(&gc, 0);
		fprop_global_init(&gr, 0);
		fprop_local_init_percpu_c_ref(&lc, 0);
		fprop_local_init_percpu(&lr, 0);
		cmp_globals(s, 0, &gc, &gr);
		cmp_locals(s, 0, &lc, &lr);

		for (c = 0; c < calls && dt_fails < 20; c++) {
			switch (rnd(4)) {
			case 0: {
				long nr = rnd_signed(1000);

				fprop_add_percpu_c_ref(&gc, &lc, nr);
				__fprop_add_percpu(&gr, &lr, nr);
				break;
			}
			case 1: {
				long nr = rnd_signed(1000);
				int max_frac = (int)rnd(1024);

				fprop_add_percpu_max_c_ref(&gc, &lc, max_frac, nr);
				__fprop_add_percpu_max(&gr, &lr, max_frac, nr);
				break;
			}
			case 2: {
				unsigned long num_c, den_c, num_r, den_r;

				fprop_fraction_percpu_c_ref(&gc, &lc, &num_c, &den_c);
				fprop_fraction_percpu(&gr, &lr, &num_r, &den_r);

				dt_checks++;
				if (num_c != num_r || den_c != den_r) {
					char d[128];

					snprintf(d, sizeof d, "num=%lu/%lu vs %lu/%lu",
						 num_c, den_c, num_r, den_r);
					dt_fail(s, c, "fprop_fraction_percpu", d);
				}
				break;
			}
			default: {
				int periods = (int)rnd(8) + 1;
				long long events_r = percpu_counter_sum(&gr.events);
				bool ret_c, ret_r;

				ret_c = fprop_new_period_c_ref(&gc, periods);
				if (events_r <= 1) {
					ret_r = false;
				} else {
					fprop_new_period_locked(&gr, periods, events_r);
					ret_r = true;
				}
				if (prove_can_fail)
					ret_r = !ret_r;

				dt_checks++;
				if (ret_c != ret_r) {
					char d[128];

					snprintf(d, sizeof d, "periods=%d ref=%d rs=%d",
						 periods, ret_c, ret_r);
					dt_fail(s, c, "fprop_new_period", d);
				}
				break;
			}
			}

			cmp_globals(s, c, &gc, &gr);
			cmp_locals(s, c, &lc, &lr);
		}

		fprop_local_destroy_percpu_c_ref(&lc);
		fprop_local_destroy_percpu(&lr);
		fprop_global_destroy_c_ref(&gc);
		fprop_global_destroy(&gr);
	}

	printf("flex_proportions: %lu scenarios, %lu checks, %lu fails\n", s, dt_checks, dt_fails);

	return dt_fails ? 1 : 0;
}
