/* SPDX-License-Identifier: GPL-2.0
 *
 * The shared measuring rig (GOALS.md §4).
 *
 * ONE binary, both arms inside it, chosen at runtime. That is not a style
 * choice: PRIOR-ART.md §1 records a control reading 0.825 on a callee that
 * was BYTE-IDENTICAL in both arms, purely because the two arms were separate
 * binaries laid out differently in memory. Re-measured on a second rig it was
 * 0.982/0.985 -- about 1.5-1.8%, ten times the run-to-run noise, and always
 * favouring Rust. One binary removes THAT bias -- the cross-BINARY one -- by
 * construction rather than by care.
 *
 * IT DOES NOT REMOVE LAYOUT BIAS, and an earlier version of this comment
 * implied it did. STABILIZER (Curtsinger & Berger) is explicit: "A single
 * binary constitutes just one sample from the space of program layouts,
 * REGARDLESS OF THE NUMBER OF RUNS," and "two versions of a program,
 * regardless of the number of runs, are only two samples from the
 * distribution over possible layouts." PRODUCING WRONG DATA WITHOUT DOING
 * ANYTHING OBVIOUSLY WRONG supplies the magnitude: changing only link order,
 * with no code change at all, moved an O2-vs-O3 speedup ratio by up to 15
 * PERCENTAGE POINTS, and reversed the sign of the effect for five of twelve
 * SPEC benchmarks.
 *
 * So a systematic alignment or cache-conflict advantage for one arm, baked
 * into the single build this rig produces, sails through 7 reps or 7000
 * unnoticed -- repetitions sample timing noise, not layout. --control cannot
 * see it either, because both slots then hold the SAME code at the SAME
 * address, so there is no arm-versus-arm placement difference left to sample.
 *
 * The honest position: this rig controls cross-binary bias and timing noise,
 * and does NOT control layout bias. Doing so would need many separately-linked
 * binaries with randomised layout, treated as another level in the variance
 * model. Not built. Any figure from here carries that caveat.
 *
 * The second recorded error was startup dilution: a harness that timed the
 * whole process counted 193,720 cycles of startup into every measurement, so
 * at typical iteration counts everything was flattened toward 1.000. Here
 * only the loop is timed, and the iteration count is chosen per benchmark so
 * that the whole run takes long enough for the clock's resolution and any
 * fixed overhead to be under 1% of it.
 *
 * ONE rig for all modules, not one per module (GOALS.md §7). A benchmark is
 * a row in the table at the bottom, not a new program.
 *
 * THE CONTROL COMES FIRST. Run with --control and both arms are pointed at
 * the SAME function. Whatever deviation appears is the kerf, by definition,
 * and no theory is required. Any measurement is meaningless until that number
 * is known, so --control is what the runner does before anything else.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- timing ----------------------------------------------------------- */

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/* A PERCENTILE BOOTSTRAP CONFIDENCE INTERVAL on the median paired ratio.
 *
 * The first attempt at fixing this rig reported the min and max of the sorted
 * ratios as if they were bounds. Jain, THE ART OF COMPUTER SYSTEMS PERFORMANCE
 * ANALYSIS §12.7, disqualifies exactly that: "In most cases, the range is not
 * very useful... there is no 'stable' point that gives a good indication of
 * the actual range. The conclusion is that the range is useful if and only if
 * there is a reason to believe that the variable is bounded." Execution-time
 * noise is not bounded -- it has a long right tail from interrupts and
 * frequency events and none on the fast side -- so a min/max range simply
 * WIDENS as reps grows. It converges to nothing, and two runs at different
 * reps cannot be compared on it.
 *
 * Jain's own decision tree points at percentiles for a non-symmetric
 * distribution, and Kalibera & Jones (QUANTIFYING PERFORMANCE CHANGES WITH
 * EFFECT SIZE CONFIDENCE INTERVALS) give the bootstrap for precisely this
 * shape of data, noting it "works for additional metrics, such as the median,
 * as well as the mean".
 *
 * What this buys that a range does not: a checkable claim. "The interval
 * excludes 1.0" is a statement about the port. "The max was 1.02" is not.
 */
#define BOOT_RESAMPLES 10000

static uint64_t boot_rng_state = 0x9E3779B97F4A7C15ULL;

static uint64_t boot_rand(void)
{
	uint64_t x = boot_rng_state;

	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	boot_rng_state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

static double median_of(const double *sorted, int n)
{
	return n & 1 ? sorted[n / 2]
		     : 0.5 * (sorted[n / 2 - 1] + sorted[n / 2]);
}

/* Fills lo/hi with the 2.5th and 97.5th percentiles of the bootstrap
 * distribution of the median. `ratios` must already be sorted. */
static void bootstrap_ci(const double *ratios, int n, double *lo, double *hi)
{
	double *meds = malloc(BOOT_RESAMPLES * sizeof(double));
	double *samp = malloc((size_t)n * sizeof(double));
	int b, i;

	if (!meds || !samp) { *lo = *hi = 0.0; free(meds); free(samp); return; }
	for (b = 0; b < BOOT_RESAMPLES; b++) {
		for (i = 0; i < n; i++)
			samp[i] = ratios[boot_rand() % (uint64_t)n];
		qsort(samp, (size_t)n, sizeof(double), cmp_double);
		meds[b] = median_of(samp, n);
	}
	qsort(meds, BOOT_RESAMPLES, sizeof(double), cmp_double);
	*lo = meds[(int)(0.025 * BOOT_RESAMPLES)];
	*hi = meds[(int)(0.975 * BOOT_RESAMPLES)];
	free(meds); free(samp);
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* ---- the arms --------------------------------------------------------- */

/*
 * Every benchmark is a function that runs `iters` iterations and returns a
 * value derived from the work, so the optimiser cannot delete the loop. The
 * returned value is accumulated and printed, which is the cheapest reliable
 * way to keep the work alive without a compiler barrier per iteration.
 */
typedef uint64_t (*arm_fn)(unsigned long iters, void *ctx);

struct bench {
	const char *name;
	arm_fn c_arm;
	arm_fn rust_arm;
	void *(*setup)(void);
	unsigned long iters;
};

/* ---- glob ------------------------------------------------------------- */

bool ref_glob_match_str(const char *pat, const char *str, const char *end);
bool rust_glob_match_str(const char *pat, const char *str, const char *end);

static const char *glob_pat = "*a*b*[bc]*[ef]*g*";
static const char *glob_str = "abacadaeafag";

static uint64_t glob_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	(void)ctx;
	for (unsigned long i = 0; i < n; i++)
		acc += ref_glob_match_str(glob_pat, glob_str, NULL);
	return acc;
}

static uint64_t glob_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	(void)ctx;
	for (unsigned long i = 0; i < n; i++)
		acc += rust_glob_match_str(glob_pat, glob_str, NULL);
	return acc;
}

/* ---- int_sqrt --------------------------------------------------------- */

unsigned long ref_int_sqrt(unsigned long x);
unsigned long rust_int_sqrt(unsigned long x);

static uint64_t isqrt_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	(void)ctx;
	for (unsigned long i = 0; i < n; i++)
		acc += ref_int_sqrt(i * 2654435761u + 1);
	return acc;
}

static uint64_t isqrt_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	(void)ctx;
	for (unsigned long i = 0; i < n; i++)
		acc += rust_int_sqrt(i * 2654435761u + 1);
	return acc;
}

/* ---- crc16 over 4 KiB -------------------------------------------------- */

uint16_t ref_crc16(uint16_t crc, const uint8_t *p, size_t len);
uint16_t rust_crc16(uint16_t crc, const uint8_t *p, size_t len);

static uint8_t big[4096];

static void *setup_big(void)
{
	for (size_t i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 131 + 7);
	return big;
}

static uint64_t crc16_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += ref_crc16(0, ctx, sizeof(big));
	return acc;
}

static uint64_t crc16_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += rust_crc16(0, ctx, sizeof(big));
	return acc;
}

/* ---- xxh64 over 4 KiB -------------------------------------------------- */

uint64_t ref_xxh64(const void *input, size_t len, uint64_t seed);
int ref_check_signature(const volatile void *io, const unsigned char *sig, int len);
int rust_check_signature(const volatile void *io, const unsigned char *sig, int len);
uint64_t rust_xxh64(const void *input, size_t len, uint64_t seed);

static uint64_t xxh64_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += ref_xxh64(ctx, sizeof(big), i);
	return acc;
}

static uint64_t xxh64_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += rust_xxh64(ctx, sizeof(big), i);
	return acc;
}

/* ---- memweight over 4 KiB ---------------------------------------------- */

size_t ref_memweight(const void *ptr, size_t bytes);
size_t rust_memweight(const void *ptr, size_t bytes);

static uint64_t memw_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += ref_memweight(ctx, sizeof(big));
	return acc;
}

static uint64_t memw_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += rust_memweight(ctx, sizeof(big));
	return acc;
}

/* ---- chacha20 block ---------------------------------------------------- */

struct chacha_state { uint32_t x[16]; };
void ref_chacha_block_generic(struct chacha_state *s, uint8_t *out, int n);
void rust_chacha_block_generic(struct chacha_state *s, uint8_t *out, int n);

static uint64_t cha_c(unsigned long n, void *ctx)
{
	struct chacha_state st;
	uint8_t out[64];
	uint64_t acc = 0;

	(void)ctx;
	memset(&st, 0x5a, sizeof(st));
	for (unsigned long i = 0; i < n; i++) {
		ref_chacha_block_generic(&st, out, 20);
		acc += out[0];
	}
	return acc;
}

static uint64_t cha_rust(unsigned long n, void *ctx)
{
	struct chacha_state st;
	uint8_t out[64];
	uint64_t acc = 0;

	(void)ctx;
	memset(&st, 0x5a, sizeof(st));
	for (unsigned long i = 0; i < n; i++) {
		rust_chacha_block_generic(&st, out, 20);
		acc += out[0];
	}
	return acc;
}

/* check_signature: a 4 KiB window that matches all the way to the end, which
 * is the loop's worst case and the only one that measures the per-byte cost.
 * The C's readb() inlines to a load; the Rust calls the helper per byte. That
 * gap IS the thing being measured -- see rig/perf/stubs.c. */
static uint64_t sig_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += (uint64_t)ref_check_signature(ctx, ctx, 4096);
	return acc;
}

static uint64_t sig_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += (uint64_t)rust_check_signature(ctx, ctx, 4096);
	return acc;
}

/* ---- zlib_inflate, in rig/perf/bench_zlib.c ---------------------------- */

/* SEVEN rows, not one. PRIOR-ART.md §5 records a twelve-fold spread on a
 * decompressor across corpus inputs, so a single number in this family means
 * almost nothing; the spread is the measurement. See bench_zlib.c for what
 * each corpus is and for why the ratio is diluted toward 1. */
uint64_t zinf_c(unsigned long n, void *ctx);
uint64_t zinf_rust(unsigned long n, void *ctx);
void *zsetup_0(void);
void *zsetup_1(void);
void *zsetup_2(void);
void *zsetup_3(void);
void *zsetup_4(void);
void *zsetup_5(void);
void *zsetup_6(void);

/* ---- lzo, in rig/perf/bench_lzo.c -------------------------------------- */

/* Six rows for the same reason the inflate ones are seven. NOT comparable to
 * the inflate rows: those time a whole inflate cycle around the ported
 * function because it cannot be called alone, these time the ported function
 * and nothing else. */
uint64_t lzo_c(unsigned long n, void *ctx);
uint64_t lzo_rust(unsigned long n, void *ctx);
void *lsetup_0(void);
void *lsetup_1(void);
void *lsetup_2(void);
void *lsetup_3(void);
void *lsetup_4(void);
void *lsetup_5(void);

/* ---- the table --------------------------------------------------------- */

static struct bench benches[] = {
	{ "glob_match",   glob_c,   glob_rust,   NULL,      2000000 },
	{ "int_sqrt",     isqrt_c,  isqrt_rust,  NULL,     20000000 },
	{ "crc16_4k",     crc16_c,  crc16_rust,  setup_big,   40000 },
	{ "xxh64_4k",     xxh64_c,  xxh64_rust,  setup_big,  200000 },
	{ "memweight_4k", memw_c,   memw_rust,   setup_big,  200000 },
	{ "chacha20_blk", cha_c,    cha_rust,    NULL,      2000000 },
	{ "checksig_4k",  sig_c,    sig_rust,    setup_big,   100000 },
	{ "inflate_run",  zinf_c,   zinf_rust,   zsetup_0,       200 },
	{ "inflate_per3", zinf_c,   zinf_rust,   zsetup_1,       200 },
	{ "inflate_per16",zinf_c,   zinf_rust,   zsetup_2,       200 },
	{ "inflate_text", zinf_c,   zinf_rust,   zsetup_3,       200 },
	{ "inflate_lit",  zinf_c,   zinf_rust,   zsetup_4,       200 },
	{ "inflate_long", zinf_c,   zinf_rust,   zsetup_5,       200 },
	{ "inflate_wind", zinf_c,   zinf_rust,   zsetup_6,       200 },
	{ "lzo_run",      lzo_c,    lzo_rust,    lsetup_0,       400 },
	{ "lzo_per3",     lzo_c,    lzo_rust,    lsetup_1,       400 },
	{ "lzo_text",     lzo_c,    lzo_rust,    lsetup_2,       400 },
	{ "lzo_lit",      lzo_c,    lzo_rust,    lsetup_3,       400 },
	{ "lzo_long",     lzo_c,    lzo_rust,    lsetup_4,       400 },
	{ "lzo_zeros",    lzo_c,    lzo_rust,    lsetup_5,       400 },
};

/* ---- driver ------------------------------------------------------------ */

static double best_of(arm_fn f, unsigned long iters, void *ctx, int reps, uint64_t *sink)
{
	double best = 1e30;

	for (int r = 0; r < reps; r++) {
		double t0 = now_s();
		uint64_t v = f(iters, ctx);
		double dt = now_s() - t0;

		*sink += v;
		if (dt < best)
			best = dt;
	}
	return best;
}

int main(int argc, char **argv)
{
	bool control = argc > 1 && !strcmp(argv[1], "--control");
	int reps = argc > 2 ? atoi(argv[2]) : 7;
	uint64_t sink = 0;

	/* REFUSE TO PRINT A TIMING NEVER MEASURED. With reps < 1 the loops
	 * below never run and every row printed best_of()'s 1e30 initial
	 * value -- a number the instrument had not measured, formatted like
	 * one it had. That is exactly what GOALS.md §4 exists to prevent, and
	 * it reached the terminal once (via run.sh passing --kerf-only
	 * through as the repetition count, since fixed). Closing the argument
	 * path would leave the class open; this closes the class. */
	if (reps < 1) {
		fprintf(stderr, "bench: reps must be >= 1, got %d\n", reps);
		return 2;
	}

	/* Minimum wall time per repetition, in seconds. Below this the clock
	 * resolution and any fixed per-call overhead stop being negligible,
	 * which is the startup-dilution error in a different costume. */
	const double min_s = 0.05;

	printf("%-14s %10s %10s %8s %-18s %s\n",
	       "benchmark", "c_s", "rust_s", "median", "95% CI (bootstrap)",
	       control ? "(CONTROL: both arms are the C arm)" : "");

	for (unsigned b = 0; b < sizeof(benches) / sizeof(benches[0]); b++) {
		struct bench *bn = &benches[b];
		void *ctx = bn->setup ? bn->setup() : NULL;
		arm_fn arm_a = bn->c_arm;
		arm_fn arm_b = control ? bn->c_arm : bn->rust_arm;
		unsigned long iters = bn->iters;
		double ta;

		/* Scale up until a repetition is long enough to measure. */
		for (;;) {
			ta = best_of(arm_a, iters, ctx, 1, &sink);
			if (ta >= min_s || iters > (1UL << 40))
				break;
			iters *= 4;
		}

		/* Interleave the arms rep by rep so that thermal drift and
		 * frequency scaling hit both equally, and keep a PAIRED ratio
		 * per repetition rather than dividing two separately-taken
		 * minima.
		 *
		 * WHY AN INTERVAL, AND NOT A SINGLE NUMBER. This reported one
		 * ratio per benchmark until 2026-09-04 -- a point estimate,
		 * recorded as an open defect since 2026-09-03, and the reason
		 * everything under rig/perf/ was marked NOT CITABLE. A lone
		 * ratio cannot be read: 1.0099 means nothing until you know
		 * whether repeated measurement of the SAME code wanders by
		 * 0.1% or by 5%. The median and the spread below give that,
		 * and running with --control (both arms are the C arm) prints
		 * the instrument's own noise floor. A delta smaller than the
		 * control's spread is not a delta. */
		{
			double *ratios = malloc((size_t)reps * sizeof(double));
			double *as = malloc((size_t)reps * sizeof(double));
			double *bs = malloc((size_t)reps * sizeof(double));
			double lo, hi;

			if (!ratios || !as || !bs) {
				fprintf(stderr, "bench: out of memory\n");
				return 2;
			}
			/* Warm BOTH arms before timing either. The scaling loop
			 * above only ever calls arm_a, so arm_b used to enter
			 * the timed loop cold -- a first-touch asymmetry
			 * between the two arms, and one Gernot's list names. */
			(void)best_of(arm_b, iters, ctx, 1, &sink);
			for (int r = 0; r < reps; r++) {
				double x = best_of(arm_a, iters, ctx, 1, &sink);
				double y = best_of(arm_b, iters, ctx, 1, &sink);

				as[r] = x; bs[r] = y;
				ratios[r] = y / x;
			}
			qsort(ratios, (size_t)reps, sizeof(double), cmp_double);
			bootstrap_ci(ratios, reps, &lo, &hi);

			/* The printed times are the MEDIANS of the same paired
			 * samples the ratio comes from, not each arm's own
			 * minimum. The previous version printed per-arm minima
			 * beside a median-of-ratios, so a reader dividing the
			 * two printed numbers did not get the printed ratio --
			 * a silently broken sanity check, which is the shape
			 * Gernot's benchmarking-crimes list warns about. */
			qsort(as, (size_t)reps, sizeof(double), cmp_double);
			qsort(bs, (size_t)reps, sizeof(double), cmp_double);
			printf("%-14s %10.6f %10.6f %8.4f  [%.4f, %.4f]   iters=%lu reps=%d\n",
			       bn->name, median_of(as, reps), median_of(bs, reps),
			       median_of(ratios, reps), lo, hi, iters, reps);
			free(ratios); free(as); free(bs);
		}
	}

	/* Keep the accumulated work alive so nothing above can be elided. */
	fprintf(stderr, "sink %llu\n", (unsigned long long)sink);
	return 0;
}
