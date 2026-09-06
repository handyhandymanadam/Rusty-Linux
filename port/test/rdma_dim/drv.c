// port/test/rdma_dim/drv.c -- end-to-end differential for rdma_dim(),
// per the adversary's design (review of dc181d0/a5540e5): drive the whole
// EXPORTED function on both arms over a shared struct dim, compare the
// entire struct after each call. Reaches is_significant_diff, both
// fallthroughs, and the nevents site without exposing any private helper --
// and would have caught the nevents bug in its first ~2016 random event
// counter values, per the adversary's own characterization.
//
// rdma_dim_c_ref/dim_*_c_ref are the pristine C (dim.c + rdma_dim.c
// compiled together with -D renames, see run.sh), so the C side's internal
// calls from rdma_dim.c into dim.c stay self-consistent. rdma_dim/dim_* are
// the Rust side's real, unrenamed exported names.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "shim/linux/dim.h"

extern void rdma_dim_c_ref(struct dim *dim, u64 completions);
extern void rdma_dim(struct dim *dim, u64 completions);

static int steps_run, mismatches;

static void reset_dim(struct dim *d) {
	memset(d, 0, sizeof(*d));
	// DIM_START_MEASURE == 0, DIM_PARKING_ON_TOP == 0: an all-zero
	// struct dim is exactly a freshly allocated/kzalloc'd one, the real
	// starting state every caller begins from.
}

// A fixed, meaningful diff so a real mismatch is diagnosable rather than
// just "differs somewhere".
static void report_diff(const struct dim *c, const struct dim *r, u64 completions, int step) {
	fprintf(stderr, "MISMATCH at step %d, completions=%llu\n", step, (unsigned long long)completions);
#define F(field, fmt) if (c->field != r->field) fprintf(stderr, "  ." #field ": C=" fmt " Rust=" fmt "\n", c->field, r->field)
	F(state, "%u"); F(profile_ix, "%u"); F(mode, "%u"); F(tune_state, "%u");
	F(steps_right, "%u"); F(steps_left, "%u"); F(tired, "%u");
#undef F
	if (memcmp(&c->prev_stats, &r->prev_stats, sizeof(c->prev_stats)) != 0)
		fprintf(stderr, "  .prev_stats differs\n");
	if (memcmp(&c->start_sample, &r->start_sample, sizeof(c->start_sample)) != 0)
		fprintf(stderr, "  .start_sample differs\n");
	if (memcmp(&c->measuring_sample, &r->measuring_sample, sizeof(c->measuring_sample)) != 0)
		fprintf(stderr, "  .measuring_sample differs\n");
}

// One test sequence: fresh dim on both sides, `n` calls to rdma_dim with
// the same (completions, tick) inputs and an identical ktime_get()
// sequence per call (checkpoint/replay via g_fake_time, see ktime_shim.c).
static void run_sequence(int n, unsigned *seed) {
	struct dim dc, dr;
	reset_dim(&dc);
	reset_dim(&dr);

	for (int i = 0; i < n; i++) {
		u64 completions = (u64)(rand_r(seed) % 2000);
		// Vary the tick size across a wide range, including boundary
		// values around the u32 ns->us truncation and near-zero
		// jumps, so both dim_calc_stats' delta_us edge and the
		// nevents edge get exercised over a run.
		int64_t tick;
		switch (rand_r(seed) % 6) {
			case 0: tick = 0; break;
			case 1: tick = 1; break;
			case 2: tick = (int64_t)(rand_r(seed) % 100000); break;
			case 3: tick = 1000LL * (1LL << 32); break; // ~71.6min in ns
			case 4: tick = -(int64_t)(rand_r(seed) % 1000); break; // backwards
			default: tick = (int64_t)(rand_r(seed) % 1000000000); break;
		}

		ktime_t checkpoint = g_fake_time;
		g_fake_time = checkpoint;
		// (tick is a per-call increment ktime_get() itself doesn't
		// know about; we approximate a real clock by advancing the
		// checkpoint ourselves between calls, then replaying the
		// SAME checkpoint for both sides below.)
		g_fake_time += tick;
		ktime_t call_time = g_fake_time;

		g_fake_time = call_time;
		rdma_dim_c_ref(&dc, completions);
		g_fake_time = call_time;
		rdma_dim(&dr, completions);

		steps_run++;
		if (memcmp(&dc, &dr, sizeof(dc)) != 0) {
			mismatches++;
			report_diff(&dc, &dr, completions, i);
		}
	}
}

// Directed: seed start_sample.event_ctr near the u16 wrap boundary and
// dim->state = DIM_MEASURE_IN_PROGRESS, so the very next call's nevents
// check exercises curr < start with a small 16-bit distance -- the exact
// shape a plain random walk from a zeroed dim essentially never reaches
// (needs ~65536 calls in one continuous sequence to wrap naturally).
// port/test/interval_tree/'s directed-stage precedent, cited by the
// adversary: a boundary has to be built, not waited for.
static void run_directed_wrap_sequence(unsigned *seed) {
	for (u16 start_ec = 65470; start_ec != 0; start_ec++) {
		for (int delta = -3; delta <= 66; delta++) {
			struct dim dc, dr;
			reset_dim(&dc);
			reset_dim(&dr);
			dc.state = dr.state = DIM_MEASURE_IN_PROGRESS;
			dc.start_sample.event_ctr = dr.start_sample.event_ctr = start_ec;
			u16 curr_ec = (u16)(start_ec + delta);
			dc.measuring_sample.event_ctr = dr.measuring_sample.event_ctr = curr_ec;
			// rdma_dim() increments measuring_sample.event_ctr by 1
			// before the nevents check, so the check actually sees
			// curr_ec + 1 -- pre-bias by -1 so `delta` above is the
			// nevents distance actually tested.
			dc.measuring_sample.event_ctr--;
			dr.measuring_sample.event_ctr--;

			u64 completions = (u64)(rand_r(seed) % 2000);
			g_fake_time = 1000000; // nonzero, so delta_us != 0 if stats do run
			rdma_dim_c_ref(&dc, completions);
			g_fake_time = 1000000;
			rdma_dim(&dr, completions);

			steps_run++;
			if (memcmp(&dc, &dr, sizeof(dc)) != 0) {
				mismatches++;
				fprintf(stderr, "DIRECTED MISMATCH start_ec=%u delta=%d\n", start_ec, delta);
				report_diff(&dc, &dr, completions, delta);
			}
		}
		if (start_ec == 65535) break; // avoid infinite loop at u16 max
	}
}

int main(int argc, char **argv) {
	long n_sequences = argc > 1 ? atol(argv[1]) : 20000;
	unsigned seed = argc > 2 ? (unsigned)atol(argv[2]) : 20260906;
	int steps_per_seq = 20;

	run_directed_wrap_sequence(&seed);

	for (long s = 0; s < n_sequences; s++) {
		unsigned seq_seed = seed + (unsigned)s;
		run_sequence(steps_per_seq, &seq_seed);
	}

	if (getenv("RDMA_DIM_PROVE_CAN_FAIL")) {
		struct dim dc, dr;
		reset_dim(&dc); reset_dim(&dr);
		g_fake_time = 0;
		rdma_dim_c_ref(&dc, 100);
		g_fake_time = 0;
		rdma_dim(&dr, 100);
		dr.profile_ix ^= 1; // corrupt on purpose
		if (memcmp(&dc, &dr, sizeof(dc)) != 0) {
			fprintf(stderr, "PROVE_CAN_FAIL_VERDICT: mismatch correctly detected\n");
			return 1;
		}
		fprintf(stderr, "PROVE_CAN_FAIL_VERDICT: poison had no effect\n");
		return 0;
	}

	fprintf(stderr, "%d steps (%ld sequences x %d), %d mismatches\n",
		steps_run, n_sequences, steps_per_seq, mismatches);
	return mismatches ? 1 : 0;
}
