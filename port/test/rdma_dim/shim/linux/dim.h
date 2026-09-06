/* Minimal userspace shim for include/linux/dim.h -- just enough for
 * lib/dim/dim.c to compile standalone. Definitions copied verbatim from
 * the real header/macros dim.c actually uses; not a general dim.h stand-in.
 */
#ifndef DIM_H
#define DIM_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "workqueue.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
typedef s64 ktime_t;

#define EXPORT_SYMBOL(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)

#define DIM_NEVENTS 64

#define IS_SIGNIFICANT_DIFF(val, ref) \
	((ref) && (((100UL * abs((val) - (ref))) / (ref)) > 10))

#define BIT_ULL(n) (1ULL << (n))
#define BIT_GAP(bits, end, start) ((((end) - (start)) + BIT_ULL(bits)) \
		& (BIT_ULL(bits) - 1))

#define BITS_PER_TYPE(type) (sizeof(type) * 8)

#define USEC_PER_MSEC 1000L
#define NSEC_PER_USEC 1000L

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP
#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); _tmp /= (uint32_t)(d); _tmp; })

static inline s64 ktime_us_delta(ktime_t later, ktime_t earlier)
{
	return (later - earlier) / NSEC_PER_USEC;
}

/* Driver-controlled fake clock. A plain extern, not static inline -- the
 * Rust side needs a REAL linkable symbol to bind `extern "C" { fn
 * ktime_get() -> i64; }` against, and the C reference must call that same
 * symbol (not its own inlined copy) for both sides to see an identical
 * sequence. Implemented once in ktime_shim.c. */
extern ktime_t g_fake_time;
ktime_t ktime_get(void);

#define fallthrough do {} while (0)
#define RDMA_DIM_PARAMS_NUM_PROFILES 9
#define RDMA_DIM_START_PROFILE 0

struct dim_stats {
	int ppms;
	int bpms;
	int epms;
	int cpms;
	int cpe_ratio;
};

struct dim_sample {
	ktime_t time;
	u32 pkt_ctr;
	u32 byte_ctr;
	u16 event_ctr;
	u32 comp_ctr;
};

enum dim_tune_state {
	DIM_PARKING_ON_TOP,
	DIM_PARKING_TIRED,
	DIM_GOING_RIGHT,
	DIM_GOING_LEFT,
};

enum dim_state {
	DIM_START_MEASURE,
	DIM_MEASURE_IN_PROGRESS,
	DIM_APPLY_NEW_PROFILE,
};

enum dim_stats_state {
	DIM_STATS_WORSE,
	DIM_STATS_SAME,
	DIM_STATS_BETTER,
};

enum dim_step_result {
	DIM_STEPPED,
	DIM_TOO_TIRED,
	DIM_ON_EDGE,
};

struct dim {
	u8 state;
	struct dim_stats prev_stats;
	struct dim_sample start_sample;
	struct dim_sample measuring_sample;
	struct work_struct work;
	void *priv;
	u8 profile_ix;
	u8 mode;
	u8 tune_state;
	u8 steps_right;
	u8 steps_left;
	u8 tired;
};

bool dim_on_top(struct dim *dim);
void dim_turn(struct dim *dim);
void dim_park_on_top(struct dim *dim);
void dim_park_tired(struct dim *dim);
bool dim_calc_stats(const struct dim_sample *start, const struct dim_sample *end,
		     struct dim_stats *curr_stats);
void rdma_dim(struct dim *dim, u64 completions);

static inline void
dim_update_sample(u16 event_ctr, u64 packets, u64 bytes, struct dim_sample *s)
{
	s->time      = ktime_get();
	s->pkt_ctr   = packets;
	s->byte_ctr  = bytes;
	s->event_ctr = event_ctr;
}

static inline void
dim_update_sample_with_comps(u16 event_ctr, u64 packets, u64 bytes, u64 comps,
			      struct dim_sample *s)
{
	dim_update_sample(event_ctr, packets, bytes, s);
	s->comp_ctr = comps;
}

#endif
