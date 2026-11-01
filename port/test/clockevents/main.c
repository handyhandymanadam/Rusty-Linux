/* clockevents differential: the pristine arithmetic-bearing functions (ARM_REF: ref.c extracted from the pristine file) against clockevents_rs.rs plus the glue (ARM_RS: ref.c extracted
 * from clockevents_glue.c), with and without CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST (-DMIN_ADJUST) and HZ 100 / 250 / 1000. Random devices (mult including 0, shift 0..63, tick limits),
 * cev_delta2ns for both ismax values, clockevents_config, clockevents_program_event (every state, KTIME, past and future expiry, force, failing and succeeding set_next_event) and
 * clockevents_increase_min_delta around its thresholds. Prints every result, the device, the printk text and a hash of the callbacks.   usage: t SHARD (env CE_N, CE_PROVE) */
#include "refshim.h"
int warns, hz_ = 1000; ktime_t now_ns; static unsigned long long cb_h; static int cb_n;
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return rs_ >> 11; }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static int mode, left;
static int fake_event(unsigned long clc, struct clock_event_device *d) { cb_h = cb_h * 1000003ULL + clc; cb_n++; if (mode == 0) return 0; if (mode == 1) return rnd(2) ? 0 : -1; if (mode == 2) return -1; return left-- > 0 ? -1 : 0; }
static int fake_ktime(ktime_t e, struct clock_event_device *d) { cb_h = cb_h * 1000003ULL + (unsigned long long)e * 7; cb_n++; return rnd(3) ? 0 : -5; }
#include "clocksrc.c"
#include SRCFILE
static u32 rmult(void) { switch (rnd(6)) { case 0: return 0; case 1: return 1; case 2: return 1u << rnd(32); case 3: return (1u << rnd(32)) + rnd(3) - 1; default: return (u32)rnd64() | 1; } }
static unsigned long rticks(void) { switch (rnd(6)) { case 0: return 0; case 1: return 1 + rnd(100); case 2: return (1UL << (1 + rnd(63))) - 1 + rnd(3); case 3: return 0xffffffffUL + rnd(3) - 1; default: return (unsigned long)rnd64() >> rnd(40); } }
static void pdev(struct clock_event_device *d)
{
	printf(" | mult=%u shift=%u min=%llu max=%llu next=%lld retries=%lu st=%d warns=%d cb=%d/%llx", d->mult, d->shift, (unsigned long long)d->min_delta_ns, (unsigned long long)d->max_delta_ns, (long long)d->next_event, d->retries,
	       d->state_use_accessors, warns, cb_n, cb_h);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("CE_N") ? atol(getenv("CE_N")) : 100000; int prove = getenv("CE_PROVE") != NULL; long i; static const int hzs[] = { 100, 250, 1000 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1); hz_ = hzs[shard / 2 % 3];
	for (i = 0; i < n; i++) {
		struct clock_event_device d; int k = rnd(5); static int pc;
		memset(&d, 0, sizeof d); d.name = rnd(4) ? "tdev" : NULL; d.set_next_event = fake_event; d.set_next_ktime = fake_ktime; d.mult = rmult(); d.shift = rnd(8) ? rnd(40) : rnd(64);
		d.min_delta_ns = rnd(3) ? rnd(20000) : rnd64() >> rnd(50); d.max_delta_ns = rnd(3) ? rnd64() >> rnd(50) : 1000000000ULL; if (rnd(8) == 0) d.max_delta_ns |= 1ULL << 63; if (rnd(10) == 0) d.min_delta_ns |= 1ULL << 63; d.features = rnd(2) ? CLOCK_EVT_FEAT_ONESHOT : rnd(4);
		if (rnd(5) == 0) d.features |= CLOCK_EVT_FEAT_KTIME;
		d.state_use_accessors = rnd(5); now_ns = (ktime_t)(rnd64() >> rnd(20)); mode = rnd(4); left = rnd(30); warns = 0; cb_h = 0; cb_n = 0;
		if (k == 0) {
			unsigned long latch = rticks(); int ismax = rnd(2); u64 r;
			if (rnd(3) == 0) {   /* the edges of the add: clc + (mult - 1) landing on exactly 2^64 - 1 and one either side; mult == 1 << shift for both ismax */
				unsigned sh = 1 + rnd(31); d.shift = sh; d.mult = rnd(4) ? 1u << sh : (1u << sh) + rnd(3) - 1; latch = (1UL << (64 - sh)) - 1 + (rnd(2) ? 0 : rnd(3) - 1);
				if (rnd(2) && sh < 28) { unsigned kk = 1 + rnd(7); d.mult = kk << sh; latch = (1UL << (64 - sh)) - kk + (rnd(4) == 0 ? rnd(3) - 1 : 0); }
				if (rnd(3) == 0) latch = rnd(5000);
			}
			printf("%ld D latch=%lu ismax=%d", i, latch, ismax);
			r = cev_delta2ns(latch, &d, ismax); if (prove && pc++ == 3) r++;
			printf(" -> %llu", (unsigned long long)r); pdev(&d);
		} else if (k == 1) {
			u32 freq = 1 + (rnd(3) ? rnd(4000000) : (u32)rnd64()); d.min_delta_ticks = rticks(); d.max_delta_ticks = rticks(); if (rnd(4) == 0) d.max_delta_ticks = (unsigned long)freq * (590 + rnd(20)) + rnd(freq);
			printf("%ld C freq=%u feat=%u min_t=%lu max_t=%lu", i, freq, d.features, d.min_delta_ticks, d.max_delta_ticks); clockevents_config(&d, freq); if (prove && pc++ == 3) d.max_delta_ns++; pdev(&d);
		} else if (k == 2 || k == 3) {
			ktime_t e = rnd(8) == 0 ? -(ktime_t)rnd(100) : now_ns + (rnd(5) ? (ktime_t)(rnd64() >> rnd(40)) - (rnd(2) ? (ktime_t)(rnd64() >> rnd(45)) : 0) : 0); int force = rnd(2), rc;
			if (d.mult == 0) d.mult = 1;
			printf("%ld P exp=%lld force=%d feat=%u", i, (long long)e, force, d.features); rc = clockevents_program_event(&d, e, force); if (prove && pc++ == 3) rc++; printf(" -> %d", rc); pdev(&d);
		} else {
#ifdef MIN_ADJUST
			static const unsigned long long edges[] = { 0, 4999, 5000, 5001, 6666, 6667, 9999 }; int rc;
			d.min_delta_ns = rnd(2) ? edges[rnd(7)] : (rnd(2) ? (unsigned long long)(NSEC_PER_SEC / hz_) + rnd(3) - 1 - (rnd(2) ? rnd(100000) : 0) : rnd64() >> rnd(50));
			printf("%ld I min=%llu", i, (unsigned long long)d.min_delta_ns); rc = clockevents_increase_min_delta(&d); if (prove && pc++ == 3) rc++; printf(" -> %d", rc); pdev(&d);
#else
			printf("%ld skip", i);
#endif
		}
		printf("\n");
	}
	return 0;
}
