/* ntp differential: the pristine discipline arithmetic (ARM_REF: ref.c) against ntp_rs.rs plus the wrappers of ntp_glue.c (ARM_RS). HZ is 100, 250, 300 or 1000 by shard. Random
 * initial states (including the clamp edges and negative values), then random adjtimex calls (all mode bits, extreme and in-range values, read-only and adjtime forms, ts around the
 * pending leap second), second_overflow steps through a leap-second day, ntp_clear and ntp_get_next_leap. Prints every result, the whole state, the timex and a hash of the audit
 * calls.   usage: t SHARD (env NP_N, NP_PROVE) */
#include "refshim.h"
#include "ntpstruct.h"
int hz_ = 1000, notices, audit_n; unsigned long long audit_h;
static long now_secs;
long ktime_get_ntp_seconds(unsigned int id) { return now_secs + id; }
void audit_ntp_set_old(struct audit_ntp_data *ad, int type, s64 val) { audit_n++; audit_h = audit_h * 1000003ULL + (unsigned)type * 2 + (unsigned long long)val; }
void audit_ntp_set_new(struct audit_ntp_data *ad, int type, s64 val) { audit_n++; audit_h = audit_h * 1000003ULL + (unsigned)type * 2 + 1 + (unsigned long long)val * 3; }
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return rs_ >> 11; }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
#ifdef ARM_REF
#include "ref.c"
#define D(id) ref_data(id)
#define T_CLEAR(id) __ntp_clear(ref_data(id))
#define T_SECOND(id, secs) second_overflow(id, secs)
#define T_ADJ(id, txc, ts, tai) ntp_adjtimex(id, txc, ts, tai, (struct audit_ntp_data *)1)
#define T_LEAP(id) ntp_get_next_leap(id)
#else
static struct ntp_data tk[TIMEKEEPERS_MAX];
const int rust_nt_hz_dummy = 0;
int rust_nt_hz;
void rust_ntp_clear(struct ntp_data *); bool rust_ntp_next_leap(const struct ntp_data *, s64 *); int rust_ntp_second_overflow(struct ntp_data *, s64);
int rust_ntp_adjtimex(struct ntp_data *, unsigned, struct __kernel_timex *, const struct timespec64 *, s32 *, struct audit_ntp_data *);
long rust_nt_ntp_seconds(unsigned int tkid) { return ktime_get_ntp_seconds(tkid); }
void rust_nt_notice_ins(void) { notices++; }
void rust_nt_notice_del(void) { notices++; }
void rust_nt_audit(struct audit_ntp_data *ad, int kind, bool is_new, s64 val) { if (is_new) audit_ntp_set_new(ad, kind, val); else audit_ntp_set_old(ad, kind, val); }
static ktime_t leap_of(unsigned id) { s64 l; if (id != TIMEKEEPER_CORE) return KTIME_MAX; return rust_ntp_next_leap(&tk[0], &l) ? ktime_set(l, 0) : KTIME_MAX; }
#define D(id) (&tk[id])
#define T_CLEAR(id) rust_ntp_clear(&tk[id])
#define T_SECOND(id, secs) rust_ntp_second_overflow(&tk[id], secs)
#define T_ADJ(id, txc, ts, tai) rust_ntp_adjtimex(&tk[id], id, txc, ts, tai, (struct audit_ntp_data *)1)
#define T_LEAP(id) leap_of(id)
#endif
static long long edge(void)
{
	switch (rnd(12)) { case 0: return 0; case 1: return -1; case 2: return 500000000LL + (long long)rnd(3) - 1; case 3: return -500000000LL - (long long)rnd(3) + 1; case 4: return 1000000LL + rnd(3) - 1;
	case 5: return (long long)rnd64() - (long long)rnd64(); case 6: return 16000000LL + (long long)rnd(3) - 1; case 7: return 10 + rnd(3); case 8: return rnd(1000); default: return (long long)rnd(2000000) - 1000000; }
}
static void pstate(int id)
{
	struct ntp_data *n = D(id);
	printf(" | st=%d s=%x off=%lld c=%ld me=%ld ee=%ld fr=%lld ref=%lld adj=%ld tick=%lu tl=%llu tlb=%llu tadj=%lld nl=%lld", n->time_state, n->time_status, (long long)n->time_offset, n->time_constant, n->time_maxerror, n->time_esterror,
	       (long long)n->time_freq, (long long)n->time_reftime, n->time_adjust, n->tick_usec, (unsigned long long)n->tick_length, (unsigned long long)n->tick_length_base, (long long)n->ntp_tick_adj, (long long)n->ntp_next_leap_sec);
}
static void randstate(struct ntp_data *n)
{
	n->tick_usec = rnd(4) ? 10000 : 9000 + rnd(2000); n->tick_length_base = rnd64(); n->tick_length = n->tick_length_base + rnd(1000);
	n->time_state = rnd(6); n->time_status = (int)rnd(0x10000); if (rnd(2)) n->time_status |= STA_PLL; if (rnd(4) == 0) n->time_status &= ~STA_NANO;
	n->time_offset = edge() << rnd(20); n->time_constant = rnd(3) ? 2 + rnd(9) : rnd(11); n->time_maxerror = rnd(3) ? rnd(16000000) : 16000000 - 500 + (long)rnd(3) - 1 - (rnd(2) ? 0 : (long)rnd(3)); n->time_esterror = rnd(16000000);
	n->time_freq = (long long)(rnd64() % (2 * MAXFREQ_SCALED)) - MAXFREQ_SCALED; { static const int sec_edges[] = { 255, 256, 257, 2047, 2048, 2049, 0, 1 }; n->time_reftime = now_secs - (rnd(4) ? (rnd(3) ? (long)rnd(5000) : sec_edges[rnd(8)]) : (long)rnd(3)); } { static const long adj_edges[] = { 0, 1, -1, 500, 501, -500, -501, 499, -499 }; n->time_adjust = rnd(3) ? (rnd(2) ? adj_edges[rnd(9)] : (long)edge()) : (long)rnd(2000) - 1000; }
	n->ntp_tick_adj = rnd(3) ? 0 : (long long)rnd(100000) << NTP_SCALE_SHIFT; n->ntp_next_leap_sec = rnd(2) ? TIME64_MAX : (long long)now_secs + rnd(200) - 100;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("NP_N") ? atol(getenv("NP_N")) : 20000; int prove = getenv("NP_PROVE") != NULL;
	static const int HZS[4] = { 100, 250, 300, 1000 };
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	hz_ = HZS[shard & 3];
#ifndef ARM_REF
	rust_nt_hz = hz_;
#endif
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long round = 0; round < n / 100; round++) {
		now_secs = 1000000000L + (long)rnd(100000000);
		for (int id = 0; id < 2; id++) { randstate(D(id)); }
		int tai = (int)rnd(40) + 10;
		for (int op = 0; op < 100; op++) {
			int id = rnd(5) ? 0 : 1; unsigned o = rnd(10); printf("%ld.%d hz=%d id=%d ", round, op, hz_, id);
			now_secs += rnd(3) ? 1 : (long)rnd(3000);
			if (o < 5) {
				struct __kernel_timex t; memset(&t, 0, sizeof t); struct timespec64 ts;
				t.modes = rnd(3) ? (unsigned)rnd(0x10000) & (ADJ_OFFSET | ADJ_FREQUENCY | ADJ_MAXERROR | ADJ_ESTERROR | ADJ_STATUS | ADJ_TIMECONST | ADJ_TAI | ADJ_MICRO | ADJ_NANO | ADJ_TICK) : 0;
				if (rnd(6) == 0) t.modes = ADJ_ADJTIME | (rnd(2) ? ADJ_OFFSET_READONLY : 0) | (rnd(2) ? 1 : 0); if (rnd(8) == 0 && t.modes == 0) t.modes = ADJ_STATUS;
				t.offset = edge() * (rnd(3) ? 1 : 1000); t.freq = (long long)(rnd64() % 20000000) - 10000000; if (rnd(5) == 0) t.freq = edge() * 100000; t.maxerror = edge(); t.esterror = edge(); t.status = rnd(3) ? (int)rnd(0x10000) : (STA_PLL | (int)rnd(0x100));
				t.constant = rnd(3) ? (long long)rnd(20) - 3 : rnd(2) ? 100000 + (long long)rnd(3) - 1 : edge(); t.tick = rnd(3) ? 9000 + rnd(2000) : edge();
				ts.tv_sec = now_secs + (rnd(2) ? 0 : (long)rnd(300) - 150); ts.tv_nsec = rnd(1000000000); if (rnd(6) == 0 && D(0)->ntp_next_leap_sec != TIME64_MAX) ts.tv_sec = D(0)->ntp_next_leap_sec + (long)rnd(3) - 1;
				if (rnd(3) == 0) { static const int ed[] = { 255, 256, 257, 2047, 2048, 2049, 0, 1, 4096 }; D(id)->time_reftime = now_secs + id - ed[rnd(9)]; }
				audit_n = 0; int r = T_ADJ(id, &t, &ts, &tai);
				printf("adjtimex modes=%x -> %d tai=%d | off=%lld freq=%lld me=%lld ee=%lld st=%x c=%lld pr=%lld tol=%lld t=%lld.%lld tick=%lld tai=%d au=%d/%llx", t.modes, r, tai, t.offset, t.freq, t.maxerror, t.esterror, t.status, t.constant, t.precision, t.tolerance, (long long)t.time.tv_sec, (long long)t.time.tv_usec, t.tick, t.tai, audit_n, audit_h);
			} else if (o < 8) {
				time64_t secs = rnd(3) ? (time64_t)now_secs : (time64_t)(86400LL * (1 + rnd(20000)) - rnd(3) + (rnd(2) ? 0 : 1));
				if (rnd(4) == 0 && D(id)->ntp_next_leap_sec != TIME64_MAX) secs = D(id)->ntp_next_leap_sec + (long)rnd(3) - 1;
				int r = T_SECOND(id, secs); printf("second_overflow %lld -> %d notices=%d", (long long)secs, r, notices);
			} else if (o < 9) { T_CLEAR(id); printf("clear"); }
			else { ktime_t k = T_LEAP(id); printf("next_leap -> %lld", (long long)k); }
			pstate(id); printf("\n");
		}
		if (prove && round == 0) printf("  POISON\n");
	}
	printf("final n=%d\n", notices);
	return 0;
}
