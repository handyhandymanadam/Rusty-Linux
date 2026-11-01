// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (kernel/time/ntp.c, 6.18.49, CONFIG_NTP_PPS=n): ntp_update_frequency, the PLL/FLL offset update, __ntp_clear, second_overflow, ntp_get_next_leap's test and
 * ntp_adjtimex with its helpers are in ntp_rs.rs. This file keeps the state array and its initial values, the exports, the CMOS / RTC sync timer, the ntp_tick_adj= parameter
 * and ntp_init() as upstream has them, the entry points as thunks, and wrappers for ktime_get_ntp_seconds(), pr_notice() and the audit hooks. Upstream's whole file is installed as
 * ntp_norust.c for CONFIG_RUST=n and for CONFIG_NTP_PPS.
 */
/*
 * NTP state machine interfaces and logic.
 *
 * This code was mainly moved from kernel/timer.c and kernel/time.c
 * Please see those files for relevant copyright info and historical
 * changelogs.
 */
#include <linux/capability.h>
#include <linux/clocksource.h>
#include <linux/workqueue.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/timex.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/audit.h>
#include <linux/timekeeper_internal.h>

#include "ntp_internal.h"
#include "timekeeping_internal.h"

/**
 * struct ntp_data - Structure holding all NTP related state
 * @tick_usec:		USER_HZ period in microseconds
 * @tick_length:	Adjusted tick length
 * @tick_length_base:	Base value for @tick_length
 * @time_state:		State of the clock synchronization
 * @time_status:	Clock status bits
 * @time_offset:	Time adjustment in nanoseconds
 * @time_constant:	PLL time constant
 * @time_maxerror:	Maximum error in microseconds holding the NTP sync distance
 *			(NTP dispersion + delay / 2)
 * @time_esterror:	Estimated error in microseconds holding NTP dispersion
 * @time_freq:		Frequency offset scaled nsecs/secs
 * @time_reftime:	Time at last adjustment in seconds
 * @time_adjust:	Adjustment value
 * @ntp_tick_adj:	Constant boot-param configurable NTP tick adjustment (upscaled)
 * @ntp_next_leap_sec:	Second value of the next pending leapsecond, or TIME64_MAX if no leap
 *
 * @pps_valid:		PPS signal watchdog counter
 * @pps_tf:		PPS phase median filter
 * @pps_jitter:		PPS current jitter in nanoseconds
 * @pps_fbase:		PPS beginning of the last freq interval
 * @pps_shift:		PPS current interval duration in seconds (shift value)
 * @pps_intcnt:		PPS interval counter
 * @pps_freq:		PPS frequency offset in scaled ns/s
 * @pps_stabil:		PPS current stability in scaled ns/s
 * @pps_calcnt:		PPS monitor: calibration intervals
 * @pps_jitcnt:		PPS monitor: jitter limit exceeded
 * @pps_stbcnt:		PPS monitor: stability limit exceeded
 * @pps_errcnt:		PPS monitor: calibration errors
 *
 * Protected by the timekeeping locks.
 */
struct ntp_data {
	unsigned long		tick_usec;
	u64			tick_length;
	u64			tick_length_base;
	int			time_state;
	int			time_status;
	s64			time_offset;
	long			time_constant;
	long			time_maxerror;
	long			time_esterror;
	s64			time_freq;
	time64_t		time_reftime;
	long			time_adjust;
	s64			ntp_tick_adj;
	time64_t		ntp_next_leap_sec;
#ifdef CONFIG_NTP_PPS
	int			pps_valid;
	long			pps_tf[3];
	long			pps_jitter;
	struct timespec64	pps_fbase;
	int			pps_shift;
	int			pps_intcnt;
	s64			pps_freq;
	long			pps_stabil;
	long			pps_calcnt;
	long			pps_jitcnt;
	long			pps_stbcnt;
	long			pps_errcnt;
#endif
};

static struct ntp_data tk_ntp_data[TIMEKEEPERS_MAX] = {
	[ 0 ... TIMEKEEPERS_MAX - 1 ] = {
		.tick_usec		= USER_TICK_USEC,
		.time_state		= TIME_OK,
		.time_status		= STA_UNSYNC,
		.time_constant		= 2,
		.time_maxerror		= NTP_PHASE_LIMIT,
		.time_esterror		= NTP_PHASE_LIMIT,
		.ntp_next_leap_sec	= TIME64_MAX,
	},
};

#define SECS_PER_DAY		86400
#define MAX_TICKADJ		500LL		/* usecs */
#define MAX_TICKADJ_SCALED \
	(((MAX_TICKADJ * NSEC_PER_USEC) << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ)
#define MAX_TAI_OFFSET		100000

#ifdef CONFIG_NTP_PPS
#error "ntp_glue.c is the CONFIG_NTP_PPS=n variant; the Makefile builds ntp_norust.c otherwise"
#endif

/* The discipline arithmetic is in ntp_rs.rs. */
void rust_ntp_clear(struct ntp_data *ntpdata);
bool rust_ntp_next_leap(const struct ntp_data *ntpdata, s64 *out);
int rust_ntp_second_overflow(struct ntp_data *ntpdata, s64 secs);
int rust_ntp_adjtimex(struct ntp_data *ntpdata, unsigned int tkid, struct __kernel_timex *txc, const struct timespec64 *ts, s32 *time_tai, struct audit_ntp_data *ad);
long rust_nt_ntp_seconds(unsigned int tkid);
void rust_nt_notice_ins(void);
void rust_nt_notice_del(void);
void rust_nt_audit(struct audit_ntp_data *ad, int kind, bool is_new, s64 val);

extern const int rust_nt_hz;
const int rust_nt_hz = NTP_INTERVAL_FREQ;
long rust_nt_ntp_seconds(unsigned int tkid) { return ktime_get_ntp_seconds(tkid); }
void rust_nt_notice_ins(void) { pr_notice("Clock: inserting leap second 23:59:60 UTC\n"); }
void rust_nt_notice_del(void) { pr_notice("Clock: deleting leap second 23:59:59 UTC\n"); }
void rust_nt_audit(struct audit_ntp_data *ad, int kind, bool is_new, s64 val)
{
	static const int types[] = { AUDIT_NTP_OFFSET, AUDIT_NTP_FREQ, AUDIT_NTP_STATUS, AUDIT_NTP_TAI, AUDIT_NTP_TICK, AUDIT_NTP_ADJUST };

	if (is_new)
		audit_ntp_set_new(ad, types[kind], val);
	else
		audit_ntp_set_old(ad, types[kind], val);
}

/* The constants and the layout the Rust uses are checked against the headers. */
static_assert(NTP_SCALE_SHIFT == 32 && SHIFT_PLL == 2 && SHIFT_FLL == 2 && SHIFT_USEC == 16 && MAXTC == 10 && MINSEC == 256 && MAXSEC == 2048);
static_assert(MAXPHASE == 500000000L && MAXFREQ == 500000 && MAXFREQ_SCALED == ((s64)500000 << 32) && NTP_PHASE_LIMIT == 16000000L);
static_assert(PPM_SCALE == (1000LL << 16) && PPM_SCALE_INV_SHIFT == 19 && PPM_SCALE_INV == ((1LL << 51) / (1000LL << 16) + 1));
static_assert(USER_HZ == 100 && NSEC_PER_USEC == 1000 && USEC_PER_SEC == 1000000 && SECS_PER_DAY == 86400 && MAX_TICKADJ == 500 && MAX_TAI_OFFSET == 100000);
static_assert(STA_PLL == 0x1 && STA_FLL == 0x8 && STA_INS == 0x10 && STA_DEL == 0x20 && STA_UNSYNC == 0x40 && STA_FREQHOLD == 0x80 && STA_CLOCKERR == 0x1000 && STA_NANO == 0x2000 && STA_MODE == 0x4000 && STA_RONLY == 0xff00);
static_assert(TIME_OK == 0 && TIME_INS == 1 && TIME_DEL == 2 && TIME_OOP == 3 && TIME_WAIT == 4 && TIME_ERROR == 5);
static_assert(ADJ_OFFSET == 1 && ADJ_FREQUENCY == 2 && ADJ_MAXERROR == 4 && ADJ_ESTERROR == 8 && ADJ_STATUS == 0x10 && ADJ_TIMECONST == 0x20 && ADJ_TAI == 0x80 && ADJ_MICRO == 0x1000 && ADJ_NANO == 0x2000 && ADJ_TICK == 0x4000 && ADJ_ADJTIME == 0x8000 && ADJ_OFFSET_READONLY == 0x2000);
static_assert(sizeof(struct __kernel_timex) == 208 && offsetof(struct __kernel_timex, tick) == 88 && offsetof(struct __kernel_timex, tai) == 160 && sizeof(struct timespec64) == 16);
static_assert(offsetof(struct ntp_data, ntp_next_leap_sec) == 96 && sizeof(struct ntp_data) == 104);

#ifdef CONFIG_NTP_PPS

/*
 * The following variables are used when a pulse-per-second (PPS) signal
 * is available. They establish the engineering parameters of the clock
 * discipline loop when controlled by the PPS signal.
 */
#define PPS_VALID	10	/* PPS signal watchdog max (s) */
#define PPS_POPCORN	4	/* popcorn spike threshold (shift) */
#define PPS_INTMIN	2	/* min freq interval (s) (shift) */
#define PPS_INTMAX	8	/* max freq interval (s) (shift) */
#define PPS_INTCOUNT	4	/* number of consecutive good intervals to
				   increase pps_shift or consecutive bad
				   intervals to decrease it */
#define PPS_MAXWANDER	100000	/* max PPS freq wander (ns/s) */

/*
 * PPS kernel consumer compensates the whole phase error immediately.
 * Otherwise, reduce the offset by a fixed factor times the time constant.
 */
static inline s64 ntp_offset_chunk(struct ntp_data *ntpdata, s64 offset)
{
	if (ntpdata->time_status & STA_PPSTIME && ntpdata->time_status & STA_PPSSIGNAL)
		return offset;
	else
		return shift_right(offset, SHIFT_PLL + ntpdata->time_constant);
}

static inline void pps_reset_freq_interval(struct ntp_data *ntpdata)
{
	/* The PPS calibration interval may end surprisingly early */
	ntpdata->pps_shift = PPS_INTMIN;
	ntpdata->pps_intcnt = 0;
}

/**
 * pps_clear - Clears the PPS state variables
 * @ntpdata:	Pointer to ntp data
 */
static inline void pps_clear(struct ntp_data *ntpdata)
{
	pps_reset_freq_interval(ntpdata);
	ntpdata->pps_tf[0] = 0;
	ntpdata->pps_tf[1] = 0;
	ntpdata->pps_tf[2] = 0;
	ntpdata->pps_fbase.tv_sec = ntpdata->pps_fbase.tv_nsec = 0;
	ntpdata->pps_freq = 0;
}

/*
 * Decrease pps_valid to indicate that another second has passed since the
 * last PPS signal. When it reaches 0, indicate that PPS signal is missing.
 */
static inline void pps_dec_valid(struct ntp_data *ntpdata)
{
	if (ntpdata->pps_valid > 0) {
		ntpdata->pps_valid--;
	} else {
		ntpdata->time_status &= ~(STA_PPSSIGNAL | STA_PPSJITTER |
					  STA_PPSWANDER | STA_PPSERROR);
		pps_clear(ntpdata);
	}
}

static inline void pps_set_freq(struct ntp_data *ntpdata)
{
	ntpdata->pps_freq = ntpdata->time_freq;
}

static inline bool is_error_status(int status)
{
	return (status & (STA_UNSYNC|STA_CLOCKERR))
		/*
		 * PPS signal lost when either PPS time or PPS frequency
		 * synchronization requested
		 */
		|| ((status & (STA_PPSFREQ|STA_PPSTIME))
			&& !(status & STA_PPSSIGNAL))
		/*
		 * PPS jitter exceeded when PPS time synchronization
		 * requested
		 */
		|| ((status & (STA_PPSTIME|STA_PPSJITTER))
			== (STA_PPSTIME|STA_PPSJITTER))
		/*
		 * PPS wander exceeded or calibration error when PPS
		 * frequency synchronization requested
		 */
		|| ((status & STA_PPSFREQ)
			&& (status & (STA_PPSWANDER|STA_PPSERROR)));
}

static inline void pps_fill_timex(struct ntp_data *ntpdata, struct __kernel_timex *txc)
{
	txc->ppsfreq	   = shift_right((ntpdata->pps_freq >> PPM_SCALE_INV_SHIFT) *
					 PPM_SCALE_INV, NTP_SCALE_SHIFT);
	txc->jitter	   = ntpdata->pps_jitter;
	if (!(ntpdata->time_status & STA_NANO))
		txc->jitter = ntpdata->pps_jitter / NSEC_PER_USEC;
	txc->shift	   = ntpdata->pps_shift;
	txc->stabil	   = ntpdata->pps_stabil;
	txc->jitcnt	   = ntpdata->pps_jitcnt;
	txc->calcnt	   = ntpdata->pps_calcnt;
	txc->errcnt	   = ntpdata->pps_errcnt;
	txc->stbcnt	   = ntpdata->pps_stbcnt;
}

#else /* !CONFIG_NTP_PPS */

static inline s64 ntp_offset_chunk(struct ntp_data *ntpdata, s64 offset)
{
	return shift_right(offset, SHIFT_PLL + ntpdata->time_constant);
}

static inline void pps_reset_freq_interval(struct ntp_data *ntpdata) {}
static inline void pps_clear(struct ntp_data *ntpdata) {}
static inline void pps_dec_valid(struct ntp_data *ntpdata) {}
static inline void pps_set_freq(struct ntp_data *ntpdata) {}

static inline bool is_error_status(int status)
{
	return status & (STA_UNSYNC|STA_CLOCKERR);
}

static inline void pps_fill_timex(struct ntp_data *ntpdata, struct __kernel_timex *txc)
{
	/* PPS is not implemented, so these are zero */
	txc->ppsfreq	   = 0;
	txc->jitter	   = 0;
	txc->shift	   = 0;
	txc->stabil	   = 0;
	txc->jitcnt	   = 0;
	txc->calcnt	   = 0;
	txc->errcnt	   = 0;
	txc->stbcnt	   = 0;
}

#endif /* CONFIG_NTP_PPS */

/*
 * Update tick_length and tick_length_base, based on tick_usec, ntp_tick_adj and
 * time_freq:
 */



static void __ntp_clear(struct ntp_data *ntpdata)
{
	rust_ntp_clear(ntpdata);
}

/**
 * ntp_clear - Clears the NTP state variables
 * @tkid:	Timekeeper ID to be able to select proper ntp data array member
 */
void ntp_clear(unsigned int tkid)
{
	__ntp_clear(&tk_ntp_data[tkid]);
}


u64 ntp_tick_length(unsigned int tkid)
{
	return tk_ntp_data[tkid].tick_length;
}

/**
 * ntp_get_next_leap - Returns the next leapsecond in CLOCK_REALTIME ktime_t
 * @tkid:	Timekeeper ID
 *
 * Returns: For @tkid == TIMEKEEPER_CORE this provides the time of the next
 *	    leap second against CLOCK_REALTIME in a ktime_t format if a
 *	    leap second is pending. KTIME_MAX otherwise.
 */
ktime_t ntp_get_next_leap(unsigned int tkid)
{
	struct ntp_data *ntpdata = &tk_ntp_data[TIMEKEEPER_CORE];
	s64 leap;

	if (tkid != TIMEKEEPER_CORE)
		return KTIME_MAX;

	if (rust_ntp_next_leap(ntpdata, &leap))
		return ktime_set(leap, 0);

	return KTIME_MAX;
}

/*
 * This routine handles the overflow of the microsecond field
 *
 * The tricky bits of code to handle the accurate clock support
 * were provided by Dave Mills (Mills@UDEL.EDU) of NTP fame.
 * They were originally developed for SUN and DEC kernels.
 * All the kudos should go to Dave for this stuff.
 *
 * Also handles leap second processing, and returns leap offset
 */
int second_overflow(unsigned int tkid, time64_t secs)
{
	return rust_ntp_second_overflow(&tk_ntp_data[tkid], secs);
}

#if defined(CONFIG_GENERIC_CMOS_UPDATE) || defined(CONFIG_RTC_SYSTOHC)
static void sync_hw_clock(struct work_struct *work);
static DECLARE_WORK(sync_work, sync_hw_clock);
static struct hrtimer sync_hrtimer;
#define SYNC_PERIOD_NS (11ULL * 60 * NSEC_PER_SEC)

static enum hrtimer_restart sync_timer_callback(struct hrtimer *timer)
{
	queue_work(system_freezable_power_efficient_wq, &sync_work);

	return HRTIMER_NORESTART;
}

static void sched_sync_hw_clock(unsigned long offset_nsec, bool retry)
{
	ktime_t exp = ktime_set(ktime_get_real_seconds(), 0);

	if (retry)
		exp = ktime_add_ns(exp, 2ULL * NSEC_PER_SEC - offset_nsec);
	else
		exp = ktime_add_ns(exp, SYNC_PERIOD_NS - offset_nsec);

	hrtimer_start(&sync_hrtimer, exp, HRTIMER_MODE_ABS);
}

/*
 * Check whether @now is correct versus the required time to update the RTC
 * and calculate the value which needs to be written to the RTC so that the
 * next seconds increment of the RTC after the write is aligned with the next
 * seconds increment of clock REALTIME.
 *
 * tsched     t1 write(t2.tv_sec - 1sec))	t2 RTC increments seconds
 *
 * t2.tv_nsec == 0
 * tsched = t2 - set_offset_nsec
 * newval = t2 - NSEC_PER_SEC
 *
 * ==> neval = tsched + set_offset_nsec - NSEC_PER_SEC
 *
 * As the execution of this code is not guaranteed to happen exactly at
 * tsched this allows it to happen within a fuzzy region:
 *
 *	abs(now - tsched) < FUZZ
 *
 * If @now is not inside the allowed window the function returns false.
 */
static inline bool rtc_tv_nsec_ok(unsigned long set_offset_nsec,
				  struct timespec64 *to_set,
				  const struct timespec64 *now)
{
	/* Allowed error in tv_nsec, arbitrarily set to 5 jiffies in ns. */
	const unsigned long TIME_SET_NSEC_FUZZ = TICK_NSEC * 5;
	struct timespec64 delay = {.tv_sec = -1,
				   .tv_nsec = set_offset_nsec};

	*to_set = timespec64_add(*now, delay);

	if (to_set->tv_nsec < TIME_SET_NSEC_FUZZ) {
		to_set->tv_nsec = 0;
		return true;
	}

	if (to_set->tv_nsec > NSEC_PER_SEC - TIME_SET_NSEC_FUZZ) {
		to_set->tv_sec++;
		to_set->tv_nsec = 0;
		return true;
	}
	return false;
}

#ifdef CONFIG_GENERIC_CMOS_UPDATE
int __weak update_persistent_clock64(struct timespec64 now64)
{
	return -ENODEV;
}
#else
static inline int update_persistent_clock64(struct timespec64 now64)
{
	return -ENODEV;
}
#endif

#ifdef CONFIG_RTC_SYSTOHC
/* Save NTP synchronized time to the RTC */
static int update_rtc(struct timespec64 *to_set, unsigned long *offset_nsec)
{
	struct rtc_device *rtc;
	struct rtc_time tm;
	int err = -ENODEV;

	rtc = rtc_class_open(CONFIG_RTC_SYSTOHC_DEVICE);
	if (!rtc)
		return -ENODEV;

	if (!rtc->ops || !rtc->ops->set_time)
		goto out_close;

	/* First call might not have the correct offset */
	if (*offset_nsec == rtc->set_offset_nsec) {
		rtc_time64_to_tm(to_set->tv_sec, &tm);
		err = rtc_set_time(rtc, &tm);
	} else {
		/* Store the update offset and let the caller try again */
		*offset_nsec = rtc->set_offset_nsec;
		err = -EAGAIN;
	}
out_close:
	rtc_class_close(rtc);
	return err;
}
#else
static inline int update_rtc(struct timespec64 *to_set, unsigned long *offset_nsec)
{
	return -ENODEV;
}
#endif

/**
 * ntp_synced - Tells whether the NTP status is not UNSYNC
 * Returns:	true if not UNSYNC, false otherwise
 */
static inline bool ntp_synced(void)
{
	return !(tk_ntp_data[TIMEKEEPER_CORE].time_status & STA_UNSYNC);
}

/*
 * If we have an externally synchronized Linux clock, then update RTC clock
 * accordingly every ~11 minutes. Generally RTCs can only store second
 * precision, but many RTCs will adjust the phase of their second tick to
 * match the moment of update. This infrastructure arranges to call to the RTC
 * set at the correct moment to phase synchronize the RTC second tick over
 * with the kernel clock.
 */
static void sync_hw_clock(struct work_struct *work)
{
	/*
	 * The default synchronization offset is 500ms for the deprecated
	 * update_persistent_clock64() under the assumption that it uses
	 * the infamous CMOS clock (MC146818).
	 */
	static unsigned long offset_nsec = NSEC_PER_SEC / 2;
	struct timespec64 now, to_set;
	int res = -EAGAIN;

	/*
	 * Don't update if STA_UNSYNC is set and if ntp_notify_cmos_timer()
	 * managed to schedule the work between the timer firing and the
	 * work being able to rearm the timer. Wait for the timer to expire.
	 */
	if (!ntp_synced() || hrtimer_is_queued(&sync_hrtimer))
		return;

	ktime_get_real_ts64(&now);
	/* If @now is not in the allowed window, try again */
	if (!rtc_tv_nsec_ok(offset_nsec, &to_set, &now))
		goto rearm;

	/* Take timezone adjusted RTCs into account */
	if (persistent_clock_is_local)
		to_set.tv_sec -= (sys_tz.tz_minuteswest * 60);

	/* Try the legacy RTC first. */
	res = update_persistent_clock64(to_set);
	if (res != -ENODEV)
		goto rearm;

	/* Try the RTC class */
	res = update_rtc(&to_set, &offset_nsec);
	if (res == -ENODEV)
		return;
rearm:
	sched_sync_hw_clock(offset_nsec, res != 0);
}

void ntp_notify_cmos_timer(bool offset_set)
{
	/*
	 * If the time jumped (using ADJ_SETOFFSET) cancels sync timer,
	 * which may have been running if the time was synchronized
	 * prior to the ADJ_SETOFFSET call.
	 */
	if (offset_set)
		hrtimer_cancel(&sync_hrtimer);

	/*
	 * When the work is currently executed but has not yet the timer
	 * rearmed this queues the work immediately again. No big issue,
	 * just a pointless work scheduled.
	 */
	if (ntp_synced() && !hrtimer_is_queued(&sync_hrtimer))
		queue_work(system_freezable_power_efficient_wq, &sync_work);
}

static void __init ntp_init_cmos_sync(void)
{
	hrtimer_setup(&sync_hrtimer, sync_timer_callback, CLOCK_REALTIME, HRTIMER_MODE_ABS);
}
#else /* CONFIG_GENERIC_CMOS_UPDATE) || defined(CONFIG_RTC_SYSTOHC) */
static inline void __init ntp_init_cmos_sync(void) { }
#endif /* !CONFIG_GENERIC_CMOS_UPDATE) || defined(CONFIG_RTC_SYSTOHC) */

/*
 * Propagate a new txc->status value into the NTP state:
 */


/*
 * adjtimex() mainly allows reading (and writing, if superuser) of
 * kernel time-keeping variables. used by xntpd.
 */
int ntp_adjtimex(unsigned int tkid, struct __kernel_timex *txc, const struct timespec64 *ts,
		 s32 *time_tai, struct audit_ntp_data *ad)
{
	return rust_ntp_adjtimex(&tk_ntp_data[tkid], tkid, txc, ts, time_tai, ad);
}

#ifdef	CONFIG_NTP_PPS

/*
 * struct pps_normtime is basically a struct timespec, but it is
 * semantically different (and it is the reason why it was invented):
 * pps_normtime.nsec has a range of ( -NSEC_PER_SEC / 2, NSEC_PER_SEC / 2 ]
 * while timespec.tv_nsec has a range of [0, NSEC_PER_SEC)
 */
struct pps_normtime {
	s64		sec;	/* seconds */
	long		nsec;	/* nanoseconds */
};

/*
 * Normalize the timestamp so that nsec is in the
 * [ -NSEC_PER_SEC / 2, NSEC_PER_SEC / 2 ] interval
 */
static inline struct pps_normtime pps_normalize_ts(struct timespec64 ts)
{
	struct pps_normtime norm = {
		.sec = ts.tv_sec,
		.nsec = ts.tv_nsec
	};

	if (norm.nsec > (NSEC_PER_SEC >> 1)) {
		norm.nsec -= NSEC_PER_SEC;
		norm.sec++;
	}

	return norm;
}

/* Get current phase correction and jitter */
static inline long pps_phase_filter_get(struct ntp_data *ntpdata, long *jitter)
{
	*jitter = ntpdata->pps_tf[0] - ntpdata->pps_tf[1];
	if (*jitter < 0)
		*jitter = -*jitter;

	/* TODO: test various filters */
	return ntpdata->pps_tf[0];
}

/* Add the sample to the phase filter */
static inline void pps_phase_filter_add(struct ntp_data *ntpdata, long err)
{
	ntpdata->pps_tf[2] = ntpdata->pps_tf[1];
	ntpdata->pps_tf[1] = ntpdata->pps_tf[0];
	ntpdata->pps_tf[0] = err;
}

/*
 * Decrease frequency calibration interval length. It is halved after four
 * consecutive unstable intervals.
 */
static inline void pps_dec_freq_interval(struct ntp_data *ntpdata)
{
	if (--ntpdata->pps_intcnt <= -PPS_INTCOUNT) {
		ntpdata->pps_intcnt = -PPS_INTCOUNT;
		if (ntpdata->pps_shift > PPS_INTMIN) {
			ntpdata->pps_shift--;
			ntpdata->pps_intcnt = 0;
		}
	}
}

/*
 * Increase frequency calibration interval length. It is doubled after
 * four consecutive stable intervals.
 */
static inline void pps_inc_freq_interval(struct ntp_data *ntpdata)
{
	if (++ntpdata->pps_intcnt >= PPS_INTCOUNT) {
		ntpdata->pps_intcnt = PPS_INTCOUNT;
		if (ntpdata->pps_shift < PPS_INTMAX) {
			ntpdata->pps_shift++;
			ntpdata->pps_intcnt = 0;
		}
	}
}

/*
 * Update clock frequency based on MONOTONIC_RAW clock PPS signal
 * timestamps
 *
 * At the end of the calibration interval the difference between the
 * first and last MONOTONIC_RAW clock timestamps divided by the length
 * of the interval becomes the frequency update. If the interval was
 * too long, the data are discarded.
 * Returns the difference between old and new frequency values.
 */
static long hardpps_update_freq(struct ntp_data *ntpdata, struct pps_normtime freq_norm)
{
	long delta, delta_mod;
	s64 ftemp;

	/* Check if the frequency interval was too long */
	if (freq_norm.sec > (2 << ntpdata->pps_shift)) {
		ntpdata->time_status |= STA_PPSERROR;
		ntpdata->pps_errcnt++;
		pps_dec_freq_interval(ntpdata);
		printk_deferred(KERN_ERR "hardpps: PPSERROR: interval too long - %lld s\n",
				freq_norm.sec);
		return 0;
	}

	/*
	 * Here the raw frequency offset and wander (stability) is
	 * calculated. If the wander is less than the wander threshold the
	 * interval is increased; otherwise it is decreased.
	 */
	ftemp = div_s64(((s64)(-freq_norm.nsec)) << NTP_SCALE_SHIFT,
			freq_norm.sec);
	delta = shift_right(ftemp - ntpdata->pps_freq, NTP_SCALE_SHIFT);
	ntpdata->pps_freq = ftemp;
	if (delta > PPS_MAXWANDER || delta < -PPS_MAXWANDER) {
		printk_deferred(KERN_WARNING "hardpps: PPSWANDER: change=%ld\n", delta);
		ntpdata->time_status |= STA_PPSWANDER;
		ntpdata->pps_stbcnt++;
		pps_dec_freq_interval(ntpdata);
	} else {
		/* Good sample */
		pps_inc_freq_interval(ntpdata);
	}

	/*
	 * The stability metric is calculated as the average of recent
	 * frequency changes, but is used only for performance monitoring
	 */
	delta_mod = delta;
	if (delta_mod < 0)
		delta_mod = -delta_mod;
	ntpdata->pps_stabil += (div_s64(((s64)delta_mod) << (NTP_SCALE_SHIFT - SHIFT_USEC),
				     NSEC_PER_USEC) - ntpdata->pps_stabil) >> PPS_INTMIN;

	/* If enabled, the system clock frequency is updated */
	if ((ntpdata->time_status & STA_PPSFREQ) && !(ntpdata->time_status & STA_FREQHOLD)) {
		ntpdata->time_freq = ntpdata->pps_freq;
		ntp_update_frequency(ntpdata);
	}

	return delta;
}

/* Correct REALTIME clock phase error against PPS signal */
static void hardpps_update_phase(struct ntp_data *ntpdata, long error)
{
	long correction = -error;
	long jitter;

	/* Add the sample to the median filter */
	pps_phase_filter_add(ntpdata, correction);
	correction = pps_phase_filter_get(ntpdata, &jitter);

	/*
	 * Nominal jitter is due to PPS signal noise. If it exceeds the
	 * threshold, the sample is discarded; otherwise, if so enabled,
	 * the time offset is updated.
	 */
	if (jitter > (ntpdata->pps_jitter << PPS_POPCORN)) {
		printk_deferred(KERN_WARNING "hardpps: PPSJITTER: jitter=%ld, limit=%ld\n",
				jitter, (ntpdata->pps_jitter << PPS_POPCORN));
		ntpdata->time_status |= STA_PPSJITTER;
		ntpdata->pps_jitcnt++;
	} else if (ntpdata->time_status & STA_PPSTIME) {
		/* Correct the time using the phase offset */
		ntpdata->time_offset = div_s64(((s64)correction) << NTP_SCALE_SHIFT,
					       NTP_INTERVAL_FREQ);
		/* Cancel running adjtime() */
		ntpdata->time_adjust = 0;
	}
	/* Update jitter */
	ntpdata->pps_jitter += (jitter - ntpdata->pps_jitter) >> PPS_INTMIN;
}

/*
 * __hardpps() - discipline CPU clock oscillator to external PPS signal
 *
 * This routine is called at each PPS signal arrival in order to
 * discipline the CPU clock oscillator to the PPS signal. It takes two
 * parameters: REALTIME and MONOTONIC_RAW clock timestamps. The former
 * is used to correct clock phase error and the latter is used to
 * correct the frequency.
 *
 * This code is based on David Mills's reference nanokernel
 * implementation. It was mostly rewritten but keeps the same idea.
 */
void __hardpps(const struct timespec64 *phase_ts, const struct timespec64 *raw_ts)
{
	struct ntp_data *ntpdata = &tk_ntp_data[TIMEKEEPER_CORE];
	struct pps_normtime pts_norm, freq_norm;

	pts_norm = pps_normalize_ts(*phase_ts);

	/* Clear the error bits, they will be set again if needed */
	ntpdata->time_status &= ~(STA_PPSJITTER | STA_PPSWANDER | STA_PPSERROR);

	/* indicate signal presence */
	ntpdata->time_status |= STA_PPSSIGNAL;
	ntpdata->pps_valid = PPS_VALID;

	/*
	 * When called for the first time, just start the frequency
	 * interval
	 */
	if (unlikely(ntpdata->pps_fbase.tv_sec == 0)) {
		ntpdata->pps_fbase = *raw_ts;
		return;
	}

	/* Ok, now we have a base for frequency calculation */
	freq_norm = pps_normalize_ts(timespec64_sub(*raw_ts, ntpdata->pps_fbase));

	/*
	 * Check that the signal is in the range
	 * [1s - MAXFREQ us, 1s + MAXFREQ us], otherwise reject it
	 */
	if ((freq_norm.sec == 0) || (freq_norm.nsec > MAXFREQ * freq_norm.sec) ||
	    (freq_norm.nsec < -MAXFREQ * freq_norm.sec)) {
		ntpdata->time_status |= STA_PPSJITTER;
		/* Restart the frequency calibration interval */
		ntpdata->pps_fbase = *raw_ts;
		printk_deferred(KERN_ERR "hardpps: PPSJITTER: bad pulse\n");
		return;
	}

	/* Signal is ok. Check if the current frequency interval is finished */
	if (freq_norm.sec >= (1 << ntpdata->pps_shift)) {
		ntpdata->pps_calcnt++;
		/* Restart the frequency calibration interval */
		ntpdata->pps_fbase = *raw_ts;
		hardpps_update_freq(ntpdata, freq_norm);
	}

	hardpps_update_phase(ntpdata, pts_norm.nsec);

}
#endif	/* CONFIG_NTP_PPS */

static int __init ntp_tick_adj_setup(char *str)
{
	int rc = kstrtos64(str, 0, &tk_ntp_data[TIMEKEEPER_CORE].ntp_tick_adj);
	if (rc)
		return rc;

	tk_ntp_data[TIMEKEEPER_CORE].ntp_tick_adj <<= NTP_SCALE_SHIFT;
	return 1;
}
__setup("ntp_tick_adj=", ntp_tick_adj_setup);

void __init ntp_init(void)
{
	for (int id = 0; id < TIMEKEEPERS_MAX; id++)
		__ntp_clear(tk_ntp_data + id);
	ntp_init_cmos_sync();
}
