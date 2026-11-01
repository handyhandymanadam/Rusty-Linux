/* Stand-ins for what the pristine slice of kernel/time/ntp.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int64_t s64; typedef uint64_t u64; typedef int32_t s32; typedef uint32_t u32; typedef int64_t time64_t; typedef int64_t ktime_t;
#define TIMEKEEPERS_MAX 2
#define TIMEKEEPER_CORE 0
#define TIME64_MAX INT64_MAX
#define KTIME_MAX INT64_MAX
#define NSEC_PER_USEC 1000L
#define USEC_PER_SEC 1000000L
#define USER_HZ 100
#define unlikely(x) __builtin_expect(!!(x), 0)
#define NTP_SCALE_SHIFT 32
extern int hz_;
#define NTP_INTERVAL_FREQ (hz_)
#define SHIFT_PLL 2
#define SHIFT_FLL 2
#define SHIFT_USEC 16
#define MAXTC 10
#define MINSEC 256
#define MAXSEC 2048
#define MAXPHASE 500000000L
#define MAXFREQ 500000
#define MAXFREQ_SCALED ((s64)MAXFREQ << NTP_SCALE_SHIFT)
#define NTP_PHASE_LIMIT ((MAXPHASE / NSEC_PER_USEC) << 5)
#define PPM_SCALE ((s64)NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC))
#define PPM_SCALE_INV_SHIFT 19
#define PPM_SCALE_INV ((1LL << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / PPM_SCALE + 1)
#define shift_right(x, s) ({ __typeof__(x) __x = (x); __typeof__(s) __s = (s); __x < 0 ? -(-__x >> __s) : __x >> __s; })
#define STA_PLL 0x0001
#define STA_PPSFREQ 0x0002
#define STA_PPSTIME 0x0004
#define STA_FLL 0x0008
#define STA_INS 0x0010
#define STA_DEL 0x0020
#define STA_UNSYNC 0x0040
#define STA_FREQHOLD 0x0080
#define STA_PPSSIGNAL 0x0100
#define STA_PPSJITTER 0x0200
#define STA_PPSWANDER 0x0400
#define STA_PPSERROR 0x0800
#define STA_CLOCKERR 0x1000
#define STA_NANO 0x2000
#define STA_MODE 0x4000
#define STA_CLK 0x8000
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)
#define TIME_OK 0
#define TIME_INS 1
#define TIME_DEL 2
#define TIME_OOP 3
#define TIME_WAIT 4
#define TIME_ERROR 5
#define ADJ_OFFSET 0x0001
#define ADJ_FREQUENCY 0x0002
#define ADJ_MAXERROR 0x0004
#define ADJ_ESTERROR 0x0008
#define ADJ_STATUS 0x0010
#define ADJ_TIMECONST 0x0020
#define ADJ_TAI 0x0080
#define ADJ_MICRO 0x1000
#define ADJ_NANO 0x2000
#define ADJ_TICK 0x4000
#define ADJ_ADJTIME 0x8000
#define ADJ_OFFSET_READONLY 0x2000
#define AUDIT_NTP_OFFSET 0
#define AUDIT_NTP_FREQ 1
#define AUDIT_NTP_STATUS 2
#define AUDIT_NTP_TAI 3
#define AUDIT_NTP_TICK 4
#define AUDIT_NTP_ADJUST 5
struct audit_ntp_data;
struct timespec64 { time64_t tv_sec; long tv_nsec; };
struct __kernel_timex_timeval { long long tv_sec; long long tv_usec; };
struct __kernel_timex { unsigned int modes; int :32; long long offset, freq, maxerror, esterror; int status; int :32; long long constant, precision, tolerance; struct __kernel_timex_timeval time; long long tick, ppsfreq, jitter; int shift; int :32; long long stabil, jitcnt, calcnt, errcnt, stbcnt; int tai; int :32; int :32; int :32; int :32; int :32; int :32; int :32; int :32; int :32; int :32; int :32; };
extern int notices, audit_n; extern unsigned long long audit_h;
#define pr_notice(...) (notices++)
void audit_ntp_set_old(struct audit_ntp_data *ad, int type, s64 val);
void audit_ntp_set_new(struct audit_ntp_data *ad, int type, s64 val);
long ktime_get_ntp_seconds(unsigned int id);
static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs) { return secs * 1000000000LL + nsecs; }
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define max(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ > b_ ? a_ : b_; })
#define clamp(v, lo, hi) min((__typeof__(v))max(v, lo), hi)
static inline u64 div_u64(u64 d, u32 v) { return d / v; }
static inline s64 div_s64(s64 d, s32 v) { return d / v; }
static inline s64 div64_long(s64 d, long v) { return d / v; }
static inline s64 div_s64_rem(s64 d, s32 v, s32 *rem) { *rem = (s32)(d % v); return d / v; }
#endif
