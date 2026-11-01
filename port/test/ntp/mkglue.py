#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- ntp_glue.c = upstream with the discipline arithmetic replaced by calls into ntp_rs.rs (see kernel/time/ntp_rs.rs). Without CONFIG_NTP_PPS only."""
import sys
s = open(sys.argv[1]).read()
def replace(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
replace("static void ntp_update_frequency(", "")
replace("static inline s64 ntp_update_offset_fll(", "")
replace("static void ntp_update_offset(", "")
replace("static void __ntp_clear(", '''static void __ntp_clear(struct ntp_data *ntpdata)
{
	rust_ntp_clear(ntpdata);
}
''')
replace("ktime_t ntp_get_next_leap(", '''ktime_t ntp_get_next_leap(unsigned int tkid)
{
	struct ntp_data *ntpdata = &tk_ntp_data[TIMEKEEPER_CORE];
	s64 leap;

	if (tkid != TIMEKEEPER_CORE)
		return KTIME_MAX;

	if (rust_ntp_next_leap(ntpdata, &leap))
		return ktime_set(leap, 0);

	return KTIME_MAX;
}
''')
replace("int second_overflow(", '''int second_overflow(unsigned int tkid, time64_t secs)
{
	return rust_ntp_second_overflow(&tk_ntp_data[tkid], secs);
}
''')
replace("static inline void process_adj_status(", "")
replace("static inline void process_adjtimex_modes(", "")
replace("int ntp_adjtimex(", '''int ntp_adjtimex(unsigned int tkid, struct __kernel_timex *txc, const struct timespec64 *ts,
		 s32 *time_tai, struct audit_ntp_data *ad)
{
	return rust_ntp_adjtimex(&tk_ntp_data[tkid], tkid, txc, ts, time_tai, ad);
}
''')
decl = '''
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
void rust_nt_notice_ins(void) { pr_notice("Clock: inserting leap second 23:59:60 UTC\\n"); }
void rust_nt_notice_del(void) { pr_notice("Clock: deleting leap second 23:59:59 UTC\\n"); }
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
'''
m = "#define SECS_PER_DAY"
i = s.index("#define MAX_TAI_OFFSET")
j = s.index("\n", i) + 1
s = s[:j] + decl + s[j:]
hdr = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/time/ntp.c, 6.18.49, CONFIG_NTP_PPS=n): ntp_update_frequency, the PLL/FLL offset update, __ntp_clear, second_overflow, ntp_get_next_leap's test and\n * ntp_adjtimex with its helpers are in ntp_rs.rs. This file keeps the state array and its initial values, the exports, the CMOS / RTC sync timer, the ntp_tick_adj= parameter\n * and ntp_init() as upstream has them, the entry points as thunks, and wrappers for ktime_get_ntp_seconds(), pr_notice() and the audit hooks. Upstream's whole file is installed as\n * ntp_norust.c for CONFIG_RUST=n and for CONFIG_NTP_PPS.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", hdr, 1)
open(sys.argv[2], "w").write(s)
