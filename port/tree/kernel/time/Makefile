# SPDX-License-Identifier: GPL-2.0

# Branch profiling isn't noinstr-safe
ifdef CONFIG_TRACE_BRANCH_PROFILING
CFLAGS_sched_clock.o += -DDISABLE_BRANCH_PROFILING
endif

# timer.o is a composite under CONFIG_RUST: timer_glue.o is upstream's timer.c without the wheel-index and jiffies-rounding arithmetic, timer_rs.o holds it. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as timer_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
timer-y := timer_glue.o timer_rs.o
else
timer-y := timer_norust.o
endif
obj-y += timer.o hrtimer.o sleep_timeout.o

# time.o is a composite under CONFIG_RUST: time_glue.o is upstream's time.c without the pure conversions (system calls,
# __user copies, jiffies_64_to_clock_t and nsec_to_clock_t stay), time_rs.o holds the conversions (exported via
# kernel::kabi_export!; needs CONFIG_HZ in 100/250/300/1000). CONFIG_RUST=n builds upstream's body, installed
# byte-identical as time_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
time-y := time_glue.o time_rs.o
else
time-y := time_norust.o
endif
obj-y += time.o
obj-y += timekeeping.o jiffies.o timer_list.o
# clocksource.o is a composite under CONFIG_RUST: clocksource_glue.o is upstream's clocksource.c without the conversion arithmetic (clocks_calc_mult_shift, clocks_calc_max_nsecs,
# the arithmetic of __clocksource_update_freq_scale), clocksource_rs.o holds it. CONFIG_RUST=n builds upstream's body, installed byte-identical as clocksource_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
clocksource-y := clocksource_glue.o clocksource_rs.o
else
clocksource-y := clocksource_norust.o
endif
obj-y += clocksource.o
# ntp.o is a composite when CONFIG_RUST and not CONFIG_NTP_PPS: ntp_glue.o is upstream's ntp.c without the discipline arithmetic, ntp_rs.o holds it. Otherwise
# (CONFIG_RUST=n, or the PPS structure layout) upstream's body is built, installed byte-identical as ntp_norust.c by rig/apply.sh.
ifeq ($(CONFIG_RUST)$(CONFIG_NTP_PPS),y)
ntp-y := ntp_glue.o ntp_rs.o
else
ntp-y := ntp_norust.o
endif
obj-y += ntp.o
# timeconv.o is replaced by timeconv_rs.o under CONFIG_RUST (time64_to_tm, exported by the Rust
# object itself via kernel::kabi_export!, no C entry). The CONFIG_RUST=n arm builds upstream's body,
# installed byte-identical as timeconv_norust.c by rig/apply.sh from port/pristine/.
ifdef CONFIG_RUST
obj-y += timeconv_rs.o
else
obj-y += timeconv_norust.o
endif
# timecounter.o likewise: the three exports are carried by timecounter_rs.o (kernel::kabi_export!).
ifdef CONFIG_RUST
obj-y += timecounter_rs.o
else
obj-y += timecounter_norust.o
endif
obj-y += alarmtimer.o

ifeq ($(CONFIG_POSIX_TIMERS),y)
 obj-y += posix-timers.o posix-cpu-timers.o posix-clock.o itimer.o
else
 obj-y += posix-stubs.o
endif

# clockevents.o is a composite under CONFIG_RUST: clockevents_glue.o is upstream's clockevents.c without the conversion arithmetic, clockevents_rs.o holds it. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as clockevents_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
clockevents-y := clockevents_glue.o clockevents_rs.o
else
clockevents-y := clockevents_norust.o
endif
obj-$(CONFIG_GENERIC_CLOCKEVENTS)		+= clockevents.o tick-common.o
ifeq ($(CONFIG_GENERIC_CLOCKEVENTS_BROADCAST),y)
 obj-y						+= tick-broadcast.o
 obj-$(CONFIG_TICK_ONESHOT)			+= tick-broadcast-hrtimer.o
endif
obj-$(CONFIG_GENERIC_SCHED_CLOCK)		+= sched_clock.o
obj-$(CONFIG_TICK_ONESHOT)			+= tick-oneshot.o tick-sched.o
obj-$(CONFIG_LEGACY_TIMER_TICK)			+= tick-legacy.o
ifeq ($(CONFIG_SMP),y)
 obj-$(CONFIG_NO_HZ_COMMON)			+= timer_migration.o
endif
obj-$(CONFIG_GENERIC_GETTIMEOFDAY)		+= vsyscall.o
obj-$(CONFIG_DEBUG_FS)				+= timekeeping_debug.o
obj-$(CONFIG_TEST_UDELAY)			+= test_udelay.o
obj-$(CONFIG_TIME_NS)				+= namespace.o
obj-$(CONFIG_TEST_CLOCKSOURCE_WATCHDOG)		+= clocksource-wdtest.o
obj-$(CONFIG_TIME_KUNIT_TEST)			+= time_test.o
