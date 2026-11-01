/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_RTC_H
#define _SHIM_VSPRINTF_LINUX_RTC_H
/* %pt (time_and_date/clock's neighbor, both deferred) -- unexercised. */
struct rtc_time {
	int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
	int tm_wday, tm_yday, tm_isdst;
};
#endif
