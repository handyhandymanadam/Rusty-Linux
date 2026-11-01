/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_TIME_H
#define _SHIM_VSPRINTF_LINUX_TIME_H
/* time64_str() (part of the deferred %pt seam) -- unexercised. */
struct tm {
	int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
	int tm_wday, tm_yday;
};
static inline void time64_to_tm(long long totalsecs, int offset, struct tm *result)
{
	*result = (struct tm){0};
}
#endif
