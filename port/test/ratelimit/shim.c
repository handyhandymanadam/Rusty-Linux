/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The one knob driving both arms' jiffies references -- see
 * shim/linux/jiffies.h. */
volatile unsigned long jiffies;

/* Captures the last printk_deferred()/_printk_deferred() call, from
 * EITHER arm (same symbol, both arms call it) -- drv.c reads and resets
 * this around each arm's call so it can tell which arm produced what. */
char g_printk_buf[256];
int g_printk_calls;

int _printk_deferred(const char *fmt, ...)
{
	va_list ap;

	g_printk_calls++;
	va_start(ap, fmt);
	vsnprintf(g_printk_buf, sizeof g_printk_buf, fmt, ap);
	va_end(ap);
	return 0;
}
