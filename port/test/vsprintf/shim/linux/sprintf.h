/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_SPRINTF_H
#define _SHIM_VSPRINTF_LINUX_SPRINTF_H
#include <stdarg.h>
#include <stddef.h>

/* Real include/linux/sprintf.h declarations. Renamed via -D<name>=ref_<name>
 * compile flags for the REF arm (both to dodge real libc's own
 * vsnprintf/snprintf/sprintf/vsscanf/sscanf, and Rust's own `bstr_printf`)
 * -- the -D substitution rewrites these declarations too, so they always
 * match whatever these functions are actually named in a given build. */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
int snprintf(char *buf, size_t size, const char *fmt, ...);
int scnprintf(char *buf, size_t size, const char *fmt, ...);
int vsprintf(char *buf, const char *fmt, va_list args);
int sprintf(char *buf, const char *fmt, ...);
int vsscanf(const char *buf, const char *fmt, va_list args);
int sscanf(const char *buf, const char *fmt, ...);
int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);

#endif
