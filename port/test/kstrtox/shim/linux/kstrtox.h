#pragma once
#include "linux/types.h"

/* include/linux/kstrtox.h -- the public header. lib/kstrtox.c defines every
 * function it calls before it calls it (kstrtoull before kstrtoll, both
 * before the type-narrowing wrappers), EXCEPT the from_user macro's
 * ul/l instantiations, which reference the public inline wrappers
 * kstrtoul()/kstrtol() (not _kstrtoul()/_kstrtol()) exactly as the real
 * header does -- reproduced verbatim here, including the compile-time
 * "is unsigned long the same width as unsigned long long" branch, which is
 * always true on this (x86-64) host. */
int kstrtoull(const char *s, unsigned int base, unsigned long long *res);
int kstrtoll(const char *s, unsigned int base, long long *res);
int _kstrtoul(const char *s, unsigned int base, unsigned long *res);
int _kstrtol(const char *s, unsigned int base, long *res);

static inline int kstrtoul(const char *s, unsigned int base, unsigned long *res)
{
	if (sizeof(unsigned long) == sizeof(unsigned long long) &&
	    __alignof__(unsigned long) == __alignof__(unsigned long long))
		return kstrtoull(s, base, (unsigned long long *)res);
	else
		return _kstrtoul(s, base, res);
}

static inline int kstrtol(const char *s, unsigned int base, long *res)
{
	if (sizeof(long) == sizeof(long long) &&
	    __alignof__(long) == __alignof__(long long))
		return kstrtoll(s, base, (long long *)res);
	else
		return _kstrtol(s, base, res);
}
