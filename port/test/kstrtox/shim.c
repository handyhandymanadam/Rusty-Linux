/* SPDX-License-Identifier: GPL-2.0-only */
/* Definitions for port/test/kstrtox/shim/linux/uaccess.h. See that file. */
#include <string.h>

/* The C arm calls copy_from_user() (the header's public name); the Rust arm
 * calls _copy_from_user() directly, per the module doc comment in
 * kstrtox_rs.rs -- "Rust code always uses the extern definition." Both are
 * given the SAME body here, so what the harness compares is the two
 * parsers' count-clamping and NUL-termination, not the copy primitive. */
unsigned long copy_from_user(void *to, const void *from, unsigned long n)
{
	memcpy(to, from, n);
	return 0;
}

unsigned long _copy_from_user(void *to, const void *from, unsigned long n)
{
	memcpy(to, from, n);
	return 0;
}
