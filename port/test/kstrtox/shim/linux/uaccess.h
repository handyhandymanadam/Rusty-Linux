#pragma once
#include "linux/types.h"

/* Userspace has no user/kernel boundary. Both arms call the SAME shim
 * (defined in shim.c, a plain memcpy that always succeeds) -- what this
 * harness compares is the two parsers' count-clamping and NUL-termination,
 * not any fault-handling machinery neither arm exercises here. */
unsigned long copy_from_user(void *to, const void *from, unsigned long n);

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
