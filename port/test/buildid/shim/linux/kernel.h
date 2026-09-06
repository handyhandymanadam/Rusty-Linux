#pragma once
#include <linux/compiler.h>
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define WARN_ON(cond) \
	({ bool __ret = !!(cond); if (__ret) fprintf(stderr, "WARN_ON: " #cond "\n"); __ret; })

#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((__typeof__(x))(a) - 1))

#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER) + sizeof(((TYPE *)0)->MEMBER))

#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)

/* Neither CONFIG_STACKTRACE_BUILD_ID nor CONFIG_VMCORE_INFO is defined for
 * this userspace probe, so IS_ENABLED() on either is always false -- this
 * harness never needs vmlinux_build_id()/init_vmlinux_build_id() (see
 * buildid_rs.rs's matching #[cfg(...)] gate on those two).
 */
#define IS_ENABLED(x) 0
