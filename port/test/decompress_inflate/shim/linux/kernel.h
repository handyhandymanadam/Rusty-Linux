/* Userspace shim: only what the pristine lib/zlib_inflate C files use, beyond
 * the shared base. Convenience macros, pointer width and byte order come from
 * port/test/common/shim/linux/kernel.h. */
#include_next <linux/kernel.h>
/* The base is MANDATORY. Without -I port/test/common/shim on the path,
 * #include_next above resolves to /usr/include/linux/kernel.h -- the UAPI
 * stub -- and several harnesses then compile CLEAN against it. That is the
 * same silent-wrong-header failure this shim arrangement exists to prevent,
 * so make it a build error instead of a mystery. Found 2026-09-03 by an
 * adversarial review of the commit that introduced it. */
#ifndef _SHIM_COMMON_LINUX_KERNEL_H
#error "port/test/common/shim must be on the include path (see run.sh -I flags)"
#endif
#ifndef _SHIM_ZLIB_LINUX_KERNEL_H
#define _SHIM_ZLIB_LINUX_KERNEL_H

typedef unsigned char u8;

/* inffast.c's only use of it is IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS).
 * run.sh compiles the oracle BOTH ways and the harness runs all three arms,
 * because the Rust replaces that fork with one read_unaligned() and the claim
 * that this is equivalent should be measured rather than asserted. */
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#endif

#endif
