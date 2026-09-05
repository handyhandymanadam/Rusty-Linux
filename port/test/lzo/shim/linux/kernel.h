/* Userspace shim: only what the pristine lib/lzo C files use, beyond the
 * shared base. Convenience macros, pointer width and byte order come from
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
#ifndef _SHIM_LZO_LINUX_KERNEL_H
#define _SHIM_LZO_LINUX_KERNEL_H

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* lzodefs.h picks COPY8 and the ctz width from these. The kernel builds this
 * project targets are x86-64, so say so -- getting it wrong would test a
 * different pair of code paths than the kernel compiles. Module-specific by
 * design: they are not facts about the host, they are a choice about which
 * kernel this harness is standing in for. */
#define CONFIG_X86_64 1
#define CONFIG_X86 1

/* The decompressor and compressor both fork on this. run.sh compiles the
 * oracle BOTH ways and the harness runs all three arms, because the Rust
 * replaces the fork with one read_unaligned() and that claim should be
 * measured rather than asserted. */
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#endif

#endif
