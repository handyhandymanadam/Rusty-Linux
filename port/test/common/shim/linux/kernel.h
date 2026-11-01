/* SPDX-License-Identifier: GPL-2.0 */
/* Shared userspace shim: the parts of <linux/kernel.h> that every
 * differential harness needs, and that are the same for all of them.
 *
 * WHY THIS FILE EXISTS. Four harnesses each grew their own <linux/kernel.h>
 * and the four drifted 40-71 lines apart. That is not a tidiness problem. The
 * shim decides which code paths the ORACLE compiles, so a fork that is missing
 * a definition silently tests something other than what the kernel builds --
 * which is exactly what happened to lib/lz4 on 2026-09-03: its fork lacked the
 * width normalisation lzo's had, the oracle took LZ4's 32-bit paths on a
 * 64-bit host, and byPtr[] overflowed LZ4_STREAMSIZE. Three debugging rounds
 * went to a fault that was never in the port. See notes/ARCHIVE.md.
 *
 * WHAT BELONGS HERE. Definitions that are (a) needed by more than one harness
 * and (b) identical for all of them -- convenience macros, and the two
 * HOST-DERIVED facts below.
 *
 * WHAT DOES NOT. Anything that selects a code path per module: CONFIG_X86*,
 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS, and the u8/u16/u32/u64 typedefs all
 * stay in the module's own shim, because the modules genuinely disagree about
 * them and a shared answer would be a wrong answer for someone.
 *
 * HOW A MODULE ADDS TO IT. Keep port/test/<mod>/shim/linux/kernel.h, make its
 * first line `#include_next <linux/kernel.h>`, and put only the delta below
 * it. A module needing no delta deletes its copy and gets this one directly.
 */
#ifndef _SHIM_COMMON_LINUX_KERNEL_H
#define _SHIM_COMMON_LINUX_KERNEL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef noinline
#define noinline __attribute__((noinline))
#endif
#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min_t
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#endif
#ifndef max_t
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#endif

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#endif

#ifndef ALIGN
#define ALIGN(x, a)      (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#endif
#ifndef PTR_ALIGN
#define PTR_ALIGN(p, a)  ((__typeof__(p))ALIGN((unsigned long)(p), (a)))
#endif
#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a) (((x) & ((__typeof__(x))(a) - 1)) == 0)
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof((a)[0]))
#endif

/* Every harness that uses it uses it only on flags it defines itself. */
#ifndef IS_ENABLED
#define IS_ENABLED(x) (x)
#endif

/* ---- the two host-derived facts, and the reason they are shared ---------
 *
 * Kernel sources fork on pointer width and byte order, and getting either
 * wrong compiles a DIFFERENT pair of code paths than the kernel does -- while
 * the test still passes, because both arms are equally wrong. They are derived
 * from this host rather than assumed, and they live here rather than in each
 * harness so that no harness can be the one that forgot.
 *
 * glibc defines BOTH __LITTLE_ENDIAN and __BIG_ENDIAN as *names for the two
 * orders*, not as an assertion about the host. Kernel headers read that as a
 * contradiction and refuse to compile, so the one that is false here is
 * removed.
 */
#if !defined(CONFIG_64BIT) && (UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu)
#define CONFIG_64BIT 1
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  undef __LITTLE_ENDIAN
#  ifndef __BIG_ENDIAN
#    define __BIG_ENDIAN 4321
#  endif
#else
#  undef __BIG_ENDIAN
#  ifndef __LITTLE_ENDIAN
#    define __LITTLE_ENDIAN 1234
#  endif
#endif

#endif /* _SHIM_COMMON_LINUX_KERNEL_H */
