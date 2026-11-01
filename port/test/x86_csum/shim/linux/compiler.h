#ifndef SHIM_linux_compiler_h
#define SHIM_linux_compiler_h
/* userspace shim: just enough of linux/compiler.h for arch/x86/lib/csum-partial_64.c */
#include <stdint.h>
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __force
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef u32 __wsum; typedef u16 __sum16;
static inline u64 ror64(u64 word, unsigned int shift) { return (word >> (shift & 63)) | (word << ((-shift) & 63)); }
#endif
