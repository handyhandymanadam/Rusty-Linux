/* SPDX-License-Identifier: GPL-2.0-only */
/* The kernel types lib/fw_table.c and the ACPICA headers need.
 *
 * ACPICA gets its integer types from <linux/types.h> rather than defining
 * its own, because include/acpi/platform/aclinux.h:31 defines
 * ACPI_USE_SYSTEM_INTTYPES for in-kernel builds -- so actypes.h's own
 * `typedef COMPILER_DEPENDENT_UINT64 u64;` block is #ifdef'd out and THESE
 * are the definitions the kernel's own struct layouts are built from. Getting
 * that wrong would change every ACPICA struct's field widths and the oracle
 * would silently be a different program (the lib/lz4 lesson).
 *
 * __le16/__le32 carry no attribute here. In the kernel they are
 * __bitwise-annotated aliases that sparse checks and the compiler ignores;
 * nothing about the generated code depends on them, and the byte-order
 * conversion below is the part that does. */
#ifndef _SHIM_FW_TABLE_LINUX_TYPES_H
#define _SHIM_FW_TABLE_LINUX_TYPES_H

#include <linux/kernel.h>	/* the shared base: byte order, CONFIG_64BIT */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef u16 __le16;
typedef u32 __le32;
typedef u64 __le64;

#define __force

/* Derived from the host, not assumed -- logs/floor.md RAISE 5. On a
 * big-endian host these become real byte swaps, exactly as the kernel's do,
 * so the CDAT paths stay honest if this harness is ever cross-run. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define le16_to_cpu(x) __builtin_bswap16((u16)(x))
#define le32_to_cpu(x) __builtin_bswap32((u32)(x))
#define cpu_to_le16(x) __builtin_bswap16((u16)(x))
#define cpu_to_le32(x) __builtin_bswap32((u32)(x))
#else
#define le16_to_cpu(x) ((u16)(x))
#define le32_to_cpu(x) ((u32)(x))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#endif

#endif
