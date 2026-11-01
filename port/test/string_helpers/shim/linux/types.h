/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_TYPES_H
#define _SHIM_LINUX_TYPES_H
#include <stdint.h>
#include <stddef.h>
#include <linux/err.h>
#include <linux/hex.h>

#ifndef __user
#define __user
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;

#endif
