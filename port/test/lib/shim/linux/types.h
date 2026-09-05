/* SPDX-License-Identifier: GPL-2.0
 *
 * Just enough <linux/types.h> to compile a pristine lib/ .c file in
 * userspace as a differential oracle. See ../../README for why the oracles
 * are COMPILED FROM port/pristine/ rather than transcribed.
 */
#ifndef _SHIM_LINUX_TYPES_H
#define _SHIM_LINUX_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
struct list_head { struct list_head *next, *prev; };
typedef int (*cmp_func_t)(const void *a, const void *b);
typedef int (*cmp_r_func_t)(const void *a, const void *b, const void *priv);
typedef void (*swap_func_t)(void *a, void *b, int size);
typedef void (*swap_r_func_t)(void *a, void *b, int size, const void *priv);
#endif
