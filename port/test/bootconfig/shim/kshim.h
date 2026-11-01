/* kernel shim for the bootconfig differential: __KERNEL__ code path of lib/bootconfig.c with memblock replaced by malloc (with failure injection) */
#ifndef KSHIM_H
#define KSHIM_H
#define __KERNEL__ 1
#define ENOENT 2
#define ENOMEM 12
#define EBUSY 16
#define ENODEV 19
#define EINVAL 22
#define ERANGE 34
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define static_assert _Static_assert
#define __init
#define __initdata
#define __visible
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define fallthrough __attribute__((__fallthrough__))
#define EXPORT_SYMBOL(x)
#define SMP_CACHE_BYTES 64
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
extern int warn_count;
#define WARN_ON(c) ({ bool c_ = !!(c); warn_count += c_; c_; })
#define BUG_ON(c) do { if (c) abort(); } while (0)
/* <linux/ctype.h>: the kernel's own table (src/linux/lib/ctype.c is linked in) */
#define _U 0x01
#define _L 0x02
#define _D 0x04
#define _C 0x08
#define _P 0x10
#define _S 0x20
#define _X 0x40
#define _SP 0x80
extern const unsigned char _ctype[];
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c) ((__ismask(c) & (_U | _L | _D)) != 0)
#define isprint(c) ((__ismask(c) & (_P | _U | _L | _D | _SP)) != 0)
#define isspace(c) ((__ismask(c) & (_S)) != 0)
/* lib/string.c */
char *skip_spaces(const char *str);
char *strim(char *s);
/* memblock */
extern int alloc_fail_in;	/* fail the Nth next allocation; 0 = never */
extern long live_allocs;
static inline void *memblock_alloc(size_t size, size_t align) { (void)align; if (alloc_fail_in && --alloc_fail_in == 0) return NULL; void *p = malloc(size); if (p) { memset(p, 0xA5, size); live_allocs++; } return p; }
static inline void memblock_free(void *p, size_t size) { (void)size; if (p) { live_allocs--; free(p); } }
static inline void memblock_free_late(unsigned long pa, size_t size) { (void)size; if (pa) { live_allocs--; free((void *)pa); } }
#define __pa(x) ((unsigned long)(x))
#include "bootconfig_body.h"
#endif
