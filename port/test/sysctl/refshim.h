/* Stand-ins for what the pristine slice of kernel/sysctl.c uses. isspace() is the kernel's _ctype table (9-13, ' ' and 0xA0 are spaces), not libc's. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#define loff_t long long
#define EINVAL 22
#define ERANGE 34
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
extern size_t page_size_g; extern int hz_g, warns;
#define PAGE_SIZE page_size_g
#define HZ hz_g
static inline int isspace(int c) { c &= 0xff; return (c >= 9 && c <= 13) || c == 32 || c == 160; }
static inline int isdigit(int c) { return '0' <= c && c <= '9'; }
struct ctl_table { const char *procname; void *data; int maxlen; void *extra1; void *extra2; };
struct task { const char *comm; }; extern struct task *current;
enum sysctl_writes_mode { SYSCTL_WRITES_LEGACY = -1, SYSCTL_WRITES_WARN = 0, SYSCTL_WRITES_STRICT = 1 };
extern enum sysctl_writes_mode sysctl_writes_strict;
#define pr_warn_once(...) (warns++)
#define static_assert(x) _Static_assert(x, #x)
#define KSTRTOX_OVERFLOW (1U << 31)
const char *_parse_integer_fixup_radix(const char *s, unsigned int *base);
unsigned int _parse_integer(const char *s, unsigned int base, unsigned long long *res);
#endif
