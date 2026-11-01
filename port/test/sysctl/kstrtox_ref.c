/* The kernel's _parse_integer_fixup_radix / _parse_integer, extracted verbatim from the pristine lib/kstrtox.c (run.sh builds this file). */
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define noinline
#define unlikely(x) __builtin_expect(!!(x), 0)
static inline int _tolower(int c) { return c | 0x20; }
static inline int isxdigit(int c) { return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F'); }
static inline unsigned long long div_u64(unsigned long long a, unsigned int b) { return a / b; }
#define KSTRTOX_OVERFLOW (1U << 31)
#include "kstrtox_body.c"
