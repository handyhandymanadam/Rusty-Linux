#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

/* The four things lib/cmdline.c reaches for outside itself. They are DECLARED
 * here and DEFINED in shim.c, not `static inline`, so that BOTH ARMS CALL THE
 * SAME CODE -- an inline definition would leave the Rust arm with undefined
 * references and, worse, could have been given a different body.
 *
 * simple_strtoull/simple_strtol live in lib/vsprintf.c, which is not ported
 * and is thousands of lines of kernel-specific formatting. Compiling it here
 * to obtain two integer parsers would be the "a shim that compiles is not a
 * shim that matches" trap approached from the other side. The host's strtoull
 * at base 0 has the same accept-a-prefix behaviour over the inputs a kernel
 * command line can hold -- and, again, both arms call it, so what this
 * harness compares is the two PARSERS, not the primitive.
 */
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base);
long simple_strtol(const char *cp, char **endp, unsigned int base);
char *skip_spaces(const char *str);

/* include/linux/compiler_attributes.h */
#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif
