#pragma once
#include <ctype.h>

/* glibc's own <ctype.h> already #defines _tolower() as an internal
 * locale-table macro -- a different thing entirely. include/linux/ctype.h's
 * is just `c | 0x20`; replace glibc's before it can collide. isxdigit()
 * from libc <ctype.h> matches the kernel's for the ASCII range this parser
 * ever indexes it with. */
#undef _tolower
#define _tolower(c) ((char)((c) | 0x20))
