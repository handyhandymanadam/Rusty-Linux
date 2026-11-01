/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_STRING_HELPERS_H
#define _SHIM_VSPRINTF_LINUX_STRING_HELPERS_H
#include <stddef.h>

#define ESCAPE_SPACE		(1u << 0)
#define ESCAPE_SPECIAL		(1u << 1)
#define ESCAPE_NULL		(1u << 2)
#define ESCAPE_OCTAL		(1u << 3)
#define ESCAPE_ANY		\
	(ESCAPE_SPACE | ESCAPE_OCTAL | ESCAPE_SPECIAL | ESCAPE_NULL)
#define ESCAPE_NP		(1u << 4)
#define ESCAPE_ANY_NP		(ESCAPE_ANY | ESCAPE_NP)
#define ESCAPE_HEX		(1u << 5)

/* Deterministic stand-in, stubs.c -- see that file's own comment. */
int string_escape_mem(const char *src, size_t isz, char *dst, size_t osz,
		unsigned int flags, const char *only);

#endif
