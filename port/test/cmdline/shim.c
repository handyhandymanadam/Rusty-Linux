/* SPDX-License-Identifier: GPL-2.0-only */
/* Definitions for port/test/cmdline/shim/linux/kernel.h. See that file. */
#include <stdlib.h>
#include <ctype.h>
#include "linux/kernel.h"

unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	return strtoull(cp, endp, base);
}

long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	return strtol(cp, endp, base);
}

char *skip_spaces(const char *str)
{
	while (isspace((unsigned char)*str))
		++str;
	return (char *)str;
}

/* lib/ctype.c's table. Only the white-space bits are consulted from
 * lib/cmdline.c; the values are _C (0x08), _S (0x20) and _SP (0x80) from
 * include/linux/ctype.h. */
const unsigned char _ctype[256] = {
	[9] = 0x08|0x20, [10] = 0x08|0x20, [11] = 0x08|0x20,
	[12] = 0x08|0x20, [13] = 0x08|0x20,
	[32] = 0x20|0x80, [160] = 0x20|0x80,
};
