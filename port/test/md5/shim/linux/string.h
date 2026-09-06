#pragma once
#include <stddef.h>
#include <string.h>

/* memzero_explicit()'s security property (a store the compiler cannot elide)
 * does not matter to this harness -- the digest is fully computed before
 * either arm ever calls it, so a plain memset gives an identical observable
 * result and is all a differential needs. */
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
}
