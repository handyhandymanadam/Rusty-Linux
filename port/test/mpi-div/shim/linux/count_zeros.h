#pragma once
/* Real (not stubbed) reproduction of count_leading_zeros() -- see
 * port/test/mpih-div/shim/linux/count_zeros.h for the derivation. */
static inline int count_leading_zeros(unsigned long x)
{
	if (x == 0)
		return 64;
	return __builtin_clzl(x);
}
