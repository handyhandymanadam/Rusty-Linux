#pragma once
/* Real (not stubbed) reproduction of include/linux/count_zeros.h's
 * count_leading_zeros() on a 64-bit long, without pulling in
 * <asm/bitops.h>'s kernel-internal fls64(). __builtin_clzl is the same
 * "count leading zeros, 0 is a defined case" operation GCC/clang provide
 * directly, and (BITS_PER_LONG - fls64(x)) is exactly clz(x) for x != 0;
 * fls64(0) == 0 so count_leading_zeros(0) == BITS_PER_LONG, which
 * __builtin_clzl(0) does NOT give (it is undefined for a zero argument on
 * this compiler), so that one case is special-cased explicitly. */
static inline int count_leading_zeros(unsigned long x)
{
	if (x == 0)
		return 64;
	return __builtin_clzl(x);
}
