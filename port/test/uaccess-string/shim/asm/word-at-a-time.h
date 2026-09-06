#pragma once
/* Reproduces arch/x86/include/asm/word-at-a-time.h's CONFIG_64BIT arm
 * exactly (verified by reading that file directly, md5-porter 2026-09-05).
 * load_unaligned_zeropad() is deliberately NOT reproduced: neither
 * strnlen_user.c nor strncpy_from_user.c calls it (confirmed by grep). */
#include <linux/wordpart.h>

struct word_at_a_time {
	unsigned long one_bits, high_bits;
};

#define WORD_AT_A_TIME_CONSTANTS { REPEAT_BYTE(0x01), REPEAT_BYTE(0x80) }

static inline unsigned long has_zero(unsigned long a, unsigned long *bits,
				      const struct word_at_a_time *c)
{
	unsigned long mask = ((a - c->one_bits) & ~a) & c->high_bits;
	*bits = mask;
	return mask;
}

static inline unsigned long prep_zero_mask(unsigned long a, unsigned long bits,
					    const struct word_at_a_time *c)
{
	(void)a;
	(void)c;
	return bits;
}

#define create_zero_mask(bits) (bits)

static inline unsigned long zero_bytemask(unsigned long bits)
{
	bits = (bits - 1) & ~bits;
	return bits >> 7;
}

#define find_zero(bits) ((unsigned long)(__builtin_ctzl(bits) >> 3))
