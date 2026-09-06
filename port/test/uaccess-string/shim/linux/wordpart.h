#pragma once
/* Little-endian arm only -- this project is x86-64 only. Matches
 * include/linux/wordpart.h exactly. */
#define REPEAT_BYTE(x)        ((~0ul / 0xff) * (x))
#define aligned_byte_mask(n)  ((1UL << (8 * (n))) - 1)
