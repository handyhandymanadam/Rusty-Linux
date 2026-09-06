#pragma once
#include <linux/types.h>
/* This is the LAST header pristine/lib/seq_buf.c includes before its own
 * body -- glibc's <endian.h> (pulled in transitively by <stdint.h>/
 * <stdio.h> earlier in that chain) unconditionally #defines BOTH
 * __BIG_ENDIAN and __LITTLE_ENDIAN as numeric constants, unlike the
 * kernel's own byteorder headers which define only the one that applies.
 * Left defined, seq_buf_putmem_hex()'s own `#ifdef __BIG_ENDIAN` would
 * take the wrong (forward-order) branch on this little-endian host.
 * A command-line `-U__BIG_ENDIAN` does not survive past glibc's own
 * #define, so it has to be undone here instead, after every header that
 * could have defined it and before the .c file's own check. */
#undef __BIG_ENDIAN
/* Simulated in the driver: a fixed "valid user range" is memcpy'd into for
 * real; anything outside it fails exactly like a real unmapped user
 * address would (returns n, meaning nothing copied). Shared by the
 * pristine reference (via the copy_to_user() macro below) and the port's
 * own rust_seq_buf_copy_to_user() thunk (lib/seq_buf.c, compiled with
 * this same shim) -- both sides exercise the identical fake primitive.
 */
unsigned long test_copy_to_user(void *to, const void *from, unsigned long n);
static inline unsigned long copy_to_user(void *to, const void *from, unsigned long n)
{
	return test_copy_to_user(to, from, n);
}
