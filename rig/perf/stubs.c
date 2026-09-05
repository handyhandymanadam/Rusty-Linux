/* SPDX-License-Identifier: GPL-2.0
 *
 * The handful of C helpers the Rust bodies call back into. In the kernel
 * these are real: a memzero_explicit, a cond_resched, a pr_warn. Here they
 * only have to exist and do the same amount of work, because the rig is
 * measuring the ported body, not the kernel primitive.
 */
#include <string.h>

struct chacha_state { unsigned int x[16]; };

void rust_chacha_zeroize_state(struct chacha_state *s);
void rust_chacha_zeroize_state(struct chacha_state *s)
{
	memset(s, 0, sizeof(*s));
}

void rust_sort_cond_resched(void);
void rust_sort_cond_resched(void) { }

void rust_earlycpio_warn_long_name(const char *name);
void rust_earlycpio_warn_long_name(const char *name) { (void)name; }

/* lib/check_signature_rs.rs. In the kernel this is rust/helpers/io.c: readb()
 * plus the architecture's ordering barriers, against a device window. Here it
 * is the plain load -- which is the WORST case for the port, not a
 * flattering one: it makes the un-inlined call the whole of the difference
 * being measured. Against real MMIO the call disappears into the bus access. */
unsigned char rust_helper_readb(const volatile void *addr);
unsigned char rust_helper_readb(const volatile void *addr)
{
	return *(const volatile unsigned char *)addr;
}
