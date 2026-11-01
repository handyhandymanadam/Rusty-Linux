#ifndef SHIM_asm_word_at_a_time_h
#define SHIM_asm_word_at_a_time_h
/* userspace stand-in for load_unaligned_zeropad(): the kernel's version takes an
 * exception when the 8 bytes cross into an unmapped page and returns zeroes for
 * the part that does not exist (fixup: load the aligned word, shift). Here a
 * load that crosses into the harness's guard page takes that path, any other
 * load is a plain 8-byte load, so the C never faults in the harness. */
#include <string.h>
extern unsigned long shim_guard_page;	/* the harness's PROT_NONE page: the only unmapped one */
static inline unsigned long load_unaligned_zeropad(const void *addr)
{
	unsigned long a = (unsigned long)addr, r;
	if ((a & 4095) > 4096 - 8 && ((a | 4095) + 1) == shim_guard_page) {
		memcpy(&r, (const void *)(a & ~7UL), 8);
		return r >> (8 * (a & 7));
	}
	memcpy(&r, addr, 8);
	return r;
}
#endif
