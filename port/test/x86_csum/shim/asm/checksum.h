#ifndef SHIM_asm_checksum_h
#define SHIM_asm_checksum_h
/* userspace shim: the declarations csum-partial_64.c needs. csum_fold is
 * copied VERBATIM from arch/x86/include/asm/checksum_64.h (6.18.49). */
#include <linux/compiler.h>
static inline __sum16 csum_fold(__wsum sum)
{
	asm("  addl %1,%0\n"
	    "  adcl $0xffff,%0"
	    : "=r" (sum)
	    : "r" ((__force u32)sum << 16),
	      "0" ((__force u32)sum & 0xffff0000));
	return (__force __sum16)(~(__force u32)sum >> 16);
}
__wsum csum_partial(const void *buff, int len, __wsum sum);
__sum16 ip_compute_csum(const void *buff, int len);
#endif
