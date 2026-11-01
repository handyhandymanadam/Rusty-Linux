/* -include'd into the TEST copy of kaslr.c only: prototypes of the renamed hardware leaf calls (see run-kaslr.sh). */
#include <linux/types.h>
bool kaslr_hw_rdrand_long(unsigned long *v);
u64 kaslr_hw_rdtsc(void);
unsigned char kaslr_hw_inb(unsigned short port);
void kaslr_hw_outb(unsigned char v, unsigned short port);
