/* Host stand-in for arch/x86/boot/msr.h: boot_rdmsr/boot_wrmsr go to the device model. */
#ifndef BOOT_MSR_H
#define BOOT_MSR_H
#include <asm/shared/msr.h>
void mock_rdmsr(unsigned int reg, unsigned int *l, unsigned int *h);
void mock_wrmsr(unsigned int reg, unsigned int l, unsigned int h);
static inline void boot_rdmsr(unsigned int reg, struct msr *m) { mock_rdmsr(reg, &m->l, &m->h); }
static inline void boot_wrmsr(unsigned int reg, const struct msr *m) { mock_wrmsr(reg, m->l, m->h); }
#endif
