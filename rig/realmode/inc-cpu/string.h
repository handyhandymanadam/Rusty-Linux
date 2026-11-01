/* Host stand-in for arch/x86/boot/string.h (cpucheck.c only needs memset). */
#ifndef BOOT_STRING_H
#define BOOT_STRING_H
void *memset(void *s, int c, unsigned long n);
#endif
