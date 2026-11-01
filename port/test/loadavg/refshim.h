#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FSHIFT 11
#define FIXED_1 (1 << FSHIFT)
static inline unsigned long calc_load(unsigned long load, unsigned long exp, unsigned long active)
{
	unsigned long newload;
	newload = load * exp + active * (FIXED_1 - exp);
	if (active >= load)
		newload += FIXED_1-1;
	return newload / FIXED_1;
}
#endif
