/* Stand-ins for what the pristine slice of kernel/time/timer.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern unsigned long jiffies;
#define time_is_after_jiffies(a) ((long)((jiffies) - (a)) < 0)
#endif
