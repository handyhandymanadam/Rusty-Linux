/* Force-included ahead of the pristine C oracle compile (-DSTATIC=static):
 * mm.h's bump allocator uses free_mem_ptr/free_mem_end_ptr without
 * declaring them -- normally supplied by an arch boot/compressed/misc.c.
 * drv.c defines the real storage; this just declares it for this TU. */
#include <stddef.h>
#include <string.h>
extern unsigned long free_mem_ptr;
extern unsigned long free_mem_end_ptr;
