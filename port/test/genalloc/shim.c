/* Userspace stand-ins for the two kernel bitmap routines genalloc calls (lib/bitmap.c, lib/find_bit.c). Both arms use these. */
#include <stddef.h>
static unsigned long bit(const unsigned long *m, unsigned long i) { return (m[i / 64] >> (i % 64)) & 1; }
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	for (unsigned long i = start; i < nbits; i++) if (bit(addr, i)) return i;
	return nbits;
}
static unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	for (unsigned long i = start; i < nbits; i++) if (!bit(addr, i)) return i;
	return nbits;
}
/* lib/bitmap.c: bitmap_find_next_zero_area_off() */
unsigned long bitmap_find_next_zero_area_off(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr,
					     unsigned long align_mask, unsigned long align_offset)
{
	unsigned long index, end, i;
again:
	index = find_next_zero_bit(map, size, start);
	index = (((index + align_offset) + align_mask) & ~align_mask) - align_offset;
	end = index + nr;
	if (end > size)
		return end;
	i = _find_next_bit(map, end, index);
	if (i < end) {
		start = i + 1;
		goto again;
	}
	return index;
}
