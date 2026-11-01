/* SPDX-License-Identifier: GPL-2.0 */
/* Exhaustive differential for fs/fs_types.c: pristine C (c_*) vs fs_types_rs.rs over EVERY input:
 * fs_ftype_to_dtype over all 2^32 values (strided above 1M), fs_umode_to_{ftype,dtype} over all 65536 modes. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
unsigned char c_fs_ftype_to_dtype(unsigned int), c_fs_umode_to_ftype(unsigned short), c_fs_umode_to_dtype(unsigned short);
unsigned char fs_ftype_to_dtype(unsigned int), fs_umode_to_ftype(unsigned short), fs_umode_to_dtype(unsigned short);
int main(void)
{
	unsigned long long fails = 0, checks = 0;
	int poison = getenv("FST_PROVE_CAN_FAIL") != 0;
	for (uint64_t f = 0; f < (1ULL << 32); f += (f < 1000000 ? 1 : 4097)) {
		unsigned char a = c_fs_ftype_to_dtype(f), b = fs_ftype_to_dtype(f);
		if (poison && f == 5) b++;
		checks++; if (a != b && fails++ < 10) fprintf(stderr, "ftype_to_dtype(%llu): c=%u rs=%u\n", (unsigned long long)f, a, b);
	}
	for (unsigned m = 0; m < 65536; m++) {
		unsigned char a = c_fs_umode_to_ftype(m), b = fs_umode_to_ftype(m), c = c_fs_umode_to_dtype(m), d = fs_umode_to_dtype(m);
		checks += 2;
		if (a != b && fails++ < 10) fprintf(stderr, "umode_to_ftype(%#x): c=%u rs=%u\n", m, a, b);
		if (c != d && fails++ < 10) fprintf(stderr, "umode_to_dtype(%#x): c=%u rs=%u\n", m, c, d);
	}
	printf("%llu checks, %llu failures\n", checks, fails);
	return fails != 0;
}
