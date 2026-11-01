/* SPDX-License-Identifier: GPL-2.0 */
/* Exhaustive differential for arch/x86/lib/cpu.c: x86_family / x86_model /
 * x86_stepping over ALL 2^32 CPUID(1).EAX signatures, pristine C (renamed c_*)
 * against the Rust, and both against an INDEPENDENT oracle written from the
 * Intel SDM CPUID.1:EAX definition (family = base family, plus extended family
 * when base == 0xF; model = base model, plus extended model << 4 when
 * family >= 6 (the kernel's rule, wider than the SDM's 6/15 so that AMD
 * family 0x17+ parts get an extended model); stepping = low nibble) -- computed
 * with 64-bit field extraction, sharing no expression with either arm.
 * usage: main SHARD NSHARDS ; CPU_PROVE_CAN_FAIL=1 poisons one Rust result.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int c_x86_family(unsigned int), c_x86_model(unsigned int), c_x86_stepping(unsigned int);
unsigned int x86_family(unsigned int), x86_model(unsigned int), x86_stepping(unsigned int);

static unsigned o_family(uint64_t sig)
{
	uint64_t base = (sig & 0xf00) >> 8, ext = (sig & 0xff00000) >> 20;
	return (unsigned)(base == 0xf ? base + ext : base);
}
static unsigned o_model(uint64_t sig)
{
	uint64_t m = (sig & 0xf0) >> 4, ext = (sig & 0xf0000) >> 16;
	return (unsigned)(o_family(sig) >= 6 ? m + ext * 16 : m);
}
static unsigned o_stepping(uint64_t sig) { return (unsigned)(sig & 0xf); }

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
	unsigned nsh = argc > 2 ? (unsigned)atoi(argv[2]) : 1;
	int poison = getenv("CPU_PROVE_CAN_FAIL") != NULL;
	unsigned long long n = 0, fails = 0;
	uint64_t i;

	for (i = shard; i <= 0xffffffffULL; i += nsh) {
		unsigned s = (unsigned)i;
		unsigned cf = c_x86_family(s), cm = c_x86_model(s), cs = c_x86_stepping(s);
		unsigned rf = x86_family(s), rm = x86_model(s), rs = x86_stepping(s);

		if (poison && s == 0x000306a9) rm++;
		n++;
		if (cf != rf || cm != rm || cs != rs || cf != o_family(s) || cm != o_model(s) || cs != o_stepping(s)) {
			if (fails++ < 10)
				fprintf(stderr, "MISMATCH sig=%#x family c=%u r=%u o=%u model c=%u r=%u o=%u step c=%u r=%u o=%u\n",
					s, cf, rf, o_family(s), cm, rm, o_model(s), cs, rs, o_stepping(s));
		}
	}
	printf("shard %u/%u: %llu signatures x 3 functions, %llu failure(s)\n", shard, nsh, n, fails);
	return fails ? 1 : 0;
}
