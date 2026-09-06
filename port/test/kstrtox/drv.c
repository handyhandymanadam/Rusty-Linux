/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/kstrtox/drv.c -- differential for lib/kstrtox.c.
 *
 * The C arm is port/pristine/lib/kstrtox.c with every symbol it defines
 * renamed c_<name> (run.sh's -D flags); the Rust arm is
 * port/tree/lib/kstrtox_rs.rs generated at run time. Both are compiled
 * against the SAME shims (shim.c), so what is compared is the two parsers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* ---- C arm (renamed) --------------------------------------------------- */
int c_kstrtoull(const char *s, unsigned int base, unsigned long long *res);
int c_kstrtoll(const char *s, unsigned int base, long long *res);
int c__kstrtoul(const char *s, unsigned int base, unsigned long *res);
int c__kstrtol(const char *s, unsigned int base, long *res);
int c_kstrtouint(const char *s, unsigned int base, unsigned int *res);
int c_kstrtoint(const char *s, unsigned int base, int *res);
int c_kstrtou16(const char *s, unsigned int base, uint16_t *res);
int c_kstrtos16(const char *s, unsigned int base, int16_t *res);
int c_kstrtou8(const char *s, unsigned int base, uint8_t *res);
int c_kstrtos8(const char *s, unsigned int base, int8_t *res);
int c_kstrtobool(const char *s, bool *res);
int c_kstrtobool_from_user(const char *s, size_t count, bool *res);
int c_kstrtoull_from_user(const char *s, size_t count, unsigned int base, unsigned long long *res);
int c_kstrtouint_from_user(const char *s, size_t count, unsigned int base, unsigned int *res);
int c_kstrtou16_from_user(const char *s, size_t count, unsigned int base, uint16_t *res);
int c_kstrtou8_from_user(const char *s, size_t count, unsigned int base, uint8_t *res);

/* ---- Rust arm ------------------------------------------------------------ */
int kstrtoull(const char *s, unsigned int base, unsigned long long *res);
int kstrtoll(const char *s, unsigned int base, long long *res);
int _kstrtoul(const char *s, unsigned int base, unsigned long *res);
int _kstrtol(const char *s, unsigned int base, long *res);
int kstrtouint(const char *s, unsigned int base, unsigned int *res);
int kstrtoint(const char *s, unsigned int base, int *res);
int kstrtou16(const char *s, unsigned int base, uint16_t *res);
int kstrtos16(const char *s, unsigned int base, int16_t *res);
int kstrtou8(const char *s, unsigned int base, uint8_t *res);
int kstrtos8(const char *s, unsigned int base, int8_t *res);
int kstrtobool(const char *s, bool *res);
int kstrtobool_from_user(const char *s, size_t count, bool *res);
int kstrtoull_from_user(const char *s, size_t count, unsigned int base, unsigned long long *res);
int kstrtouint_from_user(const char *s, size_t count, unsigned int base, unsigned int *res);
int kstrtou16_from_user(const char *s, size_t count, unsigned int base, uint16_t *res);
int kstrtou8_from_user(const char *s, size_t count, unsigned int base, uint8_t *res);

static unsigned long cases, mism;

/* PROVE THE COMPARISON CAN DISAGREE. Same device as port/test/cmdline/'s:
 * with KSTRTOX_PROVE_CAN_FAIL=1 the Rust arm's input is corrupted by one bit
 * before it parses, so the run MUST report mismatches; run.sh fails if it
 * does not. */
static int poison;

static const char *maybe_poison(const char *in, char *scratch, size_t n)
{
	if (!poison || !in[0])
		return in;
	snprintf(scratch, n, "%s", in);
	scratch[0] ^= 1;
	return scratch;
}

static void bad(const char *what, const char *in, unsigned int base)
{
	if (mism < 30)
		printf("MISMATCH %-24s base=%-3u on \"%s\"\n", what, base, in);
	mism++;
}

/* ---- the corpus --------------------------------------------------------- */
static const char *CORPUS[] = {
	"", "0", "1", "-1", "+1", "-0", "+0",
	"10", "0x10", "0X10", "010", "0x", "0X", "0",
	"10\n", "10\n\n", "10\n1", " 10", "10 ", "+", "-", "\n",
	"abc", "0xag", "0xFF", "0xff", "0Xff", "18446744073709551615",
	"18446744073709551616", "18446744073709551617",
	"-9223372036854775808", "-9223372036854775809", "9223372036854775807",
	"9223372036854775808", "4294967295", "4294967296", "-4294967296",
	"65535", "65536", "-65536", "255", "256", "-256", "127", "128", "-128",
	"-129", "32767", "32768", "-32768", "-32769", "2147483647",
	"2147483648", "-2147483648", "-2147483649", "099", "0b11", "111",
	"1111111111111111111111111111111111111111", "e", "E", "y", "Y", "t",
	"T", "d", "D", "n", "N", "f", "F", "on", "On", "ON", "off", "Off",
	"o", "O", "oz", "ye", "2",
};
#define NCORPUS (sizeof(CORPUS) / sizeof(CORPUS[0]))
static const unsigned int BASES[] = {0, 2, 8, 10, 16};
#define NBASES (sizeof(BASES) / sizeof(BASES[0]))

/* One generic differential over every corpus string x every base, for a
 * fixed-width unsigned type. */
#define T_UNSIGNED(name, ty, cfn, rsfn, cast)                                \
	static void t_##name(void)                                           \
	{                                                                     \
		for (unsigned b = 0; b < NBASES; b++)                         \
			for (unsigned i = 0; i < NCORPUS; i++) {              \
				char scratch[128];                            \
				const char *in =                              \
					maybe_poison(CORPUS[i], scratch,      \
						     sizeof(scratch));         \
				ty rv = 0, cv = 0;                            \
				int rr, cr;                                   \
				rr = rsfn(in, BASES[b], &rv);                 \
				cr = cfn(CORPUS[i], BASES[b], &cv);           \
				cases++;                                      \
				if (rr != cr ||                               \
				    (rr == 0 && (cast)rv != (cast)cv))        \
					bad(#name, CORPUS[i], BASES[b]);      \
			}                                                      \
	}

#define T_SIGNED(name, ty, cfn, rsfn, cast) T_UNSIGNED(name, ty, cfn, rsfn, cast)

T_UNSIGNED(kstrtoull, unsigned long long, c_kstrtoull, kstrtoull, unsigned long long)
T_SIGNED(kstrtoll, long long, c_kstrtoll, kstrtoll, long long)
T_UNSIGNED(_kstrtoul, unsigned long, c__kstrtoul, _kstrtoul, unsigned long)
T_SIGNED(_kstrtol, long, c__kstrtol, _kstrtol, long)
T_UNSIGNED(kstrtouint, unsigned int, c_kstrtouint, kstrtouint, unsigned int)
T_SIGNED(kstrtoint, int, c_kstrtoint, kstrtoint, int)
T_UNSIGNED(kstrtou16, uint16_t, c_kstrtou16, kstrtou16, uint16_t)
T_SIGNED(kstrtos16, int16_t, c_kstrtos16, kstrtos16, int16_t)
T_UNSIGNED(kstrtou8, uint8_t, c_kstrtou8, kstrtou8, uint8_t)
T_SIGNED(kstrtos8, int8_t, c_kstrtos8, kstrtos8, int8_t)

static void t_kstrtobool(void)
{
	for (unsigned i = 0; i < NCORPUS; i++) {
		char scratch[128];
		const char *in = maybe_poison(CORPUS[i], scratch, sizeof(scratch));
		bool rv = false, cv = false;
		int rr = kstrtobool(in, &rv);
		int cr = c_kstrtobool(CORPUS[i], &cv);
		cases++;
		if (rr != cr || (rr == 0 && rv != cv))
			bad("kstrtobool", CORPUS[i], 0);
	}
	/* NULL -s is a documented -EINVAL path, both arms. */
	{
		bool rv = false, cv = false;
		int rr = kstrtobool(NULL, &rv);
		int cr = c_kstrtobool(NULL, &cv);
		cases++;
		if (rr != cr)
			bad("kstrtobool(NULL)", "<null>", 0);
	}
}

/* ---- _from_user: representative buffer-size classes --------------------- */

static void t_kstrtobool_from_user(void)
{
	for (unsigned i = 0; i < NCORPUS; i++) {
		char scratch[128];
		const char *in = maybe_poison(CORPUS[i], scratch, sizeof(scratch));
		size_t n = strlen(CORPUS[i]);
		bool rv = false, cv = false;
		int rr = kstrtobool_from_user(in, n, &rv);
		int cr = c_kstrtobool_from_user(CORPUS[i], n, &cv);
		cases++;
		if (rr != cr || (rr == 0 && rv != cv))
			bad("kstrtobool_from_user", CORPUS[i], 0);
	}
}

#define T_FROM_USER(name, ty, cfn, rsfn)                                     \
	static void t_##name(void)                                            \
	{                                                                      \
		for (unsigned b = 0; b < NBASES; b++)                         \
			for (unsigned i = 0; i < NCORPUS; i++) {              \
				char scratch[128];                            \
				const char *in =                              \
					maybe_poison(CORPUS[i], scratch,      \
						     sizeof(scratch));         \
				size_t n = strlen(CORPUS[i]);                 \
				ty rv = 0, cv = 0;                            \
				int rr = rsfn(in, n, BASES[b], &rv);          \
				int cr = cfn(CORPUS[i], n, BASES[b], &cv);    \
				cases++;                                      \
				if (rr != cr || (rr == 0 && rv != cv))        \
					bad(#name, CORPUS[i], BASES[b]);      \
			}                                                      \
	}

T_FROM_USER(kstrtoull_from_user, unsigned long long, c_kstrtoull_from_user, kstrtoull_from_user)
T_FROM_USER(kstrtouint_from_user, unsigned int, c_kstrtouint_from_user, kstrtouint_from_user)
T_FROM_USER(kstrtou16_from_user, uint16_t, c_kstrtou16_from_user, kstrtou16_from_user)
T_FROM_USER(kstrtou8_from_user, uint8_t, c_kstrtou8_from_user, kstrtou8_from_user)

/* ---- volume: randomised digit strings ------------------------------------ */
static void t_fuzz(void)
{
	static const char alphabet[] = "0123456789abcdefABCDEFxX+-\n \t";
	unsigned seed = 0xC0FFEE;
	for (int n = 0; n < 20000; n++) {
		char buf[24];
		seed = seed * 1103515245u + 12345u;
		int len = (int)((seed >> 16) % (sizeof(buf) - 1));
		unsigned s2 = seed;
		for (int i = 0; i < len; i++) {
			s2 = s2 * 1103515245u + 12345u;
			buf[i] = alphabet[(s2 >> 16) % (sizeof(alphabet) - 1)];
		}
		buf[len] = 0;

		for (unsigned b = 0; b < NBASES; b++) {
			char scratch[32];
			const char *in = maybe_poison(buf, scratch, sizeof(scratch));
			unsigned long long rv = 0, cv = 0;
			int rr = kstrtoull(in, BASES[b], &rv);
			int cr = c_kstrtoull(buf, BASES[b], &cv);
			cases++;
			if (rr != cr || (rr == 0 && rv != cv))
				bad("fuzz:kstrtoull", buf, BASES[b]);

			long long srv = 0, scv = 0;
			int srr = kstrtoll(in, BASES[b], &srv);
			int scr = c_kstrtoll(buf, BASES[b], &scv);
			cases++;
			if (srr != scr || (srr == 0 && srv != scv))
				bad("fuzz:kstrtoll", buf, BASES[b]);
		}
	}
}

int main(void)
{
	if (getenv("KSTRTOX_PROVE_CAN_FAIL"))
		poison = 1;

	t_kstrtoull();
	t_kstrtoll();
	t__kstrtoul();
	t__kstrtol();
	t_kstrtouint();
	t_kstrtoint();
	t_kstrtou16();
	t_kstrtos16();
	t_kstrtou8();
	t_kstrtos8();
	t_kstrtobool();
	t_kstrtobool_from_user();
	t_kstrtoull_from_user();
	t_kstrtouint_from_user();
	t_kstrtou16_from_user();
	t_kstrtou8_from_user();
	t_fuzz();

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
