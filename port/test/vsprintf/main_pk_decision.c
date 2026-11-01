/* SPDX-License-Identifier: GPL-2.0 */
/*
 * %pK's restricted_pointer_decision() -- the PURE half of the pure/impure
 * split (see vsprintf_rs.rs's own module doc). There is no C function to
 * diff against here: the split itself is this project's own design, not
 * upstream's, so the oracle is upstream restricted_pointer()'s own switch
 * (port/pristine/lib/vsprintf.c:860-901), hand-transcribed into the table
 * below and checked against vsprintf_rs_restricted_pointer_decision()
 * directly. No kernel/IRQ/credential state needed -- that's the whole point
 * of factoring the decision out: the pure function is fully exercisable in
 * plain userspace, unlike the impure wrapper's two calls into real IRQ/cred
 * machinery (vsprintf_c_in_irq_context/vsprintf_c_restricted_pointer_cred_ok),
 * which stay untestable here and need a kernel-side self-test instead (not
 * built as part of this pass -- see vsprintf_rs.rs's own module doc).
 */
#include <stdio.h>
#include <stdint.h>

enum decision { HASH_AS_P = 0, PK_ERROR = 1, REAL = 2, NUL = 3 };

extern int vsprintf_rs_restricted_pointer_decision(int kptr_restrict_val, _Bool irq,
						    _Bool may_reveal_present, _Bool may_reveal_value,
						    int field_width, int *out_field_width);

static unsigned long total, failed;

static void check(const char *label, int kptr_restrict_val, _Bool irq,
		   _Bool may_reveal_present, _Bool may_reveal_value, int field_width,
		   int want_tag, int want_field_width)
{
	int out_fw = -12345;
	int tag = vsprintf_rs_restricted_pointer_decision(kptr_restrict_val, irq,
							   may_reveal_present, may_reveal_value,
							   field_width, &out_fw);
	total++;
	if (tag != want_tag || (want_tag == PK_ERROR && out_fw != want_field_width)) {
		failed++;
		printf("MISMATCH %-28s got tag=%d out_fw=%d want tag=%d out_fw=%d\n",
		       label, tag, out_fw, want_tag, want_field_width);
	}
}

int main(void)
{
	int ptr_hex_width = 2 * (int)sizeof(void *); /* 16 on x86_64 */

	/* kptr_restrict == 0: always hash-as-%p, irq/cred irrelevant. */
	check("restrict0_noirq", 0, 0, 0, 0, -1, HASH_AS_P, -1);
	check("restrict0_irq", 0, 1, 0, 0, -1, HASH_AS_P, -1);

	/* kptr_restrict == 1, irq: pK-error, field_width defaulted iff -1. */
	check("restrict1_irq_fw_default", 1, 1, 0, 0, -1, PK_ERROR, ptr_hex_width);
	check("restrict1_irq_fw_explicit", 1, 1, 0, 0, 8, PK_ERROR, 8);
	/* irq is checked before may_reveal -- a (structurally impossible)
	 * may_reveal alongside irq=true must not change the outcome. */
	check("restrict1_irq_ignores_may_reveal", 1, 1, 1, 1, -1, PK_ERROR, ptr_hex_width);

	/* kptr_restrict == 1, !irq: cred check result decides real vs null. */
	check("restrict1_noirq_cred_ok", 1, 0, 1, 1, -1, REAL, -1);
	check("restrict1_noirq_cred_bad", 1, 0, 1, 0, -1, NUL, -1);
	/* may_reveal absent here is impossible by contract (the impure
	 * wrapper only omits it when irq or kptr_restrict != 1) -- the pure
	 * function still must fail safe (never leak) rather than panic. */
	check("restrict1_noirq_no_check_failsafe", 1, 0, 0, 0, -1, NUL, -1);

	/* kptr_restrict == 2: always null, irq/cred irrelevant. */
	check("restrict2_noirq", 2, 0, 0, 0, -1, NUL, -1);
	check("restrict2_irq", 2, 1, 0, 0, -1, NUL, -1);

	/* Any other value (including negative): same as 2, always null. */
	check("restrict3_noirq", 3, 0, 0, 0, -1, NUL, -1);
	check("restrict_negative_noirq", -1, 0, 0, 0, -1, NUL, -1);
	check("restrict99_irq", 99, 1, 0, 0, -1, NUL, -1);

	printf("%lu cases, %lu mismatches\n", total, failed);
	return failed ? 1 : 0;
}
