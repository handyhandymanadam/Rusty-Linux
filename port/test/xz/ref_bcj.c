/* SPDX-License-Identifier: 0BSD */
/*
 * The oracle: PRISTINE lib/xz/xz_dec_bcj.c, compiled under renamed globals so
 * both arms live in one binary.
 *
 * Nothing is transcribed. The file is #include'd, which is the idiom
 * port/test/lib/ref_sort.c established -- a hand copy is the largest standing
 * liability this project can create for itself, and a change to the pristine
 * file has to show up as a test result rather than as silence.
 *
 * NOT -Dstatic=. That would break the `static inline` bcj_x86_test_msbyte()
 * (a C99 inline definition with no external definition) and would silently
 * turn three function-local `static const` tables into per-call automatic
 * arrays -- a different program from the one the kernel compiles.
 *
 * The filters stay static; the trampoline at the bottom is how the harness
 * reaches them.
 */

/* The seven filters 6.18 can actually build. XZ_DEC_IA64 is deliberately NOT
 * defined: there is no CONFIG_XZ_DEC_IA64 stanza in lib/xz/Kconfig, so no
 * kernel enables it, and the Rust does not implement it. Defining it here
 * would test a filter that ships in nothing. */
#define XZ_DEC_X86
#define XZ_DEC_POWERPC
#define XZ_DEC_ARM
#define XZ_DEC_ARMTHUMB
#define XZ_DEC_SPARC
#define XZ_DEC_ARM64
#define XZ_DEC_RISCV

#define xz_dec_bcj_create ref_xz_dec_bcj_create
#define xz_dec_bcj_reset  ref_xz_dec_bcj_reset
#define xz_dec_bcj_run    ref_xz_dec_bcj_run

#include "xz_dec_bcj.c"

/* --- trampolines, after the include so struct xz_dec_bcj is complete --- */

size_t ref_bcj_filter(uint32_t kind, uint32_t pos, uint32_t *prev_mask,
		      uint8_t *buf, size_t size);
size_t ref_state_size(void);

size_t ref_bcj_filter(uint32_t kind, uint32_t pos, uint32_t *prev_mask,
		      uint8_t *buf, size_t size)
{
	struct xz_dec_bcj s;
	size_t r;

	memset(&s, 0, sizeof(s));
	s.pos = pos;
	s.x86_prev_mask = *prev_mask;

	switch (kind) {
	case BCJ_X86:      r = bcj_x86(&s, buf, size); break;
	case BCJ_POWERPC:  r = bcj_powerpc(&s, buf, size); break;
	case BCJ_ARM:      r = bcj_arm(&s, buf, size); break;
	case BCJ_ARMTHUMB: r = bcj_armthumb(&s, buf, size); break;
	case BCJ_SPARC:    r = bcj_sparc(&s, buf, size); break;
	case BCJ_ARM64:    r = bcj_arm64(&s, buf, size); break;
	case BCJ_RISCV:    r = bcj_riscv(&s, buf, size); break;
	default:           r = 0; break;
	}

	*prev_mask = s.x86_prev_mask;
	return r;
}

size_t ref_state_size(void)
{
	return sizeof(struct xz_dec_bcj);
}
