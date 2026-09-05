/* SPDX-License-Identifier: GPL-2.0
 *
 * The SECOND sort() oracle: the same pristine lib/sort.c, compiled in the
 * configuration our kernels actually build.
 *
 * logs/floor.md criterion 8. sort.c forks on CONFIG_64BIT (swap_words_64
 * moves 8 bytes at a time instead of two 4-byte transfers) and on
 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS (is_aligned stops ORing the base
 * address into the alignment test). Both are set on x86-64. ref_sort.c sets
 * neither, so until 2026-09-03 the harness compared the Rust's x86-64 path
 * against a C oracle built for a 32-bit machine with slow unaligned access --
 * the two arms were not the same configuration at all, and agreed anyway
 * because both sort correctly.
 *
 * Kept as a pair rather than replaced: the Rust carries BOTH paths and takes
 * the fork as a runtime argument, so testing only this one would leave its
 * generic path as ported code no test anywhere executes -- the shape this
 * project deleted bcj_ia64 for.
 */
#define CONFIG_64BIT				1
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS	1

#define sort_r			ref64_sort_r
#define sort_r_nonatomic	ref64_sort_r_nonatomic
#define sort			ref64_sort
#define sort_nonatomic		ref64_sort_nonatomic

#include "../../pristine/lib/sort.c"
