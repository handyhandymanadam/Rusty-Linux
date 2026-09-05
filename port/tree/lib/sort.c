// SPDX-License-Identifier: GPL-2.0
/*
 * A fast, small, non-recursive O(n log n) sort for the Linux kernel
 *
 * This performs n*log2(n) + 0.37*n + o(n) comparisons on average,
 * and 1.5*n*log2(n) + O(n) in the (very contrived) worst case.
 *
 * Quicksort manages n*log2(n) - 1.26*n for random inputs (1.63*n
 * better) at the expense of stack usage and much larger code to avoid
 * quicksort's O(n^2) worst case.
 *
 * PORTED TO RUST. The heapsort, the three built-in swap strategies and the
 * branch-free parent() are all lib/sort_rs.rs. What is left here is the four
 * C entry symbols, their EXPORT_SYMBOL() lines, and two things Rust cannot
 * reach:
 *
 *   cond_resched()   a scheduling primitive, and under CONFIG_PREEMPT_DYNAMIC
 *                    a static call patched at boot. Reached through
 *                    rust_sort_cond_resched() below.
 *
 *   CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
 *                    decides whether the base address has to be aligned for
 *                    word-wide swaps. Passed in as a bool rather than guessed
 *                    at in the Rust: guessing would silently pick a different
 *                    swap strategy on an architecture nobody was testing on.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sort.h>

/*
 * The values are arbitrary as long as they can't be confused with
 * a pointer, but small integers make for the smallest compare
 * instructions. Kept in step with lib/sort_rs.rs, which compares against
 * the same four.
 */
#define SWAP_WRAPPER  ((swap_r_func_t)3)
#define _CMP_WRAPPER  ((cmp_r_func_t)0L)

#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define SORT_EFFICIENT_UNALIGNED true
#else
#define SORT_EFFICIENT_UNALIGNED false
#endif

struct wrapper {
	cmp_func_t cmp;
	swap_func_t swap;
};

/* lib/sort_rs.rs */
void rust_sort_r(void *base, size_t num, size_t size,
		 cmp_r_func_t cmp_func, swap_r_func_t swap_func,
		 const void *priv, bool may_schedule, bool efficient_unaligned);

/* Called from lib/sort_rs.rs. */
void rust_sort_cond_resched(void);
void rust_sort_cond_resched(void)
{
	cond_resched();
}

static void __sort_r(void *base, size_t num, size_t size,
		     cmp_r_func_t cmp_func,
		     swap_r_func_t swap_func,
		     const void *priv,
		     bool may_schedule)
{
	rust_sort_r(base, num, size, cmp_func, swap_func, priv, may_schedule,
		    SORT_EFFICIENT_UNALIGNED);
}

/**
 * sort_r - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 * @priv: third argument passed to comparison function
 *
 * This function does a heapsort on the given array.  You may provide
 * a swap_func function if you need to do something more than a memory
 * copy (e.g. fix up pointers or auxiliary data), but the built-in swap
 * avoids a slow retpoline and so is significantly faster.
 *
 * The comparison function must adhere to specific mathematical
 * properties to ensure correct and stable sorting:
 * - Antisymmetry: cmp_func(a, b) must return the opposite sign of
 * cmp_func(b, a).
 * - Transitivity: if cmp_func(a, b) <= 0 and cmp_func(b, c) <= 0, then
 * cmp_func(a, c) <= 0.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * quicksort is slightly faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */
void sort_r(void *base, size_t num, size_t size,
	    cmp_r_func_t cmp_func,
	    swap_r_func_t swap_func,
	    const void *priv)
{
	__sort_r(base, num, size, cmp_func, swap_func, priv, false);
}
EXPORT_SYMBOL(sort_r);

/**
 * sort_r_nonatomic - sort an array of elements, with cond_resched
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 * @priv: third argument passed to comparison function
 *
 * Same as sort_r, but preferred for larger arrays as it does a periodic
 * cond_resched().
 */
void sort_r_nonatomic(void *base, size_t num, size_t size,
		      cmp_r_func_t cmp_func,
		      swap_r_func_t swap_func,
		      const void *priv)
{
	__sort_r(base, num, size, cmp_func, swap_func, priv, true);
}
EXPORT_SYMBOL(sort_r_nonatomic);

void sort(void *base, size_t num, size_t size,
	  cmp_func_t cmp_func,
	  swap_func_t swap_func)
{
	struct wrapper w = {
		.cmp  = cmp_func,
		.swap = swap_func,
	};

	return __sort_r(base, num, size, _CMP_WRAPPER, SWAP_WRAPPER, &w, false);
}
EXPORT_SYMBOL(sort);

void sort_nonatomic(void *base, size_t num, size_t size,
		    cmp_func_t cmp_func,
		    swap_func_t swap_func)
{
	struct wrapper w = {
		.cmp  = cmp_func,
		.swap = swap_func,
	};

	return __sort_r(base, num, size, _CMP_WRAPPER, SWAP_WRAPPER, &w, true);
}
EXPORT_SYMBOL(sort_nonatomic);
