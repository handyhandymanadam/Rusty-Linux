/* SPDX-License-Identifier: GPL-2.0
 *
 * The sort() oracle. NOT a transcription: this compiles the pristine
 * lib/sort.c itself, with its exported names moved aside so both arms can
 * live in one binary. See README.
 */
#define sort_r			ref_sort_r
#define sort_r_nonatomic	ref_sort_r_nonatomic
#define sort			ref_sort
#define sort_nonatomic		ref_sort_nonatomic

#include "../../pristine/lib/sort.c"
