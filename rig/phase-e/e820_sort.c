/* The REAL pristine lib/sort.c (the kernel's heapsort), compiled as k_sort/k_sort_r/... so the harness can wrap it. */
#include "e820_shim.h"
#define sort k_sort
#define sort_r k_sort_r
#define sort_nonatomic k_sort_nonatomic
#define sort_r_nonatomic k_sort_r_nonatomic
#include SORTC
