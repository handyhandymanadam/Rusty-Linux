#pragma once
/* mpicoder.c's only use of longlong.h is count_leading_zeros(), from
 * linux/count_zeros.h, which the real longlong.h just #includes. */
#include <linux/count_zeros.h>
