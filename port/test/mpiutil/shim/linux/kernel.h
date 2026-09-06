#pragma once
#include <linux/types.h>
#include <stdio.h>

/* pr_info() as mpiutil.c's own call site uses it: one fixed string, no
 * format arguments. */
#define pr_info(fmt) printf("%s", fmt)
