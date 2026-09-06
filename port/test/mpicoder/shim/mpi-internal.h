#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpicoder.c references. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>
#include <linux/err.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* pr_info() output is not part of any function's observable contract
 * (return value / written data is), so a no-op is faithful for this
 * differential's purposes. */
#define pr_info(...) do { } while (0)
