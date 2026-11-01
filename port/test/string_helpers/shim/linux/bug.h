/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_BUG_H
#define _SHIM_LINUX_BUG_H
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#define WARN_ON(cond) ({ int __r = !!(cond); if (__r) fprintf(stderr, "WARN_ON(" #cond ")\n"); __r; })
#define BUG() abort()
#endif
