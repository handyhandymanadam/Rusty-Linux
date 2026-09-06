/* SPDX-License-Identifier: GPL-2.0 */
/* BUG_ON() here RECORDS instead of crashing the whole differential --
 * drv.c compares whether both arms would have fired it for the same
 * inputs, rather than aborting the process (which the real kernel's
 * BUG_ON does, and which the retained C thunk in port/tree/lib/
 * dynamic_queue_limits.c still reproduces literally). */
#ifndef _SHIM_ASM_BUG_H
#define _SHIM_ASM_BUG_H

void dql_test_record_bug(void);
#define BUG_ON(cond) do { if (cond) dql_test_record_bug(); } while (0)

#endif
