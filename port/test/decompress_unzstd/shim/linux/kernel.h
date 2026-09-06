/* SPDX-License-Identifier: GPL-2.0 */
/* zstd_entropy's <linux/kernel.h>: the shared base, plus nothing.
 *
 * lib/zstd needs no per-module delta, but the file has to exist anyway so
 * that the #error guard below can fire. Without a file here, a build that
 * forgot the common -I would fall through to /usr/include/linux/kernel.h and
 * compile SOMETHING -- a hole found by adversarial review on 2026-09-04.
 */
#include_next <linux/kernel.h>

#ifndef _SHIM_COMMON_LINUX_KERNEL_H
#error "port/test/common/shim must be on the include path (see run.sh -I flags)"
#endif
