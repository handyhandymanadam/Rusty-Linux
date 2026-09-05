/* SPDX-License-Identifier: GPL-2.0
 *
 * The xz harness's userspace config, EXTENDED rather than forked.
 *
 * port/test/xz/shim/xz_config.h was written for xz_dec_bcj.c. xz_dec_stream.c
 * reaches for a few more things. Including the existing file rather than
 * copying it is deliberate: four forks of <linux/kernel.h> drifted 40-71 lines
 * apart in this project and silently changed which code paths the ORACLE
 * compiled. See logs/floor.md RULE T4.
 */
#ifndef _XZ_STREAM_SHIM_CONFIG_H
#define _XZ_STREAM_SHIM_CONFIG_H

#include "../../xz/shim/xz_config.h"

#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif

/* xz_dec_lzma2.c needs these; xz_dec_bcj.c did not. The allocators are the
 * ones xz_dec_lzma2_create() uses and which stay C in the port -- the harness
 * only has to make them exist, not make them kernel-accurate. */
#include <stdlib.h>
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef vmalloc
#define vmalloc(n) malloc(n)
#define vfree(p)   free(p)
#endif

#endif
