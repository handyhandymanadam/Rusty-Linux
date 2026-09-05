/* SPDX-License-Identifier: GPL-2.0
 *
 * Reproducer, NOT part of the differential. An UPSTREAM CANDIDATE against the
 * pristine kernel C -- nothing is packaged and nothing has been sent.
 *
 * lib/zstd/common/fse_decompress.c, FSE_buildDTable_internal(). The lowprob
 * pass does
 *
 *     if (normalizedCounter[s] == -1) tableDecode[highThreshold--].symbol = s;
 *
 * once per symbol in 0..maxSymbolValue, and `highThreshold` is a U32 starting
 * at tableSize-1. The three sanity checks above it bound wkspSize,
 * maxSymbolValue, and the UPPER end of tableLog. Nothing bounds the number of
 * lowprob symbols against the table size, so more than 1<<tableLog of them
 * wraps highThreshold below zero and the write lands far outside `dt`.
 *
 * Build (from the repo root):
 *   cc -O1 -g -I port/test/zstd_entropy/shim -I port/test/common/shim \
 *      -I src/linux/lib/zstd/common -I src/linux/include \
 *      -o /tmp/repro port/test/zstd_entropy/repro_builddtable_oob.c \
 *      port/pristine/lib/zstd/common/{fse_decompress,entropy_common,error_private}.c
 *
 * Observed, all 256 counts set to -1:
 *   tableLog=5  (tableSize 32)  -> SIGSEGV
 *   tableLog=6  (tableSize 64)  -> SIGSEGV
 *   tableLog=8  (tableSize 256) -> returns 0, writes stay in bounds (256<=256)
 *
 * REACHABILITY: not reachable in-tree. FSE_buildDTable_wksp, the only public
 * way in, has zero callers anywhere in the kernel. The one other route into
 * FSE_buildDTable_internal is FSE_decompress_wksp_body, which takes both the
 * counter and tableLog from FSE_readNCount -- and that enforces
 * tableLog >= FSE_MIN_TABLELOG and decrements `remaining` (initialised to
 * tableSize+1) once per lowprob symbol, so it cannot emit more than tableSize
 * of them. Same shape as the two lib/xz MicroLZMA findings: real, and behind
 * a door nothing in this kernel opens. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define FSE_STATIC_LINKING_ONLY
#include "fse.h"

int main(int argc, char **argv)
{
    unsigned tableLog = argc > 1 ? (unsigned)atoi(argv[1]) : 5;
    unsigned maxSV    = argc > 2 ? (unsigned)atoi(argv[2]) : 255;
    size_t dtU32 = FSE_DTABLE_SIZE_U32(15);
    size_t wsz   = FSE_BUILD_DTABLE_WKSP_SIZE(15, 255);
    /* Give it a table sized for tableLog exactly, then a big red zone, so we
     * can see how far past the end it goes without dying. */
    size_t guard = 1u << 20;
    unsigned char *dtmem = calloc(1, dtU32 * 4 + guard);
    unsigned char *ws    = calloc(1, wsz + guard);
    short nc[256];
    unsigned i;
    size_t r, far = 0;
    unsigned char *end = dtmem + FSE_DTABLE_SIZE(tableLog <= 15 ? tableLog : 15);

    for (i = 0; i < 256; i++) nc[i] = -1;      /* every symbol lowprob */
    r = FSE_buildDTable_wksp((FSE_DTable *)dtmem, nc, maxSV, tableLog, ws, wsz);

    for (i = 0; i < dtU32 * 4 + guard; i++)
        if (dtmem[i]) far = i;
    printf("tableLog=%u maxSV=%u -> ret=%zu (isError=%u)\n", tableLog, maxSV, r, ERR_isError(r));
    printf("  table for tableLog=%u ends at +%td; highest byte written: +%zu  (%s)\n",
           tableLog, (ptrdiff_t)(end - dtmem), far,
           far >= (size_t)(end - dtmem) ? "PAST THE END" : "in bounds");
    return 0;
}
