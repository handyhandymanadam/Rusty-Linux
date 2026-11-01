// SPDX-License-Identifier: GPL-2.0-only
/*
 * deflate.c's exported entry symbols, for CONFIG_RUST=y. The compressor is
 * lib/zlib_deflate/deflate_rs.rs; the CONFIG_RUST=n arm builds the pristine
 * deflate.c instead (see the Makefile).
 *
 * WHY THESE STAY C. All six are EXPORT_SYMBOL'd in deflate_syms.c, so their
 * MODVERSIONS CRCs come from the DWARF of the DEFINITION (GOALS.md section 2,
 * criterion 4); defining them in Rust would change the CRCs. Same arrangement
 * as lib/zlib_inflate/inflate_thunk.c.
 *
 * Three are one-line thunks. zlib_deflateInit2() keeps its argument guards and
 * the carving of the workspace, because struct deflate_workspace is a C type
 * the Rust does not mirror (and under CONFIG_ZLIB_DFLTCC its layout depends on
 * PAGE_SIZE); it hands the Rust the four pointers. zlib_deflate_workspacesize()
 * has a BUG_ON and sizeof(deflate_workspace). zlib_deflate_dfltcc_enabled() is
 * a constant.
 */

#include <linux/module.h>
#include <linux/zutil.h>
#include "defutil.h"

#ifdef CONFIG_ZLIB_DFLTCC
#  include "../zlib_dfltcc/dfltcc_deflate.h"
#else
#define DEFLATE_DFLTCC_ENABLED() 0
#endif

/* lib/zlib_deflate/deflate_rs.rs */
int rust_zlib_deflate_init_state(z_streamp strm, deflate_state *s, int noheader,
				 int windowBits, int memLevel, int level,
				 int strategy, int method, Byte *window,
				 Pos *prev, Pos *head, ush *overlay);
int rust_zlib_deflateReset(z_streamp strm);
int rust_zlib_deflate(z_streamp strm, int flush);
int rust_zlib_deflateEnd(z_streamp strm);

/* Workspace to be allocated for deflate processing */
typedef struct deflate_workspace {
    /* State memory for the deflator */
    deflate_state deflate_memory;
#ifdef CONFIG_ZLIB_DFLTCC
    /* State memory for s390 hardware deflate */
    struct dfltcc_deflate_state dfltcc_memory;
#endif
    Byte *window_memory;
    Pos *prev_memory;
    Pos *head_memory;
    char *overlay_memory;
} deflate_workspace;

#ifdef CONFIG_ZLIB_DFLTCC
/* dfltcc_state must be doubleword aligned for DFLTCC call */
static_assert(offsetof(struct deflate_workspace, dfltcc_memory) % 8 == 0);
#endif

int zlib_deflateInit2(
	z_streamp strm,
	int  level,
	int  method,
	int  windowBits,
	int  memLevel,
	int  strategy
)
{
    deflate_state *s;
    int noheader = 0;
    deflate_workspace *mem;
    char *next;

    if (strm == NULL) return Z_STREAM_ERROR;

    strm->msg = NULL;

    if (level == Z_DEFAULT_COMPRESSION) level = 6;

    mem = (deflate_workspace *) strm->workspace;

    if (windowBits < 0) { /* undocumented feature: suppress zlib header */
        noheader = 1;
        windowBits = -windowBits;
    }
    if (memLevel < 1 || memLevel > MAX_MEM_LEVEL || method != Z_DEFLATED ||
        windowBits < 9 || windowBits > 15 || level < 0 || level > 9 ||
	strategy < 0 || strategy > Z_HUFFMAN_ONLY) {
        return Z_STREAM_ERROR;
    }

    /*
     * Direct the workspace's pointers to the chunks that were allocated
     * along with the deflate_workspace struct.
     */
    next = (char *) mem;
    next += sizeof(*mem);
#ifdef CONFIG_ZLIB_DFLTCC
    /*
     *  DFLTCC requires the window to be page aligned.
     *  Thus, we overallocate and take the aligned portion of the buffer.
     */
    mem->window_memory = (Byte *) PTR_ALIGN(next, PAGE_SIZE);
#else
    mem->window_memory = (Byte *) next;
#endif
    next += zlib_deflate_window_memsize(windowBits);
    mem->prev_memory = (Pos *) next;
    next += zlib_deflate_prev_memsize(windowBits);
    mem->head_memory = (Pos *) next;
    next += zlib_deflate_head_memsize(memLevel);
    mem->overlay_memory = next;

    s = (deflate_state *) &(mem->deflate_memory);

    return rust_zlib_deflate_init_state(strm, s, noheader, windowBits,
					memLevel, level, strategy, method,
					mem->window_memory, mem->prev_memory,
					mem->head_memory,
					(ush *) mem->overlay_memory);
}

int zlib_deflateReset(z_streamp strm)
{
	return rust_zlib_deflateReset(strm);
}

int zlib_deflate(z_streamp strm, int flush)
{
	return rust_zlib_deflate(strm, flush);
}

int zlib_deflateEnd(z_streamp strm)
{
	return rust_zlib_deflateEnd(strm);
}

int zlib_deflate_workspacesize(int windowBits, int memLevel)
{
    if (windowBits < 0) /* undocumented feature: suppress zlib header */
        windowBits = -windowBits;

    /* Since the return value is typically passed to vmalloc() unchecked... */
    BUG_ON(memLevel < 1 || memLevel > MAX_MEM_LEVEL || windowBits < 9 ||
							windowBits > 15);

    return sizeof(deflate_workspace)
        + zlib_deflate_window_memsize(windowBits)
        + zlib_deflate_prev_memsize(windowBits)
        + zlib_deflate_head_memsize(memLevel)
        + zlib_deflate_overlay_memsize(memLevel);
}

int zlib_deflate_dfltcc_enabled(void)
{
	return DEFLATE_DFLTCC_ENABLED();
}
