// SPDX-License-Identifier: Zlib
/*
 * inflate.c's exported entry symbols, for CONFIG_RUST=y. The bodies are in
 * lib/zlib_inflate/inflate_rs.rs.
 *
 * WHY THIS IS A SEPARATE FILE, and it is the arrangement Adam ruled on
 * 2026-09-04 (logs/floor.md, RAISE 2). The thunks used to live inside
 * inflate.c behind the file's own `#else` arm, which meant the original non-STATIC
 * body was GONE -- and the CONFIG_RUST=n fallback has nothing to fall back to
 * when that happens. Splitting them out puts inflate.c back to the upstream
 * body (plus the one deliberate fix noted in its header) so that ONE file
 * serves both the pre-boot textual include and the C-only build, and the
 * Makefile is the only thing that chooses between the arms.
 *
 * WHY THE C HAS TO EXIST AT ALL. All six entry points are EXPORT_SYMBOL'd in
 * inflate_syms.c, so under CONFIG_GENDWARFKSYMS their MODVERSIONS CRCs come
 * from the DWARF of the DEFINITION -- GOALS.md section 2 criterion 4. Defining any of
 * them in Rust changes its CRC and breaks module loading against a stock
 * kernel.
 *
 * TWO OF THE SIX ARE NOT THUNKS. zlib_inflate_workspacesize() and
 * zlib_inflateInit2() are the only code that needs the layout of
 * struct inflate_workspace, a C type this crate does not mirror -- and under
 * CONFIG_ZLIB_DFLTCC that layout depends on PAGE_SIZE. They stay real C and
 * hand the Rust the two pointers it needs.
 */

#include <linux/zutil.h>
#include "inftrees.h"
#include "inflate.h"
#include "infutil.h"

/* lib/zlib_inflate/inflate_rs.rs */
int rust_zlib_inflateReset(z_streamp strm);
int rust_zlib_inflateInit2(z_streamp strm, struct inflate_state *state,
			   unsigned char *window, int windowBits);
int rust_zlib_inflate(z_streamp strm, int flush);
int rust_zlib_inflateEnd(z_streamp strm);
int rust_zlib_inflateIncomp(z_stream *z);

int zlib_inflate_workspacesize(void)
{
	return sizeof(struct inflate_workspace);
}

int zlib_inflateReset(z_streamp strm)
{
	return rust_zlib_inflateReset(strm);
}

int zlib_inflateInit2(z_streamp strm, int windowBits)
{
	unsigned char *window;

	if (strm == NULL)
		return Z_STREAM_ERROR;

#ifdef CONFIG_ZLIB_DFLTCC
	/*
	 * DFLTCC requires the window to be page aligned.
	 * Thus, we overallocate and take the aligned portion of the buffer.
	 */
	window = PTR_ALIGN(&WS(strm)->working_window[0], PAGE_SIZE);
#else
	window = &WS(strm)->working_window[0];
#endif

	return rust_zlib_inflateInit2(strm, &WS(strm)->inflate_state, window,
				      windowBits);
}

int zlib_inflate(z_streamp strm, int flush)
{
	return rust_zlib_inflate(strm, flush);
}

int zlib_inflateEnd(z_streamp strm)
{
	return rust_zlib_inflateEnd(strm);
}

int zlib_inflateIncomp(z_stream *z)
{
	return rust_zlib_inflateIncomp(z);
}

