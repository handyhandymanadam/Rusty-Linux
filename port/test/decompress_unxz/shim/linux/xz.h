/* Userspace shim: only what decompress_unxz.c's non-XZ_PREBOOT arm uses.
 * The REAL <linux/xz.h> transitively pulls in <linux/types.h>, which
 * conflicts with glibc's own typedefs (fd_set, dev_t, bool, ...) once
 * -D__KERNEL__ is set (needed so decompress_unxz.c includes
 * <linux/decompress/mm.h>'s shim) -- same reasoning
 * port/test/decompress_unlz4's and decompress_unlzo's shim/linux/lz4.h and
 * lzo.h give for not using the real headers. struct xz_buf's field order
 * and types are copied exactly from the real header (GOALS.md §5: it's the
 * caller's ABI, not ours to drift on) -- both arms link against the SAME
 * pristine xz_dec_{stream,lzma2,bcj}.c backend, compiled against the REAL
 * header (port/test/xz_stream/'s own shim, unaffected by this one), so a
 * mismatch here would be a real, catchable link/behavior bug, not a
 * silently-accepted one.
 */
#ifndef _SHIM_UNXZ_LINUX_XZ_H
#define _SHIM_UNXZ_LINUX_XZ_H
#include <stddef.h>
#include <stdint.h>

enum xz_mode {
	XZ_SINGLE,
	XZ_PREALLOC,
	XZ_DYNALLOC
};

enum xz_ret {
	XZ_OK,
	XZ_STREAM_END,
	XZ_UNSUPPORTED_CHECK,
	XZ_MEM_ERROR,
	XZ_MEMLIMIT_ERROR,
	XZ_FORMAT_ERROR,
	XZ_OPTIONS_ERROR,
	XZ_DATA_ERROR,
	XZ_BUF_ERROR
};

struct xz_buf {
	const uint8_t *in;
	size_t in_pos;
	size_t in_size;

	uint8_t *out;
	size_t out_pos;
	size_t out_size;
};

struct xz_dec;

struct xz_dec *xz_dec_init(enum xz_mode mode, uint32_t dict_max);
enum xz_ret xz_dec_run(struct xz_dec *s, struct xz_buf *b);
void xz_dec_end(struct xz_dec *s);
#endif
