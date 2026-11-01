// SPDX-License-Identifier: GPL-2.0
/*
 * Pre-boot vs kernel proper, restored 2026-10-02.
 *
 * arch/x86/boot/compressed/misc.c (and every other arch's boot stub)
 * textually #includes this file with STATIC defined to get unxz-style entry
 * points. Porting replaced the whole file with the thunk below, which
 * deleted that pre-boot code and broke every CONFIG_KERNEL_<codec> build
 * (found by building CONFIG_KERNEL_XZ, logs/floor.md). The pre-boot arm is
 * therefore upstream's file, byte for byte, under #ifdef STATIC -- there is
 * no Rust at that point in the boot. The thunk arm is what the kernel proper
 * compiles.
 */
#ifdef STATIC

// SPDX-License-Identifier: GPL-2.0

/*
 * Important notes about in-place decompression
 *
 * At least on x86, the kernel is decompressed in place: the compressed data
 * is placed to the end of the output buffer, and the decompressor overwrites
 * most of the compressed data. There must be enough safety margin to
 * guarantee that the write position is always behind the read position.
 *
 * The safety margin for ZSTD with a 128 KB block size is calculated below.
 * Note that the margin with ZSTD is bigger than with GZIP or XZ!
 *
 * The worst case for in-place decompression is that the beginning of
 * the file is compressed extremely well, and the rest of the file is
 * uncompressible. Thus, we must look for worst-case expansion when the
 * compressor is encoding uncompressible data.
 *
 * The structure of the .zst file in case of a compressed kernel is as follows.
 * Maximum sizes (as bytes) of the fields are in parenthesis.
 *
 *    Frame Header: (18)
 *    Blocks: (N)
 *    Checksum: (4)
 *
 * The frame header and checksum overhead is at most 22 bytes.
 *
 * ZSTD stores the data in blocks. Each block has a header whose size is
 * a 3 bytes. After the block header, there is up to 128 KB of payload.
 * The maximum uncompressed size of the payload is 128 KB. The minimum
 * uncompressed size of the payload is never less than the payload size
 * (excluding the block header).
 *
 * The assumption, that the uncompressed size of the payload is never
 * smaller than the payload itself, is valid only when talking about
 * the payload as a whole. It is possible that the payload has parts where
 * the decompressor consumes more input than it produces output. Calculating
 * the worst case for this would be tricky. Instead of trying to do that,
 * let's simply make sure that the decompressor never overwrites any bytes
 * of the payload which it is currently reading.
 *
 * Now we have enough information to calculate the safety margin. We need
 *   - 22 bytes for the .zst file format headers;
 *   - 3 bytes per every 128 KiB of uncompressed size (one block header per
 *     block); and
 *   - 128 KiB (biggest possible zstd block size) to make sure that the
 *     decompressor never overwrites anything from the block it is currently
 *     reading.
 *
 * We get the following formula:
 *
 *    safety_margin = 22 + uncompressed_size * 3 / 131072 + 131072
 *                 <= 22 + (uncompressed_size >> 15) + 131072
 */

/*
 * Preboot environments #include "path/to/decompress_unzstd.c".
 * All of the source files we depend on must be #included.
 * zstd's only source dependency is xxhash, which has no source
 * dependencies.
 *
 * When UNZSTD_PREBOOT is defined we declare __decompress(), which is
 * used for kernel decompression, instead of unzstd().
 *
 * Define __DISABLE_EXPORTS in preboot environments to prevent symbols
 * from xxhash and zstd from being exported by the EXPORT_SYMBOL macro.
 */
#ifdef STATIC
# define UNZSTD_PREBOOT
# ifdef ZSTD_BOOT_RUST
/*
 * RUSTY-LINUX, the only edit in this arm: ZSTD_BOOT_RUST (set by
 * arch/x86/boot/compressed/Makefile when CONFIG_RUST) replaces the pasted C
 * engine (decompress_sources.h) by the same Rust engine the running kernel
 * uses (the lib/zstd _rs.rs files, built for the stub and linked in). What stays C:
 * the two entry thunks (their bodies are Rust) and zstd_decompress_module.c,
 * the zstd_* wrapper over the ZSTD_* names the Rust defines. xxhash.c is no
 * longer pasted: the Rust decoder's xxh64*() calls resolve to lib/xxhash_rs.rs,
 * built for the stub (its kernel::kabi_*! macros against boot_kernel_stub.rs).
 */
#  define ZSTD_DISABLE_ASM 1
#  include "zstd/common/entropy_common_thunk.c"
#  include "zstd/common/zstd_common_thunk.c"
#  include "zstd/zstd_decompress_module.c"
# else
#  include "xxhash.c"
#  include "zstd/decompress_sources.h"
# endif
#else
#include <linux/decompress/unzstd.h>
#endif

#include <linux/decompress/mm.h>
#include <linux/kernel.h>
#include <linux/zstd.h>

#ifdef ZSTD_BOOT_RUST
/*
 * RUSTY-LINUX: with ZSTD_BOOT_RUST the stream driver below (handle_zstd_error()
 * .. __unzstd()) is lib/decompress_unzstd_rs.rs built for the stub (with
 * --cfg=boot_driver, which adds the out_len-taking entry the pre-boot
 * __decompress() needs). Only what must be the stub's own stays here: the boot
 * malloc, reached through the two symbols the Rust calls, and __decompress().
 * large_malloc(a) is malloc(int) here, so a size is narrowed to int exactly as
 * the C driver's own large_malloc() calls did.
 */
int unzstd_boot(unsigned char *buf, long len,
		 long (*fill)(void*, unsigned long),
		 long (*flush)(void*, unsigned long),
		 unsigned char *out_buf, long out_len,
		 long *pos,
		 void (*error)(char *x));

void *decompress_unzstd_alloc(unsigned long size);
void *decompress_unzstd_alloc(unsigned long size)
{
	return large_malloc(size);
}

/* vfree is a real function to the Rust; large_free() is the stub's.
 * Parenthesised so a macro of the same name cannot expand. */
void (vfree)(const void *addr);
void (vfree)(const void *addr)
{
	if (addr != NULL)
		large_free((void *)addr);
}

#else /* !ZSTD_BOOT_RUST: the original C driver */

/* 128MB is the maximum window size supported by zstd. */
#define ZSTD_WINDOWSIZE_MAX	(1 << ZSTD_WINDOWLOG_MAX)
/*
 * Size of the input and output buffers in multi-call mode.
 * Pick a larger size because it isn't used during kernel decompression,
 * since that is single pass, and we have to allocate a large buffer for
 * zstd's window anyway. The larger size speeds up initramfs decompression.
 */
#define ZSTD_IOBUF_SIZE		(1 << 17)

static int INIT handle_zstd_error(size_t ret, void (*error)(char *x))
{
	const zstd_error_code err = zstd_get_error_code(ret);

	if (!zstd_is_error(ret))
		return 0;

	/*
	 * zstd_get_error_name() cannot be used because error takes a char *
	 * not a const char *
	 */
	switch (err) {
	case ZSTD_error_memory_allocation:
		error("ZSTD decompressor ran out of memory");
		break;
	case ZSTD_error_prefix_unknown:
		error("Input is not in the ZSTD format (wrong magic bytes)");
		break;
	case ZSTD_error_dstSize_tooSmall:
	case ZSTD_error_corruption_detected:
	case ZSTD_error_checksum_wrong:
		error("ZSTD-compressed data is corrupt");
		break;
	default:
		error("ZSTD-compressed data is probably corrupt");
		break;
	}
	return -1;
}

/*
 * Handle the case where we have the entire input and output in one segment.
 * We can allocate less memory (no circular buffer for the sliding window),
 * and avoid some memcpy() calls.
 */
static int INIT decompress_single(const u8 *in_buf, long in_len, u8 *out_buf,
				  long out_len, long *in_pos,
				  void (*error)(char *x))
{
	const size_t wksp_size = zstd_dctx_workspace_bound();
	void *wksp = large_malloc(wksp_size);
	zstd_dctx *dctx = zstd_init_dctx(wksp, wksp_size);
	int err;
	size_t ret;

	if (dctx == NULL) {
		error("Out of memory while allocating zstd_dctx");
		err = -1;
		goto out;
	}
	/*
	 * Find out how large the frame actually is, there may be junk at
	 * the end of the frame that zstd_decompress_dctx() can't handle.
	 */
	ret = zstd_find_frame_compressed_size(in_buf, in_len);
	err = handle_zstd_error(ret, error);
	if (err)
		goto out;
	in_len = (long)ret;

	ret = zstd_decompress_dctx(dctx, out_buf, out_len, in_buf, in_len);
	err = handle_zstd_error(ret, error);
	if (err)
		goto out;

	if (in_pos != NULL)
		*in_pos = in_len;

	err = 0;
out:
	if (wksp != NULL)
		large_free(wksp);
	return err;
}

static int INIT __unzstd(unsigned char *in_buf, long in_len,
			 long (*fill)(void*, unsigned long),
			 long (*flush)(void*, unsigned long),
			 unsigned char *out_buf, long out_len,
			 long *in_pos,
			 void (*error)(char *x))
{
	zstd_in_buffer in;
	zstd_out_buffer out;
	zstd_frame_header header;
	void *in_allocated = NULL;
	void *out_allocated = NULL;
	void *wksp = NULL;
	size_t wksp_size;
	zstd_dstream *dstream;
	int err;
	size_t ret;

	/*
	 * ZSTD decompression code won't be happy if the buffer size is so big
	 * that its end address overflows. When the size is not provided, make
	 * it as big as possible without having the end address overflow.
	 */
	if (out_len == 0)
		out_len = UINTPTR_MAX - (uintptr_t)out_buf;

	if (fill == NULL && flush == NULL)
		/*
		 * We can decompress faster and with less memory when we have a
		 * single chunk.
		 */
		return decompress_single(in_buf, in_len, out_buf, out_len,
					 in_pos, error);

	/*
	 * If in_buf is not provided, we must be using fill(), so allocate
	 * a large enough buffer. If it is provided, it must be at least
	 * ZSTD_IOBUF_SIZE large.
	 */
	if (in_buf == NULL) {
		in_allocated = large_malloc(ZSTD_IOBUF_SIZE);
		if (in_allocated == NULL) {
			error("Out of memory while allocating input buffer");
			err = -1;
			goto out;
		}
		in_buf = in_allocated;
		in_len = 0;
	}
	/* Read the first chunk, since we need to decode the frame header. */
	if (fill != NULL)
		in_len = fill(in_buf, ZSTD_IOBUF_SIZE);
	if (in_len < 0) {
		error("ZSTD-compressed data is truncated");
		err = -1;
		goto out;
	}
	/* Set the first non-empty input buffer. */
	in.src = in_buf;
	in.pos = 0;
	in.size = in_len;
	/* Allocate the output buffer if we are using flush(). */
	if (flush != NULL) {
		out_allocated = large_malloc(ZSTD_IOBUF_SIZE);
		if (out_allocated == NULL) {
			error("Out of memory while allocating output buffer");
			err = -1;
			goto out;
		}
		out_buf = out_allocated;
		out_len = ZSTD_IOBUF_SIZE;
	}
	/* Set the output buffer. */
	out.dst = out_buf;
	out.pos = 0;
	out.size = out_len;

	/*
	 * We need to know the window size to allocate the zstd_dstream.
	 * Since we are streaming, we need to allocate a buffer for the sliding
	 * window. The window size varies from 1 KB to ZSTD_WINDOWSIZE_MAX
	 * (8 MB), so it is important to use the actual value so as not to
	 * waste memory when it is smaller.
	 */
	ret = zstd_get_frame_header(&header, in.src, in.size);
	err = handle_zstd_error(ret, error);
	if (err)
		goto out;
	if (ret != 0) {
		error("ZSTD-compressed data has an incomplete frame header");
		err = -1;
		goto out;
	}
	if (header.windowSize > ZSTD_WINDOWSIZE_MAX) {
		error("ZSTD-compressed data has too large a window size");
		err = -1;
		goto out;
	}

	/*
	 * Allocate the zstd_dstream now that we know how much memory is
	 * required.
	 */
	wksp_size = zstd_dstream_workspace_bound(header.windowSize);
	wksp = large_malloc(wksp_size);
	dstream = zstd_init_dstream(header.windowSize, wksp, wksp_size);
	if (dstream == NULL) {
		error("Out of memory while allocating ZSTD_DStream");
		err = -1;
		goto out;
	}

	/*
	 * Decompression loop:
	 * Read more data if necessary (error if no more data can be read).
	 * Call the decompression function, which returns 0 when finished.
	 * Flush any data produced if using flush().
	 */
	if (in_pos != NULL)
		*in_pos = 0;
	do {
		/*
		 * If we need to reload data, either we have fill() and can
		 * try to get more data, or we don't and the input is truncated.
		 */
		if (in.pos == in.size) {
			if (in_pos != NULL)
				*in_pos += in.pos;
			in_len = fill ? fill(in_buf, ZSTD_IOBUF_SIZE) : -1;
			if (in_len < 0) {
				error("ZSTD-compressed data is truncated");
				err = -1;
				goto out;
			}
			in.pos = 0;
			in.size = in_len;
		}
		/* Returns zero when the frame is complete. */
		ret = zstd_decompress_stream(dstream, &out, &in);
		err = handle_zstd_error(ret, error);
		if (err)
			goto out;
		/* Flush all of the data produced if using flush(). */
		if (flush != NULL && out.pos > 0) {
			if (out.pos != flush(out.dst, out.pos)) {
				error("Failed to flush()");
				err = -1;
				goto out;
			}
			out.pos = 0;
		}
	} while (ret != 0);

	if (in_pos != NULL)
		*in_pos += in.pos;

	err = 0;
out:
	if (in_allocated != NULL)
		large_free(in_allocated);
	if (out_allocated != NULL)
		large_free(out_allocated);
	if (wksp != NULL)
		large_free(wksp);
	return err;
}

#endif /* ZSTD_BOOT_RUST */

#ifndef UNZSTD_PREBOOT
STATIC int INIT unzstd(unsigned char *buf, long len,
		       long (*fill)(void*, unsigned long),
		       long (*flush)(void*, unsigned long),
		       unsigned char *out_buf,
		       long *pos,
		       void (*error)(char *x))
{
	return __unzstd(buf, len, fill, flush, out_buf, 0, pos, error);
}
#else
STATIC int INIT __decompress(unsigned char *buf, long len,
			     long (*fill)(void*, unsigned long),
			     long (*flush)(void*, unsigned long),
			     unsigned char *out_buf, long out_len,
			     long *pos,
			     void (*error)(char *x))
{
#ifdef ZSTD_BOOT_RUST
	return unzstd_boot(buf, len, fill, flush, out_buf, out_len, pos, error);
#else
	return __unzstd(buf, len, fill, flush, out_buf, out_len, pos, error);
#endif
}
#endif

#else /* !STATIC */

/*
 * The Rust unzstd wrapper's vmalloc thunk.
 *
 * vmalloc is `alloc_hooks(vmalloc_noprof(...))` since 6.10's allocation
 * profiling -- a macro with no linkable symbol. vfree is a real
 * EXPORT_SYMBOL and is called directly from decompress_unzstd_rs.rs; only
 * the allocating half needs a C body. See that file's module doc for the
 * rest of the port.
 *
 * `size` is `unsigned long`, matching vmalloc's real parameter type --
 * found by adversarial review: an earlier version took `unsigned int`,
 * which truncates any request at or above 4GiB to its low 32 bits instead
 * of passing it through to vmalloc unchanged, while every caller on the
 * Rust side still hands zstd_init_dstream() the untruncated size. That
 * turns the C's clean vmalloc failure (a window size a crafted frame
 * header can pick freely, per this file's own module doc, requesting more
 * memory than vmalloc will ever grant) into zstd being told it owns far
 * more workspace than was actually allocated -- an out-of-bounds write on
 * initramfs input, not merely a wrong error path.
 */
#include <linux/init.h>
#include <linux/vmalloc.h>

/* -Wmissing-prototypes requires this visible before the definition below,
 * since nothing else in the C tree calls it. __init: its only caller,
 * unzstd(), is __init too. */
void *decompress_unzstd_alloc(unsigned long size) __init;

void * __init decompress_unzstd_alloc(unsigned long size)
{
	return vmalloc(size);
}

#endif /* STATIC */
