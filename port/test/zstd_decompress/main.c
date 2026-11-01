/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/zstd/decompress/zstd_decompress.c against
 * port/tree/lib/zstd/decompress/zstd_decompress_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * Three arms, not two: `ref_*` (the pristine C, renamed, see
 * ref_zstd_decompress.c), `rs_*` (this port, via probe.rs), and system
 * libzstd -- the independent, differently-authored implementation, exactly
 * the role liblzma played for xz_dec_stream and xz_dec_lzma2.
 *
 * SYSTEM LIBZSTD IS LOADED VIA dlopen/dlsym, NOT LINKED NORMALLY. Both this
 * harness's own arms define `ZSTD_decompress`, `ZSTD_isError` etc under
 * their real C names (ref_ZSTD_decompress and the port's own
 * #[no_mangle] ZSTD_decompress) -- `-lzstd` at normal link time would
 * collide with the port's real-named symbol (both are being linked into one
 * executable: a strong definition in this object, a dynamic symbol of the
 * same name in libzstd.so). Resolving libzstd's functions through function
 * pointers obtained by dlsym() sidesteps that: this file never references
 * `ZSTD_decompress` by name itself, so there is nothing for the linker to
 * collide.
 *
 * libzstd also supplies the ONLY compressor available to this harness --
 * this project has not ported zstd's compress side (CONFIG_ZSTD_COMPRESS=n
 * in both configs, per notes/STATUS.md) -- so every compressed test vector here is
 * produced by system libzstd, and decompressed by all three arms.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../common/difftest.h"

/* ZSTD_customMem: {void *(*customAlloc)(void *opaque, size_t size);
 * void (*customFree)(void *opaque, void *address); void *opaque;}. Real
 * layout, both arms agree on it (same reasoning as zdt_out/zdt_in below).
 *
 * WHY THIS IS NEEDED AT ALL, not just ZSTD_decompress()/ZSTD_createDCtx():
 * lib/zstd/common/zstd_deps.h's ZSTD_DEPS_NEED_MALLOC arm -- the kernel's
 * own shim -- defines ZSTD_malloc/ZSTD_calloc as unconditionally NULL
 * (there is no libc malloc in the kernel). ZSTD_customMalloc's fallback to
 * ZSTD_malloc() when customMem.customAlloc is NULL therefore always fails,
 * on BOTH arms, identically -- ZSTD_createDCtx()/ZSTD_defaultCMem is dead
 * weight in this kernel (see zstd_decompress_rs.rs's module doc,
 * "deliberate divergences" #1). The only live allocation path, in the
 * kernel and here, is a real customAlloc/customFree pair -- which in
 * userspace is just malloc/free. */
struct zdt_custom_mem { void *customAlloc; void *customFree; void *opaque; };

static void *zdt_alloc(void *opaque, size_t size) { (void)opaque; return malloc(size); }
static void  zdt_free(void *opaque, void *address) { (void)opaque; free(address); }

static struct zdt_custom_mem zdt_cmem(void)
{
	struct zdt_custom_mem m;
	m.customAlloc = (void *)zdt_alloc;
	m.customFree = (void *)zdt_free;
	m.opaque = NULL;
	return m;
}

/* ---- the two static arms ------------------------------------------------ */
#define ARMS(P) \
	void  *P##ZSTD_createDCtx(void); \
	void  *P##ZSTD_createDCtx_advanced(struct zdt_custom_mem); \
	size_t P##ZSTD_freeDCtx(void *); \
	size_t P##ZSTD_decompress(void *, size_t, const void *, size_t); \
	size_t P##ZSTD_decompressDCtx(void *, void *, size_t, const void *, size_t); \
	size_t P##ZSTD_decompress_usingDict(void *, void *, size_t, const void *, size_t, const void *, size_t); \
	void  *P##ZSTD_createDStream(void); \
	void  *P##ZSTD_createDStream_advanced(struct zdt_custom_mem); \
	size_t P##ZSTD_freeDStream(void *); \
	size_t P##ZSTD_initDStream(void *); \
	size_t P##ZSTD_initDStream_usingDict(void *, const void *, size_t); \
	size_t P##ZSTD_decompressStream(void *, void *, void *); \
	unsigned P##ZSTD_isFrame(const void *, size_t); \
	unsigned P##ZSTD_isSkippableFrame(const void *, size_t); \
	size_t P##ZSTD_frameHeaderSize(const void *, size_t); \
	uint64_t P##ZSTD_getFrameContentSize(const void *, size_t); \
	uint64_t P##ZSTD_getDecompressedSize(const void *, size_t); \
	size_t P##ZSTD_findFrameCompressedSize(const void *, size_t); \
	uint64_t P##ZSTD_findDecompressedSize(const void *, size_t); \
	uint64_t P##ZSTD_decompressBound(const void *, size_t); \
	unsigned P##ZSTD_getDictID_fromFrame(const void *, size_t); \
	unsigned P##ZSTD_getDictID_fromDict(const void *, size_t); \
	size_t P##ZSTD_readSkippableFrame(void *, size_t, unsigned *, const void *, size_t); \
	size_t P##ZSTD_DStreamInSize(void); \
	size_t P##ZSTD_DStreamOutSize(void); \
	size_t P##ZSTD_sizeof_DCtx(const void *); \
	size_t P##ZSTD_DCtx_setParameter(void *, int, int); \
	size_t P##ZSTD_DCtx_reset(void *, int);
ARMS(ref_)
ARMS(rs_)

/* ZSTD_outBuffer/ZSTD_inBuffer: {ptr, size, pos}, three words. Both arms
 * agree on this layout by construction -- the ref arm uses the REAL struct
 * (`<linux/zstd.h>`, via the pristine C's own includes), and probe.rs's
 * ZstdOutBuffer/ZstdInBuffer are `#[repr(C)]` mirrors of exactly the same
 * three fields, verified against the real header's field order when this
 * port was written. Declared locally here rather than included, so this
 * driver does not itself depend on which arm's header last defined them. */
struct zdt_out { void *dst; size_t size; size_t pos; };
struct zdt_in  { const void *src; size_t size; size_t pos; };

/* ---- system libzstd, via dlopen/dlsym: the independent oracle ---------- */
typedef size_t (*fn_ZSTD_compress)(void *, size_t, const void *, size_t, int);
typedef size_t (*fn_ZSTD_compressBound)(size_t);
typedef size_t (*fn_ZSTD_decompress)(void *, size_t, const void *, size_t);
typedef unsigned (*fn_ZSTD_isError)(size_t);
typedef int (*fn_ZSTD_maxCLevel)(void);

static fn_ZSTD_compress       sys_compress;
static fn_ZSTD_compressBound  sys_compressBound;
static fn_ZSTD_decompress     sys_decompress;
static fn_ZSTD_isError        sys_isError;

static void load_system_libzstd(void)
{
	void *h = dlopen("libzstd.so.1", RTLD_NOW);
	if (!h) {
		fprintf(stderr, "difftest: dlopen(libzstd.so.1) failed: %s\n", dlerror());
		exit(2);
	}
	sys_compress      = (fn_ZSTD_compress)dlsym(h, "ZSTD_compress");
	sys_compressBound = (fn_ZSTD_compressBound)dlsym(h, "ZSTD_compressBound");
	sys_decompress    = (fn_ZSTD_decompress)dlsym(h, "ZSTD_decompress");
	sys_isError       = (fn_ZSTD_isError)dlsym(h, "ZSTD_isError");
	if (!sys_compress || !sys_compressBound || !sys_decompress || !sys_isError) {
		fprintf(stderr, "difftest: dlsym failed on libzstd.so.1\n");
		exit(2);
	}
}

/* ---- corpus: plaintexts, varying size and compressibility -------------- */
static unsigned long xs_state = 88172645463325252ull;
static uint64_t xorshift64(void)
{
	xs_state ^= xs_state << 13;
	xs_state ^= xs_state >> 7;
	xs_state ^= xs_state << 17;
	return xs_state;
}

/* Fills `buf[0..len)`. `mode`: 0 = all zero (max compressible), 1 = repeating
 * short pattern, 2 = pseudo-random (near-incompressible), 3 = text-like
 * (printable ASCII, moderately compressible). */
static void fill_plaintext(unsigned char *buf, size_t len, int mode)
{
	size_t i;

	switch (mode) {
	case 0:
		memset(buf, 0, len);
		break;
	case 1:
		for (i = 0; i < len; i++)
			buf[i] = (unsigned char)("The quick brown fox jumps."[i % 27]);
		break;
	case 2:
		for (i = 0; i < len; i++)
			buf[i] = (unsigned char)(xorshift64() & 0xFF);
		break;
	default:
		for (i = 0; i < len; i++)
			buf[i] = (unsigned char)(32 + (xorshift64() % 95));
		break;
	}
}

static const size_t sizes[] = { 0, 1, 2, 7, 31, 100, 1000, 8192, 70000, 400000 };
#define NSIZES (sizeof(sizes) / sizeof(sizes[0]))

/* ---- one round-trip case ------------------------------------------------ */
static void run_one(unsigned long run, size_t plainLen, int mode, int level)
{
	unsigned char *plain = malloc(plainLen ? plainLen : 1);
	size_t cBound, cSize;
	unsigned char *comp;
	struct dt_buf out_ref, out_rs;
	size_t r_ref, r_rs, r_sys;
	unsigned char *sysbuf;

	if (!plain) { fprintf(stderr, "difftest: OOM\n"); exit(2); }
	fill_plaintext(plain, plainLen, mode);

	cBound = sys_compressBound(plainLen);
	comp = malloc(cBound);
	if (!comp) { fprintf(stderr, "difftest: OOM\n"); exit(2); }
	cSize = sys_compress(comp, cBound, plain, plainLen, level);
	if (sys_isError(cSize)) {
		fprintf(stderr, "difftest: libzstd compress failed on run %lu\n", run);
		exit(2);
	}

	/* SAME tag on both arms, deliberately: dt_poison_byte() depends only
	 * on (tag, offset), so identical tags make the padding identical
	 * between arms too, which is what makes comparing the FULL padded
	 * buffer (dt_cmp_buf) meaningful -- a different tag per arm would
	 * make every padding byte "differ" even when both arms are correct.
	 * See port/test/zstd_huf/main.c's arm_init for the same convention. */
	dt_buf_init(&out_ref, plainLen, (unsigned char)run);
	dt_buf_init(&out_rs, plainLen, (unsigned char)run);
	dt_buf_poison(&out_ref);
	dt_buf_poison(&out_rs);

	/* ZSTD_decompress()/ZSTD_defaultCMem always fails identically on both
	 * arms (see zdt_cmem's comment) -- exercise the real, live-in-kernel
	 * path instead: an explicit customMem via ZSTD_createDCtx_advanced,
	 * then ZSTD_decompressDCtx. */
	{
		void *dctx_ref = ref_ZSTD_createDCtx_advanced(zdt_cmem());
		void *dctx_rs  = rs_ZSTD_createDCtx_advanced(zdt_cmem());
		if (!dctx_ref || !dctx_rs) {
			fprintf(stderr, "difftest: createDCtx_advanced failed (ref=%p rs=%p)\n", dctx_ref, dctx_rs);
			exit(2);
		}
		r_ref = ref_ZSTD_decompressDCtx(dctx_ref, out_ref.p, plainLen, comp, cSize);
		r_rs  = rs_ZSTD_decompressDCtx(dctx_rs, out_rs.p, plainLen, comp, cSize);
		ref_ZSTD_freeDCtx(dctx_ref);
		rs_ZSTD_freeDCtx(dctx_rs);
	}
	dt_cmp_ret(run, "ZSTD_decompressDCtx", r_ref, r_rs);
	dt_cmp_buf(run, "ZSTD_decompressDCtx", "dst", &out_ref, &out_rs);

	sysbuf = malloc(plainLen ? plainLen : 1);
	if (!sysbuf) { fprintf(stderr, "difftest: OOM\n"); exit(2); }
	r_sys = sys_decompress(sysbuf, plainLen, comp, cSize);
	dt_checks++;
	if (r_sys != r_rs || (!sys_isError(r_sys) && memcmp(sysbuf, out_rs.p, plainLen) != 0)) {
		char d[160];
		snprintf(d, sizeof d, "ret sys=%zu rs=%zu (independent oracle disagrees)", r_sys, r_rs);
		dt_fail(run, "ZSTD_decompress vs system libzstd", d);
	}
	if (!sys_isError(r_rs) && plainLen > 0) {
		dt_checks++;
		if (memcmp(plain, out_rs.p, plainLen) != 0)
			dt_fail(run, "ZSTD_decompress", "round-trip: decompressed != original plaintext");
	}
	free(sysbuf);

	/* Frame-header introspection, both arms, on the same real compressed
	 * frame: exercises the parsing path independently of the block
	 * decoder. */
	{
		unsigned ir = ref_ZSTD_isFrame(comp, cSize), is = rs_ZSTD_isFrame(comp, cSize);
		dt_cmp_u32(run, "ZSTD_isFrame", "ret", ir, is);
	}
	{
		uint64_t fr = ref_ZSTD_getFrameContentSize(comp, cSize);
		uint64_t fs = rs_ZSTD_getFrameContentSize(comp, cSize);
		dt_checks++;
		if (fr != fs) {
			char d[128];
			snprintf(d, sizeof d, "ref=%llu rs=%llu", (unsigned long long)fr, (unsigned long long)fs);
			dt_fail(run, "ZSTD_getFrameContentSize", d);
		}
	}
	{
		size_t fr = ref_ZSTD_findFrameCompressedSize(comp, cSize);
		size_t fs = rs_ZSTD_findFrameCompressedSize(comp, cSize);
		dt_cmp_ret(run, "ZSTD_findFrameCompressedSize", fr, fs);
	}
	/* Truncated headers: every prefix length from 0 up to the frame
	 * header's own size, which is exactly where ZSTD_getFrameHeader_advanced's
	 * "need more input" vs "error" branching lives. */
	{
		size_t hs = ref_ZSTD_frameHeaderSize(comp, cSize < 18 ? cSize : 18);
		size_t probe_max = (!sys_isError(hs) && hs < cSize) ? hs + 1 : (cSize < 18 ? cSize : 18);
		size_t n;
		for (n = 0; n <= probe_max; n++) {
			size_t fr = ref_ZSTD_frameHeaderSize(comp, n);
			size_t fs = rs_ZSTD_frameHeaderSize(comp, n);
			dt_cmp_ret(run, "ZSTD_frameHeaderSize (truncated)", fr, fs);
		}
	}

	free(plain);
	free(comp);
	free(out_ref.base);
	free(out_rs.base);
}

/* ---- streaming: feed the same compressed frame in small, varying-size
 * chunks through ZSTD_decompressStream, comparing both arms at every step. */
static void run_streaming(unsigned long run, size_t plainLen, int mode, int level, size_t chunk)
{
	unsigned char *plain = malloc(plainLen ? plainLen : 1);
	size_t cBound, cSize;
	unsigned char *comp;
	void *zds_ref, *zds_rs;
	struct dt_buf out_ref, out_rs;
	struct zdt_in in_ref, in_rs;
	struct zdt_out o_ref, o_rs;
	size_t r_ref = 0, r_rs = 0;

	if (!plain) { fprintf(stderr, "difftest: OOM\n"); exit(2); }
	fill_plaintext(plain, plainLen, mode);

	cBound = sys_compressBound(plainLen);
	comp = malloc(cBound);
	if (!comp) { fprintf(stderr, "difftest: OOM\n"); exit(2); }
	cSize = sys_compress(comp, cBound, plain, plainLen, level);
	if (sys_isError(cSize)) { fprintf(stderr, "difftest: libzstd compress failed\n"); exit(2); }

	/* Same tag on both arms -- see run_one()'s comment. */
	dt_buf_init(&out_ref, plainLen, (unsigned char)run);
	dt_buf_init(&out_rs, plainLen, (unsigned char)run);
	dt_buf_poison(&out_ref);
	dt_buf_poison(&out_rs);

	/* ZSTD_createDStream()/ZSTD_defaultCMem is the same always-fails
	 * path as ZSTD_createDCtx() -- see run_one()'s comment. */
	zds_ref = ref_ZSTD_createDStream_advanced(zdt_cmem());
	zds_rs  = rs_ZSTD_createDStream_advanced(zdt_cmem());
	if (!zds_ref || !zds_rs) { fprintf(stderr, "difftest: createDStream failed\n"); exit(2); }
	ref_ZSTD_initDStream(zds_ref);
	rs_ZSTD_initDStream(zds_rs);

	in_ref.src = comp; in_ref.size = 0; in_ref.pos = 0;
	in_rs.src  = comp; in_rs.size  = 0; in_rs.pos  = 0;
	o_ref.dst = out_ref.p; o_ref.size = plainLen; o_ref.pos = 0;
	o_rs.dst  = out_rs.p;  o_rs.size  = plainLen; o_rs.pos  = 0;

	{
		size_t fed = 0;
		int steps = 0;
		while (fed < cSize && steps < 100000) {
			size_t take = chunk;
			if (fed + take > cSize)
				take = cSize - fed;
			in_ref.size = fed + take; in_ref.pos = fed;
			in_rs.size  = fed + take; in_rs.pos  = fed;

			r_ref = ref_ZSTD_decompressStream(zds_ref, &o_ref, &in_ref);
			r_rs  = rs_ZSTD_decompressStream(zds_rs, &o_rs, &in_rs);
			dt_cmp_ret(run, "ZSTD_decompressStream (step)", r_ref, r_rs);
			dt_checks++;
			if (in_ref.pos != in_rs.pos || o_ref.pos != o_rs.pos) {
				char d[160];
				snprintf(d, sizeof d,
					 "ref consumed %zu/%zu produced %zu, rs consumed %zu/%zu produced %zu",
					 in_ref.pos, in_ref.size, o_ref.pos,
					 in_rs.pos, in_rs.size, o_rs.pos);
				dt_fail(run, "ZSTD_decompressStream (step positions)", d);
			}
			fed = in_ref.pos;
			if (sys_isError(r_ref) || sys_isError(r_rs))
				break;
			steps++;
		}
	}

	dt_cmp_buf(run, "ZSTD_decompressStream", "dst", &out_ref, &out_rs);
	dt_checks++;
	if (o_rs.pos != plainLen)
		dt_fail(run, "ZSTD_decompressStream", "did not produce the full plaintext");
	else if (memcmp(plain, out_rs.p, plainLen) != 0)
		dt_fail(run, "ZSTD_decompressStream", "round-trip: decompressed != original plaintext");

	ref_ZSTD_freeDStream(zds_ref);
	rs_ZSTD_freeDStream(zds_rs);
	free(plain);
	free(comp);
	free(out_ref.base);
	free(out_rs.base);
}

/* ---- skippable frames: hand-constructed, never produced by ZSTD_compress */
static void run_skippable(unsigned long run)
{
	unsigned char frame[8 + 37];
	unsigned char payload_out_ref[37], payload_out_rs[37];
	unsigned magic_variant = 3;
	unsigned char magic_out_ref = 0, magic_out_rs = 0;
	size_t r_ref, r_rs;
	unsigned ir, is;

	/* ZSTD_MAGIC_SKIPPABLE_START (0x184D2A50) + magic_variant, LE, then a
	 * 4-byte LE payload length, then the payload itself. */
	uint32_t magic = 0x184D2A50u + magic_variant;
	uint32_t len = sizeof(payload_out_ref);
	memcpy(frame, &magic, 4);
	memcpy(frame + 4, &len, 4);
	fill_plaintext(frame + 8, sizeof(payload_out_ref), 3);

	ir = ref_ZSTD_isSkippableFrame(frame, sizeof(frame));
	is = rs_ZSTD_isSkippableFrame(frame, sizeof(frame));
	dt_cmp_u32(run, "ZSTD_isSkippableFrame", "ret", ir, is);

	{
		unsigned mv_ref = 0, mv_rs = 0;
		r_ref = ref_ZSTD_readSkippableFrame(payload_out_ref, sizeof(payload_out_ref), &mv_ref, frame, sizeof(frame));
		r_rs  = rs_ZSTD_readSkippableFrame(payload_out_rs, sizeof(payload_out_rs), &mv_rs, frame, sizeof(frame));
		dt_cmp_ret(run, "ZSTD_readSkippableFrame", r_ref, r_rs);
		dt_cmp_u32(run, "ZSTD_readSkippableFrame", "magicVariant", mv_ref, mv_rs);
		dt_checks++;
		if (!sys_isError(r_ref) && memcmp(payload_out_ref, payload_out_rs, sizeof(payload_out_ref)) != 0)
			dt_fail(run, "ZSTD_readSkippableFrame", "payload differs between arms");
	}
	(void)magic_out_ref; (void)magic_out_rs;
}

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 10) : 2000;
	unsigned long seed = argc > 2 ? strtoul(argv[2], NULL, 10) : 20260906;
	unsigned long i;

	xs_state = seed ? seed : 1;
	load_system_libzstd();

	printf("zstd_decompress differential: %lu runs, seed %lu\n", runs, seed);

	for (i = 0; i < runs; i++) {
		size_t sz = sizes[i % NSIZES];
		/* Perturb sizes off the fixed table too, so coverage is not
		 * limited to exactly ten lengths. */
		if (i % (4 * NSIZES) >= 3 * NSIZES)
			sz = (size_t)(xorshift64() % 200000);
		int mode = (int)(i % 4);
		int level = 1 + (int)(xorshift64() % 19);
		run_one(i, sz, mode, level);
	}

	{
		static const size_t stream_sizes[] = { 0, 1, 100, 8192, 70000 };
		static const size_t chunks[] = { 1, 2, 7, 4096, 1u << 20 };
		unsigned long r = runs;
		size_t si, ci;
		for (si = 0; si < sizeof(stream_sizes) / sizeof(stream_sizes[0]); si++)
			for (ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++)
				run_streaming(r++, stream_sizes[si], (int)((si + ci) % 4), 3, chunks[ci]);
	}

	for (i = 0; i < 50; i++)
		run_skippable(runs + 1000 + i);

	printf("checked      %lu\n", dt_checks);
	printf("mismatches   %lu\n\n", dt_fails);
	if (dt_fails) {
		printf("FAIL\n");
		return 1;
	}
	printf("PASS\n");
	return 0;
}
