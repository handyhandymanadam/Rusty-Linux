/* SPDX-License-Identifier: GPL-2.0
 *
 * Harness smoke test: makes the "rs" arm a second call into the SAME pristine
 * C, so `run.sh --selfcheck` exercises every line of main.c with an arm that
 * cannot possibly disagree.
 *
 * What this proves, and what it does not. It proves the plumbing: that the
 * buffers are poisoned to the same tag, that the canaries do not fire on
 * correct code, that the out-parameters are read back from the right place,
 * and -- the reason it exists -- that the corpus actually drives each function
 * to a SUCCESSFUL return often enough to be worth running. It proves nothing
 * whatever about the port. It is a smoke test, not a stopping rule; see
 * logs/floor.md RULE T2, which was demoted from a stopping rule after the
 * literature refuted it.
 */
#include <stddef.h>
#include <stdint.h>

typedef uint8_t BYTE;
typedef uint32_t U32;
typedef unsigned FSE_DTable;

size_t ref_FSE_readNCount_bmi2(short *, unsigned *, unsigned *, const void *, size_t, int);
size_t ref_FSE_readNCount(short *, unsigned *, unsigned *, const void *, size_t);
size_t ref_HUF_readStats_wksp(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t, void *, size_t, int);
size_t ref_HUF_readStats(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t);
size_t ref_FSE_buildDTable_wksp(FSE_DTable *, const short *, unsigned, unsigned, void *, size_t);
size_t ref_FSE_decompress_wksp_bmi2(void *, size_t, const void *, size_t, unsigned, void *, size_t, int);

size_t rs_FSE_readNCount_bmi2(short *a, unsigned *b, unsigned *c, const void *d, size_t e, int f)
{ return ref_FSE_readNCount_bmi2(a, b, c, d, e, f); }
size_t rs_FSE_readNCount(short *a, unsigned *b, unsigned *c, const void *d, size_t e)
{ return ref_FSE_readNCount(a, b, c, d, e); }
size_t rs_HUF_readStats_wksp(BYTE *a, size_t b, U32 *c, U32 *d, U32 *e, const void *f, size_t g, void *h, size_t i, int j)
{ return ref_HUF_readStats_wksp(a, b, c, d, e, f, g, h, i, j); }
size_t rs_HUF_readStats(BYTE *a, size_t b, U32 *c, U32 *d, U32 *e, const void *f, size_t g)
{ return ref_HUF_readStats(a, b, c, d, e, f, g); }
size_t rs_FSE_buildDTable_wksp(FSE_DTable *a, const short *b, unsigned c, unsigned d, void *e, size_t f)
{ return ref_FSE_buildDTable_wksp(a, b, c, d, e, f); }
size_t rs_FSE_decompress_wksp_bmi2(void *a, size_t b, const void *c, size_t d, unsigned e, void *f, size_t g, int h)
{ return ref_FSE_decompress_wksp_bmi2(a, b, c, d, e, f, g, h); }

unsigned ref_FSE_versionNumber(void);
unsigned ref_FSE_isError(size_t);
const char *ref_FSE_getErrorName(size_t);
unsigned ref_HUF_isError(size_t);
const char *ref_HUF_getErrorName(size_t);

unsigned rs_FSE_versionNumber(void) { return ref_FSE_versionNumber(); }
unsigned rs_FSE_isError(size_t c) { return ref_FSE_isError(c); }
const char *rs_FSE_getErrorName(size_t c) { return ref_FSE_getErrorName(c); }
unsigned rs_HUF_isError(size_t c) { return ref_HUF_isError(c); }
const char *rs_HUF_getErrorName(size_t c) { return ref_HUF_getErrorName(c); }

const char *ref_ERR_getErrorString(int code);
const char *rs_ERR_getErrorString(int code) { return ref_ERR_getErrorString(code); }

unsigned    ref_ZSTD_versionNumber(void);
const char *ref_ZSTD_versionString(void);
unsigned    ref_ZSTD_isError(size_t);
const char *ref_ZSTD_getErrorName(size_t);
int         ref_ZSTD_getErrorCode(size_t);
const char *ref_ZSTD_getErrorString(int);

unsigned    rs_ZSTD_versionNumber(void) { return ref_ZSTD_versionNumber(); }
const char *rs_ZSTD_versionString(void) { return ref_ZSTD_versionString(); }
unsigned    rs_ZSTD_isError(size_t c) { return ref_ZSTD_isError(c); }
const char *rs_ZSTD_getErrorName(size_t c) { return ref_ZSTD_getErrorName(c); }
int         rs_ZSTD_getErrorCode(size_t c) { return ref_ZSTD_getErrorCode(c); }
const char *rs_ZSTD_getErrorString(int c) { return ref_ZSTD_getErrorString(c); }
