/* Differential test for lib/zlib_inflate/inffast.c -> inffast_rs.rs.
 *
 * WHAT IS COMPARED
 *   The whole inflate pipeline, twice, over one corpus. Both arms are the
 *   PRISTINE lib/zlib_inflate/{inflate,inftrees}.c out of port/pristine/;
 *   the only difference is which inflate_fast() they call -- the pristine
 *   inffast.c in one arm, the Rust in the other. So a difference in the
 *   output is a difference in the ported function and nothing else.
 *
 *   inflate_fast() cannot be called in isolation: it needs a fully built
 *   inflate_state with real Huffman tables, which only the surrounding
 *   machinery produces. Driving the pipeline is not a weaker test than
 *   calling the function directly, it is the only honest one.
 *
 * WHY THE CORPUS IS SHAPED LIKE THIS
 *   PRIOR-ART.md §5 records a TWELVE-FOLD spread on a decompressor between
 *   two corpus inputs, from one mechanism. The lesson is that a single input
 *   tells you almost nothing here. So the corpus varies the data (runs,
 *   short periods, random, text, long-range repeats), the compressor
 *   (level, window bits, memlevel, strategy), and -- the part that actually
 *   reaches the hard paths -- the CHUNKING.
 *
 *   Chunking is what exercises the window. inflate_fast() copies a match out
 *   of state->window whenever it reaches further back than this call's own
 *   output, and that only happens when inflate() was handed its output in
 *   pieces. Three separate window paths (write == 0, write < op, contiguous)
 *   are unreachable with a single big output buffer.
 *
 * WHAT ELSE IS CHECKED
 *   The struct offsets and enum values the Rust mirrors, against offsetof()
 *   on the real headers. The Rust reports what it believes; this compares.
 *   Nothing else in this test would localise a wrong offset.
 */
#include <linux/zlib.h>
#include <linux/zutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "inftrees.h"
#include "inflate.h"

/* --- the two arms ------------------------------------------------------ */

extern int ref_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int ref_zlib_inflate(z_streamp strm, int flush);
extern int ref_zlib_inflateEnd(z_streamp strm);
extern int ref_zlib_inflate_workspacesize(void);

extern int refu_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int refu_zlib_inflate(z_streamp strm, int flush);
extern int refu_zlib_inflateEnd(z_streamp strm);
extern int refu_zlib_inflate_workspacesize(void);

extern int rs_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int rs_zlib_inflate(z_streamp strm, int flush);
extern int rs_zlib_inflateEnd(z_streamp strm);
extern int rs_zlib_inflate_workspacesize(void);

/* Arm D: the RETAINED PRE-BOOT C body out of port/tree/, compiled with STATIC
   defined. Pristine until 2026-09-03; it now carries upstream zlib's
   `copy > whave` guard, the same five lines as upstream/zlib-inflate-oob/'s
   patch. Nothing in this project had ever compiled a retained pre-boot body
   before, let alone run anything through one. */
extern int pre_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int pre_zlib_inflate(z_streamp strm, int flush);
extern int pre_zlib_inflateEnd(z_streamp strm);
extern int pre_zlib_inflate_workspacesize(void);

extern void inffast_rs_abi(uint64_t *out);
extern void inftrees_rs_abi(uint64_t *out);
extern void inflate_rs_abi(uint64_t *out);
extern const unsigned char *inffixed_rs_table(int which);
extern unsigned long rs_adler32(unsigned long adler, const unsigned char *buf,
                                size_t len);

/* The table builder, both arms. The oracle is pristine inftrees.c compiled
   under a renamed global; the unrenamed name is the Rust in probe.rs. */
extern int ref_zlib_inflate_table(codetype type, unsigned short *lens,
                                  unsigned codes, code **table,
                                  unsigned *bits, unsigned short *work);
extern int zlib_inflate_table(codetype type, unsigned short *lens,
                              unsigned codes, code **table,
                              unsigned *bits, unsigned short *work);

/* The oracle's real fast path, reached through the counter below. All three
   arms run the identical pipeline over the identical input, so this counts
   entries for every arm; that inflate_fast() was entered is then a number
   read back rather than an inference from the chunk sizes. */
extern void ref_inflate_fast_inner(z_streamp strm, unsigned start);
static unsigned long fast_entries;

void ref_inflate_fast(z_streamp strm, unsigned start);
void ref_inflate_fast(z_streamp strm, unsigned start)
{
    fast_entries++;
    ref_inflate_fast_inner(strm, start);
}

/* corpus.c, the only unit that sees the system zlib */
extern long corpus_compress(const unsigned char *src, unsigned long n,
                            int level, int window_bits, int mem_level,
                            int strategy, unsigned char *dst,
                            unsigned long dcap);

/* system zlib strategy values, spelled out so this file need not include it */
#define S_DEFAULT 0
#define S_FILTERED 1
#define S_HUFFMAN 2
#define S_RLE 3
#define S_FIXED 4

/* --- ABI check --------------------------------------------------------- */

#define ABI_SLOTS 22

static int abi_check(void)
{
    uint64_t got[ABI_SLOTS];
    uint64_t want[ABI_SLOTS];
    static const char *names[ABI_SLOTS] = {
        "inflate_state.mode", "inflate_state.dmax", "inflate_state.wsize",
        "inflate_state.whave", "inflate_state.write", "inflate_state.window",
        "inflate_state.hold", "inflate_state.bits", "inflate_state.lencode",
        "inflate_state.distcode", "inflate_state.lenbits",
        "inflate_state.distbits",
        "z_stream.next_in", "z_stream.avail_in", "z_stream.next_out",
        "z_stream.avail_out", "z_stream.msg", "z_stream.state",
        "sizeof(code)", "code.val",
        "inflate_mode TYPE", "inflate_mode BAD",
    };
    int i, bad = 0;

    want[0]  = offsetof(struct inflate_state, mode);
    want[1]  = offsetof(struct inflate_state, dmax);
    want[2]  = offsetof(struct inflate_state, wsize);
    want[3]  = offsetof(struct inflate_state, whave);
    want[4]  = offsetof(struct inflate_state, write);
    want[5]  = offsetof(struct inflate_state, window);
    want[6]  = offsetof(struct inflate_state, hold);
    want[7]  = offsetof(struct inflate_state, bits);
    want[8]  = offsetof(struct inflate_state, lencode);
    want[9]  = offsetof(struct inflate_state, distcode);
    want[10] = offsetof(struct inflate_state, lenbits);
    want[11] = offsetof(struct inflate_state, distbits);
    want[12] = offsetof(z_stream, next_in);
    want[13] = offsetof(z_stream, avail_in);
    want[14] = offsetof(z_stream, next_out);
    want[15] = offsetof(z_stream, avail_out);
    want[16] = offsetof(z_stream, msg);
    want[17] = offsetof(z_stream, state);
    want[18] = sizeof(code);
    want[19] = offsetof(code, val);
    want[20] = TYPE;
    want[21] = BAD;

    inffast_rs_abi(got);
    for (i = 0; i < ABI_SLOTS; i++) {
        if (got[i] != want[i]) {
            printf("  ABI MISMATCH %-26s rust %3llu  C %3llu\n", names[i],
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            bad = 1;
        }
    }
    printf("  ABI: %d offsets and constants checked against offsetof() on the\n"
           "       real headers, %s\n", ABI_SLOTS, bad ? "MISMATCHED" : "all agree");
    return bad;
}

/* struct code is mirrored in TWO ported files in this directory. Checking one
   of them would leave the other free to drift. */
#define INFTREES_ABI_SLOTS 6

static int inftrees_abi_check(void)
{
    uint64_t got[INFTREES_ABI_SLOTS];
    uint64_t want[INFTREES_ABI_SLOTS];
    static const char *const names[INFTREES_ABI_SLOTS] = {
        "sizeof(code)", "code.op", "code.bits", "code.val", "ENOUGH", "MAXD",
    };
    int i, bad = 0;

    want[0] = sizeof(code);
    want[1] = offsetof(code, op);
    want[2] = offsetof(code, bits);
    want[3] = offsetof(code, val);
    want[4] = ENOUGH;
    want[5] = MAXD;

    inftrees_rs_abi(got);
    for (i = 0; i < INFTREES_ABI_SLOTS; i++) {
        if (got[i] != want[i]) {
            printf("  ABI MISMATCH inftrees %-18s rust %3llu  C %3llu\n", names[i],
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            bad = 1;
        }
    }
    printf("  ABI: %d more from inftrees_rs.rs -- the SECOND mirror of struct\n"
           "       code in this directory, %s\n", INFTREES_ABI_SLOTS,
           bad ? "MISMATCHED" : "all agree");
    return bad;
}

/* struct inflate_state is mirrored in THREE ported files now. inffast_rs.rs
   truncates it on purpose and inflate_rs.rs carries all of it; checking two of
   the three would be worse than checking none, because the count implies
   coverage. */
#define INFLATE_ABI_SLOTS 12

static int inflate_abi_check(void)
{
    uint64_t got[INFLATE_ABI_SLOTS];
    uint64_t want[INFLATE_ABI_SLOTS];
    static const char *const names[INFLATE_ABI_SLOTS] = {
        "sizeof(inflate_state)", "inflate_state.ncode", "inflate_state.nlen",
        "inflate_state.ndist", "inflate_state.have", "inflate_state.next",
        "inflate_state.lens", "inflate_state.work", "inflate_state.codes",
        "inflate_mode HEAD", "inflate_mode MATCH", "inflate_mode SYNC",
    };
    int i, bad = 0;

    want[0]  = sizeof(struct inflate_state);
    want[1]  = offsetof(struct inflate_state, ncode);
    want[2]  = offsetof(struct inflate_state, nlen);
    want[3]  = offsetof(struct inflate_state, ndist);
    want[4]  = offsetof(struct inflate_state, have);
    want[5]  = offsetof(struct inflate_state, next);
    want[6]  = offsetof(struct inflate_state, lens);
    want[7]  = offsetof(struct inflate_state, work);
    want[8]  = offsetof(struct inflate_state, codes);
    want[9]  = HEAD;
    want[10] = MATCH;
    want[11] = SYNC;

    inflate_rs_abi(got);
    for (i = 0; i < INFLATE_ABI_SLOTS; i++) {
        if (got[i] != want[i]) {
            printf("  ABI MISMATCH inflate %-21s rust %5llu  C %5llu\n", names[i],
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            bad = 1;
        }
    }
    printf("  ABI: %d more from inflate_rs.rs -- the THIRD mirror, and the\n"
           "       only complete one, %s\n", INFLATE_ABI_SLOTS,
           bad ? "MISMATCHED" : "all agree");
    return bad;
}

/* The 544 fixed-table entries were machine-generated out of inffixed.h. This
   is what makes a wrong entry a test failure rather than a silent one: the
   header is included HERE too, and the two are compared byte for byte. */
static int fixedtables_check(void)
{
#   include "inffixed.h"
    int bad = 0;

    if (memcmp(inffixed_rs_table(0), lenfix, sizeof(lenfix)) != 0) {
        printf("  FIXED TABLE MISMATCH lenfix[512]\n");
        bad = 1;
    }
    if (memcmp(inffixed_rs_table(1), distfix, sizeof(distfix)) != 0) {
        printf("  FIXED TABLE MISMATCH distfix[32]\n");
        bad = 1;
    }
    printf("  fixed tables: %zu entries compared against inffixed.h, %s\n",
           (sizeof(lenfix) + sizeof(distfix)) / sizeof(code),
           bad ? "MISMATCHED" : "identical");
    return bad;
}

/* --- rng --------------------------------------------------------------- */

static uint64_t rng_s;
static void rng_seed(uint64_t s) { rng_s = s ? s : 0x9e3779b97f4a7c15ULL; }
static uint64_t rng_u64(void)
{
    rng_s ^= rng_s << 13;
    rng_s ^= rng_s >> 7;
    rng_s ^= rng_s << 17;
    return rng_s;
}
static unsigned rng_below(unsigned n) { return n ? (unsigned)(rng_u64() % n) : 0; }

/* --- corpus generators -------------------------------------------------- */

#define PLAIN_CAP (1u << 20)
#define COMP_CAP  (PLAIN_CAP + (PLAIN_CAP >> 2) + 4096)
#define OUT_CAP   (PLAIN_CAP + 4096)

static const char *const WORDS[] = {
    "the", "kernel", "inflate", "window", "distance", "length", "code",
    "buffer", "rust", "match", "literal", "deflate", "table", "stream",
    "a", "of", "and", "to", "in", "is", "it", "that", "for", "with",
};
#define NWORDS ((int)(sizeof(WORDS) / sizeof(WORDS[0])))

/* Scratch for the mixture generator. Allocated once at startup rather than
 * per call: the per-call malloc() here was unchecked, and when the harness
 * was first run alongside a -j kernel build it returned NULL and the
 * generator segfaulted. That looked exactly like a port failure for as long
 * as it took to read the code. Nothing under test was involved. */
static unsigned char *mix_scratch;

/* file-backed corpus, loaded once */
static unsigned char *files[8];
static unsigned long file_len[8];
static int nfiles;

static void load_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long n;

    if (!f || nfiles == 8)
        return;
    b = malloc(PLAIN_CAP);
    n = (long)fread(b, 1, PLAIN_CAP, f);
    fclose(f);
    if (n <= 0) { free(b); return; }
    files[nfiles] = b;
    file_len[nfiles] = (unsigned long)n;
    nfiles++;
}

#define NGEN 15

/* Fill `b` with corpus of kind `kind`; return its length. */
static unsigned long gen(int kind, unsigned char *b)
{
    unsigned long n, i;
    unsigned k;

    switch (kind) {
    case 0: /* zeros -- longest possible matches, dist 1 */
        n = 1 + rng_below(PLAIN_CAP - 1);
        memset(b, 0, n);
        return n;
    case 1: { /* one repeated byte -- the dist == 1 pat16 path */
        unsigned char c = (unsigned char)rng_below(256);
        n = 1 + rng_below(70000);
        memset(b, c, n);
        return n;
    }
    case 2: { /* period 2 -- the dist == 2 pat16 path */
        unsigned char c0 = (unsigned char)rng_below(256);
        unsigned char c1 = (unsigned char)rng_below(256);
        n = 2 + rng_below(70000);
        for (i = 0; i < n; i++) b[i] = (i & 1) ? c1 : c0;
        return n;
    }
    case 3: { /* period 3 -- smallest dist that takes the 16-bit copy loop */
        unsigned char p[3];
        p[0] = (unsigned char)rng_below(256);
        p[1] = (unsigned char)rng_below(256);
        p[2] = (unsigned char)rng_below(256);
        n = 3 + rng_below(70000);
        for (i = 0; i < n; i++) b[i] = p[i % 3];
        return n;
    }
    case 4: { /* period 4..64 */
        unsigned char p[64];
        k = 4 + rng_below(61);
        for (i = 0; i < k; i++) p[i] = (unsigned char)rng_below(256);
        n = k + rng_below(90000);
        for (i = 0; i < n; i++) b[i] = p[i % k];
        return n;
    }
    case 5: /* incompressible -- every code a literal */
        n = 1 + rng_below(60000);
        for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
        return n;
    case 6: { /* small alphabet -- short matches, lots of second-level codes */
        unsigned char alpha[8];
        k = 2 + rng_below(7);
        for (i = 0; i < k; i++) alpha[i] = (unsigned char)rng_below(256);
        n = 1 + rng_below(120000);
        for (i = 0; i < n; i++) b[i] = alpha[rng_below(k)];
        return n;
    }
    case 7: { /* text -- the shape real callers actually decompress */
        n = 0;
        while (n < 60000 + rng_below(60000)) {
            const char *w = WORDS[rng_below(NWORDS)];
            unsigned long l = strlen(w);
            if (n + l + 2 >= PLAIN_CAP) break;
            memcpy(b + n, w, l);
            n += l;
            b[n++] = (rng_below(12) == 0) ? '\n' : ' ';
        }
        return n ? n : 1;
    }
    case 8: /* counter */
        n = 1 + rng_below(90000);
        for (i = 0; i < n; i++) b[i] = (unsigned char)i;
        return n;
    case 9: { /* long-range repeats -- reaches back through the window */
        unsigned long blk = 4096 + rng_below(20000);
        unsigned long reps = 2 + rng_below(8);
        if (blk > PLAIN_CAP / 2) blk = PLAIN_CAP / 2;
        for (i = 0; i < blk; i++) b[i] = (unsigned char)rng_u64();
        n = blk;
        while (reps-- && n + blk < PLAIN_CAP) {
            memcpy(b + n, b, blk);
            n += blk;
        }
        return n;
    }
    case 10: { /* sparse -- mostly zeros, occasional noise */
        n = 1 + rng_below(150000);
        memset(b, 0, n);
        for (i = 0; i < n / 200 + 1; i++) b[rng_below((unsigned)n)] = (unsigned char)rng_u64();
        return n;
    }
    case 11: { /* alternating long runs of two bytes */
        unsigned char c0 = (unsigned char)rng_below(256);
        unsigned char c1 = (unsigned char)rng_below(256);
        n = 0;
        while (n < 40000 + rng_below(80000)) {
            unsigned long r = 1 + rng_below(600);
            if (n + r >= PLAIN_CAP) break;
            memset(b + n, (n & 1) ? c1 : c0, r);
            n += r;
        }
        return n ? n : 1;
    }
    case 12: { /* mixture -- boundaries between shapes inside one stream */
        unsigned long parts = 2 + rng_below(4);
        unsigned char *tmp = mix_scratch;
        n = 0;
        while (parts--) {
            unsigned long m = gen((int)rng_below(11), tmp);
            if (m > 30000) m = 30000;
            if (n + m >= PLAIN_CAP) break;
            memcpy(b + n, tmp, m);
            n += m;
        }
        return n ? n : 1;
    }
    case 13: { /* Skewed distance distribution.
                  AIMED AT ONE BRANCH. inffast.c refills the accumulator a
                  SECOND time while reading distance extra bits only when the
                  distance code is wide (a rare symbol, so a long Huffman
                  code) AND carries enough extra bits, which needs the two to
                  coincide. Ordinary corpora never produce that: it was the
                  last uncovered pair of lines in the oracle after thousands
                  of streams.

                  So the distances are drawn from a geometric distribution
                  over power-of-two buckets -- each bucket a quarter as
                  likely as the one below it. Huffman then gives the largest
                  distances codes near the 15-bit ceiling while the small
                  ones stay short, which is the shape the branch needs. */
        unsigned long base = 32768;
        n = 150000 + rng_below(100000);
        if (n > PLAIN_CAP) n = PLAIN_CAP;
        if (n < base + 1000) n = base + 1000;
        for (i = 0; i < base && i < n; i++)
            b[i] = (unsigned char)rng_u64();
        i = base;
        while (i < n) {
            unsigned kk = 0;
            unsigned long dist, run;

            /* Decay of 0.59 per octave, not 0.25. The steeper decay put
               the top octave at 4^-14 -- one match in 250 million, which is
               never. At 0.59 the top octave is about one match in a
               thousand: rare enough for an eleven-bit-plus Huffman code,
               common enough to appear a dozen times in every stream. */
            while (kk < 14 && rng_below(1000) < 590)
                kk++;
            dist = (1UL << kk) + rng_below(1U << kk);
            if (dist > base)
                dist = base;
            if (dist > i)
                dist = i;
            if (dist == 0)
                dist = 1;

            if (rng_below(3) == 0) {
                /* a literal or two, so the bit accumulator is not always
                   in the same phase when a distance code arrives */
                run = 1 + rng_below(3);
                while (run-- && i < n)
                    b[i++] = (unsigned char)(rng_u64() & 0x1f);
                continue;
            }
            run = 3 + rng_below(24);
            while (run-- && i < n) {
                b[i] = b[i - dist];
                i++;
            }
        }
        return n;
    }
    default: { /* real files off the disk */
        unsigned long off, m;
        if (!nfiles) return gen(7, b);
        k = rng_below((unsigned)nfiles);
        m = file_len[k];
        off = rng_below((unsigned)m);
        n = m - off;
        if (n > PLAIN_CAP) n = PLAIN_CAP;
        memcpy(b, files[k] + off, n);
        return n ? n : 1;
    }
    }
}

/* --- one decompression -------------------------------------------------- */

struct rr {
    int rc;
    unsigned long total_out;
    unsigned long avail_in;
    unsigned long avail_out;
    unsigned long outlen;
    int have_msg;
    char msg[96];
};

static void run(int arm, const unsigned char *cin, unsigned long clen,
                int wbits, unsigned long inchunk, unsigned long outchunk,
                unsigned char *outbuf, unsigned long outcap,
                void *ws, int flush, struct rr *r)
{
    z_stream s;
    unsigned long ipos = 0, opos = 0, guard = 0, cap;
    int rc;

    memset(&s, 0, sizeof(s));
    memset(r, 0, sizeof(*r));
    s.workspace = ws;

    rc = (arm == 0) ? ref_zlib_inflateInit2(&s, wbits)
       : (arm == 1) ? rs_zlib_inflateInit2(&s, wbits)
       : (arm == 3) ? pre_zlib_inflateInit2(&s, wbits)
                    : refu_zlib_inflateInit2(&s, wbits);
    if (rc != Z_OK) { r->rc = rc; return; }

    cap = clen + outcap + 4096;
    for (;;) {
        if (s.avail_in == 0 && ipos < clen) {
            unsigned long k = clen - ipos;
            if (k > inchunk) k = inchunk;
            s.next_in = cin + ipos;
            s.avail_in = k;
            ipos += k;
        }
        if (s.avail_out == 0 && opos < outcap) {
            unsigned long k = outcap - opos;
            if (k > outchunk) k = outchunk;
            s.next_out = outbuf + opos;
            s.avail_out = k;
            opos += k;
        }
        if (s.avail_in == 0 && s.avail_out == 0)
            break;

        rc = (arm == 0) ? ref_zlib_inflate(&s, flush)
           : (arm == 1) ? rs_zlib_inflate(&s, flush)
           : (arm == 3) ? pre_zlib_inflate(&s, flush)
                        : refu_zlib_inflate(&s, flush);
        /* Z_BUF_ERROR is zlib's "no progress on THIS call" and is NOT
         * fatal -- the caller supplies more input or output space and calls
         * again, which the top of this loop does. Breaking on it truncated
         * the decode: measured 2026-09-04, a 37,398-byte plaintext decoded
         * 300 bytes and the run counted as a pass, because all four arms
         * stopped at the same place and only the arms were compared. Found
         * by the independent-plaintext oracle on its first run. */
        if (rc == Z_BUF_ERROR) {
            /* Transient only if the NEXT iteration can actually hand the
             * decoder something it does not already have: more input, or a
             * fresh output chunk once the current one is used up. If input is
             * exhausted and the output chunk is not yet full, nothing changes
             * on the next pass and this spins until the guard -- which is what
             * the first version of this did, taking the harness from 38s to
             * over 20 minutes. */
            if ((s.avail_in == 0 && ipos < clen) ||
                (s.avail_out == 0 && opos < outcap))
                continue;
            break;
        }
        if (rc != Z_OK)
            break;
        /* No input left to give and no output space left to give: the
           decoder cannot make further progress. */
        if (s.avail_in == 0 && ipos == clen && s.avail_out == 0 && opos == outcap)
            break;
        if (++guard > cap)
            break;
    }

    r->rc = rc;
    r->total_out = s.total_out;
    r->avail_in = s.avail_in;
    r->avail_out = s.avail_out;
    r->outlen = opos - s.avail_out;
    if (s.msg) {
        r->have_msg = 1;
        strncpy(r->msg, s.msg, sizeof(r->msg) - 1);
    }
    if (arm == 0) ref_zlib_inflateEnd(&s);
    else if (arm == 1) rs_zlib_inflateEnd(&s);
    else if (arm == 3) pre_zlib_inflateEnd(&s);
    else refu_zlib_inflateEnd(&s);
}

/* --- stage: zlib_inflate_table(), called directly ------------------------ */
/*
 * Going through the pipeline exercises this function on every run, but only
 * with the code-length sets a real deflate stream carries. This calls it
 * directly, on sets built to hit the branches a stream rarely produces: a
 * single-symbol code, an all-zero code, an over-subscribed set, an incomplete
 * set, and codes deep enough to need sub-tables.
 *
 * Everything is compared, not just the return value: the whole 2048-entry
 * table (both arms start from the same poison, so a write that should not have
 * happened shows up too), how far *table advanced, the resulting *bits, and
 * the work[] scratch array, which is where the symbol sort lands.
 */
#define TBL_ENTRIES ENOUGH

/* A random COMPLETE canonical code over n symbols, by splitting leaves of a
   binary tree. Returns -1 if it would need a code longer than 15 bits. */
static int build_tree_depths(unsigned char *depth, unsigned n)
{
    unsigned cnt = 1, k, tries;

    depth[0] = 0;
    while (cnt < n) {
        k = rng_below(cnt);
        tries = 0;
        while (depth[k] >= 15 && tries++ < 128)
            k = rng_below(cnt);
        if (depth[k] >= 15)
            return -1;
        depth[k]++;
        depth[cnt++] = depth[k];
    }
    return 0;
}

static int gen_lens(unsigned short *lens, unsigned codes, int mode)
{
    static unsigned char depth[512];
    unsigned i, n;

    for (i = 0; i < codes; i++)
        lens[i] = 0;

    switch (mode) {
    case 0:                             /* all zero -- the max == 0 path */
        return 0;
    case 1:                             /* exactly one symbol */
        lens[rng_below(codes)] = 1;
        return 0;
    case 2:                             /* uniform noise; usually invalid */
        for (i = 0; i < codes; i++)
            lens[i] = (unsigned short)rng_below(16);
        return 0;
    default:
        break;
    }

    n = 1 + rng_below(codes);
    if (n > sizeof(depth))
        n = sizeof(depth);
    if (n == 1) {
        lens[rng_below(codes)] = 1;
        return 0;
    }
    if (build_tree_depths(depth, n) != 0)
        return -1;

    /* Scatter the n leaf depths over the symbol space. */
    {
        unsigned placed = 0;
        for (i = 0; i < codes && placed < n; i++) {
            if (rng_below(codes - i) < (n - placed))
                lens[i] = depth[placed++];
        }
        while (placed < n) {            /* pack the remainder */
            for (i = 0; i < codes && placed < n; i++)
                if (lens[i] == 0)
                    lens[i] = depth[placed++];
        }
    }

    if (mode == 4 && codes > 1) {       /* perturb: over- or under-subscribe */
        unsigned k = rng_below(codes);
        lens[k] = (unsigned short)rng_below(16);
    }

    /* OVER-SUBSCRIBED BY EXACTLY ONE, and it has to be constructed.
     * The over-subscription check is `left < 0` after `left -= count[len]`,
     * and mode 2's uniform noise overshoots it by miles -- so a sabotage that
     * weakens the test to `left < -1` survives noise and is caught only by an
     * input that lands on the boundary. A complete code leaves left == 0 after
     * length 15; one extra symbol at length 15 makes it exactly -1. */
    if (mode == 5) {
        for (i = 0; i < codes; i++) {
            if (lens[i] == 0) {
                lens[i] = 15;
                break;
            }
        }
    }
    return 0;
}

static unsigned long tables_stage(unsigned long runs)
{
    static unsigned short lens[512];
    static unsigned short work_a[512], work_b[512];
    static code tbl_a[TBL_ENTRIES], tbl_b[TBL_ENTRIES];
    unsigned long i, cases = 0, bad = 0;
    static const codetype TYPES[3] = { CODES, LENS, DISTS };

    for (i = 0; i < runs; i++) {
        codetype ty = TYPES[rng_below(3)];
        unsigned codes, bits_a, bits_b, off;
        code *pa, *pb;
        int ra, rb, mode;

        switch (ty) {
        case CODES: codes = 19;                    bits_a = 7; break;
        case LENS:  codes = 257 + rng_below(32);   bits_a = 9; break;
        default:    codes = 1 + rng_below(32);     bits_a = 6; break;
        }
        bits_b = bits_a;

        mode = (int)rng_below(10);
        if (mode == 6 || mode == 7)
            mode = 5;                   /* the boundary case is worth 30% */
        else if (mode > 5)
            mode = 3;
        if (gen_lens(lens, codes, mode) != 0)
            continue;

        /* Start the two arms at the SAME non-zero offset into the table some
           of the time: inflate.c calls this three times against one array and
           the second and third calls do not start at index 0. */
        off = rng_below(2) ? 0 : rng_below(64);

        memset(tbl_a, 0xA5, sizeof(tbl_a));
        memcpy(tbl_b, tbl_a, sizeof(tbl_b));
        memset(work_a, 0x5A, sizeof(work_a));
        memcpy(work_b, work_a, sizeof(work_b));

        pa = tbl_a + off;
        pb = tbl_b + off;
        ra = ref_zlib_inflate_table(ty, lens, codes, &pa, &bits_a, work_a);
        rb = zlib_inflate_table(ty, lens, codes, &pb, &bits_b, work_b);

        if (ra != rb) {
            printf("  TABLE MISMATCH return  type=%d codes=%u mode=%d  ref=%d rs=%d\n",
                   (int)ty, codes, mode, ra, rb);
            bad++;
        } else if (bits_a != bits_b) {
            printf("  TABLE MISMATCH bits    type=%d codes=%u mode=%d  ref=%u rs=%u\n",
                   (int)ty, codes, mode, bits_a, bits_b);
            bad++;
        } else if ((pa - tbl_a) != (pb - tbl_b)) {
            printf("  TABLE MISMATCH advance type=%d codes=%u mode=%d  ref=%ld rs=%ld\n",
                   (int)ty, codes, mode, (long)(pa - tbl_a), (long)(pb - tbl_b));
            bad++;
        } else if (memcmp(tbl_a, tbl_b, sizeof(tbl_a)) != 0) {
            unsigned k = 0;
            while (k < TBL_ENTRIES &&
                   memcmp(&tbl_a[k], &tbl_b[k], sizeof(code)) == 0)
                k++;
            printf("  TABLE MISMATCH entries type=%d codes=%u mode=%d  first at %u\n",
                   (int)ty, codes, mode, k);
            printf("      ref op=%u bits=%u val=%u   rs op=%u bits=%u val=%u\n",
                   tbl_a[k].op, tbl_a[k].bits, tbl_a[k].val,
                   tbl_b[k].op, tbl_b[k].bits, tbl_b[k].val);
            bad++;
        } else if (memcmp(work_a, work_b, sizeof(work_a)) != 0) {
            printf("  TABLE MISMATCH work[]  type=%d codes=%u mode=%d\n",
                   (int)ty, codes, mode);
            bad++;
        }
        cases++;
        if (bad > 4)
            break;
    }

    printf("  tables: %lu direct zlib_inflate_table() cases, %lu mismatches\n",
           cases, bad);
    return bad;
}

/* zlib_adler32() is a static inline in include/linux/zutil.h, so the port had
   to carry its own. Comparing the two only through a stream's check value
   exercises it thinly and only at the lengths a deflate stream produces. */
static int adler_stage(unsigned long runs)
{
    static unsigned char buf[3 * 5552 + 64];   /* past NMAX three times over */
    unsigned long i, bad = 0;

    for (i = 0; i < runs; i++) {
        unsigned long seedval, len, k;
        unsigned long a, b;

        /* Lengths clustered on the NMAX blocking boundary the C loops over. */
        switch (rng_below(4)) {
        case 0:  len = rng_below(64); break;
        case 1:  len = 5552 - 2 + rng_below(5); break;
        case 2:  len = 2 * 5552 - 2 + rng_below(5); break;
        default: len = rng_below(sizeof(buf)); break;
        }
        for (k = 0; k < len; k++)
            buf[k] = (unsigned char)rng_u64();

        /* Start from 1 (the C's init value) half the time and from an
           arbitrary running value the rest, so the s1/s2 split is exercised. */
        seedval = (rng_below(2) == 0) ? 1UL : (unsigned long)(rng_u64() >> 32);

        a = zlib_adler32(seedval, buf, (unsigned int)len);
        b = rs_adler32(seedval, len ? buf : NULL, len);
        if (a != b) {
            printf("  ADLER MISMATCH len=%lu seed=%08lx  C=%08lx rs=%08lx\n",
                   len, seedval, a, b);
            if (++bad > 4)
                break;
        }
    }
    printf("  adler32: %lu direct cases, %lu mismatches\n", runs, bad);
    return bad != 0;
}

/* THE ONE DELIBERATE BEHAVIOURAL DIVERGENCE, tested directly.
 *
 * upstream/zlib-inflate-oob/ is this project's own report of an out-of-bounds
 * read in the C's MATCH state. inflate_rs.rs carries upstream zlib's
 * `copy > whave` guard and the C does not, so on this input the two ARM ARMS
 * DO NOT AGREE -- the C reads about 4 GiB past its window and the Rust returns
 * Z_DATA_ERROR. The three-arm comparison cannot express that, so it is a
 * directed test instead, driven by the reproducer already in that package.
 *
 * The call pattern is repro.c's: windowBits -12, output in 4096-byte pieces.
 * Only the Rust arm is run; running the C arm here would be running the bug.
 */
static int oob_divergence_stage(void)
{
    static unsigned char comp[1 << 16];
    static unsigned char out[163841];
    const unsigned long OUTCAP = sizeof(out), OUTCHUNK = 4096;
    const char *path = "upstream/zlib-inflate-oob/reproduce/oob.raw";
    z_stream s;
    void *ws;
    unsigned long clen, opos = 0;
    FILE *f;
    int rc;

    f = fopen(path, "rb");
    if (!f) {
        printf("  oob divergence: %s NOT FOUND -- the divergence is untested\n",
               path);
        return 1;
    }
    clen = fread(comp, 1, sizeof(comp), f);
    fclose(f);

    memset(&s, 0, sizeof(s));
    ws = malloc((size_t)rs_zlib_inflate_workspacesize());
    s.workspace = ws;
    rc = rs_zlib_inflateInit2(&s, -12);
    if (rc != Z_OK) {
        printf("  oob divergence: init failed %d\n", rc);
        free(ws);
        return 1;
    }
    s.next_in = comp;
    s.avail_in = clen;

    for (;;) {
        if (s.avail_out == 0 && opos < OUTCAP) {
            unsigned long k = OUTCAP - opos;

            if (k > OUTCHUNK)
                k = OUTCHUNK;
            s.next_out = out + opos;
            s.avail_out = k;
            opos += k;
        }
        if (s.avail_in == 0 && s.avail_out == 0)
            break;
        rc = rs_zlib_inflate(&s, Z_NO_FLUSH);
        if (rc != Z_OK)
            break;
        if (s.avail_in == 0 && s.avail_out == 0 && opos == OUTCAP)
            break;
    }
    free(ws);

    if (rc == Z_DATA_ERROR && s.msg &&
        strcmp(s.msg, "invalid distance too far back") == 0) {
        int prc;

        printf("  oob divergence: the port rejects the reproducer with\n"
               "       Z_DATA_ERROR \"invalid distance too far back\"\n");

        /* AND SO DOES THE RETAINED PRE-BOOT C, since Adam's call on
           2026-09-03 to fix our kernel rather than wait on Linux. Same five
           lines as the parked patch. This is the only test any retained
           pre-boot body in this project has. */
        memset(&s, 0, sizeof(s));
        ws = malloc((size_t)pre_zlib_inflate_workspacesize());
        s.workspace = ws;
        if (pre_zlib_inflateInit2(&s, -12) != Z_OK) {
            printf("  oob divergence: pre-boot arm init failed\n");
            free(ws);
            return 1;
        }
        s.next_in = comp;
        s.avail_in = clen;
        opos = 0;
        for (;;) {
            if (s.avail_out == 0 && opos < OUTCAP) {
                unsigned long k = OUTCAP - opos;

                if (k > OUTCHUNK)
                    k = OUTCHUNK;
                s.next_out = out + opos;
                s.avail_out = k;
                opos += k;
            }
            if (s.avail_in == 0 && s.avail_out == 0)
                break;
            prc = pre_zlib_inflate(&s, Z_NO_FLUSH);
            if (prc != Z_OK)
                break;
            if (s.avail_in == 0 && s.avail_out == 0 && opos == OUTCAP)
                break;
        }
        free(ws);
        if (prc == Z_DATA_ERROR && s.msg &&
            strcmp(s.msg, "invalid distance too far back") == 0) {
            printf("       and so does the PATCHED PRE-BOOT C body -- both\n"
                   "       halves of lib/zlib_inflate/inflate.c now agree,\n"
                   "       and neither reads out of bounds\n");
            return 0;
        }
        printf("  oob divergence: the pre-boot C body did NOT reject it --\n"
               "       got %d \"%s\". The five-line guard is missing from the\n"
               "       #ifdef STATIC branch of inflate.c\n",
               prc, s.msg ? s.msg : "(none)");
        return 1;
    }
    printf("  oob divergence: EXPECTED Z_DATA_ERROR \"invalid distance too far"
           " back\",\n       got %d \"%s\" -- the MATCH-state whave guard is not"
           " doing its job\n", rc, s.msg ? s.msg : "(none)");
    return 1;
}

/* --- driver ------------------------------------------------------------- */

static const unsigned long INCHUNK[] = { 6, 11, 64, 257, 1031, 4096, 65536, ~0UL };
static const unsigned long OUTCHUNK[] = { 258, 259, 262, 300, 511, 1024, 4099, 32768, 65536, ~0UL };
#define NIN  ((int)(sizeof(INCHUNK) / sizeof(INCHUNK[0])))
#define NOUT ((int)(sizeof(OUTCHUNK) / sizeof(OUTCHUNK[0])))

static const int WBITS[] = { -15, -14, -13, -12, -11, -10, -9, 15, 14, 13, 12, 11, 10, 9 };
#define NWB ((int)(sizeof(WBITS) / sizeof(WBITS[0])))

static const int STRAT[] = { S_DEFAULT, S_FILTERED, S_HUFFMAN, S_RLE, S_FIXED };
#define NST ((int)(sizeof(STRAT) / sizeof(STRAT[0])))

int main(int argc, char **argv)
{
    unsigned long want = (argc > 1) ? strtoul(argv[1], NULL, 0) : 30000;
    unsigned long seed = (argc > 2) ? strtoul(argv[2], NULL, 0) : 20260903;
    unsigned char *plain, *comp, *o_ref, *o_rs, *o_ru, *o_pre;
    void *ws_ref, *ws_rs, *ws_ru, *ws_pre;
    unsigned long runs = 0, mismatches = 0, bytes = 0, corrupt_runs = 0;
    unsigned long notend_runs = 0;  /* non-corrupt runs not ending Z_STREAM_END */

    int i;

    printf("zlib_inflate differential: all of lib/zlib_inflate/, C vs Rust\n");
    if (abi_check())
        return 2;
    if (inftrees_abi_check())
        return 2;
    if (inflate_abi_check())
        return 2;
    if (fixedtables_check())
        return 2;
    if (ref_zlib_inflate_workspacesize() != rs_zlib_inflate_workspacesize()) {
        printf("  workspace sizes differ -- the two arms are not the same machinery\n");
        return 2;
    }

    load_file("port/tree/lib/zlib_inflate/inffast_rs.rs");
    load_file("port/pristine/lib/zlib_inflate/inflate.c");
    load_file("port/pristine/include/linux/zlib.h");
    load_file("STATUS.md");
    load_file("GOALS.md");
    printf("  corpus: %d generators, %d of them file-backed\n", NGEN, nfiles ? 1 : 0);

    mix_scratch = malloc(PLAIN_CAP);
    plain = malloc(PLAIN_CAP);
    comp  = malloc(COMP_CAP);
    o_ref = malloc(OUT_CAP);
    o_rs  = malloc(OUT_CAP);
    o_ru  = malloc(OUT_CAP);
    o_pre = malloc(OUT_CAP);
    ws_ref = malloc((size_t)ref_zlib_inflate_workspacesize());
    ws_rs  = malloc((size_t)rs_zlib_inflate_workspacesize());
    ws_ru  = malloc((size_t)refu_zlib_inflate_workspacesize());
    ws_pre = malloc((size_t)pre_zlib_inflate_workspacesize());
    if (!mix_scratch || !plain || !comp || !o_ref || !o_rs || !o_ru ||
        !o_pre || !ws_ref || !ws_rs || !ws_ru || !ws_pre) {
        printf("  out of memory\n");
        return 2;
    }

    rng_seed(seed);

    if (tables_stage(want > 200000 ? 200000 : want) != 0)
        return 1;
    if (adler_stage(want > 20000 ? 20000 : want) != 0)
        return 1;
    if (oob_divergence_stage() != 0)
        return 1;

    while (runs < want) {
        unsigned long n, cl, outcap, inchunk, outchunk;
        int kind, level, wb, memlevel, strategy, dwb, flush;
        struct rr a, b, c, e;
        int corrupt;

        kind = (int)rng_below(NGEN);
        n = gen(kind, plain);

        level    = (int)rng_below(10);
        wb       = WBITS[rng_below(NWB)];
        memlevel = 1 + (int)rng_below(9);
        strategy = STRAT[rng_below(NST)];

        cl = 0;
        {
            long r = corpus_compress(plain, n, level, wb, memlevel, strategy,
                                     comp, COMP_CAP);
            if (r < 0)
                continue;
            cl = (unsigned long)r;
        }
        /* raw streams must be inflated with the same window; zlib-wrapped
           ones carry it in the header, so ask for the maximum. */
        dwb = (wb < 0) ? wb : MAX_WBITS;

        /* One run in eight is fed a bit-flipped stream, which is what
           reaches inflate_fast()'s three error exits. Both arms get the
           SAME corruption. */
        /* Corruption is confined to FULL-WINDOW streams, and that is not
           fastidiousness. With windowBits < 15 a corrupt stream can carry a
           match distance larger than the window, and inflate.c -- not the
           ported inffast.c -- then indexes the window with an unsigned
           underflow and reads wild memory. See upstream/zlib-inflate-oob/
           for the mechanism and a reproducer that links no Rust at all.
           At windowBits 15 the largest codeable distance IS the window, so
           the underflow cannot arise and the corrupt-stream coverage of
           inflate_fast()'s three error exits is kept. */
        corrupt = (rng_below(2) == 0) && cl > 4 && (wb == 15 || wb == -15);
        if (corrupt) {
            int flips = 1 + (int)rng_below(3);
            while (flips--) {
                unsigned long p = 2 + rng_below((unsigned)(cl - 2));
                comp[p] ^= (unsigned char)(1u << rng_below(8));
            }
            corrupt_runs++;
        }

        inchunk  = INCHUNK[rng_below(NIN)];
        outchunk = OUTCHUNK[rng_below(NOUT)];
        outcap   = n + 1 + rng_below(64);
        if (outcap > OUT_CAP) outcap = OUT_CAP;

        /* Same sentinel in all three, so comparing the WHOLE buffer also
           catches an arm that wrote past the output it claimed to produce. */
        /* If ZDUMP names a path, the stream about to be decompressed is
           written there first, overwritten each run. A crash therefore
           leaves the culprit on disk. That is how the inflate.c window
           underflow below was captured. */
        {
            const char *dp = getenv("ZDUMP");

            if (dp) {
                FILE *df = fopen(dp, "wb");

                if (df) {
                    fprintf(df, "wbits %d outchunk %lu inchunk %lu outcap %lu "
                                "corrupt %d clen %lu\n",
                            dwb, outchunk, inchunk, outcap, corrupt, cl);
                    fwrite(comp, 1, cl, df);
                    fclose(df);
                }
            }
        }

        memset(o_ref, 0xa5, outcap);
        memset(o_rs,  0xa5, outcap);
        memset(o_ru,  0xa5, outcap);

        /* THE FLUSH ARGUMENT IS AN AXIS, and it was not varied until
           2026-09-03. Z_NO_FLUSH is what every caller in the tree uses except
           zlib_inflate_blob() (Z_FINISH) and ppp_deflate.c (Z_PACKET_FLUSH),
           and three branches of zlib_inflate() are reachable only through the
           others: the Z_BLOCK early return in TYPE, zlib_inflateSyncPacket()
           under Z_PACKET_FLUSH, and the Z_FINISH clause that turns Z_OK into
           Z_BUF_ERROR. A sabotage of that last one survived the whole suite
           until this was added. Both arms get the same value. */
        switch (rng_below(8)) {
        case 0:  flush = Z_BLOCK; break;
        case 1:  flush = Z_PACKET_FLUSH; break;
        case 2:  flush = Z_FINISH; break;
        default: flush = Z_NO_FLUSH; break;
        }

        run(0, comp, cl, dwb, inchunk, outchunk, o_ref, outcap, ws_ref, flush, &a);
        run(1, comp, cl, dwb, inchunk, outchunk, o_rs,  outcap, ws_rs,  flush, &b);
        run(2, comp, cl, dwb, inchunk, outchunk, o_ru,  outcap, ws_ru,  flush, &c);
        /* The patched pre-boot body, on the same stream. Its job here is to
           show the five-line guard changes NOTHING on a well-formed stream --
           a fix that rejected valid input would be worse than the bug. */
        run(3, comp, cl, dwb, inchunk, outchunk, o_pre, outcap, ws_pre, flush, &e);

        runs++;
        bytes += a.outlen;

        /* ---- THE INDEPENDENT ORACLE -----------------------------------
         *
         * Every other check in this loop compares the arms AGAINST EACH
         * OTHER, and no comparison can see a bug they share. The C oracle
         * and the Rust port are the same algorithm: a constant transcribed
         * faithfully from a misreading, or a defect in the kernel's own C,
         * is invisible to all four arms at once.
         *
         * `plain` was compressed by SYSTEM zlib (corpus.c:23), which is
         * derived from nothing in this tree. Requiring the decode to
         * reproduce `plain` exactly is therefore a check the arms cannot
         * agree their way past.
         *
         * The first attempt at this port had already named the principle,
         * in doctrine/EVIDENCE.md: "an independent invariant checker that is
         * *not* differential -- it catches a bug both implementations share,
         * which no comparison ever can."
         *
         * Added 2026-09-04, after finding Z_STREAM_END appeared ZERO times
         * in this file: the harness had always checked agreement, never
         * success. */
        if (!corrupt) {
            /* outcap is deliberately clamped to OUT_CAP, so on a large
             * plaintext the buffer CANNOT hold the whole decode and Z_BUF_ERROR
             * with a short outlen is correct behaviour, not a defect. (My first
             * version of this check ignored that and "failed" 9 times in 34
             * runs -- the check was wrong, not the decoder.) So: whatever WAS
             * produced must be a correct PREFIX of the original, always; and
             * the FULL length is required only when the buffer could hold it. */
            /* Z_BLOCK returns at every block boundary (inflate.c:409) and
             * Z_PACKET_FLUSH calls zlib_inflateSyncPacket() (:760). BOTH stop
             * the decode early BY DESIGN, so a short result under them is
             * correct, not a defect. Only the full-decode flushes may be
             * required to reach the end. */
            int must_finish = (flush == Z_NO_FLUSH || flush == Z_FINISH);

            if (a.outlen > n || memcmp(o_ref, plain, a.outlen) != 0 ||
                (must_finish && outcap > n && a.outlen != n)) {
                mismatches++;
                printf("\nINDEPENDENT ORACLE run %lu: the decode did not "
                       "reproduce what system zlib compressed\n", runs);
                printf("  kind=%d plainlen=%lu level=%d wbits=%d dwb=%d "
                       "strategy=%d rc=%d outlen=%lu outcap=%lu\n",
                       kind, n, level, wb, dwb, strategy, a.rc, a.outlen, outcap);
                if (mismatches > 8)
                    break;
            }
            /* Counted, not gated. A well-formed stream decoded in chunks can
             * legitimately stop at Z_OK when the output buffer bounds the
             * call, so measure how often before deciding to require it. */
            if (must_finish && a.rc != Z_STREAM_END)
                notend_runs++;
        }

        /* Arm C is the same C with the wide-load option off. If it ever
           disagrees with arm A the C's two spellings are not equivalent and
           the port's divergence 2 is unsound, so it is checked first and
           reported as its own failure. */
        if (a.rc != c.rc || a.total_out != c.total_out || a.outlen != c.outlen ||
            memcmp(o_ref, o_ru, outcap) != 0) {
            mismatches++;
            printf("\nORACLE SPLIT run %lu: the C's two unaligned-access "
                   "spellings disagree with each other\n", runs);
            printf("  kind=%d plainlen=%lu level=%d wbits=%d strategy=%d\n",
                   kind, n, level, wb, strategy);
            if (mismatches > 8) break;
        }

        /* Arm D is the retained PRE-BOOT body with the five-line guard.
           On a well-formed stream it must be indistinguishable from arm A;
           a fix that rejected valid input would be worse than the bug it
           fixes. On a CORRUPT stream it is allowed to differ, and that is
           the whole point -- arm A still has the bug. */
        /* Compared over a.outlen, NOT outcap. The tail beyond what was
           produced is never written, and on a CORRUPT run this arm stops
           early by design -- so from the first corrupt run onward the two
           buffers' unwritten tails differ forever. Comparing them was the
           first version of this check and it failed on run 2. */
        if (!corrupt &&
            (a.rc != e.rc || a.total_out != e.total_out || a.outlen != e.outlen ||
             memcmp(o_ref, o_pre, a.outlen) != 0)) {
            mismatches++;
            printf("\nPRE-BOOT ARM run %lu: the five-line whave guard changed "
                   "the answer on a WELL-FORMED stream\n", runs);
            printf("  kind=%d plainlen=%lu level=%d wbits=%d strategy=%d\n",
                   kind, n, level, wb, strategy);
            printf("  rc %d / %d   outlen %lu / %lu  outcap %lu\n",
                   a.rc, e.rc, a.outlen, e.outlen, outcap);
            {
                unsigned long j, at = outcap;

                for (j = 0; j < a.outlen; j++)
                    if (o_ref[j] != o_pre[j]) { at = j; break; }
                if (at < a.outlen)
                    printf("  first differing byte at %lu of %lu: %02x / %02x\n",
                           at, a.outlen, o_ref[at], o_pre[at]);
            }
            if (mismatches > 8) break;
        }

        if (a.rc != b.rc || a.total_out != b.total_out ||
            a.avail_in != b.avail_in || a.avail_out != b.avail_out ||
            a.outlen != b.outlen || a.have_msg != b.have_msg ||
            (a.have_msg && strcmp(a.msg, b.msg) != 0) ||
            memcmp(o_ref, o_rs, outcap) != 0) {
            unsigned long j, at = outcap;
            for (j = 0; j < outcap; j++)
                if (o_ref[j] != o_rs[j]) { at = j; break; }
            mismatches++;
            printf("\nMISMATCH run %lu\n", runs);
            printf("  kind=%d plainlen=%lu level=%d wbits=%d memlevel=%d "
                   "strategy=%d corrupt=%d\n",
                   kind, n, level, wb, memlevel, strategy, corrupt);
            printf("  complen=%lu inchunk=%lu outchunk=%lu outcap=%lu seed=%lu\n",
                   cl, inchunk, outchunk, outcap, seed);
            printf("  rc        %d / %d\n", a.rc, b.rc);
            printf("  total_out %lu / %lu\n", a.total_out, b.total_out);
            printf("  avail_in  %lu / %lu\n", a.avail_in, b.avail_in);
            printf("  avail_out %lu / %lu\n", a.avail_out, b.avail_out);
            printf("  outlen    %lu / %lu\n", a.outlen, b.outlen);
            printf("  msg       %s / %s\n", a.have_msg ? a.msg : "(none)",
                                            b.have_msg ? b.msg : "(none)");
            if (at < outcap)
                printf("  first differing output byte at %lu: %02x / %02x\n",
                       at, o_ref[at], o_rs[at]);
            if (mismatches > 8) {
                printf("\nstopping after 8 mismatches\n");
                break;
            }
        }

        if ((runs % 2000) == 0) {
            printf("  %lu runs, %lu MiB decoded, %lu corrupt, 0 mismatches\r",
                   runs, bytes >> 20, corrupt_runs);
            fflush(stdout);
        }
    }

    printf("\n");
    printf("  runs        %lu full decompressions, each arm\n", runs);
    printf("  bytes       %lu decoded and compared per arm (%lu MiB)\n",
           bytes, bytes >> 20);
    printf("  corrupt     %lu runs on bit-flipped streams\n", corrupt_runs);
    printf("  oracle      %lu non-corrupt runs compared against the ORIGINAL\n"
           "              plaintext -- system zlib's input, which no arm is\n"
           "              derived from. Catches a bug all arms share.\n",
           runs - corrupt_runs);
    printf("  not-END     %lu of those returned other than Z_STREAM_END\n",
           notend_runs);
    printf("  fast-path   %lu measured calls into inflate_fast() per arm\n",
           fast_entries);
    printf("  arms        4: pristine C (wide load), pristine C (byte-wise),\n"
           "                 the Rust, and the PATCHED PRE-BOOT C body --\n"
           "                 the first retained pre-boot body this project\n"
           "                 has ever compiled, let alone tested\n");
    printf("  mismatches  %lu\n", mismatches);

    for (i = 0; i < nfiles; i++)
        free(files[i]);
    free(mix_scratch);
    free(plain); free(comp); free(o_ref); free(o_rs); free(o_ru);
    free(ws_ref); free(ws_rs); free(ws_ru);
    return mismatches ? 1 : 0;
}
