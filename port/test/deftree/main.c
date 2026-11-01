/* Differential test for lib/zlib_deflate/deftree.c -> deftree_rs.rs.
 *
 * WHAT IS COMPARED
 *   deftree.c has no entry thunk and is never called directly by anything
 *   outside deflate.c -- zlib_tr_init/_tally/_flush_block/_align/
 *   _stored_block/_stored_type_only cannot be driven in isolation, they need
 *   a live deflate_state built by the surrounding compressor. So both arms
 *   run the SAME PRISTINE lib/zlib_deflate/deflate.c, out of port/pristine/,
 *   compiled TWICE under different names; the only thing that differs
 *   between the two compiled objects is which zlib_tr_*() bodies they
 *   resolve to -- pristine deftree.c in one arm, the Rust in the other.
 *   Driving the whole compressor is not a weaker test than calling deftree's
 *   functions directly, it is the only honest one, same reasoning as
 *   ../zlib_inflate/main.c's inflate_fast() comment.
 *
 * WHAT ELSE IS CHECKED
 *   The struct offsets the Rust mirrors, against offsetof() on the real
 *   defutil.h. And every accepted compressed stream is independently
 *   inflated by the SYSTEM zlib (sysinflate.c, a separate translation unit
 *   for the same reason corpus.c is one in ../zlib_inflate/) and compared
 *   byte-for-byte against the original input -- an oracle that shares no
 *   code with either arm.
 */
#include <linux/zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "defutil.h"

/* --- the two arms -------------------------------------------------------- */

extern int ref_zlib_deflateInit2(z_streamp strm, int level, int method,
                                  int windowBits, int memLevel, int strategy);
extern int ref_zlib_deflate(z_streamp strm, int flush);
extern int ref_zlib_deflateEnd(z_streamp strm);
extern int ref_zlib_deflate_workspacesize(int windowBits, int memLevel);

extern int rs_zlib_deflateInit2(z_streamp strm, int level, int method,
                                 int windowBits, int memLevel, int strategy);
extern int rs_zlib_deflate(z_streamp strm, int flush);
extern int rs_zlib_deflateEnd(z_streamp strm);
extern int rs_zlib_deflate_workspacesize(int windowBits, int memLevel);

/* The ABI report from the Rust port, see deftree_rs.rs's `deftree_rs_abi`. */
extern void deftree_rs_abi(uint64_t *out);

/* The independent roundtrip oracle, sysinflate.c. */
extern long sys_inflate_raw(const unsigned char *src, unsigned long n,
                             int window_bits, unsigned char *dst,
                             unsigned long dcap);

typedef int (*init2_fn)(z_streamp, int, int, int, int, int);
typedef int (*deflate_fn)(z_streamp, int);
typedef int (*end_fn)(z_streamp);
typedef int (*wssize_fn)(int, int);

struct arm {
    const char *name;
    init2_fn init2;
    deflate_fn deflate;
    end_fn end;
    wssize_fn wssize;
};

static const struct arm REF = { "ref", ref_zlib_deflateInit2, ref_zlib_deflate,
                                 ref_zlib_deflateEnd, ref_zlib_deflate_workspacesize };
static const struct arm RS  = { "rs",  rs_zlib_deflateInit2,  rs_zlib_deflate,
                                 rs_zlib_deflateEnd,  rs_zlib_deflate_workspacesize };

/* --- ABI check ------------------------------------------------------------ */

#define ABI_SLOTS 22

static int abi_check(void)
{
    uint64_t got[ABI_SLOTS];
    uint64_t want[ABI_SLOTS];
    static const char *const names[ABI_SLOTS] = {
        "sizeof(deflate_state)", "strm", "status", "pending_buf", "pending",
        "data_type", "w_bits", "window", "block_start", "strstart", "level",
        "dyn_ltree", "dyn_dtree", "bl_tree", "l_desc", "bl_count", "heap",
        "l_buf", "d_buf", "opt_len", "compressed_len", "bi_buf",
    };
    int i, bad = 0;

    want[0]  = sizeof(deflate_state);
    want[1]  = offsetof(deflate_state, strm);
    want[2]  = offsetof(deflate_state, status);
    want[3]  = offsetof(deflate_state, pending_buf);
    want[4]  = offsetof(deflate_state, pending);
    want[5]  = offsetof(deflate_state, data_type);
    want[6]  = offsetof(deflate_state, w_bits);
    want[7]  = offsetof(deflate_state, window);
    want[8]  = offsetof(deflate_state, block_start);
    want[9]  = offsetof(deflate_state, strstart);
    want[10] = offsetof(deflate_state, level);
    want[11] = offsetof(deflate_state, dyn_ltree);
    want[12] = offsetof(deflate_state, dyn_dtree);
    want[13] = offsetof(deflate_state, bl_tree);
    want[14] = offsetof(deflate_state, l_desc);
    want[15] = offsetof(deflate_state, bl_count);
    want[16] = offsetof(deflate_state, heap);
    want[17] = offsetof(deflate_state, l_buf);
    want[18] = offsetof(deflate_state, d_buf);
    want[19] = offsetof(deflate_state, opt_len);
    want[20] = offsetof(deflate_state, compressed_len);
    want[21] = offsetof(deflate_state, bi_buf);

    deftree_rs_abi(got);
    for (i = 0; i < ABI_SLOTS; i++) {
        if (got[i] != want[i]) {
            printf("  ABI MISMATCH %-24s rust %6llu  C %6llu\n", names[i],
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            bad = 1;
        }
    }
    printf("  ABI: %d offsets and sizes checked against offsetof() on the\n"
           "       real defutil.h, %s\n", ABI_SLOTS, bad ? "MISMATCHED" : "all agree");
    return bad;
}

/* --- rng -------------------------------------------------------------- */

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

/* --- corpus ------------------------------------------------------------- */

#define PLAIN_CAP (1u << 16)
#define OUT_CAP   (PLAIN_CAP * 2 + 8192)

static const char *const WORDS[] = {
    "the", "kernel", "deflate", "window", "distance", "length", "code",
    "buffer", "rust", "match", "literal", "tree", "table", "stream",
    "a", "of", "and", "to", "in", "is", "it", "that", "for", "with",
};
#define NWORDS ((int)(sizeof(WORDS) / sizeof(WORDS[0])))

#define NGEN 7

static unsigned long gen(int kind, unsigned char *b)
{
    unsigned long n, i;
    unsigned k;

    switch (kind) {
    case 0: /* zeros -- longest possible matches */
        n = 1 + rng_below(PLAIN_CAP - 1);
        memset(b, 0, n);
        return n;
    case 1: { /* one repeated byte -- dist == 1 */
        unsigned char c = (unsigned char)rng_below(256);
        n = 1 + rng_below(PLAIN_CAP - 1);
        memset(b, c, n);
        return n;
    }
    case 2: { /* short period */
        unsigned char p[8];
        k = 2 + rng_below(7);
        for (i = 0; i < k; i++) p[i] = (unsigned char)rng_below(256);
        n = k + rng_below(PLAIN_CAP - k - 1);
        for (i = 0; i < n; i++) b[i] = p[i % k];
        return n;
    }
    case 3: /* incompressible -- every code a literal, exercises stored-block choice */
        n = 1 + rng_below(PLAIN_CAP - 1);
        for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
        return n;
    case 4: { /* small alphabet -- lots of short matches and bl-tree traffic */
        unsigned char alpha[8];
        k = 2 + rng_below(7);
        for (i = 0; i < k; i++) alpha[i] = (unsigned char)rng_below(256);
        n = 1 + rng_below(PLAIN_CAP - 1);
        for (i = 0; i < n; i++) b[i] = alpha[rng_below(k)];
        return n;
    }
    case 5: { /* text -- the shape real callers actually compress */
        n = 0;
        while (n < PLAIN_CAP / 2) {
            const char *w = WORDS[rng_below(NWORDS)];
            unsigned long l = strlen(w);
            if (n + l + 2 >= PLAIN_CAP) break;
            memcpy(b + n, w, l);
            n += l;
            b[n++] = (rng_below(12) == 0) ? '\n' : ' ';
        }
        return n ? n : 1;
    }
    case 6: /* empty / tiny -- boundary */
        n = rng_below(4);
        for (i = 0; i < n; i++) b[i] = (unsigned char)rng_below(256);
        return n;
    default:
        return 0;
    }
}

/* --- driving deflate() --------------------------------------------------- */

/* Run one compression under `arm`, feeding `src` in `nflush` chunks, calling
 * deflate() with flushes[i] after each chunk (the last must be Z_FINISH).
 * avail_out is generous enough that the standard "loop while avail_out==0"
 * drain is never needed; the loop below instead drives to
 * "no more input for this chunk, and Z_STREAM_END once flush == Z_FINISH". */
static long run_arm(const struct arm *arm, const unsigned char *src, unsigned long srclen,
                     int level, int wbits, int memlevel, int strategy,
                     const int *flushes, int nflush,
                     unsigned char *out, unsigned long outcap, int *rc_out)
{
    z_stream s;
    int rc = Z_OK;
    unsigned long consumed = 0;
    unsigned long chunk = nflush > 0 ? srclen / nflush : srclen;
    int wssize;
    int i;

    memset(&s, 0, sizeof(s));
    /* Raw (headerless) deflate -- negative windowBits, the convention every
     * real in-kernel caller of zlib_deflate uses (btrfs, ubifs, ...), and
     * what sys_inflate_raw (sysinflate.c) expects on the other end. */
    wssize = arm->wssize(wbits, memlevel);
    s.workspace = malloc((size_t)wssize);
    if (!s.workspace) { *rc_out = Z_MEM_ERROR; return -1; }

    rc = arm->init2(&s, level, Z_DEFLATED, -wbits, memlevel, strategy);
    if (rc != Z_OK) { free(s.workspace); *rc_out = rc; return -1; }

    s.next_out = out;
    s.avail_out = (unsigned)outcap;

    for (i = 0; i < nflush; i++) {
        unsigned long this_chunk = (i == nflush - 1) ? (srclen - consumed) : chunk;
        int flush = flushes[i];

        s.next_in = (unsigned char *)src + consumed;
        s.avail_in = (unsigned)this_chunk;
        consumed += this_chunk;

        do {
            rc = arm->deflate(&s, flush);
            if (rc != Z_OK && rc != Z_STREAM_END) {
                arm->end(&s);
                free(s.workspace);
                *rc_out = rc;
                return -1;
            }
        } while (s.avail_in > 0);

        if (flush == Z_FINISH) {
            while (rc != Z_STREAM_END) {
                rc = arm->deflate(&s, flush);
                if (rc != Z_OK && rc != Z_STREAM_END) {
                    arm->end(&s);
                    free(s.workspace);
                    *rc_out = rc;
                    return -1;
                }
            }
        }
    }

    rc = arm->end(&s);
    free(s.workspace);
    *rc_out = rc;
    return (long)(outcap - s.avail_out);
}

static unsigned char *g_src, *g_ref_out, *g_rs_out, *g_roundtrip;

static int uses_packet_flush(const int *flushes, int nflush)
{
    int i;
    for (i = 0; i < nflush; i++)
        if (flushes[i] == 2 /* Z_PACKET_FLUSH */)
            return 1;
    return 0;
}

static int check_one(const unsigned char *src, unsigned long srclen,
                      int level, int wbits, int memlevel, int strategy,
                      const int *flushes, int nflush)
{
    int ref_rc = 0, rs_rc = 0;
    long ref_len, rs_len;

    ref_len = run_arm(&REF, src, srclen, level, wbits, memlevel, strategy,
                       flushes, nflush, g_ref_out, OUT_CAP, &ref_rc);
    rs_len = run_arm(&RS, src, srclen, level, wbits, memlevel, strategy,
                      flushes, nflush, g_rs_out, OUT_CAP, &rs_rc);

    if (ref_rc != rs_rc || ref_len != rs_len ||
        (ref_len >= 0 && memcmp(g_ref_out, g_rs_out, (size_t)ref_len) != 0)) {
        printf("MISMATCH level=%d wbits=%d memlevel=%d strategy=%d nflush=%d srclen=%lu\n"
               "  ref: rc=%d len=%ld\n  rs:  rc=%d len=%ld\n",
               level, wbits, memlevel, strategy, nflush, srclen,
               ref_rc, ref_len, rs_rc, rs_len);
        if (ref_len >= 0 && rs_len == ref_len) {
            long i;
            for (i = 0; i < ref_len; i++) {
                if (g_ref_out[i] != g_rs_out[i]) {
                    printf("  first differing byte at %ld: ref=%02x rs=%02x\n",
                           i, g_ref_out[i], g_rs_out[i]);
                    break;
                }
            }
        }
        return 1;
    }

    if (ref_len < 0)
        return 0; /* both arms rejected the parameters identically; nothing to inflate */

    /* Z_PACKET_FLUSH's marker (zlib_tr_stored_type_only: just the 3-bit
     * stored-block-type header, deliberately with no length/data to
     * follow) is a PPP-specific convention consumed by a matching decoder
     * that already knows to stop there -- not a complete, standalone
     * RFC 1951 stream. A generic inflate() correctly rejects it; that is
     * not a defect in either arm. */
    if (uses_packet_flush(flushes, nflush))
        return 0;

    /* independent roundtrip oracle */
    {
        long got = sys_inflate_raw(g_ref_out, (unsigned long)ref_len, wbits,
                                    g_roundtrip, PLAIN_CAP + 4096);
        if (got != (long)srclen || (srclen && memcmp(g_roundtrip, src, srclen) != 0)) {
            printf("ROUNDTRIP FAILED level=%d wbits=%d memlevel=%d strategy=%d nflush=%d "
                   "srclen=%lu compressed=%ld got=%ld\n",
                   level, wbits, memlevel, strategy, nflush, srclen, ref_len, got);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    long runs = argc > 1 ? atol(argv[1]) : 4000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 20260906ull;
    long i;
    int fails = 0;

    if (abi_check())
        fails++;

    g_src = malloc(PLAIN_CAP);
    g_ref_out = malloc(OUT_CAP);
    g_rs_out = malloc(OUT_CAP);
    g_roundtrip = malloc(PLAIN_CAP + 4096);
    if (!g_src || !g_ref_out || !g_rs_out || !g_roundtrip) {
        fprintf(stderr, "out of memory\n");
        return 2;
    }

    rng_seed(seed);

    for (i = 0; i < runs; i++) {
        int kind = (int)rng_below(NGEN);
        unsigned long srclen = gen(kind, g_src);
        int level = (int)rng_below(10);          /* 0..9 */
        int wbits = 9 + (int)rng_below(7);        /* 9..15 */
        int memlevel = 1 + (int)rng_below(8);     /* 1..8 (MAX_MEM_LEVEL) */
        int strategy = (int)rng_below(3);         /* Z_DEFAULT/Z_FILTERED/Z_HUFFMAN_ONLY */
        int single_flush[1];
        int multi_flush[6];
        int nflush;
        const int *flushes;
        static const int mid_flushes[] = { 0 /*Z_NO_FLUSH*/, 1 /*Z_PARTIAL_FLUSH*/,
                                            2 /*Z_PACKET_FLUSH*/, 3 /*Z_SYNC_FLUSH*/,
                                            4 /*Z_FULL_FLUSH*/ };

        if (rng_below(2) == 0 || srclen < 8) {
            single_flush[0] = 5; /* Z_FINISH */
            flushes = single_flush;
            nflush = 1;
        } else {
            int j, n = 1 + (int)rng_below(4);
            for (j = 0; j < n; j++)
                multi_flush[j] = mid_flushes[rng_below(5)];
            multi_flush[n] = 5; /* Z_FINISH */
            flushes = multi_flush;
            nflush = n + 1;
        }

        if (check_one(g_src, srclen, level, wbits, memlevel, strategy, flushes, nflush))
            fails++;
        if (fails > 20) {
            printf("too many failures, stopping early\n");
            break;
        }
    }

    printf("deftree differential: %ld runs, %d failed\n", runs, fails);
    return fails ? 1 : 0;
}
