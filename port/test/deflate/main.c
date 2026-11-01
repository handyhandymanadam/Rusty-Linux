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
extern void deflate_rs_abi(uint64_t *out);

/* The independent roundtrip oracle, sysinflate.c. */
extern long sys_inflate_raw(const unsigned char *src, unsigned long n,
                             int window_bits, int header, unsigned char *dst,
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


#define ABI2_SLOTS 72
static int abi_check2(void)
{
    uint64_t got[ABI2_SLOTS], want[ABI2_SLOTS];
    static const char *const names[ABI2_SLOTS] = { "sizeof(deflate_state)", "strm", "status", "pending_buf", "pending_buf_size", "pending_out", "pending", "noheader", "data_type", "method", "last_flush", "w_size", "w_bits", "w_mask", "window", "window_size", "prev", "head", "ins_h", "hash_size", "hash_bits", "hash_mask", "hash_shift", "block_start", "match_length", "prev_match", "match_available", "strstart", "match_start", "lookahead", "prev_length", "max_chain_length", "max_lazy_match", "level", "strategy", "good_match", "nice_match", "dyn_ltree", "dyn_dtree", "bl_tree", "l_desc", "d_desc", "bl_desc", "bl_count", "heap", "heap_len", "heap_max", "depth", "l_buf", "lit_bufsize", "last_lit", "d_buf", "opt_len", "static_len", "compressed_len", "matches", "last_eob_len", "bi_buf", "bi_valid", "sizeof(z_stream)", "next_in", "avail_in", "total_in", "next_out", "avail_out", "total_out", "msg", "state", "workspace", "data_type", "adler", "reserved" };
    int i = 0, bad = 0;

    want[i++] = sizeof(deflate_state);
    want[i++] = offsetof(deflate_state, strm);
    want[i++] = offsetof(deflate_state, status);
    want[i++] = offsetof(deflate_state, pending_buf);
    want[i++] = offsetof(deflate_state, pending_buf_size);
    want[i++] = offsetof(deflate_state, pending_out);
    want[i++] = offsetof(deflate_state, pending);
    want[i++] = offsetof(deflate_state, noheader);
    want[i++] = offsetof(deflate_state, data_type);
    want[i++] = offsetof(deflate_state, method);
    want[i++] = offsetof(deflate_state, last_flush);
    want[i++] = offsetof(deflate_state, w_size);
    want[i++] = offsetof(deflate_state, w_bits);
    want[i++] = offsetof(deflate_state, w_mask);
    want[i++] = offsetof(deflate_state, window);
    want[i++] = offsetof(deflate_state, window_size);
    want[i++] = offsetof(deflate_state, prev);
    want[i++] = offsetof(deflate_state, head);
    want[i++] = offsetof(deflate_state, ins_h);
    want[i++] = offsetof(deflate_state, hash_size);
    want[i++] = offsetof(deflate_state, hash_bits);
    want[i++] = offsetof(deflate_state, hash_mask);
    want[i++] = offsetof(deflate_state, hash_shift);
    want[i++] = offsetof(deflate_state, block_start);
    want[i++] = offsetof(deflate_state, match_length);
    want[i++] = offsetof(deflate_state, prev_match);
    want[i++] = offsetof(deflate_state, match_available);
    want[i++] = offsetof(deflate_state, strstart);
    want[i++] = offsetof(deflate_state, match_start);
    want[i++] = offsetof(deflate_state, lookahead);
    want[i++] = offsetof(deflate_state, prev_length);
    want[i++] = offsetof(deflate_state, max_chain_length);
    want[i++] = offsetof(deflate_state, max_lazy_match);
    want[i++] = offsetof(deflate_state, level);
    want[i++] = offsetof(deflate_state, strategy);
    want[i++] = offsetof(deflate_state, good_match);
    want[i++] = offsetof(deflate_state, nice_match);
    want[i++] = offsetof(deflate_state, dyn_ltree);
    want[i++] = offsetof(deflate_state, dyn_dtree);
    want[i++] = offsetof(deflate_state, bl_tree);
    want[i++] = offsetof(deflate_state, l_desc);
    want[i++] = offsetof(deflate_state, d_desc);
    want[i++] = offsetof(deflate_state, bl_desc);
    want[i++] = offsetof(deflate_state, bl_count);
    want[i++] = offsetof(deflate_state, heap);
    want[i++] = offsetof(deflate_state, heap_len);
    want[i++] = offsetof(deflate_state, heap_max);
    want[i++] = offsetof(deflate_state, depth);
    want[i++] = offsetof(deflate_state, l_buf);
    want[i++] = offsetof(deflate_state, lit_bufsize);
    want[i++] = offsetof(deflate_state, last_lit);
    want[i++] = offsetof(deflate_state, d_buf);
    want[i++] = offsetof(deflate_state, opt_len);
    want[i++] = offsetof(deflate_state, static_len);
    want[i++] = offsetof(deflate_state, compressed_len);
    want[i++] = offsetof(deflate_state, matches);
    want[i++] = offsetof(deflate_state, last_eob_len);
    want[i++] = offsetof(deflate_state, bi_buf);
    want[i++] = offsetof(deflate_state, bi_valid);
    want[i++] = sizeof(z_stream);
    want[i++] = offsetof(z_stream, next_in);
    want[i++] = offsetof(z_stream, avail_in);
    want[i++] = offsetof(z_stream, total_in);
    want[i++] = offsetof(z_stream, next_out);
    want[i++] = offsetof(z_stream, avail_out);
    want[i++] = offsetof(z_stream, total_out);
    want[i++] = offsetof(z_stream, msg);
    want[i++] = offsetof(z_stream, state);
    want[i++] = offsetof(z_stream, workspace);
    want[i++] = offsetof(z_stream, data_type);
    want[i++] = offsetof(z_stream, adler);
    want[i++] = offsetof(z_stream, reserved);
    deflate_rs_abi(got);
    for (i = 0; i < ABI2_SLOTS; i++) {
        if (got[i] != want[i]) {
            printf("  ABI2 MISMATCH %-24s rust %6llu  C %6llu\n", names[i],
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            bad = 1;
        }
    }
    printf("  ABI2: %d offsets and sizes (every field of deflate_state and z_stream) checked against offsetof(), %s\n",
           ABI2_SLOTS, bad ? "MISMATCHED" : "all agree");
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

#define NGEN 9

static unsigned long gen(int kind, unsigned char *b, int wbits)
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
    case 7: { /* noise with one 3-byte string repeated at distance 4095/4096/4097: the TOO_FAR cut-off */
        unsigned long d = 4095 + rng_below(3), p = 100 + rng_below(2000);
        n = p + d + 40 + rng_below(2000);
        for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
        memcpy(b + p + d, b + p, 3);
        return n;
    }
    case 8: { /* noise with strings of 3 and 20 bytes repeated at MAX_DIST-1 / MAX_DIST / MAX_DIST+1 for this window */
        unsigned long md = (1ul << wbits) - 262, d = md - 1 + rng_below(3), p = 100 + rng_below(500);
        unsigned long l = rng_below(2) ? 3 : 20;
        n = p + d + l + 20 + rng_below(500);
        if (n > PLAIN_CAP) n = PLAIN_CAP;
        for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
        if (p + d + l <= n) memcpy(b + p + d, b + p, l);
        return n;
    }
    default:
        return 0;
    }
}

/* --- driving deflate() --------------------------------------------------- */

struct totals { unsigned long total_in, total_out, adler; int data_type; unsigned long trace; };

/* Run one compression under `arm`, feeding `src` in `nflush` chunks, calling deflate() with flushes[i] after each chunk
 * (the last must be Z_FINISH). avail_out is `outchunk` bytes at a time (0 = the whole buffer at once), so the
 * "output full, call me again" returns are taken when it is small. hdr: zlib header and Adler-32 (positive windowBits)
 * or raw (negative). */
static long run_arm(const struct arm *arm, const unsigned char *src, unsigned long srclen,
                     int level, int wbits, int hdr, int memlevel, int strategy,
                     const int *flushes, int nflush, unsigned outchunk,
                     unsigned char *out, unsigned long outcap, int *rc_out, struct totals *tot)
{
    z_stream s;
    int rc = Z_OK;
    unsigned long consumed = 0, opos = 0;
    unsigned long chunk = nflush > 0 ? srclen / nflush : srclen;
    int wssize;
    int i;

    memset(&s, 0, sizeof(s));
    memset(tot, 0, sizeof(*tot));
    wssize = arm->wssize(wbits, memlevel);
    s.workspace = malloc((size_t)wssize);
    if (!s.workspace) { *rc_out = Z_MEM_ERROR; return -1; }

    rc = arm->init2(&s, level, Z_DEFLATED, hdr ? wbits : -wbits, memlevel, strategy);
    if (rc != Z_OK) { free(s.workspace); *rc_out = rc; return -1; }

    s.next_out = out;
    s.avail_out = (unsigned)(outchunk && outchunk < outcap ? outchunk : outcap);
    opos = s.avail_out;

    for (i = 0; i < nflush; i++) {
        unsigned long this_chunk = (i == nflush - 1) ? (srclen - consumed) : chunk;
        int flush = flushes[i];

        s.next_in = (unsigned char *)src + consumed;
        s.avail_in = (unsigned)this_chunk;
        consumed += this_chunk;

        for (int guard = 0;; guard += (s.avail_in == 0)) {
            /* With avail_out filled exactly by a flush marker zlib emits another empty block on the next call, so a
             * tiny output chunk can chase its tail. Give up on this flush after 2000 calls; both arms do the same. */
            if (guard > 2000 && flush != Z_FINISH)
                break;
            if (s.avail_out == 0) {
                unsigned long k = outchunk ? outchunk : outcap;
                if (k > outcap - opos) k = outcap - opos;
                if (k == 0) { arm->end(&s); free(s.workspace); *rc_out = Z_BUF_ERROR; return -1; }
                s.next_out = out + opos;
                s.avail_out = (unsigned)k;
                opos += k;
            }
            rc = arm->deflate(&s, flush);
            /* every call's return code and remaining counts feed a running hash: the arms must agree call by call */
            tot->trace = tot->trace * 1000003ul + (unsigned long)(rc + 10) * 7 + (unsigned long)s.avail_in * 13 + (unsigned long)s.avail_out * 17;
            if (rc == Z_STREAM_END)
                break;
            if (rc == Z_BUF_ERROR && s.avail_out == 0)
                continue;
            if (rc == Z_BUF_ERROR && s.avail_in == 0 && flush != Z_FINISH)
                break;
            if (rc != Z_OK) {
                if (getenv("DEFLATE_VERBOSE"))
                    printf("  driver stop: arm=%s rc=%d flush=%d (chunk %d of %d) avail_in=%lu avail_out=%lu opos=%lu\n", arm->name, rc, flush, i, nflush, (unsigned long)s.avail_in, (unsigned long)s.avail_out, opos);
                arm->end(&s);
                free(s.workspace);
                *rc_out = rc;
                return -1;
            }
            if (flush != Z_FINISH && s.avail_in == 0 && s.avail_out != 0)
                break;
        }
    }

    tot->total_in = s.total_in; tot->total_out = s.total_out; tot->adler = s.adler; tot->data_type = s.data_type;
    rc = arm->end(&s);
    free(s.workspace);
    *rc_out = rc;
    return (long)(opos - s.avail_out);
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

static long g_rejected;

static int check_one(const unsigned char *src, unsigned long srclen,
                      int level, int wbits, int hdr, int memlevel, int strategy,
                      const int *flushes, int nflush, unsigned outchunk)
{
    int ref_rc = 0, rs_rc = 0;
    long ref_len, rs_len;
    struct totals rt, st;

    ref_len = run_arm(&REF, src, srclen, level, wbits, hdr, memlevel, strategy,
                       flushes, nflush, outchunk, g_ref_out, OUT_CAP, &ref_rc, &rt);
    rs_len = run_arm(&RS, src, srclen, level, wbits, hdr, memlevel, strategy,
                      flushes, nflush, outchunk, g_rs_out, OUT_CAP, &rs_rc, &st);

    if (ref_rc != rs_rc || ref_len != rs_len || memcmp(&rt, &st, sizeof(rt)) != 0 ||
        (ref_len >= 0 && memcmp(g_ref_out, g_rs_out, (size_t)ref_len) != 0)) {
        printf("MISMATCH level=%d wbits=%d hdr=%d memlevel=%d strategy=%d nflush=%d outchunk=%u srclen=%lu\n"
               "  ref: rc=%d len=%ld in/out/adler/type=%lu/%lu/%lx/%d\n  rs:  rc=%d len=%ld in/out/adler/type=%lu/%lu/%lx/%d\n",
               level, wbits, hdr, memlevel, strategy, nflush, outchunk, srclen,
               ref_rc, ref_len, rt.total_in, rt.total_out, rt.adler, rt.data_type,
               rs_rc, rs_len, st.total_in, st.total_out, st.adler, st.data_type);
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

    if (ref_len < 0) {
        g_rejected++;   /* both arms failed identically -- counted and reported, never silent */
        if (getenv("DEFLATE_VERBOSE"))
            printf("  rejected: rc=%d level=%d wbits=%d hdr=%d memlevel=%d strategy=%d nflush=%d outchunk=%u srclen=%lu\n", ref_rc, level, wbits, hdr, memlevel, strategy, nflush, outchunk, srclen);
        return 0;
    }

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
        long got = sys_inflate_raw(g_ref_out, (unsigned long)ref_len, wbits, hdr,
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

    if (abi_check2())
        return 1;
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
        int wbits = 9 + (int)rng_below(7);        /* 9..15 */
        unsigned long srclen = gen(kind, g_src, wbits);
        int level = (int)rng_below(10);          /* 0..9 */
        int hdr = (int)rng_below(2);              /* zlib header + Adler-32, or raw */
        unsigned outchunk = rng_below(2) ? 0 : 1 + rng_below(300);
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

        if (check_one(g_src, srclen, level, wbits, hdr, memlevel, strategy, flushes, nflush, outchunk))
            fails++;
        if (fails > 20) {
            printf("too many failures, stopping early\n");
            break;
        }
    }

    printf("deflate differential: %ld runs, %d failed (%ld rejected identically by both arms)\n", runs, fails, g_rejected);
    return fails ? 1 : 0;
}
