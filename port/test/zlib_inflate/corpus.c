/* Compression side of the differential corpus.
 *
 * SEPARATE TRANSLATION UNIT ON PURPOSE. This is the only file that sees the
 * SYSTEM <zlib.h>; everything else sees the kernel's <linux/zlib.h> through
 * the shim, and the two define an incompatible `z_stream`. Keeping them in
 * different objects is cheaper than fighting the clash.
 *
 * Nothing here is under test. The kernel decoder is; this only produces
 * streams for it to eat.
 */
#include <zlib.h>
#include <string.h>

/* Deflate `src` into `dst`. Returns the compressed length, or -1. */
long corpus_compress(const unsigned char *src, unsigned long n,
                     int level, int window_bits, int mem_level, int strategy,
                     unsigned char *dst, unsigned long dcap)
{
    z_stream s;
    int rc;

    memset(&s, 0, sizeof(s));
    rc = deflateInit2(&s, level, Z_DEFLATED, window_bits, mem_level, strategy);
    if (rc != Z_OK)
        return -1;

    s.next_in = (unsigned char *)src;
    s.avail_in = (unsigned)n;
    s.next_out = dst;
    s.avail_out = (unsigned)dcap;

    rc = deflate(&s, Z_FINISH);
    if (rc != Z_STREAM_END) {
        deflateEnd(&s);
        return -1;
    }
    n = s.total_out;
    deflateEnd(&s);
    return (long)n;
}
