/* Decompression side of the differential's roundtrip check.
 *
 * SEPARATE TRANSLATION UNIT ON PURPOSE, same reason as corpus.c in
 * ../zlib_inflate/: this is the only file that sees the SYSTEM <zlib.h>;
 * everything else sees the kernel's <linux/zlib.h> through the shim, and the
 * two define an incompatible `z_stream`.
 *
 * Nothing here is under test. Both harness arms (ref and rs) run the SAME
 * pristine deflate.c, so a byte-for-byte match between them is the real
 * proof the port is correct; this only adds a fully independent check that
 * what they agree on is actually a valid RFC 1951 stream that inflates back
 * to the input, using an implementation neither arm shares a line with.
 */
#include <zlib.h>
#include <string.h>

/* Raw-inflate (no zlib/gzip header) `src` into `dst`. Returns the
 * decompressed length, or -1. `window_bits` must be the positive magnitude
 * used on the deflate side. */
long sys_inflate_raw(const unsigned char *src, unsigned long n,
                      int window_bits, unsigned char *dst, unsigned long dcap)
{
    z_stream s;
    int rc;

    memset(&s, 0, sizeof(s));
    rc = inflateInit2(&s, -window_bits);
    if (rc != Z_OK)
        return -1;

    s.next_in = (unsigned char *)src;
    s.avail_in = (unsigned)n;
    s.next_out = dst;
    s.avail_out = (unsigned)dcap;

    rc = inflate(&s, Z_FINISH);
    if (rc != Z_STREAM_END) {
        inflateEnd(&s);
        return -1;
    }
    n = s.total_out;
    inflateEnd(&s);
    return (long)n;
}
