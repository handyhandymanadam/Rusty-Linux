/* The pristine crypto/lzo[-rle].c helpers, compiled as-is (extracted) over
 * userspace stand-ins. NAME is lzo or lzorle (-DNAME_LZO / -DNAME_LZORLE). */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8;
#define EINVAL 22
#define LZO_E_OK 0
int lzo1x_1_compress_safe(const unsigned char *, size_t, unsigned char *, size_t *, void *);
int lzorle1x_1_compress_safe(const unsigned char *, size_t, unsigned char *, size_t *, void *);
int lzo1x_decompress_safe(const unsigned char *, size_t, unsigned char *, size_t *);
#include "EXTRACT"
#ifdef NAME_LZO
int c_compress(const u8 *s, unsigned n, u8 *d, unsigned *dl, void *c) { return __lzo_compress(s, n, d, dl, c); }
int c_decompress(const u8 *s, unsigned n, u8 *d, unsigned *dl) { return __lzo_decompress(s, n, d, dl); }
#else
int c_compress(const u8 *s, unsigned n, u8 *d, unsigned *dl, void *c) { return __lzorle_compress(s, n, d, dl, c); }
int c_decompress(const u8 *s, unsigned n, u8 *d, unsigned *dl) { return __lzorle_decompress(s, n, d, dl); }
#endif
