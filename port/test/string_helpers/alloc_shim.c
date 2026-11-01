/* SPDX-License-Identifier: GPL-2.0
 *
 * Userspace stand-ins for the kernel allocator/subsystem calls both arms
 * need. Shared, unrenamed: this is scaffolding around the port, not the
 * port itself -- same role port/test/zlib_inflate/corpus.c and
 * port/test/deftree/sysinflate.c play for their own harnesses.
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

typedef unsigned int gfp_t;

const char hex_asc[] = "0123456789abcdef";
int hex_to_bin(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    ch |= 0x20;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

/* The pristine C's own names (its shim headers declare these unprefixed). */
void *kmalloc(size_t size, gfp_t gfp) { (void)gfp; return malloc(size); }
void *kcalloc(size_t n, size_t size, gfp_t gfp) { (void)gfp; return calloc(n, size); }
void kfree(const void *objp) { free((void *)objp); }
char *kstrdup(const char *s, gfp_t gfp)
{
    (void)gfp;
    if (!s)
        return NULL;
    return strdup(s);
}
char *kasprintf(gfp_t gfp, const char *fmt, ...)
{
    va_list ap;
    char *out;
    int n;
    (void)gfp;
    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        return NULL;
    out = malloc((size_t)n + 1);
    if (!out)
        return NULL;
    va_start(ap, fmt);
    vsnprintf(out, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return out;
}
char *memdup_user_nul(const char *src, size_t len)
{
    char *dst = malloc(len + 1);
    if (!dst)
        return (char *)(long)-12; /* -ENOMEM */
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}
char *file_path(void *filp, char *buf, int buflen)
{
    (void)filp; (void)buf; (void)buflen;
    return (char *)(long)-36; /* -ENAMETOOLONG, unused by this harness */
}
int get_cmdline(void *task, char *buffer, int buflen)
{
    (void)task; (void)buffer; (void)buflen;
    return 0; /* unused by this harness */
}
void *__devres_alloc_node(void (*release)(void *, void *), size_t size, gfp_t gfp, int nid)
{
    (void)release; (void)gfp; (void)nid;
    return malloc(size);
}
void devres_add(void *dev, void *res) { (void)dev; (void)res; }
void devres_free(void *res) { free(res); }

/* The RS arm's own thunk names (string_helpers_rs.rs's extern block). */
void *string_helpers_kmalloc(size_t size, gfp_t gfp) { return kmalloc(size, gfp); }
void *string_helpers_kcalloc(size_t n, size_t size, gfp_t gfp) { return kcalloc(n, size, gfp); }

/* lib/cmdline_rs.rs's own two vsprintf.c externs -- close userspace
 * equivalents, not the real simple_strtoull/simple_strtol (those stay C,
 * unported, per that file's own module doc). Good enough for driving
 * get_options() with the plain-decimal inputs this harness generates. */
#include <stdint.h>
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
    return strtoull(cp, endp, base);
}
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
    return strtol(cp, endp, base);
}
