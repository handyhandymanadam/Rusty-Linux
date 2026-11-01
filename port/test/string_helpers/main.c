/* Differential test for lib/string_helpers.c -> string_helpers_rs.rs.
 *
 * Covers the 16 of 19 EXPORT_SYMBOLs that don't need struct device/file/
 * task_struct simulated: string_get_size, parse_int_array[_user],
 * string_unescape, string_escape_mem, kstrdup_quotable,
 * kstrdup_and_replace, kasprintf_strarray, kfree_strarray, skip_spaces,
 * strim, sysfs_streq, match_string, __sysfs_match_string, strreplace,
 * memcpy_and_pad. kstrdup_quotable_cmdline/_file/devm_kasprintf_strarray
 * are thin glue around get_cmdline()/file_path()/devres_* (untouched
 * kernel subsystems, not this port's own logic) and are left to the gate
 * suite's structural checks (crc-check, kabi-contract-check, boot).
 *
 * Both arms are the pristine lib/string_helpers.c, with every real global
 * renamed to `ref_*`; the RS arm calls the real Rust through `rs_*`
 * wrappers (probe.rs). Neither renames get_options() (lib/cmdline_rs.rs,
 * already Rust and already verified elsewhere) or the allocator/hex/ctype
 * helpers (alloc_shim.c, pristine hexdump.c/ctype.c) -- those are shared,
 * neutral dependencies, not what is under test here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned int gfp_t;

/* --- REF arm ------------------------------------------------------------ */
extern int ref_string_get_size(uint64_t size, uint64_t blk_size, unsigned int units, char *buf, int len);
extern int ref_parse_int_array(const char *buf, size_t count, int **array);
extern int ref_parse_int_array_user(const char *from, size_t count, int **array);
extern int ref_string_unescape(char *src, char *dst, size_t size, unsigned int flags);
extern int ref_string_escape_mem(const char *src, size_t isz, char *dst, size_t osz, unsigned int flags, const char *only);
extern char *ref_kstrdup_quotable(const char *src, gfp_t gfp);
extern char *ref_kstrdup_and_replace(const char *src, char old, char new, gfp_t gfp);
extern char **ref_kasprintf_strarray(gfp_t gfp, const char *prefix, size_t n);
extern void ref_kfree_strarray(char **array, size_t n);
extern char *ref_skip_spaces(const char *str);
extern char *ref_strim(char *s);
extern int ref_sysfs_streq(const char *s1, const char *s2);
extern int ref_match_string(const char *const *array, size_t n, const char *string);
extern int ref___sysfs_match_string(const char *const *array, size_t n, const char *str);
extern char *ref_strreplace(char *str, char old, char new);
extern void ref_memcpy_and_pad(void *dest, size_t dest_len, const void *src, size_t count, int pad);

/* --- RS arm (probe.rs) --------------------------------------------------- */
extern int rs_string_get_size(uint64_t size, uint64_t blk_size, unsigned int units, char *buf, int len);
extern int rs_parse_int_array(const char *buf, size_t count, int **array);
extern int rs_parse_int_array_user(const char *from, size_t count, int **array);
extern int rs_string_unescape(char *src, char *dst, size_t size, unsigned int flags);
extern int rs_string_escape_mem(const char *src, size_t isz, char *dst, size_t osz, unsigned int flags, const char *only);
extern char *rs_kstrdup_quotable(const char *src, gfp_t gfp);
extern char *rs_kstrdup_and_replace(const char *src, char old, char new, gfp_t gfp);
extern char **rs_kasprintf_strarray(gfp_t gfp, const char *prefix, size_t n);
extern void rs_kfree_strarray(char **array, size_t n);
extern char *rs_skip_spaces(const char *str);
extern char *rs_strim(char *s);
extern int rs_sysfs_streq(const char *s1, const char *s2);
extern int rs_match_string(const char *const *array, size_t n, const char *string);
extern int rs___sysfs_match_string(const char *const *array, size_t n, const char *str);
extern char *rs_strreplace(char *str, char old, char new);
extern void rs_memcpy_and_pad(void *dest, size_t dest_len, const void *src, size_t count, int pad);

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

static int fails = 0;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ---- string_get_size ---------------------------------------------------- */
static void test_string_get_size(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        uint64_t size = rng_u64() % (rng_below(2) ? (1ull << 40) : (1ull << 63));
        uint64_t blk = 1 + (rng_u64() % 4096);
        unsigned units = (rng_below(2) ? 1u : 0u)
                       | (rng_below(2) ? (1u << 30) : 0)
                       | (rng_below(2) ? (1u << 31) : 0);
        char rbuf[64], sbuf[64];
        int rret, sret;
        rret = ref_string_get_size(size, blk, units, rbuf, sizeof(rbuf));
        sret = rs_string_get_size(size, blk, units, sbuf, sizeof(sbuf));
        CHECK(rret == sret && strcmp(rbuf, sbuf) == 0,
              "string_get_size size=%llu blk=%llu units=%u ref=[%d,%s] rs=[%d,%s]",
              (unsigned long long)size, (unsigned long long)blk, units, rret, rbuf, sret, sbuf);
    }
}

/* ---- parse_int_array[_user] ---------------------------------------------- */
static void test_parse_int_array(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char buf[256];
        int k, m = rng_below(10);
        size_t len = 0;
        for (k = 0; k < m; k++) {
            len += (size_t)snprintf(buf + len, sizeof(buf) - len, "%s%d",
                                     k ? "," : "", (int)(rng_u64() % 20000) - 10000);
        }
        int *ra = NULL, *sa = NULL;
        int rrc = ref_parse_int_array(buf, len, &ra);
        int src = rs_parse_int_array(buf, len, &sa);
        int ok = (rrc == src);
        if (ok && rrc == 0) {
            int cnt = ra[0];
            ok = (cnt == sa[0]);
            for (k = 0; ok && k <= cnt; k++)
                if (ra[k] != sa[k]) ok = 0;
        }
        CHECK(ok, "parse_int_array buf=[%s] ref_rc=%d rs_rc=%d", buf, rrc, src);
        free(ra);
        free(sa);

        int *ua = NULL, *ub = NULL;
        int urc = ref_parse_int_array_user(buf, len, &ua);
        int vrc = rs_parse_int_array_user(buf, len, &ub);
        int uok = (urc == vrc);
        if (uok && urc == 0) {
            int cnt = ua[0];
            uok = (cnt == ub[0]);
            for (k = 0; uok && k <= cnt; k++)
                if (ua[k] != ub[k]) uok = 0;
        }
        CHECK(uok, "parse_int_array_user buf=[%s] ref_rc=%d rs_rc=%d", buf, urc, vrc);
        free(ua);
        free(ub);
    }
}

/* ---- string_unescape ------------------------------------------------------ */
static void gen_escaped(char *b, size_t cap)
{
    static const char *frags[] = {
        "\\n", "\\r", "\\t", "\\v", "\\f", "\\\\", "\\\"", "\\a", "\\e",
        "\\0", "\\7", "\\17", "\\177", "\\x1", "\\x2f", "plain", " ",
    };
    size_t n = 0;
    int reps = 1 + rng_below(20);
    while (reps-- && n + 8 < cap) {
        const char *f = frags[rng_below((unsigned)(sizeof(frags) / sizeof(frags[0])))];
        size_t l = strlen(f);
        memcpy(b + n, f, l);
        n += l;
    }
    b[n] = '\0';
}

static void test_string_unescape(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char src[128];
        gen_escaped(src, sizeof(src));
        unsigned int flags = rng_below(16);
        char rdst[128], sdst[128];
        strcpy(rdst, src);
        strcpy(sdst, src);
        int rret = ref_string_unescape(rdst, rdst, 0, flags);
        int sret = rs_string_unescape(sdst, sdst, 0, flags);
        CHECK(rret == sret && memcmp(rdst, sdst, (size_t)(rret > 0 ? rret + 1 : 1)) == 0,
              "string_unescape src=[%s] flags=%u ref=[%d,%s] rs=[%d,%s]", src, flags, rret, rdst, sret, sdst);
    }
}

/* ---- string_escape_mem ---------------------------------------------------- */
static void test_string_escape_mem(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned char src[64];
        size_t isz = rng_below(64);
        size_t k;
        for (k = 0; k < isz; k++) src[k] = (unsigned char)rng_u64();
        unsigned int flags = rng_below(512);
        const char *only = rng_below(2) ? "\n\t \\\"" : NULL;
        char rdst[512], sdst[512];
        size_t osz = 16 + rng_below(500);
        if (osz > sizeof(rdst)) osz = sizeof(rdst);
        int rret = ref_string_escape_mem((const char *)src, isz, rdst, osz, flags, only);
        int sret = rs_string_escape_mem((const char *)src, isz, sdst, osz, flags, only);
        size_t cmp = (size_t)rret < osz ? (size_t)rret : osz;
        CHECK(rret == sret && memcmp(rdst, sdst, cmp) == 0,
              "string_escape_mem isz=%zu flags=%u only=%s ref=%d rs=%d", isz, flags, only ? only : "(null)", rret, sret);
    }
}

/* ---- kstrdup_quotable / kstrdup_and_replace -------------------------------- */
static void test_kstrdup(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char src[64];
        gen_escaped(src, sizeof(src));
        char *r = ref_kstrdup_quotable(src, 0);
        char *s = rs_kstrdup_quotable(src, 0);
        CHECK((r == NULL) == (s == NULL) && (r == NULL || strcmp(r, s) == 0),
              "kstrdup_quotable src=[%s] ref=[%s] rs=[%s]", src, r ? r : "(null)", s ? s : "(null)");
        free(r);
        free(s);

        char old = (char)(32 + rng_below(95)), new = (char)(32 + rng_below(95));
        char *r2 = ref_kstrdup_and_replace(src, old, new, 0);
        char *s2 = rs_kstrdup_and_replace(src, old, new, 0);
        CHECK(strcmp(r2, s2) == 0, "kstrdup_and_replace src=[%s] ref=[%s] rs=[%s]", src, r2, s2);
        free(r2);
        free(s2);
    }
}

/* ---- kasprintf_strarray / kfree_strarray ------------------------------------ */
static void test_strarray(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        size_t k, cnt = rng_below(6);
        char **r = ref_kasprintf_strarray(0, "pfx", cnt);
        char **s = rs_kasprintf_strarray(0, "pfx", cnt);
        int ok = (r != NULL) && (s != NULL);
        for (k = 0; ok && k < cnt; k++)
            if (strcmp(r[k], s[k]) != 0) ok = 0;
        CHECK(ok, "kasprintf_strarray n=%zu", cnt);
        ref_kfree_strarray(r, cnt);
        rs_kfree_strarray(s, cnt);
    }
}

/* ---- skip_spaces / strim ---------------------------------------------------- */
static void test_trim(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char base[32];
        int m = rng_below(20);
        int k;
        for (k = 0; k < m; k++) base[k] = "ab \t\n"[rng_below(5)];
        base[m] = '\0';

        char *r1 = ref_skip_spaces(base);
        char *s1 = rs_skip_spaces(base);
        CHECK(strcmp(r1, s1) == 0, "skip_spaces base=[%s]", base);

        char rbuf[32], sbuf[32];
        strcpy(rbuf, base);
        strcpy(sbuf, base);
        char *r2 = ref_strim(rbuf);
        char *s2 = rs_strim(sbuf);
        CHECK(strcmp(r2, s2) == 0 && strcmp(rbuf, sbuf) == 0, "strim base=[%s] ref=[%s] rs=[%s]", base, r2, s2);
    }
}

/* ---- sysfs_streq ------------------------------------------------------------- */
static void test_sysfs_streq(int n)
{
    int i;
    static const char *pool[] = { "abc", "abc\n", "abc\n\n", "", "\n", "a", "ab", "abd" };
    for (i = 0; i < n; i++) {
        const char *a = pool[rng_below((unsigned)(sizeof(pool) / sizeof(pool[0])))];
        const char *b = pool[rng_below((unsigned)(sizeof(pool) / sizeof(pool[0])))];
        int r = ref_sysfs_streq(a, b);
        int s = rs_sysfs_streq(a, b);
        CHECK((!!r) == (!!s), "sysfs_streq a=[%s] b=[%s] ref=%d rs=%d", a, b, r, s);
    }
}

/* ---- match_string / __sysfs_match_string ------------------------------------- */
static void test_match_string(int n)
{
    int i;
    static const char *const arr[] = { "foo", "bar", "baz\n", NULL, "qux" };
    for (i = 0; i < n; i++) {
        size_t cnt = 1 + rng_below(4);
        /* never index 3 (NULL): strcmp(item, NULL) is UB in the real
         * match_string too, no real caller passes it. */
        static const int idx[] = { 0, 1, 2, 4 };
        const char *needle = arr[idx[rng_below(4)]];
        int r1 = ref_match_string(arr, cnt, needle);
        int s1 = rs_match_string(arr, cnt, needle);
        CHECK(r1 == s1, "match_string cnt=%zu needle=%s ref=%d rs=%d", cnt, needle ? needle : "(null)", r1, s1);

        int r2 = ref___sysfs_match_string(arr, cnt, needle);
        int s2 = rs___sysfs_match_string(arr, cnt, needle);
        CHECK(r2 == s2, "__sysfs_match_string cnt=%zu needle=%s ref=%d rs=%d", cnt, needle ? needle : "(null)", r2, s2);
    }
}

/* ---- strreplace --------------------------------------------------------------- */
static void test_strreplace(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char base[32];
        int m = rng_below(20), k;
        for (k = 0; k < m; k++) base[k] = "abc"[rng_below(3)];
        base[m] = '\0';
        char rbuf[32], sbuf[32];
        strcpy(rbuf, base);
        strcpy(sbuf, base);
        char old = "abc"[rng_below(3)], new = 'X';
        ref_strreplace(rbuf, old, new);
        rs_strreplace(sbuf, old, new);
        CHECK(strcmp(rbuf, sbuf) == 0, "strreplace base=[%s] old=%c ref=[%s] rs=[%s]", base, old, rbuf, sbuf);
    }
}

/* ---- memcpy_and_pad ------------------------------------------------------------ */
static void test_memcpy_and_pad(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned char src[32];
        size_t k, count = rng_below(32);
        for (k = 0; k < count; k++) src[k] = (unsigned char)rng_u64();
        size_t dest_len = rng_below(40);
        unsigned char rdst[40], sdst[40];
        memset(rdst, 0xAA, sizeof(rdst));
        memset(sdst, 0xAA, sizeof(sdst));
        int pad = (int)(rng_u64() % 256);
        ref_memcpy_and_pad(rdst, dest_len, src, count, pad);
        rs_memcpy_and_pad(sdst, dest_len, src, count, pad);
        CHECK(memcmp(rdst, sdst, sizeof(rdst)) == 0, "memcpy_and_pad dest_len=%zu count=%zu pad=%d", dest_len, count, pad);
    }
}

int main(int argc, char **argv)
{
    long runs = argc > 1 ? atol(argv[1]) : 2000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 20260906ull;
    rng_seed(seed);

    test_string_get_size((int)runs);
    test_parse_int_array((int)runs);
    test_string_unescape((int)runs);
    test_string_escape_mem((int)runs);
    test_kstrdup((int)runs);
    test_strarray((int)runs);
    test_trim((int)runs);
    test_sysfs_streq((int)runs);
    test_match_string((int)runs);
    test_strreplace((int)runs);
    test_memcpy_and_pad((int)runs);

    printf("string_helpers differential: %ld runs/test, %d failed\n", runs, fails);
    return fails ? 1 : 0;
}
