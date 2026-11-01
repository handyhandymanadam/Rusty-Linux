/* Stand-ins for what the pristine security/selinux/ss/mls.c, context.h and the glue wrappers use (the mls translation unit; ebitmap, hashtab and symtab have their own shims). */
#ifndef MLS_REFSHIM_H
#define MLS_REFSHIM_H
#include "../ebitmap/refshim.h"
#define EEXIST 17
#define cond_resched() do { } while (0)
#define CONFIG_NETLABEL_UNUSED 0
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
typedef int gfp_t_unused;
extern long live_strs;
static inline char *kstrdup(const char *s, gfp_t g) { char *p = strdup(s); live_strs++; return p; }
static inline void kfree(void *p) { if (p) { live_strs--; free(p); } }
static inline void *kmemdup(const void *src, size_t sz, gfp_t g) { void *p = malloc(sz ? sz : 1); memcpy(p, src, sz); return p; }
#endif
