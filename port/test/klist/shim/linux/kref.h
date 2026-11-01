#ifndef SH_KREF_H
#define SH_KREF_H
#include <stdbool.h>
typedef struct { int refs; } refcount_t;
struct kref { refcount_t refcount; };
extern int warn_count;
static inline void kref_init(struct kref *k) { k->refcount.refs = 1; }
static inline void kref_get(struct kref *k) { if (__atomic_fetch_add(&k->refcount.refs, 1, __ATOMIC_SEQ_CST) <= 0) warn_count += 1000; }
static inline bool kref_get_unless_zero(struct kref *k) { int o = __atomic_load_n(&k->refcount.refs, __ATOMIC_SEQ_CST); while (o) if (__atomic_compare_exchange_n(&k->refcount.refs, &o, o + 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) return true; return false; }
static inline bool refcount_dec_and_test(refcount_t *r) { int o = __atomic_sub_fetch(&r->refs, 1, __ATOMIC_SEQ_CST); if (o < 0) warn_count += 1000; return o == 0; }
static inline int kref_put(struct kref *k, void (*release)(struct kref *)) { if (refcount_dec_and_test(&k->refcount)) { release(k); return 1; } return 0; }
#endif
