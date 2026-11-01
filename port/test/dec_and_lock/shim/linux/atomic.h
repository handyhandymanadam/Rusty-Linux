#ifndef SH_ATOMIC_H
#define SH_ATOMIC_H
#include <assert.h>
#include <stdbool.h>
typedef struct { int counter; } atomic_t;
static inline int atomic_read(const atomic_t *v) { return __atomic_load_n(&v->counter, __ATOMIC_RELAXED); }
static inline bool atomic_add_unless(atomic_t *v, int a, int u)
{
	int c = atomic_read(v);
	do { if (c == u) return false; } while (!__atomic_compare_exchange_n(&v->counter, &c, c + a, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
	return true;
}
static inline bool atomic_dec_and_test(atomic_t *v) { return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST) == 0; }
#endif
