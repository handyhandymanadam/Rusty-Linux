#pragma once
/* Single-threaded differential -- no real concurrency, so plain
 * (non-LOCK-prefixed) operations reproduce the same observable semantics
 * as the kernel's atomic_t API. Real ordering (relaxed vs fully-ordered)
 * only matters under concurrency, which this harness has none of. */
typedef struct {
	int counter;
} atomic_t;

#define ATOMIC_INIT(i) { (i) }

static inline int atomic_read(const atomic_t *v) { return v->counter; }
static inline void atomic_set(atomic_t *v, int i) { v->counter = i; }
static inline void atomic_inc(atomic_t *v) { v->counter++; }
static inline int atomic_dec_return(atomic_t *v) { return --v->counter; }
static inline int atomic_xchg_relaxed(atomic_t *v, int new)
{
	int old = v->counter;
	v->counter = new;
	return old;
}
