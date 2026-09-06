#pragma once
/* Single-threaded userspace harness: no other thread ever touches these
 * memory locations concurrently, so a plain load/store/CAS is sufficient
 * to compare the two ports' LOGIC. It does not, and cannot, exercise the
 * concurrent-race paths -- see run.sh's own note on scope. */
#define READ_ONCE(x) (x)

#define cmpxchg_release(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)

#define xchg(ptr, new) __atomic_exchange_n(ptr, new, __ATOMIC_SEQ_CST)

#define swap(a, b) do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
