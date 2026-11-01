/* Stand-ins for what the pristine slice of kernel/ucount.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
typedef uint32_t u32; typedef unsigned long long u64;
#define NUC 3
#define NRL 2
enum ucount_type { UCOUNT_A, UCOUNT_B, UCOUNT_C };
enum rlimit_type { UCOUNT_RLIMIT_NPROC, UCOUNT_RLIMIT_MSGQUEUE };
typedef struct { long counter; } atomic_long_t;
typedef struct { u32 val; } kuid_t;
struct user_namespace;
struct ucounts { void *node[2]; struct user_namespace *ns; kuid_t uid; int refs; atomic_long_t ucount[NUC]; atomic_long_t rlimit[NRL]; };
struct user_namespace { struct ucounts *ucounts; long ucount_max[NUC]; long rlimit_max[NRL]; };
#define LONG_MAX_ LONG_MAX
#define unlikely(x) __builtin_expect(!!(x), 0)
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
extern int warns;
#define WARN_ON_ONCE(c) ({ int w_ = !!(c); if (w_) warns++; w_; })
static inline long atomic_long_read(const atomic_long_t *v) { return __atomic_load_n(&v->counter, __ATOMIC_RELAXED); }
static inline bool atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new) { return __atomic_compare_exchange_n(&v->counter, old, new, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED); }
static inline void atomic_long_dec(atomic_long_t *v) { __atomic_fetch_sub(&v->counter, 1, __ATOMIC_RELAXED); }
static inline long atomic_long_add_return(long i, atomic_long_t *v) { return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST); }
static inline long atomic_long_sub_return(long i, atomic_long_t *v) { return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST); }
static inline long atomic_long_dec_if_positive(atomic_long_t *v) { long c = atomic_long_read(v); for (;;) { long dec = c - 1; if (dec < 0) return dec; if (atomic_long_try_cmpxchg(v, &c, dec)) return dec; } }
static inline long get_rlimit_value(struct ucounts *u, enum rlimit_type t) { return atomic_long_read(&u->rlimit[t]); }
static inline long get_userns_rlimit_max(struct user_namespace *ns, enum rlimit_type t) { return READ_ONCE(ns->rlimit_max[t]); }
struct ucounts *alloc_ucounts(struct user_namespace *ns, kuid_t uid);
void put_ucounts(struct ucounts *u);
struct ucounts *get_ucounts(struct ucounts *u);
#endif
