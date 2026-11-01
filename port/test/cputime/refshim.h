/* Stand-ins for what the pristine slice of kernel/sched/cputime.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define unlikely(x) __builtin_expect(!!(x), 0)
struct task_cputime { u64 stime; u64 utime; unsigned long long sum_exec_runtime; };
struct prev_cputime { u64 utime; u64 stime; int lock; };
#define raw_spin_lock_irqsave(l, f) do { (void)(f); (*(l))++; } while (0)
#define raw_spin_unlock_irqrestore(l, f) do { (void)(f); (*(l))--; } while (0)
static inline u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c) { return (u64)(((unsigned __int128)a * b) / c); }
void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev, u64 *ut, u64 *st);
#endif
