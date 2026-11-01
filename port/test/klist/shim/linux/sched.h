#ifndef SH_SCHED_H
#define SH_SCHED_H
#include <semaphore.h>
#include <stdbool.h>
#include <assert.h>
struct task_struct { sem_t wake; };
extern __thread struct task_struct *current;
extern int warn_count;
static inline void wake_up_process(struct task_struct *t) { sem_post(&t->wake); }
static inline void schedule(void) { sem_wait(&current->wake); }
#define set_current_state(x) __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define __set_current_state(x) do { } while (0)
#define TASK_UNINTERRUPTIBLE 2
#define TASK_RUNNING 0
#define mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define WARN_ON(c) ({ int __r = !!(c); if (__r) warn_count++; __r; })
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
