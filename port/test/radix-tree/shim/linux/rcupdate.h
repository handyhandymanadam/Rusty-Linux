#ifndef SHR_RCUPDATE_H
#define SHR_RCUPDATE_H
#include <linux/types.h>
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define rcu_assign_pointer(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
#define RCU_INIT_POINTER(p, v) do { (p) = (v); } while (0)
#define rcu_dereference_raw(p) (*(volatile __typeof__(p) *)&(p))
#define rcu_dereference(p) rcu_dereference_raw(p)
#define rcu_dereference_check(p, c) ((void)(c), (p))
#define rcu_dereference_protected(p, c) ((void)(c), (p))
/* a grace period never elapses on its own here: call_rcu() queues, main.c's grace() runs the callbacks */
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head));
#endif
