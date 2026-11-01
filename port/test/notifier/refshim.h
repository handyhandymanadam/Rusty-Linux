/* Stand-ins for what the pristine slice of kernel/notifier.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#define EEXIST 17
#define EBUSY 16
#define ENOENT 2
#define NOTIFY_DONE 0x0000
#define NOTIFY_STOP_MASK 0x8000
#define unlikely(x) __builtin_expect(!!(x), 0)
struct notifier_block;
typedef int (*notifier_fn_t)(struct notifier_block *nb, unsigned long action, void *data);
struct notifier_block { notifier_fn_t notifier_call; struct notifier_block *next; int priority; };
extern int warns, traces_reg, traces_unreg, traces_run;
#define WARN(c, ...) ({ warns++; (c); })
#define rcu_assign_pointer(p, v) (__atomic_store_n(&(p), (v), __ATOMIC_RELEASE))
#define rcu_dereference_raw(p) (__atomic_load_n(&(p), __ATOMIC_RELAXED))
#define trace_notifier_register(f) (traces_reg++)
#define trace_notifier_unregister(f) (traces_unreg++)
#define trace_notifier_run(f) (traces_run++)
#define NOKPROBE_SYMBOL(x)
#define CONFIG_DEBUG_NOTIFIERS 1
int t_is_text(notifier_fn_t f);
#define func_ptr_is_kernel_text(f) t_is_text(f)
#endif
