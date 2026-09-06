#ifndef WORKQUEUE_H
#define WORKQUEUE_H
struct work_struct { char _opaque[32]; };
static inline void schedule_work(struct work_struct *work) { (void)work; }
#endif
