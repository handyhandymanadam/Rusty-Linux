/* shim for the logic_pio differential: the real struct logic_pio_hwaddr plus just enough kernel (list, RCU, mutex, printk) for lib/logic_pio.c. The limits are variables so one binary runs both the
 * plain x86 limits and the CONFIG_INDIRECT_PIO ones. */
#ifndef SH_LOGIC_PIO_H
#define SH_LOGIC_PIO_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint8_t u8; typedef uint16_t u16;
typedef u64 resource_size_t;
#define SZ_64K 0x10000
extern u64 lim_io_space, lim_mmio_upper;
#define IO_SPACE_LIMIT lim_io_space
#define MMIO_UPPER_LIMIT lim_mmio_upper
struct fwnode_handle { int id; };
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
static inline void list_add_tail_rcu(struct list_head *n, struct list_head *h) { n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static inline void list_del_rcu(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; e->prev = NULL; /* like the kernel's: next stays so readers can finish */ }
#define list_next_rcu(p) (&(p)->next)
#define rcu_dereference_raw(p) (*(p))
extern long rcu_depth, sync_count, mutex_depth;
#define rcu_read_lock() (rcu_depth++)
#define rcu_read_unlock() (rcu_depth--)
#define synchronize_rcu() (sync_count++)
struct mutex { int locked; };
#define DEFINE_MUTEX(m) struct mutex m = { 0 }
#define mutex_lock(m) do { if ((m)->locked) abort(); (m)->locked = 1; mutex_depth++; } while (0)
#define mutex_unlock(m) do { (m)->locked = 0; mutex_depth--; } while (0)
void klog(const char *tag, const char *fmt, ...);
#define pr_err(fmt, ...) klog("pr_err", pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) klog("pr_warn", pr_fmt(fmt), ##__VA_ARGS__)
#define in_range(val, start, len) ((u64)(val) - (u64)(start) < (u64)(len))
#define list_for_each_entry(pos, head, member) \
	for (pos = (void *)(head)->next; &pos->member != (head); pos = (void *)pos->member.next)
#define list_for_each_entry_rcu(pos, head, member) list_for_each_entry(pos, head, member)

enum { LOGIC_PIO_INDIRECT, LOGIC_PIO_CPU_MMIO };
struct logic_pio_hwaddr {
	struct list_head list;
	const struct fwnode_handle *fwnode;
	resource_size_t hw_start;
	resource_size_t io_start;
	resource_size_t size;
	unsigned long flags;
	void *hostdata;
	const struct logic_pio_host_ops *ops;
};
struct logic_pio_host_ops { int unused; };
int logic_pio_register_range(struct logic_pio_hwaddr *new_range);
void logic_pio_unregister_range(struct logic_pio_hwaddr *range);
struct logic_pio_hwaddr *find_io_range_by_fwnode(const struct fwnode_handle *fwnode);
resource_size_t logic_pio_to_hwaddr(unsigned long pio);
unsigned long logic_pio_trans_hwaddr(const struct fwnode_handle *fwnode, resource_size_t addr, resource_size_t size);
unsigned long logic_pio_trans_cpuaddr(resource_size_t addr);
#endif
