// SPDX-License-Identifier: GPL-2.0+
/*
 * RUST PORT (lib/logic_pio.c, 6.18.49): the range registry and the address translations are in logic_pio_rs.rs. This file keeps the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition), the BUILD_LOGIC_IO accessors (CONFIG_INDIRECT_PIO with a PCI_IOBASE only) and one-line wrappers for the mutex and
 * list head, the RCU list operations, the limits and the pr_err/pr_warn sites (the messages now name this file -- recorded divergence). Upstream's whole file is installed
 * as logic_pio_norust.c for CONFIG_RUST=n.
 */
/*
 * Copyright (C) 2017 HiSilicon Limited, All Rights Reserved.
 * Author: Gabriele Paoloni <gabriele.paoloni@huawei.com>
 * Author: Zhichang Yuan <yuanzhichang@hisilicon.com>
 * Author: John Garry <john.garry@huawei.com>
 */

#define pr_fmt(fmt)	"LOGIC PIO: " fmt

#include <linux/of.h>
#include <linux/io.h>
#include <linux/logic_pio.h>
#include <linux/mm.h>
#include <linux/rculist.h>
#include <linux/sizes.h>
#include <linux/slab.h>

/* The unique hardware address list */
static LIST_HEAD(io_range_list);
static DEFINE_MUTEX(io_range_mutex);

static_assert(sizeof(resource_size_t) == 8 && offsetof(struct logic_pio_hwaddr, list) == 0 && offsetof(struct logic_pio_hwaddr, fwnode) == 16 &&
	      offsetof(struct logic_pio_hwaddr, hw_start) == 24 && offsetof(struct logic_pio_hwaddr, io_start) == 32 && offsetof(struct logic_pio_hwaddr, size) == 40 &&
	      offsetof(struct logic_pio_hwaddr, flags) == 48 && offsetof(struct logic_pio_hwaddr, hostdata) == 56 && offsetof(struct logic_pio_hwaddr, ops) == 64 &&
	      LOGIC_PIO_INDIRECT == 0 && LOGIC_PIO_CPU_MMIO == 1);

int rust_logic_pio_register_range(struct logic_pio_hwaddr *new_range);
void rust_logic_pio_unregister_range(struct logic_pio_hwaddr *range);
struct logic_pio_hwaddr *rust_find_io_range_by_fwnode(const struct fwnode_handle *fwnode);
struct logic_pio_hwaddr *rust_find_io_range(unsigned long pio);
resource_size_t rust_logic_pio_to_hwaddr(unsigned long pio);
unsigned long rust_logic_pio_trans_hwaddr(const struct fwnode_handle *fwnode, resource_size_t addr, resource_size_t size);
unsigned long rust_logic_pio_trans_cpuaddr(resource_size_t addr);

void rust_lp_lock(void);
void rust_lp_unlock(void);
struct list_head *rust_lp_head(void);
struct list_head *rust_lp_next(struct list_head *p);
void rust_lp_add_tail_rcu(struct list_head *new);
void rust_lp_del_rcu(struct list_head *entry);
void rust_lp_synchronize_rcu(void);
void rust_lp_rcu_lock(void);
void rust_lp_rcu_unlock(void);
u64 rust_lp_mmio_upper_limit(void);
u64 rust_lp_io_space_limit(void);
void rust_lp_warn_too_big(void);
void rust_lp_err_token(unsigned long pio);
void rust_lp_err_trans_hw(void);
void rust_lp_err_size(u64 size, u64 range_size);
void rust_lp_err_cpuaddr(u64 addr);

void rust_lp_lock(void) { mutex_lock(&io_range_mutex); }
void rust_lp_unlock(void) { mutex_unlock(&io_range_mutex); }
struct list_head *rust_lp_head(void) { return &io_range_list; }
struct list_head *rust_lp_next(struct list_head *p) { return rcu_dereference_raw(list_next_rcu(p)); }
void rust_lp_add_tail_rcu(struct list_head *new) { list_add_tail_rcu(new, &io_range_list); }
void rust_lp_del_rcu(struct list_head *entry) { list_del_rcu(entry); }
void rust_lp_synchronize_rcu(void) { synchronize_rcu(); }
void rust_lp_rcu_lock(void) { rcu_read_lock(); }
void rust_lp_rcu_unlock(void) { rcu_read_unlock(); }
u64 rust_lp_mmio_upper_limit(void) { return MMIO_UPPER_LIMIT; }
u64 rust_lp_io_space_limit(void) { return IO_SPACE_LIMIT; }
void rust_lp_warn_too_big(void) { pr_warn("Requested IO range too big, new size set to 64K\n"); }
void rust_lp_err_token(unsigned long pio) { pr_err("PIO entry token 0x%lx invalid\n", pio); }
void rust_lp_err_trans_hw(void) { pr_err("IO range not found or invalid\n"); }
void rust_lp_err_size(u64 size, u64 range_size)
{
	resource_size_t s = size, r = range_size;

	pr_err("resource size %pa cannot fit in IO range size %pa\n", &s, &r);
}
void rust_lp_err_cpuaddr(u64 addr)
{
	resource_size_t a = addr;

	pr_err("addr %pa not registered in io_range_list\n", &a);
}

/**
 * logic_pio_register_range - register logical PIO range for a host
 * @new_range: pointer to the IO range to be registered.
 *
 * Returns 0 on success, the error code in case of failure.
 * If the range already exists, -EEXIST will be returned, which should be
 * considered a success.
 *
 * Register a new IO range node in the IO range list.
 */
int logic_pio_register_range(struct logic_pio_hwaddr *new_range)
{
	return rust_logic_pio_register_range(new_range);
}

/**
 * logic_pio_unregister_range - unregister a logical PIO range for a host
 * @range: pointer to the IO range which has been already registered.
 *
 * Unregister a previously-registered IO range node.
 */
void logic_pio_unregister_range(struct logic_pio_hwaddr *range)
{
	rust_logic_pio_unregister_range(range);
}

/**
 * find_io_range_by_fwnode - find logical PIO range for given FW node
 * @fwnode: FW node handle associated with logical PIO range
 *
 * Returns pointer to node on success, NULL otherwise.
 *
 * Traverse the io_range_list to find the registered node for @fwnode.
 */
struct logic_pio_hwaddr *find_io_range_by_fwnode(const struct fwnode_handle *fwnode)
{
	return rust_find_io_range_by_fwnode(fwnode);
}

/**
 * logic_pio_to_hwaddr - translate logical PIO to HW address
 * @pio: logical PIO value
 *
 * Returns HW address if valid, ~0 otherwise.
 *
 * Translate the input logical PIO to the corresponding hardware address.
 * The input PIO should be unique in the whole logical PIO space.
 */
resource_size_t logic_pio_to_hwaddr(unsigned long pio)
{
	return rust_logic_pio_to_hwaddr(pio);
}

/**
 * logic_pio_trans_hwaddr - translate HW address to logical PIO
 * @fwnode: FW node reference for the host
 * @addr: Host-relative HW address
 * @size: size to translate
 *
 * Returns Logical PIO value if successful, ~0UL otherwise
 */
unsigned long logic_pio_trans_hwaddr(const struct fwnode_handle *fwnode,
				     resource_size_t addr, resource_size_t size)
{
	return rust_logic_pio_trans_hwaddr(fwnode, addr, size);
}

unsigned long logic_pio_trans_cpuaddr(resource_size_t addr)
{
	return rust_logic_pio_trans_cpuaddr(addr);
}

#if defined(CONFIG_INDIRECT_PIO) && defined(PCI_IOBASE)
static struct logic_pio_hwaddr *find_io_range(unsigned long pio)
{
	return rust_find_io_range(pio);
}
#endif

#if defined(CONFIG_INDIRECT_PIO) && defined(PCI_IOBASE)
#define BUILD_LOGIC_IO(bwl, type)					\
type logic_in##bwl(unsigned long addr)					\
{									\
	type ret = (type)~0;						\
									\
	if (addr < MMIO_UPPER_LIMIT) {					\
		ret = _in##bwl(addr);					\
	} else if (addr >= MMIO_UPPER_LIMIT && addr < IO_SPACE_LIMIT) { \
		struct logic_pio_hwaddr *entry = find_io_range(addr);	\
									\
		if (entry)						\
			ret = entry->ops->in(entry->hostdata,		\
					addr, sizeof(type));		\
		else							\
			WARN_ON_ONCE(1);				\
	}								\
	return ret;							\
}									\
									\
void logic_out##bwl(type value, unsigned long addr)			\
{									\
	if (addr < MMIO_UPPER_LIMIT) {					\
		_out##bwl(value, addr);				\
	} else if (addr >= MMIO_UPPER_LIMIT && addr < IO_SPACE_LIMIT) {	\
		struct logic_pio_hwaddr *entry = find_io_range(addr);	\
									\
		if (entry)						\
			entry->ops->out(entry->hostdata,		\
					addr, value, sizeof(type));	\
		else							\
			WARN_ON_ONCE(1);				\
	}								\
}									\
									\
void logic_ins##bwl(unsigned long addr, void *buffer,			\
		    unsigned int count)					\
{									\
	if (addr < MMIO_UPPER_LIMIT) {					\
		reads##bwl(PCI_IOBASE + addr, buffer, count);		\
	} else if (addr >= MMIO_UPPER_LIMIT && addr < IO_SPACE_LIMIT) {	\
		struct logic_pio_hwaddr *entry = find_io_range(addr);	\
									\
		if (entry)						\
			entry->ops->ins(entry->hostdata,		\
				addr, buffer, sizeof(type), count);	\
		else							\
			WARN_ON_ONCE(1);				\
	}								\
									\
}									\
									\
void logic_outs##bwl(unsigned long addr, const void *buffer,		\
		     unsigned int count)				\
{									\
	if (addr < MMIO_UPPER_LIMIT) {					\
		writes##bwl(PCI_IOBASE + addr, buffer, count);		\
	} else if (addr >= MMIO_UPPER_LIMIT && addr < IO_SPACE_LIMIT) {	\
		struct logic_pio_hwaddr *entry = find_io_range(addr);	\
									\
		if (entry)						\
			entry->ops->outs(entry->hostdata,		\
				addr, buffer, sizeof(type), count);	\
		else							\
			WARN_ON_ONCE(1);				\
	}								\
}

BUILD_LOGIC_IO(b, u8)
EXPORT_SYMBOL(logic_inb);
EXPORT_SYMBOL(logic_insb);
EXPORT_SYMBOL(logic_outb);
EXPORT_SYMBOL(logic_outsb);

BUILD_LOGIC_IO(w, u16)
EXPORT_SYMBOL(logic_inw);
EXPORT_SYMBOL(logic_insw);
EXPORT_SYMBOL(logic_outw);
EXPORT_SYMBOL(logic_outsw);

BUILD_LOGIC_IO(l, u32)
EXPORT_SYMBOL(logic_inl);
EXPORT_SYMBOL(logic_insl);
EXPORT_SYMBOL(logic_outl);
EXPORT_SYMBOL(logic_outsl);

#endif /* CONFIG_INDIRECT_PIO && PCI_IOBASE */
