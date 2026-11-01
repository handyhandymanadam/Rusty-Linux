
#ifndef _LINUX_STACKDEPOT_H
#define _LINUX_STACKDEPOT_H

#include "../kshim.h"

typedef u32 depot_stack_handle_t;

#define STACK_DEPOT_EXTRA_BITS 5

#define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)

#define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
#define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
#define DEPOT_STACK_ALIGN 4
#define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
			       STACK_DEPOT_EXTRA_BITS)

#ifdef CONFIG_STACKDEPOT
union handle_parts {
	depot_stack_handle_t handle;
	struct {
		u32 pool_index_plus_1	: DEPOT_POOL_INDEX_BITS;
		u32 offset		: DEPOT_OFFSET_BITS;
		u32 extra		: STACK_DEPOT_EXTRA_BITS;
	};
};

struct stack_record {
	struct list_head hash_list;	/* Links in the hash table */
	u32 hash;			/* Hash in hash table */
	u32 size;			/* Number of stored frames */
	union handle_parts handle;	/* Constant after initialization */
	refcount_t count;
	union {
		unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
		struct {
			/*
			 * An important invariant of the implementation is to
			 * only place a stack record onto the freelist iff its
			 * refcount is zero. Because stack records with a zero
			 * refcount are never considered as valid, it is safe to
			 * union @entries and freelist management state below.
			 * Conversely, as soon as an entry is off the freelist
			 * and its refcount becomes non-zero, the below must not
			 * be accessed until being placed back on the freelist.
			 */
			struct list_head free_list;	/* Links in the freelist */
			unsigned long rcu_state;	/* RCU cookie */
		};
	};
};
#endif

typedef u32 depot_flags_t;

#define STACK_DEPOT_FLAG_CAN_ALLOC	((depot_flags_t)0x0001)
#define STACK_DEPOT_FLAG_GET		((depot_flags_t)0x0002)

#define STACK_DEPOT_FLAGS_NUM	2
#define STACK_DEPOT_FLAGS_MASK	((depot_flags_t)((1 << STACK_DEPOT_FLAGS_NUM) - 1))

#ifdef CONFIG_STACKDEPOT
int stack_depot_init(void);

void __init stack_depot_request_early_init(void);

int __init stack_depot_early_init(void);
#else
static inline int stack_depot_init(void) { return 0; }

static inline void stack_depot_request_early_init(void) { }

static inline int stack_depot_early_init(void)	{ return 0; }
#endif

depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
					    unsigned int nr_entries,
					    gfp_t alloc_flags,
					    depot_flags_t depot_flags);

depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries, gfp_t alloc_flags);

struct stack_record *__stack_depot_get_stack_record(depot_stack_handle_t handle);

unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries);

void stack_depot_print(depot_stack_handle_t stack);

int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
		       int spaces);

void stack_depot_put(depot_stack_handle_t handle);

depot_stack_handle_t __must_check stack_depot_set_extra_bits(
			depot_stack_handle_t handle, unsigned int extra_bits);

unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);

#endif
