// SPDX-License-Identifier: GPL-2.0-only

//! The stack depot algorithms -- the Rust behind `lib/stackdepot.c`.
//!
//! Ported from `lib/stackdepot.c` (6.18.49), "Stack depot - a stack trace storage that avoids duplication" (Alexander Potapenko). A stack
//! trace is hashed into a bucket of `stack_table`; records live in pools (4 pages each) and are named by a 32-bit handle (pool index + offset
//! + 5 extra bits). Records saved with `STACK_DEPOT_FLAG_GET` are reference counted and, when the count drops to zero, move to a freelist
//! guarded by an RCU cookie; other records are persistent.
//!
//! # Shape
//! * **In Rust**: `stack_depot_save_flags`, `stack_depot_fetch`, `stack_depot_put`, `__stack_depot_get_stack_record` and everything they
//!   call: the lockless bucket search (`find_stack`), the pool bookkeeping (`depot_init_pool`, `depot_keep_new_pool`, `depot_pop_free_pool`,
//!   `depot_pop_free`), `depot_alloc_stack`, `depot_fetch_stack`, `depot_free_stack`.
//! * **In C** (`stackdepot_glue.c`): all the global state (the hash table, pools, `pool_lock`, the freelist, the counters: handed to the Rust
//!   as pointers through `rust_sd_state()`), the boot parameters and early/late init, debugfs, `stack_depot_print`/`snprint`, the handle bit-field
//!   accessors (`stack_depot_set_extra_bits`, `get_extra_bits`, and one wrapper each for building and splitting a handle), the exports as
//!   thunks (MODVERSIONS fingerprints come from the DWARF of the definition), and one-line `rust_sdw_*` wrappers for the raw spinlock with
//!   irq save, `printk_deferred`, `refcount_t`, the RCU list primitives, the allocator, `in_nmi`, KMSAN and every `WARN` site (the warning
//!   now names the glue file -- recorded divergence).
//!
//! # The ordering contract (concurrency bar, item 1)
//! * Readers (`find_stack`) walk a bucket under `rcu_read_lock_sched_notrace` with `READ_ONCE` loads and take no lock; writers hold
//!   `pool_lock` (raw spinlock, irqs off) and publish a record with `list_add_rcu` (release), after the record is fully initialised.
//! * A record may be matched only if `refcount_inc_not_zero` succeeds (GET flag) -- a record being freed has count zero, and its entries are
//!   unioned with the freelist links, so the entry comparison is a data race that the refcount makes harmless.
//! * `depot_free_stack` unlinks with `list_del_rcu`, takes an RCU cookie, and appends to the freelist tail; `depot_pop_free` reuses only the
//!   head entry, and only once `poll_state_synchronize_rcu(cookie)` says a grace period has passed.
//! * `new_pool` and `pools_num` are written under the lock with `WRITE_ONCE` and read lockless with `READ_ONCE`.
//!
//! Replaces: lib/stackdepot.c (the algorithms; state, init, debugfs, exports and the configuration-dependent glue stay C)

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr::{null_mut, read_volatile, write_volatile};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("stackdepot_rs.rs: x86-64 little-endian only (64-bit longs, struct layouts)");

type Gfp = c_uint;

const DEPOT_COUNTER_REFD_ALLOCS: usize = 0;
const DEPOT_COUNTER_REFD_FREES: usize = 1;
const DEPOT_COUNTER_REFD_INUSE: usize = 2;
const DEPOT_COUNTER_FREELIST_SIZE: usize = 3;
const DEPOT_COUNTER_PERSIST_COUNT: usize = 4;
const DEPOT_COUNTER_PERSIST_BYTES: usize = 5;

const STACK_DEPOT_FLAG_CAN_ALLOC: c_uint = 0x1;
const STACK_DEPOT_FLAG_GET: c_uint = 0x2;
const STACK_DEPOT_FLAGS_MASK: c_uint = 0x3;
const REFCOUNT_SATURATED: c_uint = 0xC000_0000; // INT_MIN / 2 as unsigned: (UINT_MAX / 2) + (UINT_MAX / 4) + 1

/// `struct list_head`.
#[repr(C)]
struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

/// The part of `struct stack_record` that is fixed: `hash_list` 0, `hash` 16, `size` 20, `handle` 24, `count` 28, then the union at 32:
/// `entries[]` or (`free_list` 32, `rcu_state` 48).
#[repr(C)]
struct StackRecord {
    hash_list: ListHead,
    hash: u32,
    size: u32,
    handle: u32,
    count: u32,
    union_start: [usize; 0],
}

/// What the glue hands over: pointers to its globals.
#[repr(C)]
pub struct SdState {
    pool_lock: *mut c_void,
    free_stacks: *mut ListHead,
    new_pool: *mut *mut c_void,
    pools_num: *mut c_int,
    pool_offset: *mut usize,
    stack_pools: *mut *mut *mut c_void,
    counters: *mut c_long,
    stack_table: *mut *mut ListHead,
    stack_hash_mask: *mut c_uint,
    stack_max_pools: *mut c_uint,
    disabled: *mut bool,
}

extern "C" {
    static rust_sd_record_size: usize;     // sizeof(struct stack_record)
    static rust_sd_max_frames: usize;      // CONFIG_STACKDEPOT_MAX_FRAMES
    static rust_sd_pool_size: usize;       // DEPOT_POOL_SIZE
    static rust_sd_stack_align: u32;       // DEPOT_STACK_ALIGN
    static rust_sd_poison: usize;          // STACK_DEPOT_POISON

    fn rust_sd_state() -> *const SdState;
    fn rust_sdw_lock_irqsave(lock: *mut c_void) -> c_ulong;
    fn rust_sdw_trylock_irqsave(lock: *mut c_void, flags: *mut c_ulong) -> bool;
    fn rust_sdw_unlock_irqrestore(lock: *mut c_void, flags: c_ulong);
    fn rust_sdw_printk_deferred_enter();
    fn rust_sdw_printk_deferred_exit();
    fn rust_sdw_assert_held(lock: *mut c_void);
    fn rust_sdw_assert_not_held(lock: *mut c_void);
    fn rust_sdw_hash(entries: *const c_ulong, size: c_uint) -> u32;
    fn rust_sdw_refcount_set(r: *mut u32, v: c_uint);
    fn rust_sdw_refcount_read(r: *const u32) -> c_uint;
    fn rust_sdw_refcount_inc_not_zero(r: *mut u32) -> bool;
    fn rust_sdw_refcount_dec_and_test(r: *mut u32) -> bool;
    fn rust_sdw_list_add_rcu(new: *mut ListHead, head: *mut ListHead);
    fn rust_sdw_list_del_rcu(entry: *mut ListHead);
    fn rust_sdw_list_add_tail(new: *mut ListHead, head: *mut ListHead);
    fn rust_sdw_list_del(entry: *mut ListHead);
    fn rust_sdw_rcu_read_lock_sched_notrace();
    fn rust_sdw_rcu_read_unlock_sched_notrace();
    fn rust_sdw_get_state_synchronize_rcu() -> c_ulong;
    fn rust_sdw_poll_state_synchronize_rcu(cookie: c_ulong) -> bool;
    fn rust_sdw_kmsan_unpoison(p: *mut c_void, size: usize);
    fn rust_sdw_in_nmi() -> bool;
    fn rust_sdw_allow_spinning(gfp: Gfp) -> bool;
    fn rust_sdw_alloc_pool(gfp: Gfp) -> *mut c_void;
    fn rust_sdw_free_pool(p: *mut c_void, nolock: bool);
    fn rust_sdw_filter_irq_stacks(entries: *mut c_ulong, nr: c_uint) -> c_uint;
    fn rust_sdw_init_handle(stack: *mut c_void, pool_index_plus_1: u32, offset_units: u32);
    fn rust_sdw_handle_split(handle: u32, pool_index_plus_1: *mut u32, offset_units: *mut u32);
    fn rust_sdw_warn_init_pool_gt(cond: bool);
    fn rust_sdw_warn_init_pool_nonew(cond: bool);
    fn rust_sdw_warn_limit();
    fn rust_sdw_warn_pools_lt1(cond: bool) -> bool;
    fn rust_sdw_warn_no_pool(cond: bool) -> bool;
    fn rust_sdw_warn_record_size(cond: bool);
    fn rust_sdw_warn_no_entries(cond: bool) -> bool;
    fn rust_sdw_warn_index(pool_index: u32, pools_num: c_int, handle: u32);
    fn rust_sdw_warn_nopool_ptr(cond: bool) -> bool;
    fn rust_sdw_warn_zero_count(cond: bool) -> bool;
    fn rust_sdw_warn_flags(cond: bool) -> bool;
    fn rust_sdw_warn_nmi_alloc(cond: bool);
    fn rust_sdw_warn_corrupt_fetch(cond: bool) -> bool;
    fn rust_sdw_warn_corrupt_put(cond: bool) -> bool;
}

/// `READ_ONCE()`.
#[inline(always)]
unsafe fn ro<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller passes a valid, aligned location.
    unsafe { read_volatile(p) }
}

/// `WRITE_ONCE()`.
#[inline(always)]
unsafe fn wo<T: Copy>(p: *mut T, v: T) {
    // SAFETY: as above.
    unsafe { write_volatile(p, v) }
}

#[inline(always)]
unsafe fn entries_of(s: *mut StackRecord) -> *mut c_ulong {
    // SAFETY: the union starts at offset 32.
    unsafe { core::ptr::addr_of_mut!((*s).union_start) as *mut c_ulong }
}

#[inline(always)]
unsafe fn free_list_of(s: *mut StackRecord) -> *mut ListHead {
    // SAFETY: as above (`free_list` is the first member of the anonymous struct).
    unsafe { entries_of(s) as *mut ListHead }
}

#[inline(always)]
unsafe fn rcu_state_of(s: *mut StackRecord) -> *mut c_ulong {
    // SAFETY: `rcu_state` follows `free_list` (16 bytes).
    unsafe { (entries_of(s) as *mut u8).add(16) as *mut c_ulong }
}

/// `depot_init_pool()`: initialise a new pool and update the list of pools. Called with `pool_lock` held.
unsafe fn depot_init_pool(st: &SdState, prealloc: *mut *mut c_void) -> bool {
    // SAFETY: the caller holds pool_lock; `st` points at the glue's globals.
    unsafe {
        rust_sdw_assert_held(st.pool_lock);

        let pools_num = *st.pools_num;
        let max_pools = *st.stack_max_pools;
        if (pools_num as c_uint) >= max_pools {
            // Bail out if we reached the pool limit.
            rust_sdw_warn_init_pool_gt(pools_num as c_uint > max_pools); // should never happen
            rust_sdw_warn_init_pool_nonew((*st.new_pool).is_null()); // to avoid unnecessary pre-allocation
            rust_sdw_warn_limit();
            return false;
        }

        if (*st.new_pool).is_null() && !(*prealloc).is_null() {
            // We have preallocated memory, use it.
            wo(st.new_pool, *prealloc);
            *prealloc = null_mut();
        }

        if (*st.new_pool).is_null() {
            return false; // new_pool and *prealloc are NULL
        }

        // Save reference to the pool to be used by depot_fetch_stack().
        *(*st.stack_pools).add(pools_num as usize) = *st.new_pool;

        // Stack depot tries to keep an extra pool allocated even before it runs out of space in the currently used pool. To indicate that a
        // new preallocation is needed new_pool is reset to NULL; do not reset to NULL if we have reached the maximum number of pools.
        if (pools_num as c_uint) < max_pools {
            wo(st.new_pool, null_mut());
        } else {
            wo(st.new_pool, rust_sd_poison as *mut c_void);
        }

        // Pairs with concurrent READ_ONCE() in depot_fetch_stack().
        wo(st.pools_num, pools_num + 1);

        *st.pool_offset = 0;

        true
    }
}

/// `depot_keep_new_pool()`: keep the preallocated memory to be used for a new stack depot pool.
unsafe fn depot_keep_new_pool(st: &SdState, prealloc: *mut *mut c_void) {
    // SAFETY: the caller holds pool_lock.
    unsafe {
        rust_sdw_assert_held(st.pool_lock);

        // If a new pool is already saved or the maximum number of pools is reached, do not use the preallocated memory.
        if !(*st.new_pool).is_null() {
            return;
        }

        wo(st.new_pool, *prealloc);
        *prealloc = null_mut();
    }
}

/// `depot_pop_free_pool()`: try to initialize a new stack record from the current pool, a cached pool, or the current pre-allocation.
unsafe fn depot_pop_free_pool(st: &SdState, prealloc: *mut *mut c_void, size: usize) -> *mut StackRecord {
    // SAFETY: the caller holds pool_lock.
    unsafe {
        rust_sdw_assert_held(st.pool_lock);

        if (*st.pool_offset).wrapping_add(size) > rust_sd_pool_size && !depot_init_pool(st, prealloc) {
            return null_mut();
        }

        let pools_num = *st.pools_num;
        if rust_sdw_warn_pools_lt1(pools_num < 1) {
            return null_mut();
        }
        let pool_index = (pools_num - 1) as u32;
        let current_pool = *(*st.stack_pools).add(pool_index as usize);
        if rust_sdw_warn_no_pool(current_pool.is_null()) {
            return null_mut();
        }

        let stack = (current_pool as *mut u8).add(*st.pool_offset) as *mut StackRecord;

        // Pre-initialize handle once.
        rust_sdw_init_handle(stack as *mut c_void, pool_index + 1, (*st.pool_offset >> rust_sd_stack_align) as u32);
        // INIT_LIST_HEAD(&stack->hash_list)
        (*stack).hash_list.next = core::ptr::addr_of_mut!((*stack).hash_list);
        (*stack).hash_list.prev = core::ptr::addr_of_mut!((*stack).hash_list);

        *st.pool_offset = (*st.pool_offset).wrapping_add(size);

        stack
    }
}

/// `depot_pop_free()`: try to find the next free usable entry from the freelist.
unsafe fn depot_pop_free(st: &SdState) -> *mut StackRecord {
    // SAFETY: the caller holds pool_lock.
    unsafe {
        rust_sdw_assert_held(st.pool_lock);

        let head = st.free_stacks;
        if (*head).next == head {
            return null_mut(); // list_empty()
        }

        // We maintain the invariant that the elements in front are least recently used, and are therefore more likely to be associated with an
        // RCU grace period in the past. Consequently it is sufficient to only check the first entry.
        let first = (*head).next as *mut u8; // list_first_entry(): free_list is at offset 32
        let stack = first.sub(32) as *mut StackRecord;
        if !rust_sdw_poll_state_synchronize_rcu(*rcu_state_of(stack)) {
            return null_mut();
        }

        rust_sdw_list_del(free_list_of(stack));
        *st.counters.add(DEPOT_COUNTER_FREELIST_SIZE) -= 1;

        stack
    }
}

/// `depot_stack_record_size()`: the size of a record holding `nr_entries` frames, aligned to `1 << DEPOT_STACK_ALIGN`.
unsafe fn depot_stack_record_size(nr_entries: c_uint) -> usize {
    // SAFETY: reads constants only.
    unsafe {
        let used = (nr_entries as usize).wrapping_mul(8);
        let entries_size = rust_sd_max_frames.wrapping_mul(8);
        let unused = entries_size.wrapping_sub(used);

        rust_sdw_warn_record_size(entries_size < used);

        let align = 1usize << rust_sd_stack_align;
        (rust_sd_record_size.wrapping_sub(unused).wrapping_add(align - 1)) & !(align - 1)
    }
}

/// `depot_alloc_stack()`: allocate a new stack in a stack depot pool.
unsafe fn depot_alloc_stack(st: &SdState, entries: *const c_ulong, mut nr_entries: c_uint, hash: u32, flags: c_uint, prealloc: *mut *mut c_void) -> *mut StackRecord {
    // SAFETY: the caller holds pool_lock.
    unsafe {
        let mut stack: *mut StackRecord = null_mut();

        rust_sdw_assert_held(st.pool_lock);

        // This should already be checked by public API entry points.
        if rust_sdw_warn_no_entries(nr_entries == 0) {
            return null_mut();
        }

        // Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES.
        if nr_entries as usize > rust_sd_max_frames {
            nr_entries = rust_sd_max_frames as c_uint;
        }

        let record_size;
        if flags & STACK_DEPOT_FLAG_GET != 0 {
            // Evictable entries have to allocate the max. size so they may safely be re-used by differently sized allocations.
            record_size = depot_stack_record_size(rust_sd_max_frames as c_uint);
            stack = depot_pop_free(st);
        } else {
            record_size = depot_stack_record_size(nr_entries);
        }

        if stack.is_null() {
            stack = depot_pop_free_pool(st, prealloc, record_size);
            if stack.is_null() {
                return null_mut();
            }
        }

        // Save the stack trace.
        (*stack).hash = hash;
        (*stack).size = nr_entries;
        // stack->handle is already filled in by depot_pop_free_pool().
        core::ptr::copy_nonoverlapping(entries, entries_of(stack), nr_entries as usize);

        if flags & STACK_DEPOT_FLAG_GET != 0 {
            rust_sdw_refcount_set(core::ptr::addr_of_mut!((*stack).count), 1);
            *st.counters.add(DEPOT_COUNTER_REFD_ALLOCS) += 1;
            *st.counters.add(DEPOT_COUNTER_REFD_INUSE) += 1;
        } else {
            // Warn on attempts to switch to refcounting this entry.
            rust_sdw_refcount_set(core::ptr::addr_of_mut!((*stack).count), REFCOUNT_SATURATED);
            *st.counters.add(DEPOT_COUNTER_PERSIST_COUNT) += 1;
            *st.counters.add(DEPOT_COUNTER_PERSIST_BYTES) += record_size as c_long;
        }

        // Let KMSAN know the stored stack record is initialized. This shall prevent false positive reports if instrumented code accesses it.
        rust_sdw_kmsan_unpoison(stack as *mut c_void, record_size);

        stack
    }
}

/// `depot_fetch_stack()`.
unsafe fn depot_fetch_stack(st: &SdState, handle: u32) -> *mut StackRecord {
    // SAFETY: lockless; the pool pointers are published before `pools_num` is bumped.
    unsafe {
        let pools_num_cached = ro(st.pools_num);
        let mut pool_index_plus_1 = 0u32;
        let mut offset_units = 0u32;
        rust_sdw_handle_split(handle, &mut pool_index_plus_1, &mut offset_units);
        let pool_index = pool_index_plus_1.wrapping_sub(1);
        let offset = (offset_units as usize) << rust_sd_stack_align;

        rust_sdw_assert_not_held(st.pool_lock);

        if pool_index >= pools_num_cached as u32 {
            rust_sdw_warn_index(pool_index, pools_num_cached, handle);
            return null_mut();
        }

        let pool = *(*st.stack_pools).add(pool_index as usize);
        if rust_sdw_warn_nopool_ptr(pool.is_null()) {
            return null_mut();
        }

        let stack = (pool as *mut u8).add(offset) as *mut StackRecord;
        if rust_sdw_warn_zero_count(rust_sdw_refcount_read(core::ptr::addr_of!((*stack).count)) == 0) {
            return null_mut();
        }

        stack
    }
}

/// `depot_free_stack()`: link a stack into the freelist.
unsafe fn depot_free_stack(st: &SdState, stack: *mut StackRecord) {
    // SAFETY: lockless entry, takes pool_lock.
    unsafe {
        rust_sdw_assert_not_held(st.pool_lock);

        let flags = rust_sdw_lock_irqsave(st.pool_lock);
        rust_sdw_printk_deferred_enter();

        // Remove the entry from the hash list. Concurrent list traversal may still observe the entry, but since the refcount is zero, this
        // entry will no longer be considered as valid.
        rust_sdw_list_del_rcu(core::ptr::addr_of_mut!((*stack).hash_list));

        // Due to being used from constrained contexts such as the allocators, NMI, or even RCU itself, stack depot cannot rely on primitives
        // that would sleep (such as synchronize_rcu()) or recursively call into stack depot again (such as call_rcu()). Instead, get an RCU
        // cookie, so that we can ensure this entry isn't moved onto another list until the next grace period, and concurrent RCU list
        // traversal remains safe.
        *rcu_state_of(stack) = rust_sdw_get_state_synchronize_rcu();

        // Add the entry to the freelist tail, so that older entries are considered first - their RCU cookie is more likely to no longer be
        // associated with the current grace period.
        rust_sdw_list_add_tail(free_list_of(stack), st.free_stacks);

        *st.counters.add(DEPOT_COUNTER_FREELIST_SIZE) += 1;
        *st.counters.add(DEPOT_COUNTER_REFD_FREES) += 1;
        *st.counters.add(DEPOT_COUNTER_REFD_INUSE) -= 1;

        rust_sdw_printk_deferred_exit();
        rust_sdw_unlock_irqrestore(st.pool_lock, flags);
    }
}

/// `stackdepot_memcmp()`: 1 if the frames differ.
#[inline(always)]
unsafe fn stackdepot_memcmp(u1: *const c_ulong, u2: *const c_ulong, n: c_uint) -> bool {
    // SAFETY: both ranges hold `n` frames (a racing free may change the second, which the refcount check then rejects).
    unsafe {
        let mut i = 0usize;
        while i < n as usize {
            if read_volatile(u1.add(i)) != read_volatile(u2.add(i)) {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// `find_stack()`: find a stack in a bucket of the hash table.
unsafe fn find_stack(bucket: *mut ListHead, entries: *const c_ulong, size: c_int, hash: u32, flags: c_uint) -> *mut StackRecord {
    // SAFETY: lockless, under rcu_read_lock_sched_notrace.
    unsafe {
        let mut ret: *mut StackRecord = null_mut();

        // Stack depot may be used from instrumentation that instruments RCU or tracing itself; use variant that does not call into RCU and
        // cannot be traced.
        rust_sdw_rcu_read_lock_sched_notrace();

        // list_for_each_entry_rcu(stack, bucket, hash_list)
        let mut pos = ro(core::ptr::addr_of!((*bucket).next));
        while pos != bucket {
            let stack = pos as *mut StackRecord; // hash_list is the first member
            pos = ro(core::ptr::addr_of!((*pos).next));

            if ro(core::ptr::addr_of!((*stack).hash)) != hash || ro(core::ptr::addr_of!((*stack).size)) as c_int != size {
                continue;
            }

            // This may race with depot_free_stack() accessing the freelist management state unioned with @entries. The refcount is zero in
            // that case and the below refcount_inc_not_zero() will fail.
            if stackdepot_memcmp(entries, entries_of(stack), size as c_uint) {
                continue;
            }

            // Try to increment refcount. If this succeeds, the stack record is valid and has not yet been freed.
            //
            // If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior to then call stack_depot_put() later, and we can assume that a
            // stack record is never placed back on the freelist.
            if flags & STACK_DEPOT_FLAG_GET != 0 && !rust_sdw_refcount_inc_not_zero(core::ptr::addr_of_mut!((*stack).count)) {
                continue;
            }

            ret = stack;
            break;
        }

        rust_sdw_rcu_read_unlock_sched_notrace();

        ret
    }
}

/// `stack_depot_save_flags()`.
#[no_mangle]
pub unsafe extern "C" fn rust_stack_depot_save_flags(entries: *mut c_ulong, mut nr_entries: c_uint, alloc_flags: Gfp, depot_flags: c_uint) -> u32 {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        let st = &*rust_sd_state();
        let mut found: *mut StackRecord;
        let mut handle: u32 = 0;
        let mut prealloc: *mut c_void = null_mut();
        let allow_spin = rust_sdw_allow_spinning(alloc_flags);
        let can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) != 0 && allow_spin;
        let mut flags: c_ulong = 0;

        if rust_sdw_warn_flags(depot_flags & !STACK_DEPOT_FLAGS_MASK != 0) {
            return 0;
        }

        // If this stack trace is from an interrupt, including anything before interrupt entry usually leads to unbounded stack depot growth.
        //
        // Since use of filter_irq_stacks() is a requirement to ensure stack depot can efficiently deduplicate interrupt stacks, always
        // filter_irq_stacks() to simplify all callers' use of stack depot.
        nr_entries = rust_sdw_filter_irq_stacks(entries, nr_entries);

        if nr_entries == 0 || ro(st.disabled) {
            return 0;
        }

        let hash = rust_sdw_hash(entries, nr_entries);
        let bucket = (*st.stack_table).add((hash & *st.stack_hash_mask) as usize);

        'exit: {
            // Fast path: look the stack trace up without locking.
            found = find_stack(bucket, entries, nr_entries as c_int, hash, depot_flags);
            if !found.is_null() {
                break 'exit;
            }

            // Allocate memory for a new pool if required now: we won't be able to do that under the lock.
            if can_alloc && ro(st.new_pool).is_null() {
                prealloc = rust_sdw_alloc_pool(alloc_flags);
            }

            if rust_sdw_in_nmi() || !allow_spin {
                // We can never allocate in NMI context.
                rust_sdw_warn_nmi_alloc(can_alloc);
                // Best effort; bail if we fail to take the lock.
                if !rust_sdw_trylock_irqsave(st.pool_lock, &mut flags) {
                    break 'exit;
                }
            } else {
                flags = rust_sdw_lock_irqsave(st.pool_lock);
            }
            rust_sdw_printk_deferred_enter();

            // Try to find again, to avoid concurrently inserting duplicates.
            found = find_stack(bucket, entries, nr_entries as c_int, hash, depot_flags);
            if found.is_null() {
                let new = depot_alloc_stack(st, entries, nr_entries, hash, depot_flags, &mut prealloc);

                if !new.is_null() {
                    // This releases the stack record into the bucket and makes it visible to readers in find_stack().
                    rust_sdw_list_add_rcu(core::ptr::addr_of_mut!((*new).hash_list), bucket);
                    found = new;
                }
            }

            if !prealloc.is_null() {
                // Either stack depot already contains this stack trace, or depot_alloc_stack() did not consume the preallocated memory.
                // Try to keep the preallocated memory for future.
                depot_keep_new_pool(st, &mut prealloc);
            }

            rust_sdw_printk_deferred_exit();
            rust_sdw_unlock_irqrestore(st.pool_lock, flags);
        }

        if !prealloc.is_null() {
            // Stack depot didn't use this memory, free it.
            rust_sdw_free_pool(prealloc, !allow_spin);
        }
        if !found.is_null() {
            handle = (*found).handle;
        }
        handle
    }
}

/// `__stack_depot_get_stack_record()`.
#[no_mangle]
pub unsafe extern "C" fn rust_stack_depot_get_stack_record(handle: u32) -> *mut c_void {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        if handle == 0 {
            return null_mut();
        }
        depot_fetch_stack(&*rust_sd_state(), handle) as *mut c_void
    }
}

/// `stack_depot_fetch()`.
#[no_mangle]
pub unsafe extern "C" fn rust_stack_depot_fetch(handle: u32, entries: *mut *mut c_ulong) -> c_uint {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        let st = &*rust_sd_state();
        *entries = null_mut();
        // Let KMSAN know *entries is initialized. This shall prevent false positive reports if instrumented code accesses it.
        rust_sdw_kmsan_unpoison(entries as *mut c_void, core::mem::size_of::<*mut c_ulong>());

        if handle == 0 || ro(st.disabled) {
            return 0;
        }

        let stack = depot_fetch_stack(st, handle);
        // Should never be NULL, otherwise this is a use-after-put (or just a corrupt handle).
        if rust_sdw_warn_corrupt_fetch(stack.is_null()) {
            return 0;
        }

        *entries = entries_of(stack);
        (*stack).size
    }
}

/// `stack_depot_put()`.
#[no_mangle]
pub unsafe extern "C" fn rust_stack_depot_put(handle: u32) {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        let st = &*rust_sd_state();
        if handle == 0 || ro(st.disabled) {
            return;
        }

        let stack = depot_fetch_stack(st, handle);
        // Should always be able to find the stack record, otherwise this is an unbalanced put attempt (or corrupt handle).
        if rust_sdw_warn_corrupt_put(stack.is_null()) {
            return;
        }

        if rust_sdw_refcount_dec_and_test(core::ptr::addr_of_mut!((*stack).count)) {
            depot_free_stack(st, stack);
        }
    }
}
