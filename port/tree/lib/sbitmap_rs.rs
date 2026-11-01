// SPDX-License-Identifier: GPL-2.0-only

//! The sbitmap algorithms -- the Rust behind `lib/sbitmap.c`.
//!
//! Ported from `lib/sbitmap.c` (6.18.49), "scalable bitmap" (Jens Axboe, Facebook): a bitmap split into cacheline-sized words so that many CPUs
//! can allocate and free bits (tags) without sharing a cacheline, with per-CPU allocation hints, deferred clearing (`cleared` is a second mask
//! that is folded into `word` when an allocation runs dry) and a queue variant (`sbitmap_queue`) that batches wake-ups of waiters.
//!
//! # Shape
//! * **In Rust**: allocation (`sbitmap_get`, `sbitmap_get_shallow`, `__sbitmap_queue_get_batch` and everything under them), deferred clear,
//!   resize, `any_bit_set`, weight, the wake-batch arithmetic, `sbitmap_queue_wake_up` (+ `__sbitmap_queue_wake_up`), `clear`, `clear_batch`,
//!   `wake_all`.
//! * **In C** (`sbitmap_glue.c`): `sbitmap_init_node` / `sbitmap_queue_init_node` (percpu and `kvzalloc` allocation, lock and waitqueue
//!   initialisation), the `seq_file` output functions, the wait-queue plumbing (`add_wait_queue`, `prepare_to_wait_exclusive`, ...), the exports
//!   as thunks (their MODVERSIONS fingerprints come from the DWARF of the definition), and one-line `rust_sbw_*` wrappers for the primitives
//!   whose bodies depend on the configuration (raw spinlock with irq save, per-CPU access, memory barriers, wait-queue wake-ups, WARN sites --
//!   a warning now names the glue file: recorded divergence). Struct strides that vary with the configuration (`sizeof(struct sbitmap_word)`,
//!   the offsets of `cleared` and `swap_lock`, `sizeof(struct sbq_wait_state)`) are exported by the glue as constants.
//!
//! # The ordering contract (concurrency bar, item 1)
//! * Allocation sets a bit with `test_and_set_bit_lock` (ACQUIRE): it pairs with the RELEASE-less `clear` path through the barriers kept
//!   in C wrappers (`smp_mb__before_atomic()` before the deferred-clear `set_bit`, `smp_mb__after_atomic()` after it, so the waker's
//!   `waitqueue_active()` check is ordered against the waiter's `prepare_to_wait()`).
//! * `cleared -> word` folding is done under `swap_lock` (irq-saving): `xchg(&cleared, 0)` (fully ordered) then `andnot` on `word`.
//! * The batch allocator and `clear_batch` update `word` with `try_cmpxchg` (fully ordered) / `andnot` (relaxed, bracketed by the C barriers).
//! * `wake_batch`, `min_shallow_depth`, `depth` are written with `WRITE_ONCE` and read lockless with `READ_ONCE`.
//!
//! Replaces: lib/sbitmap.c (the algorithms; init, show, wait-queue plumbing and exports stay C)

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("sbitmap_rs.rs: x86-64 little-endian only (64-bit longs, struct layouts)");

const SBQ_WAIT_QUEUES: c_int = 8;
const SBQ_WAKE_BATCH: c_uint = 8;
const BITS_PER_LONG: u32 = 64;

/// `struct sbitmap`.
#[repr(C)]
pub struct Sbitmap {
    depth: c_uint,
    shift: c_uint,
    map_nr: c_uint,
    round_robin: bool,
    map: *mut u8,
    alloc_hint: *mut c_uint,
}

/// `struct sbitmap_queue`.
#[repr(C)]
pub struct SbitmapQueue {
    sb: Sbitmap,
    wake_batch: c_uint,
    wake_index: AtomicI32,
    ws: *mut u8,
    ws_active: AtomicI32,
    min_shallow_depth: c_uint,
    completion_cnt: AtomicI32,
    wakeup_cnt: AtomicI32,
}

extern "C" {
    static rust_sb_word_size: usize; // sizeof(struct sbitmap_word)
    static rust_sb_off_cleared: usize; // offsetof(struct sbitmap_word, cleared)
    static rust_sb_off_lock: usize; // offsetof(struct sbitmap_word, swap_lock)
    static rust_sb_ws_size: usize; // sizeof(struct sbq_wait_state)

    fn rust_sbw_lock_irqsave(lock: *mut c_void) -> c_ulong;
    fn rust_sbw_unlock_irqrestore(lock: *mut c_void, flags: c_ulong);
    fn rust_sbw_hint_read(sb: *mut Sbitmap) -> c_uint;
    fn rust_sbw_hint_write(sb: *mut Sbitmap, v: c_uint);
    fn rust_sbw_hint_write_cpu(sb: *mut Sbitmap, cpu: c_int, v: c_uint);
    fn rust_sbw_random_below(n: c_uint) -> c_uint;
    fn rust_sbw_cpu() -> c_int;
    fn rust_sbw_warn_no_hint_get(cond: bool) -> bool;
    fn rust_sbw_warn_no_hint_shallow(cond: bool) -> bool;
    fn rust_sbw_warn_shallow(cond: bool);
    fn rust_sbw_waitqueue_active(ws: *mut c_void) -> bool;
    fn rust_sbw_wake_up_nr(ws: *mut c_void, nr: c_int) -> c_int;
    fn rust_sbw_wake_up(ws: *mut c_void);
    fn rust_sbw_mb_before_atomic();
    fn rust_sbw_mb_after_atomic();
    fn rust_sbw_mb();
    fn rust_sbw_deferred_clear_bit(sb: *mut Sbitmap, nr: c_uint);
}

#[inline(always)]
unsafe fn ro<T: Copy>(p: *const T) -> T {
    unsafe { read_volatile(p) }
}

#[inline(always)]
unsafe fn wo<T: Copy>(p: *mut T, v: T) {
    unsafe { write_volatile(p, v) }
}

/// `&sb->map[i]`.
#[inline(always)]
unsafe fn map_at(sb: *const Sbitmap, i: usize) -> *mut u8 {
    unsafe { ro(core::ptr::addr_of!((*sb).map)).add(i.wrapping_mul(rust_sb_word_size)) }
}

#[inline(always)]
unsafe fn word_of(map: *mut u8) -> *mut u64 {
    map as *mut u64
}

#[inline(always)]
unsafe fn cleared_of(map: *mut u8) -> *mut u64 {
    unsafe { map.add(rust_sb_off_cleared) as *mut u64 }
}

#[inline(always)]
unsafe fn lock_of(map: *mut u8) -> *mut c_void {
    unsafe { map.add(rust_sb_off_lock) as *mut c_void }
}

/// `__map_depth()`: the number of bits in word `index` (the last word may be short).
#[inline(always)]
unsafe fn map_depth(sb: *const Sbitmap, index: u32) -> u32 {
    unsafe {
        let s = &*sb;
        if index == s.map_nr.wrapping_sub(1) {
            s.depth.wrapping_sub(index.wrapping_shl(s.shift))
        } else {
            1u32.wrapping_shl(s.shift)
        }
    }
}

/// `bitmap_weight(&w, nbits)` for one word.
#[inline(always)]
fn word_weight(w: u64, nbits: u32) -> u32 {
    if nbits >= BITS_PER_LONG {
        w.count_ones()
    } else {
        (w & ((1u64 << nbits) - 1)).count_ones()
    }
}

/// `find_next_zero_bit(word, size, offset)` on a single word (`size` <= 64): returns `size` when there is none.
#[inline(always)]
unsafe fn find_next_zero_bit(word: *const u64, size: u64, offset: u32) -> u64 {
    unsafe {
        if offset as u64 >= size {
            return size;
        }
        let mut v = !ro(word) & (!0u64).wrapping_shl(offset);
        if size < 64 {
            v &= (1u64 << size) - 1;
        }
        if v == 0 {
            size
        } else {
            v.trailing_zeros() as u64
        }
    }
}

/// `update_alloc_hint_before_get()`.
unsafe fn update_alloc_hint_before_get(sb: *mut Sbitmap, depth: c_uint) -> c_uint {
    unsafe {
        let mut hint = rust_sbw_hint_read(sb);
        if hint >= depth {
            hint = if depth != 0 { rust_sbw_random_below(depth) } else { 0 };
            rust_sbw_hint_write(sb, hint);
        }
        hint
    }
}

/// `update_alloc_hint_after_get()`: `nr` is the bit just allocated, or `u32::MAX` (-1) when the map was full.
unsafe fn update_alloc_hint_after_get(sb: *mut Sbitmap, depth: c_uint, hint: c_uint, nr: c_uint) {
    unsafe {
        if nr == u32::MAX {
            // If the map is full, a hint won't do us much good.
            rust_sbw_hint_write(sb, 0);
        } else if nr == hint || (*sb).round_robin {
            // Only update the hint if we used it.
            let mut h = nr.wrapping_add(1);
            if h >= depth.wrapping_sub(1) {
                h = 0;
            }
            rust_sbw_hint_write(sb, h);
        }
    }
}

/// `sbitmap_deferred_clear()`: fold `cleared` into `word`; `true` = worth retrying the allocation.
unsafe fn sbitmap_deferred_clear(map: *mut u8, depth: c_uint, alloc_hint: c_uint, wrap: bool) -> bool {
    unsafe {
        let lock = lock_of(map);
        let flags = rust_sbw_lock_irqsave(lock);
        let word = word_of(map);
        let cleared = cleared_of(map);
        let r;

        if ro(cleared) == 0 {
            if depth == 0 {
                r = false;
            } else {
                let mut word_mask = (!0u64).wrapping_shr(BITS_PER_LONG.wrapping_sub(depth));
                // The current behavior is to always retry after moving ->cleared to word, and we change it to retry in case of any free
                // bits. To avoid an infinite loop, we need to take wrap & alloc_hint into account, otherwise a soft lockup may occur.
                if !wrap && alloc_hint != 0 {
                    word_mask &= !((1u64.wrapping_shl(alloc_hint)).wrapping_sub(1));
                }
                r = (ro(word) & word_mask) != word_mask;
            }
        } else {
            // First get a stable cleared mask, setting the old mask to 0.
            let mask = AtomicU64::from_ptr(cleared).swap(0, Ordering::SeqCst);
            // Now clear the masked bits in our free word.
            AtomicU64::from_ptr(word).fetch_and(!mask, Ordering::Relaxed);
            r = true;
        }

        rust_sbw_unlock_irqrestore(lock, flags);
        r
    }
}

/// `sbitmap_resize()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_resize(sb: *mut Sbitmap, depth: c_uint) {
    unsafe {
        let bits_per_word = 1u32.wrapping_shl((*sb).shift);
        let mut i = 0u32;
        while i < (*sb).map_nr {
            sbitmap_deferred_clear(map_at(sb, i as usize), 0, 0, false);
            i += 1;
        }
        (*sb).depth = depth;
        (*sb).map_nr = depth.wrapping_add(bits_per_word - 1) / bits_per_word;
    }
}

/// `__sbitmap_get_word()`: allocate one bit from a single word; the bit number or -1.
unsafe fn sbitmap_get_word(word: *mut u64, depth: u64, mut hint: c_uint, wrap: bool) -> c_int {
    unsafe {
        // don't wrap if starting from 0
        let wrap = wrap && hint != 0;

        loop {
            let nr = find_next_zero_bit(word, depth, hint);
            if nr >= depth {
                // We started with an offset, and we didn't reset the offset to 0 in a failure case, so start from 0 to exhaust the map.
                if hint != 0 && wrap {
                    hint = 0;
                    continue;
                }
                return -1;
            }

            let bit = 1u64 << nr;
            if AtomicU64::from_ptr(word).fetch_or(bit, Ordering::Acquire) & bit == 0 {
                return nr as c_int;
            }

            hint = (nr as u32).wrapping_add(1);
            if hint as u64 >= depth.wrapping_sub(1) {
                hint = 0;
            }
        }
    }
}

/// `sbitmap_find_bit_in_word()`.
unsafe fn sbitmap_find_bit_in_word(map: *mut u8, depth: c_uint, alloc_hint: c_uint, wrap: bool) -> c_int {
    unsafe {
        loop {
            let nr = sbitmap_get_word(word_of(map), depth as u64, alloc_hint, wrap);
            if nr != -1 {
                return nr;
            }
            if !sbitmap_deferred_clear(map, depth, alloc_hint, wrap) {
                return nr;
            }
        }
    }
}

/// `__map_depth_with_shallow()`.
unsafe fn map_depth_with_shallow(sb: *const Sbitmap, index: u32, shallow_depth: c_uint) -> c_uint {
    unsafe {
        let word_depth = map_depth(sb, index);
        if shallow_depth >= (*sb).depth {
            return word_depth;
        }

        let mut shallow_word_depth = (word_depth as u64) * (shallow_depth as u64);
        let reminder = (shallow_word_depth % ((*sb).depth as u64)) as u32;
        shallow_word_depth /= (*sb).depth as u64;

        if reminder >= index.wrapping_add(1).wrapping_mul(word_depth) {
            shallow_word_depth += 1;
        }

        shallow_word_depth as u32
    }
}

/// `sbitmap_find_bit()`.
unsafe fn sbitmap_find_bit(sb: *mut Sbitmap, shallow_depth: c_uint, mut index: u32, mut alloc_hint: c_uint, wrap: bool) -> c_int {
    unsafe {
        let mut nr: c_int = -1;
        let mut i = 0u32;
        while i < (*sb).map_nr {
            let depth = map_depth_with_shallow(sb, index, shallow_depth);

            if depth != 0 {
                nr = sbitmap_find_bit_in_word(map_at(sb, index as usize), depth, alloc_hint, wrap);
            }
            if nr != -1 {
                nr = nr.wrapping_add(index.wrapping_shl((*sb).shift) as c_int);
                break;
            }

            // Jump to next index.
            alloc_hint = 0;
            index += 1;
            if index >= (*sb).map_nr {
                index = 0;
            }
            i += 1;
        }
        nr
    }
}

/// `__sbitmap_get()`.
unsafe fn sbitmap_get_inner(sb: *mut Sbitmap, mut alloc_hint: c_uint) -> c_int {
    unsafe {
        let index = alloc_hint >> (*sb).shift;

        // Unless we're doing round robin tag allocation, just use the alloc_hint to find the right word index. No point in looping twice in
        // find_next_zero_bit() for that case.
        if (*sb).round_robin {
            alloc_hint &= 1u32.wrapping_shl((*sb).shift).wrapping_sub(1);
        } else {
            alloc_hint = 0;
        }

        sbitmap_find_bit(sb, u32::MAX, index, alloc_hint, !(*sb).round_robin)
    }
}

/// `sbitmap_get()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_get(sb: *mut Sbitmap) -> c_int {
    unsafe {
        if rust_sbw_warn_no_hint_get((*sb).alloc_hint.is_null()) {
            return -1;
        }

        let depth = ro(core::ptr::addr_of!((*sb).depth));
        let hint = update_alloc_hint_before_get(sb, depth);
        let nr = sbitmap_get_inner(sb, hint);
        update_alloc_hint_after_get(sb, depth, hint, nr as c_uint);

        nr
    }
}

/// `sbitmap_get_shallow()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_get_shallow(sb: *mut Sbitmap, shallow_depth: c_ulong) -> c_int {
    unsafe {
        if rust_sbw_warn_no_hint_shallow((*sb).alloc_hint.is_null()) {
            return -1;
        }

        let depth = ro(core::ptr::addr_of!((*sb).depth));
        let hint = update_alloc_hint_before_get(sb, depth);

        // __sbitmap_get_shallow()
        let index = hint >> (*sb).shift;
        let bit = hint & 1u32.wrapping_shl((*sb).shift).wrapping_sub(1);
        let nr = sbitmap_find_bit(sb, shallow_depth as c_uint, index, bit, true);

        update_alloc_hint_after_get(sb, depth, hint, nr as c_uint);

        nr
    }
}

/// `sbitmap_any_bit_set()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_any_bit_set(sb: *const Sbitmap) -> bool {
    unsafe {
        let mut i = 0u32;
        while i < (*sb).map_nr {
            let map = map_at(sb, i as usize);
            if *word_of(map) & !*cleared_of(map) != 0 {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// `__sbitmap_weight()`: the number of set bits in `word` (`set`) or in `cleared`.
unsafe fn sbitmap_weight_of(sb: *const Sbitmap, set: bool) -> c_uint {
    unsafe {
        let mut weight = 0u32;
        let mut i = 0u32;
        while i < (*sb).map_nr {
            let map = map_at(sb, i as usize);
            let word_depth = map_depth(sb, i);
            let w = if set { *word_of(map) } else { *cleared_of(map) };
            weight = weight.wrapping_add(word_weight(w, word_depth));
            i += 1;
        }
        weight
    }
}

/// `sbitmap_cleared()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_cleared(sb: *const Sbitmap) -> c_uint {
    unsafe { sbitmap_weight_of(sb, false) }
}

/// `sbitmap_weight()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_weight(sb: *const Sbitmap) -> c_uint {
    unsafe { sbitmap_weight_of(sb, true).wrapping_sub(sbitmap_weight_of(sb, false)) }
}

/// `sbq_calc_wake_batch()`: `clamp_t(unsigned int, min(depth, min_shallow_depth) / SBQ_WAIT_QUEUES, 1, SBQ_WAKE_BATCH)`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbq_calc_wake_batch(sbq: *const SbitmapQueue, depth: c_uint) -> c_uint {
    unsafe {
        let v = depth.min((*sbq).min_shallow_depth) / (SBQ_WAIT_QUEUES as u32);
        v.max(1).min(SBQ_WAKE_BATCH)
    }
}

/// `sbitmap_queue_update_wake_batch()`.
unsafe fn sbitmap_queue_update_wake_batch(sbq: *mut SbitmapQueue, depth: c_uint) {
    unsafe {
        let wake_batch = rust_sbq_calc_wake_batch(sbq, depth);
        if (*sbq).wake_batch != wake_batch {
            wo(core::ptr::addr_of_mut!((*sbq).wake_batch), wake_batch);
        }
    }
}

/// `sbitmap_queue_recalculate_wake_batch()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_recalculate_wake_batch(sbq: *mut SbitmapQueue, users: c_uint) {
    unsafe {
        let depth = (*sbq).sb.depth.wrapping_add(users).wrapping_sub(1) / users;
        let wake_batch = (depth / (SBQ_WAIT_QUEUES as u32)).max(1).min(SBQ_WAKE_BATCH);
        wo(core::ptr::addr_of_mut!((*sbq).wake_batch), wake_batch);
    }
}

/// `sbitmap_queue_resize()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_resize(sbq: *mut SbitmapQueue, depth: c_uint) {
    unsafe {
        sbitmap_queue_update_wake_batch(sbq, depth);
        rust_sbitmap_resize(core::ptr::addr_of_mut!((*sbq).sb), depth);
    }
}

/// `__sbitmap_queue_get_batch()`: allocate up to `nr_tags` consecutive bits from one word; the mask of the bits obtained (0 = none).
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_get_batch(sbq: *mut SbitmapQueue, nr_tags: c_int, offset: *mut c_uint) -> c_ulong {
    unsafe {
        let sb = core::ptr::addr_of_mut!((*sbq).sb);

        if (*sb).round_robin {
            return 0;
        }

        let depth = ro(core::ptr::addr_of!((*sb).depth));
        let hint = update_alloc_hint_before_get(sb, depth);

        let mut index: u64 = (hint >> (*sb).shift) as u64;

        let mut i = 0u32;
        while i < (*sb).map_nr {
            let map = map_at(sb, index as usize);
            let md = map_depth(sb, index as u32);

            sbitmap_deferred_clear(map, 0, 0, false);
            let mut val = ro(word_of(map) as *const u64);
            // sic: upstream compares against (1 << (map_depth - 1)) - 1
            if val != (1u64.wrapping_shl(md.wrapping_sub(1))).wrapping_sub(1) {
                // find_first_zero_bit(&val, map_depth)
                let inv = !val & if md >= 64 { !0u64 } else { (1u64 << md) - 1 };
                let nr: u64 = if inv == 0 { md as u64 } else { inv.trailing_zeros() as u64 };
                if nr + (nr_tags as u64) <= md as u64 {
                    let ptr = AtomicU64::from_ptr(word_of(map));

                    let mut get_mask = ((1u64.wrapping_shl(nr_tags as u32)).wrapping_sub(1)).wrapping_shl(nr as u32);
                    loop {
                        match ptr.compare_exchange(val, get_mask | val, Ordering::SeqCst, Ordering::SeqCst) {
                            Ok(_) => break,
                            Err(cur) => val = cur,
                        }
                    }
                    get_mask = (get_mask & !val).wrapping_shr(nr as u32);
                    if get_mask != 0 {
                        *offset = (nr as u32).wrapping_add((index as u32).wrapping_shl((*sb).shift));
                        update_alloc_hint_after_get(sb, depth, hint, (*offset).wrapping_add(nr_tags as u32).wrapping_sub(1));
                        return get_mask as c_ulong;
                    }
                }
            }

            // Jump to next index.
            index += 1;
            if index >= (*sb).map_nr as u64 {
                index = 0;
            }
            i += 1;
        }

        0
    }
}

/// `sbitmap_queue_get_shallow()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_get_shallow(sbq: *mut SbitmapQueue, shallow_depth: c_uint) -> c_int {
    unsafe {
        rust_sbw_warn_shallow(shallow_depth < (*sbq).min_shallow_depth);
        rust_sbitmap_get_shallow(core::ptr::addr_of_mut!((*sbq).sb), shallow_depth as c_ulong)
    }
}

/// `sbitmap_queue_min_shallow_depth()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_min_shallow_depth(sbq: *mut SbitmapQueue, min_shallow_depth: c_uint) {
    unsafe {
        (*sbq).min_shallow_depth = min_shallow_depth;
        sbitmap_queue_update_wake_batch(sbq, (*sbq).sb.depth);
    }
}

#[inline(always)]
unsafe fn ws_at(sbq: *const SbitmapQueue, i: c_int) -> *mut c_void {
    unsafe { (*sbq).ws.add((i as usize).wrapping_mul(rust_sb_ws_size)) as *mut c_void }
}

/// `sbq_index_inc()`.
#[inline(always)]
fn sbq_index_inc(index: c_int) -> c_int {
    (index + 1) & (SBQ_WAIT_QUEUES - 1)
}

/// `__sbitmap_queue_wake_up()`.
unsafe fn sbitmap_queue_wake_up_inner(sbq: *mut SbitmapQueue, mut nr: c_int) {
    unsafe {
        if (*sbq).ws_active.load(Ordering::Relaxed) == 0 {
            return;
        }

        let mut wake_index = (*sbq).wake_index.load(Ordering::Relaxed);
        let mut i = 0;
        while i < SBQ_WAIT_QUEUES {
            let ws = ws_at(sbq, wake_index);

            // Advance the index before checking the current queue. It improves fairness, by ensuring the queue doesn't need to be fully
            // emptied before trying to wake up from the next one.
            wake_index = sbq_index_inc(wake_index);

            if rust_sbw_waitqueue_active(ws) {
                let woken = rust_sbw_wake_up_nr(ws, nr);
                if woken == nr {
                    break;
                }
                nr -= woken;
            }
            i += 1;
        }

        if wake_index != (*sbq).wake_index.load(Ordering::Relaxed) {
            (*sbq).wake_index.store(wake_index, Ordering::Relaxed);
        }
    }
}

/// `sbitmap_queue_wake_up()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_wake_up(sbq: *mut SbitmapQueue, nr: c_int) {
    unsafe {
        let wake_batch = ro(core::ptr::addr_of!((*sbq).wake_batch));

        if (*sbq).ws_active.load(Ordering::Relaxed) == 0 {
            return;
        }

        (*sbq).completion_cnt.fetch_add(nr, Ordering::Relaxed);
        let mut wakeups = (*sbq).wakeup_cnt.load(Ordering::Relaxed) as u32;

        loop {
            if ((*sbq).completion_cnt.load(Ordering::Relaxed) as u32).wrapping_sub(wakeups) < wake_batch {
                return;
            }
            match (*sbq).wakeup_cnt.compare_exchange(
                wakeups as i32,
                wakeups.wrapping_add(wake_batch) as i32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(cur) => wakeups = cur as u32,
            }
        }

        sbitmap_queue_wake_up_inner(sbq, wake_batch as c_int);
    }
}

/// `sbitmap_update_cpu_hint()`.
#[inline(always)]
unsafe fn sbitmap_update_cpu_hint(sb: *mut Sbitmap, cpu: c_int, tag: c_int) {
    unsafe {
        if !(*sb).round_robin && (tag as c_uint) < (*sb).depth {
            rust_sbw_hint_write_cpu(sb, cpu, tag as c_uint);
        }
    }
}

/// `sbitmap_queue_clear_batch()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_clear_batch(sbq: *mut SbitmapQueue, offset: c_int, tags: *const c_int, nr_tags: c_int) {
    unsafe {
        let sb = core::ptr::addr_of_mut!((*sbq).sb);
        let mut addr: *mut u64 = core::ptr::null_mut();
        let mut mask: u64 = 0;

        rust_sbw_mb_before_atomic();
        let mut i = 0;
        while i < nr_tags {
            let tag = (*tags.add(i as usize)).wrapping_sub(offset);

            // since we're clearing a batch, skip the deferred map
            let this_addr = word_of(map_at(sb, (tag >> (*sb).shift) as usize));
            if addr.is_null() {
                addr = this_addr;
            } else if addr != this_addr {
                AtomicU64::from_ptr(addr).fetch_and(!mask, Ordering::Relaxed);
                mask = 0;
                addr = this_addr;
            }
            mask |= 1u64.wrapping_shl((tag as u32) & 1u32.wrapping_shl((*sb).shift).wrapping_sub(1));
            i += 1;
        }

        if mask != 0 {
            AtomicU64::from_ptr(addr).fetch_and(!mask, Ordering::Relaxed);
        }

        rust_sbw_mb_after_atomic();
        rust_sbitmap_queue_wake_up(sbq, nr_tags);
        sbitmap_update_cpu_hint(sb, rust_sbw_cpu(), (*tags.add((nr_tags - 1) as usize)).wrapping_sub(offset));
    }
}

/// `sbitmap_queue_clear()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_clear(sbq: *mut SbitmapQueue, nr: c_uint, cpu: c_uint) {
    unsafe {
        let sb = core::ptr::addr_of_mut!((*sbq).sb);

        // Once the clear bit is set, the bit may be allocated out. Orders READ/WRITE on the associated instance (such as request of blk_mq)
        // by this bit for avoiding race with re-allocation, and its pair is the memory barrier implied in __sbitmap_get_word. One invariant
        // is that the clear bit has to be zero when the bit is in use.
        rust_sbw_mb_before_atomic();
        rust_sbw_deferred_clear_bit(sb, nr);

        // Pairs with the memory barrier in set_current_state() to ensure the proper ordering of clear_bit_unlock()/waitqueue_active() in the
        // waker and test_and_set_bit_lock()/prepare_to_wait()/finish_wait() in the waiter. See the comment on waitqueue_active().
        rust_sbw_mb_after_atomic();
        rust_sbitmap_queue_wake_up(sbq, 1);
        sbitmap_update_cpu_hint(sb, cpu as c_int, nr as c_int);
    }
}

/// `sbitmap_queue_wake_all()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sbitmap_queue_wake_all(sbq: *mut SbitmapQueue) {
    unsafe {
        // Pairs with the memory barrier in set_current_state() like in sbitmap_queue_wake_up().
        rust_sbw_mb();
        let mut wake_index = (*sbq).wake_index.load(Ordering::Relaxed);
        let mut i = 0;
        while i < SBQ_WAIT_QUEUES {
            let ws = ws_at(sbq, wake_index);

            if rust_sbw_waitqueue_active(ws) {
                rust_sbw_wake_up(ws);
            }

            wake_index = sbq_index_inc(wake_index);
            i += 1;
        }
    }
}
