// SPDX-License-Identifier: GPL-2.0-only

//! The percpu reference count state machine -- the Rust behind `lib/percpu-refcount.c`.
//!
//! Ported from `lib/percpu-refcount.c` (6.18.49). A `percpu_ref` starts as a set of per-CPU counters (get/put are one local add), plus an atomic `count`
//! that carries a bias so it cannot reach zero while the per-CPU parts are still being summed. `percpu_ref_kill()` marks the ref dead and switches it to
//! atomic mode: after an RCU grace period (so every CPU sees the dead flag) the per-CPU counters are summed into the atomic count, the bias is removed, a
//! confirmation callback runs, and from then on the last `put` calls `release()`. `reinit` / `resurrect` / `switch_to_percpu` go the other way. The mode lives
//! in the two low bits of `percpu_count_ptr` (`ATOMIC`, `DEAD`), changed under `percpu_ref_switch_lock`; the fast paths (header inlines) read it with
//! `READ_ONCE`.
//!
//! # Shape
//! * **In Rust**: `percpu_ref_init`, `exit`, `switch_to_atomic` / `_sync` / `switch_to_percpu`, `kill_and_confirm`, `is_zero`, `reinit`, `resurrect`, and the two
//!   RCU callbacks and the three internal mode-switch functions behind them.
//! * **In C** (`percpu_refcount_glue.c`): the exports as thunks (MODVERSIONS fingerprints from the DWARF of the definition), the global lock and wait queue,
//!   and one-line `rust_prw_*` wrappers for everything whose body depends on the configuration: the percpu allocator, the header inlines (`percpu_ref_get`,
//!   `percpu_ref_put`, `__ref_is_percpu`), the spinlock with irq save, `wait_event` / `wake_up_all`, `call_rcu_hurry`, lockdep, the bit-fields of `struct
//!   percpu_ref_data`, and every `WARN` / `BUG` site (the warning now names the glue file: recorded divergence).
//!
//! # The ordering contract (concurrency bar, item 1)
//! * The mode bits are only ever changed under `percpu_ref_switch_lock`. Readers (`__ref_is_percpu`) use `READ_ONCE`.
//! * Switching to atomic: ATOMIC is set, `percpu_ref_get()` takes a reference that is put after the confirmation, and the summing happens in an RCU callback
//!   (`call_rcu_hurry`), i.e. after every CPU that could still be in percpu mode has left its read-side section.
//! * Switching to percpu: the bias is added back, every per-CPU counter is zeroed, and only then is ATOMIC cleared with a RELEASE store (`smp_store_release`),
//!   paired with the `READ_ONCE` in `__ref_is_percpu()`: a CPU that sees percpu mode also sees the zeroing.
//! * The per-CPU sum is taken *before* it is added to `count`, and the bias subtracted in the same `atomic_long_add`.
//!
//! Replaces: lib/percpu-refcount.c (the state machine; the exports, the plumbing and the warning sites stay C)

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr::{null_mut, read_volatile};
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("percpu_refcount_rs.rs: x86-64 little-endian only (64-bit longs, struct layouts)");

const PERCPU_REF_ATOMIC: usize = 1 << 0;
const PERCPU_REF_DEAD: usize = 1 << 1;
const PERCPU_REF_ATOMIC_DEAD: usize = PERCPU_REF_ATOMIC | PERCPU_REF_DEAD;
const PERCPU_REF_FLAG_BITS: u32 = 2;
const PERCPU_REF_INIT_ATOMIC: c_uint = 1 << 0;
const PERCPU_REF_INIT_DEAD: c_uint = 1 << 1;
const PERCPU_REF_ALLOW_REINIT: c_uint = 1 << 2;
const ENOMEM: c_int = 12;

/// `PERCPU_COUNT_BIAS`.
const PERCPU_COUNT_BIAS: u64 = 1u64 << 63;

type RefFunc = Option<unsafe extern "C" fn(*mut PercpuRef)>;

/// `struct percpu_ref`.
#[repr(C)]
pub struct PercpuRef {
    percpu_count_ptr: usize,
    data: *mut PercpuRefData,
}

/// `struct percpu_ref_data` (the two bit-fields at offset 24 are reached through C wrappers; the `rcu_head` follows at 32).
#[repr(C)]
pub struct PercpuRefData {
    count: AtomicI64,
    release: RefFunc,
    confirm_switch: RefFunc,
    bits: [u8; 8],
    rcu: [usize; 2],
    ref_: *mut PercpuRef,
}

const DATA_OFF_RCU: usize = 32;

extern "C" {
    fn rust_prw_lock_irqsave() -> c_ulong;
    fn rust_prw_unlock_irqrestore(flags: c_ulong);
    fn rust_prw_assert_held();
    fn rust_prw_wait_switched(data: *mut PercpuRefData);
    fn rust_prw_wait_switched_sync(r: *mut PercpuRef);
    fn rust_prw_wake_all();
    fn rust_prw_call_rcu_hurry(data: *mut PercpuRefData, cb: unsafe extern "C" fn(*mut c_void));
    fn rust_prw_alloc_percpu(gfp: c_uint) -> usize;
    fn rust_prw_free_percpu(p: usize);
    fn rust_prw_kzalloc_data(gfp: c_uint) -> *mut PercpuRefData;
    fn rust_prw_kfree(p: *mut c_void);
    fn rust_prw_sum_percpu(p: usize) -> c_ulong;
    fn rust_prw_zero_percpu(p: usize);
    fn rust_prw_get(r: *mut PercpuRef);
    fn rust_prw_put(r: *mut PercpuRef);
    fn rust_prw_is_percpu(r: *mut PercpuRef) -> bool;
    fn rust_prw_set_force_atomic(data: *mut PercpuRefData, v: bool);
    fn rust_prw_get_force_atomic(data: *mut PercpuRefData) -> bool;
    fn rust_prw_set_allow_reinit(data: *mut PercpuRefData, v: bool);
    fn rust_prw_get_allow_reinit(data: *mut PercpuRefData) -> bool;
    fn rust_prw_warn_exit_switching(cond: bool);
    fn rust_prw_check_underflow(data: *mut PercpuRefData);
    fn rust_prw_bug_no_percpu(cond: bool);
    fn rust_prw_warn_no_reinit(cond: bool) -> bool;
    fn rust_prw_warn_kill_twice(r: *mut PercpuRef, cond: bool);
    fn rust_prw_warn_not_zero(cond: bool);
    fn rust_prw_warn_not_dying(cond: bool);
    fn rust_prw_warn_percpu(cond: bool);
}

#[inline(always)]
unsafe fn ro<T: Copy>(p: *const T) -> T {
    unsafe { read_volatile(p) }
}

/// `percpu_count_ptr()`.
#[inline(always)]
unsafe fn percpu_count_ptr(r: *const PercpuRef) -> usize {
    unsafe { (*r).percpu_count_ptr & !PERCPU_REF_ATOMIC_DEAD }
}

/// `percpu_ref_is_dying()`.
#[inline(always)]
unsafe fn is_dying(r: *const PercpuRef) -> bool {
    unsafe { (*r).percpu_count_ptr & PERCPU_REF_DEAD != 0 }
}

/// `percpu_ref_init()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_init(r: *mut PercpuRef, release: RefFunc, flags: c_uint, gfp: c_uint) -> c_int {
    unsafe {
        let mut start_count: u64 = 0;

        (*r).percpu_count_ptr = rust_prw_alloc_percpu(gfp);
        if (*r).percpu_count_ptr == 0 {
            return -ENOMEM;
        }

        let data = rust_prw_kzalloc_data(gfp);
        if data.is_null() {
            rust_prw_free_percpu((*r).percpu_count_ptr);
            (*r).percpu_count_ptr = 0;
            return -ENOMEM;
        }

        rust_prw_set_force_atomic(data, flags & PERCPU_REF_INIT_ATOMIC != 0);
        rust_prw_set_allow_reinit(data, flags & PERCPU_REF_ALLOW_REINIT != 0);

        if flags & (PERCPU_REF_INIT_ATOMIC | PERCPU_REF_INIT_DEAD) != 0 {
            (*r).percpu_count_ptr |= PERCPU_REF_ATOMIC;
            rust_prw_set_allow_reinit(data, true);
        } else {
            start_count = start_count.wrapping_add(PERCPU_COUNT_BIAS);
        }

        if flags & PERCPU_REF_INIT_DEAD != 0 {
            (*r).percpu_count_ptr |= PERCPU_REF_DEAD;
        } else {
            start_count = start_count.wrapping_add(1);
        }

        (*data).count.store(start_count as i64, Ordering::Relaxed);

        (*data).release = release;
        (*data).confirm_switch = None;
        (*data).ref_ = r;
        (*r).data = data;
        0
    }
}

/// `__percpu_ref_exit()`.
unsafe fn percpu_ref_exit_inner(r: *mut PercpuRef) {
    unsafe {
        let percpu_count = percpu_count_ptr(r);

        if percpu_count != 0 {
            // non-NULL confirm_switch indicates switching in progress
            rust_prw_warn_exit_switching(!(*r).data.is_null() && (*(*r).data).confirm_switch.is_some());
            rust_prw_free_percpu(percpu_count);
            (*r).percpu_count_ptr = PERCPU_REF_ATOMIC_DEAD;
        }
    }
}

/// `percpu_ref_exit()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_exit(r: *mut PercpuRef) {
    unsafe {
        let data = (*r).data;

        percpu_ref_exit_inner(r);
        if data.is_null() {
            return;
        }

        let flags = rust_prw_lock_irqsave();
        (*r).percpu_count_ptr |= ((*(*r).data).count.load(Ordering::Relaxed) as usize) << PERCPU_REF_FLAG_BITS;
        (*r).data = null_mut();
        rust_prw_unlock_irqrestore(flags);

        rust_prw_kfree(data as *mut c_void);
    }
}

/// `container_of(rcu, struct percpu_ref_data, rcu)`: the `rcu_head` is at offset 32 (asserted in the glue).
#[inline(always)]
unsafe fn data_of(rcu: *mut c_void) -> *mut PercpuRefData {
    unsafe { (rcu as *mut u8).sub(DATA_OFF_RCU) as *mut PercpuRefData }
}

/// `percpu_ref_call_confirm_rcu()`.
unsafe fn percpu_ref_call_confirm_rcu(rcu: *mut c_void) {
    unsafe {
        let data = data_of(rcu);
        let r = (*data).ref_;

        if let Some(f) = (*data).confirm_switch {
            f(r);
        }
        (*data).confirm_switch = None;

        rust_prw_wake_all();

        if !rust_prw_get_allow_reinit(data) {
            percpu_ref_exit_inner(r);
        }

        // drop ref from percpu_ref_switch_to_atomic()
        rust_prw_put(r);
    }
}

/// `percpu_ref_switch_to_atomic_rcu()`: the RCU callback that folds the per-CPU counts into the atomic count.
unsafe extern "C" fn percpu_ref_switch_to_atomic_rcu(rcu: *mut c_void) {
    unsafe {
        let data = data_of(rcu);
        let r = (*data).ref_;
        let percpu_count = percpu_count_ptr(r);

        let count = rust_prw_sum_percpu(percpu_count) as u64;

        // It's crucial that we sum the percpu counters _before_ adding the sum to &ref->count; since gets could be happening on one cpu while puts
        // happen on another, adding a single cpu's count could cause @ref->count to hit 0 before we've got a consistent value - but the sum of all the
        // counts will be consistent and correct. Subtracting the bias value then has to happen _after_ adding count to &ref->count; we need the bias
        // value to prevent &ref->count from reaching 0 before we add the percpu counts. But doing it at the same time is equivalent and saves us
        // atomic operations:
        (*data).count.fetch_add(count.wrapping_sub(PERCPU_COUNT_BIAS) as i64, Ordering::Relaxed);

        rust_prw_check_underflow(data);

        // @ref is viewed as dead on all CPUs, send out switch confirmation
        percpu_ref_call_confirm_rcu(rcu);
    }
}

unsafe extern "C" fn percpu_ref_noop_confirm_switch(_r: *mut PercpuRef) {}

/// `__percpu_ref_switch_to_atomic()`.
unsafe fn percpu_ref_switch_to_atomic_inner(r: *mut PercpuRef, confirm_switch: RefFunc) {
    unsafe {
        if (*r).percpu_count_ptr & PERCPU_REF_ATOMIC != 0 {
            if let Some(f) = confirm_switch {
                f(r);
            }
            return;
        }

        // switching from percpu to atomic
        (*r).percpu_count_ptr |= PERCPU_REF_ATOMIC;

        // Non-NULL ->confirm_switch is used to indicate that switching is in progress. Use noop one if unspecified.
        (*(*r).data).confirm_switch = Some(confirm_switch.unwrap_or(percpu_ref_noop_confirm_switch));

        rust_prw_get(r); // put after confirmation
        rust_prw_call_rcu_hurry((*r).data, percpu_ref_switch_to_atomic_rcu);
    }
}

/// `__percpu_ref_switch_to_percpu()`.
unsafe fn percpu_ref_switch_to_percpu_inner(r: *mut PercpuRef) {
    unsafe {
        let percpu_count = percpu_count_ptr(r);

        rust_prw_bug_no_percpu(percpu_count == 0);

        if (*r).percpu_count_ptr & PERCPU_REF_ATOMIC == 0 {
            return;
        }

        if rust_prw_warn_no_reinit(!rust_prw_get_allow_reinit((*r).data)) {
            return;
        }

        (*(*r).data).count.fetch_add(PERCPU_COUNT_BIAS as i64, Ordering::Relaxed);

        // Restore per-cpu operation. smp_store_release() is paired with READ_ONCE() in __ref_is_percpu() and guarantees that the zeroing is visible to
        // all percpu accesses which can see the following __PERCPU_REF_ATOMIC clearing.
        rust_prw_zero_percpu(percpu_count);

        let p = core::ptr::addr_of_mut!((*r).percpu_count_ptr);
        AtomicUsize::from_ptr(p).store(ro(p) & !PERCPU_REF_ATOMIC, Ordering::Release);
    }
}

/// `__percpu_ref_switch_mode()`.
unsafe fn percpu_ref_switch_mode(r: *mut PercpuRef, confirm_switch: RefFunc) {
    unsafe {
        let data = (*r).data;

        rust_prw_assert_held();

        // If the previous ATOMIC switching hasn't finished yet, wait for its completion. If the caller ensures that ATOMIC switching isn't in progress,
        // this function can be called from any context.
        rust_prw_wait_switched(data);

        if rust_prw_get_force_atomic(data) || is_dying(r) {
            percpu_ref_switch_to_atomic_inner(r, confirm_switch);
        } else {
            percpu_ref_switch_to_percpu_inner(r);
        }
    }
}

/// `percpu_ref_switch_to_atomic()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_switch_to_atomic(r: *mut PercpuRef, confirm_switch: RefFunc) {
    unsafe {
        let flags = rust_prw_lock_irqsave();

        rust_prw_set_force_atomic((*r).data, true);
        percpu_ref_switch_mode(r, confirm_switch);

        rust_prw_unlock_irqrestore(flags);
    }
}

/// `percpu_ref_switch_to_atomic_sync()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_switch_to_atomic_sync(r: *mut PercpuRef) {
    unsafe {
        rust_percpu_ref_switch_to_atomic(r, None);
        rust_prw_wait_switched_sync(r);
    }
}

/// `percpu_ref_switch_to_percpu()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_switch_to_percpu(r: *mut PercpuRef) {
    unsafe {
        let flags = rust_prw_lock_irqsave();

        rust_prw_set_force_atomic((*r).data, false);
        percpu_ref_switch_mode(r, None);

        rust_prw_unlock_irqrestore(flags);
    }
}

/// `percpu_ref_kill_and_confirm()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_kill_and_confirm(r: *mut PercpuRef, confirm_kill: RefFunc) {
    unsafe {
        let flags = rust_prw_lock_irqsave();

        rust_prw_warn_kill_twice(r, is_dying(r));
        (*r).percpu_count_ptr |= PERCPU_REF_DEAD;

        percpu_ref_switch_mode(r, confirm_kill);

        rust_prw_put(r);

        rust_prw_unlock_irqrestore(flags);
    }
}

/// `percpu_ref_is_zero()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_is_zero(r: *mut PercpuRef) -> bool {
    unsafe {
        if rust_prw_is_percpu(r) {
            return false;
        }

        // protect us from being destroyed
        let flags = rust_prw_lock_irqsave();
        let count: u64 = if !(*r).data.is_null() {
            (*(*r).data).count.load(Ordering::Relaxed) as u64
        } else {
            ((*r).percpu_count_ptr >> PERCPU_REF_FLAG_BITS) as u64
        };
        rust_prw_unlock_irqrestore(flags);

        count == 0
    }
}

/// `percpu_ref_reinit()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_reinit(r: *mut PercpuRef) {
    unsafe {
        rust_prw_warn_not_zero(!rust_percpu_ref_is_zero(r));
        rust_percpu_ref_resurrect(r);
    }
}

/// `percpu_ref_resurrect()`.
#[no_mangle]
pub unsafe extern "C" fn rust_percpu_ref_resurrect(r: *mut PercpuRef) {
    unsafe {
        let flags = rust_prw_lock_irqsave();

        rust_prw_warn_not_dying(!is_dying(r));
        rust_prw_warn_percpu(rust_prw_is_percpu(r));

        (*r).percpu_count_ptr &= !PERCPU_REF_DEAD;
        rust_prw_get(r);
        percpu_ref_switch_mode(r, None);

        rust_prw_unlock_irqrestore(flags);
    }
}
