// SPDX-License-Identifier: GPL-2.0

//! Floating proportions with flexible aging period -- the Rust behind
//! `lib/flex_proportions.c`. None of its eight functions is `EXPORT_SYMBOL`
//! (confirmed by reading the pristine C), so no kabi pin applies -- nothing
//! to preserve for external module compatibility, only for whatever calls
//! it from elsewhere in this same `vmlinux` (writeback throttling).
//!
//! Four separate primitive classes are bundled in this one file; see
//! `logs/porting-hazards.md`, "spinlock + IRQ state", for the full account
//! of why each is handled the way it is:
//!
//! 1. **`raw_spin_lock_irqsave`/`unlock_irqrestore`/`lock_init`** stay a
//!    retained C thunk (`lib/flex_proportions.c`,
//!    `rust_flexprop_lock_irqsave`/`unlock_irqrestore`/`lock_init`) --
//!    same reason as `lib/ratelimit.c`'s thunks: the real macros carry
//!    `preempt_disable()`/`preempt_enable()`, lockdep's `spin_acquire()`/
//!    `spin_release()`, and `LOCK_CONTENDED()`'s dispatch into
//!    `queued_spin_lock_slowpath()` (`kernel/locking/qspinlock.c`, a
//!    different subsystem). Reimplementing preempt-count and the
//!    qspinlock protocol to port this file would be disproportionate.
//! 2. **`local_irq_save`/`local_irq_restore`**, used standalone in
//!    `fprop_new_period()` (not wrapped in a spinlock), reproduced
//!    DIRECTLY in Rust via `core::arch::asm!` -- `CONFIG_TRACE_IRQFLAGS`
//!    is off in both project configs, so these reduce to bare
//!    `arch_local_irq_save()`/`arch_local_irq_restore()`
//!    (`arch/x86/include/asm/irqflags.h`): plain `pushf`/`pop`, `cli`,
//!    `sti`, no exception table, no goto -- a real Rust mechanism exists
//!    (stable inline asm), so it is used, matching the real functions'
//!    exact instruction sequence and operand/clobber shape below rather
//!    than adding C surface purely for consistency with (1).
//! 3. **`seqcount_t`'s barrier operations** (`write_seqcount_begin`/`end`,
//!    `read_seqcount_begin`, `read_seqcount_retry`) move straight to
//!    Rust: built from `smp_wmb()`/`smp_rmb()`/`smp_load_acquire()`,
//!    which on this x86-64 build are ALL plain compiler barriers or a
//!    `READ_ONCE` + compiler barrier -- confirmed by reading
//!    `arch/x86/include/asm/barrier.h` directly (`__smp_wmb() ==
//!    barrier()`, `__dma_rmb() == barrier()` backing `__smp_rmb()`,
//!    `__smp_load_acquire(p) == READ_ONCE(*p); barrier();`) -- no real
//!    fence instruction, no goto. Reproduced with `read_volatile`/
//!    `write_volatile` (matching this project's established
//!    `dynamic_queue_limits_rs.rs::jiffies()` convention for a plain
//!    volatile-accessed field) plus `core::sync::atomic::compiler_fence`
//!    at each `smp_wmb()`/`smp_rmb()` call site, in the SAME order the C
//!    issues them (`do_raw_write_seqcount_begin` increments THEN
//!    barriers; `do_raw_write_seqcount_end` barriers THEN increments;
//!    `read_seqcount_retry` barriers THEN reads).
//! 4. **`percpu_counter`'s real functions** (`percpu_counter_add_batch`,
//!    `percpu_counter_set`, `__percpu_counter_sum`,
//!    `__percpu_counter_init_many`, `percpu_counter_destroy_many`) are
//!    real, out-of-line, non-`static` functions declared in
//!    `include/linux/percpu_counter.h` -- called directly via
//!    `extern "C"`, no thunk needed, same shape as `mpicoder_rs.rs`'s
//!    `sg_miter_*` calls. `lib/percpu_counter.c` itself stays fully C,
//!    untouched. The `static inline` wrappers this file's C used
//!    (`percpu_counter_add`/`sum`/`read`/`read_positive`) are one-line
//!    reproductions calling those real functions.
//!
//! # Struct layouts, verified against the live `build-full` DWARF
//!
//! `pahole -C percpu_counter`: 40 bytes -- `lock` (`raw_spinlock_t`, 4
//! bytes) @0, a 4-byte compiler-inserted hole, `count` (`s64`) @8,
//! `list` (`struct list_head`, 16 bytes -- `CONFIG_HOTPLUG_CPU=y` in
//! both project configs, so always present) @16, `counters`
//! (`s32 __percpu *`, just an address value, never dereferenced here)
//! @32. `pahole -C fprop_global`/`fprop_local_percpu`: both 48 bytes,
//! `events` (the `percpu_counter` above) @0, then `period`/`sequence` or
//! `period`/`lock` @40/@44. `lock_class_key` (the macro-generated
//! per-callsite key `percpu_counter_init()` needs) is 0 bytes in this
//! config (`CONFIG_LOCKDEP` off) -- a ZST, same shape as
//! `mpicoder_rs.rs`'s `ScatterlistOpaque`.

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::sync::atomic::{compiler_fence, Ordering};

const FPROP_FRAC_SHIFT: u32 = 10;
/// `(1UL << FPROP_FRAC_SHIFT)` -- `unsigned long` in the real header, not
/// `int`; every comparison/arithmetic use below matches that type.
const FPROP_FRAC_BASE: c_ulong = 1 << FPROP_FRAC_SHIFT;

/// See this file's module doc, primitive class 1. Opaque and
/// deliberately not `Mirrors`-annotated -- same reasoning as
/// `ratelimit_rs.rs`'s `RawSpinlockT`.
#[repr(C)]
pub struct RawSpinlockT {
    /// Opaque -- see this struct's own doc comment.
    pub bits: u32,
}

/// `struct list_head` (`include/linux/types.h`): two pointers, never
/// dereferenced here -- only round-tripped as part of `PercpuCounter`'s
/// byte-for-byte size, same reasoning as `RawSpinlockT`.
#[repr(C)]
pub struct ListHead {
    /// Opaque -- see this struct's own doc comment.
    pub next: *mut c_void,
    /// Opaque -- see this struct's own doc comment.
    pub prev: *mut c_void,
}

/// `struct percpu_counter` (`include/linux/percpu_counter.h`), sized but
/// deliberately opaque past its own doc comment -- this file never reads
/// or writes any of its fields directly, only passes `&mut events` to
/// the real, out-of-line `percpu_counter_*` functions. Not
/// `Mirrors`-annotated for the same reason as `RawSpinlockT`/`ListHead`:
/// `rig/layout-check.sh` would try to pair it with `percpu_counter` and
/// (correctly) flag the opaque `counters` field's type spelling as a
/// mismatch -- this struct's contract is its SIZE, not its field types.
#[repr(C)]
pub struct PercpuCounter {
    /// Opaque -- see this struct's own doc comment.
    pub lock: RawSpinlockT,
    /// Opaque -- see this struct's own doc comment.
    pub count: i64,
    /// Opaque -- see this struct's own doc comment.
    pub list: ListHead,
    /// Opaque -- see this struct's own doc comment.
    pub counters: *mut i32,
}

/// `struct lock_class_key` -- zero-sized on this build (`CONFIG_LOCKDEP`
/// off), matching `pahole -C lock_class_key` directly. `static`s of this
/// type still get a real, stable, unique address, which is all
/// `__percpu_counter_init_many()` needs from it when lockdep is
/// compiled out.
#[repr(C)]
pub struct LockClassKey {
    _never_constructed: [u8; 0],
}
unsafe impl Sync for LockClassKey {}

/// `seqcount_t` (`include/linux/seqlock_types.h`): 4 bytes,
/// `CONFIG_DEBUG_LOCK_ALLOC` off in both project configs so no embedded
/// `lockdep_map`. Deliberately `pub sequence`, plain (not atomic) --
/// see this file's module doc, primitive class 3, for why every access
/// goes through explicit `read_volatile`/`write_volatile` plus
/// `compiler_fence` rather than an `AtomicU32`'s own ordering: the C
/// issues the read and the barrier as two separate steps, and this
/// mirrors that structure rather than folding it into one atomic op.
#[repr(C)]
pub struct SeqcountT {
    /// Odd while a writer is inside `write_seqcount_begin()`/`end()`;
    /// even otherwise. Bumped by exactly one on each call.
    pub sequence: c_uint,
}

/// Mirrors `struct fprop_global` (`include/linux/flex_proportions.h`).
#[repr(C)]
pub struct FpropGlobal {
    /// Number of events in the current period.
    pub events: PercpuCounter,
    /// Current period.
    pub period: c_uint,
    /// Synchronization with period transitions.
    pub sequence: SeqcountT,
}

/// Mirrors `struct fprop_local_percpu` (`include/linux/flex_proportions.h`).
#[repr(C)]
pub struct FpropLocalPercpu {
    /// The local events counter.
    pub events: PercpuCounter,
    /// Period in which we last updated events.
    pub period: c_uint,
    /// Protects `period` and the numerator.
    pub lock: RawSpinlockT,
}

unsafe extern "C" {
    #[link_name = "nr_cpu_ids"]
    static NR_CPU_IDS: c_uint;

    /* lib/flex_proportions.c. */
    fn rust_flexprop_lock_irqsave(lock: *mut RawSpinlockT, flags: *mut c_ulong);
    fn rust_flexprop_unlock_irqrestore(lock: *mut RawSpinlockT, flags: c_ulong);
    fn rust_flexprop_lock_init(lock: *mut RawSpinlockT);

    /* include/linux/percpu_counter.h -- real, out-of-line, non-static. */
    fn __percpu_counter_init_many(
        fbc: *mut PercpuCounter,
        amount: i64,
        gfp: c_uint,
        nr_counters: c_uint,
        key: *mut LockClassKey,
    ) -> c_int;
    fn percpu_counter_destroy_many(fbc: *mut PercpuCounter, nr_counters: c_uint);
    fn percpu_counter_set(fbc: *mut PercpuCounter, amount: i64);
    fn percpu_counter_add_batch(fbc: *mut PercpuCounter, amount: i64, batch: i32);
    fn __percpu_counter_sum(fbc: *mut PercpuCounter) -> i64;
}

// ---- percpu_counter: static-inline wrappers over the real exports ----

unsafe fn percpu_counter_init(fbc: *mut PercpuCounter, amount: i64, gfp: c_uint) -> c_int {
    static KEY: LockClassKey = LockClassKey {
        _never_constructed: [],
    };
    unsafe { __percpu_counter_init_many(fbc, amount, gfp, 1, &KEY as *const _ as *mut _) }
}

unsafe fn percpu_counter_destroy(fbc: *mut PercpuCounter) {
    unsafe { percpu_counter_destroy_many(fbc, 1) };
}

extern "C" {
    #[link_name = "percpu_counter_batch"]
    static PERCPU_COUNTER_BATCH: c_int;
}

unsafe fn percpu_counter_add(fbc: *mut PercpuCounter, amount: i64) {
    let batch = unsafe { core::ptr::read_volatile(&raw const PERCPU_COUNTER_BATCH) };
    unsafe { percpu_counter_add_batch(fbc, amount, batch) };
}

unsafe fn percpu_counter_sum(fbc: *mut PercpuCounter) -> i64 {
    unsafe { __percpu_counter_sum(fbc) }
}

unsafe fn percpu_counter_read(fbc: *const PercpuCounter) -> i64 {
    unsafe { core::ptr::read_volatile(&raw const (*fbc).count) }
}

unsafe fn percpu_counter_read_positive(fbc: *const PercpuCounter) -> i64 {
    let ret = unsafe { core::ptr::read_volatile(&raw const (*fbc).count) };
    if ret >= 0 {
        ret
    } else {
        0
    }
}

// ---- seqcount_t: straight to Rust (primitive class 3) ----

unsafe fn write_seqcount_begin(s: *mut SeqcountT) {
    unsafe {
        let seq = core::ptr::read_volatile(&raw const (*s).sequence);
        core::ptr::write_volatile(&raw mut (*s).sequence, seq.wrapping_add(1));
    }
    compiler_fence(Ordering::SeqCst);
}

unsafe fn write_seqcount_end(s: *mut SeqcountT) {
    compiler_fence(Ordering::SeqCst);
    unsafe {
        let seq = core::ptr::read_volatile(&raw const (*s).sequence);
        core::ptr::write_volatile(&raw mut (*s).sequence, seq.wrapping_add(1));
    }
}

unsafe fn read_seqcount_begin(s: *const SeqcountT) -> c_uint {
    loop {
        let seq = unsafe { core::ptr::read_volatile(&raw const (*s).sequence) };
        compiler_fence(Ordering::SeqCst);
        if seq & 1 == 0 {
            return seq;
        }
        core::hint::spin_loop();
    }
}

unsafe fn read_seqcount_retry(s: *const SeqcountT, start: c_uint) -> bool {
    compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::read_volatile(&raw const (*s).sequence) != start }
}

// ---- local_irq_save/restore: straight to Rust (primitive class 2) ----

/// `native_save_fl()` (`arch/x86/include/asm/irqflags.h`): reads the
/// whole flags register. Operand: `out(reg)` -- the real C uses `"=rm"`
/// (register-or-memory), but stable Rust asm! has no memory-operand
/// class; `reg` is always valid wherever `rm` is (a register is a
/// solution to "register or memory"), so this is a narrowing of the
/// allowed operand class, not a semantic change. No `nomem`/`nostack`/
/// `preserves_flags`: this reads the flags register itself, and the
/// real C's own `"memory"` clobber makes it a full compiler barrier,
/// matched here by asm!'s default (memory-clobbering, stack-using)
/// behaviour when no `options()` narrows it.
#[inline(always)]
unsafe fn native_save_fl() -> c_ulong {
    let flags: c_ulong;
    unsafe {
        core::arch::asm!("pushf", "pop {0}", out(reg) flags);
    }
    flags
}

/// `native_irq_disable()`: `cli`. Modifies EFLAGS.IF, so NOT
/// `preserves_flags`; the real C's `"memory"` clobber is matched by
/// asm!'s default.
#[inline(always)]
unsafe fn native_irq_disable() {
    unsafe {
        core::arch::asm!("cli");
    }
}

/// `native_irq_enable()`: `sti`. Same clobber reasoning as
/// `native_irq_disable()`.
#[inline(always)]
unsafe fn native_irq_enable() {
    unsafe {
        core::arch::asm!("sti");
    }
}

const X86_EFLAGS_IF: c_ulong = 1 << 9;

/// `arch_local_irq_save()`: save flags, THEN disable -- matching the
/// real function's own order (`flags = arch_local_save_flags();
/// arch_local_irq_disable();`) exactly, not just its net effect.
#[inline(always)]
unsafe fn arch_local_irq_save() -> c_ulong {
    let flags = unsafe { native_save_fl() };
    unsafe { native_irq_disable() };
    flags
}

/// `arch_local_irq_restore(flags)`: re-enable only if IF was set before
/// (`!arch_irqs_disabled_flags(flags)` == `flags & X86_EFLAGS_IF`).
#[inline(always)]
unsafe fn arch_local_irq_restore(flags: c_ulong) {
    if flags & X86_EFLAGS_IF != 0 {
        unsafe { native_irq_enable() };
    }
}

// ---- fls/ilog2/div_u64: plain arithmetic, no asm needed ----

/// `fls(x)`: position of the highest set bit, 1-indexed, 0 if `x == 0`.
/// `32 - x.leading_zeros()` gives exactly this for every `u32` including
/// 0 (`leading_zeros(0) == 32`), matching the real `bsr`-based
/// `fls()` (`arch/x86/include/asm/bitops.h`) without needing the asm
/// itself -- `leading_zeros()` already compiles to the same instruction.
#[inline(always)]
fn fls(x: u32) -> i32 {
    (32 - x.leading_zeros()) as i32
}

/// `PROP_BATCH`, `8*(1+ilog2(nr_cpu_ids))`. `ilog2()` on a non-constant
/// `u32` is `fls(n) - 1` (`include/linux/log2.h`'s `__ilog2_u32`).
#[inline(always)]
fn prop_batch() -> i32 {
    let nr_cpu_ids = unsafe { core::ptr::read_volatile(&raw const NR_CPU_IDS) };
    8 * (1 + (fls(nr_cpu_ids) - 1))
}

/// `fprop_global_init()`.
///
/// # Safety
/// `p` must be a valid, writable `*mut FpropGlobal`.
#[no_mangle]
pub unsafe extern "C" fn fprop_global_init(p: *mut FpropGlobal, gfp: c_uint) -> c_int {
    unsafe {
        (*p).period = 0;
        // Use 1 to avoid dealing with periods with 0 events...
        let err = percpu_counter_init(&raw mut (*p).events, 1, gfp);
        if err != 0 {
            return err;
        }
        (*p).sequence.sequence = 0;
    }
    0
}

/// `fprop_global_destroy()`.
///
/// # Safety
/// `p` must be a valid `*mut FpropGlobal` previously initialized by
/// [`fprop_global_init`].
#[no_mangle]
pub unsafe extern "C" fn fprop_global_destroy(p: *mut FpropGlobal) {
    unsafe { percpu_counter_destroy(&raw mut (*p).events) };
}

/// `fprop_new_period()`. It is up to the caller to make sure period
/// transitions cannot happen in parallel.
///
/// # Safety
/// `p` must be a valid, initialized `*mut FpropGlobal`.
#[no_mangle]
pub unsafe extern "C" fn fprop_new_period(p: *mut FpropGlobal, periods: c_int) -> bool {
    let events = unsafe { percpu_counter_sum(&raw mut (*p).events) };

    // Don't do anything if there are no events.
    if events <= 1 {
        return false;
    }

    let flags = unsafe { arch_local_irq_save() };
    unsafe { fprop_new_period_locked(p, periods, events) };
    unsafe { arch_local_irq_restore(flags) };

    true
}

/// The `write_seqcount_begin()`/`...`/`write_seqcount_end()` body of
/// `fprop_new_period()`, split out so the differential harness
/// (`port/test/flex_proportions/`) can call it directly -- the real
/// `arch_local_irq_save()`/`arch_local_irq_restore()` execute genuine
/// `cli`/`sti`, privileged instructions that fault immediately in
/// userspace, so nothing outside the kernel can call `fprop_new_period()`
/// itself. `fprop_new_period()` still calls this in exactly the same
/// place its own body used to occupy -- purely an internal split for
/// testability, not an observable change (GOALS.md §5: the C is a
/// reference for interface/layout/write-order, free to diverge
/// internally). A real, `#[no_mangle]` symbol (not `#[allow(dead_code)]`
/// or `#[cfg(test)]`-gated) for the same reason
/// `dynamic_queue_limits.c`'s `__dql_completed_bug_on()` is: something
/// the differential can link against and call, compiled from the exact
/// file the kernel builds.
///
/// # Safety
/// `p` must be a valid, initialized `*mut FpropGlobal`; `events` must be
/// the value `percpu_counter_sum(&p->events)` returned, still `> 1`, with
/// nothing else touching `*p` concurrently (the real caller holds this
/// via `arch_local_irq_save()`).
#[no_mangle]
pub unsafe extern "C" fn fprop_new_period_locked(p: *mut FpropGlobal, periods: c_int, mut events: i64) {
    unsafe { write_seqcount_begin(&raw mut (*p).sequence) };
    if periods < 64 {
        events -= events >> periods;
    }
    // Use addition to avoid losing events happening between sum and set.
    unsafe { percpu_counter_add(&raw mut (*p).events, -events) };
    unsafe { (*p).period = (*p).period.wrapping_add(periods as c_uint) };
    unsafe { write_seqcount_end(&raw mut (*p).sequence) };
}

/// `fprop_local_init_percpu()`.
///
/// # Safety
/// `pl` must be a valid, writable `*mut FpropLocalPercpu`.
#[no_mangle]
pub unsafe extern "C" fn fprop_local_init_percpu(pl: *mut FpropLocalPercpu, gfp: c_uint) -> c_int {
    unsafe {
        let err = percpu_counter_init(&raw mut (*pl).events, 0, gfp);
        if err != 0 {
            return err;
        }
        (*pl).period = 0;
        rust_flexprop_lock_init(&raw mut (*pl).lock);
    }
    0
}

/// `fprop_local_destroy_percpu()`.
///
/// # Safety
/// `pl` must be a valid `*mut FpropLocalPercpu` previously initialized
/// by [`fprop_local_init_percpu`].
#[no_mangle]
pub unsafe extern "C" fn fprop_local_destroy_percpu(pl: *mut FpropLocalPercpu) {
    unsafe { percpu_counter_destroy(&raw mut (*pl).events) };
}

unsafe fn fprop_reflect_period_percpu(p: *mut FpropGlobal, pl: *mut FpropLocalPercpu) {
    let period = unsafe { core::ptr::read_volatile(&raw const (*p).period) };

    // Fast path - period didn't change.
    if unsafe { (*pl).period } == period {
        return;
    }

    let mut flags: c_ulong = 0;
    unsafe { rust_flexprop_lock_irqsave(&raw mut (*pl).lock, &mut flags) };

    // Someone updated pl->period while we were spinning? Plain unsigned
    // comparison -- no wraparound trick in the real C here, so none here
    // either.
    if unsafe { (*pl).period } >= period {
        unsafe { rust_flexprop_unlock_irqrestore(&raw mut (*pl).lock, flags) };
        return;
    }

    // Aging zeroed our fraction? `period - pl->period` is safe as plain
    // (non-wrapping) unsigned subtraction here: the check just above
    // already established `pl->period < period`. BITS_PER_LONG is 64 on
    // this LP64 target -- note `period`/`pl->period` are only 32 bits
    // wide themselves, so this comparison is real (a 32-bit difference
    // is not always under 64), not vacuous.
    const BITS_PER_LONG: u32 = 64;
    let age = period - unsafe { (*pl).period };
    if age < BITS_PER_LONG {
        let mut val = unsafe { percpu_counter_read(&raw const (*pl).events) };
        let nr_cpu_ids = unsafe { core::ptr::read_volatile(&raw const NR_CPU_IDS) } as i64;

        if val < nr_cpu_ids * prop_batch() as i64 {
            val = unsafe { percpu_counter_sum(&raw mut (*pl).events) };
        }

        unsafe {
            percpu_counter_add_batch(
                &raw mut (*pl).events,
                -val + (val >> age),
                prop_batch(),
            )
        };
    } else {
        unsafe { percpu_counter_set(&raw mut (*pl).events, 0) };
    }
    unsafe { (*pl).period = period };
    unsafe { rust_flexprop_unlock_irqrestore(&raw mut (*pl).lock, flags) };
}

/// `__fprop_add_percpu()`. Event of type `pl` happened.
///
/// # Safety
/// `p`/`pl` must be valid, initialized, matching `*mut` pointers.
#[no_mangle]
pub unsafe extern "C" fn __fprop_add_percpu(p: *mut FpropGlobal, pl: *mut FpropLocalPercpu, nr: c_long) {
    unsafe { fprop_reflect_period_percpu(p, pl) };
    unsafe { percpu_counter_add_batch(&raw mut (*pl).events, nr as i64, prop_batch()) };
    unsafe { percpu_counter_add(&raw mut (*p).events, nr as i64) };
}

/// `fprop_fraction_percpu()`.
///
/// # Safety
/// `p`/`pl` must be valid, initialized; `numerator`/`denominator` must
/// be valid, writable `*mut c_ulong`.
#[no_mangle]
pub unsafe extern "C" fn fprop_fraction_percpu(
    p: *mut FpropGlobal,
    pl: *mut FpropLocalPercpu,
    numerator: *mut c_ulong,
    denominator: *mut c_ulong,
) {
    let (mut num, mut den);

    loop {
        let seq = unsafe { read_seqcount_begin(&raw const (*p).sequence) };
        unsafe { fprop_reflect_period_percpu(p, pl) };
        num = unsafe { percpu_counter_read_positive(&raw const (*pl).events) };
        den = unsafe { percpu_counter_read_positive(&raw const (*p).events) };
        if !unsafe { read_seqcount_retry(&raw const (*p).sequence, seq) } {
            break;
        }
    }

    // Make fraction <= 1 and denominator > 0 even in presence of percpu
    // counter errors.
    if den <= num {
        den = if num != 0 { num } else { 1 };
    }
    unsafe {
        *denominator = den as c_ulong;
        *numerator = num as c_ulong;
    }
}

/// `__fprop_add_percpu_max()`. Like [`__fprop_add_percpu`] except that
/// the event is counted only if the given type has fraction smaller
/// than `max_frac / FPROP_FRAC_BASE`.
///
/// # Safety
/// Same as [`__fprop_add_percpu`].
#[no_mangle]
pub unsafe extern "C" fn __fprop_add_percpu_max(
    p: *mut FpropGlobal,
    pl: *mut FpropLocalPercpu,
    max_frac: c_int,
    mut nr: c_long,
) {
    // `FPROP_FRAC_BASE` is `(1UL << FPROP_FRAC_SHIFT)` in the real header
    // -- `unsigned long`, not `int` -- so the comparison against
    // `max_frac` promotes `max_frac` to `c_ulong`, matched here exactly.
    if (max_frac as c_ulong) < FPROP_FRAC_BASE {
        let (mut numerator, mut denominator): (c_ulong, c_ulong) = (0, 0);

        unsafe { fprop_fraction_percpu(p, pl, &mut numerator, &mut denominator) };

        // tmp = (u64)denominator * max_frac - ((u64)numerator << FPROP_FRAC_SHIFT);
        // Computed entirely in u64 (matching C's actual evaluation, incl.
        // wraparound), THEN the final bit pattern is reinterpreted as
        // s64 on assignment to `tmp` -- not cast-per-term, which would
        // diverge on wraparound.
        let tmp: i64 = (denominator as u64)
            .wrapping_mul(max_frac as u64)
            .wrapping_sub((numerator as u64) << FPROP_FRAC_SHIFT) as i64;

        if tmp < 0 {
            // Maximum fraction already exceeded?
            return;
        }
        // `tmp >= 0` here, so its conversion to u64 below (matching the
        // C's signed-vs-unsigned comparison promotion) is value-preserving.
        let denom = FPROP_FRAC_BASE.wrapping_sub(max_frac as c_ulong);
        if (tmp as u64) < (nr as u64).wrapping_mul(denom) {
            // Add just enough for the fraction to saturate.
            // div_u64()'s divisor parameter is u32 -- the real call site
            // narrows `FPROP_FRAC_BASE - max_frac` to u32, matched here.
            let dividend = (tmp as u64)
                .wrapping_add(FPROP_FRAC_BASE)
                .wrapping_sub(max_frac as u64)
                .wrapping_sub(1);
            nr = (dividend / denom as u32 as u64) as c_long;
        }
    }

    unsafe { __fprop_add_percpu(p, pl, nr) };
}
