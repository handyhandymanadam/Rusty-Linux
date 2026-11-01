// SPDX-License-Identifier: GPL-2.0-only

//! `___ratelimit()` -- the rate-limit accounting behind `lib/ratelimit.c`.
//!
//! Replaces: `___ratelimit()`, `EXPORT_SYMBOL` (plain, not GPL). The export
//! lives here via `kernel::kabi_export!()`; the pins below were captured
//! with `rig/kabi-pin.sh --capture ___ratelimit build-full` against the
//! pristine C before it was deleted (`logs/pins/ratelimit.pins`, `.err`
//! empty, baseline CRC `0x00d6a487` reproduced).
//!
//! # The lock/IRQ primitives stay in C, and why
//!
//! `raw_spin_trylock_irqsave()`/`raw_spin_unlock_irqrestore()` are NOT bare
//! qspinlock instructions -- `_raw_spin_trylock_irqsave()`/
//! `__raw_spin_trylock()` (`include/linux/spinlock_api_smp.h`) also do
//! `preempt_disable()`/`preempt_enable()` (real per-CPU state, not a no-op
//! in any config), `spin_acquire()`/`spin_release()` (lockdep annotations),
//! and `LOCK_CONTENDED()`, which dispatches into
//! `queued_spin_lock_slowpath()` -- a real, out-of-line, safety-critical
//! algorithm in `kernel/locking/qspinlock.c`, a different subsystem
//! entirely. Reimplementing preempt-count and the qspinlock protocol to
//! port this one file would be wildly disproportionate. See
//! `logs/porting-hazards.md`, "spinlock + IRQ state", and
//! `rust_ratelimit_trylock_irqsave()`/`rust_ratelimit_unlock_irqrestore()`
//! (`lib/ratelimit.c`) for the thunks.
//!
//! `rust_ratelimit_warn_once()` (`lib/ratelimit.c`) is the same shape as
//! `lib/dynamic_queue_limits.c`'s `__dql_completed_bug_on()`: `WARN_ONCE()`
//! plants a bug-table entry naming its own file and line, so the check
//! stays in C rather than becoming a Rust-side warning that would name the
//! wrong function.
//!
//! # Atomics: `atomic_t` fields map directly to `AtomicI32`
//!
//! `atomic_t` is `struct { int counter; }`, 4 bytes, same size/align/bit
//! pattern as `core::sync::atomic::AtomicI32` -- confirmed against
//! `arch/x86/include/asm/atomic.h`: `atomic_read`/`atomic_set` are plain
//! `READ_ONCE`/`WRITE_ONCE` (`Ordering::Relaxed`), `atomic_dec_return`
//! (`arch_atomic_sub_return`, `LOCK XADD`) is fully ordered
//! (`Ordering::SeqCst`), `atomic_xchg_relaxed` is `Ordering::Relaxed` by
//! its own name, `atomic_inc` (no return read back) is `Ordering::Relaxed`.
//!
//! `interval`/`burst`/`flags` are plain `int`/`unsigned int` under
//! `READ_ONCE()`/direct field access depending on whether the C reads them
//! before or after taking `rs->lock` -- reproduced with
//! `core::ptr::read_volatile`/plain field access to match exactly, same
//! convention as `dynamic_queue_limits_rs.rs`'s `jiffies()` helper.

use core::ffi::{c_char, c_int, c_uint, c_ulong};
use core::sync::atomic::{AtomicI32, Ordering};

const RATELIMIT_MSG_ON_RELEASE: c_uint = 1 << 0;
const RATELIMIT_INITIALIZED: c_uint = 1 << 1;

/// `raw_spinlock_t` (`arch_spinlock_t` on `CONFIG_QUEUED_SPINLOCKS`, this
/// project's build), sized but deliberately opaque -- 4 bytes, confirmed
/// against the live `build-full` DWARF via `pahole -C raw_spinlock_t`;
/// `CONFIG_DEBUG_SPINLOCK`/`DEBUG_LOCK_ALLOC` are off in both project
/// configs, so no extra debug fields. Never read or written directly here
/// -- only passed by pointer to the retained C lock/unlock thunks, which
/// are the only code that touches it, same shape as `mpicoder_rs.rs`'s
/// `ScatterlistOpaque`. Deliberately NOT given a `Mirrors` doc annotation:
/// `rig/layout-check.sh` would otherwise compare a single named field
/// against `raw_spinlock_t`'s real `raw_lock` member and (correctly) call
/// the field-name mismatch a defect -- this struct's contract is its SIZE,
/// not its field layout.
#[cfg(not(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC)))]
#[repr(C)]
pub struct RawSpinlockT {
    /// Opaque -- see this struct's own doc comment.
    pub bits: u32,
}

/// Same type under `CONFIG_DEBUG_SPINLOCK` and/or `CONFIG_DEBUG_LOCK_ALLOC`
/// (the concurrency checker builds, configs/chk-ka.fragment): `raw_spinlock_t`
/// then carries `magic`, `owner_cpu`, `owner` and/or a 40-byte `lockdep_map`, and the
/// C struct is 24 / 48 / 64 bytes (pahole on build-chk-ka: 64), 8-aligned.
/// Found by the checker build: the 4-byte mirror put the following fields at the wrong
/// offsets and a KASAN+lockdep kernel died in early boot (logs/concurrency-tooling.md).
#[cfg(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC))]
#[repr(C, align(8))]
pub struct RawSpinlockT {
    /// Opaque -- see this struct's own doc comment.
    pub bits: [u8; RAW_SPINLOCK_DEBUG_SIZE],
}

#[cfg(all(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC))]
const RAW_SPINLOCK_DEBUG_SIZE: usize = 64;
#[cfg(all(not(CONFIG_DEBUG_SPINLOCK), CONFIG_DEBUG_LOCK_ALLOC))]
const RAW_SPINLOCK_DEBUG_SIZE: usize = 48;
#[cfg(all(CONFIG_DEBUG_SPINLOCK, not(CONFIG_DEBUG_LOCK_ALLOC)))]
const RAW_SPINLOCK_DEBUG_SIZE: usize = 24;
#[cfg(CONFIG_LOCK_STAT)]
compile_error!("CONFIG_LOCK_STAT adds fields to lockdep_map; the RawSpinlockT mirror sizes are for it off");

/// Mirrors `struct ratelimit_state` (`include/linux/ratelimit_types.h`),
/// verified field-for-field against `pahole -C ratelimit_state
/// build-full/vmlinux`: 32 bytes, 7 members at offsets 0/4/8/12/16/20/24.
#[repr(C)]
pub struct RatelimitState {
    /// Protects the state -- see `RawSpinlockT`'s own doc comment.
    pub lock: RawSpinlockT,
    /// Rate-limit window, in jiffies. `<= 0` means "never limit".
    pub interval: c_int,
    /// Callbacks allowed per `interval`. `<= 0` means "always limit".
    pub burst: c_int,
    /// Callbacks left in the current window.
    pub rs_n_left: AtomicI32,
    /// Callbacks suppressed since the last report.
    pub missed: AtomicI32,
    /// `RATELIMIT_INITIALIZED` / `RATELIMIT_MSG_ON_RELEASE`.
    pub flags: c_uint,
    /// Start of the current window, in jiffies.
    pub begin: c_ulong,
}

unsafe extern "C" {
    #[link_name = "jiffies"]
    static JIFFIES: c_ulong;

    /* lib/ratelimit.c. */
    fn rust_ratelimit_warn_once(interval: c_int, burst: c_int);
    fn rust_ratelimit_trylock_irqsave(lock: *mut RawSpinlockT, flags: *mut c_ulong) -> bool;
    fn rust_ratelimit_unlock_irqrestore(lock: *mut RawSpinlockT, flags: c_ulong);

    fn _printk_deferred(fmt: *const c_char, ...) -> c_int;
}

#[inline(always)]
fn jiffies() -> c_ulong {
    // SAFETY: `jiffies` is a real kernel global, always live, declared
    // `volatile` in C for the same reason this reads it that way.
    unsafe { core::ptr::read_volatile(&raw const JIFFIES) }
}

/// `time_is_before_jiffies(a)` == `time_after(jiffies, a)`. Expanding
/// `time_after(m_a, m_b) = (long)(m_b - m_a) < 0` with `m_a = jiffies`,
/// `m_b = a` gives `(long)(a - jiffies) < 0` -- `a` first, not `jiffies`
/// first (a first draft of this file had that backwards, caught by the
/// differential's window-reset scenarios before this was reported done:
/// see logs/porting-hazards.md, "spinlock + IRQ state"). Deliberately
/// `wrapping_sub`: jiffies wraps by design, and the signed-difference
/// trick is exactly what stays correct across that wrap
/// (`CONFIG_RUST_OVERFLOW_CHECKS=y` in both project configs makes a plain
/// `-` panic on the wraparound the C relies on).
#[inline(always)]
fn time_is_before_jiffies(a: c_ulong) -> bool {
    (a.wrapping_sub(jiffies()) as i64) < 0
}

/// `___ratelimit()`. Called from the Rust body directly -- see this file's
/// module doc for why the lock/IRQ primitives and the `WARN_ONCE()` check
/// stay in C.
///
/// # Safety
///
/// `rs` must be a valid, initialized `*mut RatelimitState`; `func` a valid
/// NUL-terminated C string, live for the call -- matching exactly what the
/// C's own `___ratelimit()` assumes of its caller (the `__ratelimit(state)`
/// macro passes `__func__` unconditionally).
#[no_mangle]
pub unsafe extern "C" fn ___ratelimit(rs: *mut RatelimitState, func: *const c_char) -> c_int {
    let interval = unsafe { core::ptr::read_volatile(&raw const (*rs).interval) };
    let burst = unsafe { core::ptr::read_volatile(&raw const (*rs).burst) };
    let mut flags: c_ulong = 0;
    let mut ret: c_int = 0;
    let mut locked = false;

    'body: loop {
        if interval <= 0 || burst <= 0 {
            unsafe { rust_ratelimit_warn_once(interval, burst) };
            ret = (interval == 0 || burst > 0) as c_int;

            let give_up = unsafe { core::ptr::read_volatile(&raw const (*rs).flags) }
                & RATELIMIT_INITIALIZED
                == 0
                || (interval == 0 && burst == 0)
                || !unsafe { rust_ratelimit_trylock_irqsave(&raw mut (*rs).lock, &mut flags) };
            if give_up {
                break 'body;
            }
            locked = true;

            unsafe { (*rs).flags &= !RATELIMIT_INITIALIZED };
            break 'body;
        }

        if !unsafe { rust_ratelimit_trylock_irqsave(&raw mut (*rs).lock, &mut flags) } {
            let initialized = unsafe { core::ptr::read_volatile(&raw const (*rs).flags) }
                & RATELIMIT_INITIALIZED
                != 0;
            if initialized
                && unsafe { (*rs).rs_n_left.load(Ordering::Relaxed) } > 0
                && unsafe { (*rs).rs_n_left.fetch_sub(1, Ordering::SeqCst) }.wrapping_sub(1) >= 0
            {
                ret = 1;
            }
            break 'body;
        }
        locked = true;

        if unsafe { (*rs).flags } & RATELIMIT_INITIALIZED == 0 {
            unsafe {
                (*rs).begin = jiffies();
                (*rs).flags |= RATELIMIT_INITIALIZED;
                let burst = (*rs).burst;
                (*rs).rs_n_left.store(burst, Ordering::Relaxed);
            }
        }

        if time_is_before_jiffies(unsafe { (*rs).begin }.wrapping_add(interval as c_ulong)) {
            unsafe {
                let burst = (*rs).burst;
                (*rs).rs_n_left.store(burst, Ordering::Relaxed);
                (*rs).begin = jiffies();

                if (*rs).flags & RATELIMIT_MSG_ON_RELEASE == 0 {
                    let m = (*rs).missed.swap(0, Ordering::Relaxed);
                    if m != 0 {
                        _printk_deferred(
                            c"\x014%s: %d callbacks suppressed\n".as_ptr(),
                            func,
                            m,
                        );
                    }
                }
            }
        }

        if unsafe { (*rs).rs_n_left.load(Ordering::Relaxed) } > 0
            && unsafe { (*rs).rs_n_left.fetch_sub(1, Ordering::SeqCst) }.wrapping_sub(1) >= 0
        {
            ret = 1;
        }
        break 'body;
    }

    if locked {
        unsafe { rust_ratelimit_unlock_irqrestore(&raw mut (*rs).lock, flags) };
    }

    if ret == 0 {
        unsafe { (*rs).missed.fetch_add(1, Ordering::Relaxed) };
    }

    ret
}

kernel::kabi_rule!(
    "type_string",
    "s#qspinlock",
    "structure_type qspinlock { member union_type { member t#atomic_t val data_member_location(0) , member structure_type { member t#u8 locked data_member_location(0) , member t#u8 pending data_member_location(1) } byte_size(2) data_member_location(0) , member structure_type { member t#u16 locked_pending data_member_location(0) , member t#u16 tail data_member_location(2) } byte_size(4) data_member_location(0) } byte_size(4) data_member_location(0) } byte_size(4)"
);
kernel::kabi_rule!(
    "type_string",
    "s#ratelimit_state",
    "structure_type ratelimit_state { member t#raw_spinlock_t lock data_member_location(0) , member base_type int byte_size(4) encoding(5) interval data_member_location(4) , member base_type int byte_size(4) encoding(5) burst data_member_location(8) , member t#atomic_t rs_n_left data_member_location(12) , member t#atomic_t missed data_member_location(16) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(20) , member base_type unsigned long byte_size(8) encoding(7) begin data_member_location(24) } byte_size(32)"
);
kernel::kabi_rule!(
    "type_string",
    "s#raw_spinlock",
    "structure_type raw_spinlock { member t#arch_spinlock_t raw_lock data_member_location(0) } byte_size(4)"
);
kernel::kabi_rule!(
    "type_string",
    "t#__u16",
    "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }"
);
kernel::kabi_rule!(
    "type_string",
    "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }"
);
kernel::kabi_rule!(
    "type_string",
    "t#arch_spinlock_t",
    "typedef_type arch_spinlock_t { s#qspinlock }"
);
kernel::kabi_rule!(
    "type_string",
    "t#atomic_t",
    "typedef_type atomic_t { structure_type { member base_type int byte_size(4) encoding(5) counter data_member_location(0) } byte_size(4) }"
);
kernel::kabi_rule!(
    "type_string",
    "t#raw_spinlock_t",
    "typedef_type raw_spinlock_t { s#raw_spinlock }"
);
kernel::kabi_rule!("type_string", "t#u16", "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#u8", "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    ___ratelimit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#ratelimit_state } rs , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } func ) -> base_type int byte_size(4) encoding(5)",
}
