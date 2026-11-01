// SPDX-License-Identifier: GPL-2.0

//! The lock-free fast path of `lib/lockref.c` -- the first module under the concurrency bar (`logs/concurrency-bar.md`).
//!
//! A `struct lockref` is one 64-bit word: the 4-byte spinlock in the low half and the `int` count in the high half. The C
//! `CMPXCHG_LOOP()` reads the word, and while the lock half is zero (unlocked) computes a new word with the count changed and
//! tries `cmpxchg` on the WHOLE word: it can only succeed if nobody has taken the lock in the meantime, which is what makes the
//! lock-free update "as if the spinlock had been taken". After 100 failed tries (or when the operation says the fast path does
//! not apply) the caller falls back to the spinlock. This file is that loop for the five operations that have one.
//! In C (`lockref.c`, the thunk-shaped file of the port): the public entry points, the `spin_lock()` fallback paths (the unlock
//! is inline and configuration-dependent, preempt count included) and `lockref_mark_dead()` (`assert_spin_locked` is a `BUG_ON`).
//!
//! # The ordering contract (bar item 1)
//! * Every update is a read-modify-write on the whole word with `cmpxchg` (`lock cmpxchg` on x86), `Relaxed`: the C uses
//!   `try_cmpxchg64_relaxed()`, and no other memory is published or consumed through this word, so no acquire/release is needed
//!   for the count itself. Atomicity of the RMW is what excludes a concurrent spinlock holder (the lock half would be non-zero in
//!   the compared value) and a concurrent fast-path update (the word would have changed).
//! * The initial `READ_ONCE` of the word is a plain atomic load; a stale value only costs a failed `cmpxchg` (which refreshes
//!   it), never a wrong result.
//! * The fast path is allowed only when the architecture's lock is one 4-byte word (`USE_CMPXCHG_LOCKREF`: no
//!   DEBUG_SPINLOCK / DEBUG_LOCK_ALLOC, SMP, `ARCH_USE_CMPXCHG_LOCKREF`); the Makefile gates the composite the same way and
//!   `lockref.c` carries a `static_assert` of it.
//!
//! x86 is TSO, so a missing barrier cannot show here; the weak-memory check (bar item 2, arm64) is parked.
//!
//! Replaces: lib/lockref.c (CMPXCHG_LOOP only; the entry points stay C)

use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, Ordering};

/// Mirrors `struct lockref` (`include/linux/lockref.h`) as its 64-bit view: lock in bits 0..32, count in bits 32..64.
#[repr(C, align(8))]
pub struct Lockref {
    lock_count: u64,
}

const _: () = assert!(core::mem::size_of::<Lockref>() == 8);

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("lockref_rs.rs: x86-64 little-endian only (the lock/count halves of lock_count)");
#[cfg(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC, not(CONFIG_SMP)))]
compile_error!("lockref_rs.rs: USE_CMPXCHG_LOCKREF is false in this configuration (spinlock_t is not 4 bytes, or UP): keep the C file");

/// Number of tries before falling back to the lock (`retry` in `CMPXCHG_LOOP`).
const RETRIES: i32 = 100;

/// What one step of an operation decides, given the count it saw.
enum Step {
    /// Try to swap in this new count.
    Update(i32),
    /// Leave the loop and return this value now (the C's `return` inside `CODE`).
    Return(c_int),
    /// Leave the loop and take the spinlock (the C's `break` inside `CODE`).
    Fallback,
}

/// How the loop ended.
enum Outcome {
    /// `try_cmpxchg` succeeded with this new count (the C's `SUCCESS`).
    Done(i32),
    /// The operation returned early.
    Early(c_int),
    /// Fall back to the lock.
    Slow,
}

/// `CMPXCHG_LOOP(CODE, SUCCESS)`.
///
/// # Safety
/// `lockref` points at a valid, 8-byte aligned `struct lockref`.
#[inline(always)]
unsafe fn cmpxchg_loop(lockref: *mut Lockref, code: impl Fn(i32) -> Step) -> Outcome {
    // SAFETY: caller contract; `Lockref` is `align(8)` and the C struct's `lock_count` is `aligned_u64`.
    let word = unsafe { AtomicU64::from_ptr(&raw mut (*lockref).lock_count) };
    let mut retry = RETRIES;
    let mut old = word.load(Ordering::Relaxed); /* READ_ONCE() */

    /* arch_spin_value_unlocked(): the qspinlock word is zero */
    while (old as u32) == 0 {
        let count = (old >> 32) as i32;
        match code(count) {
            Step::Return(v) => return Outcome::Early(v),
            Step::Fallback => break,
            Step::Update(new_count) => {
                let new = (old & 0xffff_ffff) | ((new_count as u32 as u64) << 32);
                match word.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return Outcome::Done(new_count),
                    Err(cur) => old = cur, /* try_cmpxchg() refreshes `old` */
                }
            }
        }
        retry -= 1;
        if retry == 0 {
            break;
        }
    }
    Outcome::Slow
}

/// `lockref_get()`'s fast path. Returns true if done; false means "take the lock".
///
/// # Safety
/// `lockref` valid and 8-byte aligned.
#[no_mangle]
pub unsafe extern "C" fn rust_lockref_get_fast(lockref: *mut Lockref) -> bool {
    matches!(unsafe { cmpxchg_loop(lockref, |c| Step::Update(c.wrapping_add(1))) }, Outcome::Done(_))
}

/// `lockref_get_not_zero()`'s fast path: 1 = got a reference, 0 = refused (count <= 0), -1 = take the lock.
///
/// # Safety
/// As [`rust_lockref_get_fast`].
#[no_mangle]
pub unsafe extern "C" fn rust_lockref_get_not_zero_fast(lockref: *mut Lockref) -> c_int {
    match unsafe { cmpxchg_loop(lockref, |c| if c <= 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {
        Outcome::Done(_) => 1,
        Outcome::Early(v) => v,
        Outcome::Slow => -1,
    }
}

/// `lockref_put_return()` entire: the new count, or -1 (also when the fast path does not apply: the C has no lock fallback).
///
/// # Safety
/// As [`rust_lockref_get_fast`].
#[no_mangle]
pub unsafe extern "C" fn rust_lockref_put_return(lockref: *mut Lockref) -> c_int {
    match unsafe { cmpxchg_loop(lockref, |c| if c <= 0 { Step::Return(-1) } else { Step::Update(c.wrapping_sub(1)) }) } {
        Outcome::Done(n) => n,
        Outcome::Early(v) => v,
        Outcome::Slow => -1,
    }
}

/// `lockref_put_or_lock()`'s fast path. Returns true if the reference was dropped; false means "take the lock" (the caller
/// re-checks `count <= 1` under it).
///
/// # Safety
/// As [`rust_lockref_get_fast`].
#[no_mangle]
pub unsafe extern "C" fn rust_lockref_put_or_lock_fast(lockref: *mut Lockref) -> bool {
    matches!(
        unsafe { cmpxchg_loop(lockref, |c| if c <= 1 { Step::Fallback } else { Step::Update(c.wrapping_sub(1)) }) },
        Outcome::Done(_)
    )
}

/// `lockref_get_not_dead()`'s fast path: 1 = got a reference, 0 = refused (count < 0, dead), -1 = take the lock.
///
/// # Safety
/// As [`rust_lockref_get_fast`].
#[no_mangle]
pub unsafe extern "C" fn rust_lockref_get_not_dead_fast(lockref: *mut Lockref) -> c_int {
    match unsafe { cmpxchg_loop(lockref, |c| if c < 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {
        Outcome::Done(_) => 1,
        Outcome::Early(v) => v,
        Outcome::Slow => -1,
    }
}
