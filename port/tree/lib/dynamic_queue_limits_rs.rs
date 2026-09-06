// SPDX-License-Identifier: GPL-2.0

//! Dynamic byte queue limits -- the Rust behind `lib/dynamic_queue_limits.c`.
//! See `include/linux/dynamic_queue_limits.h` for the algorithm's own
//! rationale, reproduced in the doc comments below where it explains a
//! non-obvious step.
//!
//! Ported from `lib/dynamic_queue_limits.c` (6.18.49), Copyright (c) 2011,
//! Tom Herbert.
//!
//! Replaces: lib/dynamic_queue_limits.c
//!
//! # What stays in `lib/dynamic_queue_limits.c`
//!
//! `BUG_ON()`'s bug-table entry names its own file and line -- the same
//! reason `lib/plist_rs.rs`/`lib/memweight_rs.rs` keep their `BUG_ON`s in
//! C. And `trace_dql_stall_detected()` is a `TRACE_EVENT()`-generated
//! `static inline` with no linkable symbol -- the "allocation reached
//! through a `static inline`" hazard class (`logs/porting-hazards.md`),
//! generalized to tracepoints. Both get a thunk in the retained C file.
//!
//! # No `&mut` over `struct dql`, anywhere, ever
//!
//! `struct dql`'s own doc comment says it plainly: "dql implementation
//! does not implement any locking." `dql_queued()`/`dql_avail()`
//! (`include/linux/dynamic_queue_limits.h`, `static inline`, unchanged,
//! called from network drivers on a *different* CPU with no lock) touch
//! `num_queued`, `last_obj_cnt`, `stall_thrs`, `history_head`, `history`
//! and `adj_limit` concurrently with every function in this file. A
//! `&mut Dql` in Rust asserts exclusive access to the struct's ENTIRE
//! byte range for its lifetime -- a concurrent access from the other
//! path to *any* field while one is alive is UB regardless of which
//! field this side is touching. So every access here goes through a raw
//! pointer to one field at a time, never a `&Dql`/`&mut Dql` over the
//! whole struct, exactly as the sha-family's aliasing-safe helpers never
//! take `&mut` over a context another live pointer can reach.
//!
//! # `READ_ONCE`/`WRITE_ONCE`/`smp_rmb`, exactly where the C has them
//!
//! `read_volatile`/`write_volatile` mark exactly the accesses the C
//! wraps in `READ_ONCE`/`WRITE_ONCE`, and `core::sync::atomic::fence`
//! stands in for `smp_rmb()` -- no more, no fewer, matching the C's own
//! division of fields into "accessed only by completion path" (plain
//! raw-pointer access here) versus genuinely shared with `dql_queued()`
//! (volatile). Adding volatile everywhere would still be race-free on
//! any hardware this project targets, but it would say something about
//! the algorithm that isn't true: it would hide which accesses actually
//! need to survive concurrent, lockless use and which don't.
//!
//! # Every subtraction here can wrap, on purpose
//!
//! `jiffies` wraps after ~49 days uptime by design, and `POSDIFF`/
//! `AFTER_EQ`/`time_after`-family macros exist specifically to stay
//! correct across that wrap (a signed comparison of an unsigned
//! difference). `CONFIG_RUST_OVERFLOW_CHECKS=y` in both this project's
//! configs makes a plain `-`/`+` panic on the wraparound the C relies
//! on, so every one of these is `wrapping_sub`/`wrapping_add`/
//! `wrapping_mul`, never a bare operator.

use core::sync::atomic::{fence, Ordering};

const DQL_HIST_LEN: usize = 4;
const BITS_PER_LONG: u64 = u64::BITS as u64;
const DQL_MAX_OBJECT: u32 = u32::MAX / 16;
const DQL_MAX_LIMIT: u32 = (u32::MAX / 2) - DQL_MAX_OBJECT;

/// Mirrors `struct dql`, `include/linux/dynamic_queue_limits.h`. 128
/// bytes, pahole-verified. `_cacheline_pad` reproduces `limit`'s
/// `____cacheline_aligned_in_smp`: the DWARF this project's kernel
/// actually emits places `limit` at offset 64, not 56 -- 8 bytes more
/// than `history`'s own natural alignment would give it -- confirmed by
/// `rig/kabi-pin.sh --capture` against the real object, not assumed from
/// the field list alone.
#[repr(C)]
pub struct Dql {
    /// Total ever queued.
    pub num_queued: u32,
    /// `limit + num_completed`.
    pub adj_limit: u32,
    /// Count at last queuing.
    pub last_obj_cnt: u32,
    /// Stall threshold, in jiffies, set by the caller.
    pub stall_thrs: u16,
    _pad0: u16,
    /// Top 58 bits of jiffies.
    pub history_head: u64,
    /// Stall entries, a bit per entry.
    pub history: [u64; DQL_HIST_LEN],
    _cacheline_pad: [u8; 8],
    /// Current limit.
    pub limit: u32,
    /// Total ever completed.
    pub num_completed: u32,
    /// Previous over-limit.
    pub prev_ovlimit: u32,
    /// Previous queue total.
    pub prev_num_queued: u32,
    /// Previous queuing count.
    pub prev_last_obj_cnt: u32,
    /// Lowest slack found.
    pub lowest_slack: u32,
    /// Time slack was last seen.
    pub slack_start_time: u64,
    /// Max limit.
    pub max_limit: u32,
    /// Minimum limit.
    pub min_limit: u32,
    /// Time to measure slack over.
    pub slack_hold_time: u32,
    /// Longest stall detected, reported to the caller.
    pub stall_max: u16,
    _pad1: u16,
    /// Last reap, in jiffies.
    pub last_reap: u64,
    /// Number of stalls.
    pub stall_cnt: u64,
}

unsafe extern "C" {
    #[link_name = "jiffies"]
    static JIFFIES: u64;

    /* lib/dynamic_queue_limits.c. Not EXPORT_SYMBOL -- see its header
     * comment. */
    fn __dql_completed_bug_on(count: u32, num_queued: u32, num_completed: u32);
    fn __dql_trace_stall_detected(
        thrs: u16,
        len: u32,
        last_reap: u64,
        hist_head: u64,
        now: u64,
        hist: *const u64,
    );
}

#[inline(always)]
fn jiffies() -> u64 {
    // SAFETY: `jiffies` is a real kernel global, always live, declared
    // `volatile` in C for the same reason this reads it that way.
    unsafe { core::ptr::read_volatile(&raw const JIFFIES) }
}

/// `POSDIFF(A, B)`.
#[inline(always)]
fn posdiff(a: u32, b: u32) -> u32 {
    let d = a.wrapping_sub(b);
    if (d as i32) > 0 {
        d
    } else {
        0
    }
}

/// `AFTER_EQ(A, B)`.
#[inline(always)]
fn after_eq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// `time_after(a, b)`.
#[inline(always)]
fn time_after(a: u64, b: u64) -> bool {
    (b.wrapping_sub(a) as i64) < 0
}

/// `time_before(a, b)` == `time_after(b, a)`.
#[inline(always)]
fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// `time_after_eq(a, b)`.
#[inline(always)]
fn time_after_eq(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) >= 0
}

/// `time_before_eq(a, b)` == `time_after_eq(b, a)`.
#[inline(always)]
fn time_before_eq(a: u64, b: u64) -> bool {
    (b.wrapping_sub(a) as i64) >= 0
}

/// `test_bit(nr, addr)` for a `DQL_HIST_LEN`-word bitmap; `nr` is always
/// pre-masked to `0..DQL_HIST_LEN*BITS_PER_LONG` by the one caller below,
/// matching `DQL_HIST_ENT`'s own `% DQL_HIST_LEN` on the word index.
///
/// # Safety
/// `hist` must be readable for `DQL_HIST_LEN` `u64`s.
#[inline(always)]
unsafe fn test_bit(nr: u64, hist: *const u64) -> bool {
    let word_idx = (nr / BITS_PER_LONG) as usize % DQL_HIST_LEN;
    // SAFETY: caller guarantees `hist` readable for DQL_HIST_LEN words;
    // `word_idx < DQL_HIST_LEN`. The C's own test_bit() here is a plain
    // (non-READ_ONCE) load -- ordering is established by the
    // history_head READ_ONCE/smp_rmb pair around this loop, not by this
    // individual word access, and the kernel relies on a native-width
    // aligned load/store simply being atomic on hardware. Rust has no
    // such escape hatch for a plain reference over memory another
    // thread is concurrently WRITE_ONCE-ing, so this reads through
    // read_volatile anyway: same value on any real hardware, but sound
    // under Rust's aliasing model rather than merely "true in practice".
    let word = unsafe { core::ptr::read_volatile(hist.add(word_idx)) };
    (word >> (nr % BITS_PER_LONG)) & 1 != 0
}

/// `dql_check_stall()`. Called only from [`dql_completed`], never
/// exported.
///
/// # Safety
/// `dql` must be a valid, non-null, properly aligned `*mut Dql` that
/// `dql_queued()`/`dql_avail()` may be reading/writing concurrently on
/// another CPU (no lock -- see the module doc).
unsafe fn dql_check_stall(dql: *mut Dql, stall_thrs: u16) {
    if stall_thrs == 0 {
        return;
    }

    let now = jiffies();
    // SAFETY: `dql` valid per this function's contract; plain read --
    // last_reap is completion-path-only (never touched by dql_queued()).
    let last_reap = unsafe { *(&raw const (*dql).last_reap) };

    if time_after_eq(now, last_reap.wrapping_add(stall_thrs as u64)) {
        'retry: loop {
            // SAFETY: `dql` valid per this function's contract;
            // history_head is genuinely concurrent with dql_queue_stall()
            // on another CPU -- READ_ONCE, pairs with its smp_wmb().
            let hist_head =
                unsafe { core::ptr::read_volatile(&raw const (*dql).history_head) };
            fence(Ordering::Acquire);

            let mut start = (hist_head.wrapping_sub(DQL_HIST_LEN as u64).wrapping_add(1))
                .wrapping_mul(BITS_PER_LONG);
            if time_before(start, last_reap.wrapping_add(1)) {
                start = last_reap.wrapping_add(1);
            }

            let mut end = hist_head
                .wrapping_mul(BITS_PER_LONG)
                .wrapping_add(BITS_PER_LONG - 1);
            if time_before(now, end.wrapping_add((stall_thrs / 2) as u64)) {
                end = now.wrapping_sub((stall_thrs / 2) as u64);
            }

            let mut t = start;
            loop {
                if !time_before_eq(t, end) {
                    break;
                }
                // SAFETY: `dql` valid per this function's contract;
                // `history` is DQL_HIST_LEN words.
                let hit = unsafe {
                    test_bit(
                        t % (DQL_HIST_LEN as u64 * BITS_PER_LONG),
                        (&raw const (*dql).history).cast(),
                    )
                };
                if hit {
                    break;
                }
                t = t.wrapping_add(1);
            }

            if !time_before_eq(t, end) {
                break 'retry;
            }

            // SAFETY: as the first history_head read above.
            let hist_head_now =
                unsafe { core::ptr::read_volatile(&raw const (*dql).history_head) };
            if hist_head != hist_head_now {
                continue 'retry;
            }

            // SAFETY: `dql` valid per this function's contract; these
            // four fields are completion-path-only.
            unsafe {
                let stall_cnt_ptr = &raw mut (*dql).stall_cnt;
                *stall_cnt_ptr = (*stall_cnt_ptr).wrapping_add(1);

                let stall_max_ptr = &raw mut (*dql).stall_max;
                let elapsed = now.wrapping_sub(t) as u16;
                *stall_max_ptr = (*stall_max_ptr).max(elapsed);

                __dql_trace_stall_detected(
                    stall_thrs,
                    now.wrapping_sub(t) as u32,
                    last_reap,
                    hist_head,
                    now,
                    (&raw const (*dql).history).cast(),
                );
            }
            break 'retry;
        }
    }

    // SAFETY: `dql` valid per this function's contract; completion-path-only.
    unsafe { *(&raw mut (*dql).last_reap) = now };
}

/// `dql_completed()`: records a completed count and recalculates the
/// queue limit. See the module doc for the aliasing and volatility
/// discipline; see `include/linux/dynamic_queue_limits.h`'s own comments
/// (reproduced below) for why the algorithm does what it does.
///
/// # Safety
/// `dql` must be a valid, non-null, properly aligned `*mut Dql` that
/// `dql_queued()`/`dql_avail()` may be reading/writing concurrently on
/// another CPU.
#[no_mangle]
pub unsafe extern "C" fn dql_completed(dql: *mut Dql, count: u32) {
    // SAFETY: `dql` valid per this function's contract; genuinely
    // concurrent with dql_queued()'s plain `+=` -- READ_ONCE, matching
    // the C.
    let num_queued = unsafe { core::ptr::read_volatile(&raw const (*dql).num_queued) };
    // Read stall_thrs in advance (same cache line as num_queued) so
    // dql_check_stall() doesn't need to touch that line again later.
    // SAFETY: as above.
    let stall_thrs = unsafe { core::ptr::read_volatile(&raw const (*dql).stall_thrs) };

    // SAFETY: `dql` valid per this function's contract; completion-path-only.
    let num_completed = unsafe { *(&raw const (*dql).num_completed) };
    // SAFETY: the real C body's BUG_ON, kept in C so the bug-table entry
    // names this function.
    unsafe { __dql_completed_bug_on(count, num_queued, num_completed) };

    let completed = num_completed.wrapping_add(count);
    // SAFETY: completion-path-only fields, `dql` valid per contract.
    let limit_field = unsafe { *(&raw const (*dql).limit) };
    let mut limit = limit_field;
    let ovlimit = posdiff(num_queued.wrapping_sub(num_completed), limit);
    let inprogress = num_queued.wrapping_sub(completed);
    // SAFETY: as above.
    let prev_num_queued = unsafe { *(&raw const (*dql).prev_num_queued) };
    let prev_inprogress = prev_num_queued.wrapping_sub(num_completed);
    let all_prev_completed = after_eq(completed, prev_num_queued);
    // SAFETY: as above.
    let prev_ovlimit = unsafe { *(&raw const (*dql).prev_ovlimit) };

    if (ovlimit != 0 && inprogress == 0) || (prev_ovlimit != 0 && all_prev_completed) {
        // Queue considered starved if:
        //   - The queue was over-limit in the last interval, and there
        //     is no more data in the queue.
        //   OR
        //   - The queue was over-limit in the previous interval and when
        //     enqueuing it was possible that all queued data had been
        //     consumed. This covers the case when the queue may have
        //     become starved between completion processing running and
        //     the next time enqueue was scheduled.
        //
        //     When the queue is starved, increase the limit by the
        //     amount of bytes both sent and completed in the last
        //     interval, plus any previous over-limit.
        limit = limit.wrapping_add(posdiff(completed, prev_num_queued).wrapping_add(prev_ovlimit));
        let now = jiffies();
        // SAFETY: completion-path-only, `dql` valid per contract.
        unsafe {
            *(&raw mut (*dql).slack_start_time) = now;
            *(&raw mut (*dql).lowest_slack) = u32::MAX;
        }
    } else if inprogress != 0 && prev_inprogress != 0 && !all_prev_completed {
        // Queue was not starved: check if the limit can be decreased. A
        // decrease is only considered if the queue has been busy the
        // whole interval (the check above).
        //
        // If there is slack -- excess data queued above the amount
        // needed to prevent starvation -- the queue limit can be
        // decreased. To avoid hysteresis, track the minimum slack found
        // over several iterations of this routine.
        //
        // Slack is the maximum of:
        //   - The queue limit plus previous over-limit minus twice the
        //     number of objects completed (a basis for an upper bound on
        //     the limit).
        //   - The portion of objects in the last queuing operation not
        //     part of a non-zero previous over-limit ("round down" by
        //     the non-overlimit portion of the last queuing operation).
        let slack = posdiff(
            limit.wrapping_add(prev_ovlimit),
            2u32.wrapping_mul(completed.wrapping_sub(num_completed)),
        );
        // SAFETY: completion-path-only, `dql` valid per contract.
        let prev_last_obj_cnt = unsafe { *(&raw const (*dql).prev_last_obj_cnt) };
        let slack_last_objs = if prev_ovlimit != 0 {
            posdiff(prev_last_obj_cnt, prev_ovlimit)
        } else {
            0
        };
        let slack = slack.max(slack_last_objs);

        // SAFETY: completion-path-only, `dql` valid per contract.
        let lowest_slack_ptr = unsafe { &raw mut (*dql).lowest_slack };
        // SAFETY: as above.
        if slack < unsafe { *lowest_slack_ptr } {
            unsafe { *lowest_slack_ptr = slack };
        }

        // SAFETY: completion-path-only, `dql` valid per contract.
        let slack_start_time = unsafe { *(&raw const (*dql).slack_start_time) };
        let slack_hold_time = unsafe { *(&raw const (*dql).slack_hold_time) };
        if time_after(jiffies(), slack_start_time.wrapping_add(slack_hold_time as u64)) {
            // SAFETY: as above.
            limit = posdiff(limit, unsafe { *lowest_slack_ptr });
            let now = jiffies();
            unsafe {
                *(&raw mut (*dql).slack_start_time) = now;
                *lowest_slack_ptr = u32::MAX;
            }
        }
    }

    // Enforce bounds on the limit.
    // SAFETY: completion-path-only, `dql` valid per contract.
    let (min_limit, max_limit) =
        unsafe { (*(&raw const (*dql).min_limit), *(&raw const (*dql).max_limit)) };
    limit = limit.clamp(min_limit, max_limit);

    let mut ovlimit = ovlimit;
    if limit != limit_field {
        // SAFETY: completion-path-only, `dql` valid per contract.
        unsafe { *(&raw mut (*dql).limit) = limit };
        ovlimit = 0;
    }

    // SAFETY: completion-path-only fields except `last_obj_cnt`
    // (READ_ONCE, genuinely concurrent with dql_queued()'s WRITE_ONCE),
    // `dql` valid per contract.
    unsafe {
        *(&raw mut (*dql).adj_limit) = limit.wrapping_add(completed);
        *(&raw mut (*dql).prev_ovlimit) = ovlimit;
        *(&raw mut (*dql).prev_last_obj_cnt) =
            core::ptr::read_volatile(&raw const (*dql).last_obj_cnt);
        *(&raw mut (*dql).num_completed) = completed;
        *(&raw mut (*dql).prev_num_queued) = num_queued;

        dql_check_stall(dql, stall_thrs);
    }
}

/// `dql_reset()`: reset all dynamic state to initial values.
///
/// # Safety
/// As [`dql_completed`].
#[no_mangle]
pub unsafe extern "C" fn dql_reset(dql: *mut Dql) {
    let now = jiffies();
    // SAFETY: `dql` valid per this function's contract. `num_queued`,
    // `last_obj_cnt` and `history`/`history_head` are concurrently
    // touched by dql_queued() on another CPU -- matching the C, which
    // resets them with plain stores too (dql_reset() is documented as a
    // caller-side reinitialization point, not something that races a
    // live dql_queued() the way dql_completed() routinely does).
    unsafe {
        let min_limit = *(&raw const (*dql).min_limit);
        *(&raw mut (*dql).limit) = min_limit;
        *(&raw mut (*dql).num_queued) = 0;
        *(&raw mut (*dql).num_completed) = 0;
        *(&raw mut (*dql).last_obj_cnt) = 0;
        *(&raw mut (*dql).prev_num_queued) = 0;
        *(&raw mut (*dql).prev_last_obj_cnt) = 0;
        *(&raw mut (*dql).prev_ovlimit) = 0;
        *(&raw mut (*dql).lowest_slack) = u32::MAX;
        *(&raw mut (*dql).slack_start_time) = now;

        *(&raw mut (*dql).last_reap) = now;
        *(&raw mut (*dql).history_head) = now / BITS_PER_LONG;
        *(&raw mut (*dql).history) = [0u64; DQL_HIST_LEN];
    }
}

/// `dql_init()`: initialize with configuration parameters.
///
/// # Safety
/// As [`dql_completed`].
#[no_mangle]
pub unsafe extern "C" fn dql_init(dql: *mut Dql, hold_time: u32) {
    // SAFETY: `dql` valid per this function's contract.
    unsafe {
        *(&raw mut (*dql).max_limit) = DQL_MAX_LIMIT;
        *(&raw mut (*dql).min_limit) = 0;
        *(&raw mut (*dql).slack_hold_time) = hold_time;
        *(&raw mut (*dql).stall_thrs) = 0;
        dql_reset(dql);
    }
}

// `s#dql`'s own type-string rule, registered standalone via kabi_rule!
// (the primitive kabi_export! is built on) rather than via kabi_export!
// itself, which always also emits an .export_symbol entry -- there is no
// symbol named "dql" to export, only a type reference the three
// contracts below need resolved.
//
// WHY THIS IS NEEDED HERE AND WASN'T FOR crypto_aes_ctx. A back-reference
// like `s#dql` normally resolves against another compiled C translation
// unit that also names the same struct (aes.c has no C left at all, but
// `struct crypto_aes_ctx` is still used by other, unrelated crypto C
// files in this tree, so gendwarfksyms already has its DWARF from
// there). `struct dql` has no such other C consumer in this project's
// minimal config-full driver set -- confirmed by `gendwarfksyms:
// __calculate_version: unknown type reference to 's#dql' when expanding
// '(null)'` the first time this was built without this rule. So this
// registration IS the only place gendwarfksyms can find it.
kernel::kabi_rule!(
    "type_string",
    "s#dql",
    "structure_type dql { member base_type unsigned int byte_size(4) encoding(7) num_queued data_member_location(0) , member base_type unsigned int byte_size(4) encoding(7) adj_limit data_member_location(4) , member base_type unsigned int byte_size(4) encoding(7) last_obj_cnt data_member_location(8) , member base_type unsigned short byte_size(2) encoding(7) stall_thrs data_member_location(12) , member base_type unsigned long byte_size(8) encoding(7) history_head data_member_location(16) , member array_type[4] { base_type unsigned long byte_size(8) encoding(7) } history data_member_location(24) , member base_type unsigned int byte_size(4) encoding(7) limit data_member_location(64) , member base_type unsigned int byte_size(4) encoding(7) num_completed data_member_location(68) , member base_type unsigned int byte_size(4) encoding(7) prev_ovlimit data_member_location(72) , member base_type unsigned int byte_size(4) encoding(7) prev_num_queued data_member_location(76) , member base_type unsigned int byte_size(4) encoding(7) prev_last_obj_cnt data_member_location(80) , member base_type unsigned int byte_size(4) encoding(7) lowest_slack data_member_location(84) , member base_type unsigned long byte_size(8) encoding(7) slack_start_time data_member_location(88) , member base_type unsigned int byte_size(4) encoding(7) max_limit data_member_location(96) , member base_type unsigned int byte_size(4) encoding(7) min_limit data_member_location(100) , member base_type unsigned int byte_size(4) encoding(7) slack_hold_time data_member_location(104) , member base_type unsigned short byte_size(2) encoding(7) stall_max data_member_location(108) , member base_type unsigned long byte_size(8) encoding(7) last_reap data_member_location(112) , member base_type unsigned long byte_size(8) encoding(7) stall_cnt data_member_location(120) } byte_size(128)"
);

kernel::kabi_export! {
    dql_completed,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dql } dql , formal_parameter base_type unsigned int byte_size(4) encoding(7) count ) -> base_type void",
}

kernel::kabi_export! {
    dql_reset,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dql } dql ) -> base_type void",
}

kernel::kabi_export! {
    dql_init,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dql } dql , formal_parameter base_type unsigned int byte_size(4) encoding(7) hold_time ) -> base_type void",
}
