// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! Dynamic Interrupt Moderation (DIM) core state machine -- the Rust behind
//! `lib/dim/dim.c`.
//!
//! Replaces: lib/dim/dim.c
//!
//! `lib/dim/net_dim.c` stays C: it reaches into `struct net_device`, out of
//! this project's scope by the same rule as every other device/mm/sched-
//! coupled file. `lib/dim/rdma_dim.c` is the companion port (`rdma_dim_rs.rs`)
//! -- both link into the same `dimlib.o` alongside the retained
//! `net_dim.o`, per `lib/dim/Makefile`'s `dimlib-y := dim.o net_dim.o
//! rdma_dim.o` list, which is why this crate's Makefile wiring swaps entries
//! in that list rather than `obj-y`/`lib-y` the way the top-level lib/
//! Makefile does.
//!
//! # `enum`s stored in a `u8` field, not a native C `enum`
//!
//! `struct dim`'s `tune_state`, `mode` and `state` are `u8` in the real
//! struct (`include/linux/dim.h`), not `enum dim_tune_state` etc. directly --
//! the header says so explicitly ("use u8 instead of enum, aiming to
//! reduce data size"). The `DIM_*` constants below are the same integer
//! values as their C enumerators, and every C `switch` over one of these
//! fields has no `default:` case despite the field's nominal width being
//! wider than the enum's live range -- reproduced here as a Rust `match`
//! with a wildcard arm that does nothing, exactly matching what an
//! unmatched byte value falls through to in the C.
//!
//! # The two truncating conversions in `dim_calc_stats`, verified against
//! # the exact macro definitions rather than assumed
//!
//! * `u32 delta_us = ktime_us_delta(...)`: `ktime_us_delta` returns `s64`
//!   (nanoseconds difference / `NSEC_PER_USEC`, `include/linux/ktime.h`).
//!   Assigning that to a `u32` local truncates to the low 32 bits --
//!   `as u32` on an `i64` in Rust does the same modular truncation, not a
//!   saturating one.
//! * `USEC_PER_MSEC` is `1000L` (`include/vdso/time64.h`) -- a `long`, not
//!   an `int`. So `npkts * USEC_PER_MSEC` promotes `npkts` (u32) to 64-bit
//!   signed arithmetic before multiplying; on LP64 this cannot overflow for
//!   any `u32` `npkts` (max product ~4.3e12, `i64::MAX` is ~9.2e18). Ported
//!   as `u64` multiplication throughout `DIV_ROUND_UP`'s three call sites,
//!   matching the C's actual (64-bit) arithmetic width instead of naively
//!   reproducing it in `u32` and risking a wraparound the C never has.
//! * `DIV_ROUND_DOWN_ULL(curr_stats->cpms * 100, curr_stats->epms)`: the
//!   numerator is computed in `int` (both operands are `int`), THEN cast to
//!   `unsigned long long` -- a signed-to-wider-unsigned conversion, which
//!   C defines as sign-extend-then-reinterpret. `cpms as i64 as u64`
//!   reproduces that; `cpms as u64` directly would NOT sign-extend a
//!   hypothetical negative product and was rejected for that reason, even
//!   though `cpms`/`epms` are never observed negative in practice --
//!   `logs/porting-hazards.md`'s "N=1 read as a property" rule applies to
//!   claiming untested inputs can't occur, not just to benchmarks.
//!
//!   THE DIVISOR NEEDS A SECOND, DIFFERENT CAST, adversarially confirmed
//!   2026-09-06 against `DIV_ROUND_DOWN_ULL`'s and `do_div`'s real bodies
//!   (`include/linux/math.h`, `include/asm-generic/div64.h`):
//!   `DIV_ROUND_DOWN_ULL(ll, d)` expands to `do_div(_tmp, d)`, and `do_div`
//!   NARROWS its divisor argument to `uint32_t` before dividing -- it is not
//!   a `u64`/`u64` division. So `epms` (an `int`) goes through TWO
//!   conversions in the real macro, not one: `int` -> `uint32_t` (truncate,
//!   which for a negative value is the same bit pattern a direct C cast to
//!   `unsigned int` would give) -> widened to `u64` only for the division
//!   itself. `epms as u32 as u64` reproduces exactly that; `epms as i64 as
//!   u64` (sign-extending straight to 64 bits, the same pattern used for the
//!   numerator above) would be WRONG here and was avoided in the code below
//!   -- a negative `epms` must become a huge 32-bit divisor, not a huge
//!   64-bit one, and those differ whenever `epms` is negative. Measured: a
//!   pathological input with `ncomps = 0xFFFFFFFF`, `delta_us = 1` drives
//!   `cpms` to -1000 and `cpe_ratio` to exactly -584115554 either way in
//!   THIS case (both casts happen to land on the same divisor here), but the
//!   two casts are not equivalent in general and only one matches `do_div`.
//!
//! # `BIT_GAP`, and why it reduces to a plain wrapping subtraction here
//!
//! `BIT_GAP(bits, end, start) = (((end)-(start)) + BIT_ULL(bits)) &
//! (BIT_ULL(bits)-1)`. Every call site in `dim_calc_stats` passes `bits=32`
//! and two `u32` operands. `(end)-(start)` is already `u32` arithmetic in
//! C (wrapping on underflow, which is the point -- a wrapped counter gap),
//! and adding `2^32` then masking by `2^32-1` is a no-op on a value already
//! in `[0, 2^32)`. So `BIT_GAP(32, a, b)` for `u32` `a`, `b` is exactly
//! `a.wrapping_sub(b)`, and that is what each call site below is.
//!
//! # Reachability, sabotage-confirmed, not assumed
//!
//! `CONFIG_DIMLIB` is on in config-full only (config-fast doesn't select
//! it). `dim_calc_stats` sabotaged to panic on entry -> clean boot on
//! config-full: **class A**, not reached. Nothing in this project's minimal
//! qemu boot has RDMA or network hardware driving interrupt moderation, so
//! neither `dim_*` nor `rdma_dim` ever fires. Same shape as
//! `check_signature()`'s BIOS-probe callers qemu never presents. No libtest
//! coverage or differential harness yet -- this port has compile-time
//! verification (kabi contracts, layout-check against pahole), CRC/guard-
//! check clean, and a boot-level sabotage proof, but not yet the userspace
//! differential the loop calls for. Flagged as follow-up, not hidden.

use core::ffi::c_int;

// --- `enum dim_tune_state`, stored in a u8 field ---------------------------
const DIM_PARKING_ON_TOP: u8 = 0;
const DIM_PARKING_TIRED: u8 = 1;
const DIM_GOING_RIGHT: u8 = 2;
const DIM_GOING_LEFT: u8 = 3;

/// Mirrors `struct dim_stats`.
#[repr(C)]
pub struct DimStats {
    /// Packets per msec.
    pub ppms: c_int,
    /// Bytes per msec.
    pub bpms: c_int,
    /// Events per msec.
    pub epms: c_int,
    /// Completions per msec.
    pub cpms: c_int,
    /// Ratio of completions to events.
    pub cpe_ratio: c_int,
}

/// Mirrors `struct dim_sample`.
#[repr(C)]
pub struct DimSample {
    /// Sample timestamp (`ktime_t`).
    pub time: i64,
    /// Number of packets.
    pub pkt_ctr: u32,
    /// Number of bytes.
    pub byte_ctr: u32,
    /// Number of events.
    pub event_ctr: u16,
    /// Current completion counter.
    pub comp_ctr: u32,
}

/// Mirrors `struct list_head` (`include/linux/types.h`) -- only ever
/// embedded inside `WorkStruct` below, never read: `dim.c`/`rdma_dim.c`
/// pass `&dim->work` straight to `schedule_work()`, a real retained C call,
/// and never touch a single field of either type. Real fields all the same,
/// not an opaque blob: a same-total-size opaque `[u8; N]` reports as ONE
/// pahole member where the C has several at different offsets, which
/// `rig/layout-check.sh` correctly flags as GEOMETRY DIFFERS even though
/// total size matches -- found adversarially 2026-09-06 on the first pass
/// at this (`WorkStruct` as `_opaque: [u8; 32]`), fixed by mirroring the
/// real nested shape instead.
#[repr(C)]
pub struct ListHead {
    next: *mut core::ffi::c_void,
    prev: *mut core::ffi::c_void,
}

/// Mirrors `struct lockdep_map` (`include/linux/lockdep_types.h`), only
/// present at all under `CONFIG_LOCKDEP` -- see `WorkStruct`'s doc.
/// `NR_LOCKDEP_CACHING_CLASSES` is 2. Never read: `dim`'s `work` field is
/// only ever passed whole to `schedule_work()`.
#[cfg(CONFIG_LOCKDEP)]
#[repr(C)]
pub struct LockdepMap {
    key: *mut core::ffi::c_void,
    class_cache: [*mut core::ffi::c_void; 2],
    name: *const core::ffi::c_char,
    wait_type_outer: u8,
    wait_type_inner: u8,
    lock_type: u8,
    #[cfg(CONFIG_LOCK_STAT)]
    cpu: i32,
    #[cfg(CONFIG_LOCK_STAT)]
    ip: usize,
}

/// Mirrors `struct work_struct` (`include/linux/workqueue.h`). Real fields,
/// not an opaque blob -- see `ListHead`'s doc for why. Pointer fields are
/// untyped (`*mut c_void`) rather than pointing at their real C pointee
/// types: pahole's geometry check only compares offset and size per member,
/// never pointee type, and every pointer here is 8 bytes regardless.
///
/// `lockdep_map` is `#[cfg(CONFIG_LOCKDEP)]`, matching the C's own
/// `#ifdef CONFIG_LOCKDEP` (`include/linux/workqueue_types.h:16-23`) --
/// adversarially found 2026-09-06: the earlier opaque-then-real-fields fix
/// got the CONFIG_LOCKDEP=n shape (32 bytes) right but had no arm for
/// CONFIG_LOCKDEP=y (72 bytes, `sizeof(struct lockdep_map)` == 40), which
/// would silently shift every field after `work` in `struct dim` by 40
/// bytes -- real corruption of a caller-owned struct, not a wrong answer.
/// UNVERIFIED BY THIS PROJECT'S OWN GATES: neither config-fast nor
/// config-full sets `CONFIG_LOCKDEP=y` (only the weaker
/// `CONFIG_LOCKDEP_SUPPORT`), so layout-check.sh cannot exercise this arm
/// against real DWARF here -- written correctly from
/// `include/linux/lockdep_types.h` rather than left silently wrong, but
/// flagged rather than claimed as gate-checked. Precedent for the `#[cfg]`
/// pattern itself (a function call, not a layout fork): `sys_info_rs.rs`,
/// `debug_show_all_locks()` at CONFIG_LOCKDEP.
#[repr(C)]
pub struct WorkStruct {
    data: i64,
    entry: ListHead,
    func: *mut core::ffi::c_void,
    #[cfg(CONFIG_LOCKDEP)]
    lockdep_map: LockdepMap,
}

/// Mirrors `struct dim`.
#[repr(C)]
pub struct Dim {
    /// Algorithm state.
    pub state: u8,
    /// Measured rates from the previous iteration.
    pub prev_stats: DimStats,
    /// Sampled data at the start of the current iteration.
    pub start_sample: DimSample,
    /// Sample used to update the current events.
    pub measuring_sample: DimSample,
    /// Work to perform on action required.
    pub work: WorkStruct,
    /// Pointer to the struct that points to this `Dim`.
    pub priv_: *mut core::ffi::c_void,
    /// Current moderation profile.
    pub profile_ix: u8,
    /// CQ period count mode.
    pub mode: u8,
    /// Algorithm tuning state -- one of the `DIM_*` constants above.
    pub tune_state: u8,
    /// Steps taken towards higher moderation.
    pub steps_right: u8,
    /// Steps taken towards lower moderation.
    pub steps_left: u8,
    /// Parking depth counter.
    pub tired: u8,
}

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
kernel::kabi_rule!("type_string", "s#dim",
    "structure_type dim { member t#u8 state data_member_location(0) , member s#dim_stats prev_stats data_member_location(4) , member s#dim_sample start_sample data_member_location(24) , member s#dim_sample measuring_sample data_member_location(48) , member s#work_struct work data_member_location(72) , member pointer_type { base_type void } priv data_member_location(104) , member t#u8 profile_ix data_member_location(112) , member t#u8 mode data_member_location(113) , member t#u8 tune_state data_member_location(114) , member t#u8 steps_right data_member_location(115) , member t#u8 steps_left data_member_location(116) , member t#u8 tired data_member_location(117) } byte_size(120)");
kernel::kabi_rule!("type_string", "s#dim_sample",
    "structure_type dim_sample { member t#ktime_t time data_member_location(0) , member t#u32 pkt_ctr data_member_location(8) , member t#u32 byte_ctr data_member_location(12) , member t#u16 event_ctr data_member_location(16) , member t#u32 comp_ctr data_member_location(20) } byte_size(24)");
kernel::kabi_rule!("type_string", "s#dim_stats",
    "structure_type dim_stats { member base_type int byte_size(4) encoding(5) ppms data_member_location(0) , member base_type int byte_size(4) encoding(5) bpms data_member_location(4) , member base_type int byte_size(4) encoding(5) epms data_member_location(8) , member base_type int byte_size(4) encoding(5) cpms data_member_location(12) , member base_type int byte_size(4) encoding(5) cpe_ratio data_member_location(16) } byte_size(20)");
kernel::kabi_rule!("type_string", "s#list_head",
    "structure_type list_head { member pointer_type { s#list_head } next data_member_location(0) , member pointer_type { s#list_head } prev data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#work_struct",
    "structure_type work_struct { member t#atomic_long_t data data_member_location(0) , member s#list_head entry data_member_location(8) , member t#work_func_t func data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#__s64",
    "typedef_type __s64 { base_type long long byte_size(8) encoding(5) }");
kernel::kabi_rule!("type_string", "t#__u16",
    "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#atomic64_t",
    "typedef_type atomic64_t { structure_type { member t#s64 counter data_member_location(0) } byte_size(8) }");
kernel::kabi_rule!("type_string", "t#atomic_long_t",
    "typedef_type atomic_long_t { t#atomic64_t }");
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#ktime_t",
    "typedef_type ktime_t { t#s64 }");
kernel::kabi_rule!("type_string", "t#s64",
    "typedef_type s64 { t#__s64 }");
kernel::kabi_rule!("type_string", "t#u16",
    "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#work_func_t",
    "typedef_type work_func_t { pointer_type { subroutine_type ( formal_parameter pointer_type { s#work_struct } ) -> base_type void } }");

kernel::kabi_export! {
    dim_on_top,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dim } dim ) -> t#bool",
}

/// # Safety
/// `dim` must point at a valid, initialized `struct dim`.
#[no_mangle]
pub unsafe extern "C" fn dim_on_top(dim: *mut Dim) -> bool {
    // SAFETY: caller's contract.
    let dim = unsafe { &*dim };
    match dim.tune_state {
        DIM_PARKING_ON_TOP | DIM_PARKING_TIRED => true,
        DIM_GOING_RIGHT => dim.steps_left > 1 && dim.steps_right == 1,
        DIM_GOING_LEFT => dim.steps_right > 1 && dim.steps_left == 1,
        // The C's `default:` arm ("DIM_GOING_LEFT") is reached for any
        // OTHER value too, since the field is a u8 and the switch has no
        // real default. `tune_state` is only ever one of the four DIM_*
        // constants by invariant, so this arm is dead in practice --
        // reproduced anyway so an out-of-band value doesn't panic where
        // the C wouldn't either.
        _ => dim.steps_right > 1 && dim.steps_left == 1,
    }
}

kernel::kabi_export! {
    dim_turn,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dim } dim ) -> base_type void",
}

/// # Safety
/// `dim` must point at a valid, initialized `struct dim`.
#[no_mangle]
pub unsafe extern "C" fn dim_turn(dim: *mut Dim) {
    // SAFETY: caller's contract.
    let dim = unsafe { &mut *dim };
    match dim.tune_state {
        DIM_PARKING_ON_TOP | DIM_PARKING_TIRED => {}
        DIM_GOING_RIGHT => {
            dim.tune_state = DIM_GOING_LEFT;
            dim.steps_left = 0;
        }
        DIM_GOING_LEFT => {
            dim.tune_state = DIM_GOING_RIGHT;
            dim.steps_right = 0;
        }
        // No C default; any other value falls through doing nothing.
        _ => {}
    }
}

kernel::kabi_export! {
    dim_park_on_top,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dim } dim ) -> base_type void",
}

/// # Safety
/// `dim` must point at a valid, writable `struct dim`.
#[no_mangle]
pub unsafe extern "C" fn dim_park_on_top(dim: *mut Dim) {
    // SAFETY: caller's contract.
    let dim = unsafe { &mut *dim };
    dim.steps_right = 0;
    dim.steps_left = 0;
    dim.tired = 0;
    dim.tune_state = DIM_PARKING_ON_TOP;
}

kernel::kabi_export! {
    dim_park_tired,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dim } dim ) -> base_type void",
}

/// # Safety
/// `dim` must point at a valid, writable `struct dim`.
#[no_mangle]
pub unsafe extern "C" fn dim_park_tired(dim: *mut Dim) {
    // SAFETY: caller's contract.
    let dim = unsafe { &mut *dim };
    dim.steps_right = 0;
    dim.steps_left = 0;
    dim.tune_state = DIM_PARKING_TIRED;
}

kernel::kabi_export! {
    dim_calc_stats,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#dim_sample } } start , formal_parameter pointer_type { const_type { s#dim_sample } } end , formal_parameter pointer_type { s#dim_stats } curr_stats ) -> t#bool",
}

/// # Safety
/// `start` and `end` must point at valid, readable `struct dim_sample`s;
/// `curr_stats` must point at a valid, writable `struct dim_stats`.
#[no_mangle]
pub unsafe extern "C" fn dim_calc_stats(
    start: *const DimSample,
    end: *const DimSample,
    curr_stats: *mut DimStats,
) -> bool {
    // SAFETY: caller's contract.
    let (start, end) = unsafe { (&*start, &*end) };

    // u32 holds up to 71 minutes, should be enough -- same comment as the C.
    let delta_us = (end.time.wrapping_sub(start.time) / 1000) as u32;
    let npkts = end.pkt_ctr.wrapping_sub(start.pkt_ctr);
    let nbytes = end.byte_ctr.wrapping_sub(start.byte_ctr);
    let ncomps = end.comp_ctr.wrapping_sub(start.comp_ctr);

    if delta_us == 0 {
        return false;
    }

    const DIM_NEVENTS: u64 = 64;
    const USEC_PER_MSEC: u64 = 1000;

    let div_round_up = |n: u64, d: u64| (n + d - 1) / d;

    // SAFETY: caller's contract.
    let curr_stats = unsafe { &mut *curr_stats };
    let delta_us64 = delta_us as u64;
    curr_stats.ppms = div_round_up(npkts as u64 * USEC_PER_MSEC, delta_us64) as c_int;
    curr_stats.bpms = div_round_up(nbytes as u64 * USEC_PER_MSEC, delta_us64) as c_int;
    curr_stats.epms = div_round_up(DIM_NEVENTS * USEC_PER_MSEC, delta_us64) as c_int;
    curr_stats.cpms = div_round_up(ncomps as u64 * USEC_PER_MSEC, delta_us64) as c_int;

    curr_stats.cpe_ratio = if curr_stats.epms != 0 {
        // Sign-extend-then-reinterpret, matching C's int -> unsigned long
        // long conversion (see module doc).
        let numer = (curr_stats.cpms as i64 as u64).wrapping_mul(100);
        let denom = curr_stats.epms as u32 as u64;
        (numer / denom) as c_int
    } else {
        0
    };

    true
}
