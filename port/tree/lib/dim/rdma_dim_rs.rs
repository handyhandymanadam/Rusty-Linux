// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

//! RDMA Dynamic Interrupt Moderation (DIM) -- the Rust behind
//! `lib/dim/rdma_dim.c`.
//!
//! Replaces: lib/dim/rdma_dim.c
//!
//! Companion port to `dim_rs.rs` (`lib/dim/dim.c`) -- see that file's module
//! doc for the `dimlib.o` linking shape and why `net_dim.c` stays C. This is
//! a SEPARATE crate (one crate per ported file, per STATUS.md's crate
//! granularity note), so `RdmaDim`/`RdmaDimStats`/`RdmaDimSample`/
//! `RdmaDimWorkStruct` below are this crate's OWN mirrors of the same C
//! structs `dim_rs.rs` also mirrors under the plain names (`Dim`/
//! `DimStats`/`DimSample`/`WorkStruct`) -- not shared Rust types, the same
//! way `lib/zstd`'s several crates each keep their own mirror of `struct
//! z_stream_s`. Prefixed here (not in dim_rs.rs) so `rig/layout-check.sh`'s
//! `pahole -C NAME` can resolve each one uniquely instead of reporting
//! AMBIGUOUS -- same fix `interval_tree_rs.rs` already applied against
//! `timerqueue_rs.rs`'s bare `RbNode`/`RbRoot` (commit 2e04648). Adversarially
//! flagged 2026-09-06: an ambiguous pair is invisible to every future gate
//! (layout-check refuses to judge it, no CRC exists on these, no
//! differential constructs one), so a later edit to one mirror and not the
//! other would go undetected forever; naming them apart turns that into an
//! ordinary per-build check again. `dim_turn()` and `dim_calc_stats()` are
//! called across the crate boundary via their real `extern "C"` symbols
//! (`dim_rs.rs`'s `kernel::kabi_export!`s), exactly like calling into any
//! other externally-defined kernel function.
//!
//! # `schedule_work()`, and the one retained C helper this file needs
//!
//! `schedule_work(work)` is `static inline`, inlining to
//! `queue_work_on(WORK_CPU_UNBOUND, system_percpu_wq, work)` --
//! and `WORK_CPU_UNBOUND == NR_CPUS`, a config-dependent value
//! (`CONFIG_NR_CPUS`) this file has no business hardcoding. Rather than
//! reproduce workqueue internals for one call, `rdma_dim_thunk.c` keeps a
//! one-line retained C helper, `rust_rdma_dim_schedule_work()`, the same
//! shape `logs/porting-hazards.md`'s "raw uaccess" resolution already
//! established for `unsafe_get_user()`: a small retained C helper per call
//! site rather than reproducing an inline macro's expansion by hand.
//!
//! # `dim_update_sample`/`dim_update_sample_with_comps`, also `static
//! # inline`, but reproduced directly rather than thunked
//!
//! Both are trivial field assignments plus one call to `ktime_get()`, which
//! IS a real `extern` function (`include/linux/timekeeping.h`) -- no
//! workqueue-style config dependency, so this file just calls `ktime_get()`
//! directly and reproduces the two inline functions' bodies verbatim
//! (`dim_update_sample_with_comps` below).
//!
//! # Truncation in `dim_update_sample_with_comps`'s two call sites
//!
//! `curr_sample->event_ctr + 1`: `event_ctr` is `u16`, but C's usual
//! arithmetic conversions promote it to `int` before the `+1`, so the
//! addition itself never wraps at 16 bits in C -- truncation only happens
//! when the `int` result is passed into the `u16 event_ctr` parameter.
//! `curr_sample.event_ctr.wrapping_add(1)` (`u16` wrapping throughout)
//! reaches the identical final value for every input including the
//! boundary (`65535 + 1` -> `int` 65536 -> truncated to `u16` 0, same as
//! wrapping `u16` 65535+1 -> 0), so the shortcut is behaviourally exact.
//! `curr_sample->comp_ctr + completions`: `comp_ctr` (`u32`) promotes to
//! `u64` to match `completions` (`u64`), and truncation to the `comp_ctr`
//! field only happens at the FINAL assignment inside
//! `dim_update_sample_with_comps` -- ported as `u64` addition throughout,
//! truncated to `u32` only where the C's assignment does.

use core::ffi::c_int;

// --- enum dim_step_result ---------------------------------------------------
const DIM_STEPPED: c_int = 0;
const DIM_ON_EDGE: c_int = 2;

// --- enum dim_stats_state ---------------------------------------------------
const DIM_STATS_WORSE: c_int = 0;
const DIM_STATS_SAME: c_int = 1;
const DIM_STATS_BETTER: c_int = 2;

// --- enum dim_state, stored in dim->state (u8) ------------------------------
const DIM_START_MEASURE: u8 = 0;
const DIM_MEASURE_IN_PROGRESS: u8 = 1;
const DIM_APPLY_NEW_PROFILE: u8 = 2;

// --- enum dim_tune_state, stored in dim->tune_state (u8) --------------------
const DIM_PARKING_ON_TOP: u8 = 0;
const DIM_PARKING_TIRED: u8 = 1;
const DIM_GOING_RIGHT: u8 = 2;
const DIM_GOING_LEFT: u8 = 3;

const RDMA_DIM_PARAMS_NUM_PROFILES: u8 = 9;
const DIM_NEVENTS: u16 = 64;

/// Mirrors `struct dim_stats`. This crate's own copy -- see module doc.
#[repr(C)]
pub struct RdmaDimStats {
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

/// Mirrors `struct dim_sample`. This crate's own copy -- see module doc.
#[repr(C)]
pub struct RdmaDimSample {
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

/// Mirrors `struct list_head`. This crate's own copy -- see module doc.
/// Only ever embedded in `RdmaDimWorkStruct`, never read -- real fields,
/// not an opaque blob, for the reason dim_rs.rs's `ListHead` doc gives
/// (an opaque same-size blob fails layout-check's per-member geometry
/// check even though total size matches).
#[repr(C)]
pub struct RdmaDimListHead {
    next: *mut core::ffi::c_void,
    prev: *mut core::ffi::c_void,
}

/// Mirrors `struct lockdep_map`, gated the same way and for the same
/// reason as `dim_rs.rs`'s `LockdepMap` -- see that file's doc.
#[cfg(CONFIG_LOCKDEP)]
#[repr(C)]
pub struct RdmaDimLockdepMap {
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

/// Mirrors `struct work_struct`. This crate's own copy -- see module doc,
/// and see `dim_rs.rs`'s `WorkStruct` for why `lockdep_map` is
/// `#[cfg(CONFIG_LOCKDEP)]` and why it's unverified by this project's own
/// gates (neither config sets `CONFIG_LOCKDEP=y`).
#[repr(C)]
pub struct RdmaDimWorkStruct {
    data: i64,
    entry: RdmaDimListHead,
    func: *mut core::ffi::c_void,
    #[cfg(CONFIG_LOCKDEP)]
    lockdep_map: RdmaDimLockdepMap,
}

/// Mirrors `struct dim`. This crate's own copy -- see module doc.
#[repr(C)]
pub struct RdmaDim {
    /// Algorithm state.
    pub state: u8,
    /// Measured rates from the previous iteration.
    pub prev_stats: RdmaDimStats,
    /// Sampled data at the start of the current iteration.
    pub start_sample: RdmaDimSample,
    /// Sample used to update the current events.
    pub measuring_sample: RdmaDimSample,
    /// Work to perform on action required.
    pub work: RdmaDimWorkStruct,
    /// Pointer to the struct that points to this `RdmaDim`.
    pub priv_: *mut core::ffi::c_void,
    /// Current moderation profile.
    pub profile_ix: u8,
    /// CQ period count mode.
    pub mode: u8,
    /// Algorithm tuning state.
    pub tune_state: u8,
    /// Steps taken towards higher moderation.
    pub steps_right: u8,
    /// Steps taken towards lower moderation.
    pub steps_left: u8,
    /// Parking depth counter.
    pub tired: u8,
}

extern "C" {
    fn dim_turn(dim: *mut RdmaDim);
    fn dim_calc_stats(start: *const RdmaDimSample, end: *const RdmaDimSample, curr_stats: *mut RdmaDimStats) -> bool;
    fn ktime_get() -> i64;
    fn rust_rdma_dim_schedule_work(work: *mut RdmaDimWorkStruct);
}

/// `IS_SIGNIFICANT_DIFF(val, ref)`: `(ref) && (((100UL * abs((val)-(ref))) /
/// (ref)) > 10)`. `abs()` operates on `int`; the multiply-by-100 promotes to
/// `unsigned long` (sign-extend-then-reinterpret, matching every other
/// int->u64 promotion in this port -- see dim_rs.rs's module doc), and the
/// division promotes `ref` the same way.
fn is_significant_diff(val: c_int, r: c_int) -> bool {
    if r == 0 {
        return false;
    }
    let diff = val.wrapping_sub(r).wrapping_abs();
    let numer = (diff as i64 as u64).wrapping_mul(100);
    let denom = r as i64 as u64;
    numer / denom > 10
}

/// Body of `dim_update_sample`/`dim_update_sample_with_comps` -- both
/// `static inline` in the C, no linkable symbol, reproduced directly.
///
/// # Safety
/// `s` must point at a valid, writable `struct dim_sample`.
unsafe fn dim_update_sample_with_comps(
    event_ctr: u16,
    packets: u64,
    bytes: u64,
    comps: u64,
    s: *mut RdmaDimSample,
) {
    // SAFETY: caller's contract.
    let s = unsafe { &mut *s };
    // SAFETY: ktime_get() has no preconditions.
    s.time = unsafe { ktime_get() };
    s.pkt_ctr = packets as u32;
    s.byte_ctr = bytes as u32;
    s.event_ctr = event_ctr;
    s.comp_ctr = comps as u32;
}

/// Body of `rdma_dim_step()`.
fn rdma_dim_step(dim: &mut RdmaDim) -> c_int {
    if dim.tune_state == DIM_GOING_RIGHT {
        if dim.profile_ix == RDMA_DIM_PARAMS_NUM_PROFILES - 1 {
            return DIM_ON_EDGE;
        }
        dim.profile_ix += 1;
        dim.steps_right += 1;
    }
    if dim.tune_state == DIM_GOING_LEFT {
        if dim.profile_ix == 0 {
            return DIM_ON_EDGE;
        }
        dim.profile_ix -= 1;
        dim.steps_left += 1;
    }
    DIM_STEPPED
}

/// Body of `rdma_dim_stats_compare()`.
fn rdma_dim_stats_compare(curr: &RdmaDimStats, prev: &RdmaDimStats) -> c_int {
    if prev.cpms == 0 {
        return DIM_STATS_SAME;
    }
    if is_significant_diff(curr.cpms, prev.cpms) {
        return if curr.cpms > prev.cpms {
            DIM_STATS_BETTER
        } else {
            DIM_STATS_WORSE
        };
    }
    if is_significant_diff(curr.cpe_ratio, prev.cpe_ratio) {
        return if curr.cpe_ratio > prev.cpe_ratio {
            DIM_STATS_BETTER
        } else {
            DIM_STATS_WORSE
        };
    }
    DIM_STATS_SAME
}

/// Body of `rdma_dim_decision()`.
///
/// # Safety
/// `dim` must point at a valid, writable `struct dim`.
unsafe fn rdma_dim_decision(curr_stats: &RdmaDimStats, dim: *mut RdmaDim) -> bool {
    // No named `&mut *dim` reborrow held across a `dim_turn(dim)` call:
    // `dim_turn` takes the raw `dim` and does its own `&mut *dim` reborrow
    // internally (dim_rs.rs), which invalidates a caller-held `&mut` across
    // the call -- same shape as the zstd_decompress_block_rs.rs fix, found
    // by the same sweep (2026-09-06). Every access below is either a fresh
    // `(*dim).field` or a reborrow created and consumed within a single
    // call expression, never named across one.
    // SAFETY: caller's contract, for every access in this function.
    unsafe {
        let prev_ix = (*dim).profile_ix;
        let state = (*dim).tune_state;

        if state != DIM_PARKING_ON_TOP && state != DIM_PARKING_TIRED {
            let stats_res = rdma_dim_stats_compare(curr_stats, &(*dim).prev_stats);

            if stats_res == DIM_STATS_SAME {
                if curr_stats.cpe_ratio <= 50 * prev_ix as c_int {
                    (*dim).profile_ix = 0;
                }
            } else if stats_res == DIM_STATS_WORSE {
                dim_turn(dim);
                let step_res = rdma_dim_step(&mut *dim);
                if step_res == DIM_ON_EDGE {
                    dim_turn(dim);
                }
            } else if stats_res == DIM_STATS_BETTER {
                let step_res = rdma_dim_step(&mut *dim);
                if step_res == DIM_ON_EDGE {
                    dim_turn(dim);
                }
            }
        }

        (*dim).prev_stats = RdmaDimStats {
            ppms: curr_stats.ppms,
            bpms: curr_stats.bpms,
            epms: curr_stats.epms,
            cpms: curr_stats.cpms,
            cpe_ratio: curr_stats.cpe_ratio,
        };

        (*dim).profile_ix != prev_ix
    }
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
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#atomic64_t",
    "typedef_type atomic64_t { structure_type { member t#s64 counter data_member_location(0) } byte_size(8) }");
kernel::kabi_rule!("type_string", "t#atomic_long_t",
    "typedef_type atomic_long_t { t#atomic64_t }");
kernel::kabi_rule!("type_string", "t#ktime_t",
    "typedef_type ktime_t { t#s64 }");
kernel::kabi_rule!("type_string", "t#s64",
    "typedef_type s64 { t#__s64 }");
kernel::kabi_rule!("type_string", "t#u16",
    "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#work_func_t",
    "typedef_type work_func_t { pointer_type { subroutine_type ( formal_parameter pointer_type { s#work_struct } ) -> base_type void } }");

kernel::kabi_export! {
    rdma_dim,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#dim } dim , formal_parameter t#u64 completions ) -> base_type void",
}

/// Runs the adaptive moderation.
///
/// # Safety
/// `dim` must point at a valid, writable `struct dim`.
#[no_mangle]
pub unsafe extern "C" fn rdma_dim(dim: *mut RdmaDim, completions: u64) {
    // No named `&mut *dim` reborrow: `rdma_dim_decision(_, dim)` below takes
    // the raw `dim` and reborrows it internally, which would invalidate a
    // caller-held `&mut` across that call -- same shape as
    // zstd_decompress_block_rs.rs's fix, found by the same sweep
    // (2026-09-06). `curr_sample_ptr` stays a raw pointer, freshly
    // dereferenced on each use (never bound to a named `&mut`), so it is
    // unaffected either way.
    // SAFETY: caller's contract, for every access in this function.
    let curr_sample_ptr: *mut RdmaDimSample = unsafe { &mut (*dim).measuring_sample };
    // SAFETY: part of `*dim`, valid per the caller's contract.
    let curr_event_ctr = unsafe { (*curr_sample_ptr).event_ctr };
    // SAFETY: part of `*dim`, valid per the caller's contract.
    let curr_comp_ctr = unsafe { (*curr_sample_ptr).comp_ctr };

    // SAFETY: `curr_sample_ptr` is valid per the caller's contract.
    unsafe {
        dim_update_sample_with_comps(
            curr_event_ctr.wrapping_add(1),
            0,
            0,
            curr_comp_ctr as u64 + completions,
            curr_sample_ptr,
        );
    }

    // SAFETY: as above.
    match unsafe { (*dim).state } {
        s if s == DIM_MEASURE_IN_PROGRESS => {
            // SAFETY: part of `*dim`.
            let curr_event_ctr = unsafe { (*curr_sample_ptr).event_ctr };
            // `u32 nevents = curr_sample->event_ctr - dim->start_sample.event_ctr;`
            // Both operands are u16, but C integer-promotes them to `int`
            // for the subtraction (32-bit signed, no 16-bit wrap) and THEN
            // converts the (possibly negative) result to the u32 `nevents`
            // -- so the promotion's extra range survives into the final
            // value, unlike `event_ctr + 1` above where the result lands
            // back in a u16 parameter and truncates the int-ness away.
            // Adversarially found (2026-09-06): a plain u16 wrapping_sub
            // here disagrees with the C on exactly the 2016 (start, curr)
            // pairs where curr < start and their 16-bit distance is 1..63 --
            // e.g. start=65535, curr=0 is C's ~4.29e9 (correctly >= 64,
            // proceeds) vs a naive u16 wrap's 1 (wrongly < 64, returns
            // early). Reproduced via i32, matching C's actual arithmetic
            // width, not the field width.
            // SAFETY: part of `*dim`.
            let nevents = (curr_event_ctr as i32)
                .wrapping_sub(unsafe { (*dim).start_sample.event_ctr } as i32)
                as u32;
            if nevents < DIM_NEVENTS as u32 {
                return;
            }
            let mut curr_stats = RdmaDimStats {
                ppms: 0,
                bpms: 0,
                epms: 0,
                cpms: 0,
                cpe_ratio: 0,
            };
            // SAFETY: dim_calc_stats is dim_rs.rs's real EXPORT_SYMBOL'd
            // function; both samples and curr_stats are valid.
            let ok = unsafe {
                dim_calc_stats(&(*dim).start_sample, curr_sample_ptr, &mut curr_stats)
            };
            if !ok {
                return;
            }
            // SAFETY: `dim` is valid per this function's contract.
            if unsafe { rdma_dim_decision(&curr_stats, dim) } {
                // SAFETY: part of `*dim`; `rdma_dim_decision`'s own
                // reborrow above has ended.
                unsafe {
                    (*dim).state = DIM_APPLY_NEW_PROFILE;
                    // `&mut (*dim).work` is a valid, embedded
                    // `struct work_struct`.
                    rust_rdma_dim_schedule_work(&mut (*dim).work);
                }
                return;
            }
            // fallthrough to DIM_START_MEASURE, matching the C's
            // `fallthrough;` between these two switch arms.
            // SAFETY: part of `*dim`.
            unsafe {
                (*dim).state = DIM_MEASURE_IN_PROGRESS;
            }
            // SAFETY: part of `*dim`.
            let curr_event_ctr = unsafe { (*curr_sample_ptr).event_ctr };
            let curr_comp_ctr = unsafe { (*curr_sample_ptr).comp_ctr };
            // SAFETY: valid pointer into `*dim`.
            unsafe {
                dim_update_sample_with_comps(
                    curr_event_ctr,
                    0,
                    0,
                    curr_comp_ctr as u64,
                    &mut (*dim).start_sample,
                );
            }
        }
        s if s == DIM_START_MEASURE => {
            // SAFETY: part of `*dim`.
            unsafe {
                (*dim).state = DIM_MEASURE_IN_PROGRESS;
            }
            // SAFETY: part of `*dim`.
            let curr_event_ctr = unsafe { (*curr_sample_ptr).event_ctr };
            let curr_comp_ctr = unsafe { (*curr_sample_ptr).comp_ctr };
            // SAFETY: valid pointer into `*dim`.
            unsafe {
                dim_update_sample_with_comps(
                    curr_event_ctr,
                    0,
                    0,
                    curr_comp_ctr as u64,
                    &mut (*dim).start_sample,
                );
            }
        }
        _ => {} // DIM_APPLY_NEW_PROFILE: nothing to do.
    }
}
