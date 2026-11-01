// SPDX-License-Identifier: GPL-2.0

//! The CPU-grouping algorithm behind `group_cpus_evenly()` -- the Rust behind `lib/group_cpus.c`.
//!
//! Ported from `lib/group_cpus.c` (6.18.49), Copyright (C) 2016 Thomas Gleixner and 2016-2017 Christoph Hellwig. In Rust:
//! `grp_spread_init_one` (fill one group from a node's CPUs, siblings first), `get_nodes_in_cpumask`, `alloc_nodes_groups` (how many
//! groups each NUMA node gets, smallest node first) and `__group_cpus_evenly` (spread the groups over the nodes and the CPUs).
//! In C (`group_cpus_glue.c`): `group_cpus_evenly()` itself -- the scratch-mask and node-table allocation and its unwinding, which
//! depend on `CONFIG_CPUMASK_OFFSTACK` -- plus every access to a kernel structure whose layout or accessor varies by configuration
//! (`struct cpumask` operations, the sibling mask, `cpu_to_node`, `node_states`, `nr_node_ids`), the three `WARN_ON_ONCE()` sites
//! and the allocator calls.
//!
//! # Notes
//! * `struct cpumask` is opaque here: it is only ever handled through the glue's one-line wrappers, and the stride between the
//!   groups of `masks[]` is `sizeof(struct cpumask)`, which the glue reports.
//! * `nodemask_t` is local to `__group_cpus_evenly` (never leaves it), so it is a plain bit array of at most 1024 nodes
//!   (`NODES_SHIFT <= 10`, asserted in the glue); `for_each_node_mask` is a scan of the set bits below `MAX_NUMNODES`.
//! * `for_each_node()` (possible nodes) goes through the glue's `rust_gc_next_node()`, which is the C macro itself.
//! * The 32-bit arithmetic of the C (`numgrps * ncpus`, `ncpus - ngroups * (ncpus / ngroups)`, the `ncpus` difference in the sort
//!   comparison) is unsigned and wraps; here it is `wrapping_*`.
//!
//! Replaces: lib/group_cpus.c (the grouping algorithm; the allocation scaffolding and the exported entry point stay C)

use core::ffi::{c_int, c_uint, c_ulong, c_void};

const ENOMEM: c_int = 12;
const BITS_PER_LONG: usize = 64;

/// The kernel's `struct cpumask`; only ever used by pointer.
#[repr(C)]
pub struct Cpumask {
    _opaque: [u8; 0],
}

/// `struct node_groups`: the node id, and (a union in the C) either the group count or the CPU count of that node.
#[repr(C)]
#[derive(Clone, Copy)]
struct NodeGroups {
    id: c_uint,
    /// `ngroups` / `ncpus`.
    v: c_uint,
}

/// `nodemask_t`, widened to the largest `MAX_NUMNODES` the kernel allows.
type Nodemask = [c_ulong; 1024 / BITS_PER_LONG];

extern "C" {
    fn rust_gc_nr_cpu_ids() -> c_uint;
    fn rust_gc_nr_node_ids() -> c_uint;
    fn rust_gc_max_numnodes() -> c_int;
    fn rust_gc_cpumask_stride() -> usize;
    fn rust_gc_next_node(n: c_int) -> c_int;
    fn rust_gc_node_mask(tbl: *mut c_void, n: c_uint) -> *mut Cpumask;
    fn rust_gc_sibling_mask(cpu: c_int) -> *const Cpumask;
    fn rust_gc_cpumask_first(m: *const Cpumask) -> c_uint;
    fn rust_gc_cpumask_next(n: c_int, m: *const Cpumask) -> c_uint;
    fn rust_gc_cpumask_clear_cpu(cpu: c_int, m: *mut Cpumask);
    fn rust_gc_cpumask_set_cpu(cpu: c_int, m: *mut Cpumask);
    fn rust_gc_cpumask_test_and_clear_cpu(cpu: c_int, m: *mut Cpumask) -> bool;
    fn rust_gc_cpumask_and(dst: *mut Cpumask, a: *const Cpumask, b: *const Cpumask) -> bool;
    fn rust_gc_cpumask_or(dst: *mut Cpumask, a: *const Cpumask, b: *const Cpumask);
    fn rust_gc_cpumask_weight(m: *const Cpumask) -> c_uint;
    fn rust_gc_cpumask_empty(m: *const Cpumask) -> bool;
    fn rust_gc_cpumask_intersects(a: *const Cpumask, b: *const Cpumask) -> bool;
    fn rust_gc_warn_numgrps_zero(cond: bool);
    fn rust_gc_warn_ngroups_gt_ncpus_alloc(cond: bool);
    fn rust_gc_warn_ngroups_gt_ncpus_spread(cond: bool);
    fn rust_gc_kcalloc(n: usize, size: usize) -> *mut c_void;
    fn rust_gc_kfree(p: *mut c_void);
    /// `lib/sort.c`.
    fn sort(
        base: *mut c_void,
        num: usize,
        size: usize,
        cmp: extern "C" fn(*const c_void, *const c_void) -> c_int,
        swap: *const c_void,
    );
}

#[inline(always)]
fn nodemask_test(m: &Nodemask, n: c_int) -> bool {
    m[n as usize / BITS_PER_LONG] >> (n as usize % BITS_PER_LONG) & 1 != 0
}

#[inline(always)]
fn nodemask_set(m: &mut Nodemask, n: c_int) {
    m[n as usize / BITS_PER_LONG] |= 1 << (n as usize % BITS_PER_LONG);
}

/// `for_each_node_mask()`'s step: the first set node after `n` (`-1` to start), or `MAX_NUMNODES`.
#[inline(always)]
unsafe fn next_node_in(n: c_int, m: &Nodemask) -> c_int {
    // SAFETY: plain value from the glue.
    let max = unsafe { rust_gc_max_numnodes() };
    let mut k = n + 1;

    while k < max {
        if nodemask_test(m, k) {
            return k;
        }
        k += 1;
    }
    max
}

/// `grp_spread_init_one()`: take `cpus_per_grp` CPUs out of `nmsk` into `irqmsk`, each CPU followed by its siblings.
unsafe fn grp_spread_init_one(irqmsk: *mut Cpumask, nmsk: *mut Cpumask, mut cpus_per_grp: c_uint) {
    // SAFETY: caller contract; the glue wrappers are the C inlines.
    unsafe {
        let nr_cpu_ids = rust_gc_nr_cpu_ids();

        while cpus_per_grp > 0 {
            let cpu = rust_gc_cpumask_first(nmsk) as c_int;

            /* Should not happen, but I'm too lazy to think about it */
            if cpu as c_uint >= nr_cpu_ids {
                return;
            }

            rust_gc_cpumask_clear_cpu(cpu, nmsk);
            rust_gc_cpumask_set_cpu(cpu, irqmsk);
            cpus_per_grp -= 1;

            /* If the cpu has siblings, use them first */
            let siblmsk = rust_gc_sibling_mask(cpu);
            let mut sibl: c_int = -1;
            while cpus_per_grp > 0 {
                sibl = rust_gc_cpumask_next(sibl, siblmsk) as c_int;
                if sibl as c_uint >= nr_cpu_ids {
                    break;
                }
                if !rust_gc_cpumask_test_and_clear_cpu(sibl, nmsk) {
                    continue;
                }
                rust_gc_cpumask_set_cpu(sibl, irqmsk);
                cpus_per_grp -= 1;
            }
        }
    }
}

/// `get_nodes_in_cpumask()`: the nodes that have a CPU in `mask`, set in `nodemsk`; returns how many.
unsafe fn get_nodes_in_cpumask(node_to_cpumask: *mut c_void, mask: *const Cpumask, nodemsk: &mut Nodemask) -> c_uint {
    // SAFETY: caller contract.
    unsafe {
        let max = rust_gc_max_numnodes();
        let mut nodes: c_uint = 0;

        /* Calculate the number of nodes in the supplied affinity mask */
        let mut n = rust_gc_next_node(-1);
        while n < max {
            if rust_gc_cpumask_intersects(mask, rust_gc_node_mask(node_to_cpumask, n as c_uint)) {
                nodemask_set(nodemsk, n);
                nodes += 1;
            }
            n = rust_gc_next_node(n);
        }
        nodes
    }
}

/// `ncpus_cmp_func()`: `sort()` comparison on the CPU count.
extern "C" fn ncpus_cmp_func(l: *const c_void, r: *const c_void) -> c_int {
    // SAFETY: `sort()` hands back pointers into the `NodeGroups` array.
    let (ln, rn) = unsafe { (&*(l as *const NodeGroups), &*(r as *const NodeGroups)) };

    ln.v.wrapping_sub(rn.v) as c_int
}

/// `alloc_nodes_groups()`: allocate a group count to each node, smallest node first, each at least 1 and at most its active CPUs.
unsafe fn alloc_nodes_groups(
    numgrps: c_uint,
    node_to_cpumask: *mut c_void,
    cpu_mask: *const Cpumask,
    nodemsk: &Nodemask,
    nmsk: *mut Cpumask,
    node_groups: *mut NodeGroups,
) {
    // SAFETY: caller contract.
    unsafe {
        let nr_node_ids = rust_gc_nr_node_ids();
        let mut numgrps = numgrps;
        let mut remaining_ncpus: c_uint = 0;

        for n in 0..nr_node_ids {
            (*node_groups.add(n as usize)).id = n;
            (*node_groups.add(n as usize)).v = c_uint::MAX;
        }

        let max = rust_gc_max_numnodes();
        let mut n = next_node_in(-1, nodemsk);
        while n < max {
            rust_gc_cpumask_and(nmsk, cpu_mask, rust_gc_node_mask(node_to_cpumask, n as c_uint));
            let ncpus = rust_gc_cpumask_weight(nmsk);

            if ncpus != 0 {
                remaining_ncpus = remaining_ncpus.wrapping_add(ncpus);
                (*node_groups.add(n as usize)).v = ncpus;
            }
            n = next_node_in(n, nodemsk);
        }

        numgrps = core::cmp::min(remaining_ncpus, numgrps);

        sort(
            node_groups.cast(),
            nr_node_ids as usize,
            core::mem::size_of::<NodeGroups>(),
            ncpus_cmp_func,
            core::ptr::null(),
        );

        /* Allocate groups for each node according to the ratio of this node's nr_cpus to remaining un-assigned ncpus. 'numgrps' is
         * bigger than number of active numa nodes. Always start the allocation from the node with minimized nr_cpus. (The C carries
         * the proof that every node ends with 1 <= ngroups <= its CPU count.) */
        for n in 0..nr_node_ids {
            let ng = &mut *node_groups.add(n as usize);

            if ng.v == c_uint::MAX {
                continue;
            }

            rust_gc_warn_numgrps_zero(numgrps == 0);

            let ncpus = ng.v;
            let ngroups = core::cmp::max(1, numgrps.wrapping_mul(ncpus) / remaining_ncpus);
            rust_gc_warn_ngroups_gt_ncpus_alloc(ngroups > ncpus);

            ng.v = ngroups;

            remaining_ncpus = remaining_ncpus.wrapping_sub(ncpus);
            numgrps = numgrps.wrapping_sub(ngroups);
        }
    }
}

/// `__group_cpus_evenly()`: spread `numgrps` groups, starting at `startgrp`, over the CPUs of `cpu_mask`. Returns the number of
/// groups filled, or `-ENOMEM`.
///
/// # Safety
/// `node_to_cpumask` is the glue's per-node mask table, `cpu_mask`/`nmsk` are valid masks, `masks` has `numgrps` groups.
#[no_mangle]
pub unsafe extern "C" fn rust___group_cpus_evenly(
    startgrp: c_uint,
    numgrps: c_uint,
    node_to_cpumask: *mut c_void,
    cpu_mask: *const Cpumask,
    nmsk: *mut Cpumask,
    masks: *mut Cpumask,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let stride = rust_gc_cpumask_stride();
        let group = |i: c_uint| (masks as *mut u8).add(i as usize * stride) as *mut Cpumask;
        let mut done: c_uint = 0;
        let last_grp = numgrps;
        let mut curgrp = startgrp;
        let mut nodemsk: Nodemask = [0; 1024 / BITS_PER_LONG];

        if rust_gc_cpumask_empty(cpu_mask) {
            return 0;
        }

        let nodes = get_nodes_in_cpumask(node_to_cpumask, cpu_mask, &mut nodemsk);

        /* If the number of nodes in the mask is greater than or equal the number of groups we just spread the groups across the nodes. */
        if numgrps <= nodes {
            let max = rust_gc_max_numnodes();
            let mut n = next_node_in(-1, &nodemsk);

            while n < max {
                /* Ensure that only CPUs which are in both masks are set */
                rust_gc_cpumask_and(nmsk, cpu_mask, rust_gc_node_mask(node_to_cpumask, n as c_uint));
                rust_gc_cpumask_or(group(curgrp), group(curgrp), nmsk);
                curgrp += 1;
                if curgrp == last_grp {
                    curgrp = 0;
                }
                n = next_node_in(n, &nodemsk);
            }
            return numgrps as c_int;
        }

        let nr_node_ids = rust_gc_nr_node_ids();
        let node_groups = rust_gc_kcalloc(nr_node_ids as usize, core::mem::size_of::<NodeGroups>()) as *mut NodeGroups;
        if node_groups.is_null() {
            return -ENOMEM;
        }

        /* allocate group number for each node */
        alloc_nodes_groups(numgrps, node_to_cpumask, cpu_mask, &nodemsk, nmsk, node_groups);
        for i in 0..nr_node_ids {
            let nv = &*node_groups.add(i as usize);

            if nv.v == c_uint::MAX {
                continue;
            }

            /* Get the cpus on this node which are in the mask */
            rust_gc_cpumask_and(nmsk, cpu_mask, rust_gc_node_mask(node_to_cpumask, nv.id));
            let ncpus = rust_gc_cpumask_weight(nmsk);
            if ncpus == 0 {
                continue;
            }

            rust_gc_warn_ngroups_gt_ncpus_spread(nv.v > ncpus);

            /* Account for rounding errors */
            let mut extra_grps = ncpus.wrapping_sub(nv.v.wrapping_mul(ncpus / nv.v));

            /* Spread allocated groups on CPUs of the current node */
            let mut v: c_uint = 0;
            while v < nv.v {
                let mut cpus_per_grp = ncpus / nv.v;

                /* Account for extra groups to compensate rounding errors */
                if extra_grps != 0 {
                    cpus_per_grp += 1;
                    extra_grps -= 1;
                }

                /* wrapping has to be considered given 'startgrp' may start anywhere */
                if curgrp >= last_grp {
                    curgrp = 0;
                }
                grp_spread_init_one(group(curgrp), nmsk, cpus_per_grp);
                v += 1;
                curgrp = curgrp.wrapping_add(1);
            }
            done = done.wrapping_add(nv.v);
        }
        rust_gc_kfree(node_groups.cast());
        done as c_int
    }
}
