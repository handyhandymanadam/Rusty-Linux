// SPDX-License-Identifier: GPL-2.0-only

//! The CPU affinity reverse-map -- the Rust behind `lib/cpu_rmap.c`.
//!
//! Ported from `lib/cpu_rmap.c` (6.18.49, Solarflare): for every CPU, the index of the nearest object (an IRQ, say) and the topological distance to it (0: in the object's
//! affinity mask, 1: SMT sibling, 2: same core group, 3: same NUMA node, `0xffff`: unknown). In Rust: `alloc_cpu_rmap()`, `cpu_rmap_add()`, and the update after an affinity
//! change (`cpu_rmap_update()` without its `cpumask_var_t`, `cpu_rmap_copy_neigh()`). In C (`cpu_rmap_glue.c`): the exports as thunks (the MODVERSIONS fingerprint comes from
//! the DWARF of the definition), `cpu_rmap_update()`'s mask allocation (`cpumask_var_t` is an array or a pointer depending on `CONFIG_CPUMASK_OFFSTACK`), `cpu_rmap_get`/`put`
//! (kref and the release callback), the IRQ glue (`struct irq_glue`, affinity notifiers) and one-line wrappers for the cpumask iteration, topology masks, `nr_cpu_ids` and the
//! allocator.
//!
//! Replaces: lib/cpu_rmap.c (alloc_cpu_rmap, cpu_rmap_add, get_free_index, cpu_rmap_copy_neigh, the body of cpu_rmap_update)

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

const ENOSPC: c_int = 28;
const CPU_RMAP_DIST_INF: u16 = 0xffff;

/// `struct cpu_rmap` up to the flexible array (checked by `cpu_rmap_glue.c`).
#[repr(C)]
pub struct CpuRmap {
    refcount: u32,
    size: u16,
    obj: *mut *mut c_void,
}

/// `near[]` entries: `{ u16 index; u16 dist; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Near {
    index: u16,
    dist: u16,
}

/// `offsetof(struct cpu_rmap, near)`.
const OFF_NEAR: usize = 16;

extern "C" {
    fn rust_cr_nr_cpu_ids() -> u32;
    fn rust_cr_kzalloc(size: usize, gfp: u32) -> *mut c_void;
    fn rust_cr_kref_init(rmap: *mut CpuRmap);
    /// `cpumask_next(n, mask)` on `cpu_possible_mask` / `cpu_online_mask` / the given mask.
    fn rust_cr_next_possible(n: c_int) -> u32;
    fn rust_cr_next_online(n: c_int) -> u32;
    fn rust_cr_next(n: c_int, mask: *const c_void) -> u32;
    fn rust_cr_set_cpu(cpu: u32, mask: *mut c_void);
    /// `cpumask_or(update_mask, update_mask, cpumask_of_node(cpu_to_node(cpu)))`
    fn rust_cr_or_node(update_mask: *mut c_void, cpu: u32);
    fn rust_cr_sibling_mask(cpu: u32) -> *const c_void;
    fn rust_cr_core_mask(cpu: u32) -> *const c_void;
    fn rust_cr_node_mask(cpu: u32) -> *const c_void;
}

#[inline(always)]
unsafe fn near(rmap: *mut CpuRmap, cpu: u32) -> *mut Near {
    unsafe { ((rmap as *mut u8).add(OFF_NEAR) as *mut Near).add(cpu as usize) }
}

/// The body of C `alloc_cpu_rmap()`.
#[no_mangle]
pub unsafe extern "C" fn rust_alloc_cpu_rmap(size: u32, flags: u32) -> *mut CpuRmap {
    unsafe {
        // This is a silly number of objects, and we use u16 indices.
        if size > 0xffff {
            return null_mut();
        }

        // Offset of object pointer array from base structure: ALIGN(offsetof(struct cpu_rmap, near[nr_cpu_ids]), sizeof(void *))
        let obj_offset = (OFF_NEAR + core::mem::size_of::<Near>() * rust_cr_nr_cpu_ids() as usize + 7) & !7;

        let rmap = rust_cr_kzalloc(obj_offset + size as usize * core::mem::size_of::<*mut c_void>(), flags) as *mut CpuRmap;
        if rmap.is_null() {
            return null_mut();
        }

        rust_cr_kref_init(rmap);
        (*rmap).obj = (rmap as *mut u8).add(obj_offset) as *mut *mut c_void;

        // Initially assign CPUs to objects on a rota, since we have no idea where the objects are. Use infinite distance, so any object with known distance is preferable.
        // Include the CPUs that are not present/online, since we definitely want any newly-hotplugged CPUs to have some object assigned.
        let mut cpu = rust_cr_next_possible(-1);
        while cpu < rust_cr_nr_cpu_ids() {
            (*near(rmap, cpu)).index = (cpu % size) as u16;
            (*near(rmap, cpu)).dist = CPU_RMAP_DIST_INF;
            cpu = rust_cr_next_possible(cpu as c_int);
        }

        (*rmap).size = size as u16;
        rmap
    }
}

unsafe fn get_free_index(rmap: *mut CpuRmap) -> c_int {
    unsafe {
        let mut i: c_int = 0;
        while i < (*rmap).size as c_int {
            if (*(*rmap).obj.add(i as usize)).is_null() {
                return i;
            }
            i += 1;
        }
        -ENOSPC
    }
}

/// The body of C `cpu_rmap_add()`.
#[no_mangle]
pub unsafe extern "C" fn rust_cpu_rmap_add(rmap: *mut CpuRmap, obj: *mut c_void) -> c_int {
    unsafe {
        let index = get_free_index(rmap);
        if index < 0 {
            return index;
        }
        *(*rmap).obj.add(index as usize) = obj;
        index
    }
}

/// Reevaluate nearest object for given CPU, comparing with the given neighbours at the given distance.
unsafe fn cpu_rmap_copy_neigh(rmap: *mut CpuRmap, cpu: u32, mask: *const c_void, dist: u16) -> bool {
    unsafe {
        let mut neigh = rust_cr_next(-1, mask);
        while neigh < rust_cr_nr_cpu_ids() {
            if (*near(rmap, cpu)).dist > dist && (*near(rmap, neigh)).dist <= dist {
                (*near(rmap, cpu)).index = (*near(rmap, neigh)).index;
                (*near(rmap, cpu)).dist = dist;
                return true;
            }
            neigh = rust_cr_next(neigh as c_int, mask);
        }
        false
    }
}

/// The body of C `cpu_rmap_update()` after the allocation of `update_mask` (a zeroed mask of `nr_cpu_ids` bits, freed by the caller).
#[no_mangle]
pub unsafe extern "C" fn rust_cpu_rmap_update(rmap: *mut CpuRmap, index: u16, affinity: *const c_void, update_mask: *mut c_void) {
    unsafe {
        let nr = rust_cr_nr_cpu_ids();

        // Invalidate distance for all CPUs for which this used to be the nearest object. Mark those CPUs for update.
        let mut cpu = rust_cr_next_online(-1);
        while cpu < nr {
            if (*near(rmap, cpu)).index == index {
                (*near(rmap, cpu)).dist = CPU_RMAP_DIST_INF;
                rust_cr_set_cpu(cpu, update_mask);
            }
            cpu = rust_cr_next_online(cpu as c_int);
        }

        // Set distance to 0 for all CPUs in the new affinity mask. Mark all CPUs within their NUMA nodes for update.
        cpu = rust_cr_next(-1, affinity);
        while cpu < nr {
            (*near(rmap, cpu)).index = index;
            (*near(rmap, cpu)).dist = 0;
            rust_cr_or_node(update_mask, cpu);
            cpu = rust_cr_next(cpu as c_int, affinity);
        }

        // Update distances based on topology
        cpu = rust_cr_next(-1, update_mask);
        while cpu < nr {
            if !cpu_rmap_copy_neigh(rmap, cpu, rust_cr_sibling_mask(cpu), 1)
                && !cpu_rmap_copy_neigh(rmap, cpu, rust_cr_core_mask(cpu), 2)
            {
                // We could continue into NUMA node distances, but for now we give up.
                cpu_rmap_copy_neigh(rmap, cpu, rust_cr_node_mask(cpu), 3);
            }
            cpu = rust_cr_next(cpu as c_int, update_mask);
        }
    }
}
