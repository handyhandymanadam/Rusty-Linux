// SPDX-License-Identifier: GPL-2.0+

//! Maple tree -- the Rust behind `lib/maple_tree.c`.
//!
//! Ported from `lib/maple_tree.c` (6.18.49), "Maple Tree implementation" by Liam R. Howlett and Matthew Wilcox (Oracle), with Peng Zhang's
//! duplication code (ByteDance): an RCU-safe B-tree variant that stores *ranges* (each node holds up to 16 slots with the pivots between
//! them; nodes of three kinds -- dense, leaf and non-leaf range/allocation-range -- 256 bytes each), edited copy-on-write so readers never
//! see a half-made change, with a state object (`struct ma_state`) that carries a walker's position between calls.
//!
//! # Shape
//! * **In Rust**: every static function and the whole `mas_*` state machine: walking, the write paths (slot store, node store, append,
//!   split, spanning store, rebalance), `mas_find`/`next`/`prev`/`empty_area`, preallocation, duplication, destruction.
//! * **In C** (`maple_tree_glue.c`): the public entry points as thunks (`EXPORT_SYMBOL` fingerprints come from the DWARF of the
//!   definition); the wrappers that take a lock (`mtree_*`, `mt_find`, `mt_next`, ... `spin_lock`/`rcu_read_lock` are inline and
//!   configuration-dependent); the slab calls (`kmem_cache_*`, sheaves, `kfree_rcu`, `call_rcu`); every `BUG_ON`/`WARN_ON`/`WARN_ON_ONCE`
//!   site (one helper per kind, so the bug-table entry now names the glue -- recorded divergence); the tracepoints; and the layout asserts.
//!   `struct maple_tree` is not mirrored: its `ma_flags`/`ma_root` offsets depend on the lock size (lockdep, `DEBUG_SPINLOCK`), so the glue
//!   hands the Rust the two offsets as constants.
//! * Not carried: the `lockdep` assertions inside `rcu_dereference_check()`/`mt_locked()` (they only exist in lockdep builds and have no
//!   effect on behaviour), and the `CONFIG_DEBUG_MAPLE_TREE` dump/validate code (the Makefile builds the pristine file instead when that
//!   option is on).
//!
//! # The ordering contract (concurrency bar, item 1)
//! Readers walk with `READ_ONCE` loads (`read_volatile`) and re-check `ma_dead_node()` (a node whose parent points to itself) after reading
//! from it, with `smp_rmb()` before the check and `smp_wmb()` after a node is marked dead; writers build replacement nodes off to the side,
//! publish with `rcu_assign_pointer()` (`Release` store) and free the old nodes through RCU (`kfree_rcu`). All of this follows the C.
//!
//! Replaces: lib/maple_tree.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code, unused_imports, unused_assignments, clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr::{null, null_mut, read_volatile};
use core::sync::atomic::{fence, AtomicPtr, Ordering};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("maple_tree_rs.rs: x86-64 little-endian only (64-bit node sizes, struct layouts)");

type Gfp = c_uint;

// ---------------------------------------------------------------------------
// constants (include/linux/maple_tree.h)
// ---------------------------------------------------------------------------
const MAPLE_NODE_SLOTS: usize = 31;
const MAPLE_RANGE64_SLOTS: usize = 16;
const MAPLE_ARANGE64_SLOTS: usize = 10;
const MAPLE_ALLOC_SLOTS: usize = MAPLE_NODE_SLOTS - 1;
const MAPLE_NODE_MASK: usize = 255;
const MAPLE_RESERVED_RANGE: usize = 4096;
const MAPLE_HEIGHT_MAX: c_uint = 31;
const MAPLE_NODE_TYPE_MASK: usize = 0x0F;
const MAPLE_NODE_TYPE_SHIFT: usize = 0x03;

const MT_FLAGS_ALLOC_RANGE: c_uint = 0x01;
const MT_FLAGS_USE_RCU: c_uint = 0x02;
const MT_FLAGS_HEIGHT_OFFSET: c_uint = 0x02;
const MT_FLAGS_HEIGHT_MASK: c_uint = 0x7C;
const MT_FLAGS_LOCK_MASK: c_uint = 0x300;
const MT_FLAGS_LOCK_EXTERN: c_uint = 0x300;
const MT_FLAGS_ALLOC_WRAPPED: c_uint = 0x0800;

// enum maple_type
const maple_dense: u32 = 0;
const maple_leaf_64: u32 = 1;
const maple_range_64: u32 = 2;
const maple_arange_64: u32 = 3;

// enum store_type
const wr_invalid: u32 = 0;
const wr_new_root: u32 = 1;
const wr_store_root: u32 = 2;
const wr_exact_fit: u32 = 3;
const wr_spanning_store: u32 = 4;
const wr_split_store: u32 = 5;
const wr_rebalance: u32 = 6;
const wr_append: u32 = 7;
const wr_node_store: u32 = 8;
const wr_slot_store: u32 = 9;

// enum maple_status
const ma_active: u32 = 0;
const ma_start: u32 = 1;
const ma_root: u32 = 2;
const ma_none: u32 = 3;
const ma_pause: u32 = 4;
const ma_overflow: u32 = 5;
const ma_underflow: u32 = 6;
const ma_error: u32 = 7;

const MA_ROOT_PARENT: usize = 1;
const MA_STATE_PREALLOC: u8 = 1;

const MAPLE_BIG_NODE_SLOTS: usize = MAPLE_RANGE64_SLOTS * 2 + 2;
const MAPLE_BIG_NODE_GAPS: usize = MAPLE_ARANGE64_SLOTS * 2 + 1;

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;
const EBUSY: c_int = 16;
const EEXIST: c_int = 17;
const ERANGE: c_int = 34;
const EAGAIN: c_int = 11;
const ENOSPC: c_int = 28;
const GFP_NOWAIT: Gfp = 0; // unused by the Rust (the glue picks the flags); see `rust_mt_*` helpers
const ULONG_MAX: c_ulong = c_ulong::MAX;

/// `mt_slots[]`.
static mt_slots: [u8; 4] = [MAPLE_NODE_SLOTS as u8, MAPLE_RANGE64_SLOTS as u8, MAPLE_RANGE64_SLOTS as u8, MAPLE_ARANGE64_SLOTS as u8];
/// `mt_pivots[]`.
static mt_pivots: [u8; 4] = [0, MAPLE_RANGE64_SLOTS as u8 - 1, MAPLE_RANGE64_SLOTS as u8 - 1, MAPLE_ARANGE64_SLOTS as u8 - 1];
/// `mt_min_slots[]`.
static mt_min_slots: [u8; 4] = [
    (MAPLE_NODE_SLOTS / 2) as u8,
    (MAPLE_RANGE64_SLOTS / 2) as u8 - 2,
    (MAPLE_RANGE64_SLOTS / 2) as u8 - 2,
    (MAPLE_ARANGE64_SLOTS / 2) as u8 - 1,
];

// ---------------------------------------------------------------------------
// layouts
// ---------------------------------------------------------------------------

/// `struct maple_enode *` -- an encoded node pointer (type in bits 3-6, flags in the low bits).
type Enode = *mut c_void;
/// `struct maple_pnode *` -- an encoded parent pointer.
type Pnode = *mut c_void;

/// `struct maple_node`: 256 bytes, a union of the node kinds. Accessed through the offset helpers below.
#[repr(C, align(256))]
pub struct MapleNode {
    w: [usize; 32],
}
const _: () = assert!(core::mem::size_of::<MapleNode>() == 256);

/// `struct maple_metadata`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Meta {
    end: u8,
    gap: u8,
}

/// `struct maple_tree` is opaque here; see [`mt_flags`] and [`mt_root_p`].
#[repr(C)]
pub struct MapleTree {
    _opaque: [u8; 0],
}

/// `struct ma_state`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MaState {
    tree: *mut MapleTree,
    index: c_ulong,
    last: c_ulong,
    node: Enode,
    min: c_ulong,
    max: c_ulong,
    sheaf: *mut c_void,
    alloc: *mut MapleNode,
    node_request: c_ulong,
    status: u32,
    depth: u8,
    offset: u8,
    mas_flags: u8,
    end: u8,
    store_type: u32,
}

/// `struct ma_wr_state`.
#[repr(C)]
pub struct MaWrState {
    mas: *mut MaState,
    node: *mut MapleNode,
    r_min: c_ulong,
    r_max: c_ulong,
    type_: u32,
    offset_end: u8,
    pivots: *mut c_ulong,
    end_piv: c_ulong,
    slots: *mut *mut c_void,
    entry: *mut c_void,
    content: *mut c_void,
    vacant_height: u8,
    sufficient_height: u8,
}

/// `struct ma_topiary`.
#[repr(C)]
pub struct MaTopiary {
    head: Enode,
    tail: Enode,
    mtree: *mut MapleTree,
}

/// `struct maple_big_node`.
#[repr(C)]
struct MapleBigNode {
    pivot: [c_ulong; MAPLE_BIG_NODE_SLOTS - 1],
    /// The union of `slot[MAPLE_BIG_NODE_SLOTS]` and `{ padding[GAPS]; gap[GAPS] }`: kept as raw words; see [`bn_slot`] / [`bn_gap`].
    sg: [usize; MAPLE_BIG_NODE_GAPS * 2],
    b_end: u8,
    type_: u32,
}
const _: () = assert!(MAPLE_BIG_NODE_SLOTS <= MAPLE_BIG_NODE_GAPS * 2);

/// `struct maple_subtree_state`.
#[repr(C)]
struct MapleSubtreeState {
    orig_l: *mut MaState,
    orig_r: *mut MaState,
    l: *mut MaState,
    m: *mut MaState,
    r: *mut MaState,
    free: *mut MaTopiary,
    destroy: *mut MaTopiary,
    bn: *mut MapleBigNode,
}

extern "C" {
    /// `offsetof(struct maple_tree, ma_flags)` / `ma_root` of this configuration (the lock before them varies in size).
    static rust_mt_flags_off: usize;
    static rust_mt_root_off: usize;

    // glue: the slab and RCU calls.
    fn rust_mt_alloc_one(gfp: Gfp) -> *mut MapleNode;
    fn rust_mt_free_bulk(size: usize, nodes: *mut *mut c_void);
    fn rust_mt_return_sheaf(sheaf: *mut c_void);
    fn rust_mt_get_sheaf(gfp: Gfp, count: c_int) -> *mut c_void;
    fn rust_mt_refill_sheaf(gfp: Gfp, sheaf: *mut *mut c_void, size: c_uint) -> c_int;
    fn rust_mt_alloc_from_sheaf(sheaf: *mut c_void) -> *mut MapleNode;
    fn rust_mt_sheaf_size(sheaf: *mut c_void) -> c_uint;
    fn rust_mt_kfree(p: *mut c_void);
    fn rust_mt_free_rcu(node: *mut MapleNode);
    fn rust_mt_call_rcu_free_walk(node: *mut MapleNode);

    // glue: BUG_ON / WARN_ON sites and tracing.
    fn rust_mt_bug() -> !;
    fn rust_mt_warn(cond: bool) -> bool;
    fn rust_mt_warn_once(cond: bool) -> bool;
    fn rust_mt_trace_ma_op(func: *const c_char, mas: *mut MaState);
    fn rust_mt_trace_ma_read(func: *const c_char, mas: *mut MaState);
    fn rust_mt_trace_ma_write(func: *const c_char, mas: *mut MaState, piv: c_ulong, val: *mut c_void);
}

/// `BUG_ON()` / `MT_BUG_ON()` / `MAS_BUG_ON()` / `MAS_WR_BUG_ON()` (non-debug builds: all are `BUG_ON`).
#[inline(always)]
fn bug_on(cond: bool) {
    if cond {
        // SAFETY: never returns.
        unsafe { rust_mt_bug() }
    }
}
/// `WARN_ON()` / `MT_WARN_ON()` / `MAS_WARN_ON()` / `MAS_WR_WARN_ON()`: returns the condition.
#[inline(always)]
fn warn_on(cond: bool) -> bool {
    // SAFETY: plain call.
    unsafe { rust_mt_warn(cond) }
}
/// `WARN_ON_ONCE()`.
#[inline(always)]
fn warn_on_once(cond: bool) -> bool {
    // SAFETY: plain call.
    unsafe { rust_mt_warn_once(cond) }
}

/// `smp_rmb()` / `smp_wmb()`.
#[inline(always)]
fn smp_rmb() {
    fence(Ordering::Acquire);
}
#[inline(always)]
fn smp_wmb() {
    fence(Ordering::Release);
}

/// `READ_ONCE()`.
#[inline(always)]
unsafe fn rd<T: Copy>(p: *const T) -> T {
    // SAFETY: caller contract.
    unsafe { read_volatile(p) }
}

// ---------------------------------------------------------------------------
// struct maple_tree access (offsets supplied by the glue)
// ---------------------------------------------------------------------------
#[inline(always)]
unsafe fn mt_flags(mt: *const MapleTree) -> *mut c_uint {
    // SAFETY: the glue's offset is `offsetof(struct maple_tree, ma_flags)`.
    unsafe { (mt as *mut u8).add(rust_mt_flags_off).cast() }
}
#[inline(always)]
unsafe fn mt_root_p(mt: *const MapleTree) -> *mut *mut c_void {
    // SAFETY: as above, for `ma_root`.
    unsafe { (mt as *mut u8).add(rust_mt_root_off).cast() }
}

// ---------------------------------------------------------------------------
// struct maple_node access (byte offsets verified by the glue's static_asserts)
// ---------------------------------------------------------------------------
#[inline(always)]
unsafe fn nb(n: *mut MapleNode, off: usize) -> *mut u8 {
    // SAFETY: caller contract (`n` is a valid node, `off` inside it).
    unsafe { (n as *mut u8).add(off) }
}
/// `node->parent`.
#[inline(always)]
unsafe fn n_parent(n: *mut MapleNode) -> *mut Pnode {
    n.cast()
}
/// `node->slot` (dense).
#[inline(always)]
unsafe fn n_dense_slots(n: *mut MapleNode) -> *mut *mut c_void {
    // SAFETY: offset 8.
    unsafe { nb(n, 8).cast() }
}
/// `node->mr64.pivot` / `node->ma64.pivot`.
#[inline(always)]
unsafe fn n_pivots(n: *mut MapleNode) -> *mut c_ulong {
    // SAFETY: offset 8.
    unsafe { nb(n, 8).cast() }
}
/// `node->mr64.slot` (offset 8 + 15 * 8).
#[inline(always)]
unsafe fn n_mr64_slots(n: *mut MapleNode) -> *mut *mut c_void {
    // SAFETY: offset 128.
    unsafe { nb(n, 128).cast() }
}
/// `node->ma64.slot` (offset 8 + 9 * 8).
#[inline(always)]
unsafe fn n_ma64_slots(n: *mut MapleNode) -> *mut *mut c_void {
    // SAFETY: offset 80.
    unsafe { nb(n, 80).cast() }
}
/// `node->ma64.gap` (offset 80 + 10 * 8).
#[inline(always)]
unsafe fn n_ma64_gaps(n: *mut MapleNode) -> *mut c_ulong {
    // SAFETY: offset 160.
    unsafe { nb(n, 160).cast() }
}
/// `node->mr64.meta` (the last slot's bytes).
#[inline(always)]
unsafe fn n_mr64_meta(n: *mut MapleNode) -> *mut Meta {
    // SAFETY: offset 248.
    unsafe { nb(n, 248).cast() }
}
/// `node->ma64.meta`.
#[inline(always)]
unsafe fn n_ma64_meta(n: *mut MapleNode) -> *mut Meta {
    // SAFETY: offset 240.
    unsafe { nb(n, 240).cast() }
}
/// `node->rcu` (the `struct rcu_head`, offset 8).
#[inline(always)]
unsafe fn n_rcu(n: *mut MapleNode) -> *mut c_void {
    // SAFETY: offset 8.
    unsafe { nb(n, 8).cast() }
}
/// `node->piv_parent`, `parent_slot`, `type`, `slot_len`, `ma_flags` (the "free node" view used by `mt_free_walk`/`mat`).
#[inline(always)]
unsafe fn n_alloc_total(n: *mut MapleNode) -> *mut c_ulong {
    n.cast()
}
/// `struct maple_topiary`: `next` is the second word.
#[inline(always)]
unsafe fn mat_next(n: *mut MapleNode) -> *mut Enode {
    // SAFETY: offset 8.
    unsafe { nb(n, 8).cast() }
}

/// `maple_big_node` accessors.
#[inline(always)]
unsafe fn bn_slot(bn: *mut MapleBigNode, i: usize) -> *mut Enode {
    // SAFETY: `i < MAPLE_BIG_NODE_SLOTS`.
    unsafe { (&raw mut (*bn).sg).cast::<Enode>().add(i) }
}
#[inline(always)]
unsafe fn bn_gap(bn: *mut MapleBigNode, i: usize) -> *mut c_ulong {
    // SAFETY: `gap[]` starts after `padding[MAPLE_BIG_NODE_GAPS]`.
    unsafe { (&raw mut (*bn).sg).cast::<c_ulong>().add(MAPLE_BIG_NODE_GAPS + i) }
}

// ---------------------------------------------------------------------------
// C lines 160-900: encoding helpers, parent pointers, slot / pivot / metadata access
// ---------------------------------------------------------------------------

/// `mt_alloc_one()`.
#[inline(always)]
unsafe fn mt_alloc_one(gfp: Gfp) -> *mut MapleNode {
    // SAFETY: glue call.
    unsafe { rust_mt_alloc_one(gfp) }
}

/// `ma_free_rcu()`.
#[inline(always)]
unsafe fn ma_free_rcu(node: *mut MapleNode) {
    // SAFETY: glue call (WARN_ON(node->parent != node); kfree_rcu).
    unsafe { rust_mt_free_rcu(node) }
}

/// `mt_height()`.
#[inline(always)]
unsafe fn mt_height(mt: *const MapleTree) -> c_uint {
    // SAFETY: caller contract.
    unsafe { (*mt_flags(mt) & MT_FLAGS_HEIGHT_MASK) >> MT_FLAGS_HEIGHT_OFFSET }
}

/// `mt_set_height()`.
unsafe fn mt_set_height(mt: *mut MapleTree, height: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut new_flags = *mt_flags(mt);

        new_flags &= !MT_FLAGS_HEIGHT_MASK;
        bug_on(height as c_uint > MAPLE_HEIGHT_MAX);
        new_flags |= (height as c_uint) << MT_FLAGS_HEIGHT_OFFSET;
        *mt_flags(mt) = new_flags;
    }
}

/// `mas_mt_height()`.
#[inline(always)]
unsafe fn mas_mt_height(mas: *mut MaState) -> c_uint {
    // SAFETY: caller contract.
    unsafe { mt_height((*mas).tree) }
}

/// `mt_in_rcu()` (`CONFIG_MAPLE_RCU_DISABLED` is not set).
#[inline(always)]
unsafe fn mt_in_rcu(mt: *const MapleTree) -> bool {
    // SAFETY: caller contract.
    unsafe { *mt_flags(mt) & MT_FLAGS_USE_RCU != 0 }
}

/// `mt_external_lock()`.
#[inline(always)]
unsafe fn mt_external_lock(mt: *const MapleTree) -> bool {
    // SAFETY: caller contract.
    unsafe { *mt_flags(mt) & MT_FLAGS_LOCK_MASK == MT_FLAGS_LOCK_EXTERN }
}

/// `mt_is_alloc()`.
#[inline(always)]
unsafe fn mt_is_alloc(mt: *const MapleTree) -> bool {
    // SAFETY: caller contract.
    unsafe { *mt_flags(mt) & MT_FLAGS_ALLOC_RANGE != 0 }
}

/// `mte_node_type()`.
#[inline(always)]
fn mte_node_type(entry: Enode) -> u32 {
    (((entry as usize) >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK) as u32
}

#[inline(always)]
fn ma_is_dense(t: u32) -> bool {
    t < maple_leaf_64
}
#[inline(always)]
fn ma_is_leaf(t: u32) -> bool {
    t < maple_range_64
}
#[inline(always)]
fn mte_is_leaf(entry: Enode) -> bool {
    ma_is_leaf(mte_node_type(entry))
}

/// `xa_is_internal()`.
#[inline(always)]
fn xa_is_internal(entry: *const c_void) -> bool {
    entry as usize & 3 == 2
}
/// `xa_is_node()`.
#[inline(always)]
fn xa_is_node(entry: *const c_void) -> bool {
    xa_is_internal(entry) && entry as usize > MAPLE_RESERVED_RANGE
}

/// `mt_is_reserved()`.
#[inline(always)]
fn mt_is_reserved(entry: *const c_void) -> bool {
    (entry as usize) < MAPLE_RESERVED_RANGE && xa_is_internal(entry)
}

/// `MA_ERROR(err)`.
#[inline(always)]
fn ma_error_enode(err: c_long) -> Enode {
    (((err as c_ulong) << 2) | 2) as usize as Enode
}

/// `mas_set_err()`.
#[inline(always)]
unsafe fn mas_set_err(mas: *mut MaState, err: c_long) {
    // SAFETY: caller contract.
    unsafe {
        (*mas).node = ma_error_enode(err);
        (*mas).status = ma_error;
    }
}

#[inline(always)]
unsafe fn mas_is_ptr(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_root }
}
#[inline(always)]
unsafe fn mas_is_start(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_start }
}
#[inline(always)]
unsafe fn mas_is_none(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_none }
}
#[inline(always)]
unsafe fn mas_is_paused(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_pause }
}
#[inline(always)]
unsafe fn mas_is_overflow(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_overflow }
}
#[inline(always)]
unsafe fn mas_is_underflow(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_underflow }
}
#[inline(always)]
unsafe fn mas_is_active(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_active }
}
#[inline(always)]
unsafe fn mas_is_err(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).status == ma_error }
}

/// `mte_to_node()`.
#[inline(always)]
fn mte_to_node(entry: Enode) -> *mut MapleNode {
    (entry as usize & !MAPLE_NODE_MASK) as *mut MapleNode
}

/// `mas_mn()`.
#[inline(always)]
unsafe fn mas_mn(mas: *const MaState) -> *mut MapleNode {
    // SAFETY: caller contract.
    mte_to_node(unsafe { (*mas).node })
}

/// `mte_set_node_dead()`.
#[inline(always)]
unsafe fn mte_set_node_dead(mn: Enode) {
    // SAFETY: caller contract.
    unsafe {
        let node = mte_to_node(mn);
        *n_parent(node) = node as Pnode;
        smp_wmb(); /* Needed for RCU */
    }
}

const MAPLE_ROOT_NODE: usize = 0x02;
const MAPLE_ENODE_TYPE_SHIFT: usize = 0x03;
const MAPLE_ENODE_NULL: usize = 0x04;

/// `mt_mk_node()`.
#[inline(always)]
fn mt_mk_node(node: *const MapleNode, type_: u32) -> Enode {
    (node as usize | ((type_ as usize) << MAPLE_ENODE_TYPE_SHIFT) | MAPLE_ENODE_NULL) as Enode
}
/// `mte_mk_root()`.
#[inline(always)]
fn mte_mk_root(node: Enode) -> *mut c_void {
    (node as usize | MAPLE_ROOT_NODE) as *mut c_void
}
/// `mte_safe_root()`.
#[inline(always)]
fn mte_safe_root(node: Enode) -> *mut c_void {
    (node as usize & !MAPLE_ROOT_NODE) as *mut c_void
}
/// `mte_set_full()` / `mte_clear_full()` / `mte_has_null()`.
#[inline(always)]
fn mte_set_full(node: Enode) -> *mut c_void {
    (node as usize & !MAPLE_ENODE_NULL) as *mut c_void
}
#[inline(always)]
fn mte_clear_full(node: Enode) -> *mut c_void {
    (node as usize | MAPLE_ENODE_NULL) as *mut c_void
}
#[inline(always)]
fn mte_has_null(node: Enode) -> bool {
    node as usize & MAPLE_ENODE_NULL != 0
}

/// `ma_is_root()`.
#[inline(always)]
unsafe fn ma_is_root(node: *mut MapleNode) -> bool {
    // SAFETY: caller contract.
    unsafe { *n_parent(node) as usize & MA_ROOT_PARENT != 0 }
}
/// `mte_is_root()`.
#[inline(always)]
unsafe fn mte_is_root(node: Enode) -> bool {
    // SAFETY: caller contract.
    unsafe { ma_is_root(mte_to_node(node)) }
}
/// `mas_is_root_limits()`.
#[inline(always)]
unsafe fn mas_is_root_limits(mas: *const MaState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*mas).min == 0 && (*mas).max == ULONG_MAX }
}

/// `mas_tree_parent()`: the root node's parent encoding.
#[inline(always)]
unsafe fn mas_tree_parent(mas: *const MaState) -> usize {
    // SAFETY: caller contract.
    unsafe { (*mas).tree as usize | MA_ROOT_PARENT }
}

// parent encoding
const MAPLE_PARENT_ROOT: usize = 0x01;
const MAPLE_PARENT_SLOT_SHIFT: usize = 0x03;
const MAPLE_PARENT_SLOT_MASK: usize = 0xF8;
const MAPLE_PARENT_16B_SLOT_SHIFT: usize = 0x02;
const MAPLE_PARENT_16B_SLOT_MASK: usize = 0xFC;
const MAPLE_PARENT_RANGE64: usize = 0x06;
const MAPLE_PARENT_RANGE32: usize = 0x02;
const MAPLE_PARENT_NOT_RANGE16: usize = 0x02;

/// `mte_parent_shift()`.
#[inline(always)]
fn mte_parent_shift(parent: usize) -> usize {
    /* Note bit 1 == 0 means 16B */
    if parent & MAPLE_PARENT_NOT_RANGE16 != 0 {
        MAPLE_PARENT_SLOT_SHIFT
    } else {
        MAPLE_PARENT_16B_SLOT_SHIFT
    }
}
/// `mte_parent_slot_mask()`.
#[inline(always)]
fn mte_parent_slot_mask(parent: usize) -> usize {
    if parent & MAPLE_PARENT_NOT_RANGE16 != 0 {
        MAPLE_PARENT_SLOT_MASK
    } else {
        MAPLE_PARENT_16B_SLOT_MASK
    }
}

/// `mas_parent_type()`.
unsafe fn mas_parent_type(mas: *mut MaState, enode: Enode) -> u32 {
    // SAFETY: caller contract.
    unsafe {
        let mut p_type = *n_parent(mte_to_node(enode)) as usize;
        if warn_on(p_type & MAPLE_PARENT_ROOT != 0) {
            return 0;
        }

        p_type &= MAPLE_NODE_MASK;
        p_type &= !mte_parent_slot_mask(p_type);
        if p_type == MAPLE_PARENT_RANGE64 {
            /* or MAPLE_PARENT_ARANGE64 */
            if mt_is_alloc((*mas).tree) {
                return maple_arange_64;
            }
            return maple_range_64;
        }

        0
    }
}

/// `mas_set_parent()`.
unsafe fn mas_set_parent(mas: *mut MaState, enode: Enode, parent: Enode, slot: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut val = parent as usize;
        let shift: usize;
        let type_: usize;
        let p_type = mte_node_type(parent);

        bug_on(p_type == maple_dense);
        bug_on(p_type == maple_leaf_64);

        match p_type {
            maple_range_64 | maple_arange_64 => {
                shift = MAPLE_PARENT_SLOT_SHIFT;
                type_ = MAPLE_PARENT_RANGE64;
            }
            _ => {
                shift = 0;
                type_ = 0;
            }
        }

        val &= !MAPLE_NODE_MASK; /* Clear all node metadata in parent */
        val |= ((slot as usize) << shift) | type_;
        *n_parent(mte_to_node(enode)) = val as Pnode;
        let _ = mas;
    }
}

/// `mte_parent_slot()`.
#[inline(always)]
unsafe fn mte_parent_slot(enode: Enode) -> c_uint {
    // SAFETY: caller contract.
    unsafe {
        let val = *n_parent(mte_to_node(enode)) as usize;

        if val & MA_ROOT_PARENT != 0 {
            return 0;
        }

        /* Okay to use MAPLE_PARENT_16B_SLOT_MASK as the last bit will be lost by shift if the parent shift is MAPLE_PARENT_SLOT_SHIFT */
        ((val & MAPLE_PARENT_16B_SLOT_MASK) >> mte_parent_shift(val)) as c_uint
    }
}

/// `mte_parent()`.
#[inline(always)]
unsafe fn mte_parent(enode: Enode) -> *mut MapleNode {
    // SAFETY: caller contract.
    unsafe { (*n_parent(mte_to_node(enode)) as usize & !MAPLE_NODE_MASK) as *mut MapleNode }
}

/// `ma_dead_node()`.
#[inline(always)]
unsafe fn ma_dead_node(node: *mut MapleNode) -> bool {
    // SAFETY: caller contract.
    unsafe {
        /* Do not reorder reads from the node prior to the parent check */
        smp_rmb();
        let parent = (rd(n_parent(node)) as usize & !MAPLE_NODE_MASK) as *mut MapleNode;
        parent == node
    }
}
/// `mte_dead_node()`.
#[inline(always)]
unsafe fn mte_dead_node(enode: Enode) -> bool {
    // SAFETY: caller contract.
    unsafe { ma_dead_node(mte_to_node(enode)) }
}

/// `ma_pivots()`.
#[inline(always)]
unsafe fn ma_pivots(node: *mut MapleNode, type_: u32) -> *mut c_ulong {
    // SAFETY: caller contract.
    unsafe {
        match type_ {
            maple_arange_64 | maple_range_64 | maple_leaf_64 => n_pivots(node),
            _ => null_mut(),
        }
    }
}
/// `ma_gaps()`.
#[inline(always)]
unsafe fn ma_gaps(node: *mut MapleNode, type_: u32) -> *mut c_ulong {
    // SAFETY: caller contract.
    unsafe {
        match type_ {
            maple_arange_64 => n_ma64_gaps(node),
            _ => null_mut(),
        }
    }
}
/// `ma_slots()`.
#[inline(always)]
unsafe fn ma_slots(mn: *mut MapleNode, mt: u32) -> *mut *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        match mt {
            maple_arange_64 => n_ma64_slots(mn),
            maple_range_64 | maple_leaf_64 => n_mr64_slots(mn),
            maple_dense => n_dense_slots(mn),
            _ => null_mut(),
        }
    }
}

/// `mas_safe_pivot()`.
#[inline(always)]
unsafe fn mas_safe_pivot(mas: *const MaState, pivots: *mut c_ulong, piv: u8, type_: u32) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        if piv >= mt_pivots[type_ as usize] {
            return (*mas).max;
        }
        *pivots.add(piv as usize)
    }
}
/// `mas_safe_min()`.
#[inline(always)]
unsafe fn mas_safe_min(mas: *const MaState, pivots: *mut c_ulong, offset: u8) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        if offset != 0 {
            return (*pivots.add(offset as usize - 1)).wrapping_add(1);
        }
        (*mas).min
    }
}
/// `mte_set_pivot()`.
unsafe fn mte_set_pivot(mn: Enode, piv: u8, val: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        let node = mte_to_node(mn);
        let type_ = mte_node_type(mn);

        bug_on(piv >= mt_pivots[type_ as usize]);
        match type_ {
            maple_range_64 | maple_leaf_64 | maple_arange_64 => *n_pivots(node).add(piv as usize) = val,
            _ => {}
        }
    }
}

/// `mt_slot()`: `rcu_dereference_check()` is a `READ_ONCE()` (the lockdep condition is not carried).
#[inline(always)]
unsafe fn mt_slot(_mt: *const MapleTree, slots: *mut *mut c_void, offset: u8) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { rd(slots.add(offset as usize)) }
}
/// `mt_slot_locked()`: `rcu_dereference_protected()` is a plain load.
#[inline(always)]
unsafe fn mt_slot_locked(_mt: *const MapleTree, slots: *mut *mut c_void, offset: u8) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { *slots.add(offset as usize) }
}
#[inline(always)]
unsafe fn mas_slot_locked(mas: *const MaState, slots: *mut *mut c_void, offset: u8) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { mt_slot_locked((*mas).tree, slots, offset) }
}
#[inline(always)]
unsafe fn mas_slot(mas: *const MaState, slots: *mut *mut c_void, offset: u8) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { mt_slot((*mas).tree, slots, offset) }
}
/// `mas_root()`.
#[inline(always)]
unsafe fn mas_root(mas: *const MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { rd(mt_root_p((*mas).tree)) }
}
/// `mt_root_locked()` / `mas_root_locked()`.
#[inline(always)]
unsafe fn mt_root_locked(mt: *const MapleTree) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { *mt_root_p(mt) }
}
#[inline(always)]
unsafe fn mas_root_locked(mas: *const MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe { mt_root_locked((*mas).tree) }
}
/// `rcu_assign_pointer(*p, v)`.
#[inline(always)]
unsafe fn rcu_assign(p: *mut *mut c_void, v: *mut c_void) {
    // SAFETY: caller contract.
    unsafe { (*(p as *const AtomicPtr<c_void>)).store(v, Ordering::Release) }
}

/// `ma_meta()`.
#[inline(always)]
unsafe fn ma_meta(mn: *mut MapleNode, mt: u32) -> *mut Meta {
    // SAFETY: caller contract.
    unsafe {
        match mt {
            maple_arange_64 => n_ma64_meta(mn),
            _ => n_mr64_meta(mn),
        }
    }
}
/// `ma_set_meta()`.
#[inline(always)]
unsafe fn ma_set_meta(mn: *mut MapleNode, mt: u32, offset: u8, end: u8) {
    // SAFETY: caller contract.
    unsafe {
        let meta = ma_meta(mn, mt);

        (*meta).gap = offset;
        (*meta).end = end;
    }
}
/// `mt_clear_meta()`.
unsafe fn mt_clear_meta(mt: *mut MapleTree, mn: *mut MapleNode, type_: u32) {
    // SAFETY: caller contract.
    unsafe {
        let meta: *mut Meta;
        match type_ {
            maple_range_64 => {
                let pivots = n_pivots(mn);
                if *pivots.add(MAPLE_RANGE64_SLOTS - 2) != 0 {
                    /* DIVERGENCE: the C peeks at the last slot and returns only if it still carries a type;
                     * mt_destroy_walk() has already stripped the type bits of dead children, so the C then
                     * zeroes the low 16 bits of the last child pointer. A full node has no metadata. */
                    let _ = mt;
                    return;
                }
                meta = ma_meta(mn, type_);
            }
            maple_arange_64 => meta = ma_meta(mn, type_),
            _ => return,
        }

        (*meta).gap = 0;
        (*meta).end = 0;
    }
}
/// `ma_meta_end()`.
#[inline(always)]
unsafe fn ma_meta_end(mn: *mut MapleNode, mt: u32) -> u8 {
    // SAFETY: caller contract.
    unsafe { (*ma_meta(mn, mt)).end }
}
/// `ma_meta_gap()`.
#[inline(always)]
unsafe fn ma_meta_gap(mn: *mut MapleNode) -> u8 {
    // SAFETY: caller contract.
    unsafe { (*n_ma64_meta(mn)).gap }
}
/// `ma_set_meta_gap()`.
#[inline(always)]
unsafe fn ma_set_meta_gap(mn: *mut MapleNode, mt: u32, offset: u8) {
    // SAFETY: caller contract.
    unsafe { (*ma_meta(mn, mt)).gap = offset }
}

// ---------------------------------------------------------------------------
// C lines 900-1380: topiary, descending / ascending, node allocation, start, data end, leaf gaps
// ---------------------------------------------------------------------------

/// `mat_add()`.
unsafe fn mat_add(mat: *mut MaTopiary, dead_enode: Enode) {
    // SAFETY: caller contract.
    unsafe {
        mte_set_node_dead(dead_enode);
        *mat_next(mte_to_node(dead_enode)) = null_mut();
        if (*mat).tail.is_null() {
            (*mat).head = dead_enode;
            (*mat).tail = dead_enode;
            return;
        }

        *mat_next(mte_to_node((*mat).tail)) = dead_enode;
        (*mat).tail = dead_enode;
    }
}

/// `mas_mat_destroy()`.
unsafe fn mas_mat_destroy(mas: *mut MaState, mat: *mut MaTopiary) {
    // SAFETY: caller contract.
    unsafe {
        let in_rcu = mt_in_rcu((*mas).tree);

        while !(*mat).head.is_null() {
            let next = *mat_next(mte_to_node((*mat).head));
            let node = mte_to_node((*mat).head);
            mt_destroy_walk((*mat).head, (*mas).tree, !in_rcu);
            if in_rcu {
                rust_mt_call_rcu_free_walk(node);
            }
            (*mat).head = next;
        }
    }
}

/// `mas_descend()`: descend into the slot stored in the ma_state (write side or debug only).
unsafe fn mas_descend(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        let node = mas_mn(mas);
        let type_ = mte_node_type((*mas).node);
        let pivots = ma_pivots(node, type_);
        let slots = ma_slots(node, type_);

        if (*mas).offset != 0 {
            (*mas).min = (*pivots.add((*mas).offset as usize - 1)).wrapping_add(1);
        }
        (*mas).max = mas_safe_pivot(mas, pivots, (*mas).offset, type_);
        (*mas).node = mas_slot(mas, slots, (*mas).offset);
    }
}

/// `mas_ascend()`: walk up a level of the tree. Returns 1 on a dead node, 0 otherwise.
unsafe fn mas_ascend(mas: *mut MaState) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut a_node = mas_mn(mas);
        if ma_is_root(a_node) {
            (*mas).offset = 0;
            return 0;
        }

        let p_node = mte_parent((*mas).node);
        if a_node == p_node {
            return 1;
        }

        let mut a_type = mas_parent_type(mas, (*mas).node);
        (*mas).offset = mte_parent_slot((*mas).node) as u8;
        let mut a_enode = mt_mk_node(p_node, a_type);

        /* Check to make sure all parent information is still accurate */
        if p_node != mte_parent((*mas).node) {
            return 1;
        }

        (*mas).node = a_enode;

        if mte_is_root(a_enode) {
            (*mas).max = ULONG_MAX;
            (*mas).min = 0;
            return 0;
        }

        let mut min: c_ulong = 0;
        let mut max: c_ulong = ULONG_MAX;
        let mut set_max = false;
        let mut set_min = false;

        /* !mas->offset implies that parent node min == mas->min. mas->offset > 0 implies that we need to walk up to find the implied pivot min. */
        if (*mas).offset == 0 {
            min = (*mas).min;
            set_min = true;
        }

        if (*mas).max == ULONG_MAX {
            set_max = true;
        }

        loop {
            let p_enode = a_enode;
            a_type = mas_parent_type(mas, p_enode);
            a_node = mte_parent(p_enode);
            let a_slot = mte_parent_slot(p_enode) as u8;
            a_enode = mt_mk_node(a_node, a_type);
            let pivots = ma_pivots(a_node, a_type);

            if ma_dead_node(a_node) {
                return 1;
            }

            if !set_min && a_slot != 0 {
                set_min = true;
                min = (*pivots.add(a_slot as usize - 1)).wrapping_add(1);
            }

            if !set_max && a_slot < mt_pivots[a_type as usize] {
                set_max = true;
                max = *pivots.add(a_slot as usize);
            }

            if ma_dead_node(a_node) {
                return 1;
            }

            if ma_is_root(a_node) {
                break;
            }

            if set_min && set_max {
                break;
            }
        }

        (*mas).max = max;
        (*mas).min = min;
        0
    }
}

/// `mas_pop_node()`: get a previously allocated maple node from the maple state.
unsafe fn mas_pop_node(mas: *mut MaState) -> *mut MapleNode {
    // SAFETY: caller contract.
    unsafe {
        let ret: *mut MapleNode;

        if !(*mas).alloc.is_null() {
            ret = (*mas).alloc;
            (*mas).alloc = null_mut();
        } else {
            if warn_on_once((*mas).sheaf.is_null()) {
                return null_mut();
            }

            ret = rust_mt_alloc_from_sheaf((*mas).sheaf);
        }

        core::ptr::write_bytes(ret, 0, 1);
        ret
    }
}

/// `mas_alloc_nodes()`: allocate nodes into a maple state.
unsafe fn mas_alloc_nodes(mas: *mut MaState, gfp: Gfp) {
    // SAFETY: caller contract.
    unsafe {
        if (*mas).node_request == 0 {
            return;
        }

        let mut use_sheaf = false;
        if (*mas).node_request == 1 {
            if !(*mas).sheaf.is_null() {
                use_sheaf = true;
            } else {
                if !(*mas).alloc.is_null() {
                    return;
                }

                (*mas).alloc = mt_alloc_one(gfp);
                if (*mas).alloc.is_null() {
                    mas_set_err(mas, -(ENOMEM as c_long));
                    return;
                }

                (*mas).node_request = 0;
                return;
            }
        }
        let _ = use_sheaf;

        // use_sheaf:
        if !(*mas).alloc.is_null() {
            rust_mt_kfree((*mas).alloc.cast());
            (*mas).alloc = null_mut();
        }

        if !(*mas).sheaf.is_null() {
            let refill = (*mas).node_request;
            if rust_mt_sheaf_size((*mas).sheaf) as c_ulong >= refill {
                (*mas).node_request = 0;
                return;
            }

            if rust_mt_refill_sheaf(gfp, &raw mut (*mas).sheaf, refill as c_uint) != 0 {
                mas_set_err(mas, -(ENOMEM as c_long));
                return;
            }

            (*mas).node_request = 0;
            return;
        }

        (*mas).sheaf = rust_mt_get_sheaf(gfp, (*mas).node_request as c_int);
        if !(*mas).sheaf.is_null() {
            (*mas).node_request = 0;
            return;
        }

        // error:
        mas_set_err(mas, -(ENOMEM as c_long));
    }
}

/// `mas_empty_nodes()`.
unsafe fn mas_empty_nodes(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        (*mas).node_request = 0;
        if !(*mas).sheaf.is_null() {
            rust_mt_return_sheaf((*mas).sheaf);
            (*mas).sheaf = null_mut();
        }

        if !(*mas).alloc.is_null() {
            rust_mt_kfree((*mas).alloc.cast());
            (*mas).alloc = null_mut();
        }
    }
}

/// `mas_free()`.
#[inline(always)]
unsafe fn mas_free(_mas: *mut MaState, used: Enode) {
    // SAFETY: caller contract.
    unsafe { ma_free_rcu(mte_to_node(used)) }
}

/// `mas_start()`: set up the maple state for operations.
unsafe fn mas_start(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        if mas_is_start(mas) {
            (*mas).min = 0;
            (*mas).max = ULONG_MAX;

            loop {
                // retry:
                (*mas).depth = 0;
                let root = mas_root(mas);
                /* Tree with nodes */
                if xa_is_node(root) {
                    (*mas).depth = 0;
                    (*mas).status = ma_active;
                    (*mas).node = mte_safe_root(root);
                    (*mas).offset = 0;
                    if mte_dead_node((*mas).node) {
                        continue;
                    }

                    return null_mut();
                }

                (*mas).node = null_mut();
                /* empty tree */
                if root.is_null() {
                    (*mas).status = ma_none;
                    (*mas).offset = MAPLE_NODE_SLOTS as u8;
                    return null_mut();
                }

                /* Single entry tree */
                (*mas).status = ma_root;
                (*mas).offset = MAPLE_NODE_SLOTS as u8;

                /* Single entry tree. */
                if (*mas).index > 0 {
                    return null_mut();
                }

                return root;
            }
        }

        null_mut()
    }
}

/// `ma_data_end()`: find the end of the data in a node.
#[inline(always)]
unsafe fn ma_data_end(node: *mut MapleNode, type_: u32, pivots: *mut c_ulong, max: c_ulong) -> u8 {
    // SAFETY: caller contract.
    unsafe {
        if pivots.is_null() {
            return 0;
        }

        if type_ == maple_arange_64 {
            return ma_meta_end(node, type_);
        }

        let offset = mt_pivots[type_ as usize] - 1;
        if *pivots.add(offset as usize) == 0 {
            return ma_meta_end(node, type_);
        }

        if *pivots.add(offset as usize) == max {
            return offset;
        }

        mt_pivots[type_ as usize]
    }
}

/// `mas_data_end()`.
unsafe fn mas_data_end(mas: *mut MaState) -> u8 {
    // SAFETY: caller contract.
    unsafe {
        let type_ = mte_node_type((*mas).node);
        let node = mas_mn(mas);
        if type_ == maple_arange_64 {
            return ma_meta_end(node, type_);
        }

        let pivots = ma_pivots(node, type_);
        if ma_dead_node(node) {
            return 0;
        }

        let offset = mt_pivots[type_ as usize] - 1;
        if *pivots.add(offset as usize) == 0 {
            return ma_meta_end(node, type_);
        }

        if *pivots.add(offset as usize) == (*mas).max {
            return offset;
        }

        mt_pivots[type_ as usize]
    }
}

/// `mas_leaf_max_gap()`: the largest gap in a leaf node.
unsafe fn mas_leaf_max_gap(mas: *mut MaState) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mt = mte_node_type((*mas).node);
        let mn = mas_mn(mas);
        let slots = ma_slots(mn, mt);
        let mut max_gap: c_ulong = 0;
        let mut gap: c_ulong;
        let mut i: u8;

        if ma_is_dense(mt) {
            gap = 0;
            i = 0;
            while i < mt_slots[mt as usize] {
                if !(*slots.add(i as usize)).is_null() {
                    if gap > max_gap {
                        max_gap = gap;
                    }
                    gap = 0;
                } else {
                    gap += 1;
                }
                i += 1;
            }
            if gap > max_gap {
                max_gap = gap;
            }
            return max_gap;
        }

        /* Check the first implied pivot optimizes the loop below and slot 1 may be skipped if there is a gap in slot 0. */
        let pivots = ma_pivots(mn, mt);
        if (*slots).is_null() {
            max_gap = (*pivots).wrapping_sub((*mas).min).wrapping_add(1);
            i = 2;
        } else {
            i = 1;
        }

        /* reduce max_piv as the special case is checked before the loop */
        let max_piv = ma_data_end(mn, mt, pivots, (*mas).max).wrapping_sub(1);
        /* Check end implied pivot which can only be a gap on the right most node. */
        if (*mas).max == ULONG_MAX && (*slots.add(max_piv as usize + 1)).is_null() {
            gap = ULONG_MAX - *pivots.add(max_piv as usize);
            if gap > max_gap {
                max_gap = gap;
            }

            if max_gap > (*pivots.add(max_piv as usize)).wrapping_sub((*mas).min) {
                return max_gap;
            }
        }

        while i <= max_piv {
            /* data == no gap. */
            if !(*slots.add(i as usize)).is_null() {
                i += 1;
                continue;
            }

            let pstart = *pivots.add(i as usize - 1);
            gap = (*pivots.add(i as usize)).wrapping_sub(pstart);
            if gap > max_gap {
                max_gap = gap;
            }

            /* There cannot be two gaps in a row. */
            i += 2;
        }
        max_gap
    }
}

// ---------------------------------------------------------------------------
// C lines 1380-2400: gaps, parents, the big-node staging area, write-walk, rebalance helpers
// ---------------------------------------------------------------------------

/// `MA_STATE(name, mt, first, end)`.
#[inline(always)]
fn ma_state_new(tree: *mut MapleTree, first: c_ulong, end: c_ulong) -> MaState {
    MaState {
        tree,
        index: first,
        last: end,
        node: null_mut(),
        min: 0,
        max: ULONG_MAX,
        sheaf: null_mut(),
        alloc: null_mut(),
        node_request: 0,
        status: ma_start,
        depth: 0,
        offset: 0,
        mas_flags: 0,
        end: 0,
        store_type: wr_invalid,
    }
}
/// `MA_WR_STATE(name, mas, entry)`.
#[inline(always)]
fn ma_wr_state_new(mas: *mut MaState, entry: *mut c_void) -> MaWrState {
    MaWrState {
        mas,
        node: null_mut(),
        r_min: 0,
        r_max: 0,
        type_: 0,
        offset_end: 0,
        pivots: null_mut(),
        end_piv: 0,
        slots: null_mut(),
        entry,
        content: null_mut(),
        vacant_height: 0,
        sufficient_height: 0,
    }
}
/// `MA_TOPIARY(name, tree)`.
#[inline(always)]
fn ma_topiary_new(tree: *mut MapleTree) -> MaTopiary {
    MaTopiary { head: null_mut(), tail: null_mut(), mtree: tree }
}

// maple_big_node field access without bounds checks (the C indexes raw arrays).
#[inline(always)]
unsafe fn bpiv(bn: *mut MapleBigNode, i: usize) -> *mut c_ulong {
    // SAFETY: caller contract.
    unsafe { (&raw mut (*bn).pivot).cast::<c_ulong>().add(i) }
}
#[inline(always)]
unsafe fn bslot(bn: *mut MapleBigNode, i: usize) -> *mut Enode {
    // SAFETY: caller contract.
    unsafe { bn_slot(bn, i) }
}
#[inline(always)]
unsafe fn bgap(bn: *mut MapleBigNode, i: usize) -> *mut c_ulong {
    // SAFETY: caller contract.
    unsafe { bn_gap(bn, i) }
}

/// `ma_max_gap()`: the maximum gap in a (non-leaf) node; the offset is stored in `*off`.
unsafe fn ma_max_gap(node: *mut MapleNode, gaps: *mut c_ulong, mt: u32, off: *mut u8) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mut max_gap: c_ulong = 0;
        let mut i: u8 = ma_meta_end(node, mt);
        let mut offset: u8 = i;

        loop {
            if *gaps.add(i as usize) > max_gap {
                max_gap = *gaps.add(i as usize);
                offset = i;
            }
            /* `while (i--)` */
            let was = i;
            i = i.wrapping_sub(1);
            if was == 0 {
                break;
            }
        }

        *off = offset;
        max_gap
    }
}

/// `mas_max_gap()`: find the largest gap in a non-leaf node and set the slot.
unsafe fn mas_max_gap(mas: *mut MaState) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mt = mte_node_type((*mas).node);
        if ma_is_leaf(mt) {
            return mas_leaf_max_gap(mas);
        }

        let node = mas_mn(mas);
        bug_on(mt != maple_arange_64);
        let offset = ma_meta_gap(node);
        let gaps = ma_gaps(node, mt);
        *gaps.add(offset as usize)
    }
}

/// `mas_parent_gap()`: set the parent gap and any gaps above, as needed.
unsafe fn mas_parent_gap(mas: *mut MaState, offset: u8, new: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        let mut offset = offset;
        let mut new = new;
        let mut pnode = mte_parent((*mas).node);
        let mut pmt = mas_parent_type(mas, (*mas).node);
        let mut penode = mt_mk_node(pnode, pmt);
        let mut pgaps = ma_gaps(pnode, pmt);
        let mut meta_offset: u8;

        loop {
            // ascend:
            bug_on(pmt != maple_arange_64);
            meta_offset = ma_meta_gap(pnode);
            let meta_gap = *pgaps.add(meta_offset as usize);

            *pgaps.add(offset as usize) = new;

            if meta_gap == new {
                return;
            }

            if offset != meta_offset {
                if meta_gap > new {
                    return;
                }

                ma_set_meta_gap(pnode, pmt, offset);
            } else if new < meta_gap {
                new = ma_max_gap(pnode, pgaps, pmt, &raw mut meta_offset);
                ma_set_meta_gap(pnode, pmt, meta_offset);
            }

            if ma_is_root(pnode) {
                return;
            }

            /* Go to the parent node. */
            pnode = mte_parent(penode);
            pmt = mas_parent_type(mas, penode);
            pgaps = ma_gaps(pnode, pmt);
            offset = mte_parent_slot(penode) as u8;
            penode = mt_mk_node(pnode, pmt);
        }
    }
}

/// `mas_update_gap()`: update a node's gaps and propagate up if necessary.
unsafe fn mas_update_gap(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        if !mt_is_alloc((*mas).tree) {
            return;
        }

        if mte_is_root((*mas).node) {
            return;
        }

        let max_gap = mas_max_gap(mas);

        let pslot = mte_parent_slot((*mas).node) as u8;
        let p_gap = *ma_gaps(mte_parent((*mas).node), mas_parent_type(mas, (*mas).node)).add(pslot as usize);

        if p_gap != max_gap {
            mas_parent_gap(mas, pslot, max_gap);
        }
    }
}

/// `mas_adopt_children()`: set the parent pointer of all nodes in `parent` to `parent` with the slot encoded.
unsafe fn mas_adopt_children(mas: *mut MaState, parent: Enode) {
    // SAFETY: caller contract.
    unsafe {
        let type_ = mte_node_type(parent);
        let node = mte_to_node(parent);
        let slots = ma_slots(node, type_);
        let pivots = ma_pivots(node, type_);

        let mut offset = ma_data_end(node, type_, pivots, (*mas).max);
        loop {
            let child = mas_slot_locked(mas, slots, offset);
            mas_set_parent(mas, child, parent, offset);
            let was = offset;
            offset = offset.wrapping_sub(1);
            if was == 0 {
                break;
            }
        }
    }
}

/// `mas_put_in_tree()`: put a new node in the tree, `smp_wmb()`, and mark the old node as dead.
unsafe fn mas_put_in_tree(mas: *mut MaState, old_enode: Enode, new_height: i8) {
    // SAFETY: caller contract.
    unsafe {
        if mte_is_root((*mas).node) {
            *n_parent(mas_mn(mas)) = mas_tree_parent(mas) as Pnode;
            rcu_assign(mt_root_p((*mas).tree), mte_mk_root((*mas).node));
            mt_set_height((*mas).tree, new_height as u8);
        } else {
            let offset = mte_parent_slot((*mas).node) as u8;
            let slots = ma_slots(mte_parent((*mas).node), mas_parent_type(mas, (*mas).node));
            rcu_assign(slots.add(offset as usize), (*mas).node);
        }

        mte_set_node_dead(old_enode);
    }
}

/// `mas_replace_node()`: put the new node in the tree, mark the old one dead and free it.
unsafe fn mas_replace_node(mas: *mut MaState, old_enode: Enode, new_height: u8) {
    // SAFETY: caller contract.
    unsafe {
        mas_put_in_tree(mas, old_enode, new_height as i8);
        mas_free(mas, old_enode);
    }
}

/// `mas_find_child()`: find a child who has the parent `mas->node`.
unsafe fn mas_find_child(mas: *mut MaState, child: *mut MaState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mt = mte_node_type((*mas).node);
        let node = mas_mn(mas);
        let slots = ma_slots(node, mt);
        let pivots = ma_pivots(node, mt);
        let end = ma_data_end(node, mt, pivots, (*mas).max);
        let mut offset = (*mas).offset;
        while offset <= end {
            let entry = mas_slot_locked(mas, slots, offset);
            if mte_parent(entry) == node {
                *child = *mas;
                (*mas).offset = offset + 1;
                (*child).offset = offset;
                mas_descend(child);
                (*child).offset = 0;
                return true;
            }
            offset = offset.wrapping_add(1);
        }
        false
    }
}

/// `mab_shift_right()`: shift the data in the big node right.
unsafe fn mab_shift_right(b_node: *mut MapleBigNode, shift: u8) {
    // SAFETY: caller contract.
    unsafe {
        let size = (*b_node).b_end as usize;

        core::ptr::copy(bpiv(b_node, 0), bpiv(b_node, shift as usize), size);
        core::ptr::copy(bslot(b_node, 0), bslot(b_node, shift as usize), size);
        if (*b_node).type_ == maple_arange_64 {
            core::ptr::copy(bgap(b_node, 0), bgap(b_node, shift as usize), size);
        }
    }
}

/// `mab_middle_node()`: check if a middle node is needed (unlikely).
unsafe fn mab_middle_node(b_node: *mut MapleBigNode, split: c_int, slot_count: u8) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let size = (*b_node).b_end;

        if size >= 2u8.wrapping_mul(slot_count) {
            return true;
        }

        if (*bslot(b_node, split as usize)).is_null() && (size as c_int >= 2 * slot_count as c_int - 1) {
            return true;
        }

        false
    }
}

/// `mab_no_null_split()`: ensure the split doesn't fall on a NULL.
unsafe fn mab_no_null_split(b_node: *mut MapleBigNode, split: u8, slot_count: u8) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut split = split as c_int;
        if (*bslot(b_node, split as usize)).is_null() {
            /* If the split is less than the max slot && the right side will still be sufficient, then increment the split on NULL. */
            if (split < slot_count as c_int - 1) && ((*b_node).b_end as c_int - split) > mt_min_slots[(*b_node).type_ as usize] as c_int {
                split += 1;
            } else {
                split -= 1;
            }
        }
        split
    }
}

/// `mab_calc_split()`: calculate the split location and whether there needs to be two splits.
unsafe fn mab_calc_split(_mas: *mut MaState, bn: *mut MapleBigNode, mid_split: *mut u8) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let b_end = (*bn).b_end;
        let mut split = (b_end / 2) as c_int; /* Assume equal split. */
        let slot_count = mt_slots[(*bn).type_ as usize];

        if mab_middle_node(bn, split, slot_count) {
            split = (b_end / 3) as c_int;
            *mid_split = (split * 2) as u8;
        } else {
            *mid_split = 0;
        }

        /* Avoid ending a node on a NULL entry */
        split = mab_no_null_split(bn, split as u8, slot_count);

        if *mid_split != 0 {
            *mid_split = mab_no_null_split(bn, *mid_split, slot_count) as u8;
        }

        split
    }
}

/// `mas_mab_cp()`: copy data from a maple state inclusively to a big node and set `b_node->b_end` to the next free slot.
unsafe fn mas_mab_cp(mas: *mut MaState, mas_start: u8, mas_end: u8, b_node: *mut MapleBigNode, mab_start: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut i: c_int = mas_start as c_int;
        let mut j: c_int = mab_start as c_int;

        let node = mas_mn(mas);
        let mt = mte_node_type((*mas).node);
        let pivots = ma_pivots(node, mt);

        'complete: {
            if i == 0 {
                *bpiv(b_node, j as usize) = *pivots.add(i as usize);
                i += 1;
                if i > mas_end as c_int {
                    break 'complete;
                }
                j += 1;
            }

            let piv_end = core::cmp::min(mas_end, mt_pivots[mt as usize]) as c_int;
            while i < piv_end {
                *bpiv(b_node, j as usize) = *pivots.add(i as usize);
                if *bpiv(b_node, j as usize) == 0 {
                    break 'complete;
                }

                if (*mas).max == *bpiv(b_node, j as usize) {
                    break 'complete;
                }
                i += 1;
                j += 1;
            }

            *bpiv(b_node, j as usize) = mas_safe_pivot(mas, pivots, i as u8, mt);
        }

        // complete:
        j += 1;
        (*b_node).b_end = j as u8;
        j -= mab_start as c_int;
        let slots = ma_slots(node, mt);
        core::ptr::copy_nonoverlapping(slots.add(mas_start as usize), bslot(b_node, mab_start as usize).cast::<*mut c_void>(), j as usize);
        if !ma_is_leaf(mt) && mt_is_alloc((*mas).tree) {
            let gaps = ma_gaps(node, mt);
            core::ptr::copy_nonoverlapping(gaps.add(mas_start as usize), bgap(b_node, mab_start as usize), j as usize);
        }
    }
}

/// `mas_leaf_set_meta()`: set the metadata of a leaf if possible.
unsafe fn mas_leaf_set_meta(node: *mut MapleNode, mt: u32, end: u8) {
    // SAFETY: caller contract.
    unsafe {
        if end < mt_slots[mt as usize] - 1 {
            ma_set_meta(node, mt, 0, end);
        }
    }
}

/// `mab_mas_cp()`: copy data from the big node to a maple encoded node.
unsafe fn mab_mas_cp(b_node: *mut MapleBigNode, mab_start: u8, mab_end: u8, mas: *mut MaState, new_max: bool) {
    // SAFETY: caller contract.
    unsafe {
        let mut mab_end = mab_end;
        let mut i: c_int;
        let mut j: c_int = 0;
        let mt = mte_node_type((*mas).node);
        let node = mte_to_node((*mas).node);
        let slots = ma_slots(node, mt);
        let pivots = ma_pivots(node, mt);

        if (mab_end as c_int - mab_start as c_int) > mt_pivots[mt as usize] as c_int {
            mab_end -= 1;
        }

        if *pivots.add(mt_pivots[mt as usize] as usize - 1) == 0 {
            *slots.add(mt_pivots[mt as usize] as usize) = null_mut();
        }

        i = mab_start as c_int;
        loop {
            *pivots.add(j as usize) = *bpiv(b_node, i as usize);
            j += 1;
            i += 1;
            if !(i <= mab_end as c_int && *bpiv(b_node, i as usize) != 0) {
                break;
            }
        }

        core::ptr::copy_nonoverlapping(bslot(b_node, mab_start as usize).cast::<*mut c_void>(), slots, (i - mab_start as c_int) as usize);

        if new_max {
            (*mas).max = *bpiv(b_node, i as usize - 1);
        }

        let end = (j - 1) as u8;
        if !ma_is_leaf(mt) && mt_is_alloc((*mas).tree) {
            let mut max_gap: c_ulong = 0;
            let mut offset: u8 = 0;

            let gaps = ma_gaps(node, mt);
            loop {
                j -= 1;
                i -= 1;
                *gaps.add(j as usize) = *bgap(b_node, i as usize);
                if *gaps.add(j as usize) > max_gap {
                    offset = j as u8;
                    max_gap = *gaps.add(j as usize);
                }
                if j == 0 {
                    break;
                }
            }

            ma_set_meta(node, mt, offset, end);
        } else {
            mas_leaf_set_meta(node, mt, end);
        }
    }
}

/// `mas_store_b_node()`: store an `entry` into the big node while also copying the data from a maple encoded node.
unsafe fn mas_store_b_node(wr_mas: *mut MaWrState, b_node: *mut MapleBigNode, offset_end: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let mut b_end: u8;
        /* Possible underflow of piv will wrap back to 0 before use. */
        let mut piv: c_ulong;

        (*b_node).type_ = (*wr_mas).type_;
        b_end = 0;
        let mut slot = (*mas).offset;
        'done: {
            if slot != 0 {
                /* Copy start data up to insert. */
                mas_mab_cp(mas, 0, slot - 1, b_node, 0);
                b_end = (*b_node).b_end;
                piv = *bpiv(b_node, b_end as usize - 1);
            } else {
                piv = (*mas).min.wrapping_sub(1);
            }

            if piv.wrapping_add(1) < (*mas).index {
                /* Handle range starting after old range */
                *bslot(b_node, b_end as usize) = (*wr_mas).content;
                if (*wr_mas).content.is_null() {
                    *bgap(b_node, b_end as usize) = (*mas).index.wrapping_sub(1).wrapping_sub(piv);
                }
                *bpiv(b_node, b_end as usize) = (*mas).index.wrapping_sub(1);
                b_end += 1;
            }

            /* Store the new entry. */
            (*mas).offset = b_end;
            *bslot(b_node, b_end as usize) = (*wr_mas).entry;
            *bpiv(b_node, b_end as usize) = (*mas).last;

            /* Appended. */
            if (*mas).last >= (*mas).max {
                break 'done;
            }

            /* Handle new range ending before old range ends */
            piv = mas_safe_pivot(mas, (*wr_mas).pivots, offset_end, (*wr_mas).type_);
            if piv > (*mas).last {
                if offset_end != slot {
                    (*wr_mas).content = mas_slot_locked(mas, (*wr_mas).slots, offset_end);
                }

                b_end += 1;
                *bslot(b_node, b_end as usize) = (*wr_mas).content;
                if (*wr_mas).content.is_null() {
                    *bgap(b_node, b_end as usize) = piv.wrapping_sub((*mas).last).wrapping_add(1);
                }
                *bpiv(b_node, b_end as usize) = piv;
            }

            slot = offset_end + 1;
            if slot > (*mas).end {
                break 'done;
            }

            /* Copy end data to the end of the node. */
            b_end += 1;
            mas_mab_cp(mas, slot, (*mas).end + 1, b_node, b_end);
            (*b_node).b_end -= 1;
            return;
        }

        // b_end:
        (*b_node).b_end = b_end;
    }
}

/// `mas_prev_sibling()`: find the previous node with the same parent.
unsafe fn mas_prev_sibling(mas: *mut MaState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let p_slot = mte_parent_slot((*mas).node);

        /* For root node, p_slot is set to 0 by mte_parent_slot(). */
        if p_slot == 0 {
            return false;
        }

        mas_ascend(mas);
        (*mas).offset = (p_slot - 1) as u8;
        mas_descend(mas);
        true
    }
}

/// `mas_next_sibling()`: find the next node with the same parent.
unsafe fn mas_next_sibling(mas: *mut MaState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mut parent = ma_state_new((*mas).tree, (*mas).index, (*mas).last);

        if mte_is_root((*mas).node) {
            return false;
        }

        parent = *mas;
        mas_ascend(&raw mut parent);
        parent.offset = (mte_parent_slot((*mas).node) + 1) as u8;
        if parent.offset > mas_data_end(&raw mut parent) {
            return false;
        }

        *mas = parent;
        mas_descend(mas);
        true
    }
}

/// `mas_node_or_none()`: set the enode and state.
#[inline(always)]
unsafe fn mas_node_or_none(mas: *mut MaState, enode: Enode) {
    // SAFETY: caller contract.
    unsafe {
        if !enode.is_null() {
            (*mas).node = enode;
            (*mas).status = ma_active;
        } else {
            (*mas).node = null_mut();
            (*mas).status = ma_none;
        }
    }
}

/// `mas_wr_node_walk()`: find the correct offset for the index in the `mas`.
unsafe fn mas_wr_node_walk(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        if ma_is_dense((*wr_mas).type_) {
            (*wr_mas).r_min = (*mas).index;
            (*wr_mas).r_max = (*mas).index;
            (*mas).index = (*mas).min;
            (*mas).offset = (*mas).index as u8;
            return;
        }

        (*wr_mas).node = mas_mn((*wr_mas).mas);
        (*wr_mas).pivots = ma_pivots((*wr_mas).node, (*wr_mas).type_);
        let count = ma_data_end((*wr_mas).node, (*wr_mas).type_, (*wr_mas).pivots, (*mas).max);
        (*mas).end = count;
        let mut offset = (*mas).offset;

        while offset < count && (*mas).index > *(*wr_mas).pivots.add(offset as usize) {
            offset += 1;
        }

        (*wr_mas).r_max = if offset < count { *(*wr_mas).pivots.add(offset as usize) } else { (*mas).max };
        (*wr_mas).r_min = mas_safe_min(mas, (*wr_mas).pivots, offset);
        (*mas).offset = offset;
        (*wr_mas).offset_end = offset;
    }
}

/// `mast_rebalance_next()`: rebalance against the next node.
unsafe fn mast_rebalance_next(mast: *mut MapleSubtreeState) {
    // SAFETY: caller contract.
    unsafe {
        let b_end = (*(*mast).bn).b_end;

        mas_mab_cp((*mast).orig_r, 0, mt_slots[mte_node_type((*(*mast).orig_r).node) as usize], (*mast).bn, b_end);
        (*(*mast).orig_r).last = (*(*mast).orig_r).max;
    }
}

/// `mast_rebalance_prev()`: rebalance against the previous node.
unsafe fn mast_rebalance_prev(mast: *mut MapleSubtreeState) {
    // SAFETY: caller contract.
    unsafe {
        let end = mas_data_end((*mast).orig_l).wrapping_add(1);
        let b_end = (*(*mast).bn).b_end;

        mab_shift_right((*mast).bn, end);
        mas_mab_cp((*mast).orig_l, 0, end.wrapping_sub(1), (*mast).bn, 0);
        (*(*mast).l).min = (*(*mast).orig_l).min;
        (*(*mast).orig_l).index = (*(*mast).orig_l).min;
        (*(*mast).bn).b_end = end.wrapping_add(b_end);
        (*(*mast).l).offset = (*(*mast).l).offset.wrapping_add(end);
    }
}

/// `mast_spanning_rebalance()`: rebalance nodes with the nearest neighbour favouring the node to the right.
unsafe fn mast_spanning_rebalance(mast: *mut MapleSubtreeState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let r_tmp = *(*mast).orig_r;
        let l_tmp = *(*mast).orig_l;
        let mut depth: u8 = 0;

        loop {
            mas_ascend((*mast).orig_r);
            mas_ascend((*mast).orig_l);
            depth += 1;
            if (*(*mast).orig_r).offset < mas_data_end((*mast).orig_r) {
                (*(*mast).orig_r).offset += 1;
                loop {
                    mas_descend((*mast).orig_r);
                    (*(*mast).orig_r).offset = 0;
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }

                mast_rebalance_next(mast);
                *(*mast).orig_l = l_tmp;
                return true;
            } else if (*(*mast).orig_l).offset != 0 {
                (*(*mast).orig_l).offset -= 1;
                loop {
                    mas_descend((*mast).orig_l);
                    (*(*mast).orig_l).offset = mas_data_end((*mast).orig_l);
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }

                mast_rebalance_prev(mast);
                *(*mast).orig_r = r_tmp;
                return true;
            }
            if mte_is_root((*(*mast).orig_r).node) {
                break;
            }
        }

        *(*mast).orig_r = r_tmp;
        *(*mast).orig_l = l_tmp;
        false
    }
}

/// `mast_ascend()`: ascend the original left and right maple states.
unsafe fn mast_ascend(mast: *mut MapleSubtreeState) {
    // SAFETY: caller contract.
    unsafe {
        let mut wr_mas = ma_wr_state_new((*mast).orig_r, null_mut());
        mas_ascend((*mast).orig_l);
        mas_ascend((*mast).orig_r);

        (*(*mast).orig_r).offset = 0;
        (*(*mast).orig_r).index = (*(*mast).r).max;
        /* last should be larger than or equal to index */
        if (*(*mast).orig_r).last < (*(*mast).orig_r).index {
            (*(*mast).orig_r).last = (*(*mast).orig_r).index;
        }

        wr_mas.type_ = mte_node_type((*(*mast).orig_r).node);
        mas_wr_node_walk(&raw mut wr_mas);
        /* Set up the left side of things */
        (*(*mast).orig_l).offset = 0;
        (*(*mast).orig_l).index = (*(*mast).l).min;
        wr_mas.mas = (*mast).orig_l;
        wr_mas.type_ = mte_node_type((*(*mast).orig_l).node);
        mas_wr_node_walk(&raw mut wr_mas);

        (*(*mast).bn).type_ = wr_mas.type_;
    }
}

/// `mas_new_ma_node()`: create and return a new maple node (type from the big node).
#[inline(always)]
unsafe fn mas_new_ma_node(mas: *mut MaState, b_node: *mut MapleBigNode) -> Enode {
    // SAFETY: caller contract.
    unsafe { mt_mk_node(mas_pop_node(mas), (*b_node).type_) }
}

/// `mas_mab_to_node()`: set up right and middle nodes; returns the split of left.
unsafe fn mas_mab_to_node(
    mas: *mut MaState,
    b_node: *mut MapleBigNode,
    left: *mut Enode,
    right: *mut Enode,
    middle: *mut Enode,
    mid_split: *mut u8,
) -> u8 {
    // SAFETY: caller contract.
    unsafe {
        let split: u8;
        let slot_count = mt_slots[(*b_node).type_ as usize];

        *left = mas_new_ma_node(mas, b_node);
        *right = null_mut();
        *middle = null_mut();
        *mid_split = 0;

        if (*b_node).b_end < slot_count {
            split = (*b_node).b_end;
        } else {
            split = mab_calc_split(mas, b_node, mid_split) as u8;
            *right = mas_new_ma_node(mas, b_node);
        }

        if *mid_split != 0 {
            *middle = mas_new_ma_node(mas, b_node);
        }

        split
    }
}

/// `mab_set_b_end()`: add an entry to the big node at `b_end` and increment the end pointer.
unsafe fn mab_set_b_end(b_node: *mut MapleBigNode, mas: *mut MaState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        if entry.is_null() {
            return;
        }

        *bslot(b_node, (*b_node).b_end as usize) = entry;
        if mt_is_alloc((*mas).tree) {
            *bgap(b_node, (*b_node).b_end as usize) = mas_max_gap(mas);
        }
        *bpiv(b_node, (*b_node).b_end as usize) = (*mas).max;
        (*b_node).b_end = (*b_node).b_end.wrapping_add(1);
    }
}

/// `mas_set_split_parent()`: set the parent of `mas->node` to either `left` or `right`, depending on `slot` and `split`.
unsafe fn mas_set_split_parent(mas: *mut MaState, left: Enode, right: Enode, slot: *mut u8, split: u8) {
    // SAFETY: caller contract.
    unsafe {
        if mas_is_none(mas) {
            return;
        }

        if *slot <= split {
            mas_set_parent(mas, (*mas).node, left, *slot);
        } else if !right.is_null() {
            mas_set_parent(mas, (*mas).node, right, (*slot).wrapping_sub(split).wrapping_sub(1));
        }

        *slot = (*slot).wrapping_add(1);
    }
}

/// `mte_mid_split_check()`: check if the next node passes the mid-split.
unsafe fn mte_mid_split_check(l: *mut Enode, r: *mut Enode, right: Enode, slot: u8, split: *mut u8, mid_split: u8) {
    // SAFETY: caller contract.
    unsafe {
        if *r == right {
            return;
        }

        if slot < mid_split {
            return;
        }

        *l = *r;
        *r = right;
        *split = mid_split;
    }
}

/// `mast_set_split_parents()`: set three nodes' parents; the slot is taken from `mast->l`.
unsafe fn mast_set_split_parents(mast: *mut MapleSubtreeState, left: Enode, middle: Enode, right: Enode, split: u8, mid_split: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut split = split;
        let mut l = left;
        let mut r = right;

        if mas_is_none((*mast).l) {
            return;
        }

        if !middle.is_null() {
            r = middle;
        }

        let mut slot = (*(*mast).l).offset;

        mte_mid_split_check(&raw mut l, &raw mut r, right, slot, &raw mut split, mid_split);
        mas_set_split_parent((*mast).l, l, r, &raw mut slot, split);

        mte_mid_split_check(&raw mut l, &raw mut r, right, slot, &raw mut split, mid_split);
        mas_set_split_parent((*mast).m, l, r, &raw mut slot, split);

        mte_mid_split_check(&raw mut l, &raw mut r, right, slot, &raw mut split, mid_split);
        mas_set_split_parent((*mast).r, l, r, &raw mut slot, split);
    }
}

/// `mas_topiary_node()`: dispose of a single node (RCU free).
unsafe fn mas_topiary_node(_mas: *mut MaState, tmp_mas: *mut MaState, _in_rcu: bool) {
    // SAFETY: caller contract.
    unsafe {
        if mas_is_none(tmp_mas) {
            return;
        }

        let enode = (*tmp_mas).node;
        let tmp = mte_to_node(enode);
        mte_set_node_dead(enode);
        ma_free_rcu(tmp);
    }
}

// ---------------------------------------------------------------------------
// C lines 2330-2800: topiary replace, spanning rebalance, range walk
// ---------------------------------------------------------------------------

/// `mas_reset()`.
#[inline(always)]
unsafe fn mas_reset(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        (*mas).status = ma_start;
        (*mas).node = null_mut();
    }
}

/// `mas_topiary_replace()`: replace the data with new data, then repair the parent links within the new tree and discard the old nodes.
unsafe fn mas_topiary_replace(mas: *mut MaState, old_enode: Enode, new_height: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut tmp: [MaState; 3] = core::mem::zeroed();
        let mut tmp_next: [MaState; 3] = core::mem::zeroed();
        let mut subtrees = ma_topiary_new((*mas).tree);
        let mut i: usize;
        let mut n: usize;

        /* Place data in tree & then mark node as old */
        mas_put_in_tree(mas, old_enode, new_height as i8);

        /* Update the parent pointers in the tree */
        tmp[0] = *mas;
        tmp[0].offset = 0;
        tmp[1].status = ma_none;
        tmp[2].status = ma_none;
        while !mte_is_leaf(tmp[0].node) {
            n = 0;
            i = 0;
            while i < 3 {
                if mas_is_none(&raw const tmp[i]) {
                    i += 1;
                    continue;
                }

                while n < 3 {
                    if !mas_find_child(&raw mut tmp[i], &raw mut tmp_next[n]) {
                        break;
                    }
                    n += 1;
                }

                mas_adopt_children(&raw mut tmp[i], tmp[i].node);
                i += 1;
            }

            if warn_on(n == 0) {
                break;
            }

            while n < 3 {
                tmp_next[n].status = ma_none;
                n += 1;
            }

            i = 0;
            while i < 3 {
                tmp[i] = tmp_next[i];
                i += 1;
            }
        }

        /* Collect the old nodes that need to be discarded */
        if mte_is_leaf(old_enode) {
            mas_free(mas, old_enode);
            return;
        }

        tmp[0] = *mas;
        tmp[0].offset = 0;
        tmp[0].node = old_enode;
        tmp[1].status = ma_none;
        tmp[2].status = ma_none;
        let in_rcu = mt_in_rcu((*mas).tree);
        loop {
            n = 0;
            i = 0;
            while i < 3 {
                if mas_is_none(&raw const tmp[i]) {
                    i += 1;
                    continue;
                }

                while n < 3 {
                    if !mas_find_child(&raw mut tmp[i], &raw mut tmp_next[n]) {
                        break;
                    }

                    if tmp_next[n].min >= tmp_next[0].index && tmp_next[n].max <= tmp_next[0].last {
                        mat_add(&raw mut subtrees, tmp_next[n].node);
                        tmp_next[n].status = ma_none;
                    } else {
                        n += 1;
                    }
                }
                i += 1;
            }

            if warn_on(n == 0) {
                break;
            }

            while n < 3 {
                tmp_next[n].status = ma_none;
                n += 1;
            }

            i = 0;
            while i < 3 {
                mas_topiary_node(mas, &raw mut tmp[i], in_rcu);
                tmp[i] = tmp_next[i];
                i += 1;
            }

            if mte_is_leaf(tmp[0].node) {
                break;
            }
        }

        i = 0;
        while i < 3 {
            mas_topiary_node(mas, &raw mut tmp[i], in_rcu);
            i += 1;
        }

        mas_mat_destroy(mas, &raw mut subtrees);
    }
}

/// `mas_wmb_replace()`: write memory barrier and replace; updates gaps as necessary.
unsafe fn mas_wmb_replace(mas: *mut MaState, old_enode: Enode, new_height: u8) {
    // SAFETY: caller contract.
    unsafe {
        /* Insert the new data in the tree */
        mas_topiary_replace(mas, old_enode, new_height);

        if mte_is_leaf((*mas).node) {
            return;
        }

        mas_update_gap(mas);
    }
}

/// `mast_cp_to_nodes()`: copy data out to nodes.
unsafe fn mast_cp_to_nodes(mast: *mut MapleSubtreeState, left: Enode, middle: Enode, right: Enode, split: u8, mid_split: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut split = split;
        let mut new_lmax = true;

        mas_node_or_none((*mast).l, left);
        mas_node_or_none((*mast).m, middle);
        mas_node_or_none((*mast).r, right);

        (*(*mast).l).min = (*(*mast).orig_l).min;
        if split == (*(*mast).bn).b_end {
            (*(*mast).l).max = (*(*mast).orig_r).max;
            new_lmax = false;
        }

        mab_mas_cp((*mast).bn, 0, split, (*mast).l, new_lmax);

        if !middle.is_null() {
            mab_mas_cp((*mast).bn, split.wrapping_add(1), mid_split, (*mast).m, true);
            (*(*mast).m).min = (*bpiv((*mast).bn, split as usize)).wrapping_add(1);
            split = mid_split;
        }

        (*(*mast).r).max = (*(*mast).orig_r).max;
        if !right.is_null() {
            mab_mas_cp((*mast).bn, split.wrapping_add(1), (*(*mast).bn).b_end, (*mast).r, false);
            (*(*mast).r).min = (*bpiv((*mast).bn, split as usize)).wrapping_add(1);
        }
    }
}

/// `mast_combine_cp_left()`: copy in the original left side of the tree into the combined data set.
unsafe fn mast_combine_cp_left(mast: *mut MapleSubtreeState) {
    // SAFETY: caller contract.
    unsafe {
        let l_slot = (*(*mast).orig_l).offset;

        if l_slot == 0 {
            return;
        }

        mas_mab_cp((*mast).orig_l, 0, l_slot - 1, (*mast).bn, 0);
    }
}

/// `mast_combine_cp_right()`: copy in the original right side of the tree into the combined data set.
unsafe fn mast_combine_cp_right(mast: *mut MapleSubtreeState) {
    // SAFETY: caller contract.
    unsafe {
        if *bpiv((*mast).bn, (*(*mast).bn).b_end as usize - 1) >= (*(*mast).orig_r).max {
            return;
        }

        mas_mab_cp(
            (*mast).orig_r,
            (*(*mast).orig_r).offset + 1,
            mt_slots[mte_node_type((*(*mast).orig_r).node) as usize],
            (*mast).bn,
            (*(*mast).bn).b_end,
        );
        (*(*mast).orig_r).last = (*(*mast).orig_r).max;
    }
}

/// `mast_sufficient()`: enough data in the big node to create at least one sufficient node.
unsafe fn mast_sufficient(mast: *mut MapleSubtreeState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*(*mast).bn).b_end > mt_min_slots[mte_node_type((*(*mast).orig_l).node) as usize] }
}

/// `mast_overflow()`: too much data for a single node.
unsafe fn mast_overflow(mast: *mut MapleSubtreeState) -> bool {
    // SAFETY: caller contract.
    unsafe { (*(*mast).bn).b_end > mt_slots[mte_node_type((*(*mast).orig_l).node) as usize] }
}

/// `mtree_range_walk()`.
unsafe fn mtree_range_walk(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut next = (*mas).node;
        let mut min = (*mas).min;
        let mut max = (*mas).max;
        let mut last: Enode;
        let mut prev_min: c_ulong;
        let mut prev_max: c_ulong;
        let mut offset: u8;
        let mut end: u8;

        loop {
            last = next;
            let node = mte_to_node(next);
            let type_ = mte_node_type(next);
            let pivots = ma_pivots(node, type_);
            end = ma_data_end(node, type_, pivots, max);
            prev_min = min;
            prev_max = max;
            if *pivots >= (*mas).index {
                offset = 0;
                max = *pivots;
            } else {
                offset = 1;
                while offset < end {
                    if *pivots.add(offset as usize) >= (*mas).index {
                        max = *pivots.add(offset as usize);
                        break;
                    }
                    offset += 1;
                }

                min = (*pivots.add(offset as usize - 1)).wrapping_add(1);
            }

            // next:
            let slots = ma_slots(node, type_);
            next = mt_slot((*mas).tree, slots, offset);
            if ma_dead_node(node) {
                // dead_node:
                mas_reset(mas);
                return null_mut();
            }

            if ma_is_leaf(type_) {
                break;
            }
        }

        (*mas).end = end;
        (*mas).offset = offset;
        (*mas).index = min;
        (*mas).last = max;
        (*mas).min = prev_min;
        (*mas).max = prev_max;
        (*mas).node = last;
        next
    }
}

/// `mas_spanning_rebalance()`: rebalance across two nodes which may not be peers.
unsafe fn mas_spanning_rebalance(mas: *mut MaState, mast: *mut MapleSubtreeState, count: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut count = count;
        let mut split: u8;
        let mut mid_split: u8 = 0;
        let mut slot: u8 = 0;
        let mut new_height: u8 = 0; /* used if node is a new root */
        let mut left: Enode = null_mut();
        let mut middle: Enode = null_mut();
        let mut right: Enode = null_mut();

        let mut l_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).index);
        let mut r_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut m_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).index);

        /* The tree needs to be rebalanced and leaves need to be kept at the same level. Rebalancing is done by use of the topiary. */
        (*mast).l = &raw mut l_mas;
        (*mast).m = &raw mut m_mas;
        (*mast).r = &raw mut r_mas;
        l_mas.status = ma_none;
        r_mas.status = ma_none;
        m_mas.status = ma_none;

        /* Check if this is not root and has sufficient data.  */
        if ((*(*mast).orig_l).min != 0 || (*(*mast).orig_r).max != ULONG_MAX) && (*(*mast).bn).b_end <= mt_min_slots[(*(*mast).bn).type_ as usize] {
            mast_spanning_rebalance(mast);
        }

        let mut goto_new_root = false;
        while count != 0 {
            count -= 1;
            (*(*mast).bn).b_end = (*(*mast).bn).b_end.wrapping_sub(1);
            (*(*mast).bn).type_ = mte_node_type((*(*mast).orig_l).node);
            split = mas_mab_to_node(mas, (*mast).bn, &raw mut left, &raw mut right, &raw mut middle, &raw mut mid_split);
            mast_set_split_parents(mast, left, middle, right, split, mid_split);
            mast_cp_to_nodes(mast, left, middle, right, split, mid_split);
            new_height += 1;

            /* Copy data from next level in the tree to mast->bn from next iteration */
            core::ptr::write_bytes((*mast).bn, 0, 1);
            (*(*mast).bn).type_ = mte_node_type(left);

            /* Root already stored in l->node. */
            if mas_is_root_limits((*mast).l) {
                goto_new_root = true;
                break;
            }

            mast_ascend(mast);
            mast_combine_cp_left(mast);
            l_mas.offset = (*(*mast).bn).b_end;
            mab_set_b_end((*mast).bn, &raw mut l_mas, left);
            mab_set_b_end((*mast).bn, &raw mut m_mas, middle);
            mab_set_b_end((*mast).bn, &raw mut r_mas, right);

            /* Copy anything necessary out of the right node. */
            mast_combine_cp_right(mast);
            (*(*mast).orig_l).last = (*(*mast).orig_l).max;

            if mast_sufficient(mast) {
                if mast_overflow(mast) {
                    continue;
                }

                if (*(*mast).orig_l).node == (*(*mast).orig_r).node {
                    /* The data in b_node should be stored in one node and in the tree */
                    slot = (*(*mast).l).offset;
                    break;
                }

                continue;
            }

            /* May be a new root stored in mast->bn */
            if mas_is_root_limits((*mast).orig_l) {
                break;
            }

            mast_spanning_rebalance(mast);

            /* rebalancing from other nodes may require another loop. */
            if count == 0 {
                count += 1;
            }
        }

        if !goto_new_root {
            l_mas.node = mt_mk_node(mas_pop_node(mas), mte_node_type((*(*mast).orig_l).node));

            mab_mas_cp((*mast).bn, 0, mt_slots[(*(*mast).bn).type_ as usize] - 1, &raw mut l_mas, true);
            new_height += 1;
            mas_set_parent(mas, left, l_mas.node, slot);
            if !middle.is_null() {
                slot += 1;
                mas_set_parent(mas, middle, l_mas.node, slot);
            }

            if !right.is_null() {
                slot += 1;
                mas_set_parent(mas, right, l_mas.node, slot);
            }
        }

        if goto_new_root || mas_is_root_limits((*mast).l) {
            // new_root:
            *n_parent(mas_mn((*mast).l)) = mas_tree_parent(mas) as Pnode;
            while !mte_is_root((*(*mast).orig_l).node) {
                mast_ascend(mast);
            }
        } else {
            *n_parent(mas_mn(&raw const l_mas)) = *n_parent(mas_mn((*mast).orig_l));
        }

        let old_enode = (*(*mast).orig_l).node;
        (*mas).depth = l_mas.depth;
        (*mas).node = l_mas.node;
        (*mas).min = l_mas.min;
        (*mas).max = l_mas.max;
        (*mas).offset = l_mas.offset;
        mas_wmb_replace(mas, old_enode, new_height);
        mtree_range_walk(mas);
    }
}

/// `mas_rebalance()`: rebalance a given node.
unsafe fn mas_rebalance(mas: *mut MaState, b_node: *mut MapleBigNode) {
    // SAFETY: caller contract.
    unsafe {
        let empty_count = mas_mt_height(mas) as u8;
        (*b_node).b_end = (*b_node).b_end.wrapping_add(1);
        let b_end = (*b_node).b_end;

        let mut l_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut r_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut mast: MapleSubtreeState = core::mem::zeroed();

        rust_mt_trace_ma_op(c"mas_rebalance".as_ptr(), mas);

        mast.orig_l = &raw mut l_mas;
        mast.orig_r = &raw mut r_mas;
        mast.bn = b_node;
        (*mast.bn).type_ = mte_node_type((*mas).node);

        r_mas = *mas;
        l_mas = r_mas;

        if mas_next_sibling(&raw mut r_mas) {
            mas_mab_cp(&raw mut r_mas, 0, mt_slots[mte_node_type(r_mas.node) as usize], b_node, b_end);
            r_mas.index = r_mas.max;
            r_mas.last = r_mas.index;
        } else {
            mas_prev_sibling(&raw mut l_mas);
            let shift = mas_data_end(&raw mut l_mas).wrapping_add(1);
            mab_shift_right(b_node, shift);
            (*mas).offset = (*mas).offset.wrapping_add(shift);
            mas_mab_cp(&raw mut l_mas, 0, shift.wrapping_sub(1), b_node, 0);
            (*b_node).b_end = shift.wrapping_add(b_end);
            l_mas.last = l_mas.min;
            l_mas.index = l_mas.last;
        }

        mas_spanning_rebalance(mas, &raw mut mast, empty_count);
    }
}

// ---------------------------------------------------------------------------
// C lines 2800-3320: split, push data, root store, write walk
// ---------------------------------------------------------------------------

/// `mas_split_final_node()`: split the final node in a subtree operation.
unsafe fn mas_split_final_node(mast: *mut MapleSubtreeState, mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        if mte_is_root((*mas).node) {
            if mt_is_alloc((*mas).tree) {
                (*(*mast).bn).type_ = maple_arange_64;
            } else {
                (*(*mast).bn).type_ = maple_range_64;
            }
        }
        /* Only a single node is used here, could be root. The Big_node data should just fit in a single node. */
        let ancestor = mas_new_ma_node(mas, (*mast).bn);
        mas_set_parent(mas, (*(*mast).l).node, ancestor, (*(*mast).l).offset);
        mas_set_parent(mas, (*(*mast).r).node, ancestor, (*(*mast).r).offset);
        *n_parent(mte_to_node(ancestor)) = *n_parent(mas_mn(mas));

        (*(*mast).l).node = ancestor;
        mab_mas_cp((*mast).bn, 0, mt_slots[(*(*mast).bn).type_ as usize] - 1, (*mast).l, true);
        (*mas).offset = (*(*mast).bn).b_end.wrapping_sub(1);
    }
}

/// `mast_fill_bnode()`: copy data into the big node in the subtree state.
unsafe fn mast_fill_bnode(mast: *mut MapleSubtreeState, mas: *mut MaState, skip: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mut cp = true;

        core::ptr::write_bytes((*mast).bn, 0, 1);

        if mte_is_root((*mas).node) {
            cp = false;
        } else {
            mas_ascend(mas);
            (*mas).offset = mte_parent_slot((*mas).node) as u8;
        }

        if cp && (*(*mast).l).offset != 0 {
            mas_mab_cp(mas, 0, (*(*mast).l).offset - 1, (*mast).bn, 0);
        }

        let split = (*(*mast).bn).b_end;
        mab_set_b_end((*mast).bn, (*mast).l, (*(*mast).l).node);
        (*(*mast).r).offset = (*(*mast).bn).b_end;
        mab_set_b_end((*mast).bn, (*mast).r, (*(*mast).r).node);
        if *bpiv((*mast).bn, (*(*mast).bn).b_end as usize - 1) == (*mas).max {
            cp = false;
        }

        if cp {
            mas_mab_cp(
                mas,
                split.wrapping_add(skip),
                mt_slots[mte_node_type((*mas).node) as usize] - 1,
                (*mast).bn,
                (*(*mast).bn).b_end,
            );
        }

        (*(*mast).bn).b_end = (*(*mast).bn).b_end.wrapping_sub(1);
        (*(*mast).bn).type_ = mte_node_type((*mas).node);
    }
}

/// `mast_split_data()`: split the data in the subtree state big node into regular nodes.
unsafe fn mast_split_data(mast: *mut MapleSubtreeState, mas: *mut MaState, split: u8) {
    // SAFETY: caller contract.
    unsafe {
        mab_mas_cp((*mast).bn, 0, split, (*mast).l, true);
        mte_set_pivot((*(*mast).r).node, 0, (*(*mast).r).max);
        mab_mas_cp((*mast).bn, split.wrapping_add(1), (*(*mast).bn).b_end, (*mast).r, false);
        (*(*mast).l).offset = mte_parent_slot((*mas).node) as u8;
        (*(*mast).l).max = *bpiv((*mast).bn, split as usize);
        (*(*mast).r).min = (*(*mast).l).max.wrapping_add(1);
        if mte_is_leaf((*mas).node) {
            return;
        }

        let mut p_slot = (*(*mast).orig_l).offset;
        mas_set_split_parent((*mast).orig_l, (*(*mast).l).node, (*(*mast).r).node, &raw mut p_slot, split);
        mas_set_split_parent((*mast).orig_r, (*(*mast).l).node, (*(*mast).r).node, &raw mut p_slot, split);
    }
}

/// `mas_push_data()`: instead of splitting a node, push the data to the right or left node if there is room.
unsafe fn mas_push_data(mas: *mut MaState, mast: *mut MapleSubtreeState, left: bool) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mut slot_total = (*(*mast).bn).b_end;
        let end: u8;
        let mut space: u8;
        let mut split: u8;

        let mut tmp_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        tmp_mas = *mas;
        tmp_mas.depth = (*(*mast).l).depth;

        if left && !mas_prev_sibling(&raw mut tmp_mas) {
            return false;
        } else if !left && !mas_next_sibling(&raw mut tmp_mas) {
            return false;
        }

        end = mas_data_end(&raw mut tmp_mas);
        slot_total = slot_total.wrapping_add(end);
        space = (2u8.wrapping_mul(mt_slots[mte_node_type((*mas).node) as usize])).wrapping_sub(2);
        /* -2 instead of -1 to ensure there isn't a triple split */
        if ma_is_leaf((*(*mast).bn).type_) {
            space = space.wrapping_sub(1);
        }

        if (*mas).max == ULONG_MAX {
            space = space.wrapping_sub(1);
        }

        if slot_total >= space {
            return false;
        }

        /* Get the data; Fill mast->bn */
        (*(*mast).bn).b_end = (*(*mast).bn).b_end.wrapping_add(1);
        if left {
            mab_shift_right((*mast).bn, end.wrapping_add(1));
            mas_mab_cp(&raw mut tmp_mas, 0, end, (*mast).bn, 0);
            (*(*mast).bn).b_end = slot_total.wrapping_add(1);
        } else {
            mas_mab_cp(&raw mut tmp_mas, 0, end, (*mast).bn, (*(*mast).bn).b_end);
        }

        /* Configure mast for splitting of mast->bn */
        split = mt_slots[(*(*mast).bn).type_ as usize] - 2;
        if left {
            /* Switch mas to prev node */
            *mas = tmp_mas;
            /* Start using mast->l for the left side. */
            tmp_mas.node = (*(*mast).l).node;
            *(*mast).l = tmp_mas;
        } else {
            tmp_mas.node = (*(*mast).r).node;
            *(*mast).r = tmp_mas;
            split = slot_total.wrapping_sub(split);
        }
        split = mab_no_null_split((*mast).bn, split, mt_slots[(*(*mast).bn).type_ as usize]) as u8;
        /* Update parent slot for split calculation. */
        if left {
            (*(*mast).orig_l).offset = (*(*mast).orig_l).offset.wrapping_add(end).wrapping_add(1);
        }

        mast_split_data(mast, mas, split);
        mast_fill_bnode(mast, mas, 2);
        mas_split_final_node(mast, mas);
        true
    }
}

/// `mas_split()`: split data that is too big for one node into two.
unsafe fn mas_split(mas: *mut MaState, b_node: *mut MapleBigNode) {
    // SAFETY: caller contract.
    unsafe {
        let mut mast: MapleSubtreeState = core::mem::zeroed();
        let mut height: c_int = 0;
        let orig_height = mas_mt_height(mas);
        let mut mid_split: u8 = 0;
        let mut split: u8;

        /* Splitting is handled differently from any other B-tree; the Maple Tree splits upwards. */
        let mut l_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut r_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut prev_l_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);
        let mut prev_r_mas = ma_state_new((*mas).tree, (*mas).index, (*mas).last);

        rust_mt_trace_ma_op(c"mas_split".as_ptr(), mas);

        mast.l = &raw mut l_mas;
        mast.r = &raw mut r_mas;
        mast.orig_l = &raw mut prev_l_mas;
        mast.orig_r = &raw mut prev_r_mas;
        mast.bn = b_node;

        loop {
            /* `while (height++ <= orig_height)` */
            let cont = (height as c_uint) <= orig_height;
            height += 1;
            if !cont {
                break;
            }

            if mt_slots[(*b_node).type_ as usize] > (*b_node).b_end {
                mas_split_final_node(&raw mut mast, mas);
                break;
            }

            r_mas = *mas;
            l_mas = r_mas;
            l_mas.node = mas_new_ma_node(mas, b_node);
            r_mas.node = mas_new_ma_node(mas, b_node);
            /* Another way that 'jitter' is avoided is to terminate a split up early if the left or right node has space to spare. */
            /* Try to push left. */
            if mas_push_data(mas, &raw mut mast, true) {
                height += 1;
                break;
            }
            /* Try to push right. */
            if mas_push_data(mas, &raw mut mast, false) {
                height += 1;
                break;
            }

            split = mab_calc_split(mas, b_node, &raw mut mid_split) as u8;
            mast_split_data(&raw mut mast, mas, split);
            /* Usually correct, mab_mas_cp in the above call overwrites r->max. */
            (*mast.r).max = (*mas).max;
            mast_fill_bnode(&raw mut mast, mas, 1);
            prev_l_mas = *mast.l;
            prev_r_mas = *mast.r;
        }

        /* Set the original node as dead */
        let old = (*mas).node;
        (*mas).node = l_mas.node;
        mas_wmb_replace(mas, old, height as u8);
        mtree_range_walk(mas);
    }
}

/// `mas_commit_b_node()`: commit the big node into the tree.
unsafe fn mas_commit_b_node(wr_mas: *mut MaWrState, b_node: *mut MapleBigNode) {
    // SAFETY: caller contract.
    unsafe {
        let type_ = (*(*wr_mas).mas).store_type;

        warn_on_once(type_ != wr_rebalance && type_ != wr_split_store);

        if type_ == wr_rebalance {
            mas_rebalance((*wr_mas).mas, b_node);
            return;
        }

        mas_split((*wr_mas).mas, b_node);
    }
}

/// `mas_root_expand()`: expand a root to a node.
unsafe fn mas_root_expand(mas: *mut MaState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        let contents = mas_root_locked(mas);
        let type_ = maple_leaf_64;
        let mut slot: usize = 0;

        let node = mas_pop_node(mas);
        let pivots = ma_pivots(node, type_);
        let slots = ma_slots(node, type_);
        *n_parent(node) = mas_tree_parent(mas) as Pnode;
        (*mas).node = mt_mk_node(node, type_);
        (*mas).status = ma_active;

        if (*mas).index != 0 {
            if !contents.is_null() {
                rcu_assign(slots.add(slot), contents);
                if (*mas).index > 1 {
                    slot += 1;
                }
            }
            *pivots.add(slot) = (*mas).index - 1;
            slot += 1;
        }

        rcu_assign(slots.add(slot), entry);
        (*mas).offset = slot as u8;
        *pivots.add(slot) = (*mas).last;
        if (*mas).last != ULONG_MAX {
            slot += 1;
            *pivots.add(slot) = ULONG_MAX;
        }

        mt_set_height((*mas).tree, 1);
        ma_set_meta(node, maple_leaf_64, 0, slot as u8);
        /* swap the new root into the tree */
        rcu_assign(mt_root_p((*mas).tree), mte_mk_root((*mas).node));
    }
}

/// `mas_store_root()`: storing a value into the root.
unsafe fn mas_store_root(mas: *mut MaState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        if entry.is_null() {
            if (*mas).index == 0 {
                rcu_assign(mt_root_p((*mas).tree), null_mut());
            }
        } else if (*mas).last != 0 || (*mas).index != 0 {
            mas_root_expand(mas, entry);
        } else if (entry as usize) & 3 == 2 {
            mas_root_expand(mas, entry);
        } else {
            rcu_assign(mt_root_p((*mas).tree), entry);
            (*mas).status = ma_start;
        }
    }
}

/// `mas_is_span_wr()`: check if the write needs to be treated as a write that spans the node.
unsafe fn mas_is_span_wr(wr_mas: *mut MaWrState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mut max = (*wr_mas).r_max;
        let last = (*(*wr_mas).mas).last;
        let type_ = (*wr_mas).type_;
        let entry = (*wr_mas).entry;

        /* Contained in this pivot, fast path */
        if last < max {
            return false;
        }

        if ma_is_leaf(type_) {
            max = (*(*wr_mas).mas).max;
            if last < max {
                return false;
            }
        }

        if last == max {
            /* The last entry of leaf node cannot be NULL unless it is the rightmost node (writing ULONG_MAX), otherwise it spans slots. */
            if !entry.is_null() || last == ULONG_MAX {
                return false;
            }
        }

        rust_mt_trace_ma_write(c"mas_is_span_wr".as_ptr(), (*wr_mas).mas, (*wr_mas).r_max, entry);
        true
    }
}

unsafe fn mas_wr_walk_descend(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        (*wr_mas).type_ = mte_node_type((*(*wr_mas).mas).node);
        mas_wr_node_walk(wr_mas);
        (*wr_mas).slots = ma_slots((*wr_mas).node, (*wr_mas).type_);
    }
}

unsafe fn mas_wr_walk_traverse(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        (*(*wr_mas).mas).max = (*wr_mas).r_max;
        (*(*wr_mas).mas).min = (*wr_mas).r_min;
        (*(*wr_mas).mas).node = (*wr_mas).content;
        (*(*wr_mas).mas).offset = 0;
        (*(*wr_mas).mas).depth += 1;
    }
}

/// `mas_wr_walk()`: walk the tree for a write. Returns true if it is contained in a node, false on a spanning write.
unsafe fn mas_wr_walk(wr_mas: *mut MaWrState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        loop {
            mas_wr_walk_descend(wr_mas);
            if mas_is_span_wr(wr_mas) {
                return false;
            }

            (*wr_mas).content = mas_slot_locked(mas, (*wr_mas).slots, (*mas).offset);
            if ma_is_leaf((*wr_mas).type_) {
                return true;
            }

            if ((*mas).end as c_int) < mt_slots[(*wr_mas).type_ as usize] as c_int - 1 {
                (*wr_mas).vacant_height = (*mas).depth + 1;
            }

            if ma_is_root(mas_mn(mas)) {
                /* root needs more than 2 entries to be sufficient + 1 */
                if (*mas).end > 2 {
                    (*wr_mas).sufficient_height = 1;
                }
            } else if (*mas).end as c_int > mt_min_slots[(*wr_mas).type_ as usize] as c_int + 1 {
                (*wr_mas).sufficient_height = (*mas).depth + 1;
            }

            mas_wr_walk_traverse(wr_mas);
        }
    }
}

unsafe fn mas_wr_walk_index(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        loop {
            mas_wr_walk_descend(wr_mas);
            (*wr_mas).content = mas_slot_locked(mas, (*wr_mas).slots, (*mas).offset);
            if ma_is_leaf((*wr_mas).type_) {
                return;
            }
            mas_wr_walk_traverse(wr_mas);
        }
    }
}

/// `mas_extend_spanning_null()`: extend a store of a NULL to include surrounding NULLs.
///
/// **Deliberate divergence (to be confirmed by `port/test/maple_tree`)**: the C calls
/// `mas_safe_pivot(r_mas, pivots, r_wr_mas->type, r_mas->offset + 1)`, i.e. with the `piv` and `type` arguments swapped relative to the
/// function's declaration (`piv` first, then `type`), which indexes `mt_pivots[]` out of bounds and returns `pivots[type]`; this port
/// passes them in the declared order.
unsafe fn mas_extend_spanning_null(l_wr_mas: *mut MaWrState, r_wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let r_mas = (*r_wr_mas).mas;
        let l_mas = (*l_wr_mas).mas;

        let l_slot = (*l_mas).offset;
        if (*l_wr_mas).content.is_null() {
            (*l_mas).index = (*l_wr_mas).r_min;
        }

        if (*l_mas).index == (*l_wr_mas).r_min && l_slot != 0 && mas_slot_locked(l_mas, (*l_wr_mas).slots, l_slot - 1).is_null() {
            if l_slot > 1 {
                (*l_mas).index = (*(*l_wr_mas).pivots.add(l_slot as usize - 2)).wrapping_add(1);
            } else {
                (*l_mas).index = (*l_mas).min;
            }

            (*l_mas).offset = l_slot - 1;
        }

        if (*r_wr_mas).content.is_null() {
            if (*r_mas).last < (*r_wr_mas).r_max {
                (*r_mas).last = (*r_wr_mas).r_max;
            }
            (*r_mas).offset += 1;
        } else if (*r_mas).last == (*r_wr_mas).r_max
            && (*r_mas).last < (*r_mas).max
            && mas_slot_locked(r_mas, (*r_wr_mas).slots, (*r_mas).offset + 1).is_null()
        {
            (*r_mas).last = mas_safe_pivot(r_mas, (*r_wr_mas).pivots, (*r_mas).offset + 1, (*r_wr_mas).type_);
            (*r_mas).offset += 1;
        }
    }
}

/// `mas_state_walk()`.
unsafe fn mas_state_walk(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let entry = mas_start(mas);
        if mas_is_none(mas) {
            return null_mut();
        }

        if mas_is_ptr(mas) {
            return entry;
        }

        mtree_range_walk(mas)
    }
}

// ---------------------------------------------------------------------------
// C lines 3300-3800: lookup walk, new root, the store paths
// ---------------------------------------------------------------------------

/// `__mas_set_range()`.
#[inline(always)]
unsafe fn __mas_set_range(mas: *mut MaState, start: c_ulong, last: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        /* Ensure the range starts within the current slot */
        warn_on(mas_is_active(mas) && ((*mas).index > start || (*mas).last < start));
        (*mas).index = start;
        (*mas).last = last;
    }
}
/// `mas_set_range()`.
#[inline(always)]
unsafe fn mas_set_range(mas: *mut MaState, start: c_ulong, last: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        mas_reset(mas);
        __mas_set_range(mas, start, last);
    }
}
/// `mas_set()`.
#[inline(always)]
unsafe fn mas_set(mas: *mut MaState, index: c_ulong) {
    // SAFETY: caller contract.
    unsafe { mas_set_range(mas, index, index) }
}

/// `mtree_lookup_walk()`: internal quick lookup that does not keep the maple state up to date.
unsafe fn mtree_lookup_walk(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut next = (*mas).node;

        loop {
            let node = mte_to_node(next);
            let type_ = mte_node_type(next);
            let pivots = ma_pivots(node, type_);
            let end = mt_pivots[type_ as usize];
            let mut offset: u8 = 0;
            loop {
                if *pivots.add(offset as usize) >= (*mas).index {
                    break;
                }
                offset += 1;
                if offset >= end {
                    break;
                }
            }

            let slots = ma_slots(node, type_);
            next = mt_slot((*mas).tree, slots, offset);
            if ma_dead_node(node) {
                // dead_node:
                mas_reset(mas);
                return null_mut();
            }

            if ma_is_leaf(type_) {
                break;
            }
        }

        next
    }
}

/// `mas_new_root()`: create a new root node that only contains the entry passed in (index == 0, last == ULONG_MAX).
unsafe fn mas_new_root(mas: *mut MaState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        let root = mas_root_locked(mas);
        let type_ = maple_leaf_64;

        warn_on_once((*mas).index != 0 || (*mas).last != ULONG_MAX);

        if entry.is_null() {
            mt_set_height((*mas).tree, 0);
            rcu_assign(mt_root_p((*mas).tree), entry);
            (*mas).status = ma_start;
        } else {
            let node = mas_pop_node(mas);
            let pivots = ma_pivots(node, type_);
            let slots = ma_slots(node, type_);
            *n_parent(node) = mas_tree_parent(mas) as Pnode;
            (*mas).node = mt_mk_node(node, type_);
            (*mas).status = ma_active;
            rcu_assign(slots, entry);
            *pivots = (*mas).last;
            mt_set_height((*mas).tree, 1);
            rcu_assign(mt_root_p((*mas).tree), mte_mk_root((*mas).node));
        }

        // done:
        if xa_is_node(root) {
            mte_destroy_walk(root, (*mas).tree);
        }
    }
}

/// `mas_wr_spanning_store()`: create a subtree with the store operation completed and new nodes where necessary, then place the subtree in the
/// actual tree. `mas` is expected to point to the node which caused the store to span.
unsafe fn mas_wr_spanning_store(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mut mast: MapleSubtreeState = core::mem::zeroed();
        let mut b_node: MapleBigNode = core::mem::zeroed();

        /* Left and Right side of spanning store */
        let mut l_mas = ma_state_new(null_mut(), 0, 0);
        let mut r_mas = ma_state_new(null_mut(), 0, 0);
        let mut r_wr_mas = ma_wr_state_new(&raw mut r_mas, (*wr_mas).entry);
        let mut l_wr_mas = ma_wr_state_new(&raw mut l_mas, (*wr_mas).entry);

        let mas = (*wr_mas).mas;
        rust_mt_trace_ma_op(c"mas_wr_spanning_store".as_ptr(), mas);

        if (*mas).index == 0 && (*mas).last == ULONG_MAX {
            mas_new_root(mas, (*wr_mas).entry);
            return;
        }
        /* Node rebalancing may occur due to this store, so there may be three new entries per level plus a new root. */
        let height = mas_mt_height(mas) as u8;

        /* Set up right side. Need to get to the next offset after the spanning store to ensure it's not NULL and to combine both the next
         * node and the node with the start together. */
        r_mas = *mas;
        /* Avoid overflow, walk to next slot in the tree. */
        if r_mas.last.wrapping_add(1) != 0 {
            r_mas.last += 1;
        }

        r_mas.index = r_mas.last;
        mas_wr_walk_index(&raw mut r_wr_mas);
        r_mas.index = (*mas).last;
        r_mas.last = r_mas.index;

        /* Set up left side. */
        l_mas = *mas;
        mas_wr_walk_index(&raw mut l_wr_mas);

        if (*wr_mas).entry.is_null() {
            mas_extend_spanning_null(&raw mut l_wr_mas, &raw mut r_wr_mas);
            (*mas).offset = l_mas.offset;
            (*mas).index = l_mas.index;
            l_mas.last = r_mas.last;
            (*mas).last = l_mas.last;
        }

        /* expanding NULLs may make this cover the entire range */
        if l_mas.index == 0 && r_mas.last == ULONG_MAX {
            mas_set_range(mas, 0, ULONG_MAX);
            mas_new_root(mas, (*wr_mas).entry);
            return;
        }

        core::ptr::write_bytes(&raw mut b_node, 0, 1);
        /* Copy l_mas and store the value in b_node. */
        mas_store_b_node(&raw mut l_wr_mas, &raw mut b_node, l_mas.end);
        /* Copy r_mas into b_node if there is anything to copy. */
        if r_mas.max > r_mas.last {
            mas_mab_cp(&raw mut r_mas, r_mas.offset, r_mas.end, &raw mut b_node, b_node.b_end.wrapping_add(1));
        } else {
            b_node.b_end = b_node.b_end.wrapping_add(1);
        }

        /* Stop spanning searches by searching for just index. */
        l_mas.last = (*mas).index;
        l_mas.index = l_mas.last;

        mast.bn = &raw mut b_node;
        mast.orig_l = &raw mut l_mas;
        mast.orig_r = &raw mut r_mas;
        /* Combine l_mas and r_mas and split them up evenly again. */
        mas_spanning_rebalance(mas, &raw mut mast, height.wrapping_add(1));
    }
}

/// `mas_wr_node_store()`: attempt to store the value in a node (reuses the node when not in RCU mode, may allocate).
unsafe fn mas_wr_node_store(wr_mas: *mut MaWrState, new_end: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let mut offset_end = (*wr_mas).offset_end;
        let mut reuse: MapleNode = core::mem::zeroed();
        let node_pivots = mt_pivots[(*wr_mas).type_ as usize];
        let in_rcu = mt_in_rcu((*mas).tree);
        let height = mas_mt_height(mas) as u8;

        if (*mas).last == (*wr_mas).end_piv {
            offset_end += 1; /* don't copy this offset */
        }

        /* set up node. */
        let newnode: *mut MapleNode;
        if in_rcu {
            newnode = mas_pop_node(mas);
        } else {
            core::ptr::write_bytes(&raw mut reuse, 0, 1);
            newnode = &raw mut reuse;
        }

        *n_parent(newnode) = *n_parent(mas_mn(mas));
        let dst_pivots = ma_pivots(newnode, (*wr_mas).type_);
        let dst_slots = ma_slots(newnode, (*wr_mas).type_);
        /* Copy from start to insert point */
        core::ptr::copy_nonoverlapping((*wr_mas).pivots, dst_pivots, (*mas).offset as usize);
        core::ptr::copy_nonoverlapping((*wr_mas).slots, dst_slots, (*mas).offset as usize);

        /* Handle insert of new range starting after old range */
        if (*wr_mas).r_min < (*mas).index {
            rcu_assign(dst_slots.add((*mas).offset as usize), (*wr_mas).content);
            *dst_pivots.add((*mas).offset as usize) = (*mas).index - 1;
            (*mas).offset += 1;
        }

        /* Store the new entry and range end. */
        if (*mas).offset < node_pivots {
            *dst_pivots.add((*mas).offset as usize) = (*mas).last;
        }
        rcu_assign(dst_slots.add((*mas).offset as usize), (*wr_mas).entry);

        /* this range wrote to the end of the node or it overwrote the rest of the data */
        if offset_end <= (*mas).end {
            let dst_offset = (*mas).offset + 1;
            /* Copy to the end of node if necessary. */
            let copy_size = (*mas).end.wrapping_sub(offset_end).wrapping_add(1);
            core::ptr::copy_nonoverlapping((*wr_mas).slots.add(offset_end as usize), dst_slots.add(dst_offset as usize), copy_size as usize);
            core::ptr::copy_nonoverlapping(
                (*wr_mas).pivots.add(offset_end as usize),
                dst_pivots.add(dst_offset as usize),
                copy_size.wrapping_sub(1) as usize,
            );

            if new_end < node_pivots {
                *dst_pivots.add(new_end as usize) = (*mas).max;
            }
        }

        // done:
        mas_leaf_set_meta(newnode, maple_leaf_64, new_end);
        if in_rcu {
            let old_enode = (*mas).node;

            (*mas).node = mt_mk_node(newnode, (*wr_mas).type_);
            mas_replace_node(mas, old_enode, height);
        } else {
            core::ptr::copy_nonoverlapping(newnode, (*wr_mas).node, 1);
        }
        rust_mt_trace_ma_write(c"mas_wr_node_store".as_ptr(), mas, 0, (*wr_mas).entry);
        mas_update_gap(mas);
        (*mas).end = new_end;
    }
}

/// `mas_wr_slot_store()`: attempt to store a value in a slot.
unsafe fn mas_wr_slot_store(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let offset = (*mas).offset;
        let slots = (*wr_mas).slots;
        let mut gap = false;

        gap |= mt_slot_locked((*mas).tree, slots, offset).is_null();
        gap |= mt_slot_locked((*mas).tree, slots, offset + 1).is_null();

        if (*wr_mas).offset_end as c_int - offset as c_int == 1 {
            if (*mas).index == (*wr_mas).r_min {
                /* Overwriting the range and a part of the next one */
                rcu_assign(slots.add(offset as usize), (*wr_mas).entry);
                *(*wr_mas).pivots.add(offset as usize) = (*mas).last;
            } else {
                /* Overwriting a part of the range and the next one */
                rcu_assign(slots.add(offset as usize + 1), (*wr_mas).entry);
                *(*wr_mas).pivots.add(offset as usize) = (*mas).index - 1;
                (*mas).offset += 1; /* Keep mas accurate. */
            }
        } else {
            warn_on_once(mt_in_rcu((*mas).tree));
            /* Expand the range, only partially overwriting the previous and next ranges */
            gap |= mt_slot_locked((*mas).tree, slots, offset + 2).is_null();
            rcu_assign(slots.add(offset as usize + 1), (*wr_mas).entry);
            *(*wr_mas).pivots.add(offset as usize) = (*mas).index - 1;
            *(*wr_mas).pivots.add(offset as usize + 1) = (*mas).last;
            (*mas).offset += 1; /* Keep mas accurate. */
        }

        rust_mt_trace_ma_write(c"mas_wr_slot_store".as_ptr(), mas, 0, (*wr_mas).entry);
        /* Only update gap when the new entry is empty or there is an empty entry in the original two ranges. */
        if (*wr_mas).entry.is_null() || gap {
            mas_update_gap(mas);
        }
    }
}

unsafe fn mas_wr_extend_null(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        if (*(*wr_mas).slots.add((*wr_mas).offset_end as usize)).is_null() {
            /* If this one is null, the next and prev are not */
            (*mas).last = (*wr_mas).end_piv;
        } else {
            /* Check next slot(s) if we are overwriting the end */
            if (*mas).last == (*wr_mas).end_piv
                && (*mas).end != (*wr_mas).offset_end
                && (*(*wr_mas).slots.add((*wr_mas).offset_end as usize + 1)).is_null()
            {
                (*wr_mas).offset_end += 1;
                if (*wr_mas).offset_end == (*mas).end {
                    (*mas).last = (*mas).max;
                } else {
                    (*mas).last = *(*wr_mas).pivots.add((*wr_mas).offset_end as usize);
                }
                (*wr_mas).end_piv = (*mas).last;
            }
        }

        if (*wr_mas).content.is_null() {
            /* If this one is null, the next and prev are not */
            (*mas).index = (*wr_mas).r_min;
        } else {
            /* Check prev slot if we are overwriting the start */
            if (*mas).index == (*wr_mas).r_min && (*mas).offset != 0 && (*(*wr_mas).slots.add((*mas).offset as usize - 1)).is_null() {
                (*mas).offset -= 1;
                (*mas).index = mas_safe_min(mas, (*wr_mas).pivots, (*mas).offset);
                (*wr_mas).r_min = (*mas).index;
                (*wr_mas).r_max = *(*wr_mas).pivots.add((*mas).offset as usize);
            }
        }
    }
}

unsafe fn mas_wr_end_piv(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        while (*wr_mas).offset_end < (*(*wr_mas).mas).end && (*(*wr_mas).mas).last > *(*wr_mas).pivots.add((*wr_mas).offset_end as usize) {
            (*wr_mas).offset_end += 1;
        }

        if (*wr_mas).offset_end < (*(*wr_mas).mas).end {
            (*wr_mas).end_piv = *(*wr_mas).pivots.add((*wr_mas).offset_end as usize);
        } else {
            (*wr_mas).end_piv = (*(*wr_mas).mas).max;
        }
    }
}

unsafe fn mas_wr_new_end(wr_mas: *mut MaWrState) -> u8 {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let mut new_end: u8 = (*mas).end.wrapping_add(2);

        new_end = new_end.wrapping_sub(((*wr_mas).offset_end as c_int - (*mas).offset as c_int) as u8);
        if (*wr_mas).r_min == (*mas).index {
            new_end = new_end.wrapping_sub(1);
        }

        if (*wr_mas).end_piv == (*mas).last {
            new_end = new_end.wrapping_sub(1);
        }

        new_end
    }
}

/// `mas_wr_append()`: attempt to append (unsafe in RCU mode: readers may cache the end of the node).
unsafe fn mas_wr_append(wr_mas: *mut MaWrState, new_end: u8) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let end = (*mas).end;

        if new_end < mt_pivots[(*wr_mas).type_ as usize] {
            *(*wr_mas).pivots.add(new_end as usize) = *(*wr_mas).pivots.add(end as usize);
            ma_set_meta((*wr_mas).node, (*wr_mas).type_, 0, new_end);
        }

        let slots = (*wr_mas).slots;
        if new_end == end.wrapping_add(1) {
            if (*mas).last == (*wr_mas).r_max {
                /* Append to end of range */
                rcu_assign(slots.add(new_end as usize), (*wr_mas).entry);
                *(*wr_mas).pivots.add(end as usize) = (*mas).index - 1;
                (*mas).offset = new_end;
            } else {
                /* Append to start of range */
                rcu_assign(slots.add(new_end as usize), (*wr_mas).content);
                *(*wr_mas).pivots.add(end as usize) = (*mas).last;
                rcu_assign(slots.add(end as usize), (*wr_mas).entry);
            }
        } else {
            /* Append to the range without touching any boundaries. */
            rcu_assign(slots.add(new_end as usize), (*wr_mas).content);
            *(*wr_mas).pivots.add(end as usize + 1) = (*mas).last;
            rcu_assign(slots.add(end as usize + 1), (*wr_mas).entry);
            *(*wr_mas).pivots.add(end as usize) = (*mas).index - 1;
            (*mas).offset = end + 1;
        }

        if (*wr_mas).content.is_null() || (*wr_mas).entry.is_null() {
            mas_update_gap(mas);
        }

        (*mas).end = new_end;
        rust_mt_trace_ma_write(c"mas_wr_append".as_ptr(), mas, new_end as c_ulong, (*wr_mas).entry);
    }
}

/// `mas_wr_bnode()`: slow path for a modification (split and rebalance end up here).
unsafe fn mas_wr_bnode(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mut b_node: MapleBigNode = core::mem::zeroed();

        rust_mt_trace_ma_write(c"mas_wr_bnode".as_ptr(), (*wr_mas).mas, 0, (*wr_mas).entry);
        core::ptr::write_bytes(&raw mut b_node, 0, 1);
        mas_store_b_node(wr_mas, &raw mut b_node, (*wr_mas).offset_end);
        mas_commit_b_node(wr_mas, &raw mut b_node);
    }
}

/// `mas_wr_store_entry()`: internal call to store a value.
unsafe fn mas_wr_store_entry(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let new_end = mas_wr_new_end(wr_mas);

        match (*mas).store_type {
            wr_exact_fit => {
                rcu_assign((*wr_mas).slots.add((*mas).offset as usize), (*wr_mas).entry);
                if (!(*wr_mas).entry.is_null()) ^ (!(*wr_mas).content.is_null()) {
                    mas_update_gap(mas);
                }
            }
            wr_append => mas_wr_append(wr_mas, new_end),
            wr_slot_store => mas_wr_slot_store(wr_mas),
            wr_node_store => mas_wr_node_store(wr_mas, new_end),
            wr_spanning_store => mas_wr_spanning_store(wr_mas),
            wr_split_store | wr_rebalance => mas_wr_bnode(wr_mas),
            wr_new_root => mas_new_root(mas, (*wr_mas).entry),
            wr_store_root => mas_store_root(mas, (*wr_mas).entry),
            wr_invalid => bug_on(true),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// C lines 3785-4260: preallocation set-up, store type, insert, cyclic allocation, previous-slot walk
// ---------------------------------------------------------------------------

extern "C" {
    /// `GFP_NOWAIT` / `GFP_KERNEL` of this configuration (the glue passes the real values).
    static rust_gfp_nowait: Gfp;
}

/// `xa_err()`.
#[inline(always)]
fn xa_err(entry: *const c_void) -> c_int {
    if xa_is_internal(entry) && (entry as usize) >= (-4096isize) as usize {
        return ((entry as isize) >> 2) as c_int;
    }
    0
}

unsafe fn mas_wr_prealloc_setup(wr_mas: *mut MaWrState) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let mut reset = false;

        'decide: {
            if !mas_is_active(mas) {
                if mas_is_start(mas) {
                    break 'decide; // set_content
                }

                if mas_is_paused(mas) || mas_is_none(mas) || mas_is_overflow(mas) || mas_is_underflow(mas) {
                    reset = true;
                    break 'decide;
                }
            }

            /* A less strict version of mas_is_span_wr() where we allow spanning writes within this node. This is to stop partial walks in
             * mas_prealloc() from being reset. */
            if (*mas).last > (*mas).max {
                reset = true;
                break 'decide;
            }

            if !(*wr_mas).entry.is_null() {
                break 'decide;
            }

            if mte_is_leaf((*mas).node) && (*mas).last == (*mas).max {
                reset = true;
            }
        }

        if reset {
            mas_reset(mas);
        }
        // set_content:
        (*wr_mas).content = mas_start(mas);
    }
}

/// `mas_prealloc_calc()`: calculate the number of nodes needed for a given store operation.
unsafe fn mas_prealloc_calc(wr_mas: *mut MaWrState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;
        let height = mas_mt_height(mas) as u8;
        let mut ret: c_int = height as c_int * 3 + 1;
        let delta: u8 = height.wrapping_sub((*wr_mas).vacant_height);

        match (*mas).store_type {
            wr_exact_fit | wr_append | wr_slot_store => ret = 0,
            wr_spanning_store => {
                if (*wr_mas).sufficient_height < (*wr_mas).vacant_height {
                    ret = (height as c_int - (*wr_mas).sufficient_height as c_int) * 3 + 1;
                } else {
                    ret = delta as c_int * 3 + 1;
                }
            }
            wr_split_store => ret = delta as c_int * 2 + 1,
            wr_rebalance => {
                if (*wr_mas).sufficient_height < (*wr_mas).vacant_height {
                    ret = (height as c_int - (*wr_mas).sufficient_height as c_int) * 2 + 1;
                } else {
                    ret = delta as c_int * 2 + 1;
                }
            }
            wr_node_store => ret = if mt_in_rcu((*mas).tree) { 1 } else { 0 },
            wr_new_root => ret = 1,
            wr_store_root => {
                if (*mas).last != 0 || (*mas).index != 0 {
                    ret = 1;
                } else if (entry as usize) & 3 == 2 {
                    ret = 1;
                } else {
                    ret = 0;
                }
            }
            wr_invalid => {
                warn_on_once(true);
            }
            _ => {}
        }

        (*mas).node_request = ret as c_long as c_ulong;
    }
}

/// `mas_wr_store_type()`: determine the store type for a given store operation.
unsafe fn mas_wr_store_type(wr_mas: *mut MaWrState) -> u32 {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        if mas_is_none(mas) || mas_is_ptr(mas) {
            return wr_store_root;
        }

        if !mas_wr_walk(wr_mas) {
            return wr_spanning_store;
        }

        /* At this point, we are at the leaf node that needs to be altered. */
        mas_wr_end_piv(wr_mas);
        if (*wr_mas).entry.is_null() {
            mas_wr_extend_null(wr_mas);
        }

        if (*wr_mas).r_min == (*mas).index && (*wr_mas).r_max == (*mas).last {
            return wr_exact_fit;
        }

        if (*mas).index == 0 && (*mas).last == ULONG_MAX {
            return wr_new_root;
        }

        let new_end = mas_wr_new_end(wr_mas);
        /* Potential spanning rebalance collapsing a node */
        if new_end < mt_min_slots[(*wr_mas).type_ as usize] {
            if !mte_is_root((*mas).node) {
                return wr_rebalance;
            }
            return wr_node_store;
        }

        if new_end >= mt_slots[(*wr_mas).type_ as usize] {
            return wr_split_store;
        }

        if !mt_in_rcu((*mas).tree) && (*mas).offset == (*mas).end {
            return wr_append;
        }

        if new_end == (*mas).end && (!mt_in_rcu((*mas).tree) || ((*wr_mas).offset_end as c_int - (*mas).offset as c_int) == 1) {
            return wr_slot_store;
        }

        wr_node_store
    }
}

/// `mas_wr_preallocate()`: preallocate enough nodes for a store operation.
unsafe fn mas_wr_preallocate(wr_mas: *mut MaWrState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        let mas = (*wr_mas).mas;

        mas_wr_prealloc_setup(wr_mas);
        (*mas).store_type = mas_wr_store_type(wr_mas);
        mas_prealloc_calc(wr_mas, entry);
        if (*mas).node_request == 0 {
            return;
        }

        mas_alloc_nodes(mas, rust_gfp_nowait);
    }
}

/// `mas_insert()`: internal call to insert a value. Returns NULL or the contents that already exist at the requested index.
unsafe fn mas_insert(mas: *mut MaState, entry: *mut c_void) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut wr_mas = ma_wr_state_new(mas, entry);
        let wr = &raw mut wr_mas;

        'exists: {
            wr_mas.content = mas_start(mas);
            if !wr_mas.content.is_null() {
                break 'exists;
            }

            mas_wr_preallocate(wr, entry);
            if mas_is_err(mas) {
                return null_mut();
            }

            /* spanning writes always overwrite something */
            if (*mas).store_type == wr_spanning_store {
                break 'exists;
            }

            /* At this point, we are at the leaf node that needs to be altered. */
            if (*mas).store_type != wr_new_root && (*mas).store_type != wr_store_root {
                wr_mas.offset_end = (*mas).offset;
                wr_mas.end_piv = wr_mas.r_max;

                if !wr_mas.content.is_null() || (*mas).last > wr_mas.r_max {
                    break 'exists;
                }
            }

            mas_wr_store_entry(wr);
            return wr_mas.content;
        }

        // exists:
        mas_set_err(mas, -(EEXIST as c_long));
        wr_mas.content
    }
}

/// `mas_alloc_cyclic()`: internal call to find somewhere to store an entry.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_alloc_cyclic(
    mas: *mut MaState,
    startp: *mut c_ulong,
    entry: *mut c_void,
    range_lo: c_ulong,
    range_hi: c_ulong,
    next: *mut c_ulong,
    gfp: Gfp,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let min = range_lo;
        let mut ret: c_int;

        let range_lo = core::cmp::max(min, *next);
        ret = rust_mas_empty_area(mas, range_lo, range_hi, 1);
        if *mt_flags((*mas).tree) & MT_FLAGS_ALLOC_WRAPPED != 0 && ret == 0 {
            *mt_flags((*mas).tree) &= !MT_FLAGS_ALLOC_WRAPPED;
            ret = 1;
        }
        if ret < 0 && range_lo > min {
            mas_reset(mas);
            ret = rust_mas_empty_area(mas, min, range_hi, 1);
            if ret == 0 {
                ret = 1;
            }
        }
        if ret < 0 {
            return ret;
        }

        loop {
            mas_insert(mas, entry);
            if !rust_mas_nomem(mas, gfp) {
                break;
            }
        }
        if mas_is_err(mas) {
            return xa_err((*mas).node);
        }

        *startp = (*mas).index;
        *next = (*startp).wrapping_add(1);
        if *next == 0 {
            *mt_flags((*mas).tree) |= MT_FLAGS_ALLOC_WRAPPED;
        }

        rust_mas_destroy(mas);
        ret
    }
}

unsafe fn mas_rewalk(mas: *mut MaState, index: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        loop {
            // retry:
            mas_set(mas, index);
            mas_state_walk(mas);
            if mas_is_start(mas) {
                continue;
            }
            break;
        }
    }
}

unsafe fn mas_rewalk_if_dead(mas: *mut MaState, node: *mut MapleNode, index: c_ulong) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if ma_dead_node(node) {
            mas_rewalk(mas, index);
            return true;
        }
        false
    }
}

/// `mas_prev_node()`: find the previous non-null entry at the same level in the tree. Returns 1 if the node is dead, 0 otherwise.
unsafe fn mas_prev_node(mas: *mut MaState, min: c_ulong) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut node = mas_mn(mas);
        'no_entry: {
            if (*mas).min == 0 {
                break 'no_entry;
            }

            let max = (*mas).min - 1;
            if max < min {
                break 'no_entry;
            }

            let mut level: c_int = 0;
            let mut offset: c_int;
            loop {
                if ma_is_root(node) {
                    break 'no_entry;
                }

                /* Walk up. */
                if mas_ascend(mas) != 0 {
                    return 1;
                }
                offset = (*mas).offset as c_int;
                level += 1;
                node = mas_mn(mas);
                if offset != 0 {
                    break;
                }
            }

            offset -= 1;
            let mut mt = mte_node_type((*mas).node);
            while level > 1 {
                level -= 1;
                let slots = ma_slots(node, mt);
                (*mas).node = mas_slot(mas, slots, offset as u8);
                if ma_dead_node(node) {
                    return 1;
                }

                mt = mte_node_type((*mas).node);
                node = mas_mn(mas);
                let pivots = ma_pivots(node, mt);
                offset = ma_data_end(node, mt, pivots, max) as c_int;
                if ma_dead_node(node) {
                    return 1;
                }
            }

            let slots = ma_slots(node, mt);
            (*mas).node = mas_slot(mas, slots, offset as u8);
            let pivots = ma_pivots(node, mt);
            if ma_dead_node(node) {
                return 1;
            }

            if offset != 0 {
                (*mas).min = (*pivots.add(offset as usize - 1)).wrapping_add(1);
            }
            (*mas).max = max;
            (*mas).offset = mas_data_end(mas);
            if mte_dead_node((*mas).node) {
                return 1;
            }

            (*mas).end = (*mas).offset;
            return 0;
        }

        // no_entry:
        if ma_dead_node(node) {
            return 1;
        }

        (*mas).status = ma_underflow;
        0
    }
}

/// `mas_prev_slot()`: get the entry in the previous slot (possibly NULL when `empty`).
unsafe fn mas_prev_slot(mas: *mut MaState, min: c_ulong, empty: bool) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let save_point = (*mas).index;

        'retry: loop {
            let mut node = mas_mn(mas);
            let mut type_ = mte_node_type((*mas).node);
            let mut pivots = ma_pivots(node, type_);
            if mas_rewalk_if_dead(mas, node, save_point) {
                continue 'retry;
            }

            if (*mas).min <= min {
                let pivot = mas_safe_min(mas, pivots, (*mas).offset);

                if mas_rewalk_if_dead(mas, node, save_point) {
                    continue 'retry;
                }

                if pivot <= min {
                    (*mas).status = ma_underflow;
                    return null_mut();
                }
            }

            loop {
                // again:
                if (*mas).offset != 0 {
                    (*mas).offset -= 1;
                    (*mas).last = (*mas).index - 1;
                    (*mas).index = mas_safe_min(mas, pivots, (*mas).offset);
                } else {
                    if (*mas).index <= min {
                        (*mas).status = ma_underflow;
                        return null_mut();
                    }

                    if mas_prev_node(mas, min) != 0 {
                        mas_rewalk(mas, save_point);
                        continue 'retry;
                    }

                    if warn_on_once(mas_is_underflow(mas)) {
                        return null_mut();
                    }

                    (*mas).last = (*mas).max;
                    node = mas_mn(mas);
                    type_ = mte_node_type((*mas).node);
                    pivots = ma_pivots(node, type_);
                    (*mas).index = (*pivots.add((*mas).offset as usize - 1)).wrapping_add(1);
                }

                let slots = ma_slots(node, type_);
                let entry = mas_slot(mas, slots, (*mas).offset);
                if mas_rewalk_if_dead(mas, node, save_point) {
                    continue 'retry;
                }

                if !entry.is_null() {
                    return entry;
                }

                if !empty {
                    if (*mas).index <= min {
                        (*mas).status = ma_underflow;
                        return null_mut();
                    }

                    continue; // again
                }

                return entry;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// C lines 4240-4720: next-node walk, allocation walks, mas_walk
// ---------------------------------------------------------------------------

/// `mas_next_node()`: get the next node at the same level in the tree. Returns 1 on a dead node, 0 otherwise.
unsafe fn mas_next_node(mas: *mut MaState, node: *mut MapleNode, max: c_ulong) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut node = node;
        'overflow: {
            if (*mas).max >= max {
                break 'overflow;
            }

            let min = (*mas).max.wrapping_add(1);
            let mut level: c_int = 0;
            let mut mt: u32;
            let mut pivots: *mut c_ulong;
            loop {
                if ma_is_root(node) {
                    break 'overflow;
                }

                /* Walk up. */
                if mas_ascend(mas) != 0 {
                    return 1;
                }

                level += 1;
                node = mas_mn(mas);
                mt = mte_node_type((*mas).node);
                pivots = ma_pivots(node, mt);
                let node_end = ma_data_end(node, mt, pivots, (*mas).max);
                if ma_dead_node(node) {
                    return 1;
                }

                if (*mas).offset != node_end {
                    break;
                }
            }

            let mut slots = ma_slots(node, mt);
            (*mas).offset += 1;
            let mut enode = mas_slot(mas, slots, (*mas).offset);
            if ma_dead_node(node) {
                return 1;
            }

            if level > 1 {
                (*mas).offset = 0;
            }

            while level > 1 {
                level -= 1;
                (*mas).node = enode;
                node = mas_mn(mas);
                mt = mte_node_type((*mas).node);
                slots = ma_slots(node, mt);
                enode = mas_slot(mas, slots, 0);
                if ma_dead_node(node) {
                    return 1;
                }
            }

            if (*mas).offset == 0 {
                pivots = ma_pivots(node, mt);
            }

            (*mas).max = mas_safe_pivot(mas, pivots, (*mas).offset, mt);
            let tmp = mte_to_node(enode);
            mt = mte_node_type(enode);
            pivots = ma_pivots(tmp, mt);
            (*mas).end = ma_data_end(tmp, mt, pivots, (*mas).max);
            if ma_dead_node(node) {
                return 1;
            }

            (*mas).node = enode;
            (*mas).min = min;
            return 0;
        }

        // overflow:
        if ma_dead_node(node) {
            return 1;
        }

        (*mas).status = ma_overflow;
        0
    }
}

/// `mas_next_slot()`: get the entry in the next slot (possibly NULL when `empty`).
unsafe fn mas_next_slot(mas: *mut MaState, max: c_ulong, empty: bool) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let save_point = (*mas).last;

        'retry: loop {
            let mut node = mas_mn(mas);
            let mut type_ = mte_node_type((*mas).node);
            let mut pivots = ma_pivots(node, type_);
            if mas_rewalk_if_dead(mas, node, save_point) {
                continue 'retry;
            }

            if (*mas).max >= max {
                let pivot = if (*mas).offset < (*mas).end { *pivots.add((*mas).offset as usize) } else { (*mas).max };

                if mas_rewalk_if_dead(mas, node, save_point) {
                    continue 'retry;
                }

                if pivot >= max {
                    /* Was at the limit, next will extend beyond */
                    (*mas).status = ma_overflow;
                    return null_mut();
                }
            }

            let mut first = true;
            loop {
                if first && (*mas).offset < (*mas).end {
                    (*mas).index = (*pivots.add((*mas).offset as usize)).wrapping_add(1);
                    first = false;
                    // again:
                    (*mas).offset += 1;
                    if (*mas).offset < (*mas).end {
                        (*mas).last = *pivots.add((*mas).offset as usize);
                    } else {
                        (*mas).last = (*mas).max;
                    }
                } else if first {
                    first = false;
                    if (*mas).last >= max {
                        (*mas).status = ma_overflow;
                        return null_mut();
                    }

                    if mas_next_node(mas, node, max) != 0 {
                        mas_rewalk(mas, save_point);
                        continue 'retry;
                    }

                    if warn_on_once(mas_is_overflow(mas)) {
                        return null_mut();
                    }

                    (*mas).offset = 0;
                    (*mas).index = (*mas).min;
                    node = mas_mn(mas);
                    type_ = mte_node_type((*mas).node);
                    pivots = ma_pivots(node, type_);
                    (*mas).last = *pivots;
                } else {
                    // again: (reached from the `!empty` path below)
                    (*mas).offset += 1;
                    if (*mas).offset < (*mas).end {
                        (*mas).last = *pivots.add((*mas).offset as usize);
                    } else {
                        (*mas).last = (*mas).max;
                    }
                }

                let slots = ma_slots(node, type_);
                let entry = mt_slot((*mas).tree, slots, (*mas).offset);
                if mas_rewalk_if_dead(mas, node, save_point) {
                    continue 'retry;
                }

                if !entry.is_null() {
                    return entry;
                }

                if !empty {
                    if (*mas).last >= max {
                        (*mas).status = ma_overflow;
                        return null_mut();
                    }

                    (*mas).index = (*mas).last.wrapping_add(1);
                    continue; // goto again
                }

                return entry;
            }
        }
    }
}

/// `mas_rev_awalk()`: reverse allocation walk. Find the highest gap address of a given size in a given node and descend.
unsafe fn mas_rev_awalk(mas: *mut MaState, size: c_ulong, gap_min: *mut c_ulong, gap_max: *mut c_ulong) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let type_ = mte_node_type((*mas).node);
        let node = mas_mn(mas);
        let mut gap: c_ulong = 0;

        if mas_is_err(mas) {
            return true;
        }

        if ma_is_dense(type_) {
            /* dense nodes. */
            (*mas).offset = (*mas).index.wrapping_sub((*mas).min) as u8;
            return true;
        }

        let pivots = ma_pivots(node, type_);
        let slots = ma_slots(node, type_);
        let gaps = ma_gaps(node, type_);
        let mut offset = (*mas).offset;
        let mut min = mas_safe_min(mas, pivots, offset);
        /* Skip out of bounds. */
        while (*mas).last < min {
            offset = offset.wrapping_sub(1);
            min = mas_safe_min(mas, pivots, offset);
        }

        let mut max = mas_safe_pivot(mas, pivots, offset, type_);
        'ascend: {
            while (*mas).index <= max {
                gap = 0;
                if !gaps.is_null() {
                    gap = *gaps.add(offset as usize);
                } else if mas_slot(mas, slots, offset).is_null() {
                    gap = max.wrapping_sub(min).wrapping_add(1);
                }

                if gap != 0 {
                    if size <= gap && size <= (*mas).last.wrapping_sub(min).wrapping_add(1) {
                        break;
                    }

                    if gaps.is_null() {
                        /* Skip the next slot, it cannot be a gap. */
                        if offset < 2 {
                            break 'ascend;
                        }

                        offset -= 2;
                        max = *pivots.add(offset as usize);
                        min = mas_safe_min(mas, pivots, offset);
                        continue;
                    }
                }

                if offset == 0 {
                    break 'ascend;
                }

                offset -= 1;
                max = min.wrapping_sub(1);
                min = mas_safe_min(mas, pivots, offset);
            }

            if (*mas).index > max || size.wrapping_sub(1) > max.wrapping_sub((*mas).index) {
                // no_space:
                mas_set_err(mas, -(EBUSY as c_long));
                return false;
            }

            if ma_is_leaf(type_) {
                (*mas).offset = offset;
                *gap_min = min;
                *gap_max = min.wrapping_add(gap).wrapping_sub(1);
                return true;
            }

            /* descend, only happens under lock. */
            (*mas).node = mas_slot(mas, slots, offset);
            (*mas).min = min;
            (*mas).max = max;
            (*mas).offset = mas_data_end(mas);
            return false;
        }

        // ascend:
        if !mte_is_root((*mas).node) {
            return false;
        }

        // no_space:
        mas_set_err(mas, -(EBUSY as c_long));
        false
    }
}

unsafe fn mas_anode_descend(mas: *mut MaState, size: c_ulong) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let type_ = mte_node_type((*mas).node);
        let mut gap: c_ulong = 0;
        let mut found = false;

        if ma_is_dense(type_) {
            (*mas).offset = (*mas).index.wrapping_sub((*mas).min) as u8;
            return true;
        }

        let node = mas_mn(mas);
        let pivots = ma_pivots(node, type_);
        let slots = ma_slots(node, type_);
        let gaps = ma_gaps(node, type_);
        let mut offset = (*mas).offset;
        let mut min = mas_safe_min(mas, pivots, offset);
        let data_end = ma_data_end(node, type_, pivots, (*mas).max);
        'outer: while offset <= data_end {
            let pivot = mas_safe_pivot(mas, pivots, offset, type_);

            'next_slot: {
                /* Not within lower bounds */
                if (*mas).index > pivot {
                    break 'next_slot;
                }

                if !gaps.is_null() {
                    gap = *gaps.add(offset as usize);
                } else if mas_slot(mas, slots, offset).is_null() {
                    gap = core::cmp::min(pivot, (*mas).last).wrapping_sub(core::cmp::max((*mas).index, min)).wrapping_add(1);
                } else {
                    break 'next_slot;
                }

                if gap >= size {
                    if ma_is_leaf(type_) {
                        found = true;
                        break 'outer;
                    }

                    (*mas).node = mas_slot(mas, slots, offset);
                    (*mas).min = min;
                    (*mas).max = pivot;
                    offset = 0;
                    break 'outer;
                }
            }
            // next_slot:
            min = pivot.wrapping_add(1);
            if (*mas).last <= pivot {
                mas_set_err(mas, -(EBUSY as c_long));
                return true;
            }
            offset += 1;
        }

        (*mas).offset = offset;
        found
    }
}

/// `mas_walk()`: search for `mas->index` in the tree.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_walk(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        if !mas_is_active(mas) && !mas_is_start(mas) {
            (*mas).status = ma_start;
        }
        loop {
            // retry:
            let entry = mas_state_walk(mas);
            if mas_is_start(mas) {
                continue;
            } else if mas_is_none(mas) {
                (*mas).index = 0;
                (*mas).last = ULONG_MAX;
            } else if mas_is_ptr(mas) {
                if (*mas).index == 0 {
                    (*mas).last = 0;
                    return entry;
                }

                (*mas).index = 1;
                (*mas).last = ULONG_MAX;
                (*mas).status = ma_none;
                return null_mut();
            }

            return entry;
        }
    }
}

unsafe fn mas_rewind_node(mas: *mut MaState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let mut slot: u8;

        loop {
            if mte_is_root((*mas).node) {
                slot = (*mas).offset;
                if slot == 0 {
                    return false;
                }
            } else {
                mas_ascend(mas);
                slot = (*mas).offset;
            }
            if slot != 0 {
                break;
            }
        }

        slot -= 1;
        (*mas).offset = slot;
        true
    }
}

/// `mas_skip_node()`: skip over a node. Returns true if there is another node.
unsafe fn mas_skip_node(mas: *mut MaState) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if mas_is_err(mas) {
            return false;
        }

        loop {
            if mte_is_root((*mas).node) {
                if (*mas).offset >= mas_data_end(mas) {
                    mas_set_err(mas, -(EBUSY as c_long));
                    return false;
                }
            } else {
                mas_ascend(mas);
            }
            if (*mas).offset < mas_data_end(mas) {
                break;
            }
        }

        (*mas).offset += 1;
        true
    }
}

/// `mas_awalk()`: allocation walk. Search from low address to high for a gap of `size`.
unsafe fn mas_awalk(mas: *mut MaState, size: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        let mut last: Enode = null_mut();

        /* There are 4 options: go to child (descend), go back to parent (ascend), no gap found (return, error == -EBUSY), found the gap. */
        while !mas_is_err(mas) && !mas_anode_descend(mas, size) {
            if last == (*mas).node {
                mas_skip_node(mas);
            } else {
                last = (*mas).node;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// C lines 4690-5190: gap search, destroy / free walks, store entry points
// ---------------------------------------------------------------------------

// The "dead node" view of a maple_node (the arrays are reused once a node is dead).
#[inline(always)]
unsafe fn n_piv_parent(n: *mut MapleNode) -> *mut Enode {
    // SAFETY: offset 24.
    unsafe { nb(n, 24).cast() }
}
#[inline(always)]
unsafe fn n_parent_slot(n: *mut MapleNode) -> *mut u8 {
    // SAFETY: offset 32.
    unsafe { nb(n, 32) }
}
#[inline(always)]
unsafe fn n_type(n: *mut MapleNode) -> *mut u32 {
    // SAFETY: offset 36.
    unsafe { nb(n, 36).cast() }
}
#[inline(always)]
unsafe fn n_slot_len(n: *mut MapleNode) -> *mut u8 {
    // SAFETY: offset 40.
    unsafe { nb(n, 40) }
}

/// `mas_sparse_area()`: return the upper or lower limit when searching for a gap in an empty tree.
unsafe fn mas_sparse_area(mas: *mut MaState, min: c_ulong, max: c_ulong, size: c_ulong, fwd: bool) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut min = min;
        if !mas_is_none(mas) && min == 0 {
            min += 1;
            /* At this time, min is increased, we need to recheck whether the size is satisfied. */
            if min > max || max.wrapping_sub(min).wrapping_add(1) < size {
                return -EBUSY;
            }
        }
        /* mas_is_ptr */

        if fwd {
            (*mas).index = min;
            (*mas).last = min.wrapping_add(size).wrapping_sub(1);
        } else {
            (*mas).last = max;
            (*mas).index = max.wrapping_sub(size).wrapping_add(1);
        }
        0
    }
}

/// `mas_empty_area()`: get the lowest address within the range that is sufficient for the size requested.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_empty_area(mas: *mut MaState, min: c_ulong, max: c_ulong, size: c_ulong) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut min = min;

        if min > max {
            return -EINVAL;
        }

        if size == 0 || max.wrapping_sub(min) < size.wrapping_sub(1) {
            return -EINVAL;
        }

        if mas_is_start(mas) {
            mas_start(mas);
        } else if (*mas).offset >= 2 {
            (*mas).offset -= 2;
        } else if !mas_skip_node(mas) {
            return -EBUSY;
        }

        /* Empty set */
        if mas_is_none(mas) || mas_is_ptr(mas) {
            return mas_sparse_area(mas, min, max, size, true);
        }

        /* The start of the window can only be within these values */
        (*mas).index = min;
        (*mas).last = max;
        mas_awalk(mas, size);

        if mas_is_err(mas) {
            return xa_err((*mas).node);
        }

        let offset = (*mas).offset;
        let node = mas_mn(mas);
        let mt = mte_node_type((*mas).node);
        let pivots = ma_pivots(node, mt);
        min = mas_safe_min(mas, pivots, offset);
        if (*mas).index < min {
            (*mas).index = min;
        }
        (*mas).last = (*mas).index.wrapping_add(size).wrapping_sub(1);
        (*mas).end = ma_data_end(node, mt, pivots, (*mas).max);
        0
    }
}

/// `mas_empty_area_rev()`: get the highest address within the range that is sufficient for the size requested.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_empty_area_rev(mas: *mut MaState, min: c_ulong, max: c_ulong, size: c_ulong) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut min = min;
        let mut max = max;
        let mut last = (*mas).node;

        if min > max {
            return -EINVAL;
        }

        if size == 0 || max.wrapping_sub(min) < size.wrapping_sub(1) {
            return -EINVAL;
        }

        if mas_is_start(mas) {
            mas_start(mas);
        } else if (*mas).offset < 2 && !mas_rewind_node(mas) {
            return -EBUSY;
        }

        if mas_is_none(mas) || mas_is_ptr(mas) {
            return mas_sparse_area(mas, min, max, size, false);
        } else if (*mas).offset >= 2 {
            (*mas).offset -= 2;
        } else {
            (*mas).offset = mas_data_end(mas);
        }

        /* The start of the window can only be within these values. */
        (*mas).index = min;
        (*mas).last = max;

        while !mas_rev_awalk(mas, size, &raw mut min, &raw mut max) {
            if last == (*mas).node {
                if !mas_rewind_node(mas) {
                    return -EBUSY;
                }
            } else {
                last = (*mas).node;
            }
        }

        if mas_is_err(mas) {
            return xa_err((*mas).node);
        }

        if (*mas).offset as usize == MAPLE_NODE_SLOTS {
            return -EBUSY;
        }

        /* Trim the upper limit to the max. */
        if max < (*mas).last {
            (*mas).last = max;
        }

        (*mas).index = (*mas).last.wrapping_sub(size).wrapping_add(1);
        (*mas).end = mas_data_end(mas);
        0
    }
}

/// `mte_dead_leaves()`: mark all leaves of a node as dead (write lock held). Returns the number of leaves marked.
unsafe fn mte_dead_leaves(enode: Enode, mt: *mut MapleTree, slots: *mut *mut c_void) -> u8 {
    // SAFETY: caller contract.
    unsafe {
        let mut offset: c_int = 0;

        while offset < mt_slots[mte_node_type(enode) as usize] as c_int {
            let entry = mt_slot(mt, slots, offset as u8);
            let type_ = mte_node_type(entry);
            let node = mte_to_node(entry);
            /* Use both node and type to catch LE & BE metadata */
            if node.is_null() || type_ == 0 {
                break;
            }

            mte_set_node_dead(entry);
            *n_type(node) = type_;
            rcu_assign(slots.add(offset as usize), node.cast());
            offset += 1;
        }

        offset as u8
    }
}

/// `mte_dead_walk()`: walk down a dead tree to just before the leaves (RCU callback context only).
unsafe fn mte_dead_walk(enode: *mut Enode, offset: u8) -> *mut *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut offset = offset;
        let mut next = mte_to_node(*enode);
        let mut slots: *mut *mut c_void;

        loop {
            *enode = next.cast();
            let node = mte_to_node(*enode);
            slots = ma_slots(node, *n_type(node));
            next = (*slots.add(offset as usize)).cast();
            offset = 0;
            if ma_is_leaf(*n_type(next)) {
                break;
            }
        }

        slots
    }
}

/// `mt_free_walk()`: walk and free a tree in the RCU callback context.
///
/// # Safety
/// `node` is the node whose `rcu` head the callback was given.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_free_walk(node: *mut MapleNode) {
    // SAFETY: caller contract.
    unsafe {
        let mut node = node;

        'free_leaf: {
            if ma_is_leaf(*n_type(node)) {
                break 'free_leaf;
            }

            let start = node;
            let mut enode = mt_mk_node(node, *n_type(node));
            let mut slots = mte_dead_walk(&raw mut enode, 0);
            node = mte_to_node(enode);
            loop {
                rust_mt_free_bulk(*n_slot_len(node) as usize, slots);
                let offset = (*n_parent_slot(node)).wrapping_add(1);
                enode = *n_piv_parent(node);
                if mte_to_node(enode) == node {
                    break 'free_leaf;
                }

                let type_ = mte_node_type(enode);
                slots = ma_slots(mte_to_node(enode), type_);
                if (offset as usize) < mt_slots[type_ as usize] as usize && !(*slots.add(offset as usize)).is_null() {
                    slots = mte_dead_walk(&raw mut enode, offset);
                }
                node = mte_to_node(enode);
                if !(node != start || *n_slot_len(node) < offset) {
                    break;
                }
            }

            slots = ma_slots(node, *n_type(node));
            rust_mt_free_bulk(*n_slot_len(node) as usize, slots);
        }

        // free_leaf:
        rust_mt_kfree(node.cast());
    }
}

/// `mte_destroy_descend()`.
unsafe fn mte_destroy_descend(enode: *mut Enode, mt: *mut MapleTree, prev: Enode, offset: u8) -> *mut *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut prev = prev;
        let mut offset = offset;
        let mut next = *enode;
        let mut slots: *mut *mut c_void;
        let mut next_offset: u8 = 0;

        loop {
            *enode = next;
            let node = mte_to_node(*enode);
            let type_ = mte_node_type(*enode);
            slots = ma_slots(node, type_);
            next = mt_slot_locked(mt, slots, next_offset);
            if mte_dead_node(next) {
                next_offset += 1;
                next = mt_slot_locked(mt, slots, next_offset);
            }

            mte_set_node_dead(*enode);
            *n_type(node) = type_;
            *n_piv_parent(node) = prev;
            *n_parent_slot(node) = offset;
            offset = next_offset;
            next_offset = 0;
            prev = *enode;
            if mte_is_leaf(next) {
                break;
            }
        }

        slots
    }
}

/// `mt_destroy_walk()`.
unsafe fn mt_destroy_walk(enode: Enode, mt: *mut MapleTree, free: bool) {
    // SAFETY: caller contract.
    unsafe {
        let mut enode = enode;
        let mut node = mte_to_node(enode);

        'free_leaf: {
            if mte_is_leaf(enode) {
                mte_set_node_dead(enode);
                *n_type(node) = mte_node_type(enode);
                break 'free_leaf;
            }

            let start = enode;
            let mut slots = mte_destroy_descend(&raw mut enode, mt, start, 0);
            node = mte_to_node(enode); // Updated in the above call.
            loop {
                *n_slot_len(node) = mte_dead_leaves(enode, mt, slots);
                if free {
                    rust_mt_free_bulk(*n_slot_len(node) as usize, slots);
                }
                let offset = (*n_parent_slot(node)).wrapping_add(1);
                enode = *n_piv_parent(node);
                if mte_to_node(enode) == node {
                    break 'free_leaf;
                }

                let type_ = mte_node_type(enode);
                slots = ma_slots(mte_to_node(enode), type_);
                if (offset as usize) < mt_slots[type_ as usize] as usize {
                    let tmp = mt_slot_locked(mt, slots, offset);
                    if mte_node_type(tmp) != 0 && !mte_to_node(tmp).is_null() {
                        let parent = enode;
                        enode = tmp;
                        slots = mte_destroy_descend(&raw mut enode, mt, parent, offset);
                    }
                }
                // next:
                node = mte_to_node(enode);
                if start == enode {
                    break;
                }
            }

            node = mte_to_node(enode);
            *n_slot_len(node) = mte_dead_leaves(enode, mt, slots);
            if free {
                rust_mt_free_bulk(*n_slot_len(node) as usize, slots);
            }
        }

        // free_leaf:
        if free {
            rust_mt_kfree(node.cast());
        } else {
            mt_clear_meta(mt, node, *n_type(node));
        }
    }
}

/// `mte_destroy_walk()`: free a tree or sub-tree (write lock held).
unsafe fn mte_destroy_walk(enode: Enode, mt: *mut MapleTree) {
    // SAFETY: caller contract.
    unsafe {
        let node = mte_to_node(enode);

        if mt_in_rcu(mt) {
            mt_destroy_walk(enode, mt, false);
            rust_mt_call_rcu_free_walk(node);
        } else {
            mt_destroy_walk(enode, mt, true);
        }
    }
}

/// `mas_store()`: store an `entry`; the range is `mas->index`..`mas->last`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store(mas: *mut MaState, entry: *mut c_void) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut wr_mas = ma_wr_state_new(mas, entry);
        let wr = &raw mut wr_mas;

        rust_mt_trace_ma_write(c"mas_store".as_ptr(), mas, 0, entry);

        /* Storing is the same operation as insert with the added caveat that it can overwrite entries. */
        mas_wr_prealloc_setup(wr);
        (*mas).store_type = mas_wr_store_type(wr);
        if (*mas).mas_flags & MA_STATE_PREALLOC != 0 {
            mas_wr_store_entry(wr);
            bug_on(mas_is_err(mas));
            return wr_mas.content;
        }

        mas_prealloc_calc(wr, entry);
        if (*mas).node_request != 0 {
            mas_alloc_nodes(mas, rust_gfp_nowait);
            if mas_is_err(mas) {
                return null_mut();
            }
        }

        // store:
        mas_wr_store_entry(wr);
        rust_mas_destroy(mas);
        wr_mas.content
    }
}

/// `mas_store_gfp()`: store a value into the tree.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store_gfp(mas: *mut MaState, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let index = (*mas).index;
        let last = (*mas).last;
        let mut wr_mas = ma_wr_state_new(mas, entry);
        let wr = &raw mut wr_mas;
        let mut ret: c_int = 0;

        loop {
            // retry:
            mas_wr_preallocate(wr, entry);
            if rust_mas_nomem(mas, gfp) {
                if entry.is_null() {
                    __mas_set_range(mas, index, last);
                }
                continue;
            }
            break;
        }

        if mas_is_err(mas) {
            ret = xa_err((*mas).node);
        } else {
            mas_wr_store_entry(wr);
        }
        // out:
        rust_mas_destroy(mas);
        ret
    }
}

/// `mas_store_prealloc()`: store a value into the tree using memory preallocated in the maple state.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store_prealloc(mas: *mut MaState, entry: *mut c_void) {
    // SAFETY: caller contract.
    unsafe {
        let mut wr_mas = ma_wr_state_new(mas, entry);
        let wr = &raw mut wr_mas;

        if (*mas).store_type == wr_store_root {
            mas_wr_prealloc_setup(wr);
        } else {
            mas_wr_walk_descend(wr);
            if (*mas).store_type != wr_spanning_store {
                /* set wr_mas->content to current slot */
                wr_mas.content = mas_slot_locked(mas, wr_mas.slots, (*mas).offset);
                mas_wr_end_piv(wr);
            }
        }

        // store:
        rust_mt_trace_ma_write(c"mas_store_prealloc".as_ptr(), mas, 0, entry);
        mas_wr_store_entry(wr);
        bug_on(mas_is_err(mas));
        rust_mas_destroy(mas);
    }
}

// ---------------------------------------------------------------------------
// C lines 5180-5640: preallocate, destroy, next / prev / pause / find set-up
// ---------------------------------------------------------------------------

/// `mas_preallocate()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_preallocate(mas: *mut MaState, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut wr_mas = ma_wr_state_new(mas, entry);
        let wr = &raw mut wr_mas;

        mas_wr_prealloc_setup(wr);
        (*mas).store_type = mas_wr_store_type(wr);
        mas_prealloc_calc(wr, entry);
        if (*mas).node_request != 0 {
            (*mas).mas_flags &= !MA_STATE_PREALLOC;
            mas_alloc_nodes(mas, gfp);
            if mas_is_err(mas) {
                let ret = xa_err((*mas).node);

                (*mas).node_request = 0;
                rust_mas_destroy(mas);
                mas_reset(mas);
                return ret;
            }
        }

        // set_flag:
        (*mas).mas_flags |= MA_STATE_PREALLOC;
        0
    }
}

/// `mas_destroy()`: destroy a maple state (frees any allocated nodes associated with it).
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_destroy(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        (*mas).mas_flags &= !MA_STATE_PREALLOC;
        mas_empty_nodes(mas);
    }
}

unsafe fn mas_may_activate(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        if (*mas).node.is_null() {
            (*mas).status = ma_start;
        } else if (*mas).index > (*mas).max || (*mas).index < (*mas).min {
            (*mas).status = ma_start;
        } else {
            (*mas).status = ma_active;
        }
    }
}

unsafe fn mas_next_setup(mas: *mut MaState, max: c_ulong, entry: *mut *mut c_void) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let was_none = mas_is_none(mas);

        if (*mas).last >= max {
            (*mas).status = ma_overflow;
            return true;
        }

        match (*mas).status {
            ma_active => return false,
            ma_none | ma_pause => {
                (*mas).status = ma_start;
                rust_mas_walk(mas); /* Retries on dead nodes handled by mas_walk */
            }
            ma_start => {
                rust_mas_walk(mas); /* Retries on dead nodes handled by mas_walk */
            }
            ma_overflow => {
                /* Overflowed before, but the max changed */
                mas_may_activate(mas);
            }
            ma_underflow => {
                /* The user expects the mas to be one before where it is */
                mas_may_activate(mas);
                *entry = rust_mas_walk(mas);
                if !(*entry).is_null() {
                    return true;
                }
            }
            ma_root => {}
            ma_error => return true,
            _ => {}
        }

        if mas_is_active(mas) {
            /* Fast path */
            return false;
        }

        if mas_is_ptr(mas) {
            *entry = null_mut();
            if was_none && (*mas).index == 0 {
                (*mas).last = 0;
                (*mas).index = 0;
                return true;
            }
            (*mas).index = 1;
            (*mas).last = ULONG_MAX;
            (*mas).status = ma_none;
            return true;
        }

        if mas_is_none(mas) {
            return true;
        }

        false
    }
}

/// `mas_next()`: get the next entry.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_next(mas: *mut MaState, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_next_setup(mas, max, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_next_slot */
        mas_next_slot(mas, max, false)
    }
}

/// `mas_next_range()`: advance the maple state to the next range.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_next_range(mas: *mut MaState, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_next_setup(mas, max, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_next_slot */
        mas_next_slot(mas, max, true)
    }
}

unsafe fn mas_prev_setup(mas: *mut MaState, min: c_ulong, entry: *mut *mut c_void) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if (*mas).index <= min {
            (*mas).status = ma_underflow;
            return true;
        }

        match (*mas).status {
            ma_active => return false,
            ma_start => {}
            ma_none | ma_pause => (*mas).status = ma_start,
            ma_underflow => {
                /* underflowed before but the min changed */
                mas_may_activate(mas);
            }
            ma_overflow => {
                /* User expects mas to be one after where it is */
                mas_may_activate(mas);
                *entry = rust_mas_walk(mas);
                if !(*entry).is_null() {
                    return true;
                }
            }
            ma_root => {}
            ma_error => return true,
            _ => {}
        }

        if mas_is_start(mas) {
            rust_mas_walk(mas);
        }

        if mas_is_ptr(mas) {
            if (*mas).index == 0 {
                (*mas).status = ma_none;
                return true;
            }
            (*mas).last = 0;
            (*mas).index = 0;
            *entry = mas_root(mas);
            return true;
        }

        if mas_is_none(mas) {
            if (*mas).index != 0 {
                /* Walked to out-of-range pointer? */
                (*mas).last = 0;
                (*mas).index = 0;
                (*mas).status = ma_root;
                *entry = mas_root(mas);
                return true;
            }
            return true;
        }

        false
    }
}

/// `mas_prev()`: get the previous entry.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_prev(mas: *mut MaState, min: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_prev_setup(mas, min, &raw mut entry) {
            return entry;
        }

        mas_prev_slot(mas, min, false)
    }
}

/// `mas_prev_range()`: advance to the previous range.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_prev_range(mas: *mut MaState, min: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_prev_setup(mas, min, &raw mut entry) {
            return entry;
        }

        mas_prev_slot(mas, min, true)
    }
}

/// `mas_pause()`: pause a `mas_find`/`mas_for_each` to drop the lock.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_pause(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        (*mas).status = ma_pause;
        (*mas).node = null_mut();
    }
}

/// `mas_find_setup()`: internal function to set up `mas_find*()`. Returns true if `entry` is the answer.
unsafe fn mas_find_setup(mas: *mut MaState, max: c_ulong, entry: *mut *mut c_void) -> bool {
    // SAFETY: caller contract.
    unsafe {
        match (*mas).status {
            ma_active => {
                if (*mas).last < max {
                    return false;
                }
                return true;
            }
            ma_start => {}
            ma_pause => {
                if (*mas).last >= max {
                    return true;
                }

                (*mas).last = (*mas).last.wrapping_add(1);
                (*mas).index = (*mas).last;
                (*mas).status = ma_start;
            }
            ma_none => {
                if (*mas).last >= max {
                    return true;
                }

                (*mas).index = (*mas).last;
                (*mas).status = ma_start;
            }
            ma_underflow => {
                /* mas is pointing at entry before unable to go lower */
                if (*mas).index >= max {
                    (*mas).status = ma_overflow;
                    return true;
                }

                mas_may_activate(mas);
                *entry = rust_mas_walk(mas);
                if !(*entry).is_null() {
                    return true;
                }
            }
            ma_overflow => {
                if (*mas).last >= max {
                    return true;
                }

                mas_may_activate(mas);
                *entry = rust_mas_walk(mas);
                if !(*entry).is_null() {
                    return true;
                }
            }
            ma_root => {}
            ma_error => return true,
            _ => {}
        }

        if mas_is_start(mas) {
            /* First run or continue */
            if (*mas).index > max {
                return true;
            }

            *entry = rust_mas_walk(mas);
            if !(*entry).is_null() {
                return true;
            }
        }

        if mas_is_ptr(mas) {
            // ptr_out_of_range:
            (*mas).status = ma_none;
            (*mas).index = 1;
            (*mas).last = ULONG_MAX;
            return true;
        }

        if mas_is_none(mas) {
            return true;
        }

        if (*mas).index == max {
            return true;
        }

        false
    }
}

/// `mas_find()`: on the first call, find the entry at or after `mas->index` up to `max`; otherwise the entry after `mas->index`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find(mas: *mut MaState, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_find_setup(mas, max, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_next_slot */
        entry = mas_next_slot(mas, max, false);
        /* Ignore overflow */
        (*mas).status = ma_active;
        entry
    }
}

// ---------------------------------------------------------------------------
// C lines 5620-6100: find variants, erase, nomem, the mtree_* interface
// ---------------------------------------------------------------------------

extern "C" {
    static rust_gfp_kernel: Gfp;
    // glue: lock and RCU read-side helpers (inline, configuration-dependent in the C).
    fn rust_mtree_lock(mt: *mut MapleTree);
    fn rust_mtree_unlock(mt: *mut MapleTree);
    fn rust_rcu_read_lock();
    fn rust_rcu_read_unlock();
    fn rust_gfp_allow_blocking(gfp: Gfp) -> bool;
}

const XA_ZERO_ENTRY: usize = (257 << 2) | 2;
const XA_RETRY_ENTRY: usize = (256 << 2) | 2;

#[inline(always)]
fn xa_is_zero(entry: *const c_void) -> bool {
    entry as usize == XA_ZERO_ENTRY
}
#[inline(always)]
fn xa_is_advanced(entry: *const c_void) -> bool {
    xa_is_internal(entry) && (entry as usize) <= XA_RETRY_ENTRY
}

/// `mas_find_range()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_range(mas: *mut MaState, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_find_setup(mas, max, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_next_slot */
        mas_next_slot(mas, max, true)
    }
}

/// `mas_find_rev_setup()`.
unsafe fn mas_find_rev_setup(mas: *mut MaState, min: c_ulong, entry: *mut *mut c_void) -> bool {
    // SAFETY: caller contract.
    unsafe {
        'none: {
            'active: {
                match (*mas).status {
                    ma_active => break 'active,
                    ma_start => {}
                    ma_pause => {
                        if (*mas).index <= min {
                            (*mas).status = ma_underflow;
                            return true;
                        }
                        (*mas).index = (*mas).index.wrapping_sub(1);
                        (*mas).last = (*mas).index;
                        (*mas).status = ma_start;
                    }
                    ma_none => {
                        if (*mas).index <= min {
                            break 'none;
                        }

                        (*mas).last = (*mas).index;
                        (*mas).status = ma_start;
                    }
                    ma_overflow => {
                        /* user expects the mas to be one after where it is */
                        if (*mas).index <= min {
                            (*mas).status = ma_underflow;
                            return true;
                        }

                        (*mas).status = ma_active;
                    }
                    ma_underflow => {
                        /* user expects the mas to be one before where it is */
                        if (*mas).index <= min {
                            return true;
                        }

                        (*mas).status = ma_active;
                    }
                    ma_root => {}
                    ma_error => return true,
                    _ => {}
                }

                if mas_is_start(mas) {
                    /* First run or continue */
                    if (*mas).index < min {
                        return true;
                    }

                    *entry = rust_mas_walk(mas);
                    if !(*entry).is_null() {
                        return true;
                    }
                }

                if mas_is_ptr(mas) {
                    break 'none;
                }

                if mas_is_none(mas) {
                    /* Walked to the location, and there was nothing so the previous location is 0. */
                    (*mas).index = 0;
                    (*mas).last = 0;
                    (*mas).status = ma_root;
                    *entry = mas_root(mas);
                    return true;
                }
            }

            // active:
            if (*mas).index < min {
                return true;
            }

            return false;
        }

        // none:
        (*mas).status = ma_none;
        true
    }
}

/// `mas_find_rev()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_rev(mas: *mut MaState, min: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_find_rev_setup(mas, min, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_prev_slot */
        mas_prev_slot(mas, min, false)
    }
}

/// `mas_find_range_rev()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_range_rev(mas: *mut MaState, min: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut entry: *mut c_void = null_mut();

        if mas_find_rev_setup(mas, min, &raw mut entry) {
            return entry;
        }

        /* Retries on dead nodes handled by mas_prev_slot */
        mas_prev_slot(mas, min, true)
    }
}

/// `mas_erase()`: find the range in which `index` resides and erase the entire range.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_erase(mas: *mut MaState) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let index = (*mas).index;
        let mut wr_mas = ma_wr_state_new(mas, null_mut());
        let wr = &raw mut wr_mas;
        let mut entry: *mut c_void;

        if !mas_is_active(mas) || !mas_is_start(mas) {
            (*mas).status = ma_start;
        }

        loop {
            // write_retry:
            let e = mas_state_walk(mas);
            if e.is_null() {
                return null_mut();
            }
            entry = e;

            /* Must reset to ensure spanning writes of last slot are detected */
            mas_reset(mas);
            mas_wr_preallocate(wr, null_mut());
            if rust_mas_nomem(mas, rust_gfp_kernel) {
                /* in case the range of entry changed when unlocked */
                (*mas).last = index;
                (*mas).index = index;
                continue;
            }
            break;
        }

        if !mas_is_err(mas) {
            mas_wr_store_entry(wr);
        }
        // out:
        rust_mas_destroy(mas);
        entry
    }
}

/// `mas_nomem()`: check if there was an error allocating and do the allocation if necessary. Returns true on allocation.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_nomem(mas: *mut MaState, gfp: Gfp) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if (*mas).node != ma_error_enode(-(ENOMEM as c_long)) {
            return false;
        }

        if rust_gfp_allow_blocking(gfp) && !mt_external_lock((*mas).tree) {
            rust_mtree_unlock((*mas).tree);
            mas_alloc_nodes(mas, gfp);
            rust_mtree_lock((*mas).tree);
        } else {
            mas_alloc_nodes(mas, gfp);
        }

        if (*mas).sheaf.is_null() && (*mas).alloc.is_null() {
            return false;
        }

        (*mas).status = ma_start;
        true
    }
}

/// `mtree_load()`: load a value stored in a maple tree.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_load(mt: *mut MapleTree, index: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, index, index);
        let m = &raw mut mas;
        let mut entry: *mut c_void = null_mut();

        rust_mt_trace_ma_read(c"mtree_load".as_ptr(), m);
        rust_rcu_read_lock();
        'unlock: loop {
            // retry:
            entry = mas_start(m);
            if mas_is_none(m) {
                break 'unlock;
            }

            if mas_is_ptr(m) {
                if index != 0 {
                    entry = null_mut();
                }

                break 'unlock;
            }

            entry = mtree_lookup_walk(m);
            if entry.is_null() && mas_is_start(m) {
                continue;
            }
            break;
        }
        // unlock:
        rust_rcu_read_unlock();
        if xa_is_zero(entry) {
            return null_mut();
        }

        entry
    }
}

/// `mtree_store_range()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_store_range(mt: *mut MapleTree, index: c_ulong, last: c_ulong, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, index, last);

        rust_mt_trace_ma_write(c"mtree_store_range".as_ptr(), &raw mut mas, 0, entry);
        if warn_on_once(xa_is_advanced(entry)) {
            return -EINVAL;
        }

        if index > last {
            return -EINVAL;
        }

        rust_mtree_lock(mt);
        let ret = rust_mas_store_gfp(&raw mut mas, entry, gfp);
        rust_mtree_unlock(mt);

        ret
    }
}

/// `mtree_insert_range()`: insert an entry at a given range if there is no value.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_insert_range(mt: *mut MapleTree, first: c_ulong, last: c_ulong, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut ms = ma_state_new(mt, first, last);
        let m = &raw mut ms;
        let mut ret: c_int = 0;

        if warn_on_once(xa_is_advanced(entry)) {
            return -EINVAL;
        }

        if first > last {
            return -EINVAL;
        }

        rust_mtree_lock(mt);
        loop {
            // retry:
            mas_insert(m, entry);
            if rust_mas_nomem(m, gfp) {
                continue;
            }
            break;
        }

        rust_mtree_unlock(mt);
        if mas_is_err(m) {
            ret = xa_err(ms.node);
        }

        rust_mas_destroy(m);
        ret
    }
}

/// `mtree_alloc_range()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_alloc_range(
    mt: *mut MapleTree,
    startp: *mut c_ulong,
    entry: *mut c_void,
    size: c_ulong,
    min: c_ulong,
    max: c_ulong,
    gfp: Gfp,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut ret: c_int;
        let mut mas = ma_state_new(mt, 0, 0);
        let m = &raw mut mas;

        if !mt_is_alloc(mt) {
            return -EINVAL;
        }

        if warn_on_once(mt_is_reserved(entry)) {
            return -EINVAL;
        }

        rust_mtree_lock(mt);
        loop {
            // retry:
            ret = rust_mas_empty_area(m, min, max, size);
            if ret != 0 {
                break;
            }

            mas_insert(m, entry);
            /* mas_nomem() may release the lock, causing the allocated area to be unavailable, so try to allocate a free area again. */
            if rust_mas_nomem(m, gfp) {
                continue;
            }

            if mas_is_err(m) {
                ret = xa_err(mas.node);
            } else {
                *startp = mas.index;
            }
            break;
        }

        // unlock:
        rust_mtree_unlock(mt);
        rust_mas_destroy(m);
        ret
    }
}

/// `mtree_alloc_cyclic()`: find somewhere to store this entry in the tree.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_alloc_cyclic(
    mt: *mut MapleTree,
    startp: *mut c_ulong,
    entry: *mut c_void,
    range_lo: c_ulong,
    range_hi: c_ulong,
    next: *mut c_ulong,
    gfp: Gfp,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, 0, 0);

        if !mt_is_alloc(mt) {
            return -EINVAL;
        }
        if warn_on_once(mt_is_reserved(entry)) {
            return -EINVAL;
        }
        rust_mtree_lock(mt);
        let ret = rust_mas_alloc_cyclic(&raw mut mas, startp, entry, range_lo, range_hi, next, gfp);
        rust_mtree_unlock(mt);
        ret
    }
}

// ---------------------------------------------------------------------------
// C lines 6090-6550: reverse range allocation, erase, duplication, destroy, find
// ---------------------------------------------------------------------------

extern "C" {
    fn rust_mtree_lock_nested(mt: *mut MapleTree);
}

/// `mtree_alloc_rrange()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_alloc_rrange(
    mt: *mut MapleTree,
    startp: *mut c_ulong,
    entry: *mut c_void,
    size: c_ulong,
    min: c_ulong,
    max: c_ulong,
    gfp: Gfp,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut ret: c_int;
        let mut mas = ma_state_new(mt, 0, 0);
        let m = &raw mut mas;

        if !mt_is_alloc(mt) {
            return -EINVAL;
        }

        if warn_on_once(mt_is_reserved(entry)) {
            return -EINVAL;
        }

        rust_mtree_lock(mt);
        loop {
            // retry:
            ret = rust_mas_empty_area_rev(m, min, max, size);
            if ret != 0 {
                break;
            }

            mas_insert(m, entry);
            /* mas_nomem() may release the lock, causing the allocated area to be unavailable, so try to allocate a free area again. */
            if rust_mas_nomem(m, gfp) {
                continue;
            }

            if mas_is_err(m) {
                ret = xa_err(mas.node);
            } else {
                *startp = mas.index;
            }
            break;
        }

        // unlock:
        rust_mtree_unlock(mt);
        rust_mas_destroy(m);
        ret
    }
}

/// `mtree_erase()`: find an index and erase the entire range.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_erase(mt: *mut MapleTree, index: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, index, index);
        let m = &raw mut mas;
        rust_mt_trace_ma_op(c"mtree_erase".as_ptr(), m);

        rust_mtree_lock(mt);
        let entry = rust_mas_erase(m);
        rust_mtree_unlock(mt);

        entry
    }
}

/// `mas_dup_free()`: free an incomplete duplication of a tree.
unsafe fn mas_dup_free(mas: *mut MaState) {
    // SAFETY: caller contract.
    unsafe {
        /* Maybe the first node allocation failed. */
        if mas_is_none(mas) {
            return;
        }

        while !mte_is_root((*mas).node) {
            mas_ascend(mas);
            if (*mas).offset != 0 {
                (*mas).offset -= 1;
                loop {
                    mas_descend(mas);
                    (*mas).offset = mas_data_end(mas);
                    if mte_is_leaf((*mas).node) {
                        break;
                    }
                }

                mas_ascend(mas);
            }

            let node = mte_to_node((*mas).node);
            let type_ = mte_node_type((*mas).node);
            let slots = ma_slots(node, type_);
            let count = mas_data_end(mas).wrapping_add(1);
            let mut i: u8 = 0;
            while i < count {
                *slots.cast::<c_ulong>().add(i as usize) &= !(MAPLE_NODE_MASK as c_ulong);
                i += 1;
            }
            rust_mt_free_bulk(count as usize, slots);
        }

        let node = mte_to_node((*mas).node);
        rust_mt_kfree(node.cast());
    }
}

/// `mas_copy_node()`: copy a maple node and replace the parent.
unsafe fn mas_copy_node(mas: *mut MaState, new_mas: *mut MaState, parent: Pnode) {
    // SAFETY: caller contract.
    unsafe {
        let node = mte_to_node((*mas).node);
        let new_node = mte_to_node((*new_mas).node);

        /* Copy the node completely. */
        core::ptr::copy_nonoverlapping(node, new_node, 1);
        /* Update the parent node pointer. */
        let val = *n_parent(node) as usize & MAPLE_NODE_MASK;
        *n_parent(new_node) = (val | parent as usize) as Pnode;
    }
}

/// `mas_dup_alloc()`: allocate child nodes for a maple node during duplication.
unsafe fn mas_dup_alloc(mas: *mut MaState, new_mas: *mut MaState, gfp: Gfp) {
    // SAFETY: caller contract.
    unsafe {
        let node = mte_to_node((*mas).node);
        let new_node = mte_to_node((*new_mas).node);

        /* Allocate memory for child nodes. */
        let type_ = mte_node_type((*mas).node);
        let new_slots = ma_slots(new_node, type_);
        let count = mas_data_end(mas).wrapping_add(1);
        (*mas).node_request = count as c_ulong;
        mas_alloc_nodes(mas, gfp);
        if mas_is_err(mas) {
            return;
        }

        let slots = ma_slots(node, type_);
        let mut i: u8 = 0;
        while i < count {
            let mut val = mt_slot_locked((*mas).tree, slots, i) as usize;
            val &= MAPLE_NODE_MASK;
            *new_slots.add(i as usize) = (mas_pop_node(mas) as usize | val) as *mut c_void;
            i += 1;
        }
    }
}

/// `mas_dup_build()`: build a new maple tree from a source tree.
unsafe fn mas_dup_build(mas: *mut MaState, new_mas: *mut MaState, gfp: Gfp) {
    // SAFETY: caller contract.
    unsafe {
        let mut parent: Pnode = null_mut();

        if (*mt_flags((*mas).tree) & !MT_FLAGS_HEIGHT_MASK) != (*mt_flags((*new_mas).tree) & !MT_FLAGS_HEIGHT_MASK)
            || !(*mt_root_p((*new_mas).tree)).is_null()
        {
            mas_set_err(mas, -(EINVAL as c_long));
            return;
        }

        let mut root: *mut c_void = mas_start(mas);
        let mut empty_mas_only = false;
        'set_new_tree: {
            if mas_is_ptr(mas) || mas_is_none(mas) {
                break 'set_new_tree;
            }

            let node = mt_alloc_one(gfp);
            if node.is_null() {
                (*new_mas).status = ma_none;
                mas_set_err(mas, -(ENOMEM as c_long));
                return;
            }

            let type_ = mte_node_type((*mas).node);
            root = mt_mk_node(node, type_);
            (*new_mas).node = root;
            (*new_mas).min = 0;
            (*new_mas).max = ULONG_MAX;
            root = mte_mk_root(root);
            loop {
                mas_copy_node(mas, new_mas, parent);
                if !mte_is_leaf((*mas).node) {
                    /* Only allocate child nodes for non-leaf nodes. */
                    mas_dup_alloc(mas, new_mas, gfp);
                    if mas_is_err(mas) {
                        // goto empty_mas
                        empty_mas_only = true;
                        break 'set_new_tree;
                    }
                } else {
                    /* This is the last leaf node and duplication is completed. */
                    if (*mas).max == ULONG_MAX {
                        // done: Specially handle the parent of the root node.
                        *n_parent(mte_to_node(root)) = mas_tree_parent(new_mas) as Pnode;
                        break 'set_new_tree;
                    }

                    /* This is not the last leaf node and needs to go up. */
                    loop {
                        mas_ascend(mas);
                        mas_ascend(new_mas);
                        if (*mas).offset != mas_data_end(mas) {
                            break;
                        }
                    }

                    /* Move to the next subtree. */
                    (*mas).offset += 1;
                    (*new_mas).offset += 1;
                }

                mas_descend(mas);
                parent = mte_to_node((*new_mas).node) as Pnode;
                mas_descend(new_mas);
                (*mas).offset = 0;
                (*new_mas).offset = 0;
            }
        }

        if !empty_mas_only {
            // set_new_tree: make them the same height
            *mt_flags((*new_mas).tree) = *mt_flags((*mas).tree);
            rcu_assign(mt_root_p((*new_mas).tree), root);
        }
        // empty_mas:
        mas_empty_nodes(mas);
    }
}

/// `__mt_dup()`: duplicate an entire maple tree (the caller locks both).
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust___mt_dup(mt: *mut MapleTree, new: *mut MapleTree, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut mas = ma_state_new(mt, 0, 0);
        let mut new_mas = ma_state_new(new, 0, 0);

        mas_dup_build(&raw mut mas, &raw mut new_mas, gfp);
        if mas_is_err(&raw const mas) {
            ret = xa_err(mas.node);
            if ret == -ENOMEM {
                mas_dup_free(&raw mut new_mas);
            }
        }

        ret
    }
}

/// `mtree_dup()`: duplicate an entire maple tree (takes both locks).
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_dup(mt: *mut MapleTree, new: *mut MapleTree, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut ret: c_int = 0;
        let mut mas = ma_state_new(mt, 0, 0);
        let mut new_mas = ma_state_new(new, 0, 0);

        rust_mtree_lock(new_mas.tree); /* mas_lock(&new_mas) */
        rust_mtree_lock_nested(mas.tree); /* mas_lock_nested(&mas, SINGLE_DEPTH_NESTING) */
        mas_dup_build(&raw mut mas, &raw mut new_mas, gfp);
        rust_mtree_unlock(mas.tree); /* mas_unlock(&mas) */
        if mas_is_err(&raw const mas) {
            ret = xa_err(mas.node);
            if ret == -ENOMEM {
                mas_dup_free(&raw mut new_mas);
            }
        }

        rust_mtree_unlock(new_mas.tree); /* mas_unlock(&new_mas) */
        ret
    }
}

/// `__mt_destroy()`: walk and free all nodes of a locked maple tree (does not handle locking).
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust___mt_destroy(mt: *mut MapleTree) {
    // SAFETY: caller contract.
    unsafe {
        let root = mt_root_locked(mt);

        rcu_assign(mt_root_p(mt), null_mut());
        if xa_is_node(root) {
            mte_destroy_walk(root, mt);
        }

        *mt_flags(mt) &= !MT_FLAGS_HEIGHT_MASK; /* mt->ma_flags = mt_attr(mt) */
    }
}

/// `mtree_destroy()`: destroy a maple tree (handles locking).
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_destroy(mt: *mut MapleTree) {
    // SAFETY: caller contract.
    unsafe {
        rust_mtree_lock(mt);
        rust___mt_destroy(mt);
        rust_mtree_unlock(mt);
    }
}

/// `mt_find()`: search from the start up until an entry is found.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_find(mt: *mut MapleTree, index: *mut c_ulong, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, *index, *index);
        let m = &raw mut mas;
        let mut entry: *mut c_void;

        rust_mt_trace_ma_read(c"mt_find".as_ptr(), m);

        if *index > max {
            return null_mut();
        }

        rust_rcu_read_lock();
        loop {
            // retry:
            entry = mas_state_walk(m);
            if mas_is_start(m) {
                continue;
            }
            break;
        }

        if xa_is_zero(entry) {
            entry = null_mut();
        }

        if entry.is_null() {
            while mas_is_active(m) && mas.last < max {
                entry = mas_next_slot(m, max, false);
                if !entry.is_null() && !xa_is_zero(entry) {
                    break;
                }
            }

            if xa_is_zero(entry) {
                entry = null_mut();
            }
        }
        // unlock:
        rust_rcu_read_unlock();
        if !entry.is_null() {
            *index = mas.last.wrapping_add(1);
        }

        entry
    }
}

/// `mt_find_after()`: same as `mt_find()` except that it checks `index` for 0 before searching.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_find_after(mt: *mut MapleTree, index: *mut c_ulong, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        if *index == 0 {
            return null_mut();
        }

        rust_mt_find(mt, index, max)
    }
}

/// `mt_next()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_next(mt: *mut MapleTree, index: c_ulong, max: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, index, index);

        rust_rcu_read_lock();
        let entry = rust_mas_next(&raw mut mas, max);
        rust_rcu_read_unlock();
        entry
    }
}

/// `mt_prev()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_prev(mt: *mut MapleTree, index: c_ulong, min: c_ulong) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut mas = ma_state_new(mt, index, index);

        rust_rcu_read_lock();
        let entry = rust_mas_prev(&raw mut mas, min);
        rust_rcu_read_unlock();
        entry
    }
}

/// `mtree_store()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_store(mt: *mut MapleTree, index: c_ulong, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe { rust_mtree_store_range(mt, index, index, entry, gfp) }
}

/// `mtree_insert()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn rust_mtree_insert(mt: *mut MapleTree, index: c_ulong, entry: *mut c_void, gfp: Gfp) -> c_int {
    // SAFETY: caller contract.
    unsafe { rust_mtree_insert_range(mt, index, index, entry, gfp) }
}
