// SPDX-License-Identifier: GPL-2.0+
//! XArray implementation, ported from `lib/xarray.c`.
//!
//! `struct xa_node`'s layout is depended on directly by `mm/workingset.c`
//! (reads `->array`, `->count`, `->nr_values`, and `container_of`s on
//! `->private_list`), so it is not opaque outside this file the way
//! `rb_node` was reproduced independently by other Rust crates -- here
//! there is one canonical C definition and one external C reader. See
//! the layout test in `port/test/xarray/` for the cross-check.
//!
//! `XA_CHUNK_SHIFT` is a compile-time knob in the C (`#ifndef
//! XA_CHUNK_SHIFT ... IS_ENABLED(CONFIG_BASE_SMALL) ? 4 : 6`), overridden
//! by this project's differential harness to 4 so multi-level trees and
//! sibling runs show up at small, fuzzable indices instead of needing
//! thousands of entries (see the verification plan sent to
//! rusty-linux-e6). CONFIG_BASE_SMALL is absent from both build-fast and
//! build-full's `.config`, so the real kernel value is 6. The Rust
//! mirror of that same knob is a `cfg`-gated const, not a runtime branch:
//! the harness's `run.sh` passes `--cfg xa_harness_small_chunk` when
//! compiling this same file; the real kernel build never does, so it
//! gets 6. Both arms of a given build see the identical constant, which
//! is the property that matters -- the C reference and this file must
//! always agree with EACH OTHER, not with the real kernel, when running
//! inside the harness.
//!
//! # The six `WARN` sites, and why they are macros rather than bare `if`s
//!
//! The C guards its exported entry points with `WARN_ON_ONCE()`
//! (`__xa_store`, `__xa_cmpxchg_raw`, `xa_store_range`, `__xa_alloc` twice)
//! and `WARN_ON()` (`xas_split_alloc`). The first version of this file
//! reproduced every condition and every return value and dropped the
//! warning itself -- which is invisible to a differential (a warning is not
//! a result), invisible to `crc-check` (the signature does not move), and
//! invisible to a boot (none of them fires on valid input). It is the exact
//! class that cost seven thunk-closure reverts on 2026-09-04.
//!
//! `kernel::kabi_warn_on_once!` covers the five `WARN_ON_ONCE`s.
//! `xas_split_alloc` uses `kernel::warn_on!` instead, deliberately: its C
//! guard is a plain `WARN_ON`, which reports on EVERY occurrence, and the
//! `_once` macro would have reported once and then diverged silently.
//!
//! The 15 `XA_NODE_BUG_ON` sites are NOT reproduced and do not need to be:
//! they expand to nothing unless `XA_DEBUG` is `#define`d, and nothing in
//! the tree defines it (`include/linux/xarray.h:1189` only tests it).
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;
#[allow(unused_imports)]
use core::sync::atomic::{fence, Ordering};

#[cfg(xa_harness_small_chunk)]
const XA_CHUNK_SHIFT: usize = 4;
#[cfg(not(xa_harness_small_chunk))]
const XA_CHUNK_SHIFT: usize = 6;

const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;
const XA_CHUNK_MASK: usize = XA_CHUNK_SIZE - 1;
const XA_MAX_MARKS: usize = 3;
const XA_MARK_LONGS: usize = XA_CHUNK_SIZE.div_ceil(usize::BITS as usize);

const XA_MARK_0: u32 = 0;
const XA_MARK_2: u32 = 2;
const XA_MARK_MAX: u32 = XA_MARK_2;
const XA_FREE_MARK: u32 = XA_MARK_0;

const MAX_ERRNO: isize = 4095;

/// Mirrors `struct xarray` (`include/linux/xarray.h`). `xa_lock` is never read as a `spinlock_t` by this
/// file (only its address is ever taken, via [`xa_lock_ptr`]) -- its
/// exact internal bit layout does not matter here, only its size, which
/// is pinned to the real kernel's 4 bytes (pahole on `build-fast/vmlinux`:
/// qspinlock, `CONFIG_DEBUG_SPINLOCK=n`, `CONFIG_DEBUG_LOCK_ALLOC=n` in
/// both configs) so `xa_flags`/`xa_head` land at the real offsets.
///
/// CONFIG-DEPENDENT SIZE (found by the concurrency checker build, logs/concurrency-tooling.md): with
/// `CONFIG_DEBUG_SPINLOCK` and/or `CONFIG_DEBUG_LOCK_ALLOC` `spinlock_t` is 24 / 48 / 64 bytes (pahole on
/// build-chk-ka: 64, xa_flags @64, xa_head @72), 8-aligned. With the 4-byte mirror `xa_head` was read at the
/// wrong offset, `xa_find_after()` returned garbage and a KASAN+lockdep kernel died in early boot.
#[cfg(not(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC)))]
#[repr(C)]
pub struct Xarray {
    xa_lock: [u8; 4],
    xa_flags: u32,
    xa_head: *mut c_void,
}

#[cfg(all(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC))]
const XA_LOCK_SIZE: usize = 64;
#[cfg(all(not(CONFIG_DEBUG_SPINLOCK), CONFIG_DEBUG_LOCK_ALLOC))]
const XA_LOCK_SIZE: usize = 48;
#[cfg(all(CONFIG_DEBUG_SPINLOCK, not(CONFIG_DEBUG_LOCK_ALLOC)))]
const XA_LOCK_SIZE: usize = 24;
#[cfg(CONFIG_LOCK_STAT)]
compile_error!("CONFIG_LOCK_STAT adds fields to lockdep_map; the Xarray mirror sizes are for it off");

#[cfg(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC))]
#[repr(C, align(8))]
pub struct Xarray {
    xa_lock: [u8; XA_LOCK_SIZE],
    xa_flags: u32,
    xa_head: *mut c_void,
}

// The sizes pahole reports for `struct xarray` (build-fast: 16, xa_head @8; build-chk-ka: 80, xa_head @72).
#[cfg(not(any(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC)))]
const _: () = assert!(core::mem::size_of::<Xarray>() == 16 && core::mem::offset_of!(Xarray, xa_head) == 8);
#[cfg(all(CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC))]
const _: () = assert!(core::mem::size_of::<Xarray>() == 80 && core::mem::offset_of!(Xarray, xa_head) == 72);

const XA_FLAGS_LOCK_IRQ: u32 = 1;
const XA_FLAGS_LOCK_BH: u32 = 2;
const XA_FLAGS_TRACK_FREE: u32 = 4;
const XA_FLAGS_ZERO_BUSY: u32 = 8;
const XA_FLAGS_ALLOC_WRAPPED: u32 = 16;
const XA_FLAGS_ACCOUNT: u32 = 32;

/// `XA_FLAGS_MARK()`: the mark bits sit above `__GFP_BITS_SHIFT`, which depends on the configuration, so the value comes from `xarray.c`.
fn xa_flags_mark(mark: u32) -> u32 {
    (1u32 << unsafe { rust_xa_gfp_bits_shift }) << mark
}

/// `struct xa_node`. `private_list`/`rcu_head` (a union in C) is never
/// read by this file -- the slab allocator's constructor initialises it
/// on every allocation/reuse, and `XA_NODE_BUG_ON`'s `list_empty()`
/// check on it only fires under `XA_DEBUG`, which is not defined by any
/// Kconfig symbol and is not set in either build -- so it is opaque
/// bytes here, sized to match the real union (2 pointers, 16 bytes).
#[repr(C)]
pub struct XaNode {
    shift: u8,
    offset: u8,
    count: u8,
    nr_values: u8,
    parent: *mut XaNode,
    array: *mut Xarray,
    _private_list_or_rcu_head: [usize; 2],
    slots: [*mut c_void; XA_CHUNK_SIZE],
    marks: [[usize; XA_MARK_LONGS]; XA_MAX_MARKS],
}

/// `xa_update_node_t`.
pub type XaUpdateNode = Option<unsafe extern "C" fn(*mut XaNode)>;

/// `struct xa_state`. Declared by C callers on the stack via the
/// `XA_STATE`/`XA_STATE_ORDER` macros (unchanged, still in the real
/// header) and passed by pointer into every function this file exports
/// -- this mirror must match that macro's field order and widths
/// exactly. Confirmed via pahole on `build-fast/vmlinux`: 56 bytes,
/// `xa_shift`/`xa_sibs`/`xa_offset`/`xa_pad` each 1 byte with no gap
/// among them, matching the real header's declared order.
#[repr(C)]
pub struct XaState {
    xa: *mut Xarray,
    xa_index: usize,
    xa_shift: u8,
    xa_sibs: u8,
    xa_offset: u8,
    xa_pad: u8,
    xa_node: *mut XaNode,
    xa_alloc: *mut XaNode,
    xa_update: XaUpdateNode,
    xa_lru: *mut c_void,
}

// `XAS_BOUNDS`/`XAS_RESTART`/`XA_ERROR` are sentinel *values* stashed in
// the `xa_node` pointer field, not real node pointers -- same encoding
// as the C's `(struct xa_node *)1UL` / `3UL` / `(errno<<2)|2UL`.
fn xas_bounds() -> *mut XaNode {
    1usize as *mut XaNode
}
fn xas_restart() -> *mut XaNode {
    3usize as *mut XaNode
}
fn xa_error_node(errno: isize) -> *mut XaNode {
    (((errno as usize) << 2) | 2) as *mut XaNode
}

// ---- internal-entry encoding (Private, from include/linux/xarray.h) ----

fn xa_is_value(entry: *const c_void) -> bool {
    (entry as usize) & 1 != 0
}

fn xa_mk_internal(v: usize) -> *mut c_void {
    ((v << 2) | 2) as *mut c_void
}

fn xa_to_internal(entry: *const c_void) -> usize {
    (entry as usize) >> 2
}

fn xa_is_internal(entry: *const c_void) -> bool {
    (entry as usize) & 3 == 2
}

fn xa_zero_entry() -> *mut c_void {
    xa_mk_internal(257)
}

fn xa_is_zero(entry: *const c_void) -> bool {
    entry == xa_zero_entry()
}

fn xa_is_err(entry: *const c_void) -> bool {
    xa_is_internal(entry) && entry >= xa_mk_internal((-MAX_ERRNO) as usize)
}

fn xa_err(entry: *mut c_void) -> i32 {
    if xa_is_err(entry) {
        // xa_to_internal() would not sign-extend.
        ((entry as isize) >> 2) as i32
    } else {
        0
    }
}

fn xa_zero_to_null(entry: *mut c_void) -> *mut c_void {
    if xa_is_zero(entry) {
        ptr::null_mut()
    } else {
        entry
    }
}

fn xa_mk_node(node: *const XaNode) -> *mut c_void {
    ((node as usize) | 2) as *mut c_void
}

fn xa_to_node(entry: *const c_void) -> *mut XaNode {
    ((entry as usize) - 2) as *mut XaNode
}

fn xa_is_node(entry: *const c_void) -> bool {
    xa_is_internal(entry) && (entry as usize) > 4096
}

fn xa_mk_sibling(offset: u32) -> *mut c_void {
    xa_mk_internal(offset as usize)
}

fn xa_to_sibling(entry: *const c_void) -> usize {
    xa_to_internal(entry)
}

fn xa_is_sibling(entry: *const c_void) -> bool {
    // CONFIG_XARRAY_MULTI is NOT always on for this project (verified
    // by reading .config: build-full has it, build-fast does not --
    // an earlier version of this comment claimed otherwise without
    // checking). Dropping the C's IS_ENABLED(CONFIG_XARRAY_MULTI)
    // guard here is still safe, not just unverified: under
    // !CONFIG_XARRAY_MULTI, xas_set_order()'s own C fallback is
    // `BUG_ON(order > 0); xas_set(...)`, so no caller can ever create
    // a multi-slot entry in the first place -- nothing this file's own
    // logic ever encounters can be sibling-shaped in that
    // configuration, guard or no guard. See the 7 `#[cfg(
    // CONFIG_XARRAY_MULTI)]`-gated exports (xa_get_order and friends)
    // for the one place this config genuinely changes this file's
    // ABI, not just an optimisation in unreachable code.
    xa_is_internal(entry) && (entry as usize) < xa_mk_sibling((XA_CHUNK_SIZE - 1) as u32) as usize
}

fn xa_retry_entry() -> *mut c_void {
    xa_mk_internal(256)
}

fn xa_is_retry(entry: *const c_void) -> bool {
    entry == xa_retry_entry()
}

fn xa_is_advanced(entry: *const c_void) -> bool {
    xa_is_internal(entry) && (entry as usize) <= xa_retry_entry() as usize
}

// ---- xa_flags helpers ----

fn xa_track_free(xa: &Xarray) -> bool {
    xa.xa_flags & XA_FLAGS_TRACK_FREE != 0
}

fn xa_zero_busy(xa: &Xarray) -> bool {
    xa.xa_flags & XA_FLAGS_ZERO_BUSY != 0
}

fn xa_marked(xa: &Xarray, mark: u32) -> bool {
    xa.xa_flags & xa_flags_mark(mark) != 0
}

fn xa_mark_set(xa: &mut Xarray, mark: u32) {
    xa.xa_flags |= xa_flags_mark(mark);
}

fn xa_mark_clear(xa: &mut Xarray, mark: u32) {
    xa.xa_flags &= !xa_flags_mark(mark);
}

fn xa_lock_ptr(xa: *mut Xarray) -> *mut c_void {
    xa as *mut c_void
}

unsafe extern "C" {
    /// `__GFP_BITS_SHIFT`, from `xarray.c`.
    static rust_xa_gfp_bits_shift: u32;
    fn rust_helper_spin_lock(lock: *mut c_void);
    fn rust_helper_spin_unlock(lock: *mut c_void);
    fn rust_helper_spin_lock_bh(lock: *mut c_void);
    fn rust_helper_spin_unlock_bh(lock: *mut c_void);
    fn rust_helper_spin_lock_irq(lock: *mut c_void);
    fn rust_helper_spin_unlock_irq(lock: *mut c_void);
    fn rust_helper_spin_lock_irqsave(lock: *mut c_void, flags: *mut usize);
    fn rust_helper_spin_unlock_irqrestore(lock: *mut c_void, flags: usize);
    fn rust_helper_rcu_read_lock();
    fn rust_helper_rcu_read_unlock();

    /// Real symbol from `lib/radix-tree.c`, untouched by this port --
    /// never called directly, only handed to `call_rcu()` by address.
    fn radix_tree_node_rcu_free(head: *mut c_void);
    /// Real `EXPORT_SYMBOL_GPL` (`kernel/rcu/tree.c`), not macroed.
    fn call_rcu(head: *mut c_void, func: unsafe extern "C" fn(*mut c_void));
    /// `port/tree/lib/xarray.c` -- see its module doc and
    /// `logs/allocation.md` for why `kmem_cache_alloc_lru()` itself
    /// cannot be called directly from Rust.
    fn rust_xa_node_alloc_nowait(lru: *mut c_void, account: i32) -> *mut XaNode;
    fn rust_xa_node_alloc(lru: *mut c_void, gfp: u32, account: i32) -> *mut XaNode;
    /// `port/tree/lib/xarray.c` -- `gfpflags_allow_blocking()`'s
    /// `__GFP_DIRECT_RECLAIM` bit is bit-position-derived, same reasoning
    /// as `__GFP_ACCOUNT` above.
    fn rust_gfp_allows_blocking(gfp: u32) -> i32;
}

fn xa_lock(xa: *mut Xarray) {
    unsafe { rust_helper_spin_lock(xa_lock_ptr(xa)) };
}

fn xa_unlock(xa: *mut Xarray) {
    unsafe { rust_helper_spin_unlock(xa_lock_ptr(xa)) };
}

fn xa_lock_bh(xa: *mut Xarray) {
    unsafe { rust_helper_spin_lock_bh(xa_lock_ptr(xa)) };
}

fn xa_unlock_bh(xa: *mut Xarray) {
    unsafe { rust_helper_spin_unlock_bh(xa_lock_ptr(xa)) };
}

fn xa_lock_irqsave(xa: *mut Xarray) -> usize {
    let mut flags: usize = 0;
    unsafe { rust_helper_spin_lock_irqsave(xa_lock_ptr(xa), &mut flags) };
    flags
}

fn xa_unlock_irqrestore(xa: *mut Xarray, flags: usize) {
    unsafe { rust_helper_spin_unlock_irqrestore(xa_lock_ptr(xa), flags) };
}

/// `xa_lock_type()`: the low two bits of `xa_flags` select which of the
/// three lock flavours `__xas_nomem()`'s drop/reacquire uses.
fn xa_lock_type(xa: &Xarray) -> u32 {
    xa.xa_flags & 3
}

fn xas_lock_type(xas: &XaState, lock_type: u32) {
    if lock_type == XA_FLAGS_LOCK_IRQ {
        unsafe { rust_helper_spin_lock_irq(xa_lock_ptr(xas.xa)) };
    } else if lock_type == XA_FLAGS_LOCK_BH {
        xa_lock_bh(xas.xa);
    } else {
        xa_lock(xas.xa);
    }
}

fn xas_unlock_type(xas: &XaState, lock_type: u32) {
    if lock_type == XA_FLAGS_LOCK_IRQ {
        unsafe { rust_helper_spin_unlock_irq(xa_lock_ptr(xas.xa)) };
    } else if lock_type == XA_FLAGS_LOCK_BH {
        xa_unlock_bh(xas.xa);
    } else {
        xa_unlock(xas.xa);
    }
}

// ---- node mark primitives ----

fn node_marks<'a>(node: &'a XaNode, mark: u32) -> &'a [usize; XA_MARK_LONGS] {
    &node.marks[mark as usize]
}

fn node_marks_mut<'a>(node: &'a mut XaNode, mark: u32) -> &'a mut [usize; XA_MARK_LONGS] {
    &mut node.marks[mark as usize]
}

fn test_bit(nr: usize, addr: &[usize]) -> bool {
    (addr[nr / usize::BITS as usize] >> (nr % usize::BITS as usize)) & 1 != 0
}

fn __set_bit(nr: usize, addr: &mut [usize]) {
    addr[nr / usize::BITS as usize] |= 1usize << (nr % usize::BITS as usize);
}

fn __clear_bit(nr: usize, addr: &mut [usize]) {
    addr[nr / usize::BITS as usize] &= !(1usize << (nr % usize::BITS as usize));
}

fn find_next_bit(addr: &[usize], size: usize, offset: usize) -> usize {
    (offset..size).find(|&i| test_bit(i, addr)).unwrap_or(size)
}

fn bitmap_clear(map: &mut [usize], start: usize, nbits: usize) {
    for i in start..start + nbits {
        __clear_bit(i, map);
    }
}

fn bitmap_fill(dst: &mut [usize], nbits: usize) {
    for i in 0..nbits {
        __set_bit(i, dst);
    }
}

fn bitmap_empty(src: &[usize], nbits: usize) -> bool {
    !(0..nbits).any(|i| test_bit(i, src))
}

fn node_get_mark(node: &XaNode, offset: u32, mark: u32) -> bool {
    test_bit(offset as usize, node_marks(node, mark))
}

/// Returns true if the bit was already set.
fn node_set_mark(node: &mut XaNode, offset: u32, mark: u32) -> bool {
    let old = node_get_mark(node, offset, mark);
    __set_bit(offset as usize, node_marks_mut(node, mark));
    old
}

/// Returns true if the bit was set (i.e. actually cleared something).
fn node_clear_mark(node: &mut XaNode, offset: u32, mark: u32) -> bool {
    let old = node_get_mark(node, offset, mark);
    __clear_bit(offset as usize, node_marks_mut(node, mark));
    old
}

fn node_any_mark(node: &XaNode, mark: u32) -> bool {
    !bitmap_empty(node_marks(node, mark), XA_CHUNK_SIZE)
}

fn node_mark_all(node: &mut XaNode, mark: u32) {
    bitmap_fill(node_marks_mut(node, mark), XA_CHUNK_SIZE);
}

fn mark_inc(mark: u32) -> u32 {
    mark + 1
}

/// `xas_squash_marks()` -- merge all marks to the first (canonical) entry
/// of a sibling run, clearing them on every sibling slot. This is why
/// the mark invariant checker must exclude sibling slots from its
/// OR-over-live-descendants: after this runs, only the canonical slot
/// ever carries the bit for a multi-slot entry.
fn xas_squash_marks(xas: &XaState) {
    let node = unsafe { &mut *xas.xa_node };
    let limit = xas.xa_offset as usize + xas.xa_sibs as usize + 1;
    let mut mark = 0u32;

    loop {
        let marks = node_marks_mut(node, mark);
        if find_next_bit(marks, limit, xas.xa_offset as usize + 1) != limit {
            __set_bit(xas.xa_offset as usize, marks);
            bitmap_clear(marks, xas.xa_offset as usize + 1, xas.xa_sibs as usize);
        }
        if mark == XA_MARK_MAX {
            break;
        }
        mark = mark_inc(mark);
    }
}

// ---- private xa_entry / xa_parent accessors ----
//
// The C versions dereference through rcu_dereference_check/_protected,
// which under lockdep_is_held() reduce to a plain load -- the lock/RCU
// discipline is enforced by the caller (matching the C's own contract),
// not re-derived here.

fn get_offset(index: usize, node: &XaNode) -> u32 {
    ((index >> node.shift) & XA_CHUNK_MASK) as u32
}

fn xa_head(xa: &Xarray) -> *mut c_void {
    xa.xa_head
}

fn xa_entry(node: &XaNode, offset: u32) -> *mut c_void {
    debug_assert!((offset as usize) < XA_CHUNK_SIZE);
    node.slots[offset as usize]
}

fn xa_parent(node: &XaNode) -> *mut XaNode {
    node.parent
}

fn xas_set_offset(xas: &mut XaState) {
    xas.xa_offset = get_offset(xas.xa_index, unsafe { &*xas.xa_node }) as u8;
}

fn xas_move_index(xas: &mut XaState, offset: u32) {
    let shift = unsafe { &*xas.xa_node }.shift;
    // C: `xas->xa_index &= ~XA_CHUNK_MASK << shift;` -- unary `~` binds
    // tighter than `<<` in C, so this is `(~XA_CHUNK_MASK) << shift`,
    // NOT `~(XA_CHUNK_MASK << shift)`. At shift==0 the two coincide,
    // which is why the differential's shallow trees never caught this:
    // `!(XA_CHUNK_MASK << shift)` clears the low `shift` index bits
    // too (shifted out to 0) instead of preserving them, corrupting
    // xa_index during xas_find()'s cross-node advancement in any tree
    // deep enough to need shift>0. Reproduced for real:
    // CONFIG_TEST_XARRAY's check_xas_erase(56) walks off to the wrong
    // entry at exactly this boundary.
    xas.xa_index &= !XA_CHUNK_MASK << shift;
    // C: `xas->xa_index += offset << shift;` -- plain unsigned `+=`,
    // wraps if xa_index is already near usize::MAX (reachable from
    // xas_find()'s cross-node walk with max==ULONG_MAX). The wrapped
    // value is caught by the caller's own `xas_index <= max` loop
    // guard/`Mind the wrap` checks, not something to panic on here.
    xas.xa_index = xas.xa_index.wrapping_add((offset as usize) << shift);
}

fn xas_next_offset(xas: &mut XaState) {
    xas.xa_offset += 1;
    xas_move_index(xas, xas.xa_offset as u32);
}

fn set_bounds(xas: &mut XaState) -> *mut c_void {
    xas.xa_node = xas_bounds();
    ptr::null_mut()
}

// ---- xa_state predicates ----

fn xas_error(xas: &XaState) -> i32 {
    xa_err(xas.xa_node as *mut c_void)
}

fn xas_set_err(xas: &mut XaState, err: isize) {
    xas.xa_node = xa_error_node(err);
}

fn xas_invalid(xas: &XaState) -> bool {
    (xas.xa_node as usize) & 3 != 0
}

fn xas_valid(xas: &XaState) -> bool {
    !xas_invalid(xas)
}

/// True if the pointer is something other than a node.
fn xas_not_node(node: *mut XaNode) -> bool {
    (node as usize) & 3 != 0 || node.is_null()
}

/// True if the node represents head-of-tree, RESTART or BOUNDS.
fn xas_top(node: *mut XaNode) -> bool {
    (node as usize) <= xas_restart() as usize
}

/// True if the node represents RESTART or an error.
fn xas_frozen(node: *mut XaNode) -> bool {
    (node as usize) & 2 != 0
}

fn xas_reset(xas: &mut XaState) {
    xas.xa_node = xas_restart();
}

fn xas_retry(xas: &mut XaState, entry: *const c_void) -> bool {
    if xa_is_zero(entry) {
        return true;
    }
    if !xa_is_retry(entry) {
        return false;
    }
    xas_reset(xas);
    true
}

fn xas_reload(xas: &XaState) -> *mut c_void {
    if xas.xa_node.is_null() {
        return xa_head(unsafe { &*xas.xa });
    }
    let node = unsafe { &*xas.xa_node };
    // Always the CONFIG_XARRAY_MULTI arm -- see xa_is_sibling's own
    // comment for why that's safe even when the config is off.
    let offset = ((xas.xa_index >> node.shift) & XA_CHUNK_MASK) as u32;
    let entry = xa_entry(node, offset);
    if !xa_is_sibling(entry) {
        return entry;
    }
    let offset = xa_to_sibling(entry) as u32;
    xa_entry(node, offset)
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn xas_set(xas: &mut XaState, index: usize) {
    xas.xa_index = index;
    xas.xa_node = xas_restart();
}

fn xas_is_node(xas: &XaState) -> bool {
    xas_valid(xas) && !xas.xa_node.is_null()
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn xas_set_order(xas: &mut XaState, index: usize, order: u32) {
    // CONFIG_XARRAY_MULTI arm only -- see xa_is_sibling's comment. The
    // header's !CONFIG_XARRAY_MULTI fallback (BUG_ON(order>0);
    // xas_set(index)) is never reproduced here: nothing in xarray.c
    // itself calls xas_set_order() except xa_store_range(), which is
    // gated the same way, so there is no caller to serve in that
    // configuration either way.
    xas.xa_index = if (order as usize) < usize::BITS as usize {
        (index >> order) << order
    } else {
        0
    };
    xas.xa_shift = (order - order % XA_CHUNK_SHIFT as u32) as u8;
    xas.xa_sibs = ((1u32 << (order % XA_CHUNK_SHIFT as u32)) - 1) as u8;
    xas.xa_node = xas_restart();
}

/// Starts a walk. See the C's own doc comment on `xas_start()`.
fn xas_start(xas: &mut XaState) -> *mut c_void {
    if xas_valid(xas) {
        return xas_reload(xas);
    }
    if xas_error(xas) != 0 {
        return ptr::null_mut();
    }

    let entry = xa_head(unsafe { &*xas.xa });
    if !xa_is_node(entry) {
        if xas.xa_index != 0 {
            return set_bounds(xas);
        }
    } else {
        let node = unsafe { &*xa_to_node(entry) };
        if (xas.xa_index >> node.shift) > XA_CHUNK_MASK {
            return set_bounds(xas);
        }
    }

    xas.xa_node = ptr::null_mut();
    entry
}

/// `node` is a raw pointer, not `&XaNode`: the C's `struct xa_node *`
/// parameter is mutable-capable, and `xas.xa_node` (set from it below)
/// is later used for WRITES via `xas_store`'s `rcu_assign_ptr`. Miri
/// caught a real Stacked Borrows violation from an earlier `&XaNode`
/// version of this signature: the shared-reference-derived pointer
/// carried a SharedReadOnly tag, and a later write through
/// `xas.xa_node` (reached via a completely different call path) was
/// UB even though it never touched THIS function's own local `node`
/// binding again -- a value-comparing differential cannot see this
/// class of bug at all, since the computed values are correct either
/// way on real hardware.
fn xas_descend(xas: &mut XaState, node: *const XaNode) -> *mut c_void {
    let n = unsafe { &*node };
    let mut offset = get_offset(xas.xa_index, n);
    let mut entry = xa_entry(n, offset);

    xas.xa_node = node as *mut XaNode;
    while xa_is_sibling(entry) {
        offset = xa_to_sibling(entry) as u32;
        entry = xa_entry(n, offset);
        if n.shift != 0 && xa_is_node(entry) {
            entry = xa_retry_entry();
        }
    }

    xas.xa_offset = offset as u8;
    entry
}

// ---- node allocation / freeing ----
//
// kmem_cache_alloc_lru() itself cannot be called from Rust: since 6.10's
// allocation profiling it is `alloc_hooks(kmem_cache_alloc_lru_noprof(...))`,
// a macro over a static inline with no linkable symbol (logs/allocation.md).
// rust_xa_node_alloc[_nowait]() are the retained-C wrappers
// (port/tree/lib/xarray.c) that make the real call.

const XA_RCU_FREE: *mut Xarray = 1usize as *mut Xarray;

/// `list_empty(&node->private_list)`. `XA_NODE_BUG_ON`'s `list_empty`
/// checks are otherwise dead code under `!XA_DEBUG` (never set by any
/// Kconfig symbol, unset in both real configs) -- but adversarial
/// review pointed out these specific ones cover a use-after-free-on-
/// the-shrinker-list class the value-comparing differential cannot
/// see at all (this project's harness never sets `xa_update`, so
/// `private_list` is never touched by anything the differential
/// exercises), making them pure added coverage rather than redundant.
/// A `struct list_head` is empty iff `next == &self` -- both harness
/// allocators (`radix_tree_stub.c`'s `INIT_LIST_HEAD`, and the Miri
/// harness's own explicit self-link) must set this up at allocation
/// time for these asserts to mean anything rather than misfire on
/// every fresh node.
fn node_private_list_empty(node: &XaNode) -> bool {
    let addr = &node._private_list_or_rcu_head as *const _ as usize;
    node._private_list_or_rcu_head[0] == addr
}

fn xa_node_free(node: *mut XaNode) {
    debug_assert!(node_private_list_empty(unsafe { &*node }));
    unsafe { (*node).array = XA_RCU_FREE };
    let head = unsafe { &raw mut (*node)._private_list_or_rcu_head } as *mut c_void;
    unsafe { call_rcu(head, radix_tree_node_rcu_free) };
}

kernel::kabi_export! {
    xas_destroy,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> base_type void",
}

/// `xas_destroy()`: frees the chain of pre-allocated-but-unused nodes
/// hanging off `xas.xa_alloc`, if any. Unlike `xa_node_free()`, this
/// frees SYNCHRONOUSLY (`radix_tree_node_rcu_free()` called directly,
/// not via `call_rcu()`) -- these nodes were never published into the
/// tree, so no lockless reader can be holding a reference RCU needs to
/// outlive, matching the C's own reasoning exactly.
#[no_mangle]
pub unsafe extern "C" fn xas_destroy(xas: *mut XaState) {
    let xas = unsafe { &mut *xas };
    let mut node = xas.xa_alloc;

    while !node.is_null() {
        debug_assert!(node_private_list_empty(unsafe { &*node }));
        let next = unsafe { (*node).parent };
        let head = unsafe { &raw mut (*node)._private_list_or_rcu_head } as *mut c_void;
        unsafe { radix_tree_node_rcu_free(head) };
        xas.xa_alloc = next;
        node = next;
    }
}

kernel::kabi_export! {
    xas_nomem,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter t#gfp_t gfp ) -> t#bool",
}

/// `xas_nomem()`.
#[no_mangle]
pub unsafe extern "C" fn xas_nomem(xas: *mut XaState, gfp: u32) -> bool {
    let xas_ref = unsafe { &mut *xas };

    if xas_ref.xa_node != xa_error_node(-ENOMEM) {
        unsafe { xas_destroy(xas) };
        return false;
    }
    let account = xa_track_free_flag_account(xas_ref);
    xas_ref.xa_alloc =
        unsafe { rust_xa_node_alloc(xas_ref.xa_lru, gfp, account) };
    if xas_ref.xa_alloc.is_null() {
        return false;
    }
    unsafe { (*xas_ref.xa_alloc).parent = ptr::null_mut() };
    debug_assert!(node_private_list_empty(unsafe { &*xas_ref.xa_alloc }));
    xas_ref.xa_node = xas_restart();
    true
}

/// `__xas_nomem()`: the internal variant used while still holding the
/// lock -- drops it (matching the xarray's own configured lock flavour:
/// plain, irq or bh, via `xa_lock_type()`/`xas_lock_type()`/
/// `xas_unlock_type()`) to allocate if the gfp flags permit sleeping,
/// then reacquires it. Real drivers use all three flavours (e.g.
/// `drivers/firewire/core-cdev.c` uses `XA_FLAGS_LOCK_BH`), so the
/// dispatch is complete rather than narrowed to what this project's own
/// boot path happens to exercise -- see `port/tree/rust/helpers/
/// spinlock.c`'s bh/irq additions.
fn __xas_nomem(xas: &mut XaState, gfp: u32) -> bool {
    if xas.xa_node != xa_error_node(-ENOMEM) {
        unsafe { xas_destroy(xas) };
        return false;
    }
    let lock_type = xa_lock_type(unsafe { &*xas.xa });
    let account = xa_track_free_flag_account(xas);
    if gfpflags_allow_blocking(gfp) {
        xas_unlock_type(xas, lock_type);
        xas.xa_alloc = unsafe { rust_xa_node_alloc(xas.xa_lru, gfp, account) };
        xas_lock_type(xas, lock_type);
    } else {
        xas.xa_alloc = unsafe { rust_xa_node_alloc(xas.xa_lru, gfp, account) };
    }
    if xas.xa_alloc.is_null() {
        return false;
    }
    unsafe { (*xas.xa_alloc).parent = ptr::null_mut() };
    debug_assert!(node_private_list_empty(unsafe { &*xas.xa_alloc }));
    xas.xa_node = xas_restart();
    true
}

fn xa_track_free_flag_account(xas: &XaState) -> i32 {
    let xa = unsafe { &*xas.xa };
    (xa.xa_flags & XA_FLAGS_ACCOUNT != 0) as i32
}

/// `-ENOMEM`. A stable UAPI errno number (`include/uapi/asm-generic/
/// errno-base.h`), not a kernel-internal bit-position enumeration --
/// unlike `__GFP_ACCOUNT`/`__GFP_DIRECT_RECLAIM`, safe to hardcode.
/// Same convention as e.g. `buildid_rs.rs`'s `-22 // -EINVAL`.
const ENOMEM: isize = 12;

fn gfpflags_allow_blocking(gfp: u32) -> bool {
    unsafe { rust_gfp_allows_blocking(gfp) != 0 }
}

fn xas_update(xas: &XaState, node: *mut XaNode) {
    if let Some(update) = xas.xa_update {
        unsafe { update(node) };
    } else {
        // XA_NODE_BUG_ON(node, !list_empty(&node->private_list)): with
        // no update callback, nothing should have put this node on any
        // list -- this harness never sets xa_update, so this is the
        // one site that runs on every single xas_update() call, not
        // just the allocation-adjacent ones above.
        debug_assert!(node_private_list_empty(unsafe { &*node }));
    }
}

fn xas_alloc(xas: &mut XaState, shift: u8) -> *mut XaNode {
    let parent = xas.xa_node;
    let mut node = xas.xa_alloc;

    if xas_invalid(xas) {
        return ptr::null_mut();
    }

    if !node.is_null() {
        xas.xa_alloc = ptr::null_mut();
    } else {
        let account = xa_track_free_flag_account(xas);
        node = unsafe { rust_xa_node_alloc_nowait(xas.xa_lru, account) };
        if node.is_null() {
            xas_set_err(xas, -ENOMEM);
            return ptr::null_mut();
        }
    }

    if !parent.is_null() {
        unsafe {
            (*node).offset = xas.xa_offset;
            (*parent).count += 1;
            // XA_NODE_BUG_ON(node, parent->count > XA_CHUNK_SIZE) in
            // the C -- catches a runaway count far earlier than the u8
            // overflow-check on the `+= 1` above would (that only
            // fires at 256, this fires at 17/65).
            debug_assert!((*parent).count as usize <= XA_CHUNK_SIZE);
        }
        xas_update(xas, parent);
    }
    // XA_NODE_BUG_ON(node, shift > BITS_PER_LONG); XA_NODE_BUG_ON(node,
    // !list_empty(&node->private_list)); in the C, in this order.
    debug_assert!(shift as u32 <= usize::BITS);
    debug_assert!(node_private_list_empty(unsafe { &*node }));
    unsafe {
        (*node).shift = shift;
        (*node).count = 0;
        (*node).nr_values = 0;
        // RCU_INIT_POINTER(node->parent, xas->xa_node) in the C --
        // WRITE_ONCE, no fence (adversary review finding: this one and
        // xas_split_alloc's own were plain stores in an earlier draft).
        ptr::write_volatile(&raw mut (*node).parent, xas.xa_node);
        (*node).array = xas.xa;
    }

    node
}

/// A real acquire/release RCU-visible store to one XArray slot -- either
/// `&xa->xa_head` or `&node->slots[offset]`, hence the raw
/// `*mut *mut c_void` rather than a typed reference. Same treatment as
/// `rbtree_rs.rs`'s `WRITE_ONCE` sites: `write_volatile` alone stops the
/// compiler tearing/eliding/reordering the store; the `fence(Release)`
/// gives it the same release-barrier semantics `rcu_assign_pointer()`
/// documents (xarray.c:820-827's comment on why mark-clearing must be
/// visible before the NULL store is the reason this matters here, not
/// just cargo-culted from rbtree).
fn rcu_assign_ptr(slot: *mut *mut c_void, val: *mut c_void) {
    fence(Ordering::Release);
    unsafe { ptr::write_volatile(slot, val) };
}

/// `RCU_INIT_POINTER()`: `WRITE_ONCE`, no barrier -- early
/// initialisation the caller already knows is not yet visible to any
/// reader.
fn rcu_init_ptr(slot: *mut *mut c_void, val: *mut c_void) {
    unsafe { ptr::write_volatile(slot, val) };
}

fn xas_size(xas: &XaState) -> usize {
    (xas.xa_sibs as usize + 1) << xas.xa_shift
}

fn xas_max(xas: &XaState) -> usize {
    let mut max = xas.xa_index;
    // C: the mask branch is `#ifdef CONFIG_XARRAY_MULTI`-only, compiled
    // out entirely under !MULTI. Needed as a real gate, not just dead
    // code under normal use: xas.xa_shift doubles as "current node's
    // shift during descent" (xas_descend sets it on every walk,
    // multi-order or not) as well as "requested order" here, and
    // xas_reset() only clears xa_node -- so a reused xa_state can carry
    // a stale nonzero xa_shift from an earlier, unrelated descent into
    // this xas_top()-branch check. Under !MULTI that stale value must
    // be ignored, exactly as the C's #ifdef does.
    if cfg!(CONFIG_XARRAY_MULTI) && (xas.xa_shift != 0 || xas.xa_sibs != 0) {
        // C relies on well-defined unsigned wraparound here: once a
        // node's shift is large enough that xas_size() itself
        // overflows to 0, `0 - 1` wraps to usize::MAX, which is the
        // intended "no limit" result (this node's subtree already
        // covers the whole address space). A plain `-` would panic
        // under this kernel's overflow-checks instead of reproducing
        // that intentional wraparound.
        let mask = xas_size(xas).wrapping_sub(1);
        max |= mask;
        if mask == max {
            // Same reasoning as the mask above: when mask (and now
            // max) is usize::MAX from that wraparound, C's `max++`
            // wraps back to 0, which is correct here -- this branch
            // means the whole range is already covered, i.e. "the
            // next index past the end" legitimately wraps.
            max = max.wrapping_add(1);
        }
    }
    max
}

fn max_index(entry: *mut c_void) -> usize {
    if !xa_is_node(entry) {
        return 0;
    }
    // Same intentional-wraparound reasoning as xas_max's mask above:
    // once a deep enough node's shift makes XA_CHUNK_SIZE << shift
    // overflow to 0, `0 - 1` wrapping to usize::MAX is the correct
    // "this subtree covers everything" answer, not a bug to guard
    // against. Reproduced for real: CONFIG_TEST_XARRAY's
    // check_xa_shrink() stores at index 0 then usize::MAX, which grows
    // the tree exactly into this wraparound and panicked here with a
    // plain `-` under overflow-checks.
    (XA_CHUNK_SIZE << unsafe { &*xa_to_node(entry) }.shift).wrapping_sub(1)
}

fn xas_shrink(xas: &mut XaState) {
    let xa = xas.xa;
    let mut node = xas.xa_node;

    loop {
        let n = unsafe { &mut *node };
        // XA_NODE_BUG_ON(node, node->count > XA_CHUNK_SIZE).
        debug_assert!(n.count as usize <= XA_CHUNK_SIZE);
        if n.count != 1 {
            break;
        }
        let mut entry = xa_entry(n, 0);
        if entry.is_null() {
            break;
        }
        if !xa_is_node(entry) && n.shift != 0 {
            break;
        }
        if xa_zero_busy(unsafe { &*xa }) {
            entry = xa_zero_to_null(entry);
        }
        xas.xa_node = xas_bounds();

        rcu_init_ptr(&raw mut (*unsafe { &mut *xa }).xa_head, entry);
        if xa_track_free(unsafe { &*xa }) && !node_get_mark(n, 0, XA_FREE_MARK) {
            xa_mark_clear(unsafe { &mut *xa }, XA_FREE_MARK);
        }

        n.count = 0;
        n.nr_values = 0;
        if !xa_is_node(entry) {
            rcu_init_ptr(&raw mut n.slots[0], xa_retry_entry());
        }
        xas_update(xas, node);
        xa_node_free(node);
        if !xa_is_node(entry) {
            break;
        }
        node = xa_to_node(entry);
        unsafe { (*node).parent = ptr::null_mut() };
    }
}

fn xas_delete_node(xas: &mut XaState) {
    let mut node = xas.xa_node;

    loop {
        let n = unsafe { &mut *node };
        // XA_NODE_BUG_ON(node, node->count > XA_CHUNK_SIZE).
        debug_assert!(n.count as usize <= XA_CHUNK_SIZE);
        if n.count != 0 {
            break;
        }
        let parent = xa_parent(n);
        xas.xa_node = parent;
        xas.xa_offset = n.offset;
        xa_node_free(node);

        if parent.is_null() {
            unsafe { (*xas.xa).xa_head = ptr::null_mut() };
            xas.xa_node = xas_bounds();
            return;
        }

        unsafe { (*parent).slots[xas.xa_offset as usize] = ptr::null_mut() };
        unsafe { (*parent).count -= 1 };
        // XA_NODE_BUG_ON(parent, parent->count > XA_CHUNK_SIZE).
        debug_assert!(unsafe { (*parent).count } as usize <= XA_CHUNK_SIZE);
        node = parent;
        xas_update(xas, node);
    }

    if unsafe { &*node }.parent.is_null() {
        xas_shrink(xas);
    }
}

/// `xas_free_nodes()`. The inner `while (offset == XA_CHUNK_SIZE)` in
/// the C is a REAL loop, not a single pass -- freeing a node that was
/// itself the last child of ITS parent must cascade up and free that
/// parent too, possibly repeatedly. An earlier draft of this function
/// had an unconditional `break` at the bottom of that inner loop,
/// turning the cascade into a single hop and leaving a `xas_update`/
/// `xa_node_free` skipped a level up -- caught by a debug_assert! in
/// `xa_entry` firing on a stale `offset == XA_CHUNK_SIZE` the next
/// iteration read as a real slot index.
fn xas_free_nodes(xas: &XaState, top: *mut XaNode) {
    let mut offset: u32 = 0;
    let mut node = top;

    loop {
        let entry = xa_entry(unsafe { &*node }, offset);

        if unsafe { &*node }.shift != 0 && xa_is_node(entry) {
            node = xa_to_node(entry);
            offset = 0;
            continue;
        }
        if !entry.is_null() {
            rcu_init_ptr(unsafe { &raw mut (*node).slots[offset as usize] }, xa_retry_entry());
        }
        offset += 1;
        while offset as usize == XA_CHUNK_SIZE {
            let n = unsafe { &mut *node };
            let parent = xa_parent(n);
            offset = n.offset as u32 + 1;
            n.count = 0;
            n.nr_values = 0;
            xas_update(xas, node);
            xa_node_free(node);
            if node == top {
                return;
            }
            node = parent;
        }
    }
}

/// `xas_expand()`. Grows the tree by adding root nodes until it can
/// contain `xas.xa_index`, publishing each new root via `rcu_assign_ptr`
/// so lockless readers never see a partially-initialised node became
/// reachable.
fn xas_expand(xas: &mut XaState, mut head: *mut c_void) -> i32 {
    let xa = xas.xa;
    let mut node: *mut XaNode = ptr::null_mut();
    let mut shift: u32 = 0;
    let max = xas_max(xas);

    if head.is_null() {
        if max == 0 {
            return 0;
        }
        while (max >> shift) >= XA_CHUNK_SIZE {
            shift += XA_CHUNK_SHIFT as u32;
        }
        return shift as i32 + XA_CHUNK_SHIFT as i32;
    } else if xa_is_node(head) {
        node = xa_to_node(head);
        shift = unsafe { &*node }.shift as u32 + XA_CHUNK_SHIFT as u32;
    }
    xas.xa_node = ptr::null_mut();

    while max > max_index(head) {
        let mut mark: u32 = 0;

        node = xas_alloc(xas, shift as u8);
        if node.is_null() {
            return -ENOMEM as i32;
        }
        let n = unsafe { &mut *node };
        n.count = 1;
        if xa_is_value(head) {
            n.nr_values = 1;
        }
        rcu_init_ptr(&raw mut n.slots[0], head);

        loop {
            let xa_ref = unsafe { &mut *xa };
            if xa_track_free(xa_ref) && mark == XA_FREE_MARK {
                node_mark_all(n, XA_FREE_MARK);
                if !xa_marked(xa_ref, XA_FREE_MARK) {
                    node_clear_mark(n, 0, XA_FREE_MARK);
                    xa_mark_set(xa_ref, XA_FREE_MARK);
                }
            } else if xa_marked(xa_ref, mark) {
                node_set_mark(n, 0, mark);
            }
            if mark == XA_MARK_MAX {
                break;
            }
            mark = mark_inc(mark);
        }

        if xa_is_node(head) {
            let head_node = unsafe { &mut *xa_to_node(head) };
            head_node.offset = 0;
            rcu_assign_ptr(&raw mut head_node.parent as *mut *mut c_void, node as *mut c_void);
        }
        head = xa_mk_node(node);
        rcu_assign_ptr(&raw mut (*unsafe { &mut *xa }).xa_head, head);
        xas_update(xas, node);

        shift += XA_CHUNK_SHIFT as u32;
    }

    xas.xa_node = node;
    shift as i32
}

/// `xas_create()`: ensures a slot exists for `xas` to store into,
/// expanding/descending the tree as needed. `slot` is a raw
/// `*mut *mut c_void` because it aliases either `&xa->xa_head` or
/// `&node->slots[offset]` over the life of this function, exactly like
/// the C's own `void __rcu **slot`.
fn xas_create(xas: &mut XaState, allow_root: bool) -> *mut c_void {
    let xa = xas.xa;
    let mut entry: *mut c_void;
    let mut slot: *mut *mut c_void;
    let mut node = xas.xa_node;
    let mut shift: i32;
    let order = xas.xa_shift as i32;

    if xas_top(node) {
        entry = xa_head(unsafe { &*xa });
        xas.xa_node = ptr::null_mut();
        if entry.is_null() && xa_zero_busy(unsafe { &*xa }) {
            entry = xa_zero_entry();
        }
        shift = xas_expand(xas, entry);
        if shift < 0 {
            return ptr::null_mut();
        }
        if shift == 0 && !allow_root {
            shift = XA_CHUNK_SHIFT as i32;
        }
        entry = xa_head(unsafe { &*xa });
        slot = unsafe { &raw mut (*xa).xa_head };
    } else if xas_error(xas) != 0 {
        return ptr::null_mut();
    } else if !node.is_null() {
        let n = unsafe { &mut *node };
        let offset = xas.xa_offset;
        shift = n.shift as i32;
        entry = xa_entry(n, offset as u32);
        slot = &raw mut n.slots[offset as usize];
    } else {
        shift = 0;
        entry = xa_head(unsafe { &*xa });
        slot = unsafe { &raw mut (*xa).xa_head };
    }

    while shift > order {
        shift -= XA_CHUNK_SHIFT as i32;
        if entry.is_null() {
            node = xas_alloc(xas, shift as u8);
            if node.is_null() {
                break;
            }
            if xa_track_free(unsafe { &*xa }) {
                node_mark_all(unsafe { &mut *node }, XA_FREE_MARK);
            }
            rcu_assign_ptr(slot, xa_mk_node(node));
        } else if xa_is_node(entry) {
            node = xa_to_node(entry);
        } else {
            break;
        }
        entry = xas_descend(xas, node);
        slot = unsafe { &raw mut (*node).slots[xas.xa_offset as usize] };
    }

    entry
}

fn update_node(xas: &mut XaState, node: *mut XaNode, count: i32, values: i32) {
    if node.is_null() || (count == 0 && values == 0) {
        return;
    }
    let n = unsafe { &mut *node };
    n.count = (n.count as i32 + count) as u8;
    n.nr_values = (n.nr_values as i32 + values) as u8;
    // XA_NODE_BUG_ON(node, node->count > XA_CHUNK_SIZE) and the same
    // for nr_values, in the C. The `as u8` casts just above wrap
    // silently on a bad delta (no overflow-check panic possible from a
    // cast, only from a checked arithmetic op) -- this is exactly the
    // check that would have caught the count/values sign-inversion bug
    // on its first occurrence instead of needing the invariant checker
    // to find count=255 several operations downstream.
    debug_assert!(n.count as usize <= XA_CHUNK_SIZE);
    debug_assert!(n.nr_values as usize <= XA_CHUNK_SIZE);
    xas_update(xas, node);
    if count < 0 {
        xas_delete_node(xas);
    }
}

kernel::kabi_export! {
    xas_store,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter pointer_type { base_type void } entry ) -> pointer_type { base_type void }",
}

/// `xas_store()`. The insert/erase engine every mutating entry point in
/// this file ultimately calls.
#[no_mangle]
pub unsafe extern "C" fn xas_store(xas: *mut XaState, entry: *mut c_void) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    let node: *mut XaNode;
    let mut slot: *mut *mut c_void = unsafe { &raw mut (*xas.xa).xa_head };
    let mut offset: u32;
    let max: u32;
    let mut count: i32 = 0;
    let mut values: i32 = 0;
    let mut first: *mut c_void;
    let mut next: *mut c_void;
    let value = xa_is_value(entry);
    let mut entry = entry;

    if !entry.is_null() {
        let allow_root = !xa_is_node(entry) && !xa_is_zero(entry);
        first = xas_create(xas, allow_root);
    } else {
        first = unsafe { xas_load(xas) };
    }

    if xas_invalid(xas) {
        return first;
    }
    node = xas.xa_node;
    if !node.is_null() && (xas.xa_shift as usize) < unsafe { &*node }.shift as usize {
        xas.xa_sibs = 0;
    }
    if first == entry && xas.xa_sibs == 0 {
        return first;
    }

    next = first;
    offset = xas.xa_offset as u32;
    max = xas.xa_offset as u32 + xas.xa_sibs as u32;
    if !node.is_null() {
        slot = unsafe { &raw mut (*node).slots[offset as usize] };
        if xas.xa_sibs != 0 {
            xas_squash_marks(xas);
        }
    }
    if entry.is_null() {
        unsafe { xas_init_marks(xas) };
    }

    loop {
        // Must clear the marks before setting the entry to NULL,
        // otherwise xas_for_each_marked may find a NULL entry and stop
        // early. rcu_assign_ptr's release fence makes the mark-clearing
        // stores (xas_squash_marks/xas_init_marks, above) visible before
        // this store -- see xarray.c:820-827's comment.
        rcu_assign_ptr(slot, entry);
        if xa_is_node(next) && (node.is_null() || unsafe { &*node }.shift != 0) {
            xas_free_nodes(xas, xa_to_node(next));
        }
        if node.is_null() {
            break;
        }
        // C's `!next - !entry`: `!ptr` means "ptr is null" (1) here, NOT
        // "not null" -- `.is_null()` already matches that directly, no
        // extra `!` needed. (Found via a real 255-vs-1 count mismatch:
        // the sign was backwards, inflating every occupied-slot delta
        // by -1 instead of +1.)
        count += next.is_null() as i32 - entry.is_null() as i32;
        values += !xa_is_value(first) as i32 - !value as i32;
        if !entry.is_null() {
            if offset == max {
                break;
            }
            if !xa_is_sibling(entry) {
                entry = xa_mk_sibling(xas.xa_offset as u32);
            }
        } else if offset == XA_CHUNK_MASK as u32 {
            break;
        }
        offset += 1;
        next = xa_entry(unsafe { &*node }, offset);
        if !xa_is_sibling(next) {
            if entry.is_null() && offset > max {
                break;
            }
            first = next;
        }
        slot = unsafe { &raw mut (*node).slots[offset as usize] };
    }

    update_node(xas, node, count, values);
    first
}

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
kernel::kabi_rule!("type_string", "s#callback_head",
    "structure_type callback_head { member pointer_type { s#callback_head } next data_member_location(0) , member pointer_type { subroutine_type ( formal_parameter pointer_type { s#callback_head } ) -> base_type void } func data_member_location(8) } byte_size(16) alignment(8)");
kernel::kabi_rule!("type_string", "s#list_head",
    "structure_type list_head { member pointer_type { s#list_head } next data_member_location(0) , member pointer_type { s#list_head } prev data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#list_lru",
    "structure_type list_lru { }");
kernel::kabi_rule!("type_string", "s#qspinlock",
    "structure_type qspinlock { member union_type { member t#atomic_t val data_member_location(0) , member structure_type { member t#u8 locked data_member_location(0) , member t#u8 pending data_member_location(1) } byte_size(2) data_member_location(0) , member structure_type { member t#u16 locked_pending data_member_location(0) , member t#u16 tail data_member_location(2) } byte_size(4) data_member_location(0) } byte_size(4) data_member_location(0) } byte_size(4)");
kernel::kabi_rule!("type_string", "s#raw_spinlock",
    "structure_type raw_spinlock { member t#arch_spinlock_t raw_lock data_member_location(0) } byte_size(4)");
kernel::kabi_rule!("type_string", "s#spinlock",
    "structure_type spinlock { member union_type { member s#raw_spinlock rlock data_member_location(0) } byte_size(4) data_member_location(0) } byte_size(4)");
kernel::kabi_rule!("type_string", "s#xa_limit",
    "structure_type xa_limit { member t#u32 max data_member_location(0) , member t#u32 min data_member_location(4) } byte_size(8)");
kernel::kabi_rule!("type_string", "s#xa_node",
    "structure_type xa_node { member base_type unsigned char byte_size(1) encoding(8) shift data_member_location(0) , member base_type unsigned char byte_size(1) encoding(8) offset data_member_location(1) , member base_type unsigned char byte_size(1) encoding(8) count data_member_location(2) , member base_type unsigned char byte_size(1) encoding(8) nr_values data_member_location(3) , member pointer_type { s#xa_node } parent data_member_location(8) , member pointer_type { s#xarray } array data_member_location(16) , member union_type { member s#list_head private_list data_member_location(0) , member s#callback_head callback_head data_member_location(0) } byte_size(16) data_member_location(24) , member array_type[64] { pointer_type { base_type void } } slots data_member_location(40) , member union_type { member array_type[3][1] { base_type unsigned long byte_size(8) encoding(7) } tags data_member_location(0) , member array_type[3][1] { base_type unsigned long byte_size(8) encoding(7) } marks data_member_location(0) } byte_size(24) data_member_location(552) } byte_size(576)");
kernel::kabi_rule!("type_string", "s#xa_state",
    "structure_type xa_state { member pointer_type { s#xarray } xa data_member_location(0) , member base_type unsigned long byte_size(8) encoding(7) xa_index data_member_location(8) , member base_type unsigned char byte_size(1) encoding(8) xa_shift data_member_location(16) , member base_type unsigned char byte_size(1) encoding(8) xa_sibs data_member_location(17) , member base_type unsigned char byte_size(1) encoding(8) xa_offset data_member_location(18) , member base_type unsigned char byte_size(1) encoding(8) xa_pad data_member_location(19) , member pointer_type { s#xa_node } xa_node data_member_location(24) , member pointer_type { s#xa_node } xa_alloc data_member_location(32) , member t#xa_update_node_t xa_update data_member_location(40) , member pointer_type { s#list_lru } xa_lru data_member_location(48) } byte_size(56)");
kernel::kabi_rule!("type_string", "s#xarray",
    "structure_type xarray { member t#spinlock_t xa_lock data_member_location(0) , member t#gfp_t xa_flags data_member_location(4) , member pointer_type { base_type void } xa_head data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#__u16",
    "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#arch_spinlock_t",
    "typedef_type arch_spinlock_t { s#qspinlock }");
kernel::kabi_rule!("type_string", "t#atomic_t",
    "typedef_type atomic_t { structure_type { member base_type int byte_size(4) encoding(5) counter data_member_location(0) } byte_size(4) }");
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#gfp_t",
    "typedef_type gfp_t { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#spinlock_t",
    "typedef_type spinlock_t { s#spinlock }");
kernel::kabi_rule!("type_string", "t#u16",
    "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#xa_mark_t",
    "typedef_type xa_mark_t { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#xa_update_node_t",
    "typedef_type xa_update_node_t { pointer_type { subroutine_type ( formal_parameter pointer_type { s#xa_node } ) -> base_type void } }");

kernel::kabi_export! {
    xas_load,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> pointer_type { base_type void }",
}

/// `xas_load()`.
#[no_mangle]
pub unsafe extern "C" fn xas_load(xas: *mut XaState) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    let mut entry = xas_start(xas);

    while xa_is_node(entry) {
        let node = xa_to_node(entry);
        if xas.xa_shift as usize > unsafe { &*node }.shift as usize {
            break;
        }
        entry = xas_descend(xas, node);
        if unsafe { &*node }.shift == 0 {
            break;
        }
    }
    entry
}

kernel::kabi_export! {
    xas_set_mark,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#xa_state } } xas , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `xas_set_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xas_set_mark(xas: *const XaState, mark: u32) {
    let xas = unsafe { &*xas };
    let mut node = xas.xa_node;
    let mut offset = xas.xa_offset as u32;

    if xas_invalid(xas) {
        return;
    }
    while !node.is_null() {
        let n = unsafe { &mut *node };
        if node_set_mark(n, offset, mark) {
            return;
        }
        offset = n.offset as u32;
        node = xa_parent(n);
    }
    let xa = unsafe { &mut *xas.xa };
    if !xa_marked(xa, mark) {
        xa_mark_set(xa, mark);
    }
}

kernel::kabi_export! {
    xas_clear_mark,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#xa_state } } xas , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `xas_clear_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xas_clear_mark(xas: *const XaState, mark: u32) {
    let xas = unsafe { &*xas };
    let mut node = xas.xa_node;
    let mut offset = xas.xa_offset as u32;

    if xas_invalid(xas) {
        return;
    }
    while !node.is_null() {
        let n = unsafe { &mut *node };
        if !node_clear_mark(n, offset, mark) {
            return;
        }
        if node_any_mark(n, mark) {
            return;
        }
        offset = n.offset as u32;
        node = xa_parent(n);
    }
    let xa = unsafe { &mut *xas.xa };
    if xa_marked(xa, mark) {
        xa_mark_clear(xa, mark);
    }
}

kernel::kabi_export! {
    xas_init_marks,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#xa_state } } xas ) -> base_type void",
}

/// `xas_init_marks()`.
#[no_mangle]
pub unsafe extern "C" fn xas_init_marks(xas: *const XaState) {
    let mut mark: u32 = 0;
    loop {
        if xa_track_free(unsafe { &*(*xas).xa }) && mark == XA_FREE_MARK {
            unsafe { xas_set_mark(xas, mark) };
        } else {
            unsafe { xas_clear_mark(xas, mark) };
        }
        if mark == XA_MARK_MAX {
            break;
        }
        mark = mark_inc(mark);
    }
}

// ---- plain xa_* API: thin, lock-taking wrappers over the xas_* engine ----

/// `__XA_STATE()`/`XA_STATE()`: every plain `xa_*` entry point below
/// constructs its own `xa_state` locally, exactly like the C macro
/// expands inline in each function's own body -- there is no shared
/// `xa_state` passed in from the caller for these.
fn xa_state_new(xa: *mut Xarray, index: usize) -> XaState {
    XaState {
        xa,
        xa_index: index,
        xa_shift: 0,
        xa_sibs: 0,
        xa_offset: 0,
        xa_pad: 0,
        xa_node: xas_restart(),
        xa_alloc: ptr::null_mut(),
        xa_update: None,
        xa_lru: ptr::null_mut(),
    }
}

/// `xas_result()`.
fn xas_result(xas: &XaState, curr: *mut c_void) -> *mut c_void {
    if xas_error(xas) != 0 {
        xas.xa_node as *mut c_void
    } else {
        curr
    }
}

kernel::kabi_export! {
    xa_load,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index ) -> pointer_type { base_type void }",
}

/// `xa_load()`.
#[no_mangle]
pub unsafe extern "C" fn xa_load(xa: *mut Xarray, index: usize) -> *mut c_void {
    let mut xas = xa_state_new(xa, index);
    let mut entry;

    unsafe { rust_helper_rcu_read_lock() };
    loop {
        entry = xa_zero_to_null(unsafe { xas_load(&mut xas) });
        if !xas_retry(&mut xas, entry) {
            break;
        }
    }
    unsafe { rust_helper_rcu_read_unlock() };
    entry
}

kernel::kabi_export! {
    __xa_erase,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index ) -> pointer_type { base_type void }",
}

/// `__xa_erase()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_erase(xa: *mut Xarray, index: usize) -> *mut c_void {
    let mut xas = xa_state_new(xa, index);
    let stored = xa_zero_to_null(unsafe { xas_store(&mut xas, ptr::null_mut()) });
    xas_result(&xas, stored)
}

kernel::kabi_export! {
    xa_erase,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index ) -> pointer_type { base_type void }",
}

/// `xa_erase()`.
#[no_mangle]
pub unsafe extern "C" fn xa_erase(xa: *mut Xarray, index: usize) -> *mut c_void {
    xa_lock(xa);
    let entry = unsafe { __xa_erase(xa, index) };
    xa_unlock(xa);
    entry
}

const EINVAL: isize = 22;
const EBUSY: isize = 16;

kernel::kabi_export! {
    __xa_store,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter pointer_type { base_type void } entry , formal_parameter t#gfp_t gfp ) -> pointer_type { base_type void }",
}

/// `__xa_store()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_store(
    xa: *mut Xarray,
    index: usize,
    mut entry: *mut c_void,
    gfp: u32,
) -> *mut c_void {
    let mut xas = xa_state_new(xa, index);
    let mut curr: *mut c_void;

    if kernel::kabi_warn_on_once!(xa_is_advanced(entry)) {
        return xa_error_node(-EINVAL) as *mut c_void;
    }
    if xa_track_free(unsafe { &*xa }) && entry.is_null() {
        entry = xa_zero_entry();
    }

    loop {
        curr = unsafe { xas_store(&mut xas, entry) };
        if xa_track_free(unsafe { &*xa }) {
            unsafe { xas_clear_mark(&xas, XA_FREE_MARK) };
        }
        if !__xas_nomem(&mut xas, gfp) {
            break;
        }
    }

    xas_result(&xas, xa_zero_to_null(curr))
}

kernel::kabi_export! {
    xa_store,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter pointer_type { base_type void } entry , formal_parameter t#gfp_t gfp ) -> pointer_type { base_type void }",
}

/// `xa_store()`.
#[no_mangle]
pub unsafe extern "C" fn xa_store(
    xa: *mut Xarray,
    index: usize,
    entry: *mut c_void,
    gfp: u32,
) -> *mut c_void {
    xa_lock(xa);
    let curr = unsafe { __xa_store(xa, index, entry, gfp) };
    xa_unlock(xa);
    curr
}

/// `__xa_cmpxchg_raw()` (the C's own `static inline` helper, not itself
/// exported -- inlined into `__xa_cmpxchg()`/`__xa_insert()` here rather
/// than kept as a separate private function, since Rust has no
/// C-style forward-declared-static-inline ordering constraint to work
/// around).
fn xa_cmpxchg_raw(
    xa: *mut Xarray,
    index: usize,
    old: *mut c_void,
    entry: *mut c_void,
    gfp: u32,
) -> *mut c_void {
    let mut xas = xa_state_new(xa, index);
    let mut curr: *mut c_void;

    if kernel::kabi_warn_on_once!(xa_is_advanced(entry)) {
        return xa_error_node(-EINVAL) as *mut c_void;
    }

    loop {
        curr = unsafe { xas_load(&mut xas) };
        if curr == old {
            unsafe { xas_store(&mut xas, entry) };
            if xa_track_free(unsafe { &*xa }) && !entry.is_null() && curr.is_null() {
                unsafe { xas_clear_mark(&xas, XA_FREE_MARK) };
            }
        }
        if !__xas_nomem(&mut xas, gfp) {
            break;
        }
    }

    xas_result(&xas, curr)
}

kernel::kabi_export! {
    __xa_cmpxchg,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter pointer_type { base_type void } old , formal_parameter pointer_type { base_type void } entry , formal_parameter t#gfp_t gfp ) -> pointer_type { base_type void }",
}

/// `__xa_cmpxchg()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_cmpxchg(
    xa: *mut Xarray,
    index: usize,
    old: *mut c_void,
    entry: *mut c_void,
    gfp: u32,
) -> *mut c_void {
    xa_zero_to_null(xa_cmpxchg_raw(xa, index, old, entry, gfp))
}

kernel::kabi_export! {
    __xa_insert,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter pointer_type { base_type void } entry , formal_parameter t#gfp_t gfp ) -> base_type int byte_size(4) encoding(5)",
}

/// `__xa_insert()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_insert(
    xa: *mut Xarray,
    index: usize,
    mut entry: *mut c_void,
    gfp: u32,
) -> i32 {
    if entry.is_null() {
        entry = xa_zero_entry();
    }
    let curr = xa_cmpxchg_raw(xa, index, ptr::null_mut(), entry, gfp);
    let errno = xa_err(curr);
    if errno != 0 {
        return errno;
    }
    if !curr.is_null() {
        -(EBUSY as i32)
    } else {
        0
    }
}

// ---- mark API: plain wrappers ----

kernel::kabi_export! {
    xas_get_mark,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#xa_state } } xas , formal_parameter t#xa_mark_t mark ) -> t#bool",
}

/// `xas_get_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xas_get_mark(xas: *const XaState, mark: u32) -> bool {
    let xas = unsafe { &*xas };
    if xas_invalid(xas) {
        return false;
    }
    if xas.xa_node.is_null() {
        return xa_marked(unsafe { &*xas.xa }, mark);
    }
    node_get_mark(unsafe { &*xas.xa_node }, xas.xa_offset as u32, mark)
}

kernel::kabi_export! {
    xa_get_mark,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter t#xa_mark_t mark ) -> t#bool",
}

/// `xa_get_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xa_get_mark(xa: *mut Xarray, index: usize, mark: u32) -> bool {
    let mut xas = xa_state_new(xa, index);
    let mut entry;

    unsafe { rust_helper_rcu_read_lock() };
    entry = xas_start(&mut xas);
    while unsafe { xas_get_mark(&xas, mark) } {
        if !xa_is_node(entry) {
            unsafe { rust_helper_rcu_read_unlock() };
            return true;
        }
        entry = xas_descend(&mut xas, xa_to_node(entry));
    }
    unsafe { rust_helper_rcu_read_unlock() };
    false
}

kernel::kabi_export! {
    __xa_set_mark,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `__xa_set_mark()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_set_mark(xa: *mut Xarray, index: usize, mark: u32) {
    let mut xas = xa_state_new(xa, index);
    let entry = unsafe { xas_load(&mut xas) };
    if !entry.is_null() {
        unsafe { xas_set_mark(&xas, mark) };
    }
}

kernel::kabi_export! {
    __xa_clear_mark,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `__xa_clear_mark()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_clear_mark(xa: *mut Xarray, index: usize, mark: u32) {
    let mut xas = xa_state_new(xa, index);
    let entry = unsafe { xas_load(&mut xas) };
    if !entry.is_null() {
        unsafe { xas_clear_mark(&xas, mark) };
    }
}

kernel::kabi_export! {
    xa_set_mark,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `xa_set_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xa_set_mark(xa: *mut Xarray, index: usize, mark: u32) {
    xa_lock(xa);
    unsafe { __xa_set_mark(xa, index, mark) };
    xa_unlock(xa);
}

kernel::kabi_export! {
    xa_clear_mark,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index , formal_parameter t#xa_mark_t mark ) -> base_type void",
}

/// `xa_clear_mark()`.
#[no_mangle]
pub unsafe extern "C" fn xa_clear_mark(xa: *mut Xarray, index: usize, mark: u32) {
    xa_lock(xa);
    unsafe { __xa_clear_mark(xa, index, mark) };
    xa_unlock(xa);
}

// ---- multi-order / split ----

#[cfg(CONFIG_XARRAY_MULTI)]
fn node_mark_slots(node: &mut XaNode, sibs: u32, mark: u32) {
    if sibs == 0 {
        node_mark_all(node, mark);
    } else {
        let mut i = 0u32;
        while (i as usize) < XA_CHUNK_SIZE {
            node_set_mark(node, i, mark);
            i += sibs + 1;
        }
    }
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn node_get_marks(node: &XaNode, offset: u32) -> u32 {
    let mut marks: u32 = 0;
    let mut mark: u32 = XA_MARK_0;
    loop {
        if node_get_mark(node, offset, mark) {
            marks |= 1 << mark;
        }
        if mark == XA_MARK_MAX {
            break;
        }
        mark = mark_inc(mark);
    }
    marks
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn node_set_marks(node: &mut XaNode, offset: u32, child: *mut XaNode, sibs: u32, marks: u32) {
    let mut mark: u32 = XA_MARK_0;
    loop {
        if marks & (1 << mark) != 0 {
            node_set_mark(node, offset, mark);
            if !child.is_null() {
                node_mark_slots(unsafe { &mut *child }, sibs, mark);
            }
        }
        if mark == XA_MARK_MAX {
            break;
        }
        mark = mark_inc(mark);
    }
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn xas_init_node_for_split(xas: &XaState, node: *mut XaNode, entry: *mut c_void) {
    if node.is_null() {
        return;
    }
    let n = unsafe { &mut *node };
    n.array = xas.xa;
    let mask = xas.xa_sibs as usize;
    let mut sibling: *mut c_void = ptr::null_mut();
    for i in 0..XA_CHUNK_SIZE {
        if i & mask == 0 {
            rcu_init_ptr(&raw mut n.slots[i], entry);
            sibling = xa_mk_sibling(i as u32);
        } else {
            rcu_init_ptr(&raw mut n.slots[i], sibling);
        }
    }
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xas_split_alloc,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter pointer_type { base_type void } entry , formal_parameter base_type unsigned int byte_size(4) encoding(7) order , formal_parameter t#gfp_t gfp ) -> base_type void",
}

/// `xas_split_alloc()`. `rust_xa_node_alloc()` is called with
/// `account=0` -- this is the one allocation site in the file that does
/// NOT inherit `XA_FLAGS_ACCOUNT` (confirmed against the C: no such
/// check exists in this function's body, unlike `xas_alloc`/
/// `xas_nomem`/`__xas_nomem`/`xas_try_split`).
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xas_split_alloc(
    xas: *mut XaState,
    entry: *mut c_void,
    order: u32,
    gfp: u32,
) {
    let xas = unsafe { &mut *xas };
    let mut sibs = (1u32 << (order % XA_CHUNK_SHIFT as u32)) - 1;

    if kernel::warn_on!(xas.xa_shift as u32 + 2 * XA_CHUNK_SHIFT as u32 <= order) {
        unsafe { xas_destroy(xas) };
        xas_set_err(xas, -ENOMEM);
        return;
    }
    if xas.xa_shift as u32 + XA_CHUNK_SHIFT as u32 > order {
        return;
    }

    loop {
        let node = unsafe { rust_xa_node_alloc(xas.xa_lru, gfp, 0) };
        if node.is_null() {
            unsafe { xas_destroy(xas) };
            xas_set_err(xas, -ENOMEM);
            return;
        }
        xas_init_node_for_split(xas, node, entry);
        // RCU_INIT_POINTER(node->parent, xas->xa_alloc) in the C.
        unsafe { ptr::write_volatile(&raw mut (*node).parent, xas.xa_alloc) };
        xas.xa_alloc = node;
        if sibs == 0 {
            break;
        }
        sibs -= 1;
    }
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xas_split,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter pointer_type { base_type void } entry , formal_parameter base_type unsigned int byte_size(4) encoding(7) order ) -> base_type void",
}

/// `xas_split()`. The outer `do {...} while (offset-- > xas->xa_offset)`
/// loop and the canon-branch's own inner `while (offset > canon)
/// node->slots[offset--] = ...` loop in the C share ONE mutable
/// `offset` -- the inner loop can walk `offset` all the way down to
/// `canon` before the outer loop's own postfix-decrement check ever
/// runs, so a flat (non-descending) split's outer loop executes exactly
/// once no matter how many siblings there are. Reproduced here with the
/// same single shared `offset`, not two independently-stepped ones.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xas_split(xas: *mut XaState, entry: *mut c_void, order: u32) {
    let xas = unsafe { &mut *xas };
    // Order-derived, used ONLY for the initial `offset` -- every other
    // use in this function (canon, node_set_marks, the values formula)
    // is `xas.xa_sibs` (the state's own sibs), not this local.
    let sibs = (1u32 << (order % XA_CHUNK_SHIFT as u32)) - 1;
    let curr = unsafe { xas_load(xas) };
    let mut values: i32 = 0;

    let node = xas.xa_node;
    if xas_top(node) {
        return;
    }
    let n = unsafe { &mut *node };
    let marks = node_get_marks(n, xas.xa_offset as u32);
    let mut offset = xas.xa_offset as u32 + sibs;

    loop {
        if (xas.xa_shift as u32) < n.shift as u32 {
            let child = xas.xa_alloc;
            let c = unsafe { &mut *child };
            xas.xa_alloc = c.parent;
            c.shift = n.shift - XA_CHUNK_SHIFT as u8;
            c.offset = offset as u8;
            c.count = XA_CHUNK_SIZE as u8;
            c.nr_values = if xa_is_value(entry) { XA_CHUNK_SIZE as u8 } else { 0 };
            unsafe { ptr::write_volatile(&raw mut c.parent, node) };
            node_set_marks(n, offset, child, xas.xa_sibs as u32, marks);
            rcu_assign_ptr(
                &raw mut n.slots[offset as usize],
                xa_mk_node(child),
            );
            if xa_is_value(curr) {
                values -= 1;
            }
            xas_update(xas, child);
        } else {
            let canon = offset - xas.xa_sibs as u32;
            node_set_marks(n, canon, ptr::null_mut(), 0, marks);
            rcu_assign_ptr(&raw mut n.slots[canon as usize], entry);
            while offset > canon {
                rcu_assign_ptr(&raw mut n.slots[offset as usize], xa_mk_sibling(canon));
                offset -= 1;
            }
            values += (xa_is_value(entry) as i32 - xa_is_value(curr) as i32)
                * (xas.xa_sibs as i32 + 1);
        }

        let old_offset = offset;
        offset = offset.wrapping_sub(1);
        if !(old_offset > xas.xa_offset as u32) {
            break;
        }
    }

    n.nr_values = (n.nr_values as i32 + values) as u8;
    xas_update(xas, node);
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xas_try_split_min_order,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) order ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// `xas_try_split_min_order()`.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xas_try_split_min_order(order: u32) -> u32 {
    if order % XA_CHUNK_SHIFT as u32 == 0 {
        if order == 0 {
            0
        } else {
            order - 1
        }
    } else {
        order - (order % XA_CHUNK_SHIFT as u32)
    }
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xas_try_split,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter pointer_type { base_type void } entry , formal_parameter base_type unsigned int byte_size(4) encoding(7) order ) -> base_type void",
}

/// `xas_try_split()`. Uses `rust_xa_node_alloc_nowait()` (GFP_NOWAIT
/// base, same as `xas_alloc()`) since this is the other call site that
/// hardcodes `gfp = GFP_NOWAIT` before conditionally ORing in
/// `__GFP_ACCOUNT`, unlike `xas_split_alloc()`'s caller-supplied gfp.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xas_try_split(xas: *mut XaState, entry: *mut c_void, order: u32) {
    let xas = unsafe { &mut *xas };
    let sibs = (1u32 << (order % XA_CHUNK_SHIFT as u32)) - 1;
    let curr = unsafe { xas_load(xas) };
    let mut values: i32 = 0;

    let node = xas.xa_node;
    if xas_top(node) {
        return;
    }
    let n = unsafe { &mut *node };
    let account = xa_track_free_flag_account(xas);
    let marks = node_get_marks(n, xas.xa_offset as u32);
    let offset = xas.xa_offset as u32 + sibs;

    if (xas.xa_shift as u32) < n.shift as u32 {
        let mut child = xas.xa_alloc;
        let expected_sibs = (1u32 << ((order - 1) % XA_CHUNK_SHIFT as u32)) - 1;

        if sibs != 0 || xas.xa_sibs as u32 != expected_sibs {
            unsafe { xas_destroy(xas) };
            xas_set_err(xas, -EINVAL);
            return;
        }

        if child.is_null() {
            child = unsafe { rust_xa_node_alloc_nowait(xas.xa_lru, account) };
            if child.is_null() {
                unsafe { xas_destroy(xas) };
                xas_set_err(xas, -ENOMEM);
                return;
            }
            unsafe { ptr::write_volatile(&raw mut (*child).parent, xas.xa_alloc) };
        }
        xas_init_node_for_split(xas, child, entry);

        let c = unsafe { &mut *child };
        xas.xa_alloc = c.parent;
        c.shift = n.shift - XA_CHUNK_SHIFT as u8;
        c.offset = offset as u8;
        c.count = XA_CHUNK_SIZE as u8;
        c.nr_values = if xa_is_value(entry) { XA_CHUNK_SIZE as u8 } else { 0 };
        unsafe { ptr::write_volatile(&raw mut c.parent, node) };
        node_set_marks(n, offset, child, xas.xa_sibs as u32, marks);
        rcu_assign_ptr(&raw mut n.slots[offset as usize], xa_mk_node(child));
        if xa_is_value(curr) {
            values -= 1;
        }
        xas_update(xas, child);
    } else {
        let mut offset = offset;
        loop {
            let canon = offset - xas.xa_sibs as u32;
            node_set_marks(n, canon, ptr::null_mut(), 0, marks);
            rcu_assign_ptr(&raw mut n.slots[canon as usize], entry);
            while offset > canon {
                rcu_assign_ptr(&raw mut n.slots[offset as usize], xa_mk_sibling(canon));
                offset -= 1;
            }
            values += (xa_is_value(entry) as i32 - xa_is_value(curr) as i32)
                * (xas.xa_sibs as i32 + 1);

            let old_offset = offset;
            offset = offset.wrapping_sub(1);
            if !(old_offset > xas.xa_offset as u32) {
                break;
            }
        }
    }

    n.nr_values = (n.nr_values as i32 + values) as u8;
    xas_update(xas, node);
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xas_get_order,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> base_type int byte_size(4) encoding(5)",
}

/// `xas_get_order()`.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xas_get_order(xas: *mut XaState) -> i32 {
    let xas = unsafe { &mut *xas };
    let mut order: i32 = 0;

    if xas.xa_node.is_null() {
        return 0;
    }
    let n = unsafe { &*xas.xa_node };
    loop {
        let slot = xas.xa_offset as u32 + (1 << order);
        if slot as usize >= XA_CHUNK_SIZE {
            break;
        }
        if !xa_is_sibling(xa_entry(n, slot)) {
            break;
        }
        order += 1;
    }
    order + n.shift as i32
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xa_get_order,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) index ) -> base_type int byte_size(4) encoding(5)",
}

/// `xa_get_order()`.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xa_get_order(xa: *mut Xarray, index: usize) -> i32 {
    let mut xas = xa_state_new(xa, index);
    let mut order = 0;

    unsafe { rust_helper_rcu_read_lock() };
    let entry = unsafe { xas_load(&mut xas) };
    if !entry.is_null() {
        order = unsafe { xas_get_order(&mut xas) };
    }
    unsafe { rust_helper_rcu_read_unlock() };
    order
}

#[cfg(CONFIG_XARRAY_MULTI)]
fn xas_set_range(xas: &mut XaState, first_arg: usize, last: usize) {
    let mut shift: u32 = 0;
    let mut sibs = last - first_arg;
    let mut offset: usize = XA_CHUNK_MASK;
    let mut first = first_arg;

    xas_set(xas, first);

    while first & XA_CHUNK_MASK == 0 {
        if sibs < XA_CHUNK_MASK {
            break;
        }
        if sibs == XA_CHUNK_MASK && offset < XA_CHUNK_MASK {
            break;
        }
        shift += XA_CHUNK_SHIFT as u32;
        if offset == XA_CHUNK_MASK {
            offset = sibs & XA_CHUNK_MASK;
        }
        sibs >>= XA_CHUNK_SHIFT;
        first >>= XA_CHUNK_SHIFT;
    }

    offset = first & XA_CHUNK_MASK;
    if offset + sibs > XA_CHUNK_MASK {
        sibs = XA_CHUNK_MASK - offset;
    }
    // Same intentional-wraparound shape as xas_max()/max_index()/
    // xas_create_range(): a range spanning up to usize::MAX (a real,
    // reachable xa_store_range(xa, 0, usize::MAX, ...) call -- first
    // stays 0 while sibs shrinks and shift grows into the ~58-66
    // range through this function's own preceding loop) makes
    // `(first+sibs+1) << shift` overflow to 0, and the C's `- 1`
    // relies on that wrapping to usize::MAX ("no shrink needed, this
    // sibling range already reaches the end") rather than panicking.
    if (((first + sibs + 1) << shift).wrapping_sub(1)) > last {
        sibs -= 1;
    }

    xas.xa_shift = shift as u8;
    xas.xa_sibs = sibs as u8;
}

#[cfg(CONFIG_XARRAY_MULTI)]
kernel::kabi_export! {
    xa_store_range,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter base_type unsigned long byte_size(8) encoding(7) first , formal_parameter base_type unsigned long byte_size(8) encoding(7) last , formal_parameter pointer_type { base_type void } entry , formal_parameter t#gfp_t gfp ) -> pointer_type { base_type void }",
}

/// `xa_store_range()`.
#[cfg(CONFIG_XARRAY_MULTI)]
#[no_mangle]
pub unsafe extern "C" fn xa_store_range(
    xa: *mut Xarray,
    mut first: usize,
    last: usize,
    entry: *mut c_void,
    gfp: u32,
) -> *mut c_void {
    let mut xas = xa_state_new(xa, 0);

    if kernel::kabi_warn_on_once!(xa_is_internal(entry)) {
        return xa_error_node(-EINVAL) as *mut c_void;
    }
    if last < first {
        return xa_error_node(-EINVAL) as *mut c_void;
    }

    loop {
        xa_lock(xa);
        'body: {
            if !entry.is_null() {
                let order = if last.wrapping_add(1) != 0 {
                    (last + 1).trailing_zeros()
                } else {
                    usize::BITS
                };
                xas_set_order(&mut xas, last, order);
                xas_create(&mut xas, true);
                if xas_error(&xas) != 0 {
                    break 'body;
                }
            }
            loop {
                xas_set_range(&mut xas, first, last);
                unsafe { xas_store(&mut xas, entry) };
                if xas_error(&xas) != 0 {
                    break 'body;
                }
                first += xas_size(&xas);
                if first > last {
                    break;
                }
            }
        }
        xa_unlock(xa);
        if !unsafe { xas_nomem(&mut xas, gfp) } {
            break;
        }
    }

    xas_result(&xas, ptr::null_mut())
}

// ---- traversal ----

kernel::kabi_export! {
    __xas_prev,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> pointer_type { base_type void }",
}

/// `__xas_prev()`.
#[no_mangle]
pub unsafe extern "C" fn __xas_prev(xas: *mut XaState) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    if !xas_frozen(xas.xa_node) {
        xas.xa_index = xas.xa_index.wrapping_sub(1);
    }
    if xas.xa_node.is_null() {
        return set_bounds(xas);
    }
    if xas_not_node(xas.xa_node) {
        return unsafe { xas_load(xas) };
    }
    if xas.xa_offset != get_offset(xas.xa_index, unsafe { &*xas.xa_node }) as u8 {
        xas.xa_offset = xas.xa_offset.wrapping_sub(1);
    }
    while xas.xa_offset == 255 {
        xas.xa_offset = unsafe { &*xas.xa_node }.offset.wrapping_sub(1);
        xas.xa_node = xa_parent(unsafe { &*xas.xa_node });
        if xas.xa_node.is_null() {
            return set_bounds(xas);
        }
    }
    loop {
        let entry = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
        if !xa_is_node(entry) {
            return entry;
        }
        xas.xa_node = xa_to_node(entry);
        xas_set_offset(xas);
    }
}

kernel::kabi_export! {
    __xas_next,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> pointer_type { base_type void }",
}

/// `__xas_next()`.
#[no_mangle]
pub unsafe extern "C" fn __xas_next(xas: *mut XaState) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    if !xas_frozen(xas.xa_node) {
        xas.xa_index = xas.xa_index.wrapping_add(1);
    }
    if xas.xa_node.is_null() {
        return set_bounds(xas);
    }
    if xas_not_node(xas.xa_node) {
        return unsafe { xas_load(xas) };
    }
    if xas.xa_offset != get_offset(xas.xa_index, unsafe { &*xas.xa_node }) as u8 {
        xas.xa_offset = xas.xa_offset.wrapping_add(1);
    }
    while xas.xa_offset as usize == XA_CHUNK_SIZE {
        xas.xa_offset = unsafe { &*xas.xa_node }.offset.wrapping_add(1);
        xas.xa_node = xa_parent(unsafe { &*xas.xa_node });
        if xas.xa_node.is_null() {
            return set_bounds(xas);
        }
    }
    loop {
        let entry = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
        if !xa_is_node(entry) {
            return entry;
        }
        xas.xa_node = xa_to_node(entry);
        xas_set_offset(xas);
    }
}

kernel::kabi_export! {
    xas_find,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter base_type unsigned long byte_size(8) encoding(7) max ) -> pointer_type { base_type void }",
}

/// `xas_find()`.
#[no_mangle]
pub unsafe extern "C" fn xas_find(xas: *mut XaState, max: usize) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    let mut entry;

    if xas_error(xas) != 0 || xas.xa_node == xas_bounds() {
        return ptr::null_mut();
    }
    if xas.xa_index > max {
        return set_bounds(xas);
    }

    if xas.xa_node.is_null() {
        xas.xa_index = 1;
        return set_bounds(xas);
    } else if xas.xa_node == xas_restart() {
        entry = unsafe { xas_load(xas) };
        if !entry.is_null() || xas_not_node(xas.xa_node) {
            return entry;
        }
    } else if unsafe { &*xas.xa_node }.shift == 0
        && xas.xa_offset as usize != (xas.xa_index & XA_CHUNK_MASK)
    {
        xas.xa_offset = (((xas.xa_index - 1) & XA_CHUNK_MASK) + 1) as u8;
    }

    xas_next_offset(xas);

    while !xas.xa_node.is_null() && xas.xa_index <= max {
        if xas.xa_offset as usize == XA_CHUNK_SIZE {
            xas.xa_offset = unsafe { &*xas.xa_node }.offset + 1;
            xas.xa_node = xa_parent(unsafe { &*xas.xa_node });
            continue;
        }

        entry = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
        if xa_is_node(entry) {
            xas.xa_node = xa_to_node(entry);
            xas.xa_offset = 0;
            continue;
        }
        if !entry.is_null() && !xa_is_sibling(entry) {
            return entry;
        }
        xas_next_offset(xas);
    }

    if xas.xa_node.is_null() {
        xas.xa_node = xas_bounds();
    }
    ptr::null_mut()
}

/// `xas_find_chunk()` (private, `include/linux/xarray.h`). Always the
/// `find_next_bit` path -- the C's `XA_CHUNK_SIZE == BITS_PER_LONG` fast
/// path is a pure optimisation with an identical result (confirmed: both
/// this project's configs make that comparison false anyway, since
/// XA_MARK_LONGS is 1 either way and the fast/slow paths agree bit for
/// bit), so keeping one path here is a deliberate simplification, not a
/// behavioural change.
fn xas_find_chunk(xas: &XaState, advance: bool, mark: u32) -> u32 {
    let node = unsafe { &*xas.xa_node };
    let addr = node_marks(node, mark);
    let mut offset = xas.xa_offset as u32;
    if advance {
        offset += 1;
    }
    find_next_bit(addr, XA_CHUNK_SIZE, offset as usize) as u32
}

kernel::kabi_export! {
    xas_find_marked,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas , formal_parameter base_type unsigned long byte_size(8) encoding(7) max , formal_parameter t#xa_mark_t mark ) -> pointer_type { base_type void }",
}

/// `xas_find_marked()`. Rewritten from the C's goto-based control flow
/// using early returns for the `out:`/`max:` labels (each `goto out`/
/// `goto max` site becomes the same few lines those labels contain) --
/// NOT nested inside the initial if/else, since the C's `while` loop
/// runs unconditionally after that if/else falls through, including the
/// common continuation case where `xas.xa_node` is neither null nor
/// top-of-tree and NEITHER branch executes.
#[no_mangle]
pub unsafe extern "C" fn xas_find_marked(xas: *mut XaState, max: usize, mark: u32) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    let mut advance = true;

    if xas_error(xas) != 0 {
        return ptr::null_mut();
    }
    if xas.xa_index > max {
        xas.xa_node = xas_restart();
        return ptr::null_mut();
    }

    if xas.xa_node.is_null() {
        xas.xa_index = 1;
        if xas.xa_index > max {
            xas.xa_node = xas_restart();
            return ptr::null_mut();
        }
        return set_bounds(xas);
    } else if xas_top(xas.xa_node) {
        advance = false;
        let entry = xa_head(unsafe { &*xas.xa });
        xas.xa_node = ptr::null_mut();
        if xas.xa_index > max_index(entry) {
            if xas.xa_index > max {
                xas.xa_node = xas_restart();
                return ptr::null_mut();
            }
            return set_bounds(xas);
        }
        if !xa_is_node(entry) {
            if xa_marked(unsafe { &*xas.xa }, mark) {
                return entry;
            }
            xas.xa_index = 1;
            if xas.xa_index > max {
                xas.xa_node = xas_restart();
                return ptr::null_mut();
            }
            return set_bounds(xas);
        }
        xas.xa_node = xa_to_node(entry);
        xas.xa_offset = (xas.xa_index >> unsafe { &*xas.xa_node }.shift) as u8;
    }

    while xas.xa_index <= max {
        if xas.xa_offset as usize == XA_CHUNK_SIZE {
            xas.xa_offset = unsafe { &*xas.xa_node }.offset + 1;
            xas.xa_node = xa_parent(unsafe { &*xas.xa_node });
            if xas.xa_node.is_null() {
                break;
            }
            advance = false;
            continue;
        }

        if !advance {
            let entry = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
            if xa_is_sibling(entry) {
                xas.xa_offset = xa_to_sibling(entry) as u8;
                xas_move_index(xas, xas.xa_offset as u32);
            }
        }

        let offset = xas_find_chunk(xas, advance, mark);
        if offset > xas.xa_offset as u32 {
            advance = false;
            xas_move_index(xas, offset);
            // Mind the wrap.
            if xas.xa_index.wrapping_sub(1) >= max {
                xas.xa_node = xas_restart();
                return ptr::null_mut();
            }
            xas.xa_offset = offset as u8;
            if offset as usize == XA_CHUNK_SIZE {
                continue;
            }
        }

        let entry = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
        if entry.is_null() && !(xa_track_free(unsafe { &*xas.xa }) && mark == XA_FREE_MARK) {
            continue;
        }
        if xa_is_sibling(entry) {
            continue;
        }
        if !xa_is_node(entry) {
            return entry;
        }
        xas.xa_node = xa_to_node(entry);
        xas_set_offset(xas);
    }

    if xas.xa_index > max {
        xas.xa_node = xas_restart();
        return ptr::null_mut();
    }
    set_bounds(xas)
}

kernel::kabi_export! {
    xas_find_conflict,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> pointer_type { base_type void }",
}

/// `xas_find_conflict()`.
#[no_mangle]
pub unsafe extern "C" fn xas_find_conflict(xas: *mut XaState) -> *mut c_void {
    let xas = unsafe { &mut *xas };
    let mut curr: *mut c_void;

    if xas_error(xas) != 0 {
        return ptr::null_mut();
    }
    if xas.xa_node.is_null() {
        return ptr::null_mut();
    }

    if xas_top(xas.xa_node) {
        curr = xas_start(xas);
        if curr.is_null() {
            return ptr::null_mut();
        }
        while xa_is_node(curr) {
            curr = xas_descend(xas, xa_to_node(curr));
        }
        if !curr.is_null() {
            return curr;
        }
    }

    if unsafe { &*xas.xa_node }.shift as u32 > xas.xa_shift as u32 {
        return ptr::null_mut();
    }

    loop {
        let n = unsafe { &*xas.xa_node };
        if n.shift as u32 == xas.xa_shift as u32 {
            if xas.xa_offset & xas.xa_sibs == xas.xa_sibs {
                break;
            }
        } else if xas.xa_offset as usize == XA_CHUNK_MASK {
            xas.xa_offset = n.offset;
            xas.xa_node = xa_parent(n);
            if xas.xa_node.is_null() {
                break;
            }
            continue;
        }
        xas.xa_offset += 1;
        curr = xa_entry(unsafe { &*xas.xa_node }, xas.xa_offset as u32);
        if xa_is_sibling(curr) {
            continue;
        }
        while xa_is_node(curr) {
            xas.xa_node = xa_to_node(curr);
            xas.xa_offset = 0;
            curr = xa_entry(unsafe { &*xas.xa_node }, 0);
        }
        if !curr.is_null() {
            return curr;
        }
    }
    xas.xa_offset -= xas.xa_sibs;
    ptr::null_mut()
}

kernel::kabi_export! {
    xa_find,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } indexp , formal_parameter base_type unsigned long byte_size(8) encoding(7) max , formal_parameter t#xa_mark_t filter ) -> pointer_type { base_type void }",
}

/// `xa_find()`.
#[no_mangle]
pub unsafe extern "C" fn xa_find(
    xa: *mut Xarray,
    indexp: *mut usize,
    max: usize,
    filter: u32,
) -> *mut c_void {
    let mut xas = xa_state_new(xa, unsafe { *indexp });
    let mut entry;

    unsafe { rust_helper_rcu_read_lock() };
    loop {
        entry = if filter < XA_MAX_MARKS as u32 {
            unsafe { xas_find_marked(&mut xas, max, filter) }
        } else {
            unsafe { xas_find(&mut xas, max) }
        };
        if !xas_retry(&mut xas, entry) {
            break;
        }
    }
    unsafe { rust_helper_rcu_read_unlock() };

    if !entry.is_null() {
        unsafe { *indexp = xas.xa_index };
    }
    entry
}

fn xas_sibling(xas: &XaState) -> bool {
    // Always the CONFIG_XARRAY_MULTI arm -- see xa_is_sibling's own
    // comment for why that's safe even when the config is off.
    if xas.xa_node.is_null() {
        return false;
    }
    let node = unsafe { &*xas.xa_node };
    // Same intentional-wraparound shape as max_index(): a deep enough
    // node's shift makes XA_CHUNK_SIZE << shift overflow to 0, and the
    // C's `- 1` relies on that wrapping to usize::MAX.
    let mask = (XA_CHUNK_SIZE << node.shift).wrapping_sub(1);
    (xas.xa_index & mask) > ((xas.xa_offset as usize) << node.shift)
}

kernel::kabi_export! {
    xa_find_after,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } indexp , formal_parameter base_type unsigned long byte_size(8) encoding(7) max , formal_parameter t#xa_mark_t filter ) -> pointer_type { base_type void }",
}

/// `xa_find_after()`.
#[no_mangle]
pub unsafe extern "C" fn xa_find_after(
    xa: *mut Xarray,
    indexp: *mut usize,
    max: usize,
    filter: u32,
) -> *mut c_void {
    // C: `XA_STATE(xas, xa, *indexp + 1)` relies on well-defined usize
    // wraparound when *indexp == ULONG_MAX -- wrapping to 0 is exactly
    // what the very next check tests for ("no more entries after the
    // max index"), not a bug to guard against. Reproduced for real:
    // CONFIG_TEST_XARRAY's check_find_4() walks indexp up to
    // ULONG_MAX and panicked here under this kernel's overflow-checks.
    let mut xas = xa_state_new(xa, unsafe { *indexp }.wrapping_add(1));
    let mut entry;

    if xas.xa_index == 0 {
        return ptr::null_mut();
    }

    unsafe { rust_helper_rcu_read_lock() };
    loop {
        entry = if filter < XA_MAX_MARKS as u32 {
            unsafe { xas_find_marked(&mut xas, max, filter) }
        } else {
            unsafe { xas_find(&mut xas, max) }
        };

        if xas_invalid(&xas) {
            break;
        }
        if xas_sibling(&xas) {
            continue;
        }
        if !xas_retry(&mut xas, entry) {
            break;
        }
    }
    unsafe { rust_helper_rcu_read_unlock() };

    if !entry.is_null() {
        unsafe { *indexp = xas.xa_index };
    }
    entry
}

fn xas_extract_present(xas: &mut XaState, dst: *mut *mut c_void, max: usize, n: u32) -> u32 {
    let mut i: u32 = 0;

    unsafe { rust_helper_rcu_read_lock() };
    let mut entry = unsafe { xas_find(xas, max) };
    while !entry.is_null() {
        if !xas_retry(xas, entry) {
            unsafe { *dst.add(i as usize) = entry };
            i += 1;
            if i == n {
                break;
            }
        }
        entry = xas_next_entry(xas, max);
    }
    unsafe { rust_helper_rcu_read_unlock() };
    i
}

fn xas_extract_marked(
    xas: &mut XaState,
    dst: *mut *mut c_void,
    max: usize,
    n: u32,
    mark: u32,
) -> u32 {
    let mut i: u32 = 0;

    unsafe { rust_helper_rcu_read_lock() };
    let mut entry = unsafe { xas_find_marked(xas, max, mark) };
    while !entry.is_null() {
        if !xas_retry(xas, entry) {
            unsafe { *dst.add(i as usize) = entry };
            i += 1;
            if i == n {
                break;
            }
        }
        entry = xas_next_marked(xas, max, mark);
    }
    unsafe { rust_helper_rcu_read_unlock() };
    i
}

/// `xas_next_entry()` (private, `include/linux/xarray.h`).
fn xas_next_entry(xas: &mut XaState, max: usize) -> *mut c_void {
    let node = xas.xa_node;
    if xas_not_node(node)
        || unsafe { &*node }.shift != 0
        || xas.xa_offset as usize != (xas.xa_index & XA_CHUNK_MASK)
    {
        return unsafe { xas_find(xas, max) };
    }
    loop {
        if xas.xa_index >= max {
            return unsafe { xas_find(xas, max) };
        }
        if xas.xa_offset as usize == XA_CHUNK_MASK {
            return unsafe { xas_find(xas, max) };
        }
        let entry = xa_entry(unsafe { &*node }, xas.xa_offset as u32 + 1);
        if xa_is_internal(entry) {
            return unsafe { xas_find(xas, max) };
        }
        xas.xa_offset += 1;
        xas.xa_index += 1;
        if !entry.is_null() {
            return entry;
        }
    }
}

/// `xas_next_marked()` (private, `include/linux/xarray.h`).
fn xas_next_marked(xas: &mut XaState, max: usize, mark: u32) -> *mut c_void {
    let node = xas.xa_node;
    if xas_not_node(node) || unsafe { &*node }.shift != 0 {
        return unsafe { xas_find_marked(xas, max, mark) };
    }
    let offset = xas_find_chunk(xas, true, mark);
    xas.xa_offset = offset as u8;
    xas.xa_index = (xas.xa_index & !XA_CHUNK_MASK) + offset as usize;
    if xas.xa_index > max {
        return ptr::null_mut();
    }
    if offset as usize == XA_CHUNK_SIZE {
        return unsafe { xas_find_marked(xas, max, mark) };
    }
    let entry = xa_entry(unsafe { &*node }, offset);
    if entry.is_null() {
        return unsafe { xas_find_marked(xas, max, mark) };
    }
    entry
}

kernel::kabi_export! {
    xa_extract,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter pointer_type { pointer_type { base_type void } } dst , formal_parameter base_type unsigned long byte_size(8) encoding(7) start , formal_parameter base_type unsigned long byte_size(8) encoding(7) max , formal_parameter base_type unsigned int byte_size(4) encoding(7) n , formal_parameter t#xa_mark_t filter ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// `xa_extract()`.
#[no_mangle]
pub unsafe extern "C" fn xa_extract(
    xa: *mut Xarray,
    dst: *mut *mut c_void,
    start: usize,
    max: usize,
    n: u32,
    filter: u32,
) -> u32 {
    let mut xas = xa_state_new(xa, start);
    if n == 0 {
        return 0;
    }
    if filter < XA_MAX_MARKS as u32 {
        xas_extract_marked(&mut xas, dst, max, n, filter)
    } else {
        xas_extract_present(&mut xas, dst, max, n)
    }
}

kernel::kabi_export! {
    xa_delete_node,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_node } node , formal_parameter t#xa_update_node_t update ) -> base_type void",
}

/// `xa_delete_node()`. "For the benefit of the test suite" -- the C's
/// own comment; the caller (`mm/workingset.c`, still C) constructs the
/// `xa_state` fields not listed here as zero, matching a C struct
/// literal's implicit zeroing of unlisted members.
#[no_mangle]
pub unsafe extern "C" fn xa_delete_node(node: *mut XaNode, update: XaUpdateNode) {
    let n = unsafe { &*node };
    let mut xas = XaState {
        xa: n.array,
        xa_index: (n.offset as usize) << (n.shift as u32 + XA_CHUNK_SHIFT as u32),
        xa_shift: n.shift + XA_CHUNK_SHIFT as u8,
        xa_sibs: 0,
        xa_offset: n.offset,
        xa_pad: 0,
        xa_node: xa_parent(n),
        xa_alloc: ptr::null_mut(),
        xa_update: update,
        xa_lru: ptr::null_mut(),
    };
    unsafe { xas_store(&mut xas, ptr::null_mut()) };
}

kernel::kabi_export! {
    xa_destroy,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa ) -> base_type void",
}

/// `xa_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn xa_destroy(xa: *mut Xarray) {
    let mut xas = xa_state_new(xa, 0);
    xas.xa_node = ptr::null_mut();

    let flags = xa_lock_irqsave(xa);
    let entry = xa_head(unsafe { &*xa });
    rcu_init_ptr(&raw mut (*unsafe { &mut *xa }).xa_head, ptr::null_mut());
    unsafe { xas_init_marks(&xas) };
    if xa_zero_busy(unsafe { &*xa }) {
        xa_mark_clear(unsafe { &mut *xa }, XA_FREE_MARK);
    }
    if xa_is_node(entry) {
        xas_free_nodes(&xas, xa_to_node(entry));
    }
    xa_unlock_irqrestore(xa, flags);
}

/// `struct xa_limit`. Field order matters -- `max` then `min`, matching
/// the real header exactly (this is passed by value across the FFI
/// boundary from real C callers).
#[repr(C)]
pub struct XaLimit {
    /// `xa_limit.max`.
    pub max: u32,
    /// `xa_limit.min`.
    pub min: u32,
}

kernel::kabi_export! {
    __xa_alloc,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter pointer_type { t#u32 } id , formal_parameter pointer_type { base_type void } entry , formal_parameter s#xa_limit limit , formal_parameter t#gfp_t gfp ) -> base_type int byte_size(4) encoding(5)",
}

/// `__xa_alloc()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_alloc(
    xa: *mut Xarray,
    id: *mut u32,
    mut entry: *mut c_void,
    limit: XaLimit,
    gfp: u32,
) -> i32 {
    let mut xas = xa_state_new(xa, 0);

    if kernel::kabi_warn_on_once!(xa_is_advanced(entry)) {
        return -(EINVAL as i32);
    }
    if kernel::kabi_warn_on_once!(!xa_track_free(unsafe { &*xa })) {
        return -(EINVAL as i32);
    }
    if entry.is_null() {
        entry = xa_zero_entry();
    }

    loop {
        xas.xa_index = limit.min as usize;
        unsafe { xas_find_marked(&mut xas, limit.max as usize, XA_FREE_MARK) };
        if xas.xa_node == xas_restart() {
            xas_set_err(&mut xas, -EBUSY);
        } else {
            unsafe { *id = xas.xa_index as u32 };
        }
        unsafe { xas_store(&mut xas, entry) };
        unsafe { xas_clear_mark(&xas, XA_FREE_MARK) };
        if !unsafe { xas_nomem(&mut xas, gfp) } {
            break;
        }
    }

    xas_error(&xas)
}

kernel::kabi_export! {
    __xa_alloc_cyclic,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xarray } xa , formal_parameter pointer_type { t#u32 } id , formal_parameter pointer_type { base_type void } entry , formal_parameter s#xa_limit limit , formal_parameter pointer_type { t#u32 } next , formal_parameter t#gfp_t gfp ) -> base_type int byte_size(4) encoding(5)",
}

/// `__xa_alloc_cyclic()`.
#[no_mangle]
pub unsafe extern "C" fn __xa_alloc_cyclic(
    xa: *mut Xarray,
    id: *mut u32,
    entry: *mut c_void,
    mut limit: XaLimit,
    next: *mut u32,
    gfp: u32,
) -> i32 {
    let min = limit.min;
    let mut ret: i32;

    limit.min = min.max(unsafe { *next });
    ret = unsafe { __xa_alloc(xa, id, entry, XaLimit { max: limit.max, min: limit.min }, gfp) };
    // No persisting `&mut Xarray` reborrow across the second
    // __xa_alloc() call below -- that call takes the same raw `xa` and
    // touches `xa_flags` itself, so a `&mut` bound here and read again
    // afterward would be exactly the reborrow-invalidation hazard this
    // project's sweep exists to catch (found by that sweep, on this
    // exact function: the original draft held `xa_ref` live across
    // the second call). Every access below re-derives it fresh.
    if unsafe { (*xa).xa_flags } & XA_FLAGS_ALLOC_WRAPPED != 0 && ret == 0 {
        unsafe { (*xa).xa_flags &= !XA_FLAGS_ALLOC_WRAPPED };
        ret = 1;
    }

    if ret < 0 && limit.min > min {
        limit.min = min;
        ret = unsafe { __xa_alloc(xa, id, entry, XaLimit { max: limit.max, min: limit.min }, gfp) };
        if ret == 0 {
            ret = 1;
        }
    }

    if ret >= 0 {
        // C: `*next = *id + 1;` relies on well-defined u32 wraparound
        // when *id == u32::MAX -- the "next" cursor cycling back to 0
        // is the intended wraparound-allocation behaviour, not a bug
        // to guard against. Reproduced for real: CONFIG_TEST_XARRAY's
        // check_xa_alloc() drives ids up to u32::MAX and panicked here
        // under this kernel's overflow-checks.
        let next_val = unsafe { *id }.wrapping_add(1);
        unsafe { *next = next_val };
        if next_val == 0 {
            unsafe { (*xa).xa_flags |= XA_FLAGS_ALLOC_WRAPPED };
        }
    }
    ret
}

kernel::kabi_export! {
    xas_create_range,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> base_type void",
}

/// `xas_create_range()`.
#[no_mangle]
pub unsafe extern "C" fn xas_create_range(xas: *mut XaState) {
    let xas = unsafe { &mut *xas };
    let index = xas.xa_index;
    let shift = xas.xa_shift;
    let sibs = xas.xa_sibs;

    // Same intentional-wraparound shape as xas_size()/xas_max()'s mask
    // computation (and the same fix): a large enough shift makes
    // `(sibs+1) << shift` overflow to 0, and the C's `- 1` relies on
    // that wrapping to usize::MAX (covers-everything), not panicking.
    xas.xa_index |= ((sibs as usize + 1) << shift).wrapping_sub(1);
    if xas_is_node(xas) && unsafe { &*xas.xa_node }.shift == xas.xa_shift {
        xas.xa_offset |= sibs;
    }
    xas.xa_shift = 0;
    xas.xa_sibs = 0;

    loop {
        xas_create(xas, true);
        if xas_error(xas) != 0 {
            // restore:
            xas.xa_shift = shift;
            xas.xa_sibs = sibs;
            xas.xa_index = index;
            return;
        }
        if xas.xa_index <= (index | XA_CHUNK_MASK) {
            // success:
            xas.xa_index = index;
            if !xas.xa_node.is_null() {
                xas_set_offset(xas);
            }
            return;
        }
        xas.xa_index -= XA_CHUNK_SIZE;

        loop {
            let node = unsafe { &*xas.xa_node };
            if node.shift >= shift {
                break;
            }
            xas.xa_node = xa_parent(node);
            xas.xa_offset = node.offset.wrapping_sub(1);
            if node.offset != 0 {
                break;
            }
        }
    }
}

kernel::kabi_export! {
    xas_pause,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xa_state } xas ) -> base_type void",
}

/// `xas_pause()`.
#[no_mangle]
pub unsafe extern "C" fn xas_pause(xas: *mut XaState) {
    let xas = unsafe { &mut *xas };
    let node = xas.xa_node;

    if xas_invalid(xas) {
        return;
    }

    xas.xa_node = xas_restart();
    if !node.is_null() {
        let n = unsafe { &*node };
        let mut offset = xas.xa_offset as u32;
        loop {
            offset += 1;
            if offset as usize >= XA_CHUNK_SIZE {
                break;
            }
            if !xa_is_sibling(xa_entry(n, offset)) {
                break;
            }
        }
        xas.xa_index &= !0usize << n.shift;
        // C: plain `+=`, relying on wraparound to 0 as the sentinel
        // the very next line checks for ("paused past the top of the
        // address space"), not a bug to guard against.
        xas.xa_index = xas
            .xa_index
            .wrapping_add((offset as usize - xas.xa_offset as usize) << n.shift);
        if xas.xa_index == 0 {
            xas.xa_node = xas_bounds();
        }
    } else {
        xas.xa_index += 1;
    }
}

/// Layout probe for `port/test/xarray/layout/` -- compiled into
/// nothing this project ships: only reachable when explicitly enabled
/// via `--cfg xa_layout_probe` (a small standalone binary calls this;
/// see `layout/run.sh`). Prints `size_of`/`offset_of` for every field
/// of every `#[repr(C)]` mirror in this file, in the exact format
/// `layout/layout_probe.c`'s C-side twin uses, so a plain text diff
/// between the two is a direct layout mismatch -- these types' fields
/// are private everywhere else in this project specifically so nothing
/// outside this file can misuse them, and `offset_of!` needs field-name
/// access, so this has to live here rather than in the probe binary
/// itself.
#[cfg(xa_layout_probe)]
pub fn print_layout() {
    use core::mem::{offset_of, size_of};

    println!("XA_CHUNK_SHIFT={}", XA_CHUNK_SHIFT);
    println!("XA_CHUNK_SIZE={}", XA_CHUNK_SIZE);
    println!("XA_MARK_LONGS={}", XA_MARK_LONGS);

    println!("sizeof(struct xarray)={}", size_of::<Xarray>());
    println!("offsetof(xarray,xa_flags)={}", offset_of!(Xarray, xa_flags));
    println!("offsetof(xarray,xa_head)={}", offset_of!(Xarray, xa_head));
    println!("sizeof(spinlock_t)={}", size_of::<[u8; 4]>());

    println!("sizeof(struct xa_node)={}", size_of::<XaNode>());
    println!("offsetof(xa_node,shift)={}", offset_of!(XaNode, shift));
    println!("offsetof(xa_node,offset)={}", offset_of!(XaNode, offset));
    println!("offsetof(xa_node,count)={}", offset_of!(XaNode, count));
    println!("offsetof(xa_node,nr_values)={}", offset_of!(XaNode, nr_values));
    println!("offsetof(xa_node,parent)={}", offset_of!(XaNode, parent));
    println!("offsetof(xa_node,array)={}", offset_of!(XaNode, array));
    println!(
        "offsetof(xa_node,private_list)={}",
        offset_of!(XaNode, _private_list_or_rcu_head)
    );
    println!(
        "offsetof(xa_node,rcu_head)={}",
        offset_of!(XaNode, _private_list_or_rcu_head)
    );
    println!(
        "sizeof(xa_node.private_list)={}",
        size_of::<[usize; 2]>()
    );
    println!("sizeof(xa_node.rcu_head)={}", size_of::<[usize; 2]>());
    println!("offsetof(xa_node,slots)={}", offset_of!(XaNode, slots));
    println!(
        "sizeof(xa_node.slots)={}",
        size_of::<[*mut c_void; XA_CHUNK_SIZE]>()
    );
    println!("offsetof(xa_node,tags)={}", offset_of!(XaNode, marks));
    println!("offsetof(xa_node,marks)={}", offset_of!(XaNode, marks));
    println!(
        "sizeof(xa_node.tags)={}",
        size_of::<[[usize; XA_MARK_LONGS]; XA_MAX_MARKS]>()
    );
    println!(
        "sizeof(xa_node.marks)={}",
        size_of::<[[usize; XA_MARK_LONGS]; XA_MAX_MARKS]>()
    );

    println!("sizeof(struct xa_state)={}", size_of::<XaState>());
    println!("offsetof(xa_state,xa)={}", offset_of!(XaState, xa));
    println!("offsetof(xa_state,xa_index)={}", offset_of!(XaState, xa_index));
    println!("offsetof(xa_state,xa_shift)={}", offset_of!(XaState, xa_shift));
    println!("offsetof(xa_state,xa_sibs)={}", offset_of!(XaState, xa_sibs));
    println!("offsetof(xa_state,xa_offset)={}", offset_of!(XaState, xa_offset));
    println!("offsetof(xa_state,xa_pad)={}", offset_of!(XaState, xa_pad));
    println!("offsetof(xa_state,xa_node)={}", offset_of!(XaState, xa_node));
    println!("offsetof(xa_state,xa_alloc)={}", offset_of!(XaState, xa_alloc));
    println!("offsetof(xa_state,xa_update)={}", offset_of!(XaState, xa_update));
    println!("offsetof(xa_state,xa_lru)={}", offset_of!(XaState, xa_lru));
}
