// SPDX-License-Identifier: GPL-2.0

//! Generic radix tree / sparse array -- the Rust behind
//! `lib/generic-radix-tree.c`.
//!
//! Replaces: lib/generic-radix-tree.c
//!
//! A lock-free radix tree of fixed-size (`GENRADIX_NODE_SIZE` = 512-byte)
//! nodes, indexed by byte offset. The root pointer is tagged: its low bits
//! (`GENRADIX_DEPTH_MASK`) hold the tree's current depth, the rest is the
//! (512-byte-aligned, so those low bits are free) pointer to the root node.
//!
//! # Node allocation stays in C -- see `lib/generic-radix-tree.c`
//!
//! `genradix_alloc_node()`/`genradix_free_node()` are `static inline`
//! wrappers over `kzalloc()`/`kfree()`, and `kzalloc()` (since 6.10's
//! allocation profiling) is `alloc_hooks(kzalloc_noprof(...))` -- a macro
//! over a `static inline`, with no linkable symbol. This is a standing,
//! undesigned exception across this project (`logs/allocation.md`): an
//! allocating/freeing pair stays together in whichever language can call
//! the allocator, which today is only C. `rust_genradix_alloc_node()` and
//! `rust_genradix_free_node()` in the retained C file are that pair.
//!
//! # `cmpxchg_release` maps to `Release` success / `Relaxed` failure --
//! correct here, but for a narrower reason than "x86 is always a full fence"
//!
//! Both call sites use the kernel's `cmpxchg_release()`. At the *CPU*
//! level x86-64 has no weaker atomic read-modify-write instruction, so the
//! hardware fence is the same regardless of the ordering requested. But
//! `arch_cmpxchg()`'s inline asm (`arch/x86/include/asm/cmpxchg.h`) also
//! carries an explicit `"memory"` clobber -- a full *compiler* barrier,
//! independent of and stronger than any ordering the call site asks for.
//! Rust's `Ordering::Relaxed` on the failure arm gives LLVM no equivalent
//! blanket guarantee against reordering nearby independent non-atomic
//! accesses; it only respects genuine data/control dependencies.
//!
//! What actually makes `Release`/`Relaxed` sound *here*: every non-atomic
//! write adjacent to a CAS in this file (`new_node.children[0] = n` before,
//! `= null` after) touches memory this call site exclusively owns and has
//! not yet published, on both the success and failure paths -- there is no
//! independent, already-visible access nearby for a reordering to disturb.
//! That is a property of this file's current code, not a property of the
//! ordering choice in general. If a future edit adds a non-atomic access
//! near either CAS that depends on ordering relative to *other* threads,
//! re-derive this reasoning rather than assuming it still holds.
//!
//! # `ilog2()`/`round_down()` reproduced directly
//!
//! Both are `include/linux/{log2,math}.h` macros with no linkable symbol;
//! each is reproduced here as the same bit arithmetic, checked against the
//! header's own definition rather than assumed. `round_up()`/
//! `is_power_of_2()` are used only by header-side caller macros this file
//! never reaches (`__idx_to_offset()` and the iterator advance/rewind
//! helpers), not by anything `lib/generic-radix-tree.c` itself defines, so
//! they are not reproduced here.

use core::ffi::{c_uint, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};

const GENRADIX_NODE_SHIFT: u32 = 9;
const GENRADIX_NODE_SIZE: usize = 1 << GENRADIX_NODE_SHIFT; // 512
/// `GENRADIX_ARY`: node fan-out. `size_of::<*mut GenradixNode>()` is 8 on
/// this (the only) target, so this is `512 / 8 = 64`.
const GENRADIX_ARY: usize = GENRADIX_NODE_SIZE / core::mem::size_of::<*mut GenradixNode>();
const GENRADIX_ARY_SHIFT: u32 = ilog2_const(GENRADIX_ARY as u64);
/// `GENRADIX_MAX_DEPTH`: `DIV_ROUND_UP(BITS_PER_LONG - GENRADIX_NODE_SHIFT, GENRADIX_ARY_SHIFT)`.
const GENRADIX_MAX_DEPTH: u32 = (64 - GENRADIX_NODE_SHIFT).div_ceil(GENRADIX_ARY_SHIFT);
/// `GENRADIX_DEPTH_MASK`: `roundup_pow_of_two(GENRADIX_MAX_DEPTH + 1) - 1`.
const GENRADIX_DEPTH_MASK: usize = (roundup_pow_of_two_const(GENRADIX_MAX_DEPTH as u64 + 1) - 1) as usize;

/// `ilog2()` for a compile-time constant -- `include/linux/log2.h`'s
/// `__builtin_constant_p` arm: `63 - clz(n)`, undefined at `n < 1` (matches
/// the header, which special-cases only `n < 2` to `0`; every constant this
/// file evaluates it on is a real power-of-two fan-out, never 0 or 1).
const fn ilog2_const(n: u64) -> u32 {
    if n < 2 {
        0
    } else {
        63 - n.leading_zeros()
    }
}

/// `roundup_pow_of_two()`, `include/linux/log2.h`, for a compile-time value.
const fn roundup_pow_of_two_const(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        1u64 << (64 - (n - 1).leading_zeros())
    }
}

/// `ilog2()`, runtime (`__ilog2_u64` = `fls64(n) - 1`): position of the
/// highest set bit, or `-1` at `n == 0` -- `fls64(0) == 0` is well-defined,
/// unlike a raw `clz`, and the C compares this against
/// `genradix_depth_shift()` (also `int`) as a SIGNED comparison, which is
/// exactly what lets `offset == 0` always pass every range check below
/// without a separate special case. Returning `u32` and special-casing 0
/// here would be a different (and, at the u32::MAX-underflow boundary,
/// wrong) translation.
#[inline]
fn ilog2(n: u64) -> i32 {
    if n == 0 {
        -1
    } else {
        (63 - n.leading_zeros()) as i32
    }
}

#[inline]
fn round_down(x: usize, y: usize) -> usize {
    x & !(y - 1)
}

/// Opaque: never dereferenced as a struct anywhere, C or Rust -- only ever
/// a tagged pointer value. `struct genradix_root;` in the C is likewise
/// forward-declared and never defined.
/// See the module doc comment -- opaque, never dereferenced as a struct.
#[repr(C)]
pub struct GenradixRoot {
    _opaque: [u8; 0],
}

/// Mirrors `struct genradix_node`: a fan-out array of child pointers,
/// aliased with a flat byte buffer of the same total size (`union` in the
/// C). `GENRADIX_ARY` (64) pointers of 8 bytes each is exactly
/// `GENRADIX_NODE_SIZE` (512) bytes, so the union has one size either way.
/// See the module doc comment for the layout rationale.
#[repr(C)]
pub union GenradixNode {
    children: [*mut GenradixNode; GENRADIX_ARY],
    data: [u8; GENRADIX_NODE_SIZE],
}

/// Mirrors `struct __genradix`.
#[repr(C)]
pub struct Genradix {
    root: AtomicPtr<GenradixRoot>,
}

/// Mirrors `struct genradix_iter`.
#[repr(C)]
pub struct GenradixIter {
    offset: usize,
    pos: usize,
}

extern "C" {
    fn rust_genradix_alloc_node(gfp_mask: c_uint) -> *mut GenradixNode;
    fn rust_genradix_free_node(node: *mut GenradixNode);
}

/// `genradix_depth_shift()`: `int` in the C, deliberately -- see [`ilog2`].
#[inline]
fn genradix_depth_shift(depth: u32) -> i32 {
    (GENRADIX_NODE_SHIFT + GENRADIX_ARY_SHIFT * depth) as i32
}

#[inline]
fn genradix_depth_size(depth: u32) -> usize {
    1usize << (genradix_depth_shift(depth) as u32)
}

#[inline]
fn genradix_root_to_depth(r: *mut GenradixRoot) -> u32 {
    (r as usize & GENRADIX_DEPTH_MASK) as u32
}

#[inline]
fn genradix_root_to_node(r: *mut GenradixRoot) -> *mut GenradixNode {
    (r as usize & !GENRADIX_DEPTH_MASK) as *mut GenradixNode
}

#[inline]
fn genradix_root_new(node: *mut GenradixNode, depth: u32) -> *mut GenradixRoot {
    ((node as usize) | (depth as usize)) as *mut GenradixRoot
}

/// `__genradix_ptr_inlined()`. Public (`pub(crate)` would do, but this
/// mirrors the C's own non-`static` linkage within the file) since
/// `sys_info`-style callers elsewhere in a from-Rust future could want it;
/// today only [`__genradix_ptr`] calls it, matching the C.
///
/// # Safety
/// `radix` must be valid.
unsafe fn genradix_ptr_inlined(radix: *const Genradix, offset: usize) -> *mut c_void {
    // SAFETY: caller guarantees `radix` is valid. Relaxed matches the C's
    // plain READ_ONCE() here -- no ordering is implied by this read alone.
    let r = unsafe { (*radix).root.load(Ordering::Relaxed) };
    let mut n = genradix_root_to_node(r);
    let level = genradix_root_to_depth(r);
    // `unsigned shift = genradix_depth_shift(level)` in the C: the same
    // value, but held in an unsigned local from here on for the descent.
    let mut shift = genradix_depth_shift(level) as u32;

    // ilog2(0) == -1 (see `ilog2`'s doc comment), which is always less
    // than genradix_depth_shift's result (>= GENRADIX_NODE_SHIFT), so
    // offset == 0 always passes this check with no special case needed --
    // exactly as in the C.
    if ilog2(offset as u64) >= genradix_depth_shift(level) {
        return core::ptr::null_mut();
    }

    let mut offset = offset;
    while !n.is_null() && shift > GENRADIX_NODE_SHIFT {
        shift -= GENRADIX_ARY_SHIFT;
        // SAFETY: `n` is non-null and, by construction of this tree, a
        // valid interior node whenever `shift > GENRADIX_NODE_SHIFT`.
        n = unsafe { (*n).children[offset >> shift] };
        offset &= (1usize << shift) - 1;
    }

    if n.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: `n` is a valid leaf node and `offset` is within it.
        unsafe { (*n).data.as_mut_ptr().add(offset).cast() }
    }
}

kernel::kabi_rule!("type_string", "s#genradix_root",
    "structure_type genradix_root { }");
kernel::kabi_rule!("type_string", "s#__genradix",
    "structure_type __genradix { member pointer_type { s#genradix_root } root data_member_location(0) } byte_size(8)");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "s#genradix_iter",
    "structure_type genradix_iter { member t#size_t offset data_member_location(0) , member t#size_t pos data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#gfp_t",
    "typedef_type gfp_t { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "s#genradix_node",
    "structure_type genradix_node { member union_type { member array_type[64] { pointer_type { s#genradix_node } } children data_member_location(0) , member array_type[512] { t#u8 } data data_member_location(0) } byte_size(512) data_member_location(0) } byte_size(512)");

kernel::kabi_export! {
    __genradix_ptr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__genradix } radix , formal_parameter t#size_t offset ) -> pointer_type { base_type void }",
}

/// `__genradix_ptr()`.
///
/// # Safety
/// `radix` must be valid.
#[no_mangle]
pub unsafe extern "C" fn __genradix_ptr(radix: *const Genradix, offset: usize) -> *mut c_void {
    // SAFETY: forwarding the caller's guarantee.
    unsafe { genradix_ptr_inlined(radix, offset) }
}

kernel::kabi_export! {
    __genradix_ptr_alloc,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__genradix } radix , formal_parameter t#size_t offset , formal_parameter pointer_type { pointer_type { s#genradix_node } } preallocated , formal_parameter t#gfp_t gfp_mask ) -> pointer_type { base_type void }",
}

/// `__genradix_ptr_alloc()`: get a pointer to `offset`, allocating nodes as
/// needed.
///
/// # Safety
/// `radix` must be valid; `preallocated`, if non-null, must point at a
/// valid `*mut GenradixNode` (a node this caller owns, or null).
#[no_mangle]
pub unsafe extern "C" fn __genradix_ptr_alloc(
    radix: *const Genradix,
    offset: usize,
    preallocated: *mut *mut GenradixNode,
    gfp_mask: c_uint,
) -> *mut c_void {
    // SAFETY: caller guarantees `radix` is valid. Relaxed: paired with the
    // release stores below via the cmpxchg loop, same as the C's
    // READ_ONCE() start-of-loop read feeding into cmpxchg_release().
    let mut v = unsafe { (*radix).root.load(Ordering::Relaxed) };
    let mut new_node: *mut GenradixNode = core::ptr::null_mut();

    if !preallocated.is_null() {
        // SAFETY: caller guarantees `preallocated` is valid.
        unsafe { core::mem::swap(&mut new_node, &mut *preallocated) };
    }

    // Increase tree depth if necessary.
    let (mut n, mut level);
    loop {
        let r = v;
        n = genradix_root_to_node(r);
        level = genradix_root_to_depth(r);

        if !n.is_null() && ilog2(offset as u64) < genradix_depth_shift(level) {
            break;
        }

        if new_node.is_null() {
            // SAFETY: gfp_mask is the caller's, forwarded as-is.
            new_node = unsafe { rust_genradix_alloc_node(gfp_mask) };
            if new_node.is_null() {
                return core::ptr::null_mut();
            }
        }

        // SAFETY: `new_node` is a freshly allocated, exclusively-owned node.
        unsafe { (*new_node).children[0] = n };
        let new_depth = if !n.is_null() { level + 1 } else { 0 };
        let new_root = genradix_root_new(new_node, new_depth);

        // SAFETY: `&(*radix).root` is a valid atomic; `new_node` remains
        // exclusively owned until a successful exchange publishes it.
        match unsafe {
            (*radix)
                .root
                .compare_exchange(r, new_root, Ordering::Release, Ordering::Relaxed)
        } {
            Ok(_) => {
                v = new_root;
                new_node = core::ptr::null_mut();
            }
            Err(actual) => {
                v = actual;
                // SAFETY: `new_node` is still exclusively owned (the
                // exchange failed, so it was never published).
                unsafe { (*new_node).children[0] = core::ptr::null_mut() };
            }
        }
    }

    let mut offset = offset;
    while level > 0 {
        level -= 1;
        // SAFETY: `n` is non-null on every iteration (checked below after
        // the first, and guaranteed non-null on entry by the loop above).
        let p = unsafe { core::ptr::addr_of_mut!((*n).children[offset >> genradix_depth_shift(level)]) };
        offset &= genradix_depth_size(level) - 1;

        // SAFETY: `p` is a valid child-pointer slot.
        let mut child = unsafe { core::ptr::read_volatile(p) };
        if child.is_null() {
            if new_node.is_null() {
                // SAFETY: gfp_mask is the caller's, forwarded as-is.
                new_node = unsafe { rust_genradix_alloc_node(gfp_mask) };
                if new_node.is_null() {
                    return core::ptr::null_mut();
                }
            }

            // SAFETY: `p` is a valid, properly-aligned `*mut GenradixNode`
            // slot; this is the same cmpxchg_release() the C performs on
            // an ordinary child pointer (not the tagged root), so no depth
            // bits are involved here.
            let cell = unsafe { &*p.cast::<core::sync::atomic::AtomicPtr<GenradixNode>>() };
            match cell.compare_exchange(
                core::ptr::null_mut(),
                new_node,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    child = new_node;
                    new_node = core::ptr::null_mut();
                }
                Err(actual) => {
                    child = actual;
                }
            }
        }
        n = child;
    }

    if !new_node.is_null() {
        // SAFETY: `new_node` was allocated by `rust_genradix_alloc_node`
        // and never published (still exclusively owned here).
        unsafe { rust_genradix_free_node(new_node) };
    }

    // SAFETY: `n` is a valid leaf node and `offset` is within it.
    unsafe { (*n).data.as_mut_ptr().add(offset).cast() }
}

kernel::kabi_export! {
    __genradix_iter_peek,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#genradix_iter } iter , formal_parameter pointer_type { s#__genradix } radix , formal_parameter t#size_t objs_per_page ) -> pointer_type { base_type void }",
}

/// `__genradix_iter_peek()`.
///
/// # Safety
/// `iter` and `radix` must be valid.
#[no_mangle]
pub unsafe extern "C" fn __genradix_iter_peek(
    iter: *mut GenradixIter,
    radix: *const Genradix,
    objs_per_page: usize,
) -> *mut c_void {
    // SAFETY: caller guarantees `iter` is valid.
    if unsafe { (*iter).offset } == usize::MAX {
        return core::ptr::null_mut();
    }

    'restart: loop {
        // SAFETY: caller guarantees `radix` is valid.
        let r = unsafe { (*radix).root.load(Ordering::Relaxed) };
        if r.is_null() {
            return core::ptr::null_mut();
        }

        let mut n = genradix_root_to_node(r);
        let mut level = genradix_root_to_depth(r);

        // SAFETY: `iter` is valid. ilog2(0) == -1 (see `ilog2`), always
        // less than genradix_depth_shift's result, so offset 0 always
        // passes -- no special case needed, matching the C.
        let offset0 = unsafe { (*iter).offset };
        if ilog2(offset0 as u64) >= genradix_depth_shift(level) {
            return core::ptr::null_mut();
        }

        while level > 0 {
            level -= 1;
            // SAFETY: `iter` is valid.
            let off = unsafe { (*iter).offset };
            let mut i = (off >> genradix_depth_shift(level)) & (GENRADIX_ARY - 1);

            loop {
                // SAFETY: `n` is a valid interior node at this depth.
                let child = unsafe { (*n).children[i] };
                if !child.is_null() {
                    n = child;
                    break;
                }

                let objs_per_ptr = genradix_depth_size(level);
                // SAFETY: `iter` is valid.
                let cur = unsafe { (*iter).offset };
                if cur.wrapping_add(objs_per_ptr) < cur {
                    // SAFETY: `iter` is valid.
                    unsafe {
                        (*iter).offset = usize::MAX;
                        (*iter).pos = usize::MAX;
                    }
                    return core::ptr::null_mut();
                }

                i += 1;
                let new_offset = round_down(cur.wrapping_add(objs_per_ptr), objs_per_ptr);
                // SAFETY: `iter` is valid.
                unsafe {
                    (*iter).offset = new_offset;
                    (*iter).pos = (new_offset >> GENRADIX_NODE_SHIFT) * objs_per_page;
                }
                if i == GENRADIX_ARY {
                    continue 'restart;
                }
            }
        }

        // SAFETY: `iter` is valid; `n` is a valid leaf node.
        let off = unsafe { (*iter).offset };
        return unsafe { (*n).data.as_mut_ptr().add(off & (GENRADIX_NODE_SIZE - 1)).cast() };
    }
}

kernel::kabi_export! {
    __genradix_iter_peek_prev,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#genradix_iter } iter , formal_parameter pointer_type { s#__genradix } radix , formal_parameter t#size_t objs_per_page , formal_parameter t#size_t obj_size_plus_page_remainder ) -> pointer_type { base_type void }",
}

/// `__genradix_iter_peek_prev()`.
///
/// # Safety
/// `iter` and `radix` must be valid.
#[no_mangle]
pub unsafe extern "C" fn __genradix_iter_peek_prev(
    iter: *mut GenradixIter,
    radix: *const Genradix,
    objs_per_page: usize,
    obj_size_plus_page_remainder: usize,
) -> *mut c_void {
    // SAFETY: caller guarantees `iter` is valid.
    if unsafe { (*iter).offset } == usize::MAX {
        return core::ptr::null_mut();
    }

    'restart: loop {
        // SAFETY: caller guarantees `radix` is valid.
        let r = unsafe { (*radix).root.load(Ordering::Relaxed) };
        if r.is_null() {
            return core::ptr::null_mut();
        }

        let mut n = genradix_root_to_node(r);
        let mut level = genradix_root_to_depth(r);

        // SAFETY: `iter` is valid.
        let offset0 = unsafe { (*iter).offset };
        let past_end = ilog2(offset0 as u64) >= genradix_depth_shift(level);
        if past_end {
            let sz = genradix_depth_size(level);
            // SAFETY: `iter` is valid.
            unsafe {
                (*iter).offset = sz;
                (*iter).pos = (sz >> GENRADIX_NODE_SHIFT) * objs_per_page;
                (*iter).offset -= obj_size_plus_page_remainder;
                (*iter).pos -= 1;
            }
        }

        while level > 0 {
            level -= 1;
            // SAFETY: `iter` is valid.
            let off = unsafe { (*iter).offset };
            let mut i = (off >> genradix_depth_shift(level)) & (GENRADIX_ARY - 1);

            loop {
                // SAFETY: `n` is a valid interior node at this depth.
                let child = unsafe { (*n).children[i] };
                if !child.is_null() {
                    n = child;
                    break;
                }

                let objs_per_ptr = genradix_depth_size(level);
                // SAFETY: `iter` is valid.
                let cur = unsafe { (*iter).offset };
                let new_offset = round_down(cur, objs_per_ptr);
                // SAFETY: `iter` is valid.
                unsafe {
                    (*iter).offset = new_offset;
                    (*iter).pos = (new_offset >> GENRADIX_NODE_SHIFT) * objs_per_page;
                }

                if new_offset == 0 {
                    return core::ptr::null_mut();
                }

                // SAFETY: `iter` is valid.
                unsafe {
                    (*iter).offset -= obj_size_plus_page_remainder;
                    (*iter).pos -= 1;
                }

                if i == 0 {
                    continue 'restart;
                }
                i -= 1;
            }
        }

        // SAFETY: `iter` is valid; `n` is a valid leaf node.
        let off = unsafe { (*iter).offset };
        return unsafe { (*n).data.as_mut_ptr().add(off & (GENRADIX_NODE_SIZE - 1)).cast() };
    }
}

/// `genradix_free_recurse()`.
///
/// # Safety
/// `n`, if non-null, must be a valid node at the given `level` (0 = leaf).
unsafe fn genradix_free_recurse(n: *mut GenradixNode, level: u32) {
    if n.is_null() {
        return;
    }
    if level > 0 {
        for i in 0..GENRADIX_ARY {
            // SAFETY: `n` is a valid interior node at this level.
            let child = unsafe { (*n).children[i] };
            // SAFETY: `child`, if non-null, is a valid node at `level - 1`.
            unsafe { genradix_free_recurse(child, level - 1) };
        }
    }
    // SAFETY: `n` is non-null here and was allocated by
    // `rust_genradix_alloc_node`.
    unsafe { rust_genradix_free_node(n) };
}

kernel::kabi_export! {
    __genradix_prealloc,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__genradix } radix , formal_parameter t#size_t size , formal_parameter t#gfp_t gfp_mask ) -> base_type int byte_size(4) encoding(5)",
}

/// `__genradix_prealloc()`.
///
/// # Safety
/// `radix` must be valid.
#[no_mangle]
pub unsafe extern "C" fn __genradix_prealloc(
    radix: *const Genradix,
    size: usize,
    gfp_mask: c_uint,
) -> core::ffi::c_int {
    let mut offset = 0usize;
    while offset < size {
        // SAFETY: forwarding the caller's guarantee.
        if unsafe { __genradix_ptr_alloc(radix, offset, core::ptr::null_mut(), gfp_mask) }.is_null()
        {
            return -12; // -ENOMEM
        }
        offset += GENRADIX_NODE_SIZE;
    }
    0
}

kernel::kabi_export! {
    __genradix_free,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__genradix } radix ) -> base_type void",
}

/// `__genradix_free()`.
///
/// # Safety
/// `radix` must be valid, and nothing else may be concurrently accessing
/// it (the C's own `xchg()` makes no stronger promise: it only makes the
/// free race-free against a concurrent read of the OLD root, not against
/// concurrent use of the tree in general).
#[no_mangle]
pub unsafe extern "C" fn __genradix_free(radix: *mut Genradix) {
    // SAFETY: caller guarantees `radix` is valid. SeqCst matches the C's
    // xchg(), which the kernel defines as a full barrier.
    let r = unsafe { (*radix).root.swap(core::ptr::null_mut(), Ordering::SeqCst) };
    // SAFETY: `r` came from the tree's own root, so it is either null or a
    // valid tagged root pointer.
    unsafe { genradix_free_recurse(genradix_root_to_node(r), genradix_root_to_depth(r)) };
}
