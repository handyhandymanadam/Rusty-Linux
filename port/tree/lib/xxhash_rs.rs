// SPDX-License-Identifier: GPL-2.0

//! xxHash -- the Rust bodies behind `lib/xxhash.c`.
//!
//! Ported from `lib/xxhash.c` (6.18.49), which is Yann Collet's xxHash under
//! the kernel's Dual BSD/GPL. The constants, the rounds, the rotations and
//! the avalanche are all unchanged: this is a hash, and its output is its
//! specification.
//!
//! # Every arithmetic operation here wraps
//!
//! xxHash is *built* on unsigned overflow — the mixing is multiply-and-wrap.
//! The C gets that for free from `uint32_t` and `uint64_t`; the kernel builds
//! Rust with overflow checks on, so a plain `+` or `*` anywhere in this file
//! would be a kernel panic on ordinary input, not a wrong number. Every one
//! is `wrapping_*`, and that is not defensiveness — it is the algorithm.
//!
//! # Two shapes of checked arithmetic left in place, not wrapped
//!
//! `rig/uaccess-panic-check.sh` also found live `panic_bounds_check` and
//! two live checked subtractions the block above's `wrapping_*` blanket
//! does not cover, deliberately:
//!
//! - `le32()`/`le64()`'s `b[i..i + 4]`/`b[i..i + 8]` slicing. Every call
//!   site's own loop keeps `i` within `len` before calling in (the same
//!   invariant the C's `p`/`b_end` pointer pair enforces by construction) --
//!   provably in range, but across a function boundary the compiler
//!   cannot see that. Left checked rather than switched to
//!   `get_unchecked()`: this is the untrusted-input boundary the whole
//!   point of porting to Rust was to get a bounds check on.
//! - `xxh64_update()`'s `memsize + len < 32` and `take = 32 - memsize`.
//!   `memsize` is `Xxh64State.memsize`, a plain field of a `#[repr(C)]`
//!   struct passed across the FFI boundary -- the algorithm's own
//!   invariant keeps it `< 32`, but nothing stops a corrupted or
//!   hand-built state from violating that. `wrapping_add` on the first
//!   check would let a wrapped (small) sum slip a corrupted `memsize`
//!   past the guard it exists to be; `wrapping_sub` on the second would
//!   silently turn a corrupted `memsize > 32` into a huge `take` instead
//!   of catching it. Both stay checked because wrapping here would make
//!   the outcome worse, not merely different -- unlike the two uses of
//!   `memsize + len` immediately after the first check passes (line-local
//!   redundant recomputations of an already-proven-safe value), which
//!   are `wrapping_*` like everything else.
//!
//! # Slices and indices, not pointer walking
//!
//! The C walks `const uint8_t *p` against a `b_end`. Doing the same in Rust
//! runs into two corners the C does not have: `ptr::add` and `offset_from`
//! both require a pointer into a real allocation, and `xxh32(NULL, 0, seed)`
//! is a perfectly ordinary call. So the input becomes a bounds-checked slice
//! at the boundary — empty when `len` is zero — and everything after that is
//! an index. The undefined behaviour goes away for free; **the loads do
//! not** — an index has to be written so that it lowers to the load the C
//! issues, which is the subject of the endianness note below.
//!
//! # Endianness, and the load that has to be one load
//!
//! The C reads with `get_unaligned_le32`/`get_unaligned_le64`, so the hash of
//! a byte string is the same on every architecture. Here that is
//! `u32::from_le_bytes`/`u64::from_le_bytes` over a **subslice** -- `b[i..i +
//! 8]` -- which is one bounds check and one unaligned load, and is a no-op on
//! little-endian.
//!
//! **The first version of `le32`/`le64` built the value from separately
//! indexed bytes** -- `u64::from_le_bytes([b[i], b[i + 1], ...])` -- with a
//! comment claiming it was "the same loads" as the C. It was not: that is
//! eight loads, eight bounds checks and a reassembly where
//! `get_unaligned_le64()` issues one load. The GOALS.md §4 rig measured the
//! cost at **4.52x slower than the C** on a 4 KiB buffer. Written out
//! bytewise it looked like it was spelling out what the hardware would do
//! anyway; it was spelling out what the hardware would then have to be told
//! to do.
//!
//! # State layout is the caller's
//!
//! `struct xxh32_state` and `struct xxh64_state` are declared in
//! `include/linux/xxhash.h` and embedded by callers, so the `#[repr(C)]`
//! mirrors below match them field for field (GOALS.md §5).
//!
//! Replaces: lib/xxhash.c

use core::ffi::c_void;

const PRIME32_1: u32 = 2654435761;
const PRIME32_2: u32 = 2246822519;
const PRIME32_3: u32 = 3266489917;
const PRIME32_4: u32 = 668265263;
const PRIME32_5: u32 = 374761393;

const PRIME64_1: u64 = 11400714785074694791;
const PRIME64_2: u64 = 14029467366897019727;
const PRIME64_3: u64 = 1609587929392839161;
const PRIME64_4: u64 = 9650029242287828579;
const PRIME64_5: u64 = 2870177450012600261;

/// Mirrors `struct xxh32_state` in `include/linux/xxhash.h`.
#[repr(C)]
pub struct Xxh32State {
    /// Bytes hashed so far, modulo 2^32.
    pub total_len_32: u32,
    /// Whether at least one full 16-byte block has been consumed.
    pub large_len: u32,
    /// Accumulator 1.
    pub v1: u32,
    /// Accumulator 2.
    pub v2: u32,
    /// Accumulator 3.
    pub v3: u32,
    /// Accumulator 4.
    pub v4: u32,
    /// Partial block not yet consumed.
    pub mem32: [u32; 4],
    /// Bytes valid in `mem32`.
    pub memsize: u32,
}

/// Mirrors `struct xxh64_state` in `include/linux/xxhash.h`.
#[repr(C)]
pub struct Xxh64State {
    /// Bytes hashed so far.
    pub total_len: u64,
    /// Accumulator 1.
    pub v1: u64,
    /// Accumulator 2.
    pub v2: u64,
    /// Accumulator 3.
    pub v3: u64,
    /// Accumulator 4.
    pub v4: u64,
    /// Partial block not yet consumed.
    pub mem64: [u64; 4],
    /// Bytes valid in `mem64`.
    pub memsize: u32,
}

/// The input as a slice. Empty for a zero length, so a NULL pointer with
/// `len == 0` — which the C accepts — never reaches `from_raw_parts`.
///
/// # Safety
/// `p` must be readable for `len` bytes when `len` is non-zero.
#[inline]
unsafe fn as_slice<'a>(p: *const c_void, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at a non-null
        // `p`. The slice is read-only and does not outlive the call.
        unsafe { core::slice::from_raw_parts(p as *const u8, len) }
    }
}

/// `get_unaligned_le32()`, bounds-checked.
///
/// Slicing first is what makes this one load: `b[i..i + 4]` is a single
/// bounds check, and the array conversion behind it cannot fail because the
/// range is four bytes long by construction. Indexing the four bytes
/// separately instead is four loads -- see the note at the top of this file.
#[inline]
fn le32(b: &[u8], i: usize) -> u32 {
    match <[u8; 4]>::try_from(&b[i..i + 4]) {
        Ok(w) => u32::from_le_bytes(w),
        // The slice is exactly four bytes long, so this arm is unreachable.
        Err(_) => 0,
    }
}

/// `get_unaligned_le64()`, bounds-checked. One load; see `le32`.
#[inline]
fn le64(b: &[u8], i: usize) -> u64 {
    match <[u8; 8]>::try_from(&b[i..i + 8]) {
        Ok(w) => u64::from_le_bytes(w),
        // The slice is exactly eight bytes long, so this arm is unreachable.
        Err(_) => 0,
    }
}

#[inline]
fn round32(seed: u32, input: u32) -> u32 {
    let seed = seed.wrapping_add(input.wrapping_mul(PRIME32_2));

    seed.rotate_left(13).wrapping_mul(PRIME32_1)
}

#[inline]
fn round64(acc: u64, input: u64) -> u64 {
    let acc = acc.wrapping_add(input.wrapping_mul(PRIME64_2));

    acc.rotate_left(31).wrapping_mul(PRIME64_1)
}

#[inline]
fn merge_round64(acc: u64, val: u64) -> u64 {
    let val = round64(0, val);

    (acc ^ val).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

/// The final avalanche for the 32-bit hash.
#[inline]
fn avalanche32(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^ (h >> 16)
}

/// The final avalanche for the 64-bit hash.
#[inline]
fn avalanche64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^ (h >> 32)
}

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
// The MODULE_*() metadata of the C file this replaced. It is real output
// for a built-in object: kbuild extracts .modinfo into the installed
// modules.builtin.modinfo. See kernel::kabi_modinfo.
kernel::kabi_modinfo! {
    "xxhash",
    file = "lib/xxhash",
    description = "xxHash",
    license = "Dual BSD/GPL",
}

kernel::kabi_rule!("type_string", "s#xxh32_state",
    "structure_type xxh32_state { member t#uint32_t total_len_32 data_member_location(0) , member t#uint32_t large_len data_member_location(4) , member t#uint32_t v1 data_member_location(8) , member t#uint32_t v2 data_member_location(12) , member t#uint32_t v3 data_member_location(16) , member t#uint32_t v4 data_member_location(20) , member array_type[4] { t#uint32_t } mem32 data_member_location(24) , member t#uint32_t memsize data_member_location(40) } byte_size(44)");
kernel::kabi_rule!("type_string", "s#xxh64_state",
    "structure_type xxh64_state { member t#uint64_t total_len data_member_location(0) , member t#uint64_t v1 data_member_location(8) , member t#uint64_t v2 data_member_location(16) , member t#uint64_t v3 data_member_location(24) , member t#uint64_t v4 data_member_location(32) , member array_type[4] { t#uint64_t } mem64 data_member_location(40) , member t#uint32_t memsize data_member_location(72) } byte_size(80)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");
kernel::kabi_rule!("type_string", "t#uint32_t",
    "typedef_type uint32_t { t#u32 }");
kernel::kabi_rule!("type_string", "t#uint64_t",
    "typedef_type uint64_t { t#u64 }");

kernel::kabi_export! {
    xxh32_copy_state,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xxh32_state } dst , formal_parameter pointer_type { const_type { s#xxh32_state } } src ) -> base_type void",
}

/// Body of `xxh32_copy_state()`.
///
/// # Safety
/// Both pointers must be valid, non-null and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn xxh32_copy_state(dst: *mut Xxh32State, src: *const Xxh32State) {
    // SAFETY: the caller's contract; this is the C's memcpy().
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 1) };
}

kernel::kabi_export! {
    xxh64_copy_state,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xxh64_state } dst , formal_parameter pointer_type { const_type { s#xxh64_state } } src ) -> base_type void",
}

/// Body of `xxh64_copy_state()`.
///
/// # Safety
/// Both pointers must be valid, non-null and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn xxh64_copy_state(dst: *mut Xxh64State, src: *const Xxh64State) {
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 1) };
}

kernel::kabi_export! {
    xxh32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } input , formal_parameter const_type { t#size_t } len , formal_parameter const_type { t#uint32_t } seed ) -> t#uint32_t",
}

/// Body of `xxh32()`.
///
/// # Safety
/// `input` must be readable for `len` bytes.
///
/// See `include/linux/xxhash.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn xxh32(input: *const c_void, len: usize, seed: u32) -> u32 {
    // SAFETY: the caller guarantees `len` readable bytes at `input`.
    let b = unsafe { as_slice(input, len) };
    let mut i = 0usize;
    let mut h32: u32;

    if len >= 16 {
        let limit = len.wrapping_sub(16);
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);

        loop {
            v1 = round32(v1, le32(b, i));
            v2 = round32(v2, le32(b, i.wrapping_add(4)));
            v3 = round32(v3, le32(b, i.wrapping_add(8)));
            v4 = round32(v4, le32(b, i.wrapping_add(12)));
            i = i.wrapping_add(16);
            if i > limit {
                break;
            }
        }

        h32 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h32 = seed.wrapping_add(PRIME32_5);
    }

    h32 = h32.wrapping_add(len as u32);

    while len.wrapping_sub(i) >= 4 {
        h32 = h32.wrapping_add(le32(b, i).wrapping_mul(PRIME32_3));
        h32 = h32.rotate_left(17).wrapping_mul(PRIME32_4);
        i = i.wrapping_add(4);
    }

    while i < len {
        h32 = h32.wrapping_add((b[i] as u32).wrapping_mul(PRIME32_5));
        h32 = h32.rotate_left(11).wrapping_mul(PRIME32_1);
        i = i.wrapping_add(1);
    }

    avalanche32(h32)
}

kernel::kabi_export! {
    xxh64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } input , formal_parameter const_type { t#size_t } len , formal_parameter const_type { t#uint64_t } seed ) -> t#uint64_t",
}

/// Body of `xxh64()`.
///
/// # Safety
/// `input` must be readable for `len` bytes.
///
/// See `include/linux/xxhash.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn xxh64(input: *const c_void, len: usize, seed: u64) -> u64 {
    // SAFETY: the caller guarantees `len` readable bytes at `input`.
    let b = unsafe { as_slice(input, len) };
    let mut i = 0usize;
    let mut h64: u64;

    if len >= 32 {
        let limit = len.wrapping_sub(32);
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        loop {
            v1 = round64(v1, le64(b, i));
            v2 = round64(v2, le64(b, i.wrapping_add(8)));
            v3 = round64(v3, le64(b, i.wrapping_add(16)));
            v4 = round64(v4, le64(b, i.wrapping_add(24)));
            i = i.wrapping_add(32);
            if i > limit {
                break;
            }
        }

        h64 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h64 = merge_round64(h64, v1);
        h64 = merge_round64(h64, v2);
        h64 = merge_round64(h64, v3);
        h64 = merge_round64(h64, v4);
    } else {
        h64 = seed.wrapping_add(PRIME64_5);
    }

    h64 = h64.wrapping_add(len as u64);

    while len.wrapping_sub(i) >= 8 {
        let k1 = round64(0, le64(b, i));

        h64 ^= k1;
        h64 = h64.rotate_left(27).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
        i = i.wrapping_add(8);
    }

    if len.wrapping_sub(i) >= 4 {
        h64 ^= (le32(b, i) as u64).wrapping_mul(PRIME64_1);
        h64 = h64.rotate_left(23).wrapping_mul(PRIME64_2).wrapping_add(PRIME64_3);
        i = i.wrapping_add(4);
    }

    while i < len {
        h64 ^= (b[i] as u64).wrapping_mul(PRIME64_5);
        h64 = h64.rotate_left(11).wrapping_mul(PRIME64_1);
        i = i.wrapping_add(1);
    }

    avalanche64(h64)
}

kernel::kabi_export! {
    xxh32_reset,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xxh32_state } statePtr , formal_parameter const_type { t#uint32_t } seed ) -> base_type void",
}

/// Body of `xxh32_reset()`.
///
/// # Safety
/// `state` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn xxh32_reset(state: *mut Xxh32State, seed: u32) {
    // ZERO THE WHOLE STRUCT FIRST, exactly as the C does. The C's
    // "use a local state for memcpy() to avoid strict-aliasing warnings"
    // dance has a second effect its comment does not mention: the memset
    // clears the TAIL PADDING after `memsize`, and the memcpy carries the
    // zeroed padding across. Writing only the fields leaves that padding
    // whatever was on the stack.
    //
    // The differential test caught this -- the hashes agreed everywhere and
    // the states did not. In a kernel that is not a cosmetic difference:
    // xxh64_copy_state() memcpy()s the whole struct, so uninitialised
    // padding propagates, and a struct that reaches userspace by any route
    // leaks it.
    // SAFETY: the caller guarantees `state` is valid and writable.
    unsafe {
        core::ptr::write_bytes(state, 0, 1);
        core::ptr::write(
            state,
            Xxh32State {
                total_len_32: 0,
                large_len: 0,
                v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
                v2: seed.wrapping_add(PRIME32_2),
                v3: seed,
                v4: seed.wrapping_sub(PRIME32_1),
                mem32: [0; 4],
                memsize: 0,
            },
        );
    }
}

kernel::kabi_export! {
    xxh64_reset,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xxh64_state } statePtr , formal_parameter const_type { t#uint64_t } seed ) -> base_type void",
}

/// Body of `xxh64_reset()`.
///
/// # Safety
/// `state` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn xxh64_reset(state: *mut Xxh64State, seed: u64) {
    // SAFETY: as xxh32_reset, including the leading zeroing of the
    // struct's tail padding.
    unsafe {
        core::ptr::write_bytes(state, 0, 1);
        core::ptr::write(
            state,
            Xxh64State {
                total_len: 0,
                v1: seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
                v2: seed.wrapping_add(PRIME64_2),
                v3: seed,
                v4: seed.wrapping_sub(PRIME64_1),
                mem64: [0; 4],
                memsize: 0,
            },
        );
    }
}

kernel::kabi_export! {
    xxh64_update,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#xxh64_state } state , formal_parameter pointer_type { const_type { base_type void } } input , formal_parameter const_type { t#size_t } len ) -> base_type int byte_size(4) encoding(5)",
}

/// Body of `xxh64_update()`. Returns 0, or `-EINVAL` for a NULL input.
///
/// # Safety
/// `state` must be valid and writable, and `input` readable for `len` bytes
/// unless it is NULL.
///
/// See `include/linux/xxhash.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn xxh64_update(
    state: *mut Xxh64State,
    input: *const c_void,
    len: usize,
) -> core::ffi::c_int {
    // 22 is EINVAL. The C returns -EINVAL; there is no errno header to
    // reach from here, and the value is fixed by the uapi.
    const EINVAL: core::ffi::c_int = 22;

    if input.is_null() {
        return -EINVAL;
    }

    // SAFETY: the caller guarantees `len` readable bytes at `input`, and
    // that `state` is valid, writable and uniquely borrowed for this call.
    let b = unsafe { as_slice(input, len) };
    let st = unsafe { &mut *state };
    let mut i = 0usize;

    st.total_len = st.total_len.wrapping_add(len as u64);

    // `mem64` is four u64s; viewing it as 32 bytes is what the C does too,
    // and the reads back out of it go through le64() exactly as the C's
    // get_unaligned_le64() does.
    let mem: &mut [u8; 32] = unsafe { &mut *(st.mem64.as_mut_ptr() as *mut [u8; 32]) };
    let memsize = st.memsize as usize;

    if memsize + len < 32 {
        mem[memsize..memsize.wrapping_add(len)].copy_from_slice(b);
        st.memsize = st.memsize.wrapping_add(len as u32);
        return 0;
    }

    if memsize != 0 {
        let take = 32 - memsize;

        mem[memsize..32].copy_from_slice(&b[..take]);

        st.v1 = round64(st.v1, le64(mem, 0));
        st.v2 = round64(st.v2, le64(mem, 8));
        st.v3 = round64(st.v3, le64(mem, 16));
        st.v4 = round64(st.v4, le64(mem, 24));

        i = take;
        st.memsize = 0;
    }

    if len.wrapping_sub(i) >= 32 {
        let limit = len.wrapping_sub(32);
        let mut v1 = st.v1;
        let mut v2 = st.v2;
        let mut v3 = st.v3;
        let mut v4 = st.v4;

        loop {
            v1 = round64(v1, le64(b, i));
            v2 = round64(v2, le64(b, i.wrapping_add(8)));
            v3 = round64(v3, le64(b, i.wrapping_add(16)));
            v4 = round64(v4, le64(b, i.wrapping_add(24)));
            i = i.wrapping_add(32);
            if i > limit {
                break;
            }
        }

        st.v1 = v1;
        st.v2 = v2;
        st.v3 = v3;
        st.v4 = v4;
    }

    if i < len {
        let rest = len.wrapping_sub(i);

        mem[..rest].copy_from_slice(&b[i..]);
        st.memsize = rest as u32;
    }

    0
}

kernel::kabi_export! {
    xxh64_digest,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#xxh64_state } } state ) -> t#uint64_t",
}

/// Body of `xxh64_digest()`.
///
/// # Safety
/// `state` must be valid and readable.
///
/// See `include/linux/xxhash.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn xxh64_digest(state: *const Xxh64State) -> u64 {
    // SAFETY: the caller guarantees `state` is valid and readable.
    let st = unsafe { &*state };
    // SAFETY: memsize is never above 32, which is mem64's size in bytes.
    let mem: &[u8; 32] = unsafe { &*(st.mem64.as_ptr() as *const [u8; 32]) };
    let n = st.memsize as usize;
    let mut i = 0usize;
    let mut h64: u64;

    if st.total_len >= 32 {
        h64 = st
            .v1
            .rotate_left(1)
            .wrapping_add(st.v2.rotate_left(7))
            .wrapping_add(st.v3.rotate_left(12))
            .wrapping_add(st.v4.rotate_left(18));
        h64 = merge_round64(h64, st.v1);
        h64 = merge_round64(h64, st.v2);
        h64 = merge_round64(h64, st.v3);
        h64 = merge_round64(h64, st.v4);
    } else {
        h64 = st.v3.wrapping_add(PRIME64_5);
    }

    h64 = h64.wrapping_add(st.total_len);

    while n.wrapping_sub(i) >= 8 {
        let k1 = round64(0, le64(mem, i));

        h64 ^= k1;
        h64 = h64.rotate_left(27).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
        i = i.wrapping_add(8);
    }

    if n.wrapping_sub(i) >= 4 {
        h64 ^= (le32(mem, i) as u64).wrapping_mul(PRIME64_1);
        h64 = h64.rotate_left(23).wrapping_mul(PRIME64_2).wrapping_add(PRIME64_3);
        i = i.wrapping_add(4);
    }

    while i < n {
        h64 ^= (mem[i] as u64).wrapping_mul(PRIME64_5);
        h64 = h64.rotate_left(11).wrapping_mul(PRIME64_1);
        i = i.wrapping_add(1);
    }

    avalanche64(h64)
}
