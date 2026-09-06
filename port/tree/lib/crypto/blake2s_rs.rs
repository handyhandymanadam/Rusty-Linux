// SPDX-License-Identifier: GPL-2.0 OR MIT

//! BLAKE2s -- the Rust behind `lib/crypto/blake2s.c`.
//!
//! Ported from `lib/crypto/blake2s.c` (6.18.49), Copyright (C) 2015-2019
//! Jason A. Donenfeld <Jason@zx2c4.com>. Dual GPL-2.0/MIT, as the C is.
//!
//! Replaces: lib/crypto/blake2s.c
//!
//! # The C file is not gone, and this is the pattern for all of `lib/crypto`
//!
//! What remains of `blake2s.c` is the architecture dispatch: two static keys,
//! `kernel_fpu_begin()`, and `asmlinkage` calls into the SSSE3 and AVX-512
//! cores. `$(SRCARCH)/blake2s.h` builds `blake2s_compress()` out of those as
//! a **`static`** function, so it has no symbol; the retained C gives it one
//! as `blake2s_compress_dispatch()` and this file calls that.
//!
//! `lib/crypto/{sha1,sha256,sha512,md5,poly1305,chacha,curve25519}.c` all
//! fork on SIMD the same way, so this arrangement is the one that decides how
//! much of `lib/crypto` can move. It is recorded in `logs/c-entry-rule.md`.
//!
//! # The generic compression is REACHED on x86-64, not just on the fallback
//! # architectures
//!
//! It would be easy to assume the Rust body below is dead code on a machine
//! with SSSE3. It is not: `blake2s_compress()` calls it whenever
//! `may_use_simd()` is false, which includes hard IRQ context, and
//! `/dev/random` drives BLAKE2s from places where that happens.
//!
//! # `blake2s_final()` wipes the state, and that is a security property
//!
//! `memzero_explicit()` is a `memset` the compiler is forbidden to remove as
//! a dead store to a dying object. `write_volatile` in a loop is the same
//! guarantee here. A plain `= Default::default()` or `*state = zeroed()` is
//! the Rust that gives identical answers and leaves the chaining values in
//! memory -- the exact shape of the `memneq` trap, in a different file.

use core::ffi::c_uint;

/// `BLAKE2S_BLOCK_SIZE`.
const BLOCK_SIZE: usize = 64;

/// `IS_ENABLED(DEBUG)` as the C evaluates it here.
///
/// **It is unconditionally false, and reproducing it anyway is the point.**
/// `IS_ENABLED(x)` tests for `x_ENABLED` being defined, so `IS_ENABLED(DEBUG)`
/// asks about `DEBUG_ENABLED`, which no Kconfig produces -- `DEBUG` is the
/// file-local `#define` convention, and `lib/crypto/blake2s.c` does not use
/// it. So both of the C's `WARN_ON(IS_ENABLED(DEBUG) && ...)` guards are dead
/// in every kernel build.
///
/// They are carried here as `if DEBUG && ...` rather than dropped, because
/// "this guard can never fire" is a claim about a macro three headers away
/// and the next person to add `#define DEBUG` to that file should get the
/// same behaviour from both languages. It costs nothing: the condition folds
/// away.
const DEBUG: bool = false;

/// `blake2s_sigma[10][16]` -- the message-word permutation per round.
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// `enum blake2s_iv` -- the BLAKE2s initialisation vector.
const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
];

/// Mirrors `struct blake2s_state` (`include/crypto/blake2s.h`).
///
/// **`h`, `t` and `f` are read by hand-written assembly**, which is why the C
/// carries a comment telling anyone editing it to keep them where they are.
/// Their offsets are 0, 32 and 40 and the struct is 120 bytes;
/// `rig/layout-check.sh` measures that against the C rather than trusting it.
#[repr(C)]
pub struct Blake2sState {
    /// Chaining value.
    pub h: [u32; 8],
    /// Counter, low then high.
    pub t: [u32; 2],
    /// Finalisation flags.
    pub f: [u32; 2],
    /// Partial block.
    pub buf: [u8; BLOCK_SIZE],
    /// Bytes held in `buf`.
    pub buflen: c_uint,
    /// Digest length this state was initialised for.
    pub outlen: c_uint,
}

extern "C" {
    /// `lib/crypto/blake2s.c`. The architecture dispatcher, which is `static`
    /// there and needs a symbol; see the module documentation.
    fn blake2s_compress_dispatch(state: *mut Blake2sState, block: *const u8, nblocks: usize, inc: u32);
}

/// One `G` of the round function.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn g(v: &mut [u32; 16], r: usize, i: usize, a: usize, b: usize, c: usize, d: usize, m: &[u32; 16]) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i] as usize]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i + 1] as usize]);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// `blake2s_increment_counter()`: a 64-bit counter kept in two `u32`s.
#[inline(always)]
fn increment_counter(state: &mut Blake2sState, inc: u32) {
    state.t[0] = state.t[0].wrapping_add(inc);
    // The carry: `state->t[0] < inc` AFTER the addition.
    state.t[1] = state.t[1].wrapping_add(u32::from(state.t[0] < inc));
}

/// `blake2s_compress_generic()`, exported to the retained C under a
/// `rust_`-prefixed name because the C keeps the unprefixed one as its
/// fall-back symbol.
///
/// # Safety
/// `state` must be a valid `blake2s_state` and `block` readable for
/// `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_blake2s_compress_generic(
    state: *mut Blake2sState,
    block: *const u8,
    nblocks: usize,
    inc: u32,
) {
    // SAFETY: the caller guarantees a valid state.
    let state = unsafe { &mut *state };
    let mut block = block;
    let mut nblocks = nblocks;

    if DEBUG && nblocks > 1 && inc != BLOCK_SIZE as u32 {
        kernel::warn_on!(true);
    }

    while nblocks > 0 {
        increment_counter(state, inc);

        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            // SAFETY: `nblocks > 0`, so 64 bytes are readable from `block`.
            // le32_to_cpu_array() after a memcpy is a little-endian load.
            *w = u32::from_le(unsafe { (block.add(i * 4) as *const u32).read_unaligned() });
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&state.h);
        v[8..12].copy_from_slice(&IV[..4]);
        v[12] = IV[4] ^ state.t[0];
        v[13] = IV[5] ^ state.t[1];
        v[14] = IV[6] ^ state.f[0];
        v[15] = IV[7] ^ state.f[1];

        for r in 0..10 {
            g(&mut v, r, 0, 0, 4, 8, 12, &m);
            g(&mut v, r, 1, 1, 5, 9, 13, &m);
            g(&mut v, r, 2, 2, 6, 10, 14, &m);
            g(&mut v, r, 3, 3, 7, 11, 15, &m);
            g(&mut v, r, 4, 0, 5, 10, 15, &m);
            g(&mut v, r, 5, 1, 6, 11, 12, &m);
            g(&mut v, r, 6, 2, 7, 8, 13, &m);
            g(&mut v, r, 7, 3, 4, 9, 14, &m);
        }

        for i in 0..8 {
            state.h[i] ^= v[i] ^ v[i + 8];
        }

        // SAFETY: one block consumed; `nblocks` still bounds what is left.
        block = unsafe { block.add(BLOCK_SIZE) };
        nblocks -= 1;
    }
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "s#blake2s_state",
    "structure_type blake2s_state { member array_type[8] { t#u32 } h data_member_location(0) , member array_type[2] { t#u32 } t data_member_location(32) , member array_type[2] { t#u32 } f data_member_location(40) , member array_type[64] { t#u8 } buf data_member_location(48) , member base_type unsigned int byte_size(4) encoding(7) buflen data_member_location(112) , member base_type unsigned int byte_size(4) encoding(7) outlen data_member_location(116) } byte_size(120)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    blake2s_update,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#blake2s_state } state , formal_parameter pointer_type { const_type { t#u8 } } in , formal_parameter t#size_t inlen ) -> base_type void",
}

/// Body of `blake2s_update()`: absorb `inlen` bytes.
///
/// **It deliberately leaves a non-empty buffer**: the final block cannot be
/// compressed until `blake2s_final()` knows it is final, so the last
/// `1..=64` bytes always stay in `state.buf`. That is why the middle branch
/// is `inlen > BLOCK_SIZE` and not `>=`, and why it compresses
/// `nblocks - 1` blocks rather than `nblocks`. Both off-by-ones give the
/// right answer for most inputs and the wrong one for a multiple of 64.
///
/// # Safety
/// `state` must be a valid, initialised `blake2s_state` and `in_` readable
/// for `inlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn blake2s_update(state: *mut Blake2sState, in_: *const u8, inlen: usize) {
    // No named `&mut *state` reborrow here: `blake2s_compress_dispatch`
    // takes the raw `state` and (being a foreign, externally-defined
    // function) may access it in a way that a live Rust reference across
    // the call cannot safely assume survives -- same shape as the
    // zstd_decompress_block_rs.rs fix (found by the same sweep,
    // 2026-09-06). Every field access below goes through a fresh
    // `(*state).field` instead.
    // SAFETY: the caller guarantees a valid state, for every access below.
    let fill = BLOCK_SIZE - unsafe { (*state).buflen } as usize;
    let mut in_ = in_;
    let mut inlen = inlen;

    if inlen == 0 {
        return;
    }

    if inlen > fill {
        // SAFETY: `fill <= 64 - buflen`, so the copy fits in `buf`, and the
        // caller guarantees `inlen > fill` readable bytes.
        unsafe {
            let buflen = (*state).buflen as usize;
            core::ptr::copy_nonoverlapping(in_, (*state).buf.as_mut_ptr().add(buflen), fill);
            blake2s_compress_dispatch(state, (*state).buf.as_ptr(), 1, BLOCK_SIZE as u32);
            (*state).buflen = 0;
            in_ = in_.add(fill);
        }
        inlen -= fill;
    }

    if inlen > BLOCK_SIZE {
        // DIV_ROUND_UP, then one fewer -- see the doc comment.
        let nblocks = inlen.div_ceil(BLOCK_SIZE);
        // SAFETY: `(nblocks - 1) * 64 < inlen` readable bytes.
        unsafe {
            blake2s_compress_dispatch(state, in_, nblocks - 1, BLOCK_SIZE as u32);
            in_ = in_.add(BLOCK_SIZE * (nblocks - 1));
        }
        inlen -= BLOCK_SIZE * (nblocks - 1);
    }

    // SAFETY: `inlen <= 64 - buflen` here, so the copy fits.
    unsafe {
        let buflen = (*state).buflen as usize;
        core::ptr::copy_nonoverlapping(in_, (*state).buf.as_mut_ptr().add(buflen), inlen);
        (*state).buflen += inlen as c_uint;
    }
}

kernel::kabi_export! {
    blake2s_final,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#blake2s_state } state , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// Body of `blake2s_final()`: pad, set the last-block flag, compress, emit
/// `state.outlen` bytes, and **wipe the state**.
///
/// # Safety
/// `state` must be a valid, initialised `blake2s_state` and `out` writable
/// for `state.outlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn blake2s_final(state: *mut Blake2sState, out: *mut u8) {
    if DEBUG && out.is_null() {
        kernel::warn_on!(true);
    }

    // No named `&mut *state` reborrow held across `blake2s_compress_dispatch`
    // -- same reasoning as `blake2s_update`'s fix above, found by the same
    // sweep (2026-09-06). Every field access goes through a fresh
    // `(*state).field` instead.
    // SAFETY: the caller guarantees a valid state, for every access below.
    unsafe {
        // blake2s_set_lastblock().
        (*state).f[0] = u32::MAX;

        let buflen = (*state).buflen as usize;
        // Padding. Not `(*state).buf[buflen..].fill(0)`: that indexing
        // expression implicitly autorefs a `&mut` out of the raw
        // dereference, exactly what this function no longer does anywhere
        // else (`dangerous_implicit_autorefs` catches it at deny-level).
        core::ptr::write_bytes((*state).buf.as_mut_ptr().add(buflen), 0, BLOCK_SIZE - buflen);
    }

    // SAFETY: `state` is valid and `buf` is 64 bytes. `inc` is the number of
    // bytes actually present, NOT the block size -- the counter must end at
    // the true message length.
    unsafe {
        let buflen = (*state).buflen as usize;
        blake2s_compress_dispatch(state, (*state).buf.as_ptr(), 1, buflen as u32);
    };

    // cpu_to_le32_array(state->h, 8), then memcpy(out, state->h, outlen).
    let mut le = [0u8; 32];
    // SAFETY: `state` is valid.
    for (i, w) in unsafe { (*state).h }.iter().enumerate() {
        le[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // SAFETY: `state` is valid.
    let outlen = unsafe { (*state).outlen } as usize;
    // SAFETY: the caller guarantees `outlen` writable bytes, and `outlen` is
    // at most BLAKE2S_HASH_SIZE (32) by construction of __blake2s_init().
    unsafe { core::ptr::copy_nonoverlapping(le.as_ptr(), out, outlen) };

    // memzero_explicit(state, sizeof(*state)). VOLATILE WRITES: a plain
    // zeroing of a struct that is about to die is a dead store the compiler
    // may delete, and what would be left in memory is the chaining value.
    let p = state as *mut u8;
    for i in 0..core::mem::size_of::<Blake2sState>() {
        // SAFETY: `state` is valid for its own size.
        unsafe { p.add(i).write_volatile(0) };
    }
}
