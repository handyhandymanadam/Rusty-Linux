// SPDX-License-Identifier: GPL-2.0-or-later

//! The ChaCha core -- the Rust bodies behind
//! `lib/crypto/chacha-block-generic.c`.
//!
//! Ported from `lib/crypto/chacha-block-generic.c` (6.18.49), Copyright (C)
//! 2015 Martin Willi. The permutation is RFC 7539's, unchanged.
//!
//! # Wrapping, again, and again it is the algorithm
//!
//! ChaCha is ARX — add, rotate, xor — and the add is modulo 2^32 by
//! definition. Every `+` here is `wrapping_add`, not out of caution but
//! because a checked add would panic the kernel on the first block of any
//! real keystream.
//!
//! # The quarter-round, written once
//!
//! The C spells out sixteen lines per double round, four times over. The
//! same eighty lines are one `quarter_round` here, called eight times per
//! double round. Rust inlines it; the arithmetic and its order are
//! identical, and the C's own comment calls the layout "the ChaCha core", so
//! nothing about the expansion is load-bearing. GOALS.md §5: nothing outside
//! can observe it, no layout or interface moves, nothing else changes.
//!
//! # Zeroization stays in C
//!
//! `chacha_zeroize_state()` is `memzero_explicit()`, whose entire purpose is
//! to survive an optimiser that can prove the write is dead. Rust has
//! `write_volatile`, but the kernel's guarantee is the kernel's barrier, and
//! reimplementing it here would be asserting something about codegen rather
//! than relying on the thing the kernel already relies on. The Rust calls
//! back into `lib/crypto/chacha-block-generic.c` for it.
//!
//! Replaces: lib/crypto/chacha-block-generic.c

use core::ffi::c_int;

/// `CHACHA_STATE_WORDS` from `include/crypto/chacha.h`.
const STATE_WORDS: usize = 16;
/// `HCHACHA_OUT_WORDS` from `include/crypto/chacha.h`.
const HCHACHA_OUT_WORDS: usize = 8;

/// Mirrors `struct chacha_state` in `include/crypto/chacha.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChachaState {
    /// The 16-word state matrix.
    pub x: [u32; STATE_WORDS],
}

extern "C" {
    /// `lib/crypto/chacha-block-generic.c`, wrapping the header's
    /// `chacha_zeroize_state()` -- that is `memzero_explicit()`, and its
    /// whole point is surviving an optimiser.
    fn rust_chacha_zeroize_state(state: *mut ChachaState);
}

/// One ChaCha quarter-round on four state indices.
#[inline(always)]
fn quarter_round(x: &mut [u32; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// The permutation. `nrounds` is 20 or 12; `lib/crypto/chacha-block-generic.c`
/// has already `WARN_ON_ONCE`d anything else.
fn permute(x: &mut [u32; STATE_WORDS], nrounds: c_int) {
    let mut i = 0;

    while i < nrounds {
        // Column rounds.
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 1, 5, 9, 13);
        quarter_round(x, 2, 6, 10, 14);
        quarter_round(x, 3, 7, 11, 15);

        // Diagonal rounds.
        quarter_round(x, 0, 5, 10, 15);
        quarter_round(x, 1, 6, 11, 12);
        quarter_round(x, 2, 7, 8, 13);
        quarter_round(x, 3, 4, 9, 14);

        i += 2;
    }
}

/// Body of `chacha_block_generic()`: one keystream block, and the block
/// counter incremented.
///
/// # Safety
/// `state` must be valid and writable; `out` must be writable for 64 bytes.
/// Same contract as the C.
///
/// See `include/crypto/chacha.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_chacha_block_generic(
    state: *mut ChachaState,
    out: *mut u8,
    nrounds: c_int,
) {
    // SAFETY: the caller guarantees `state` is valid, writable and uniquely
    // borrowed for this call.
    let st = unsafe { &mut *state };
    let mut permuted = ChachaState { x: st.x };

    permute(&mut permuted.x, nrounds);

    // put_unaligned_le32 of permuted[i] + state[i], sixteen times.
    for i in 0..STATE_WORDS {
        let w = permuted.x[i].wrapping_add(st.x[i]).to_le_bytes();

        // SAFETY: the caller guarantees 64 writable bytes at `out`, and
        // `i * 4 + 3 < 64` for every i below 16.
        unsafe {
            core::ptr::copy_nonoverlapping(w.as_ptr(), out.add(i * 4), 4);
        }
    }

    st.x[12] = st.x[12].wrapping_add(1);

    // SAFETY: `permuted` is a live local for the duration of the call.
    unsafe { rust_chacha_zeroize_state(&mut permuted) };
}

/// Body of `hchacha_block_generic()`: the abbreviated core used by XChaCha,
/// which skips the final addition and emits only eight words.
///
/// # Safety
/// `state` must be valid and readable; `out` must be writable for eight
/// `u32`s. Same contract as the C.
///
/// See `include/crypto/chacha.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_hchacha_block_generic(
    state: *const ChachaState,
    out: *mut u32,
    nrounds: c_int,
) {
    // SAFETY: the caller guarantees `state` is valid and readable.
    let mut permuted = ChachaState { x: unsafe { (*state).x } };

    permute(&mut permuted.x, nrounds);

    // SAFETY: the caller guarantees HCHACHA_OUT_WORDS writable words. The C
    // does this as two 16-byte memcpy()s from x[0..4] and x[12..16].
    unsafe {
        core::ptr::copy_nonoverlapping(permuted.x.as_ptr(), out, 4);
        core::ptr::copy_nonoverlapping(
            permuted.x.as_ptr().add(12),
            out.add(4),
            HCHACHA_OUT_WORDS - 4,
        );
    }

    // SAFETY: `permuted` is a live local.
    unsafe { rust_chacha_zeroize_state(&mut permuted) };
}
