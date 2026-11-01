// SPDX-License-Identifier: GPL-2.0-or-later

//! MD5 and HMAC-MD5 -- the Rust behind `lib/crypto/md5.c`.
//!
//! Ported from `lib/crypto/md5.c` (6.18.49). `md5_block_generic()` is derived
//! from the cryptoapi implementation, originally based on the public domain
//! implementation written by Colin Plumb in 1993.
//!
//! Replaces: lib/crypto/md5.c
//!
//! # No architecture dispatch here, unlike the rest of `lib/crypto`
//!
//! `logs/c-entry-rule.md`'s SIMD-dispatch note lists
//! `{blake2s,sha1,sha256,sha512,md5,poly1305,chacha,curve25519}.c` as one
//! family, all forking on SIMD the same way. **That is wrong for this file on
//! any configuration this project builds, and the correction belongs here.**
//! `CONFIG_CRYPTO_LIB_MD5_ARCH` (`lib/crypto/Kconfig`) defaults to `y` only for
//! `MIPS && CPU_CAVIUM_OCTEON`, `PPC`, or `SPARC64` -- never for x86-64, which
//! is the only architecture either of this project's configs build. So the
//! pristine C's `#ifdef CONFIG_CRYPTO_LIB_MD5_ARCH / #include "md5.h"` is dead
//! code here, `md5_blocks` is simply `#define`d to `md5_blocks_generic`, and
//! there is no dispatcher, no jump label, no `kernel_fpu_begin()`, and nothing
//! for a retained C file to do. This file is the WHOLE of `lib/crypto/md5.c`
//! on x86-64, not a portable-fallback half of it -- the `bcd`/`int_pow` shape,
//! not the `blake2s` shape. (The PPC/SPARC `md5-asm.o` arm in the Makefile is
//! untouched and still builds under `CONFIG_CRYPTO_LIB_MD5_ARCH=y`; it is
//! simply not called by anything any more, since the Rust always takes the
//! generic path. Neither architecture is one this project tests or builds
//! -- SCOPE.md §3a -- so this is dead weight, not a correctness regression,
//! on a target nobody here exercises.)
//!
//! # `memzero_explicit()` is reproduced with `write_volatile`
//!
//! Same reasoning as `blake2s_final()`: a plain zeroing store to a context
//! about to go out of scope is a dead store the compiler is entitled to
//! remove, and what would be left behind is exactly the key material and
//! chaining state HMAC-MD5 exists to protect. `write_volatile` in a byte loop
//! is not eligible for that optimisation.
//!
//! # The IPAD/OPAD XOR is done byte-wise, not word-wise
//!
//! The C XORs a `REPEAT_BYTE(HMAC_IPAD_VALUE)`-filled `unsigned long` into
//! each word of the 64-byte derived key, to get vectorised XOR from the
//! compiler. `REPEAT_BYTE` broadcasts the *same* byte to every byte of the
//! word, so XORing word-at-a-time with a repeated byte is bit-for-bit
//! identical, on any endianness, to XORing every individual byte with that
//! byte value -- the two are not merely equivalent in result, they perform
//! the exact same per-byte operation, just grouped differently. Byte-wise
//! avoids the C's union-of-`u8`-and-`unsigned long` reinterpretation, which
//! has no clean safe-Rust equivalent, for a difference nothing outside this
//! function can observe (GOALS.md §5's three questions are all "no" here).

use core::ffi::c_void;

/// `MD5_BLOCK_SIZE`.
const BLOCK_SIZE: usize = 64;
/// `MD5_BLOCK_WORDS`.
const BLOCK_WORDS: usize = 16;
/// `MD5_DIGEST_SIZE`.
const DIGEST_SIZE: usize = 16;

/// `MD5_H0`..`MD5_H3`: the MD5 initialization vector.
const MD5_IV: Md5BlockState = Md5BlockState {
    h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
};

/// `HMAC_IPAD_VALUE` (`include/crypto/hmac.h`).
const HMAC_IPAD_VALUE: u8 = 0x36;
/// `HMAC_OPAD_VALUE` (`include/crypto/hmac.h`).
const HMAC_OPAD_VALUE: u8 = 0x5c;

/// Mirrors `struct md5_block_state` (`include/crypto/md5.h`): the state of
/// the MD5 compression function alone, without the byte counter or partial
/// block buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Md5BlockState {
    /// The four 32-bit hash words.
    pub h: [u32; 4],
}

/// Mirrors `struct md5_ctx` (`include/crypto/md5.h`).
#[repr(C)]
pub struct Md5Ctx {
    /// The compression function state.
    pub state: Md5BlockState,
    /// Number of bytes processed so far.
    pub bytecount: u64,
    /// Partial block buffer; `bytecount % BLOCK_SIZE` bytes are valid.
    pub buf: [u8; BLOCK_SIZE],
}

/// Mirrors `struct hmac_md5_key` (`include/crypto/md5.h`).
#[repr(C)]
pub struct HmacMd5Key {
    /// Inner-hash initial state, derived from the key.
    pub istate: Md5BlockState,
    /// Outer-hash initial state, derived from the key.
    pub ostate: Md5BlockState,
}

/// Mirrors `struct hmac_md5_ctx` (`include/crypto/md5.h`).
#[repr(C)]
pub struct HmacMd5Ctx {
    /// The inner hash's own context.
    pub hash_ctx: Md5Ctx,
    /// The outer hash's state, primed by `hmac_md5_init()`.
    pub ostate: Md5BlockState,
}

// Layout must match the C exactly (GOALS.md §5's "Layout" boundary) --
// checked here as well as by `rig/layout-check.sh`, and confirmed against
// the captured pins in `logs/pins/md5.pins`.
const _: () = {
    assert!(core::mem::size_of::<Md5BlockState>() == 16);
    assert!(core::mem::size_of::<Md5Ctx>() == 88);
    assert!(core::mem::size_of::<HmacMd5Key>() == 32);
    assert!(core::mem::size_of::<HmacMd5Ctx>() == 104);
};

#[inline(always)]
fn f1(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}
#[inline(always)]
fn f2(x: u32, y: u32, z: u32) -> u32 {
    f1(z, x, y)
}
#[inline(always)]
fn f3(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
#[inline(always)]
fn f4(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

/// `MD5STEP(f, w, x, y, z, in, s)`: `w += f(x,y,z) + in; w = rotl(w, s) + x;`
/// with the update applied and returned, since Rust has no macro that
/// rewrites a local by name. Callers pass `f(x, y, z)` already evaluated.
#[inline(always)]
fn step(w: u32, f: u32, m: u32, x: u32, s: u32) -> u32 {
    w.wrapping_add(f).wrapping_add(m).rotate_left(s).wrapping_add(x)
}

/// `md5_block_generic()`: one 64-byte block, mirroring the C's manually
/// unrolled 64 `MD5STEP` invocations line for line so it can be checked
/// against the pristine C by inspection as well as by the differential
/// harness in `port/test/md5/`.
fn md5_block_generic(state: &mut Md5BlockState, data: &[u8; BLOCK_SIZE]) {
    let mut in_ = [0u32; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        in_[i] = u32::from_le_bytes([
            data[4 * i],
            data[4 * i + 1],
            data[4 * i + 2],
            data[4 * i + 3],
        ]);
    }

    let (mut a, mut b, mut c, mut d) = (state.h[0], state.h[1], state.h[2], state.h[3]);

    a = step(a, f1(b, c, d), in_[0].wrapping_add(0xd76a_a478), b, 7);
    d = step(d, f1(a, b, c), in_[1].wrapping_add(0xe8c7_b756), a, 12);
    c = step(c, f1(d, a, b), in_[2].wrapping_add(0x2420_70db), d, 17);
    b = step(b, f1(c, d, a), in_[3].wrapping_add(0xc1bd_ceee), c, 22);
    a = step(a, f1(b, c, d), in_[4].wrapping_add(0xf57c_0faf), b, 7);
    d = step(d, f1(a, b, c), in_[5].wrapping_add(0x4787_c62a), a, 12);
    c = step(c, f1(d, a, b), in_[6].wrapping_add(0xa830_4613), d, 17);
    b = step(b, f1(c, d, a), in_[7].wrapping_add(0xfd46_9501), c, 22);
    a = step(a, f1(b, c, d), in_[8].wrapping_add(0x6980_98d8), b, 7);
    d = step(d, f1(a, b, c), in_[9].wrapping_add(0x8b44_f7af), a, 12);
    c = step(c, f1(d, a, b), in_[10].wrapping_add(0xffff_5bb1), d, 17);
    b = step(b, f1(c, d, a), in_[11].wrapping_add(0x895c_d7be), c, 22);
    a = step(a, f1(b, c, d), in_[12].wrapping_add(0x6b90_1122), b, 7);
    d = step(d, f1(a, b, c), in_[13].wrapping_add(0xfd98_7193), a, 12);
    c = step(c, f1(d, a, b), in_[14].wrapping_add(0xa679_438e), d, 17);
    b = step(b, f1(c, d, a), in_[15].wrapping_add(0x49b4_0821), c, 22);

    a = step(a, f2(b, c, d), in_[1].wrapping_add(0xf61e_2562), b, 5);
    d = step(d, f2(a, b, c), in_[6].wrapping_add(0xc040_b340), a, 9);
    c = step(c, f2(d, a, b), in_[11].wrapping_add(0x265e_5a51), d, 14);
    b = step(b, f2(c, d, a), in_[0].wrapping_add(0xe9b6_c7aa), c, 20);
    a = step(a, f2(b, c, d), in_[5].wrapping_add(0xd62f_105d), b, 5);
    d = step(d, f2(a, b, c), in_[10].wrapping_add(0x0244_1453), a, 9);
    c = step(c, f2(d, a, b), in_[15].wrapping_add(0xd8a1_e681), d, 14);
    b = step(b, f2(c, d, a), in_[4].wrapping_add(0xe7d3_fbc8), c, 20);
    a = step(a, f2(b, c, d), in_[9].wrapping_add(0x21e1_cde6), b, 5);
    d = step(d, f2(a, b, c), in_[14].wrapping_add(0xc337_07d6), a, 9);
    c = step(c, f2(d, a, b), in_[3].wrapping_add(0xf4d5_0d87), d, 14);
    b = step(b, f2(c, d, a), in_[8].wrapping_add(0x455a_14ed), c, 20);
    a = step(a, f2(b, c, d), in_[13].wrapping_add(0xa9e3_e905), b, 5);
    d = step(d, f2(a, b, c), in_[2].wrapping_add(0xfcef_a3f8), a, 9);
    c = step(c, f2(d, a, b), in_[7].wrapping_add(0x676f_02d9), d, 14);
    b = step(b, f2(c, d, a), in_[12].wrapping_add(0x8d2a_4c8a), c, 20);

    a = step(a, f3(b, c, d), in_[5].wrapping_add(0xfffa_3942), b, 4);
    d = step(d, f3(a, b, c), in_[8].wrapping_add(0x8771_f681), a, 11);
    c = step(c, f3(d, a, b), in_[11].wrapping_add(0x6d9d_6122), d, 16);
    b = step(b, f3(c, d, a), in_[14].wrapping_add(0xfde5_380c), c, 23);
    a = step(a, f3(b, c, d), in_[1].wrapping_add(0xa4be_ea44), b, 4);
    d = step(d, f3(a, b, c), in_[4].wrapping_add(0x4bde_cfa9), a, 11);
    c = step(c, f3(d, a, b), in_[7].wrapping_add(0xf6bb_4b60), d, 16);
    b = step(b, f3(c, d, a), in_[10].wrapping_add(0xbebf_bc70), c, 23);
    a = step(a, f3(b, c, d), in_[13].wrapping_add(0x289b_7ec6), b, 4);
    d = step(d, f3(a, b, c), in_[0].wrapping_add(0xeaa1_27fa), a, 11);
    c = step(c, f3(d, a, b), in_[3].wrapping_add(0xd4ef_3085), d, 16);
    b = step(b, f3(c, d, a), in_[6].wrapping_add(0x0488_1d05), c, 23);
    a = step(a, f3(b, c, d), in_[9].wrapping_add(0xd9d4_d039), b, 4);
    d = step(d, f3(a, b, c), in_[12].wrapping_add(0xe6db_99e5), a, 11);
    c = step(c, f3(d, a, b), in_[15].wrapping_add(0x1fa2_7cf8), d, 16);
    b = step(b, f3(c, d, a), in_[2].wrapping_add(0xc4ac_5665), c, 23);

    a = step(a, f4(b, c, d), in_[0].wrapping_add(0xf429_2244), b, 6);
    d = step(d, f4(a, b, c), in_[7].wrapping_add(0x432a_ff97), a, 10);
    c = step(c, f4(d, a, b), in_[14].wrapping_add(0xab94_23a7), d, 15);
    b = step(b, f4(c, d, a), in_[5].wrapping_add(0xfc93_a039), c, 21);
    a = step(a, f4(b, c, d), in_[12].wrapping_add(0x655b_59c3), b, 6);
    d = step(d, f4(a, b, c), in_[3].wrapping_add(0x8f0c_cc92), a, 10);
    c = step(c, f4(d, a, b), in_[10].wrapping_add(0xffef_f47d), d, 15);
    b = step(b, f4(c, d, a), in_[1].wrapping_add(0x8584_5dd1), c, 21);
    a = step(a, f4(b, c, d), in_[8].wrapping_add(0x6fa8_7e4f), b, 6);
    d = step(d, f4(a, b, c), in_[15].wrapping_add(0xfe2c_e6e0), a, 10);
    c = step(c, f4(d, a, b), in_[6].wrapping_add(0xa301_4314), d, 15);
    b = step(b, f4(c, d, a), in_[13].wrapping_add(0x4e08_11a1), c, 21);
    a = step(a, f4(b, c, d), in_[4].wrapping_add(0xf753_7e82), b, 6);
    d = step(d, f4(a, b, c), in_[11].wrapping_add(0xbd3a_f235), a, 10);
    c = step(c, f4(d, a, b), in_[2].wrapping_add(0x2ad7_d2bb), d, 15);
    b = step(b, f4(c, d, a), in_[9].wrapping_add(0xeb86_d391), c, 21);

    state.h[0] = state.h[0].wrapping_add(a);
    state.h[1] = state.h[1].wrapping_add(b);
    state.h[2] = state.h[2].wrapping_add(c);
    state.h[3] = state.h[3].wrapping_add(d);
}

/// `md5_blocks()`: on this project's configurations this IS
/// `md5_blocks_generic()`, unconditionally -- see the module documentation.
///
/// # Safety
/// `state` must be valid, and `data` must be readable for
/// `nblocks * BLOCK_SIZE` bytes. `nblocks` must be at least 1: every call
/// site in this file guarantees it, matching the C's `do { } while
/// (--nblocks)`, which has the same requirement.
unsafe fn md5_blocks(state: &mut Md5BlockState, data: *const u8, nblocks: usize) {
    let mut data = data;
    let mut nblocks = nblocks;
    loop {
        // SAFETY: caller guarantees at least `nblocks * BLOCK_SIZE` readable
        // bytes remain from `data`, and `nblocks >= 1` here.
        let block = unsafe { &*(data as *const [u8; BLOCK_SIZE]) };
        md5_block_generic(state, block);
        // SAFETY: one block consumed; still within the caller's bound.
        data = unsafe { data.add(BLOCK_SIZE) };
        nblocks = nblocks.wrapping_sub(1);
        if nblocks == 0 {
            break;
        }
    }
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture (logs/pins/md5.pins); do not
// hand-edit.
kernel::kabi_rule!("type_string", "s#hmac_md5_ctx",
    "structure_type hmac_md5_ctx { member s#md5_ctx hash_ctx data_member_location(0) , member s#md5_block_state ostate data_member_location(88) } byte_size(104)");
kernel::kabi_rule!("type_string", "s#hmac_md5_key",
    "structure_type hmac_md5_key { member s#md5_block_state istate data_member_location(0) , member s#md5_block_state ostate data_member_location(16) } byte_size(32)");
kernel::kabi_rule!("type_string", "s#md5_block_state",
    "structure_type md5_block_state { member array_type[4] { t#u32 } h data_member_location(0) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#md5_ctx",
    "structure_type md5_ctx { member s#md5_block_state state data_member_location(0) , member t#u64 bytecount data_member_location(16) , member array_type[64] { t#u8 } buf data_member_location(24) } byte_size(88)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    md5_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#md5_ctx } ctx ) -> base_type void",
}

/// `md5_init()`: initialize a context for a new message.
///
/// # Safety
/// `ctx` must be valid for writes. `ctx.buf` is left untouched, matching the
/// C -- it is only ever read after being written by `md5_update()`.
#[no_mangle]
pub unsafe extern "C" fn md5_init(ctx: *mut Md5Ctx) {
    // SAFETY: caller guarantees `ctx` valid for writes; only the `state` and
    // `bytecount` fields are touched, so `buf` need not be initialized yet.
    unsafe {
        (*ctx).state = MD5_IV;
        (*ctx).bytecount = 0;
    }
}

kernel::kabi_export! {
    md5_update,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#md5_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len ) -> base_type void",
}

/// `md5_update()`: absorb `len` bytes of message data.
///
/// # Safety
/// `ctx` must be a valid, initialized `Md5Ctx`, and `data` readable for
/// `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn md5_update(ctx: *mut Md5Ctx, data: *const u8, len: usize) {
    // SAFETY: caller guarantees `ctx` valid.
    let mut partial = (unsafe { (*ctx).bytecount } % BLOCK_SIZE as u64) as usize;
    unsafe { (*ctx).bytecount = (*ctx).bytecount.wrapping_add(len as u64) };

    let mut data = data;
    let mut len = len;

    if partial.wrapping_add(len) >= BLOCK_SIZE {
        if partial != 0 {
            let l = BLOCK_SIZE.wrapping_sub(partial);
            // SAFETY: `partial + len >= BLOCK_SIZE` so `l <= len`, and the
            // caller guarantees `len` readable bytes at `data`. `buf` has
            // room for `l` bytes starting at `partial` (`partial + l ==
            // BLOCK_SIZE`).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data,
                    (*ctx).buf.as_mut_ptr().add(partial),
                    l,
                )
            };
            data = unsafe { data.add(l) };
            len = len.wrapping_sub(l);
            // SAFETY: `(*ctx).buf` holds one full, just-completed block.
            unsafe { md5_blocks(&mut (*ctx).state, (*ctx).buf.as_ptr(), 1) };
        }

        let nblocks = len / BLOCK_SIZE;
        len %= BLOCK_SIZE;
        if nblocks != 0 {
            // SAFETY: the caller's `data` has at least `len` (pre-update)
            // readable bytes remaining here, which is at least
            // `nblocks * BLOCK_SIZE`.
            unsafe { md5_blocks(&mut (*ctx).state, data, nblocks) };
            data = unsafe { data.add(nblocks * BLOCK_SIZE) };
        }
        partial = 0;
    }

    if len != 0 {
        // SAFETY: `len < BLOCK_SIZE - partial` here (the branch above
        // handled every case reaching `BLOCK_SIZE`), so the copy fits in
        // `buf`, and the caller guarantees `len` readable bytes at `data`.
        unsafe {
            core::ptr::copy_nonoverlapping(data, (*ctx).buf.as_mut_ptr().add(partial), len)
        };
    }
}

/// Shared body of `md5_final()` and the inner hash inside `hmac_md5_final()`:
/// pad, process the final block(s), and write the digest to `out`. Does
/// **not** wipe `ctx` -- callers zeroize on their own terms.
///
/// `ctx` is kept as a raw pointer throughout, rather than reborrowed as
/// `&mut Md5Ctx`, specifically so that `out` MAY alias `(*ctx).buf` --
/// `hmac_md5_final()` relies on exactly that, reusing the inner hash's own
/// buffer as scratch space for its digest. A `&mut Md5Ctx` spanning the call
/// would make that aliasing undefined behaviour even though every read of
/// `(*ctx).buf` in this function happens before `out` is written.
///
/// # Safety
/// `ctx` must be a valid, initialized `Md5Ctx`, and `out` writable for
/// `DIGEST_SIZE` bytes (whether or not `out` aliases `(*ctx).buf`).
unsafe fn md5_final_internal(ctx: *mut Md5Ctx, out: *mut u8) {
    // SAFETY: caller guarantees `ctx` valid.
    let bytecount = unsafe { (*ctx).bytecount };
    let bitcount = bytecount << 3;
    let mut partial = (bytecount % BLOCK_SIZE as u64) as usize;

    // SAFETY: `partial < BLOCK_SIZE`, so this index and the ranges below are
    // in bounds.
    unsafe { (*ctx).buf[partial] = 0x80 };
    partial = partial.wrapping_add(1);
    if partial > BLOCK_SIZE - 8 {
        // SAFETY: `(*ctx).buf` is a disjoint field of `*ctx`; this reference
        // is dropped at the end of the statement, before `out` (which may
        // alias `(*ctx).buf`, but is not touched until after this function's
        // final `md5_blocks()` call) is ever read from.
        unsafe { (&mut (*ctx).buf)[partial..BLOCK_SIZE].fill(0) };
        // SAFETY: `(*ctx).buf` holds one full, just-padded block.
        unsafe { md5_blocks(&mut (*ctx).state, (*ctx).buf.as_ptr(), 1) };
        partial = 0;
    }
    // SAFETY: see above.
    unsafe { (&mut (*ctx).buf)[partial..BLOCK_SIZE - 8].fill(0) };
    unsafe { (&mut (*ctx).buf)[BLOCK_SIZE - 8..].copy_from_slice(&bitcount.to_le_bytes()) };
    // SAFETY: `(*ctx).buf` holds one full, fully-padded final block.
    unsafe { md5_blocks(&mut (*ctx).state, (*ctx).buf.as_ptr(), 1) };

    // cpu_to_le32_array(ctx->state.h, 4); memcpy(out, ctx->state.h, 16).
    // Computed into a local rather than mutated in place (as
    // blake2s_final() does): `out` may alias `(*ctx).buf`, but never
    // `(*ctx).state`, so the read here is race-free regardless of aliasing.
    let mut le = [0u8; DIGEST_SIZE];
    for i in 0..4 {
        // SAFETY: `ctx` valid.
        let w = unsafe { (*ctx).state.h[i] };
        le[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // SAFETY: caller guarantees `out` writable for `DIGEST_SIZE` bytes.
    unsafe { core::ptr::copy_nonoverlapping(le.as_ptr(), out, DIGEST_SIZE) };
}

/// Zero `len` bytes at `p`, the way `memzero_explicit()` does: a volatile
/// write per byte, so the store cannot be optimised away as dead even though
/// the object is about to go out of scope. See the module documentation.
///
/// # Safety
/// `p` must be valid for writes for `len` bytes.
unsafe fn zeroize(p: *mut c_void, len: usize) {
    let p = p as *mut u8;
    for i in 0..len {
        // SAFETY: `i < len`, and the caller guarantees `p` valid for `len`
        // bytes.
        unsafe { p.add(i).write_volatile(0) };
    }
}

kernel::kabi_export! {
    md5_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#md5_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// `md5_final()`: finish computing the digest and wipe `ctx`.
///
/// # Safety
/// `ctx` must be a valid, initialized `Md5Ctx`, and `out` writable for
/// `DIGEST_SIZE` bytes and not aliasing `ctx`.
#[no_mangle]
pub unsafe extern "C" fn md5_final(ctx: *mut Md5Ctx, out: *mut u8) {
    // SAFETY: caller guarantees `ctx` valid and `out` a fresh, non-aliasing
    // output buffer.
    unsafe { md5_final_internal(ctx, out) };
    // memzero_explicit(ctx, sizeof(*ctx)).
    // SAFETY: `ctx` valid for its own size.
    unsafe { zeroize(ctx as *mut c_void, core::mem::size_of::<Md5Ctx>()) };
}

kernel::kabi_export! {
    md5,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// `md5()`: compute an MD5 digest in one shot.
///
/// # Safety
/// `data` must be readable for `len` bytes, and `out` writable for
/// `DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn md5(data: *const u8, len: usize, out: *mut u8) {
    // Inlines md5_init()'s effect; `buf` is never read before `md5_update()`
    // writes it, so zeroing it here (unlike the C's uninitialized stack
    // local) changes nothing observable -- see the module documentation.
    let mut ctx = Md5Ctx {
        state: MD5_IV,
        bytecount: 0,
        buf: [0u8; BLOCK_SIZE],
    };
    let ctx = &mut ctx as *mut Md5Ctx;
    // SAFETY: `ctx` is a valid, live pointer to a local variable; `data` and
    // `out` are the caller's, per this function's own contract.
    unsafe {
        md5_update(ctx, data, len);
        md5_final(ctx, out);
    }
}

/// Body of `hmac_md5_preparekey()`: derive `istate`/`ostate` from a raw key
/// of any length. See the module documentation for the byte-wise IPAD/OPAD
/// XOR.
///
/// # Safety
/// `istate` and `ostate` must be valid for writes, and `raw_key` readable
/// for `raw_key_len` bytes.
unsafe fn hmac_md5_preparekey_internal(
    istate: *mut Md5BlockState,
    ostate: *mut Md5BlockState,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    let mut derived_key = [0u8; BLOCK_SIZE];

    if raw_key_len > BLOCK_SIZE {
        // SAFETY: caller guarantees `raw_key_len` readable bytes at
        // `raw_key`; `derived_key` is `BLOCK_SIZE` bytes.
        unsafe { md5(raw_key, raw_key_len, derived_key.as_mut_ptr()) };
    } else {
        // SAFETY: `raw_key_len <= BLOCK_SIZE == derived_key.len()`, and the
        // caller guarantees `raw_key_len` readable bytes at `raw_key`.
        unsafe {
            core::ptr::copy_nonoverlapping(raw_key, derived_key.as_mut_ptr(), raw_key_len)
        };
    }

    for b in derived_key.iter_mut() {
        *b ^= HMAC_IPAD_VALUE;
    }
    // SAFETY: caller guarantees `istate` valid for writes.
    unsafe { *istate = MD5_IV };
    // SAFETY: `istate` valid; `derived_key` holds one full block.
    unsafe { md5_blocks(&mut *istate, derived_key.as_ptr(), 1) };

    for b in derived_key.iter_mut() {
        *b ^= HMAC_OPAD_VALUE ^ HMAC_IPAD_VALUE;
    }
    // SAFETY: caller guarantees `ostate` valid for writes.
    unsafe { *ostate = MD5_IV };
    // SAFETY: `ostate` valid; `derived_key` holds one full block.
    unsafe { md5_blocks(&mut *ostate, derived_key.as_ptr(), 1) };

    // memzero_explicit(&derived_key, sizeof(derived_key)).
    // SAFETY: `derived_key` is a valid local array.
    unsafe { zeroize(derived_key.as_mut_ptr() as *mut c_void, BLOCK_SIZE) };
}

kernel::kabi_export! {
    hmac_md5_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_md5_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// `hmac_md5_preparekey()`: prepare a reusable HMAC-MD5 key.
///
/// # Safety
/// `key` must be valid for writes, and `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5_preparekey(
    key: *mut HmacMd5Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    let istate = unsafe { core::ptr::addr_of_mut!((*key).istate) };
    let ostate = unsafe { core::ptr::addr_of_mut!((*key).ostate) };
    // SAFETY: caller guarantees `key` valid for writes and `raw_key`
    // readable for `raw_key_len` bytes; `istate`/`ostate` are disjoint
    // fields of `*key`.
    unsafe { hmac_md5_preparekey_internal(istate, ostate, raw_key, raw_key_len) };
}

kernel::kabi_export! {
    hmac_md5_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_md5_ctx } ctx , formal_parameter pointer_type { const_type { s#hmac_md5_key } } key ) -> base_type void",
}

/// `hmac_md5_init()`: initialize a context for a new message, from a
/// prepared key.
///
/// # Safety
/// `ctx` must be valid for writes, and `key` a valid, initialized
/// `HmacMd5Key`.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5_init(ctx: *mut HmacMd5Ctx, key: *const HmacMd5Key) {
    // SAFETY: caller guarantees both valid. `hash_ctx.buf` is left
    // untouched, matching the C -- only read after `md5_update()` writes it.
    unsafe {
        (*ctx).hash_ctx.state = (*key).istate;
        (*ctx).hash_ctx.bytecount = BLOCK_SIZE as u64;
        (*ctx).ostate = (*key).ostate;
    }
}

kernel::kabi_export! {
    hmac_md5_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_md5_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// `hmac_md5_init_usingrawkey()`: initialize a context for a new message,
/// deriving the key on the fly.
///
/// # Safety
/// `ctx` must be valid for writes, and `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5_init_usingrawkey(
    ctx: *mut HmacMd5Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    let istate = unsafe { core::ptr::addr_of_mut!((*ctx).hash_ctx.state) };
    let ostate = unsafe { core::ptr::addr_of_mut!((*ctx).ostate) };
    // SAFETY: caller guarantees `ctx` valid for writes and `raw_key`
    // readable for `raw_key_len` bytes; `istate`/`ostate` are disjoint
    // fields of `*ctx`.
    unsafe { hmac_md5_preparekey_internal(istate, ostate, raw_key, raw_key_len) };
    // SAFETY: caller guarantees `ctx` valid.
    unsafe { (*ctx).hash_ctx.bytecount = BLOCK_SIZE as u64 };
}

kernel::kabi_export! {
    hmac_md5_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_md5_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// `hmac_md5_final()`: finish computing the HMAC value and wipe `ctx`.
///
/// # Safety
/// `ctx` must be a valid, initialized `HmacMd5Ctx`, and `out` writable for
/// `DIGEST_SIZE` bytes and not aliasing `ctx`.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5_final(ctx: *mut HmacMd5Ctx, out: *mut u8) {
    let hash_ctx = unsafe { core::ptr::addr_of_mut!((*ctx).hash_ctx) };
    // SAFETY: `hash_ctx` valid; the inner hash's digest is written into its
    // own `buf`, which `md5_final_internal()` explicitly permits aliasing
    // (see its doc comment) -- this is the C's own reuse of that buffer as
    // scratch space, reproduced rather than avoided.
    let inner_out = unsafe { (*hash_ctx).buf.as_mut_ptr() };
    unsafe { md5_final_internal(hash_ctx, inner_out) };

    // Outer padding, built on top of the inner digest now sitting in
    // buf[0..DIGEST_SIZE].
    // SAFETY: `hash_ctx` valid; every index and range below is within
    // `BLOCK_SIZE` (`DIGEST_SIZE < BLOCK_SIZE - 8`).
    unsafe {
        (&mut (*hash_ctx).buf)[DIGEST_SIZE..BLOCK_SIZE].fill(0);
        (*hash_ctx).buf[DIGEST_SIZE] = 0x80;
        let bitcount: u64 = 8 * (BLOCK_SIZE + DIGEST_SIZE) as u64;
        (&mut (*hash_ctx).buf)[BLOCK_SIZE - 8..].copy_from_slice(&bitcount.to_le_bytes());
        md5_blocks(&mut (*ctx).ostate, (*hash_ctx).buf.as_ptr(), 1);
    }

    let mut le = [0u8; DIGEST_SIZE];
    for i in 0..4 {
        // SAFETY: `ctx` valid.
        let w = unsafe { (*ctx).ostate.h[i] };
        le[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    // SAFETY: caller guarantees `out` writable for `DIGEST_SIZE` bytes and
    // not aliasing `ctx`.
    unsafe { core::ptr::copy_nonoverlapping(le.as_ptr(), out, DIGEST_SIZE) };

    // memzero_explicit(ctx, sizeof(*ctx)).
    // SAFETY: `ctx` valid for its own size.
    unsafe { zeroize(ctx as *mut c_void, core::mem::size_of::<HmacMd5Ctx>()) };
}

kernel::kabi_export! {
    hmac_md5,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_md5_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// `hmac_md5()`: compute an HMAC-MD5 value in one shot, using a prepared
/// key.
///
/// # Safety
/// `key` must be a valid, initialized `HmacMd5Key`; `data` readable for
/// `data_len` bytes; `out` writable for `DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5(
    key: *const HmacMd5Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx = HmacMd5Ctx {
        hash_ctx: Md5Ctx {
            state: MD5_IV,
            bytecount: 0,
            buf: [0u8; BLOCK_SIZE],
        },
        ostate: MD5_IV,
    };
    let ctx = &mut ctx as *mut HmacMd5Ctx;
    // SAFETY: `ctx` is a valid, live pointer to a local variable; `key`,
    // `data` and `out` are the caller's, per this function's own contract.
    // `hmac_md5_update()` is `static inline` in the C header and calls only
    // `md5_update()`, so it is inlined here rather than reproduced as a
    // symbol -- it is not among this file's exported functions.
    unsafe {
        hmac_md5_init(ctx, key);
        md5_update(core::ptr::addr_of_mut!((*ctx).hash_ctx), data, data_len);
        hmac_md5_final(ctx, out);
    }
}

kernel::kabi_export! {
    hmac_md5_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// `hmac_md5_usingrawkey()`: compute an HMAC-MD5 value in one shot, using a
/// raw key.
///
/// # Safety
/// `raw_key` must be readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_md5_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx = HmacMd5Ctx {
        hash_ctx: Md5Ctx {
            state: MD5_IV,
            bytecount: 0,
            buf: [0u8; BLOCK_SIZE],
        },
        ostate: MD5_IV,
    };
    let ctx = &mut ctx as *mut HmacMd5Ctx;
    // SAFETY: `ctx` is a valid, live pointer to a local variable; the other
    // arguments are the caller's, per this function's own contract.
    unsafe {
        hmac_md5_init_usingrawkey(ctx, raw_key, raw_key_len);
        md5_update(core::ptr::addr_of_mut!((*ctx).hash_ctx), data, data_len);
        hmac_md5_final(ctx, out);
    }
}

// Built-in: `<modname>.<tag>=<value>` (kernel::kabi_modinfo). As a module
// (CRYPTO_LIB_MD5=m, e.g. arm64 defconfig; never the case on x86-64 where it
// is =y) modpost wants the UNPREFIXED `license=`/`description=` of the C's
// MODULE_LICENSE()/MODULE_DESCRIPTION(), else "missing MODULE_LICENSE()".
#[cfg(not(MODULE))]
kernel::kabi_modinfo! {
    "md5",
    file = "lib/crypto/md5",
    description = "MD5 and HMAC-MD5 library functions",
    license = "GPL",
}

#[cfg(MODULE)]
core::arch::global_asm!(
    ".section \".modinfo\",\"a\"",
    ".asciz \"description=MD5 and HMAC-MD5 library functions\"",
    ".asciz \"license=GPL\"",
    ".previous",
);
