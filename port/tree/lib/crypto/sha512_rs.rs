// SPDX-License-Identifier: GPL-2.0-or-later

//! SHA-384, SHA-512, HMAC-SHA384, and HMAC-SHA512 -- the Rust behind
//! `lib/crypto/sha512.c`.
//!
//! Ported from `lib/crypto/sha512.c` (6.18.49), Copyright 2025 Google LLC.
//!
//! Replaces: lib/crypto/sha512.c
//!
//! # The C file is not gone -- same split as `blake2s_rs.rs`
//!
//! `sha512.c` keeps the architecture dispatch (a `static_call` selecting the
//! SSSE3/AVX/AVX2 core, patched at boot) because that is three things Rust
//! cannot express here: the `static_call` itself, `kernel_fpu_begin()`/
//! `kernel_fpu_end()`, and `asmlinkage` calls into hand-written asm. See
//! `blake2s_rs.rs`'s module doc and `logs/c-entry-rule.md`.
//! `sha512_blocks()` is `static` there, so `sha512_blocks_dispatch()` gives
//! it a symbol for this file to call.
//!
//! # The round function is a straight loop, not the C's 8-at-a-time unroll
//!
//! `sha512_block_generic()` in the C computes eight rounds per loop
//! iteration with the accumulator rotation written out by hand (`t1`/`t2`
//! reassigned to different named variables each time) -- a hand-unrolling
//! that produces the same 80 rounds of arithmetic as the textbook
//! single-variable rotation used here. Verified byte-for-byte identical
//! against the real C via the differential harness in `port/test/sha512/`,
//! not asserted from reading the two side by side.
//!
//! # Two aliasing raw pointers, never a `&mut` over both
//!
//! `sha512_core_final()`'s `out` parameter and the HMAC final path's own
//! internal buffer alias on purpose -- the C writes the digest back into
//! `ctx->sha_ctx.buf`, the same memory `__sha512_final()` just finished
//! reading as compression input (`__hmac_sha512_final()` calls
//! `__sha512_final(&ctx->sha_ctx, ctx->sha_ctx.buf, digest_size)`). Every
//! function that can be called this way takes and dereferences raw pointers
//! only -- never a `&mut` reference over the context struct -- so nothing
//! here ever asserts exclusive access to memory a sibling pointer also
//! reaches while both are live. This is `logs/porting-hazards.md`'s open
//! item ("aliasing UB from `&mut` over pointers that alias") applied rather
//! than merely noted: the aliasing is real and intentional here, so the
//! discipline that avoids UB from it is load-bearing, not decorative.
//!
//! # `memzero_explicit()` -- volatile writes, matching `blake2s_rs.rs`
//!
//! Every place the C wipes a context after use, this does too, with the
//! same per-byte `write_volatile` loop `blake2s_final()` uses and for the
//! same reason: a plain zeroing of a struct about to die is a dead store the
//! compiler is free to remove, and what would be left behind is key and
//! chaining-value material.
//!
//! # Local contexts are zero-initialized, not left uninitialized
//!
//! `sha384()`/`sha512()`/`hmac_sha384()`/`hmac_sha512()`/the two
//! `_usingrawkey()` one-shots each declare a context on the C stack that
//! `_init()` only partly populates (`buf` is written lazily, by whichever
//! byte range `_update()`/`_final()` actually touch). C leaves that
//! initial content as whatever was already on the stack; the Rust local is
//! `core::mem::zeroed()` instead. Every field the algorithm actually reads
//! is always written before that read on every path -- checked against the
//! C's own control flow, not assumed -- so this changes no output; it only
//! removes a class of reads-of-stack-garbage that Rust's model dislikes and
//! this file's differential cannot distinguish from correct behaviour
//! anyway (garbage in, garbage overwritten, either language).

const SHA512_BLOCK_SIZE: usize = 128;
const SHA384_DIGEST_SIZE: usize = 48;
const SHA512_DIGEST_SIZE: usize = 64;
const HMAC_IPAD_VALUE: u8 = 0x36;
const HMAC_OPAD_VALUE: u8 = 0x5c;

const SHA384_IV: Sha512BlockState = Sha512BlockState {
    h: [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ],
};

const SHA512_IV: Sha512BlockState = Sha512BlockState {
    h: [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ],
};

/// `sha512_K[80]`.
#[rustfmt::skip]
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Mirrors `struct sha512_block_state` (`include/crypto/sha2.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha512BlockState {
    /// The eight 64-bit chaining values.
    pub h: [u64; 8],
}

/// Mirrors `struct __sha512_ctx` (`include/crypto/sha2.h`), the context
/// shared by SHA-384 and SHA-512.
#[repr(C)]
pub struct Sha512CoreCtx {
    /// The running compression state.
    pub state: Sha512BlockState,
    /// Total bytes absorbed so far, low word.
    pub bytecount_lo: u64,
    /// Total bytes absorbed so far, high word (the carry out of `bytecount_lo`).
    pub bytecount_hi: u64,
    /// The partial block not yet compressed.
    pub buf: [u8; SHA512_BLOCK_SIZE],
}

/// Mirrors `struct sha384_ctx`.
#[repr(C)]
pub struct Sha384Ctx {
    /// Private.
    pub ctx: Sha512CoreCtx,
}

/// Mirrors `struct sha512_ctx`.
#[repr(C)]
pub struct Sha512Ctx {
    /// Private.
    pub ctx: Sha512CoreCtx,
}

/// Mirrors `struct __hmac_sha512_key`, shared by HMAC-SHA384 and HMAC-SHA512.
#[repr(C)]
pub struct Sha512HmacKeyCore {
    /// The inner-hash initial state, derived from the key.
    pub istate: Sha512BlockState,
    /// The outer-hash initial state, derived from the key.
    pub ostate: Sha512BlockState,
}

/// Mirrors `struct __hmac_sha512_ctx`, shared by HMAC-SHA384 and HMAC-SHA512.
#[repr(C)]
pub struct Sha512HmacCtxCore {
    /// The inner hash's running context.
    pub sha_ctx: Sha512CoreCtx,
    /// The outer-hash initial state, carried until `_final()`.
    pub ostate: Sha512BlockState,
}

/// Mirrors `struct hmac_sha384_key`.
#[repr(C)]
pub struct HmacSha384Key {
    /// Private.
    pub key: Sha512HmacKeyCore,
}

/// Mirrors `struct hmac_sha512_key`.
#[repr(C)]
pub struct HmacSha512Key {
    /// Private.
    pub key: Sha512HmacKeyCore,
}

/// Mirrors `struct hmac_sha384_ctx`.
#[repr(C)]
pub struct HmacSha384Ctx {
    /// Private.
    pub ctx: Sha512HmacCtxCore,
}

/// Mirrors `struct hmac_sha512_ctx`.
#[repr(C)]
pub struct HmacSha512Ctx {
    /// Private.
    pub ctx: Sha512HmacCtxCore,
}

unsafe extern "C" {
    /// `lib/crypto/sha512.c`. The architecture dispatcher, which is `static`
    /// there and needs a symbol; see the module documentation.
    fn sha512_blocks_dispatch(state: *mut Sha512BlockState, data: *const u8, nblocks: usize);
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    z ^ (x & (y ^ z))
}
#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) | (z & (x | y))
}
#[inline(always)]
fn big_e0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
#[inline(always)]
fn big_e1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
#[inline(always)]
fn small_s0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
#[inline(always)]
fn small_s1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// `sha512_block_generic()`: compress one 128-byte block.
fn sha512_block_generic(state: &mut Sha512BlockState, data: &[u8; SHA512_BLOCK_SIZE]) {
    let mut w = [0u64; 80];
    for (i, chunk) in data.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = small_s1(w[i.wrapping_sub(2)])
            .wrapping_add(w[i.wrapping_sub(7)])
            .wrapping_add(small_s0(w[i.wrapping_sub(15)]))
            .wrapping_add(w[i.wrapping_sub(16)]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state.h;

    for i in 0..80 {
        let t1 = h
            .wrapping_add(big_e1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let t2 = big_e0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state.h[0] = state.h[0].wrapping_add(a);
    state.h[1] = state.h[1].wrapping_add(b);
    state.h[2] = state.h[2].wrapping_add(c);
    state.h[3] = state.h[3].wrapping_add(d);
    state.h[4] = state.h[4].wrapping_add(e);
    state.h[5] = state.h[5].wrapping_add(f);
    state.h[6] = state.h[6].wrapping_add(g);
    state.h[7] = state.h[7].wrapping_add(h);
}

/// `sha512_blocks_generic()`, exported to the retained C under a
/// `rust_`-prefixed name because the C keeps the unprefixed one as its
/// fall-back symbol -- see `blake2s_rs.rs`'s
/// `rust_blake2s_compress_generic()` for the same shape.
///
/// The C is a `do`/`while` that runs at least once and relies on every
/// caller passing `nblocks >= 1`; this is a `while`, which additionally
/// tolerates `nblocks == 0` as a no-op rather than wrapping `nblocks - 1`
/// to `usize::MAX`. No caller in this file ever passes 0, so this changes
/// no observable behaviour -- it just stops being an invariant the callee
/// has to trust blindly.
///
/// # Safety
/// `state` must be a valid `Sha512BlockState` and `data` readable for
/// `nblocks * 128` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sha512_blocks_generic(
    state: *mut Sha512BlockState,
    data: *const u8,
    nblocks: usize,
) {
    // SAFETY: the caller guarantees a valid state.
    let state = unsafe { &mut *state };
    let mut data = data;
    let mut nblocks = nblocks;
    while nblocks > 0 {
        // SAFETY: `nblocks > 0`, so 128 bytes are readable from `data`.
        let block: &[u8; SHA512_BLOCK_SIZE] = unsafe { &*data.cast() };
        sha512_block_generic(state, block);
        // SAFETY: one block consumed; `nblocks` still bounds what is left.
        data = unsafe { data.add(SHA512_BLOCK_SIZE) };
        nblocks = nblocks.wrapping_sub(1);
    }
}

fn sha512_core_init(ctx: &mut Sha512CoreCtx, iv: &Sha512BlockState, initial_bytecount: u64) {
    ctx.state = *iv;
    ctx.bytecount_lo = initial_bytecount;
    ctx.bytecount_hi = 0;
}

kernel::kabi_export! {
    sha384_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha384_ctx } ctx ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn sha384_init(ctx: *mut Sha384Ctx) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    sha512_core_init(&mut ctx.ctx, &SHA384_IV, 0);
}

kernel::kabi_export! {
    sha512_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha512_ctx } ctx ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn sha512_init(ctx: *mut Sha512Ctx) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    sha512_core_init(&mut ctx.ctx, &SHA512_IV, 0);
}

kernel::kabi_export! {
    __sha512_update,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__sha512_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn __sha512_update(ctx: *mut Sha512CoreCtx, data: *const u8, len: usize) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    let mut data = data;
    let mut len = len;
    let mut partial = (ctx.bytecount_lo % SHA512_BLOCK_SIZE as u64) as usize;

    let (new_lo, overflowed) = ctx.bytecount_lo.overflowing_add(len as u64);
    ctx.bytecount_lo = new_lo;
    if overflowed {
        ctx.bytecount_hi = ctx.bytecount_hi.wrapping_add(1);
    }

    if partial.wrapping_add(len) >= SHA512_BLOCK_SIZE {
        if partial != 0 {
            let l = SHA512_BLOCK_SIZE.wrapping_sub(partial);
            // SAFETY: `partial < 128` so this fits in `buf`; the caller
            // guarantees `data` readable for `len >= l` bytes here.
            unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), l) };
            // SAFETY: `l` bytes consumed above.
            data = unsafe { data.add(l) };
            len = len.wrapping_sub(l);
            // SAFETY: `ctx.buf` holds one full, valid block.
            unsafe { sha512_blocks_dispatch(&mut ctx.state, ctx.buf.as_ptr(), 1) };
        }

        let nblocks = len / SHA512_BLOCK_SIZE;
        len %= SHA512_BLOCK_SIZE;
        if nblocks != 0 {
            // SAFETY: the caller guarantees `data` readable for
            // `nblocks * 128` bytes here.
            unsafe { sha512_blocks_dispatch(&mut ctx.state, data, nblocks) };
            // SAFETY: `nblocks * 128` bytes consumed above.
            data = unsafe { data.add(nblocks * SHA512_BLOCK_SIZE) };
        }
        partial = 0;
    }
    if len != 0 {
        // SAFETY: `partial + len <= 128` here, so this fits in `buf`; the
        // caller guarantees `data` readable for the remaining `len` bytes.
        unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), len) };
    }
}

/// `__sha512_final()`. `out` MAY alias `(*ctx).buf` -- the HMAC final path
/// relies on exactly that, see the module doc comment -- so this takes and
/// dereferences only raw pointers, never a `&mut` reference over `*ctx`.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `digest_size` bytes,
/// which must be at most `SHA512_DIGEST_SIZE`.
unsafe fn sha512_core_final(ctx: *mut Sha512CoreCtx, out: *mut u8, digest_size: usize) {
    unsafe {
        let bytecount_lo = (*ctx).bytecount_lo;
        let bytecount_hi = (*ctx).bytecount_hi;
        let bitcount_hi = (bytecount_hi << 3) | (bytecount_lo >> 61);
        let bitcount_lo = bytecount_lo << 3;
        let mut partial = (bytecount_lo % SHA512_BLOCK_SIZE as u64) as usize;

        // `(*ctx).buf[range].fill(...)`/`.copy_from_slice(...)` would need an
        // implicit `&mut` autoref through the raw-pointer deref -- exactly
        // the shape this function's doc comment says to avoid, and rustc's
        // `dangerous_implicit_autorefs` lint refuses to compile it. Every
        // access below goes through this one explicit `*mut u8` instead.
        let buf: *mut u8 = (&raw mut (*ctx).buf).cast();

        *buf.add(partial) = 0x80;
        partial = partial.wrapping_add(1);
        if partial > SHA512_BLOCK_SIZE - 16 {
            core::ptr::write_bytes(buf.add(partial), 0, SHA512_BLOCK_SIZE.wrapping_sub(partial));
            sha512_blocks_dispatch(&raw mut (*ctx).state, buf, 1);
            partial = 0;
        }
        core::ptr::write_bytes(buf.add(partial), 0, (SHA512_BLOCK_SIZE - 16).wrapping_sub(partial));
        core::ptr::copy_nonoverlapping(
            bitcount_hi.to_be_bytes().as_ptr(),
            buf.add(SHA512_BLOCK_SIZE - 16),
            8,
        );
        core::ptr::copy_nonoverlapping(
            bitcount_lo.to_be_bytes().as_ptr(),
            buf.add(SHA512_BLOCK_SIZE - 8),
            8,
        );
        sha512_blocks_dispatch(&raw mut (*ctx).state, buf, 1);

        let mut i = 0;
        while i < digest_size {
            let bytes = (*ctx).state.h[i / 8].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 8);
            i = i.wrapping_add(8);
        }
    }
}

kernel::kabi_export! {
    sha384_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha384_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA384_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha384_final(ctx: *mut Sha384Ctx, out: *mut u8) {
    unsafe {
        sha512_core_final(&raw mut (*ctx).ctx, out, SHA384_DIGEST_SIZE);
        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha384Ctx>());
    }
}

kernel::kabi_export! {
    sha512_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha512_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA512_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha512_final(ctx: *mut Sha512Ctx, out: *mut u8) {
    unsafe {
        sha512_core_final(&raw mut (*ctx).ctx, out, SHA512_DIGEST_SIZE);
        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha512Ctx>());
    }
}

kernel::kabi_export! {
    sha384,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `data` readable for `len` bytes; `out` writable for `SHA384_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha384(data: *const u8, len: usize, out: *mut u8) {
    // A fresh local context. See the module doc comment: zeroed rather than
    // left uninitialized, and every byte `_update()`/`_final()` read is
    // always written first on every path either way.
    let mut ctx: Sha384Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        sha384_init(&mut ctx);
        __sha512_update(&mut ctx.ctx, data, len);
        sha384_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    sha512,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `data` readable for `len` bytes; `out` writable for `SHA512_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha512(data: *const u8, len: usize, out: *mut u8) {
    let mut ctx: Sha512Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        sha512_init(&mut ctx);
        __sha512_update(&mut ctx.ctx, data, len);
        sha512_final(&mut ctx, out);
    }
}

/// `__hmac_sha512_preparekey()`. `use_sha384` replaces the C's
/// pointer-identity check (`iv == &sha384_iv`) on which one-shot hash to use
/// for an over-length key -- an explicit flag is the same decision made
/// without comparing addresses.
///
/// # Safety
/// `istate`/`ostate` must be valid and writable; `raw_key` readable for
/// `raw_key_len` bytes.
unsafe fn hmac_preparekey(
    istate: *mut Sha512BlockState,
    ostate: *mut Sha512BlockState,
    raw_key: *const u8,
    raw_key_len: usize,
    iv: &Sha512BlockState,
    use_sha384: bool,
) {
    let mut derived_key = [0u8; SHA512_BLOCK_SIZE];
    unsafe {
        if raw_key_len > SHA512_BLOCK_SIZE {
            if use_sha384 {
                sha384(raw_key, raw_key_len, derived_key.as_mut_ptr());
            } else {
                sha512(raw_key, raw_key_len, derived_key.as_mut_ptr());
            }
        } else {
            core::ptr::copy_nonoverlapping(raw_key, derived_key.as_mut_ptr(), raw_key_len);
        }

        for b in derived_key.iter_mut() {
            *b ^= HMAC_IPAD_VALUE;
        }
        *istate = *iv;
        sha512_blocks_dispatch(istate, derived_key.as_ptr(), 1);

        for b in derived_key.iter_mut() {
            *b ^= HMAC_OPAD_VALUE ^ HMAC_IPAD_VALUE;
        }
        *ostate = *iv;
        sha512_blocks_dispatch(ostate, derived_key.as_ptr(), 1);
    }

    // SAFETY: `derived_key` is a valid, exclusively-owned local array.
    unsafe { memzero_explicit_bytes(derived_key.as_mut_ptr(), derived_key.len()) };
}

kernel::kabi_export! {
    hmac_sha384_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha384_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `key` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha384_preparekey(
    key: *mut HmacSha384Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*key).key.istate,
            &raw mut (*key).key.ostate,
            raw_key,
            raw_key_len,
            &SHA384_IV,
            true,
        );
    }
}

kernel::kabi_export! {
    hmac_sha512_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha512_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `key` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha512_preparekey(
    key: *mut HmacSha512Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*key).key.istate,
            &raw mut (*key).key.ostate,
            raw_key,
            raw_key_len,
            &SHA512_IV,
            false,
        );
    }
}

kernel::kabi_export! {
    __hmac_sha512_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__hmac_sha512_ctx } ctx , formal_parameter pointer_type { const_type { s#__hmac_sha512_key } } key ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `key` valid for reads.
#[no_mangle]
pub unsafe extern "C" fn __hmac_sha512_init(ctx: *mut Sha512HmacCtxCore, key: *const Sha512HmacKeyCore) {
    unsafe {
        sha512_core_init(&mut (*ctx).sha_ctx, &(*key).istate, SHA512_BLOCK_SIZE as u64);
        (*ctx).ostate = (*key).ostate;
    }
}

kernel::kabi_export! {
    hmac_sha384_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha384_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha384_init_usingrawkey(
    ctx: *mut HmacSha384Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*ctx).ctx.sha_ctx.state,
            &raw mut (*ctx).ctx.ostate,
            raw_key,
            raw_key_len,
            &SHA384_IV,
            true,
        );
        (*ctx).ctx.sha_ctx.bytecount_lo = SHA512_BLOCK_SIZE as u64;
        (*ctx).ctx.sha_ctx.bytecount_hi = 0;
    }
}

kernel::kabi_export! {
    hmac_sha512_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha512_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha512_init_usingrawkey(
    ctx: *mut HmacSha512Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*ctx).ctx.sha_ctx.state,
            &raw mut (*ctx).ctx.ostate,
            raw_key,
            raw_key_len,
            &SHA512_IV,
            false,
        );
        (*ctx).ctx.sha_ctx.bytecount_lo = SHA512_BLOCK_SIZE as u64;
        (*ctx).ctx.sha_ctx.bytecount_hi = 0;
    }
}

/// `__hmac_sha512_final()`. Zeroes `*ctx` itself before returning, matching
/// the C -- unlike the plain SHA path, where the exported wrapper does the
/// zeroing.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `digest_size` bytes.
unsafe fn hmac_core_final(ctx: *mut Sha512HmacCtxCore, out: *mut u8, digest_size: usize) {
    unsafe {
        let sha_ctx_ptr: *mut Sha512CoreCtx = &raw mut (*ctx).sha_ctx;
        // See sha512_core_final()'s comment: raw-pointer field access only,
        // since `buf` deliberately aliases with `sha_ctx_ptr` here.
        let buf: *mut u8 = (&raw mut (*ctx).sha_ctx.buf).cast();
        sha512_core_final(sha_ctx_ptr, buf, digest_size);

        core::ptr::write_bytes(buf.add(digest_size), 0, SHA512_BLOCK_SIZE.wrapping_sub(digest_size));
        *buf.add(digest_size) = 0x80;
        let bits: u32 = 8u32.wrapping_mul((SHA512_BLOCK_SIZE.wrapping_add(digest_size)) as u32);
        core::ptr::copy_nonoverlapping(bits.to_be_bytes().as_ptr(), buf.add(SHA512_BLOCK_SIZE - 4), 4);

        let ostate_ptr: *mut Sha512BlockState = &raw mut (*ctx).ostate;
        sha512_blocks_dispatch(ostate_ptr, buf, 1);
        let mut i = 0;
        while i < digest_size {
            let bytes = (*ctx).ostate.h[i / 8].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 8);
            i = i.wrapping_add(8);
        }

        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha512HmacCtxCore>());
    }
}

kernel::kabi_export! {
    hmac_sha384_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha384_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA384_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha384_final(ctx: *mut HmacSha384Ctx, out: *mut u8) {
    unsafe { hmac_core_final(&raw mut (*ctx).ctx, out, SHA384_DIGEST_SIZE) };
}

kernel::kabi_export! {
    hmac_sha512_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha512_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA512_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha512_final(ctx: *mut HmacSha512Ctx, out: *mut u8) {
    unsafe { hmac_core_final(&raw mut (*ctx).ctx, out, SHA512_DIGEST_SIZE) };
}

kernel::kabi_export! {
    hmac_sha384,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_sha384_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `key` valid for reads; `data` readable for `data_len` bytes; `out`
/// writable for `SHA384_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha384(
    key: *const HmacSha384Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha384Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        __hmac_sha512_init(&mut ctx.ctx, &(*key).key);
        __sha512_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha384_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha512,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_sha512_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `key` valid for reads; `data` readable for `data_len` bytes; `out`
/// writable for `SHA512_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha512(
    key: *const HmacSha512Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha512Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        __hmac_sha512_init(&mut ctx.ctx, &(*key).key);
        __sha512_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha512_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha384_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `raw_key` readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `SHA384_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha384_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha384Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha384_init_usingrawkey(&mut ctx, raw_key, raw_key_len);
        __sha512_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha384_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha512_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `raw_key` readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `SHA512_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha512_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha512Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha512_init_usingrawkey(&mut ctx, raw_key, raw_key_len);
        __sha512_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha512_final(&mut ctx, out);
    }
}

/// `memzero_explicit()`: a `memset` the compiler is forbidden to elide as a
/// dead store to a dying object. Matches `blake2s_rs.rs`'s own volatile-
/// write loop, for the same reason -- see this file's module doc comment.
///
/// # Safety
/// `ptr` must be valid and writable for `len` bytes.
unsafe fn memzero_explicit_bytes(ptr: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: caller guarantees `ptr` valid and writable for `len` bytes.
        unsafe { ptr.add(i).write_volatile(0) };
    }
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "s#__hmac_sha512_ctx",
    "structure_type __hmac_sha512_ctx { member s#__sha512_ctx sha_ctx data_member_location(0) , member s#sha512_block_state ostate data_member_location(208) } byte_size(272)");
kernel::kabi_rule!("type_string", "s#__hmac_sha512_key",
    "structure_type __hmac_sha512_key { member s#sha512_block_state istate data_member_location(0) , member s#sha512_block_state ostate data_member_location(64) } byte_size(128)");
kernel::kabi_rule!("type_string", "s#__sha512_ctx",
    "structure_type __sha512_ctx { member s#sha512_block_state state data_member_location(0) , member t#u64 bytecount_lo data_member_location(64) , member t#u64 bytecount_hi data_member_location(72) , member array_type[128] { t#u8 } buf data_member_location(80) } byte_size(208)");
kernel::kabi_rule!("type_string", "s#hmac_sha384_ctx",
    "structure_type hmac_sha384_ctx { member s#__hmac_sha512_ctx ctx data_member_location(0) } byte_size(272)");
kernel::kabi_rule!("type_string", "s#hmac_sha384_key",
    "structure_type hmac_sha384_key { member s#__hmac_sha512_key key data_member_location(0) } byte_size(128)");
kernel::kabi_rule!("type_string", "s#hmac_sha512_ctx",
    "structure_type hmac_sha512_ctx { member s#__hmac_sha512_ctx ctx data_member_location(0) } byte_size(272)");
kernel::kabi_rule!("type_string", "s#hmac_sha512_key",
    "structure_type hmac_sha512_key { member s#__hmac_sha512_key key data_member_location(0) } byte_size(128)");
kernel::kabi_rule!("type_string", "s#sha384_ctx",
    "structure_type sha384_ctx { member s#__sha512_ctx ctx data_member_location(0) } byte_size(208)");
kernel::kabi_rule!("type_string", "s#sha512_block_state",
    "structure_type sha512_block_state { member array_type[8] { t#u64 } h data_member_location(0) } byte_size(64)");
kernel::kabi_rule!("type_string", "s#sha512_ctx",
    "structure_type sha512_ctx { member s#__sha512_ctx ctx data_member_location(0) } byte_size(208)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
