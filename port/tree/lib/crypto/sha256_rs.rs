// SPDX-License-Identifier: GPL-2.0-or-later

//! SHA-224, SHA-256, HMAC-SHA224, and HMAC-SHA256 -- the Rust behind
//! `lib/crypto/sha256.c`.
//!
//! Ported from `lib/crypto/sha256.c` (6.18.49), Copyright 2025 Google LLC.
//!
//! Replaces: lib/crypto/sha256.c
//!
//! # Same split as `sha1_rs.rs`/`sha512_rs.rs`, but with a SECOND dispatcher
//!
//! `sha256_blocks()` is the same `static_call` shape as `sha1`/`sha512`. But
//! `sha256_finup_2x_arch()` is an unrelated second hook -- an interleaved
//! two-message compression routine gated by a `static_branch`, not part of
//! the block-compression `static_call` chain at all -- so it gets its own
//! dispatch symbol, `sha256_finup_2x_dispatch()`, in the retained C. See
//! `sha256.c`'s own header comment for the full shape.
//!
//! # `sha256_finup_2x()`'s generic fallback is real Rust logic, not a stub
//!
//! When `sha256_finup_2x_dispatch()` returns `false` (no SHA-NI, or `len`
//! outside the asm routine's accepted range), `sha256_finup_2x_sequential()`
//! below runs -- two ordinary hashes from a copied prefix context. This is
//! reachable on every machine without SHA-NI, not a theoretical fallback.
//!
//! # `INITIAL_SHA256_CTX` replaces a `NULL` default argument
//!
//! `sha256_finup_2x(NULL, ...)` in the C substitutes `&initial_sha256_ctx`,
//! a file-scope constant equal to a freshly-`sha256_init()`-ed context. This
//! is that same constant, reproduced directly from `SHA256_IV` rather than
//! computed at runtime, since it is never mutated.
//!
//! # The round function, the aliasing-safe `_core_final` helpers, and
//! # `memzero_explicit()` all follow `sha512_rs.rs`/`sha1_rs.rs` exactly
//!
//! Same textbook single-loop round function instead of the C's 8-at-a-time
//! unroll (verified via the differential, not asserted from reading), same
//! raw-pointer-only aliasing discipline in `sha256_core_final()`/
//! `hmac_core_final()` (`logs/porting-hazards.md`'s open aliasing item —
//! `hmac_sha256_final()`'s `out` aliases the context's own buffer), and the
//! same per-byte `write_volatile` zeroing. See either sibling file's module
//! doc comment for the full reasoning; not repeated here.

const SHA256_BLOCK_SIZE: usize = 64;
const SHA224_DIGEST_SIZE: usize = 28;
const SHA256_DIGEST_SIZE: usize = 32;
const HMAC_IPAD_VALUE: u8 = 0x36;
const HMAC_OPAD_VALUE: u8 = 0x5c;

const SHA224_IV: Sha256BlockState = Sha256BlockState {
    h: [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ],
};

const SHA256_IV: Sha256BlockState = Sha256BlockState {
    h: [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ],
};

/// `initial_sha256_ctx` -- the substitute for a `NULL` `ctx` argument to
/// `sha256_finup_2x()`. See the module doc comment.
const INITIAL_SHA256_CTX: Sha256Ctx = Sha256Ctx {
    ctx: Sha256CoreCtx {
        state: SHA256_IV,
        bytecount: 0,
        buf: [0u8; SHA256_BLOCK_SIZE],
    },
};

/// `sha256_K[64]`.
#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Mirrors `struct sha256_block_state` (`include/crypto/sha2.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha256BlockState {
    /// The eight 32-bit chaining values.
    pub h: [u32; 8],
}

/// Mirrors `struct __sha256_ctx`, the context shared by SHA-224 and SHA-256.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha256CoreCtx {
    /// The running compression state.
    pub state: Sha256BlockState,
    /// Total bytes absorbed so far.
    pub bytecount: u64,
    /// The partial block not yet compressed.
    pub buf: [u8; SHA256_BLOCK_SIZE],
}

/// Mirrors `struct sha224_ctx`.
#[repr(C)]
pub struct Sha224Ctx {
    /// Private.
    pub ctx: Sha256CoreCtx,
}

/// Mirrors `struct sha256_ctx`.
#[repr(C)]
pub struct Sha256Ctx {
    /// Private.
    pub ctx: Sha256CoreCtx,
}

/// Mirrors `struct __hmac_sha256_key`, shared by HMAC-SHA224 and HMAC-SHA256.
#[repr(C)]
pub struct Sha256HmacKeyCore {
    /// The inner-hash initial state, derived from the key.
    pub istate: Sha256BlockState,
    /// The outer-hash initial state, derived from the key.
    pub ostate: Sha256BlockState,
}

/// Mirrors `struct __hmac_sha256_ctx`, shared by HMAC-SHA224 and HMAC-SHA256.
#[repr(C)]
pub struct Sha256HmacCtxCore {
    /// The inner hash's running context.
    pub sha_ctx: Sha256CoreCtx,
    /// The outer-hash initial state, carried until `_final()`.
    pub ostate: Sha256BlockState,
}

/// Mirrors `struct hmac_sha224_key`.
#[repr(C)]
pub struct HmacSha224Key {
    /// Private.
    pub key: Sha256HmacKeyCore,
}

/// Mirrors `struct hmac_sha256_key`.
#[repr(C)]
pub struct HmacSha256Key {
    /// Private.
    pub key: Sha256HmacKeyCore,
}

/// Mirrors `struct hmac_sha224_ctx`.
#[repr(C)]
pub struct HmacSha224Ctx {
    /// Private.
    pub ctx: Sha256HmacCtxCore,
}

/// Mirrors `struct hmac_sha256_ctx`.
#[repr(C)]
pub struct HmacSha256Ctx {
    /// Private.
    pub ctx: Sha256HmacCtxCore,
}

unsafe extern "C" {
    /// `lib/crypto/sha256.c`. The architecture dispatcher, which is `static`
    /// there and needs a symbol; see the module documentation.
    fn sha256_blocks_dispatch(state: *mut Sha256BlockState, data: *const u8, nblocks: usize);
    /// `lib/crypto/sha256.c`. The SECOND, unrelated dispatcher; see the
    /// module documentation.
    fn sha256_finup_2x_dispatch(
        ctx: *const Sha256CoreCtx,
        data1: *const u8,
        data2: *const u8,
        len: usize,
        out1: *mut u8,
        out2: *mut u8,
    ) -> bool;
    fn sha256_finup_2x_is_optimized_dispatch() -> bool;
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x | y))
}
#[inline(always)]
fn big_e0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline(always)]
fn big_e1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[inline(always)]
fn small_s0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline(always)]
fn small_s1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// `sha256_block_generic()`: compress one 64-byte block.
fn sha256_block_generic(state: &mut Sha256BlockState, data: &[u8; SHA256_BLOCK_SIZE]) {
    let mut w = [0u32; 64];
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = small_s1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_s0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state.h;

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_e1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(SHA256_K[i])
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

/// `sha256_blocks_generic()`, exported to the retained C under a
/// `rust_`-prefixed name -- see `sha512_rs.rs`'s
/// `rust_sha512_blocks_generic()` for the same shape.
///
/// # Safety
/// `state` must be a valid `Sha256BlockState` and `data` readable for
/// `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sha256_blocks_generic(
    state: *mut Sha256BlockState,
    data: *const u8,
    nblocks: usize,
) {
    // SAFETY: the caller guarantees a valid state.
    let state = unsafe { &mut *state };
    let mut data = data;
    let mut nblocks = nblocks;
    while nblocks > 0 {
        // SAFETY: `nblocks > 0`, so 64 bytes are readable from `data`.
        let block: &[u8; SHA256_BLOCK_SIZE] = unsafe { &*data.cast() };
        sha256_block_generic(state, block);
        // SAFETY: one block consumed; `nblocks` still bounds what is left.
        data = unsafe { data.add(SHA256_BLOCK_SIZE) };
        nblocks -= 1;
    }
}

fn sha256_core_init(ctx: &mut Sha256CoreCtx, iv: &Sha256BlockState, initial_bytecount: u64) {
    ctx.state = *iv;
    ctx.bytecount = initial_bytecount;
}

kernel::kabi_export! {
    sha224_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha224_ctx } ctx ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn sha224_init(ctx: *mut Sha224Ctx) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    sha256_core_init(&mut ctx.ctx, &SHA224_IV, 0);
}

kernel::kabi_export! {
    sha256_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha256_ctx } ctx ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn sha256_init(ctx: *mut Sha256Ctx) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    sha256_core_init(&mut ctx.ctx, &SHA256_IV, 0);
}

kernel::kabi_export! {
    __sha256_update,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__sha256_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn __sha256_update(ctx: *mut Sha256CoreCtx, data: *const u8, len: usize) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    let mut data = data;
    let mut len = len;
    let mut partial = (ctx.bytecount % SHA256_BLOCK_SIZE as u64) as usize;

    ctx.bytecount = ctx.bytecount.wrapping_add(len as u64);

    if partial + len >= SHA256_BLOCK_SIZE {
        if partial != 0 {
            let l = SHA256_BLOCK_SIZE - partial;
            // SAFETY: `partial < 64` so this fits in `buf`; the caller
            // guarantees `data` readable for `len >= l` bytes here.
            unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), l) };
            // SAFETY: `l` bytes consumed above.
            data = unsafe { data.add(l) };
            len -= l;
            // SAFETY: `ctx.buf` holds one full, valid block.
            unsafe { sha256_blocks_dispatch(&mut ctx.state, ctx.buf.as_ptr(), 1) };
        }

        let nblocks = len / SHA256_BLOCK_SIZE;
        len %= SHA256_BLOCK_SIZE;
        if nblocks != 0 {
            // SAFETY: the caller guarantees `data` readable for
            // `nblocks * 64` bytes here.
            unsafe { sha256_blocks_dispatch(&mut ctx.state, data, nblocks) };
            // SAFETY: `nblocks * 64` bytes consumed above.
            data = unsafe { data.add(nblocks * SHA256_BLOCK_SIZE) };
        }
        partial = 0;
    }
    if len != 0 {
        // SAFETY: `partial + len <= 64` here, so this fits in `buf`; the
        // caller guarantees `data` readable for the remaining `len` bytes.
        unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), len) };
    }
}

/// `__sha256_final()`. `out` MAY alias `(*ctx).buf` -- see the module doc
/// comment -- so this takes and dereferences only raw pointers, never a
/// `&mut` reference over `*ctx`.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `digest_size` bytes,
/// which must be at most `SHA256_DIGEST_SIZE`.
unsafe fn sha256_core_final(ctx: *mut Sha256CoreCtx, out: *mut u8, digest_size: usize) {
    unsafe {
        let bytecount = (*ctx).bytecount;
        let bitcount = bytecount << 3;
        let mut partial = (bytecount % SHA256_BLOCK_SIZE as u64) as usize;

        let buf: *mut u8 = (&raw mut (*ctx).buf).cast();

        *buf.add(partial) = 0x80;
        partial += 1;
        if partial > SHA256_BLOCK_SIZE - 8 {
            core::ptr::write_bytes(buf.add(partial), 0, SHA256_BLOCK_SIZE - partial);
            sha256_blocks_dispatch(&raw mut (*ctx).state, buf, 1);
            partial = 0;
        }
        core::ptr::write_bytes(buf.add(partial), 0, SHA256_BLOCK_SIZE - 8 - partial);
        core::ptr::copy_nonoverlapping(bitcount.to_be_bytes().as_ptr(), buf.add(SHA256_BLOCK_SIZE - 8), 8);
        sha256_blocks_dispatch(&raw mut (*ctx).state, buf, 1);

        let mut i = 0;
        while i < digest_size {
            let bytes = (*ctx).state.h[i / 4].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 4);
            i += 4;
        }
    }
}

kernel::kabi_export! {
    sha224_final,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha224_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA224_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha224_final(ctx: *mut Sha224Ctx, out: *mut u8) {
    unsafe {
        sha256_core_final(&raw mut (*ctx).ctx, out, SHA224_DIGEST_SIZE);
        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha224Ctx>());
    }
}

kernel::kabi_export! {
    sha256_final,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha256_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA256_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha256_final(ctx: *mut Sha256Ctx, out: *mut u8) {
    unsafe {
        sha256_core_final(&raw mut (*ctx).ctx, out, SHA256_DIGEST_SIZE);
        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha256Ctx>());
    }
}

kernel::kabi_export! {
    sha224,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `data` readable for `len` bytes; `out` writable for `SHA224_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha224(data: *const u8, len: usize, out: *mut u8) {
    let mut ctx: Sha224Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        sha224_init(&mut ctx);
        __sha256_update(&mut ctx.ctx, data, len);
        sha224_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    sha256,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `data` readable for `len` bytes; `out` writable for `SHA256_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha256(data: *const u8, len: usize, out: *mut u8) {
    let mut ctx: Sha256Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        sha256_init(&mut ctx);
        __sha256_update(&mut ctx.ctx, data, len);
        sha256_final(&mut ctx, out);
    }
}

/// `sha256_finup_2x_sequential()`: the portable fallback when the arch
/// dispatch declines (`sha256_finup_2x_dispatch()` returns `false`).
///
/// # Safety
/// `ctx` valid for reads; `data1`/`data2` readable for `len` bytes each;
/// `out1`/`out2` writable for `SHA256_DIGEST_SIZE` bytes each.
unsafe fn sha256_finup_2x_sequential(
    ctx: *const Sha256CoreCtx,
    data1: *const u8,
    data2: *const u8,
    len: usize,
    out1: *mut u8,
    out2: *mut u8,
) {
    unsafe {
        let mut mut_ctx = *ctx;
        __sha256_update(&mut mut_ctx, data1, len);
        sha256_core_final(&mut mut_ctx, out1, SHA256_DIGEST_SIZE);

        let mut mut_ctx = *ctx;
        __sha256_update(&mut mut_ctx, data2, len);
        sha256_core_final(&mut mut_ctx, out2, SHA256_DIGEST_SIZE);
    }
}

kernel::kabi_export! {
    sha256_finup_2x,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#sha256_ctx } } ctx , formal_parameter pointer_type { const_type { t#u8 } } data1 , formal_parameter pointer_type { const_type { t#u8 } } data2 , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out1 , formal_parameter pointer_type { t#u8 } out2 ) -> base_type void",
}

/// `sha256_finup_2x()`: two independent digests of `data1`/`data2` (each
/// `len` bytes), continuing from the same prefix context `ctx` (or from a
/// freshly-initialized one if `ctx` is null -- see `INITIAL_SHA256_CTX`).
///
/// # Safety
/// `ctx` must be null or valid for reads; `data1`/`data2` readable for
/// `len` bytes each; `out1`/`out2` writable for `SHA256_DIGEST_SIZE` bytes
/// each.
#[no_mangle]
pub unsafe extern "C" fn sha256_finup_2x(
    ctx: *const Sha256Ctx,
    data1: *const u8,
    data2: *const u8,
    len: usize,
    out1: *mut u8,
    out2: *mut u8,
) {
    // SAFETY: `ctx` is either null (handled below) or caller-guaranteed
    // valid for reads.
    let ctx = if ctx.is_null() { &INITIAL_SHA256_CTX } else { unsafe { &*ctx } };
    let inner: *const Sha256CoreCtx = &ctx.ctx;
    unsafe {
        if sha256_finup_2x_dispatch(inner, data1, data2, len, out1, out2) {
            return;
        }
        sha256_finup_2x_sequential(inner, data1, data2, len, out1, out2);
    }
}

kernel::kabi_export! {
    sha256_finup_2x_is_optimized,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( ) -> t#bool",
}

/// # Safety
/// None -- takes no arguments.
#[no_mangle]
pub unsafe extern "C" fn sha256_finup_2x_is_optimized() -> bool {
    // SAFETY: no preconditions.
    unsafe { sha256_finup_2x_is_optimized_dispatch() }
}

/// `__hmac_sha256_preparekey()`. `use_sha224` replaces the C's
/// pointer-identity check (`iv == &sha224_iv`) -- see `sha512_rs.rs`'s
/// `hmac_preparekey()` for the same substitution.
///
/// # Safety
/// `istate`/`ostate` must be valid and writable; `raw_key` readable for
/// `raw_key_len` bytes.
unsafe fn hmac_preparekey(
    istate: *mut Sha256BlockState,
    ostate: *mut Sha256BlockState,
    raw_key: *const u8,
    raw_key_len: usize,
    iv: &Sha256BlockState,
    use_sha224: bool,
) {
    let mut derived_key = [0u8; SHA256_BLOCK_SIZE];
    unsafe {
        if raw_key_len > SHA256_BLOCK_SIZE {
            if use_sha224 {
                sha224(raw_key, raw_key_len, derived_key.as_mut_ptr());
            } else {
                sha256(raw_key, raw_key_len, derived_key.as_mut_ptr());
            }
        } else {
            core::ptr::copy_nonoverlapping(raw_key, derived_key.as_mut_ptr(), raw_key_len);
        }

        for b in derived_key.iter_mut() {
            *b ^= HMAC_IPAD_VALUE;
        }
        *istate = *iv;
        sha256_blocks_dispatch(istate, derived_key.as_ptr(), 1);

        for b in derived_key.iter_mut() {
            *b ^= HMAC_OPAD_VALUE ^ HMAC_IPAD_VALUE;
        }
        *ostate = *iv;
        sha256_blocks_dispatch(ostate, derived_key.as_ptr(), 1);
    }

    // SAFETY: `derived_key` is a valid, exclusively-owned local array.
    unsafe { memzero_explicit_bytes(derived_key.as_mut_ptr(), derived_key.len()) };
}

kernel::kabi_export! {
    hmac_sha224_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha224_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `key` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha224_preparekey(
    key: *mut HmacSha224Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*key).key.istate,
            &raw mut (*key).key.ostate,
            raw_key,
            raw_key_len,
            &SHA224_IV,
            true,
        );
    }
}

kernel::kabi_export! {
    hmac_sha256_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha256_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `key` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha256_preparekey(
    key: *mut HmacSha256Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*key).key.istate,
            &raw mut (*key).key.ostate,
            raw_key,
            raw_key_len,
            &SHA256_IV,
            false,
        );
    }
}

kernel::kabi_export! {
    __hmac_sha256_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__hmac_sha256_ctx } ctx , formal_parameter pointer_type { const_type { s#__hmac_sha256_key } } key ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `key` valid for reads.
#[no_mangle]
pub unsafe extern "C" fn __hmac_sha256_init(ctx: *mut Sha256HmacCtxCore, key: *const Sha256HmacKeyCore) {
    unsafe {
        sha256_core_init(&mut (*ctx).sha_ctx, &(*key).istate, SHA256_BLOCK_SIZE as u64);
        (*ctx).ostate = (*key).ostate;
    }
}

kernel::kabi_export! {
    hmac_sha224_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha224_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha224_init_usingrawkey(
    ctx: *mut HmacSha224Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*ctx).ctx.sha_ctx.state,
            &raw mut (*ctx).ctx.ostate,
            raw_key,
            raw_key_len,
            &SHA224_IV,
            true,
        );
        (*ctx).ctx.sha_ctx.bytecount = SHA256_BLOCK_SIZE as u64;
    }
}

kernel::kabi_export! {
    hmac_sha256_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha256_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha256_init_usingrawkey(
    ctx: *mut HmacSha256Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(
            &raw mut (*ctx).ctx.sha_ctx.state,
            &raw mut (*ctx).ctx.ostate,
            raw_key,
            raw_key_len,
            &SHA256_IV,
            false,
        );
        (*ctx).ctx.sha_ctx.bytecount = SHA256_BLOCK_SIZE as u64;
    }
}

/// `__hmac_sha256_final()`. Zeroes `*ctx` itself before returning, matching
/// the C -- see `sha512_rs.rs`'s `hmac_core_final()` for the same shape.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `digest_size` bytes.
unsafe fn hmac_core_final(ctx: *mut Sha256HmacCtxCore, out: *mut u8, digest_size: usize) {
    unsafe {
        let sha_ctx_ptr: *mut Sha256CoreCtx = &raw mut (*ctx).sha_ctx;
        let buf: *mut u8 = (&raw mut (*ctx).sha_ctx.buf).cast();
        sha256_core_final(sha_ctx_ptr, buf, digest_size);

        core::ptr::write_bytes(buf.add(digest_size), 0, SHA256_BLOCK_SIZE - digest_size);
        *buf.add(digest_size) = 0x80;
        let bits: u32 = 8u32.wrapping_mul((SHA256_BLOCK_SIZE + digest_size) as u32);
        core::ptr::copy_nonoverlapping(bits.to_be_bytes().as_ptr(), buf.add(SHA256_BLOCK_SIZE - 4), 4);

        let ostate_ptr: *mut Sha256BlockState = &raw mut (*ctx).ostate;
        sha256_blocks_dispatch(ostate_ptr, buf, 1);
        let mut i = 0;
        while i < digest_size {
            let bytes = (*ctx).ostate.h[i / 4].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 4);
            i += 4;
        }

        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha256HmacCtxCore>());
    }
}

kernel::kabi_export! {
    hmac_sha224_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha224_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA224_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha224_final(ctx: *mut HmacSha224Ctx, out: *mut u8) {
    unsafe { hmac_core_final(&raw mut (*ctx).ctx, out, SHA224_DIGEST_SIZE) };
}

kernel::kabi_export! {
    hmac_sha256_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha256_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA256_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha256_final(ctx: *mut HmacSha256Ctx, out: *mut u8) {
    unsafe { hmac_core_final(&raw mut (*ctx).ctx, out, SHA256_DIGEST_SIZE) };
}

kernel::kabi_export! {
    hmac_sha224,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_sha224_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `key` valid for reads; `data` readable for `data_len` bytes; `out`
/// writable for `SHA224_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha224(
    key: *const HmacSha224Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha224Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        __hmac_sha256_init(&mut ctx.ctx, &(*key).key);
        __sha256_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha224_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha256,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_sha256_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `key` valid for reads; `data` readable for `data_len` bytes; `out`
/// writable for `SHA256_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha256(
    key: *const HmacSha256Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha256Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        __hmac_sha256_init(&mut ctx.ctx, &(*key).key);
        __sha256_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha256_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha224_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `raw_key` readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `SHA224_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha224_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha224Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha224_init_usingrawkey(&mut ctx, raw_key, raw_key_len);
        __sha256_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha224_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha256_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `raw_key` readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `SHA256_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha256_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha256Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha256_init_usingrawkey(&mut ctx, raw_key, raw_key_len);
        __sha256_update(&mut ctx.ctx.sha_ctx, data, data_len);
        hmac_sha256_final(&mut ctx, out);
    }
}

/// `memzero_explicit()`: matches every other port here -- see
/// `sha512_rs.rs`'s own copy of this function for the reasoning.
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
kernel::kabi_rule!("type_string", "s#__hmac_sha256_ctx",
    "structure_type __hmac_sha256_ctx { member s#__sha256_ctx sha_ctx data_member_location(0) , member s#sha256_block_state ostate data_member_location(104) } byte_size(136)");
kernel::kabi_rule!("type_string", "s#__hmac_sha256_key",
    "structure_type __hmac_sha256_key { member s#sha256_block_state istate data_member_location(0) , member s#sha256_block_state ostate data_member_location(32) } byte_size(64)");
kernel::kabi_rule!("type_string", "s#__sha256_ctx",
    "structure_type __sha256_ctx { member s#sha256_block_state state data_member_location(0) , member t#u64 bytecount data_member_location(32) , member array_type[64] { t#u8 } buf data_member_location(40) } byte_size(104)");
kernel::kabi_rule!("type_string", "s#hmac_sha224_ctx",
    "structure_type hmac_sha224_ctx { member s#__hmac_sha256_ctx ctx data_member_location(0) } byte_size(136)");
kernel::kabi_rule!("type_string", "s#hmac_sha224_key",
    "structure_type hmac_sha224_key { member s#__hmac_sha256_key key data_member_location(0) } byte_size(64)");
kernel::kabi_rule!("type_string", "s#hmac_sha256_ctx",
    "structure_type hmac_sha256_ctx { member s#__hmac_sha256_ctx ctx data_member_location(0) } byte_size(136)");
kernel::kabi_rule!("type_string", "s#hmac_sha256_key",
    "structure_type hmac_sha256_key { member s#__hmac_sha256_key key data_member_location(0) } byte_size(64)");
kernel::kabi_rule!("type_string", "s#sha224_ctx",
    "structure_type sha224_ctx { member s#__sha256_ctx ctx data_member_location(0) } byte_size(104)");
kernel::kabi_rule!("type_string", "s#sha256_block_state",
    "structure_type sha256_block_state { member array_type[8] { t#u32 } h data_member_location(0) } byte_size(32)");
kernel::kabi_rule!("type_string", "s#sha256_ctx",
    "structure_type sha256_ctx { member s#__sha256_ctx ctx data_member_location(0) } byte_size(104)");
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
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
