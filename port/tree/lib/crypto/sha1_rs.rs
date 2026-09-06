// SPDX-License-Identifier: GPL-2.0

//! SHA-1 and HMAC-SHA1 -- the Rust behind `lib/crypto/sha1.c`.
//!
//! Ported from `lib/crypto/sha1.c` (6.18.49).
//!
//! Replaces: lib/crypto/sha1.c
//!
//! # Same split as `sha512_rs.rs`, same reasons
//!
//! `sha1.c` keeps the architecture dispatch (a `static_call` selecting the
//! SHA-NI/AVX2/AVX/SSSE3 core). See `sha512_rs.rs`'s module doc and
//! `logs/c-entry-rule.md`. `sha1_blocks_dispatch()` gives the C's `static`
//! `sha1_blocks()` a symbol for this file to call.
//!
//! # The round function is a plain loop over `W[0..80]`, not the C's rolling
//! # 16-word buffer with hand-unrolled register rotation
//!
//! The C's `SHA_MIX(t)` reads `array[(t+13)&15] ^ array[(t+8)&15] ^
//! array[(t+2)&15] ^ array[(t)&15]` against a mod-16 rolling buffer -- working
//! out the aliasing shows this is exactly the textbook message schedule
//! `W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)` for `t >= 16`, and
//! `SHA_ROUND`'s `B = ror32(B, 2)` before the parallel assignment is the
//! textbook `C' = B <<< 30` (`ROTR32(x, 2) == ROTL32(x, 30)`). Both forms
//! compute the same 80 rounds; this uses a full `[u32; 80]` schedule instead
//! of a rolling 16-word one, verified byte-for-byte against the real C via
//! the differential harness in `port/test/sha1/`.
//!
//! # `sha1_transform()`/`sha1_init_raw()` are the legacy, non-`_GPL` API
//!
//! Both operate on raw `u32` arrays, not `Sha1Ctx`, predate the context API,
//! and upstream's own doc comment says "Don't use this function." They are
//! plain `EXPORT_SYMBOL` (not `_GPL`), reproduced here unchanged rather than
//! dropped -- this port preserves the ABI, not upstream's opinion of it.
//!
//! # Two aliasing raw pointers, matching `sha512_rs.rs`
//!
//! `sha1_core_final()`'s `out` MAY alias the context's own buffer -- the HMAC
//! final path writes its digest back into `ctx->sha_ctx.buf`, the same
//! memory `sha1_core_final()` just read as compression input
//! (`hmac_sha1_final()` calls `__sha1_final(&ctx->sha_ctx, ctx->sha_ctx.buf)`
//! in the C). Every function reachable that way takes and dereferences raw
//! pointers only, never a `&mut` reference over the context struct -- see
//! `sha512_rs.rs`'s module doc for the full reasoning
//! (`logs/porting-hazards.md`'s open aliasing item).
//!
//! # `memzero_explicit()` -- volatile writes, matching every other port here
//!
//! Same per-byte `write_volatile` loop as `blake2s_rs.rs`/`sha512_rs.rs`, for
//! the same reason: a plain zeroing of a struct about to die is a dead store
//! the compiler may remove.

use core::ffi::c_char;

const SHA1_BLOCK_SIZE: usize = 64;
const SHA1_DIGEST_SIZE: usize = 20;
const HMAC_IPAD_VALUE: u8 = 0x36;
const HMAC_OPAD_VALUE: u8 = 0x5c;

const SHA1_IV: Sha1BlockState = Sha1BlockState {
    h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
};

/// Mirrors `struct sha1_block_state` (`include/crypto/sha1.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha1BlockState {
    /// The five 32-bit chaining values.
    pub h: [u32; 5],
}

/// Mirrors `struct sha1_ctx`.
#[repr(C)]
pub struct Sha1Ctx {
    /// The running compression state.
    pub state: Sha1BlockState,
    /// Total bytes absorbed so far.
    pub bytecount: u64,
    /// The partial block not yet compressed.
    pub buf: [u8; SHA1_BLOCK_SIZE],
}

/// Mirrors `struct hmac_sha1_key`.
#[repr(C)]
pub struct HmacSha1Key {
    /// The inner-hash initial state, derived from the key.
    pub istate: Sha1BlockState,
    /// The outer-hash initial state, derived from the key.
    pub ostate: Sha1BlockState,
}

/// Mirrors `struct hmac_sha1_ctx`.
#[repr(C)]
pub struct HmacSha1Ctx {
    /// The inner hash's running context.
    pub sha_ctx: Sha1Ctx,
    /// The outer-hash initial state, carried until `_final()`.
    pub ostate: Sha1BlockState,
}

unsafe extern "C" {
    /// `lib/crypto/sha1.c`. The architecture dispatcher, which is `static`
    /// there and needs a symbol; see the module documentation.
    fn sha1_blocks_dispatch(state: *mut Sha1BlockState, data: *const u8, nblocks: usize);
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}
#[inline(always)]
fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// `sha1_transform()`'s core round function, applied to one 64-byte block.
fn sha1_block_generic(state: &mut Sha1BlockState, data: &[u8; SHA1_BLOCK_SIZE]) {
    let mut w = [0u32; 80];
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = state.h;

    for (i, &wt) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => (ch(b, c, d), 0x5a827999u32),
            20..=39 => (parity(b, c, d), 0x6ed9eba1),
            40..=59 => (maj(b, c, d), 0x8f1bbcdc),
            _ => (parity(b, c, d), 0xca62c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state.h[0] = state.h[0].wrapping_add(a);
    state.h[1] = state.h[1].wrapping_add(b);
    state.h[2] = state.h[2].wrapping_add(c);
    state.h[3] = state.h[3].wrapping_add(d);
    state.h[4] = state.h[4].wrapping_add(e);
}

/// `sha1_blocks_generic()`, exported to the retained C under a
/// `rust_`-prefixed name -- see `sha512_rs.rs`'s
/// `rust_sha512_blocks_generic()` for the same shape and the same note
/// about `while` replacing the C's `do`/`while`.
///
/// # Safety
/// `state` must be a valid `Sha1BlockState` and `data` readable for
/// `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sha1_blocks_generic(
    state: *mut Sha1BlockState,
    data: *const u8,
    nblocks: usize,
) {
    // SAFETY: the caller guarantees a valid state.
    let state = unsafe { &mut *state };
    let mut data = data;
    let mut nblocks = nblocks;
    while nblocks > 0 {
        // SAFETY: `nblocks > 0`, so 64 bytes are readable from `data`.
        let block: &[u8; SHA1_BLOCK_SIZE] = unsafe { &*data.cast() };
        sha1_block_generic(state, block);
        // SAFETY: one block consumed; `nblocks` still bounds what is left.
        data = unsafe { data.add(SHA1_BLOCK_SIZE) };
        nblocks -= 1;
    }
}

kernel::kabi_export! {
    sha1_transform,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#__u32 } digest , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } data , formal_parameter pointer_type { t#__u32 } array ) -> base_type void",
}

/// `sha1_transform()` -- the legacy, deprecated single-block compression
/// primitive. See the module doc comment: reproduced for ABI compatibility,
/// not because it should be used.
///
/// # Safety
/// `digest` must be valid and writable for 5 `u32`s; `data` readable for 64
/// bytes; `array` valid and writable for 16 `u32`s (the workspace, per the
/// upstream doc comment left for the caller to clear if security-sensitive).
#[no_mangle]
pub unsafe extern "C" fn sha1_transform(digest: *mut u32, data: *const c_char, array: *mut u32) {
    // SAFETY: the caller guarantees `digest` valid for 5 `u32`s.
    let mut state = Sha1BlockState {
        h: unsafe { core::slice::from_raw_parts(digest, 5).try_into().unwrap() },
    };
    let mut w = [0u32; 80];
    // SAFETY: the caller guarantees `data` readable for 64 bytes.
    let data_bytes: &[u8; SHA1_BLOCK_SIZE] = unsafe { &*data.cast() };
    for (i, chunk) in data_bytes.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    // The legacy entry point also publishes each computed schedule word into
    // the caller's workspace, matching the C's `setW(t, TEMP)` -- observable
    // through the `array` pointer, so kept rather than treated as a private
    // scratch buffer.
    for i in 0..16 {
        // SAFETY: `array` is valid and writable for 16 `u32`s.
        unsafe { *array.add(i) = w[i] };
    }
    for i in 16..80 {
        // SAFETY: same as above; `i & 15` stays within the 16-word buffer.
        unsafe { *array.add(i & 15) = w[i] };
    }

    let [mut a, mut b, mut c, mut d, mut e] = state.h;
    for (i, &wt) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => (ch(b, c, d), 0x5a827999u32),
            20..=39 => (parity(b, c, d), 0x6ed9eba1),
            40..=59 => (maj(b, c, d), 0x8f1bbcdc),
            _ => (parity(b, c, d), 0xca62c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state.h = [
        state.h[0].wrapping_add(a),
        state.h[1].wrapping_add(b),
        state.h[2].wrapping_add(c),
        state.h[3].wrapping_add(d),
        state.h[4].wrapping_add(e),
    ];
    // SAFETY: the caller guarantees `digest` valid and writable for 5 `u32`s.
    unsafe { core::ptr::copy_nonoverlapping(state.h.as_ptr(), digest, 5) };
}

kernel::kabi_export! {
    sha1_init_raw,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#__u32 } buf ) -> base_type void",
}

/// # Safety
/// `buf` must be valid and writable for 5 `u32`s.
#[no_mangle]
pub unsafe extern "C" fn sha1_init_raw(buf: *mut u32) {
    // SAFETY: the caller guarantees `buf` valid and writable for 5 `u32`s.
    unsafe { core::ptr::copy_nonoverlapping(SHA1_IV.h.as_ptr(), buf, 5) };
}

kernel::kabi_export! {
    sha1_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha1_ctx } ctx ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn sha1_init(ctx: *mut Sha1Ctx) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    ctx.state = SHA1_IV;
    ctx.bytecount = 0;
}

kernel::kabi_export! {
    sha1_update,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha1_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sha1_update(ctx: *mut Sha1Ctx, data: *const u8, len: usize) {
    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    let mut data = data;
    let mut len = len;
    let mut partial = (ctx.bytecount % SHA1_BLOCK_SIZE as u64) as usize;

    ctx.bytecount = ctx.bytecount.wrapping_add(len as u64);

    if partial + len >= SHA1_BLOCK_SIZE {
        if partial != 0 {
            let l = SHA1_BLOCK_SIZE - partial;
            // SAFETY: `partial < 64` so this fits in `buf`; the caller
            // guarantees `data` readable for `len >= l` bytes here.
            unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), l) };
            // SAFETY: `l` bytes consumed above.
            data = unsafe { data.add(l) };
            len -= l;
            // SAFETY: `ctx.buf` holds one full, valid block.
            unsafe { sha1_blocks_dispatch(&mut ctx.state, ctx.buf.as_ptr(), 1) };
        }

        let nblocks = len / SHA1_BLOCK_SIZE;
        len %= SHA1_BLOCK_SIZE;
        if nblocks != 0 {
            // SAFETY: the caller guarantees `data` readable for
            // `nblocks * 64` bytes here.
            unsafe { sha1_blocks_dispatch(&mut ctx.state, data, nblocks) };
            // SAFETY: `nblocks * 64` bytes consumed above.
            data = unsafe { data.add(nblocks * SHA1_BLOCK_SIZE) };
        }
        partial = 0;
    }
    if len != 0 {
        // SAFETY: `partial + len <= 64` here, so this fits in `buf`; the
        // caller guarantees `data` readable for the remaining `len` bytes.
        unsafe { core::ptr::copy_nonoverlapping(data, ctx.buf.as_mut_ptr().add(partial), len) };
    }
}

/// `__sha1_final()`. `out` MAY alias `(*ctx).buf` -- the HMAC final path
/// relies on exactly that, see the module doc comment -- so this takes and
/// dereferences only raw pointers, never a `&mut` reference over `*ctx`.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA1_DIGEST_SIZE`
/// bytes.
unsafe fn sha1_core_final(ctx: *mut Sha1Ctx, out: *mut u8) {
    unsafe {
        let bytecount = (*ctx).bytecount;
        let bitcount = bytecount << 3;
        let mut partial = (bytecount % SHA1_BLOCK_SIZE as u64) as usize;

        // See sha512_rs.rs's sha512_core_final() for why this is one
        // explicit `*mut u8` and not `(*ctx).buf[range].fill/copy_from_slice`.
        let buf: *mut u8 = (&raw mut (*ctx).buf).cast();

        *buf.add(partial) = 0x80;
        partial += 1;
        if partial > SHA1_BLOCK_SIZE - 8 {
            core::ptr::write_bytes(buf.add(partial), 0, SHA1_BLOCK_SIZE - partial);
            sha1_blocks_dispatch(&raw mut (*ctx).state, buf, 1);
            partial = 0;
        }
        core::ptr::write_bytes(buf.add(partial), 0, SHA1_BLOCK_SIZE - 8 - partial);
        core::ptr::copy_nonoverlapping(bitcount.to_be_bytes().as_ptr(), buf.add(SHA1_BLOCK_SIZE - 8), 8);
        sha1_blocks_dispatch(&raw mut (*ctx).state, buf, 1);

        let mut i = 0;
        while i < SHA1_DIGEST_SIZE {
            let bytes = (*ctx).state.h[i / 4].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 4);
            i += 4;
        }
    }
}

kernel::kabi_export! {
    sha1_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#sha1_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA1_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha1_final(ctx: *mut Sha1Ctx, out: *mut u8) {
    unsafe {
        sha1_core_final(ctx, out);
        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<Sha1Ctx>());
    }
}

kernel::kabi_export! {
    sha1,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `data` readable for `len` bytes; `out` writable for `SHA1_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sha1(data: *const u8, len: usize, out: *mut u8) {
    // Zeroed rather than left uninitialized -- see sha512_rs.rs's module
    // doc comment; every byte read here is always written first.
    let mut ctx: Sha1Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        sha1_init(&mut ctx);
        sha1_update(&mut ctx, data, len);
        sha1_final(&mut ctx, out);
    }
}

/// `__hmac_sha1_preparekey()`.
///
/// # Safety
/// `istate`/`ostate` must be valid and writable; `raw_key` readable for
/// `raw_key_len` bytes.
unsafe fn hmac_preparekey(
    istate: *mut Sha1BlockState,
    ostate: *mut Sha1BlockState,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    let mut derived_key = [0u8; SHA1_BLOCK_SIZE];
    unsafe {
        if raw_key_len > SHA1_BLOCK_SIZE {
            sha1(raw_key, raw_key_len, derived_key.as_mut_ptr());
        } else {
            core::ptr::copy_nonoverlapping(raw_key, derived_key.as_mut_ptr(), raw_key_len);
        }

        for b in derived_key.iter_mut() {
            *b ^= HMAC_IPAD_VALUE;
        }
        *istate = SHA1_IV;
        sha1_blocks_dispatch(istate, derived_key.as_ptr(), 1);

        for b in derived_key.iter_mut() {
            *b ^= HMAC_OPAD_VALUE ^ HMAC_IPAD_VALUE;
        }
        *ostate = SHA1_IV;
        sha1_blocks_dispatch(ostate, derived_key.as_ptr(), 1);
    }

    // SAFETY: `derived_key` is a valid, exclusively-owned local array.
    unsafe { memzero_explicit_bytes(derived_key.as_mut_ptr(), derived_key.len()) };
}

kernel::kabi_export! {
    hmac_sha1_preparekey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha1_key } key , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `key` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1_preparekey(
    key: *mut HmacSha1Key,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(&raw mut (*key).istate, &raw mut (*key).ostate, raw_key, raw_key_len);
    }
}

kernel::kabi_export! {
    hmac_sha1_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha1_ctx } ctx , formal_parameter pointer_type { const_type { s#hmac_sha1_key } } key ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `key` valid for reads.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1_init(ctx: *mut HmacSha1Ctx, key: *const HmacSha1Key) {
    unsafe {
        (*ctx).sha_ctx.state = (*key).istate;
        (*ctx).sha_ctx.bytecount = SHA1_BLOCK_SIZE as u64;
        (*ctx).ostate = (*key).ostate;
    }
}

kernel::kabi_export! {
    hmac_sha1_init_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha1_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `raw_key` readable for `raw_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1_init_usingrawkey(
    ctx: *mut HmacSha1Ctx,
    raw_key: *const u8,
    raw_key_len: usize,
) {
    unsafe {
        hmac_preparekey(&raw mut (*ctx).sha_ctx.state, &raw mut (*ctx).ostate, raw_key, raw_key_len);
        (*ctx).sha_ctx.bytecount = SHA1_BLOCK_SIZE as u64;
    }
}

/// `__hmac_sha1_final()`. Zeroes `*ctx` itself before returning, matching
/// the C -- unlike the plain SHA path, where the exported wrapper does the
/// zeroing.
///
/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA1_DIGEST_SIZE`
/// bytes.
unsafe fn hmac_core_final(ctx: *mut HmacSha1Ctx, out: *mut u8) {
    unsafe {
        let sha_ctx_ptr: *mut Sha1Ctx = &raw mut (*ctx).sha_ctx;
        // See sha1_core_final()'s comment: raw-pointer field access only,
        // since `buf` deliberately aliases with `sha_ctx_ptr` here.
        let buf: *mut u8 = (&raw mut (*ctx).sha_ctx.buf).cast();
        sha1_core_final(sha_ctx_ptr, buf);

        core::ptr::write_bytes(buf.add(SHA1_DIGEST_SIZE), 0, SHA1_BLOCK_SIZE - SHA1_DIGEST_SIZE);
        *buf.add(SHA1_DIGEST_SIZE) = 0x80;
        let bits: u32 = 8u32.wrapping_mul((SHA1_BLOCK_SIZE + SHA1_DIGEST_SIZE) as u32);
        core::ptr::copy_nonoverlapping(bits.to_be_bytes().as_ptr(), buf.add(SHA1_BLOCK_SIZE - 4), 4);

        let ostate_ptr: *mut Sha1BlockState = &raw mut (*ctx).ostate;
        sha1_blocks_dispatch(ostate_ptr, buf, 1);
        let mut i = 0;
        while i < SHA1_DIGEST_SIZE {
            let bytes = (*ctx).ostate.h[i / 4].to_be_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i), 4);
            i += 4;
        }

        memzero_explicit_bytes(ctx.cast(), core::mem::size_of::<HmacSha1Ctx>());
    }
}

kernel::kabi_export! {
    hmac_sha1_final,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#hmac_sha1_ctx } ctx , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `ctx` must be valid and writable; `out` writable for `SHA1_DIGEST_SIZE`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1_final(ctx: *mut HmacSha1Ctx, out: *mut u8) {
    unsafe { hmac_core_final(ctx, out) };
}

kernel::kabi_export! {
    hmac_sha1,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#hmac_sha1_key } } key , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `key` valid for reads; `data` readable for `data_len` bytes; `out`
/// writable for `SHA1_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1(
    key: *const HmacSha1Key,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha1Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha1_init(&mut ctx, key);
        sha1_update(&mut ctx.sha_ctx, data, data_len);
        hmac_sha1_final(&mut ctx, out);
    }
}

kernel::kabi_export! {
    hmac_sha1_usingrawkey,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { t#u8 } } raw_key , formal_parameter t#size_t raw_key_len , formal_parameter pointer_type { const_type { t#u8 } } data , formal_parameter t#size_t data_len , formal_parameter pointer_type { t#u8 } out ) -> base_type void",
}

/// # Safety
/// `raw_key` readable for `raw_key_len` bytes; `data` readable for
/// `data_len` bytes; `out` writable for `SHA1_DIGEST_SIZE` bytes.
#[no_mangle]
pub unsafe extern "C" fn hmac_sha1_usingrawkey(
    raw_key: *const u8,
    raw_key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) {
    let mut ctx: HmacSha1Ctx = unsafe { core::mem::zeroed() };
    unsafe {
        hmac_sha1_init_usingrawkey(&mut ctx, raw_key, raw_key_len);
        sha1_update(&mut ctx.sha_ctx, data, data_len);
        hmac_sha1_final(&mut ctx, out);
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
kernel::kabi_rule!("type_string", "s#hmac_sha1_ctx",
    "structure_type hmac_sha1_ctx { member s#sha1_ctx sha_ctx data_member_location(0) , member s#sha1_block_state ostate data_member_location(96) } byte_size(120)");
kernel::kabi_rule!("type_string", "s#hmac_sha1_key",
    "structure_type hmac_sha1_key { member s#sha1_block_state istate data_member_location(0) , member s#sha1_block_state ostate data_member_location(20) } byte_size(40)");
kernel::kabi_rule!("type_string", "s#sha1_block_state",
    "structure_type sha1_block_state { member array_type[5] { t#u32 } h data_member_location(0) } byte_size(20)");
kernel::kabi_rule!("type_string", "s#sha1_ctx",
    "structure_type sha1_ctx { member s#sha1_block_state state data_member_location(0) , member t#u64 bytecount data_member_location(24) , member array_type[64] { t#u8 } buf data_member_location(32) } byte_size(96)");
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
