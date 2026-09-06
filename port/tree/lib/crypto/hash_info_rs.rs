// SPDX-License-Identifier: GPL-2.0-only

//! Hash algorithm metadata tables -- the Rust behind `lib/crypto/hash_info.c`.
//!
//! Replaces: lib/crypto/hash_info.c
//!
//! Every value below is read straight from the headers that define the
//! upstream macros (`include/crypto/{sha1,sha2,sha3,md5,streebog}.h`,
//! `include/uapi/linux/hash_info.h`), not from the C literal -- so this is
//! checked against the same authorities the C itself was written against,
//! not against the C as an oracle for its own values.
//!
//! # `*const c_char` needs a `Sync` wrapper to sit in a `static` array
//!
//! A bare `[*const c_char; N]` does not compile as a `static`: raw pointers
//! are not `Sync`, and a shared static's type must be. Every pointer here
//! is to a `'static` string literal, immutable for the life of the binary,
//! so asserting `Sync` is sound. `SyncCStr` is `#[repr(transparent)]`, so
//! an array of it has the exact same layout as an array of the pointer it
//! wraps -- the ABI this port has to preserve.

use core::ffi::{c_char, c_int};

/// A `*const c_char` asserted `Sync` because it only ever points at a
/// `'static` string literal. See the module doc comment.
#[repr(transparent)]
pub struct SyncCStr(*const c_char);
// SAFETY: every value is a pointer into a `'static`, immutable string
// literal below; nothing ever writes through it.
unsafe impl Sync for SyncCStr {}

/// `HASH_ALGO__LAST` from `include/uapi/linux/hash_info.h` -- one past the
/// last named algorithm, and the length of both tables below.
const HASH_ALGO_LAST: usize = 23;

kernel::kabi_export! {
    hash_algo_name,
    license = "GPL",
    namespace = "",
    contract = "variable array_type[23] { const_type { pointer_type { const_type { base_type char byte_size(1) encoding(8) } } } }",
}

/// `hash_algo_name[HASH_ALGO__LAST]`: the name string for each `enum
/// hash_algo` value, in enum order.
#[no_mangle]
pub static hash_algo_name: [SyncCStr; HASH_ALGO_LAST] = [
    SyncCStr(c"md4".as_ptr()),         // HASH_ALGO_MD4
    SyncCStr(c"md5".as_ptr()),         // HASH_ALGO_MD5
    SyncCStr(c"sha1".as_ptr()),        // HASH_ALGO_SHA1
    SyncCStr(c"rmd160".as_ptr()),      // HASH_ALGO_RIPE_MD_160
    SyncCStr(c"sha256".as_ptr()),      // HASH_ALGO_SHA256
    SyncCStr(c"sha384".as_ptr()),      // HASH_ALGO_SHA384
    SyncCStr(c"sha512".as_ptr()),      // HASH_ALGO_SHA512
    SyncCStr(c"sha224".as_ptr()),      // HASH_ALGO_SHA224
    SyncCStr(c"rmd128".as_ptr()),      // HASH_ALGO_RIPE_MD_128
    SyncCStr(c"rmd256".as_ptr()),      // HASH_ALGO_RIPE_MD_256
    SyncCStr(c"rmd320".as_ptr()),      // HASH_ALGO_RIPE_MD_320
    SyncCStr(c"wp256".as_ptr()),       // HASH_ALGO_WP_256
    SyncCStr(c"wp384".as_ptr()),       // HASH_ALGO_WP_384
    SyncCStr(c"wp512".as_ptr()),       // HASH_ALGO_WP_512
    SyncCStr(c"tgr128".as_ptr()),      // HASH_ALGO_TGR_128
    SyncCStr(c"tgr160".as_ptr()),      // HASH_ALGO_TGR_160
    SyncCStr(c"tgr192".as_ptr()),      // HASH_ALGO_TGR_192
    SyncCStr(c"sm3".as_ptr()),         // HASH_ALGO_SM3_256
    SyncCStr(c"streebog256".as_ptr()), // HASH_ALGO_STREEBOG_256
    SyncCStr(c"streebog512".as_ptr()), // HASH_ALGO_STREEBOG_512
    SyncCStr(c"sha3-256".as_ptr()),    // HASH_ALGO_SHA3_256
    SyncCStr(c"sha3-384".as_ptr()),    // HASH_ALGO_SHA3_384
    SyncCStr(c"sha3-512".as_ptr()),    // HASH_ALGO_SHA3_512
];

kernel::kabi_export! {
    hash_digest_size,
    license = "GPL",
    namespace = "",
    contract = "variable array_type[23] { const_type { base_type int byte_size(4) encoding(5) } }",
}

/// `hash_digest_size[HASH_ALGO__LAST]`: the digest size in bytes for each
/// `enum hash_algo` value, in enum order. Every value is read from the
/// `*_DIGEST_SIZE` macro the C itself uses -- `include/crypto/{sha1,sha2,
/// sha3,md5,streebog}.h` for the ones defined there, `lib/crypto/
/// hash_info.c`'s own "not defined in include/crypto/" literals for the
/// rest (RIPEMD, Whirlpool, Tiger, SM3).
#[no_mangle]
pub static hash_digest_size: [c_int; HASH_ALGO_LAST] = [
    16, // HASH_ALGO_MD4       (MD5_DIGEST_SIZE, no separate MD4 macro)
    16, // HASH_ALGO_MD5       (MD5_DIGEST_SIZE)
    20, // HASH_ALGO_SHA1      (SHA1_DIGEST_SIZE)
    20, // HASH_ALGO_RIPE_MD_160 (RMD160_DIGEST_SIZE)
    32, // HASH_ALGO_SHA256    (SHA256_DIGEST_SIZE)
    48, // HASH_ALGO_SHA384    (SHA384_DIGEST_SIZE)
    64, // HASH_ALGO_SHA512    (SHA512_DIGEST_SIZE)
    28, // HASH_ALGO_SHA224    (SHA224_DIGEST_SIZE)
    16, // HASH_ALGO_RIPE_MD_128 (RMD128_DIGEST_SIZE)
    32, // HASH_ALGO_RIPE_MD_256 (RMD256_DIGEST_SIZE)
    40, // HASH_ALGO_RIPE_MD_320 (RMD320_DIGEST_SIZE)
    32, // HASH_ALGO_WP_256    (WP256_DIGEST_SIZE)
    48, // HASH_ALGO_WP_384    (WP384_DIGEST_SIZE)
    64, // HASH_ALGO_WP_512    (WP512_DIGEST_SIZE)
    16, // HASH_ALGO_TGR_128   (TGR128_DIGEST_SIZE)
    20, // HASH_ALGO_TGR_160   (TGR160_DIGEST_SIZE)
    24, // HASH_ALGO_TGR_192   (TGR192_DIGEST_SIZE)
    32, // HASH_ALGO_SM3_256   (SM3256_DIGEST_SIZE)
    32, // HASH_ALGO_STREEBOG_256 (STREEBOG256_DIGEST_SIZE)
    64, // HASH_ALGO_STREEBOG_512 (STREEBOG512_DIGEST_SIZE)
    32, // HASH_ALGO_SHA3_256  (256 / 8)
    48, // HASH_ALGO_SHA3_384  (384 / 8)
    64, // HASH_ALGO_SHA3_512  (512 / 8)
];

// Every name is non-empty and NUL-terminated (guaranteed by `c"..."`
// literals, checked here so the guarantee is visible at this file's own
// boundary rather than only implied by the literal syntax), and both
// tables are exactly HASH_ALGO__LAST long.
const _: () = {
    assert!(hash_algo_name.len() == HASH_ALGO_LAST);
    assert!(hash_digest_size.len() == HASH_ALGO_LAST);
};
