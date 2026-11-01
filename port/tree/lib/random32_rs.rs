// SPDX-License-Identifier: GPL-2.0

//! Pseudo-random number generator (Tausworthe 113) -- the Rust behind part of `lib/random32.c`.
//!
//! Ported from `lib/random32.c` (6.18.49): `prandom_u32_state()` (one step of the four-register
//! L'Ecuyer "Maximally Equidistributed Combined Tausworthe Generators" generator, Math. Comp. 65 (1996)) and
//! `prandom_bytes_state()` (fills a buffer from successive outputs, low byte first). In C (`random32_glue.c`):
//! `prandom_seed_full_state()` (per-CPU states, `get_random_bytes`) and the CONFIG_RANDOM32_SELFTEST code.
//!
//! The state is the caller's `struct rnd_state { u32 s1, s2, s3, s4 }`. Neither export has a guard, WARN or static
//! key, so no C entry stays: `kernel::kabi_export!` carries each export and its contract (C fingerprints taken from
//! the C object before it was removed, `rig/kabi-symtypes.sh`). In-kernel check: `lib/libtest.c` `test_prandom()`
//! (the four published seed -> value pairs of the C file's own selftest table).
//!
//! Replaces: lib/random32.c (the generator)

use core::ffi::c_void;

/// Mirrors `struct rnd_state` (`include/linux/prandom.h`).
#[repr(C)]
pub struct RndState {
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
}

/// `TAUSWORTHE(s, a, b, c, d)`.
#[inline(always)]
fn tausworthe(s: u32, a: u32, b: u32, c: u32, d: u32) -> u32 {
    ((s & c) << d) ^ (((s << a) ^ s) >> b)
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#rnd_state",
    "structure_type rnd_state { member t#__u32 s1 data_member_location(0) , member t#__u32 s2 data_member_location(4) , member t#__u32 s3 data_member_location(8) , member t#__u32 s4 data_member_location(12) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");

kernel::kabi_export! {
    prandom_u32_state,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rnd_state } state ) -> t#u32",
}
/// `prandom_u32_state()`: advance the generator, return 32 pseudo-random bits.
///
/// # Safety
/// `state` valid and writable.
#[no_mangle]
pub unsafe extern "C" fn prandom_u32_state(state: *mut RndState) -> u32 {
    let st = unsafe { &mut *state };
    st.s1 = tausworthe(st.s1, 6, 13, 4294967294, 18);
    st.s2 = tausworthe(st.s2, 2, 27, 4294967288, 2);
    st.s3 = tausworthe(st.s3, 13, 21, 4294967280, 7);
    st.s4 = tausworthe(st.s4, 3, 12, 4294967168, 13);

    st.s1 ^ st.s2 ^ st.s3 ^ st.s4
}

kernel::kabi_export! {
    prandom_bytes_state,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rnd_state } state , formal_parameter pointer_type { base_type void } buf , formal_parameter t#size_t bytes ) -> base_type void",
}
/// `prandom_bytes_state()`: fill `buf` with `bytes` pseudo-random bytes.
///
/// # Safety
/// `state` valid and writable; `buf` writable for `bytes` bytes.
#[no_mangle]
pub unsafe extern "C" fn prandom_bytes_state(state: *mut RndState, buf: *mut c_void, bytes: usize) {
    let mut ptr = buf as *mut u8;
    let mut bytes = bytes;

    while bytes >= 4 {
        let v = unsafe { prandom_u32_state(state) };
        /* put_unaligned() */
        unsafe { core::ptr::write_unaligned(ptr as *mut u32, v) };
        ptr = unsafe { ptr.add(4) };
        bytes -= 4;
    }

    if bytes > 0 {
        let mut rem = unsafe { prandom_u32_state(state) };
        loop {
            unsafe { *ptr = rem as u8 };
            ptr = unsafe { ptr.add(1) };
            bytes -= 1;
            rem >>= 8;
            if bytes == 0 {
                break;
            }
        }
    }
}
