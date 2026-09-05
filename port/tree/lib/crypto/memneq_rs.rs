// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

//! Constant-time equality testing of memory regions -- the Rust body behind
//! `lib/crypto/memneq.c`.
//!
//! Ported from `lib/crypto/memneq.c` (6.18.49), by James Yonan
//! <james@openvpn.net> and Daniel Borkmann <dborkman@redhat.com>,
//! Copyright (c) 2013 OpenVPN Technologies, Inc. Dual BSD/GPLv2, as the C is.
//!
//! # THE WHOLE POINT OF THIS FUNCTION IS A THING NO TEST CAN SEE
//!
//! `__crypto_memneq` exists because `memcmp()` returns early on the first
//! differing byte, and an attacker who can time it learns *how many leading
//! bytes of an authentication tag they guessed right*. That turns forging a
//! 16-byte MAC from 2^128 work into 16 x 256. So this compares every byte
//! whatever happens, and ORs the differences together.
//!
//! **A correct-looking port of this file can destroy that property while
//! passing every differential test ever written against it**, because the
//! property is about the SHAPE OF THE EMITTED CODE, not about the answer. Two
//! ways it goes wrong, and both are the compiler being helpful:
//!
//! 1. The optimiser proves `neq` is only ever tested against zero, and turns
//!    the accumulate-everything loop back into an early-exit compare.
//! 2. It vectorises or unrolls in a way that branches on partial results.
//!
//! The C's defence is `OPTIMIZER_HIDE_VAR(neq)` after every accumulation --
//! `__asm__ ("" : "=r" (var) : "0" (var))`, an empty instruction sequence that
//! the compiler must nonetheless believe can put anything at all in `neq`.
//! [`hide`] below is that construct, spelled in Rust. **It is not decoration
//! and it is not a performance hint. Delete it and the port is a security
//! regression that every check in this project reports as green.**
//!
//! `core::hint::black_box` is deliberately NOT used: its documentation says
//! it is a best-effort hint with no guarantee, which is the opposite of what
//! is wanted here. `asm!` is a guarantee.
//!
//! # `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS`
//!
//! The C has two spellings of each loop -- word-at-a-time behind that symbol,
//! byte-at-a-time without it -- and both are carried here, because RAISE 1
//! (`logs/floor.md`) makes the config space part of "it builds".
//!
//! **The `not()` arm is compiled by neither of our configurations and is
//! covered by no test.** x86-64 always sets the symbol; no Kconfig choice
//! turns it off. It is checked by a standalone `rustc --cfg` compile and
//! nothing more, and that limit is recorded in `logs/build-limits.md` rather
//! than left for a reader to discover.
//!
//! The C's third fork -- `sizeof(unsigned int) == 4` inside the 16-byte path
//! -- is 32-bit only, and `kernel::kabi_export!` already refuses to build on
//! a 32-bit target. It is not reproduced.
//!
//! Replaces: lib/crypto/memneq.c

use core::ffi::{c_ulong, c_void};

/// `OPTIMIZER_HIDE_VAR()` from `include/linux/compiler.h`.
///
/// The C is `__asm__ ("" : "=r" (var) : "0" (var))` -- no instructions, one
/// register in, the same register out.
///
/// # The options are DELIBERATELY STRONGER than the C's, not equal to them
///
/// This was written as `options(pure, nomem, nostack, preserves_flags)` on
/// the theory that it was the same statement. **It was not, and an
/// adversarial review found it by reading the two LLVM IRs side by side:**
///
/// | | constraint string | call attributes |
/// |---|---|---|
/// | C, clang, kernel flags | `"=r,0,~{dirflag},~{fpsr},~{flags}"` | `nounwind memory(none)` |
/// | Rust, with `pure` | `"=&r,0"` | `nounwind willreturn memory(none)` |
///
/// Two divergences, both LOOSENING the barrier: `pure` adds `willreturn`,
/// which with `memory(none) nounwind` makes the block fully speculatable --
/// and the Rust Reference says of `pure` in as many words that it "allows the
/// compiler to execute the asm block fewer times than specified in the
/// program (e.g. by hoisting it out of a loop or eliminating it entirely if
/// the outputs are not used)". `preserves_flags` drops the `~{flags}` clobber
/// that GCC and clang attach to every extended asm.
///
/// Neither was being exercised -- the emitted code was identical either way
/// on rustc 1.98.0 at `-Copt-level=2` -- so this is a licence granted rather
/// than a licence taken. **A barrier that relies on the optimiser not having
/// noticed is not a barrier.** So `pure` and `preserves_flags` are gone: the
/// block is now side-effecting, which cannot be hoisted or elided at all, and
/// clobbers flags, which the C does too. That is stricter than the C on both
/// axes, and stricter is the safe direction for this one function.
#[inline(always)]
fn hide(v: c_ulong) -> c_ulong {
    let mut v = v;
    // SAFETY: an empty assembly template executes no instructions. It reads
    // and writes one general register, touches no memory (`nomem`) and does
    // not use the stack (`nostack`).
    unsafe {
        core::arch::asm!(
            // An assembler comment, not an instruction. rustc rejects a
            // template that never names its operand ("argument never used"),
            // and this is the spelling its own diagnostic suggests. rustc
            // emits Intel dialect, so what reaches the assembler is `# rcx`
            // or similar -- not the AT&T `/* %rax */` this comment claimed
            // until the same review checked. It assembles to nothing either
            // way; the wrong detail was in the description, not the code.
            "/* {v} */",
            v = inout(reg) v,
            options(nomem, nostack),
        );
    }
    v
}

/// `__crypto_memneq_generic()`: arbitrary size, a word at a time then the
/// tail a byte at a time.
///
/// # Safety
/// `a` and `b` must each be readable for `size` bytes.
#[cfg(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)]
#[inline(always)]
unsafe fn memneq_generic(a: *const u8, b: *const u8, size: usize) -> c_ulong {
    const W: usize = core::mem::size_of::<c_ulong>();

    let mut neq: c_ulong = 0;
    let mut a = a;
    let mut b = b;
    let mut size = size;

    while size >= W {
        // SAFETY: `size >= W` limbs remain readable on both sides, and
        // `read_unaligned` imposes no alignment requirement -- which is the
        // whole reason the C uses `get_unaligned()` here.
        neq |= unsafe { (a as *const c_ulong).read_unaligned() ^ (b as *const c_ulong).read_unaligned() };
        neq = hide(neq);
        // SAFETY: still within the `size` bytes the caller guaranteed.
        a = unsafe { a.add(W) };
        b = unsafe { b.add(W) };
        size -= W;
    }
    while size > 0 {
        // SAFETY: `size` bytes remain readable on both sides.
        neq |= unsafe { c_ulong::from(*a) ^ c_ulong::from(*b) };
        neq = hide(neq);
        // SAFETY: as above.
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
        size -= 1;
    }
    neq
}

/// `__crypto_memneq_generic()` where an unaligned word load is not cheap:
/// a byte at a time, all the way.
///
/// NOT COMPILED BY EITHER CONFIGURATION AND COVERED BY NO TEST. See the
/// module documentation and `logs/build-limits.md`.
///
/// # Safety
/// `a` and `b` must each be readable for `size` bytes.
#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
#[inline(always)]
unsafe fn memneq_generic(a: *const u8, b: *const u8, size: usize) -> c_ulong {
    let mut neq: c_ulong = 0;
    let mut a = a;
    let mut b = b;
    let mut size = size;

    while size > 0 {
        // SAFETY: `size` bytes remain readable on both sides.
        neq |= unsafe { c_ulong::from(*a) ^ c_ulong::from(*b) };
        neq = hide(neq);
        // SAFETY: as above.
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
        size -= 1;
    }
    neq
}

/// `__crypto_memneq_16()`: the loop-free path for the 16-byte case, which is
/// every 128-bit authentication tag in the kernel.
///
/// # Safety
/// `a` and `b` must each be readable for 16 bytes.
#[cfg(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)]
#[inline(always)]
unsafe fn memneq_16(a: *const u8, b: *const u8) -> c_ulong {
    // The C forks on `sizeof(unsigned long) == 8` here. This file is the
    // 64-bit arm; `kernel::kabi_export!` already refuses to build on 32-bit.
    const _: () = assert!(core::mem::size_of::<c_ulong>() == 8);

    let mut neq: c_ulong = 0;
    // SAFETY: 16 bytes are readable on both sides, so both 8-byte unaligned
    // reads at offsets 0 and 8 are in bounds.
    neq |= unsafe { (a as *const c_ulong).read_unaligned() ^ (b as *const c_ulong).read_unaligned() };
    neq = hide(neq);
    // SAFETY: as above, the second half.
    neq |= unsafe {
        (a.add(8) as *const c_ulong).read_unaligned() ^ (b.add(8) as *const c_ulong).read_unaligned()
    };
    hide(neq)
}

/// `__crypto_memneq_16()` where an unaligned word load is not cheap: the C
/// spells out sixteen byte compares with a barrier after each, and so does
/// this.
///
/// NOT COMPILED BY EITHER CONFIGURATION AND COVERED BY NO TEST. See the
/// module documentation and `logs/build-limits.md`.
///
/// # Safety
/// `a` and `b` must each be readable for 16 bytes.
#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
#[inline(always)]
unsafe fn memneq_16(a: *const u8, b: *const u8) -> c_ulong {
    let mut neq: c_ulong = 0;

    for i in 0..16 {
        // SAFETY: 16 bytes are readable on both sides and `i < 16`.
        neq |= unsafe { c_ulong::from(*a.add(i)) ^ c_ulong::from(*b.add(i)) };
        neq = hide(neq);
    }
    neq
}

// The C types this contract names. A Rust object has no C type graph to
// resolve them against, so they are not duplicates of anything -- omit one
// and the build stops naming the reference it could not resolve.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");

kernel::kabi_export! {
    __crypto_memneq,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } a , formal_parameter pointer_type { const_type { base_type void } } b , formal_parameter t#size_t size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// Body of `__crypto_memneq()`. Non-zero if the two regions differ.
///
/// `#[inline(never)]` is the C's `noinline`, and it is load-bearing for the
/// same reason [`hide`] is: inlined into a caller that immediately branches
/// on the result, the optimiser gets a second chance to reintroduce an early
/// exit. Callers use the `crypto_memneq()` wrapper in `include/crypto/
/// utils.h`, which is where the `!= 0` lives.
///
/// # Safety
/// `a` and `b` must each be readable for `size` bytes. Same contract as the
/// C; neither is dereferenced when `size` is zero.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __crypto_memneq(a: *const c_void, b: *const c_void, size: usize) -> c_ulong {
    // SAFETY: the caller guarantees `size` readable bytes on both sides, and
    // the 16-byte arm is only entered when `size` is exactly 16.
    unsafe {
        match size {
            16 => memneq_16(a as *const u8, b as *const u8),
            _ => memneq_generic(a as *const u8, b as *const u8, size),
        }
    }
}
