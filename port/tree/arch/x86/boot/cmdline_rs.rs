// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/cmdline.c in the 16-bit real-mode setup (code16, -Zregparm=3).
//! Exports exactly the two symbols the C object exports: `__cmdline_find_option()` and
//! `__cmdline_find_option_bool()` (boot.h's static-inline wrappers `cmdline_find_option*()` stay C
//! and check `cmd_line_ptr >= 0x100000`; cpucheck_rs.rs does the same check itself).
//! This source is shared in C with the 64-bit boot stub, which has its own accepted Rust version
//! (compressed/cmdline_rs.rs); that file is untouched. This one is the real-mode flavour: the command
//! line is read through `%fs` exactly like boot.h's `set_fs(seg); rdfs8(off)`.
//!
//! Address arithmetic (the whole point): `cptr = cmdline_ptr & 0xf` is the starting OFFSET, `set_fs(cmdline_ptr >> 4)`
//! the segment (u16 truncation as in the C), so `fs:cptr` is the linear address `cmdline_ptr` for any
//! cmdline_ptr < 1 MiB; the scan runs while `cptr < 0x10000`, i.e. at most up to the end of the 64 KiB segment window
//! (offset <= 0xffff, never a 16-bit offset wrap), and hitting that limit without a NUL ends the scan
//! (find_option: result so far; find_option_bool: 0 "buffer overrun"). `cmdline_ptr == 0` -> -1 before anything is read.
//!
//! Semantics reproduced from the C (state machine st_wordstart / st_wordcmp / st_wordskip / st_bufcpy):
//! `myisspace(c)` is `c <= ' '` (unsigned byte: NUL, controls, tab, newline, space; bytes >= 0x80 are NOT space).
//! There is NO quote handling in the C and none here (a `"` is an ordinary byte, spaces split words even inside quotes).
//! find_option: last `option=value` word wins (the buffer is restarted, `len = 0`, at every match; bytes beyond the final
//! NUL of an earlier longer value stay in the caller's buffer); returns the full value length even when truncated,
//! -1 if not found; copies at most bufsize-1 bytes and writes the terminating NUL at buffer[min(len, bufsize-1)] iff
//! bufsize != 0 (also on "not found": buffer[0] = 0). `option=` with an empty value gives 0. An empty option name
//! matches a word that starts with '='. find_option_bool: first word equal to `option` (word ends at whitespace or NUL;
//! NOT at the window end), returns its 1-based position (counting from the first byte read, cmdline_ptr), 0 if absent;
//! a prefix of a longer word (`debug` vs `debugfoo`) and a longer option than the word do not match; an empty option never matches.
//! No message strings exist in the C or here.
//!
//! Deliberate divergences: none in behaviour. `bufsize - 1` is computed wrapping (the C is signed arithmetic compiled under the
//! kernel's -fno-strict-overflow, `lea -1(%ecx)`; callers pass sizeof(buf) > 0; bufsize < 0 is out of contract and, as in the
//! C, writes only buffer[0]; INT_MIN would wrap to INT_MAX in both). The loop counters can't overflow (<= 0x10000 iterations).
//! The algorithm is one generic function per entry point (`LIM` = the window size) so Kani can prove the SAME code with a small
//! window (`cfg(kani)`, rig/realmode/kani); the exported functions use LIM = 0x10000. Under `--cfg host_mock` (host tests only)
//! set_fs / rdfs8 are extern hooks (rig/realmode/cmdline-diff.c), never set for the target build.
//!
//! TEST-GAP: the real `%fs:` segment-relative access with a real-mode segment base/limit (the 1 MiB wrap with A20 off, a
//! cmdline in the HMA, 64 KiB limit faults) cannot be provoked in QEMU boots: the loader puts the command line at 0x20000
//! and the boot test cannot choose cmdline_ptr. The host rig models memory as a flat 1.06 MiB buffer addressed seg*16+off and
//! the object compare shows the same fs: instruction; the boots cover the real asm with the loader's pointer only.
#![allow(dead_code)]

use core::ffi::{c_char, c_int};

/// The offset window of one segment (`while (cptr < 0x10000 ...)` in the C).
const SEG_WINDOW: u32 = 0x10000;

#[cfg(not(any(host_mock, kani)))]
mod seg {
    use core::arch::asm;
    /// boot.h `set_fs()`: `movw %0,%%fs`.
    #[inline(always)]
    pub unsafe fn set_fs(seg: u16) {
        // SAFETY: loads a segment register with a real-mode paragraph (same as the C's asm volatile).
        unsafe { asm!("mov fs, {0:x}", in(reg_abcd) seg, options(nostack, preserves_flags)) };
    }
    /// boot.h `rdfs8()`: `movb %fs:(off),%reg`.
    #[inline(always)]
    pub unsafe fn rdfs8(off: u32) -> u8 {
        let v: u8;
        // SAFETY: reads one byte of the loader's command line; off < 0x10000 (the callers' loop condition).
        unsafe { asm!("mov {0}, byte ptr fs:[{1:e}]", out(reg_byte) v, in(reg) off, options(nostack, preserves_flags, readonly)) };
        v
    }
}

#[cfg(host_mock)]
mod seg {
    extern "C" {
        fn mock_set_fs(s: u16);
        fn mock_rdfs8(off: u32) -> u8;
    }
    pub unsafe fn set_fs(s: u16) {
        unsafe { mock_set_fs(s) }
    }
    pub unsafe fn rdfs8(off: u32) -> u8 {
        unsafe { mock_rdfs8(off) }
    }
}

/// Kani model: the segment window is a symbolic array KMEM (any bytes); an access outside it is a Kani failure, so every
/// `rdfs8(off)` is also proved to stay inside the window. set_fs has no effect on the model.
#[cfg(kani)]
mod seg {
    pub const KWIN: usize = 16;
    pub static mut KMEM: [u8; KWIN] = [0; KWIN];
    pub unsafe fn set_fs(_s: u16) {}
    pub unsafe fn rdfs8(off: u32) -> u8 {
        // SAFETY (model): single-threaded harness; indexing is bounds-checked by Rust/Kani.
        unsafe { KMEM[off as usize] }
    }
}

#[inline(always)]
fn myisspace(c: u8) -> bool {
    c <= b' ' // "Close enough approximation", as the C says
}

// The C's four states are compiled here into control flow instead of a `state` variable (a `state` enum made LLVM keep
// the state in memory: 773 bytes vs 510 for the C). Mapping, per byte read:
//   st_wordstart = the `skip whitespace` loop;  st_wordcmp = the `'word` loop;  st_wordskip = the `skip` loop;  st_bufcpy = the copy loop.
// Every read goes through one of the `next` steps, which is the C's `while (cptr < 0x10000 && (c = rdfs8(cptr++)))`.

/// `__cmdline_find_option()` of cmdline.c with the window size as a parameter.
///
/// # Safety
/// `option` is NUL-terminated; `buffer` has room for `bufsize` bytes (bufsize >= 0, or >= 1 byte if negative).
#[inline(always)]
unsafe fn find_option_impl<const LIM: u32>(cmdline_ptr: u32, option: *const u8, buffer: *mut u8, bufsize: c_int) -> c_int {
    let mut len: c_int = -1;
    let mut bufptr = buffer;

    if cmdline_ptr == 0 {
        return -1; // no command line
    }

    const { assert!(LIM > 0xf) }; // cptr starts at <= 0xf and steps by 1, so `cptr == LIM` is the C's `cptr < LIM` (the C compiles to the same compare)
    let mut cptr: u32 = cmdline_ptr & 0xf;
    // SAFETY: segment register load, as the C.
    unsafe { seg::set_fs((cmdline_ptr >> 4) as u16) };

    // `while (cptr < LIM && (c = rdfs8(cptr++)))`: ends the scan (not the function) at the window end or a NUL.
    macro_rules! next {
        ($c:ident, $done:lifetime) => {
            if cptr == LIM {
                break $done;
            }
            // SAFETY: cptr < LIM <= 0x10000: inside the segment window.
            let $c = unsafe { seg::rdfs8(cptr) };
            cptr += 1;
            if $c == 0 {
                break $done;
            }
        };
    }

    'scan: loop {
        // st_wordstart: skip whitespace
        let mut c;
        loop {
            next!(c0, 'scan);
            c = c0;
            if !myisspace(c) {
                break;
            }
        }
        // st_wordcmp (first byte of a word): opptr = option
        let mut opptr = option;
        'word: loop {
            // SAFETY: opptr walks the NUL-terminated `option`; it steps past a NUL only when the byte read was nonzero and
            // not '=' / not a space and mismatching, which moves to the skip loop, so a byte beyond the NUL is never read.
            if c == b'=' && unsafe { *opptr } == 0 {
                len = 0;
                bufptr = buffer;
                // st_bufcpy
                loop {
                    next!(c1, 'scan);
                    if myisspace(c1) {
                        continue 'scan; // st_wordstart
                    }
                    if len < bufsize.wrapping_sub(1) {
                        // SAFETY: 0 <= len < bufsize-1 so bufptr = buffer+len is inside the caller's buffer
                        // (proved: logs/proofs/cmdline-bounds.py, Kani harnesses in this file).
                        unsafe { *bufptr = c1 };
                        // SAFETY: at most buffer + bufsize - 1.
                        bufptr = unsafe { bufptr.add(1) };
                    }
                    len += 1;
                }
            } else if myisspace(c) {
                continue 'scan; // st_wordstart
            } else {
                // SAFETY: as above (`c != *opptr++`).
                let o = unsafe { *opptr };
                // SAFETY: at most one past the NUL; not dereferenced again (see above).
                opptr = unsafe { opptr.add(1) };
                if c != o {
                    // st_wordskip
                    loop {
                        next!(c2, 'scan);
                        if myisspace(c2) {
                            continue 'scan; // st_wordstart
                        }
                    }
                }
            }
            next!(c3, 'scan);
            c = c3;
            continue 'word;
        }
    }

    if bufsize != 0 {
        // SAFETY: bufptr <= buffer + max(bufsize-1, 0).
        unsafe { *bufptr = 0 };
    }
    len
}

/// `__cmdline_find_option_bool()` of cmdline.c with the window size as a parameter.
///
/// # Safety
/// `option` is NUL-terminated.
#[inline(always)]
unsafe fn find_option_bool_impl<const LIM: u32>(cmdline_ptr: u32, option: *const u8) -> c_int {
    let mut pos: c_int = 0;

    if cmdline_ptr == 0 {
        return -1; // no command line
    }

    const { assert!(LIM > 0xf) }; // cptr starts at <= 0xf and steps by 1, so `cptr == LIM` is the C's `cptr < LIM` (the C compiles to the same compare)
    let mut cptr: u32 = cmdline_ptr & 0xf;
    // SAFETY: segment register load, as the C.
    unsafe { seg::set_fs((cmdline_ptr >> 4) as u16) };

    // `while (cptr < LIM) { c = rdfs8(cptr++); pos++; ...}`; the window end is "buffer overrun" -> 0. A NUL is handled by
    // each state (it ends the scan with 0, or with `wstart` when the word is complete).
    macro_rules! next {
        ($c:ident) => {
            if cptr == LIM {
                return 0; // buffer overrun
            }
            // SAFETY: cptr < LIM <= 0x10000: inside the segment window.
            let $c = unsafe { seg::rdfs8(cptr) };
            cptr += 1;
            pos += 1;
        };
    }

    loop {
        // st_wordstart
        let mut c;
        loop {
            next!(c0);
            c = c0;
            if c == 0 {
                return 0;
            } else if !myisspace(c) {
                break;
            }
        }
        let wstart = pos;
        let mut opptr = option;
        loop {
            // st_wordcmp
            // SAFETY: opptr walks the NUL-terminated `option` and never passes its NUL: at the NUL we
            // return or switch to the skip loop (which reads nothing from option).
            let o = unsafe { *opptr };
            let mut skip = false;
            if o == 0 {
                if c == 0 || myisspace(c) {
                    return wstart;
                } else {
                    skip = true;
                }
            } else if c == 0 {
                return 0;
            } else {
                // SAFETY: *opptr != 0 here, so opptr+1 is still inside the string.
                opptr = unsafe { opptr.add(1) };
                if c != o {
                    skip = true;
                }
            }
            if skip {
                // st_wordskip
                loop {
                    next!(c2);
                    if c2 == 0 {
                        return 0;
                    } else if myisspace(c2) {
                        break;
                    }
                }
                break; // back to st_wordstart
            }
            next!(c3);
            c = c3;
        }
    }
}

/// `int __cmdline_find_option(unsigned long cmdline_ptr, const char *option, char *buffer, int bufsize)`
/// (`unsigned long` is 32 bits in the setup's i386 code).
#[cfg(not(kani))]
#[no_mangle]
pub unsafe extern "C" fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int {
    // SAFETY: same contracts as the C.
    unsafe { find_option_impl::<SEG_WINDOW>(cmdline_ptr, option as *const u8, buffer as *mut u8, bufsize) }
}

/// `int __cmdline_find_option_bool(unsigned long cmdline_ptr, const char *option)`.
#[cfg(not(kani))]
#[no_mangle]
pub unsafe extern "C" fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int {
    // SAFETY: same contract as the C.
    unsafe { find_option_bool_impl::<SEG_WINDOW>(cmdline_ptr, option as *const u8) }
}

// ---- Kani proofs (rig/realmode/run-cmdline-kani.sh). The memory is KMEM (a symbolic array), the window is KLIM = 16 bytes (> 15: the start offset is at most 0xf), and the harnesses start in the last 5 bytes of it (cmdline_ptr & 0xf >= 11): the
// code's loops are nested, CBMC unrolls them multiplicatively (a start of 0 did not finish in 8 minutes). So the proved range is every run of <= 5 reads
// (all state transitions occur in it), not the full window; the full 0x10000 window is covered by the Z3 proof A1/A2 (arithmetic) and the host rig
// instead of 0x10000 so that CBMC can unwind the loop; the proved code is the generic function above, the same text the target uses.
#[cfg(kani)]
mod proofs {
    use super::*;
    const KLIM: u32 = seg::KWIN as u32;

    fn fill_mem() {
        let m: [u8; seg::KWIN] = kani::any();
        // SAFETY: single-threaded harness.
        unsafe { seg::KMEM = m };
    }

    /// Any command line (KMEM), any pointer (incl. >= 1 MiB, low nibble anything), any 0..2-char option, bufsize in [-3, 6],
    /// buffer of 6 bytes: no read of `option` past its NUL, no read outside the window (KMEM index), no write outside
    /// buffer[0..max(bufsize,1)], no overflow (every `+`/`-`/`+=` is checked), the loop unwinds within the window, result in
    /// [-1, KLIM], the NUL at buffer[min(len, bufsize-1)] for bufsize >= 1, buffer untouched for bufsize == 0 or no cmdline.
    #[kani::proof]
    #[kani::unwind(7)]
    fn find_option_memory_safe() {
        fill_mem();
        let ptr: u32 = kani::any();
        kani::assume(ptr & 0xf >= 11); // at most 5 reads before the window end (nested loops: CBMC unrolling is multiplicative)
        let opt: [u8; 3] = [kani::any(), kani::any(), 0]; // NUL-terminated, any two leading bytes
        let mut buf = [0x5au8; 6];
        let bufsize: c_int = kani::any();
        kani::assume(bufsize >= -3 && bufsize <= 6);
        let r = unsafe { find_option_impl::<KLIM>(ptr, opt.as_ptr(), buf.as_mut_ptr(), bufsize) };
        assert!(r >= -1 && r <= KLIM as c_int);
        if ptr == 0 {
            assert!(r == -1 && buf == [0x5a; 6]); // nothing read, nothing written
        } else if bufsize == 0 {
            assert!(buf == [0x5a; 6]);
        } else if bufsize >= 1 {
            let idx = if r < 0 { 0 } else if r < bufsize - 1 { r as usize } else { (bufsize - 1) as usize };
            assert!(buf[idx] == 0);
            let mut i = bufsize as usize;
            while i < 6 {
                assert!(buf[i] == 0x5a); // nothing at or beyond bufsize was written (between the NUL and bufsize: stale bytes of an earlier, longer match are legal)
                i += 1;
            }
        } else {
            // bufsize < 0 (out of contract): only buffer[0] may be written
            let mut i = 1;
            while i < 6 {
                assert!(buf[i] == 0x5a);
                i += 1;
            }
        }
    }

    /// find_option_bool: the same memory-safety / overflow / termination facts; result in [-1, KLIM]; -1 iff no command line.
    #[kani::proof]
    #[kani::unwind(7)]
    fn find_option_bool_memory_safe() {
        fill_mem();
        let ptr: u32 = kani::any();
        kani::assume(ptr & 0xf >= 11); // at most 5 reads before the window end (nested loops: CBMC unrolling is multiplicative)
        let opt: [u8; 4] = [kani::any(), kani::any(), kani::any(), 0];
        let r = unsafe { find_option_bool_impl::<KLIM>(ptr, opt.as_ptr()) };
        assert!(r >= -1 && r <= KLIM as c_int);
        assert!((r == -1) == (ptr == 0));
    }

    /// The write-index bound for EVERY int bufsize >= 1 (up to INT_MAX; the 6-byte buffer harness cannot cover them), on the very
    /// expression the code uses (`len < bufsize.wrapping_sub(1)`): a copy at index len implies len + 1 <= bufsize - 1, so the
    /// terminating NUL at buffer + (copies) is at index <= bufsize - 1; `len` of one window (<= 0x10000) never overflows.
    #[kani::proof]
    fn copy_index_bound_any_bufsize() {
        let bufsize: c_int = kani::any();
        let len: c_int = kani::any();
        kani::assume(bufsize >= 1);
        kani::assume(len >= 0 && len <= SEG_WINDOW as c_int);
        if len < bufsize.wrapping_sub(1) {
            assert!((len as i64) + 1 <= (bufsize as i64) - 1);
            assert!(len.checked_add(1).is_some());
        }
    }
}
