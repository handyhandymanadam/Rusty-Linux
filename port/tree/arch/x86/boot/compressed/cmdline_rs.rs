// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/cmdline.c, which #includes
//! ../cmdline.c (the algorithm shared with the 16-bit real-mode setup; that
//! file stays C and is untouched).
//!
//! In the 64-bit stub the real-mode "fs:offset" read is `fs = seg << 4;
//! *(char *)(fs + addr)` (see the C's rdfs8()), i.e. the flat address
//! `(cmdline_ptr >> 4 << 4) + off` with `off` starting at `cmdline_ptr & 0xf`
//! and the scan stopping at off == 0x10000. That is reproduced exactly,
//! including the 64 KiB window from the 16-byte-aligned base.

use core::ffi::{c_char, c_int, c_ulong};

extern "C" {
    /// `struct boot_params *boot_params_ptr` (pgtable_64.c / ident_map_64.c).
    static boot_params_ptr: *const u8;
}

/// offsetof(struct boot_params, hdr.cmd_line_ptr) = 0x1f1 + 0x37 (u32). Checked
/// against the compiler by logs/ (see the commit message / test evidence).
const CMD_LINE_PTR_OFF: usize = 0x228;
/// offsetof(struct boot_params, ext_cmd_line_ptr) (u32).
const EXT_CMD_LINE_PTR_OFF: usize = 0x0c8;

#[inline(always)]
fn myisspace(c: u8) -> bool {
    c <= b' ' // "Close enough approximation", as the C says
}

/// Byte at flat address `fs + off`.
///
/// # Safety
/// The address must be readable: it is, for the C as well, because it is the
/// boot loader's command line (identity mapped by the stub).
#[inline(always)]
unsafe fn rdfs8(fs: usize, off: usize) -> u8 {
    // SAFETY: caller contract above.
    unsafe { *((fs + off) as *const u8) }
}

#[no_mangle]
pub unsafe extern "C" fn get_cmd_line_ptr() -> c_ulong {
    // SAFETY: boot_params_ptr is set (pgtable_64.c/ident_map_64.c) before any caller runs, as for the C.
    let bp = unsafe { boot_params_ptr };
    // SAFETY: both fields lie inside struct boot_params (offsets above); u32, unaligned-tolerant read.
    let (lo, ext) = unsafe {
        (
            (bp.add(CMD_LINE_PTR_OFF) as *const u32).read_unaligned(),
            (bp.add(EXT_CMD_LINE_PTR_OFF) as *const u32).read_unaligned(),
        )
    };
    (lo as c_ulong) | ((ext as u64) << 32) as c_ulong
}

#[derive(PartialEq, Clone, Copy)]
enum St {
    WordStart, // start of word / after whitespace
    WordCmp,   // comparing this word
    WordSkip,  // miscompare, skip
    BufCpy,    // copying this to buffer
}

/// `__cmdline_find_option()` of ../cmdline.c.
unsafe fn find_option(cmdline_ptr: c_ulong, option: *const u8, buffer: *mut u8, bufsize: c_int) -> c_int {
    let mut len: c_int = -1;
    let mut opptr: *const u8 = core::ptr::null();
    let mut bufptr = buffer;
    let mut state = St::WordStart;

    if cmdline_ptr == 0 {
        return -1; // no command line
    }

    let mut cptr = (cmdline_ptr & 0xf) as usize;
    let fs = ((cmdline_ptr >> 4) << 4) as usize;

    while cptr < 0x10000 {
        // SAFETY: see rdfs8().
        let c = unsafe { rdfs8(fs, cptr) };
        cptr += 1;
        if c == 0 {
            break;
        }
        // st_wordstart falls through into st_wordcmp
        if state == St::WordStart {
            if myisspace(c) {
                continue;
            }
            state = St::WordCmp;
            opptr = option;
        }
        match state {
            St::WordCmp => {
                // SAFETY: opptr walks the NUL-terminated `option`; it stops advancing at its NUL
                // because a NUL in `c` (the only way past it) has ended the loop, as in the C.
                if c == b'=' && unsafe { *opptr } == 0 {
                    len = 0;
                    bufptr = buffer;
                    state = St::BufCpy;
                } else if myisspace(c) {
                    state = St::WordStart;
                } else {
                    // SAFETY: as above.
                    let o = unsafe { *opptr };
                    // SAFETY: as above (one past the NUL is never read, see above).
                    opptr = unsafe { opptr.add(1) };
                    if c != o {
                        state = St::WordSkip;
                    }
                }
            }
            St::WordSkip => {
                if myisspace(c) {
                    state = St::WordStart;
                }
            }
            St::BufCpy => {
                if myisspace(c) {
                    state = St::WordStart;
                } else {
                    if len < bufsize.wrapping_sub(1) {
                        // SAFETY: len < bufsize-1, so the byte is inside the caller's buffer.
                        unsafe { *bufptr = c };
                        // SAFETY: stays within (or one past) the caller's buffer.
                        bufptr = unsafe { bufptr.add(1) };
                    }
                    len += 1;
                }
            }
            St::WordStart => {}
        }
    }

    if bufsize != 0 {
        // SAFETY: bufptr is within the caller's buffer (at most buffer + bufsize - 1).
        unsafe { *bufptr = 0 };
    }
    len
}

/// `__cmdline_find_option_bool()` of ../cmdline.c.
unsafe fn find_option_bool(cmdline_ptr: c_ulong, option: *const u8) -> c_int {
    let mut pos: c_int = 0;
    let mut wstart: c_int = 0;
    let mut opptr: *const u8 = core::ptr::null();
    let mut state = St::WordStart;

    if cmdline_ptr == 0 {
        return -1; // no command line
    }

    let mut cptr = (cmdline_ptr & 0xf) as usize;
    let fs = ((cmdline_ptr >> 4) << 4) as usize;

    while cptr < 0x10000 {
        // SAFETY: see rdfs8().
        let c = unsafe { rdfs8(fs, cptr) };
        cptr += 1;
        pos += 1;

        if state == St::WordStart {
            if c == 0 {
                return 0;
            } else if myisspace(c) {
                continue;
            }
            state = St::WordCmp;
            opptr = option;
            wstart = pos;
        }
        match state {
            St::WordCmp => {
                // SAFETY: opptr walks the NUL-terminated `option` and never passes its NUL:
                // at the NUL we return or switch state, as in the C.
                let o = unsafe { *opptr };
                if o == 0 {
                    if c == 0 || myisspace(c) {
                        return wstart;
                    } else {
                        state = St::WordSkip;
                    }
                } else if c == 0 {
                    return 0;
                } else {
                    // SAFETY: as above.
                    opptr = unsafe { opptr.add(1) };
                    if c != o {
                        state = St::WordSkip;
                    }
                }
            }
            St::WordSkip => {
                if c == 0 {
                    return 0;
                } else if myisspace(c) {
                    state = St::WordStart;
                }
            }
            St::WordStart | St::BufCpy => {}
        }
    }
    0 // buffer overrun
}

#[no_mangle]
pub unsafe extern "C" fn cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int {
    // SAFETY: same contracts as the C wrapper.
    unsafe { find_option(get_cmd_line_ptr(), option as *const u8, buffer as *mut u8, bufsize) }
}

#[no_mangle]
pub unsafe extern "C" fn cmdline_find_option_bool(option: *const c_char) -> c_int {
    // SAFETY: same contract as the C wrapper.
    unsafe { find_option_bool(get_cmd_line_ptr(), option as *const u8) }
}
