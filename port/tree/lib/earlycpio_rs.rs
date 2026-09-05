// SPDX-License-Identifier: GPL-2.0-only

//! Find a member of an uncompressed cpio -- the Rust body behind
//! `lib/earlycpio.c`.
//!
//! Ported from `lib/earlycpio.c` (6.18.49), Copyright 2012 Intel
//! Corporation, author H. Peter Anvin. Used to locate items in the initramfs
//! that the kernel needs before the main initramfs is decompressed — early
//! microcode, mostly.
//!
//! # No C entry symbol
//!
//! `find_cpio_data()` is global but not `EXPORT_SYMBOL`, so it has no
//! MODVERSIONS CRC and needs no thunk. `lib/earlycpio.c` keeps one four-line
//! function that Rust cannot express — see below.
//!
//! # Offsets, not pointers
//!
//! The C walks a `const char *p` and decrements a `len`, and does its
//! bounds checks by comparing pointers that it has already advanced —
//! `nptr > p + len || dptr < p || nptr < dptr`. Those comparisons are only
//! meaningful if none of the intermediate pointers has overflowed, which is
//! exactly what the check is trying to establish. Working in offsets into a
//! bounded slice makes the same three tests checked arithmetic on integers,
//! and every read is then in range by construction.
//!
//! Replaces: lib/earlycpio.c

use core::ffi::{c_char, c_long, c_void};

/// `MAX_CPIO_FILE_NAME` from `include/linux/earlycpio.h`.
const MAX_CPIO_FILE_NAME: usize = 18;

/// Mirrors `struct cpio_data` in `include/linux/earlycpio.h`. Returned by
/// value across the FFI boundary, so the layout is the caller's.
#[repr(C)]
pub struct CpioData {
    /// The member's contents, or null if not found.
    pub data: *mut c_void,
    /// Its length in bytes.
    pub size: usize,
    /// Its name with the searched directory prefix removed.
    pub name: [c_char; MAX_CPIO_FILE_NAME],
}

/// Field indices in a newc cpio header, as the C's `enum cpio_fields`.
const C_MAGIC: usize = 0;
const C_MODE: usize = 2;
const C_FILESIZE: usize = 7;
const C_NAMESIZE: usize = 12;
const C_NFIELDS: usize = 14;

extern "C" {
    /// `lib/earlycpio.c`. `pr_warn()` is a macro over `printk` with a
    /// per-call format string and section magic; it is not something a Rust
    /// body can raise on the C's behalf.
    fn rust_earlycpio_warn_long_name(name: *const c_char);
}

/// Round `x` up to the next multiple of 4, as the C's `PTR_ALIGN(_, 4)`.
/// Returns `None` on overflow, which the C's pointer arithmetic could not
/// have detected.
#[inline]
fn align4(x: usize) -> Option<usize> {
    x.checked_add(3).map(|v| v & !3)
}

/// Body of `find_cpio_data()`.
///
/// # Safety
/// `path` must be a NUL-terminated string and `data` readable for `len`
/// bytes. `nextoff` may be null; if not, it must be writable. Same contract
/// as the C.
///
/// See `include/linux/earlycpio.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn find_cpio_data(
    path: *const c_char,
    data: *mut c_void,
    len: usize,
    nextoff: *mut c_long,
) -> CpioData {
    // Six characters of magic, then thirteen eight-character fields.
    const HEADER_LEN: usize = 8 * C_NFIELDS - 2;

    let mut cd = CpioData {
        data: core::ptr::null_mut(),
        size: 0,
        name: [0; MAX_CPIO_FILE_NAME],
    };

    // SAFETY: the caller guarantees a NUL-terminated `path` and `len`
    // readable bytes at `data`.
    let (buf, path_bytes) = unsafe {
        let mut n = 0usize;

        while *(path as *const u8).add(n) != 0 {
            n += 1;
        }
        (
            if len == 0 {
                &[][..]
            } else {
                core::slice::from_raw_parts(data as *const u8, len)
            },
            core::slice::from_raw_parts(path as *const u8, n),
        )
    };
    let mypathsize = path_bytes.len();

    // `off` is the C's `p` and `avail` its `len`; both are offsets and
    // counts into `buf` rather than pointers, so nothing can wrap.
    let mut off = 0usize;
    let mut avail = len;

    while avail > HEADER_LEN {
        if buf[off] == 0 {
            // All cpio headers are 4-byte aligned.
            if avail < 4 {
                break;
            }
            off += 4;
            avail -= 4;
            continue;
        }

        let mut ch = [0u32; C_NFIELDS];
        let mut width = 6; // the magic field is only six characters
        let mut cur = off;

        for field in ch.iter_mut() {
            let mut v: u32 = 0;

            for _ in 0..width {
                if cur >= buf.len() {
                    return cd;
                }
                let c = buf[cur];

                cur += 1;
                v <<= 4;
                let x = c.wrapping_sub(b'0');

                if x < 10 {
                    v += x as u32;
                    continue;
                }
                let x = (c | 0x20).wrapping_sub(b'a');

                if x < 6 {
                    v += x as u32 + 10;
                    continue;
                }
                return cd; // invalid hexadecimal
            }
            *field = v;
            width = 8; // every other field is eight characters
        }
        off = cur;

        if ch[C_MAGIC].wrapping_sub(0x070701) > 1 {
            return cd; // invalid magic
        }

        avail -= HEADER_LEN;

        // The C computes these as pointers and then checks them for
        // overrun; here the same three tests are checked integer
        // arithmetic, so a malformed archive cannot form a wild pointer
        // before the check that is meant to reject it.
        let Some(dptr) = align4(off.wrapping_add(ch[C_NAMESIZE] as usize)) else {
            return cd;
        };
        let Some(nptr) = align4(dptr.wrapping_add(ch[C_FILESIZE] as usize)) else {
            return cd;
        };

        if nptr > off + avail || dptr < off || nptr < dptr {
            return cd; // buffer overrun
        }

        // A regular file (S_IFREG) whose name starts with the path we want.
        if ch[C_MODE] & 0o170000 == 0o100000
            && ch[C_NAMESIZE] as usize >= mypathsize
            && off + mypathsize <= buf.len()
            && &buf[off..off + mypathsize] == path_bytes
        {
            if !nextoff.is_null() {
                // SAFETY: the caller guarantees `nextoff` is writable.
                unsafe { *nextoff = nptr as c_long };
            }

            if ch[C_NAMESIZE] as usize - mypathsize >= MAX_CPIO_FILE_NAME {
                // SAFETY: `off` is inside `buf`, and the name in a valid
                // archive is NUL-terminated within it -- the same string
                // the C hands to pr_warn.
                unsafe { rust_earlycpio_warn_long_name(buf.as_ptr().add(off) as *const c_char) };
            }

            // strscpy(cd.name, p + mypathsize, MAX_CPIO_FILE_NAME): copy up
            // to 17 bytes and always NUL-terminate. Bounded by the buffer
            // as well as by the field, which the C's strscpy is not --
            // see DIVERGENCES.
            let start = off + mypathsize;
            let mut i = 0;

            while i < MAX_CPIO_FILE_NAME - 1 && start + i < buf.len() {
                let b = buf[start + i];

                if b == 0 {
                    break;
                }
                cd.name[i] = b as c_char;
                i += 1;
            }
            cd.name[i] = 0;

            // SAFETY: `dptr` was just checked to be within `off + avail`,
            // which is within the caller's buffer.
            cd.data = unsafe { (data as *mut u8).add(dptr) } as *mut c_void;
            cd.size = ch[C_FILESIZE] as usize;
            return cd; // found it
        }

        avail -= nptr - off;
        off = nptr;
    }

    cd
}

// DIVERGENCES from lib/earlycpio.c, per GOALS.md §5.
//
// 1. The name copy is bounded by the input buffer as well as by
//    MAX_CPIO_FILE_NAME. The C calls strscpy(), which stops at 17 bytes or
//    at a NUL -- and in a malformed archive whose final name field has no
//    NUL before the end of the buffer, that NUL is not there to find.
//
//    Q1 observable?  Only on input where the C reads past the end of the
//       buffer it was given, which is undefined behaviour rather than
//       behaviour. On every valid archive the two are identical.
//    Q2 layout or interface?  No.
//    Q3 forces a change elsewhere?  No.
//
// 2. The two `PTR_ALIGN` computations are checked for overflow. The C forms
//    the pointers first and then tests them for overrun, which cannot
//    detect the case where forming them overflowed. Same three tests, done
//    where they still mean something.
