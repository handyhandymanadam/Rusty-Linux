// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/printf.c (16-bit real-mode setup): the tiny
//! printf family -- vsprintf(), sprintf(), printf(). No 64-bit support, as in the C ("Live with
//! it."); `long` is 32 bits on this target. Output is byte-for-byte what the C produces,
//! including its quirks: unknown conversions are copied as "%<c>", `%s` with no precision
//! uses strnlen(s, (size_t)-1), a base outside 2..=16 makes number() return NULL.
//!
//! The variadic entry points need the unstable `c_variadic` feature (logs/unstable-features.md).
//! The `...` parameters are passed on the stack, as for the C: regparm does not apply to them.
#![feature(c_variadic)]
#![allow(dead_code)]

#[path = "rm_common.rs"]
mod rm;

use core::ffi::{c_char, c_int, c_void, VaList};

extern "C" {
    /// string.c
    fn strnlen(s: *const c_char, maxlen: usize) -> usize;
    /// tty (tty.c / tty_rs.rs)
    fn puts(s: *const c_char);
}

const ZEROPAD: i32 = 1; // pad with zero
const SIGN: i32 = 2; // unsigned/signed long
const PLUS: i32 = 4; // show plus
const SPACE: i32 = 8; // space if plus
const LEFT: i32 = 16; // left justified
const SMALL: i32 = 32; // must be 32 == 0x20
const SPECIAL: i32 = 64; // 0x

#[inline(always)]
fn isdigit(c: u8) -> bool {
    c.wrapping_sub(b'0') < 10
}

unsafe fn skip_atoi(s: &mut *const u8) -> i32 {
    let mut i: i32 = 0;
    // SAFETY: *s walks a NUL-terminated format string; the NUL stops the loop.
    unsafe {
        while isdigit(**s) {
            i = i.wrapping_mul(10).wrapping_add((**s - b'0') as i32);
            *s = (*s).add(1);
        }
    }
    i
}

/// Returns the new `str`, or NULL for a base outside 2..=16.
unsafe fn number(mut str: *mut u8, num: i32, base: i32, mut size: i32, mut precision: i32, mut typ: i32) -> *mut u8 {
    // we are called with base 8, 10 or 16, only, thus don't need "G..."
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut tmp = [0u8; 66];

    // locase = 0 or 0x20. ORing digits or letters with 'locase' produces the same digits or
    // (maybe lowercased) letters.
    let locase = (typ & SMALL) as u8;
    if typ & LEFT != 0 {
        typ &= !ZEROPAD;
    }
    if base < 2 || base > 16 {
        return core::ptr::null_mut();
    }
    let c = if typ & ZEROPAD != 0 { b'0' } else { b' ' };
    let mut sign: u8 = 0;
    let mut n = num;
    if typ & SIGN != 0 {
        if n < 0 {
            sign = b'-';
            n = n.wrapping_neg();
            size -= 1;
        } else if typ & PLUS != 0 {
            sign = b'+';
            size -= 1;
        } else if typ & SPACE != 0 {
            sign = b' ';
            size -= 1;
        }
    }
    if typ & SPECIAL != 0 {
        if base == 16 {
            size -= 2;
        } else if base == 8 {
            size -= 1;
        }
    }
    let mut i: i32 = 0;
    let mut u = n as u32; // __do_div works on (unsigned long)
    if n == 0 {
        tmp[i as usize] = b'0';
        i += 1;
    } else {
        while u != 0 {
            let r = u % base as u32;
            u /= base as u32;
            tmp[i as usize] = DIGITS[r as usize] | locase;
            i += 1;
        }
    }
    if i > precision {
        precision = i;
    }
    size -= precision;
    // SAFETY: the caller's buffer is large enough, as for the C (same lengths written).
    unsafe {
        if typ & (ZEROPAD + LEFT) == 0 {
            // while (size-- > 0): the C also decrements on the failing test
            loop {
                let go = size > 0;
                size = size.wrapping_sub(1);
                if !go {
                    break;
                }
                *str = b' ';
                str = str.add(1);
            }
        }
        if sign != 0 {
            *str = sign;
            str = str.add(1);
        }
        if typ & SPECIAL != 0 {
            if base == 8 {
                *str = b'0';
                str = str.add(1);
            } else if base == 16 {
                *str = b'0';
                str = str.add(1);
                *str = b'X' | locase;
                str = str.add(1);
            }
        }
        if typ & LEFT == 0 {
            // while (size-- > 0)
            loop {
                let go = size > 0;
                size = size.wrapping_sub(1);
                if !go {
                    break;
                }
                *str = c;
                str = str.add(1);
            }
        }
        // while (i < precision--)
        loop {
            let go = i < precision;
            precision = precision.wrapping_sub(1);
            if !go {
                break;
            }
            *str = b'0';
            str = str.add(1);
        }
        // while (i-- > 0)
        loop {
            let go = i > 0;
            i -= 1;
            if !go {
                break;
            }
            *str = tmp[i as usize];
            str = str.add(1);
        }
        // while (size-- > 0)
        loop {
            let go = size > 0;
            size = size.wrapping_sub(1);
            if !go {
                break;
            }
            *str = b' ';
            str = str.add(1);
        }
    }
    str
}

unsafe fn do_vsprintf(buf: *mut u8, mut fmt: *const u8, args: &mut VaList<'_>) -> c_int {
    let mut str = buf;
    // SAFETY: fmt is NUL-terminated and args match it, as for the C.
    unsafe {
        while *fmt != 0 {
            if *fmt != b'%' {
                *str = *fmt;
                str = str.add(1);
                fmt = fmt.add(1);
                continue;
            }

            // process flags
            let mut flags: i32 = 0;
            loop {
                fmt = fmt.add(1); // this also skips first '%'
                match *fmt {
                    b'-' => flags |= LEFT,
                    b'+' => flags |= PLUS,
                    b' ' => flags |= SPACE,
                    b'#' => flags |= SPECIAL,
                    b'0' => flags |= ZEROPAD,
                    _ => break,
                }
            }

            // get field width
            let mut field_width: i32 = -1;
            if isdigit(*fmt) {
                field_width = skip_atoi(&mut fmt);
            } else if *fmt == b'*' {
                fmt = fmt.add(1);
                // it's the next argument
                field_width = args.next_arg::<i32>();
                if field_width < 0 {
                    field_width = field_width.wrapping_neg();
                    flags |= LEFT;
                }
            }

            // get the precision
            let mut precision: i32 = -1;
            if *fmt == b'.' {
                fmt = fmt.add(1);
                if isdigit(*fmt) {
                    precision = skip_atoi(&mut fmt);
                } else if *fmt == b'*' {
                    fmt = fmt.add(1);
                    // it's the next argument
                    precision = args.next_arg::<i32>();
                }
                if precision < 0 {
                    precision = 0;
                }
            }

            // get the conversion qualifier
            let mut qualifier: i32 = -1;
            if *fmt == b'h' || *fmt == b'l' || *fmt == b'L' {
                qualifier = *fmt as i32;
                fmt = fmt.add(1);
            }

            // default base
            let mut base: i32 = 10;

            match *fmt {
                b'c' => {
                    if flags & LEFT == 0 {
                        loop {
                            field_width = field_width.wrapping_sub(1);
                            if !(field_width > 0) {
                                break;
                            }
                            *str = b' ';
                            str = str.add(1);
                        }
                    }
                    *str = args.next_arg::<i32>() as u8;
                    str = str.add(1);
                    loop {
                        field_width = field_width.wrapping_sub(1);
                        if !(field_width > 0) {
                            break;
                        }
                        *str = b' ';
                        str = str.add(1);
                    }
                    fmt = fmt.add(1);
                    continue;
                }
                b's' => {
                    let mut s = args.next_arg::<*const u8>();
                    let len = strnlen(s as *const c_char, precision as usize) as i32;

                    if flags & LEFT == 0 {
                        // while (len < field_width--)
                        loop {
                            let go = len < field_width;
                            field_width = field_width.wrapping_sub(1);
                            if !go {
                                break;
                            }
                            *str = b' ';
                            str = str.add(1);
                        }
                    }
                    let mut i = 0;
                    while i < len {
                        *str = *s;
                        str = str.add(1);
                        s = s.add(1);
                        i += 1;
                    }
                    loop {
                        let go = len < field_width;
                        field_width = field_width.wrapping_sub(1);
                        if !go {
                            break;
                        }
                        *str = b' ';
                        str = str.add(1);
                    }
                    fmt = fmt.add(1);
                    continue;
                }
                b'p' => {
                    if field_width == -1 {
                        field_width = 2 * core::mem::size_of::<*const c_void>() as i32;
                        flags |= ZEROPAD;
                    }
                    str = number(str, args.next_arg::<*const c_void>() as usize as i32, 16, field_width, precision, flags);
                    fmt = fmt.add(1);
                    continue;
                }
                b'n' => {
                    // `long *` and `int *` are both 32-bit here
                    let ip = args.next_arg::<*mut i32>();
                    *ip = str.offset_from(buf) as i32;
                    fmt = fmt.add(1);
                    continue;
                }
                b'%' => {
                    *str = b'%';
                    str = str.add(1);
                    fmt = fmt.add(1);
                    continue;
                }
                // integer number formats - set up the flags and "break"
                b'o' => base = 8,
                b'x' => {
                    flags |= SMALL;
                    base = 16;
                }
                b'X' => base = 16,
                b'd' | b'i' => flags |= SIGN,
                b'u' => {}
                _ => {
                    *str = b'%';
                    str = str.add(1);
                    if *fmt != 0 {
                        *str = *fmt;
                        str = str.add(1);
                    } else {
                        fmt = fmt.sub(1);
                    }
                    fmt = fmt.add(1);
                    continue;
                }
            }
            let num: i32 = if qualifier == b'l' as i32 {
                args.next_arg::<u32>() as i32
            } else if qualifier == b'h' as i32 {
                let mut n = args.next_arg::<i32>() as u16 as u32 as i32; // (unsigned short)
                if flags & SIGN != 0 {
                    n = n as i16 as i32; // (short)
                }
                n
            } else if flags & SIGN != 0 {
                args.next_arg::<i32>()
            } else {
                args.next_arg::<u32>() as i32
            };
            str = number(str, num, base, field_width, precision, flags);
            fmt = fmt.add(1);
        }
        *str = 0;
        str.offset_from(buf) as c_int
    }
}

/// `int vsprintf(char *buf, const char *fmt, va_list args)`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf(buf: *mut c_char, fmt: *const c_char, mut args: VaList<'_>) -> c_int {
    // SAFETY: caller contract (as for the C).
    unsafe { do_vsprintf(buf as *mut u8, fmt as *const u8, &mut args) }
}

/// `int sprintf(char *buf, const char *fmt, ...)`.
#[no_mangle]
pub unsafe extern "C" fn sprintf(buf: *mut c_char, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: caller contract.
    unsafe { do_vsprintf(buf as *mut u8, fmt as *const u8, &mut args) }
}

/// `int printf(const char *fmt, ...)`.
#[no_mangle]
pub unsafe extern "C" fn printf(fmt: *const c_char, mut args: ...) -> c_int {
    // like the C's `char printf_buf[1024]`: uninitialised (vsprintf NUL-terminates it)
    let mut printf_buf = core::mem::MaybeUninit::<[u8; 1024]>::uninit();
    // SAFETY: caller contract; the C's 1024-byte buffer has the same limit.
    unsafe {
        let printed = do_vsprintf(printf_buf.as_mut_ptr() as *mut u8, fmt as *const u8, &mut args);
        puts(printf_buf.as_ptr() as *const c_char);
        printed
    }
}
