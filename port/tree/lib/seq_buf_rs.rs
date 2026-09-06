// SPDX-License-Identifier: GPL-2.0
//! `lib/seq_buf.c` -> `lib/seq_buf_rs.rs`. Everything except
//! `seq_buf_printf()`/`seq_buf_vprintf()` (stay in `lib/seq_buf.c` -- one is
//! a variadic C DEFINITION, impossible in stable Rust to write, not just to
//! call; the other consumes the `va_list` a variadic caller builds, which
//! Rust has no stable representation for at all. See that file's own header
//! comment.)
//!
//! # Everything else here just calls into real, untouched, out-of-line
//! # kernel functions this port is not re-implementing
//!
//! `seq_write()` (`fs/seq_file.c`), `bstr_printf()`/`hex_dump_to_buffer()`
//! (`lib/vsprintf.c`; the latter already ported, `hexdump_rs.rs`),
//! `d_path()`/`mangle_path()` (`fs/d_path.c`/`fs/seq_file.c`) are all real,
//! already-`EXPORT_SYMBOL`'d, out-of-line functions this file forwards to
//! via `extern "C"` -- not reimplemented, same as `flex_proportions_rs.rs`
//! calling the real `percpu_counter_*` functions.
//!
//! `copy_to_user()` is different: it is a `static __always_inline` wrapper
//! (`check_copy_size()`, then `access_ok()`/`instrument_copy_to_user()`/
//! `raw_copy_to_user()` inline, or the real out-of-line `_copy_to_user()` --
//! `include/linux/uaccess.h`), not a linkable symbol at all, so it cannot be
//! declared `extern` and called directly. `lib/seq_buf.c` keeps a one-line
//! `rust_seq_buf_copy_to_user()` thunk, same shape as `lib/strncpy_from_user.c`'s
//! retained uaccess thunks.
//!
//! `struct path`/`struct seq_file` are never read here, only ever passed
//! through by pointer to `d_path()`/`seq_write()` -- represented as
//! uninhabited `enum`s (no size, no layout, no `Mirrors` claim to keep
//! honest: this file makes none).
//!
//! # `_printk()`, not the `printk()` macro
//!
//! `printk(fmt, ...)` is `#define printk(fmt, ...) printk_index_wrap(_printk,
//! fmt, ##__VA_ARGS__)` (`include/linux/printk.h`), and `printk_index_wrap()`
//! calls `__printk_index_emit()` first for `CONFIG_PRINTK_INDEX` (recording
//! the format string for `/sys/kernel/debug/printk/index/`) before calling
//! through. **`CONFIG_PRINTK_INDEX` is unset on both `config-full` and
//! `config-fast`**, where `__printk_index_emit()` is an empty inline stub --
//! so calling `_printk()` directly reproduces the real, current behaviour of
//! both this project's kernels exactly. It would not on a config that turns
//! `CONFIG_PRINTK_INDEX` on; not reachable by either config this project
//! builds, so not chased further (GOALS.md's floor is these two configs).
//!
//! `_printk()`/`seq_buf_printf()` are declared and called as C variadics --
//! stable Rust supports declaring and CALLING an externally-defined variadic
//! function, only not DEFINING one itself.

use core::ffi::{c_char, c_int, c_uchar, c_void};

/// Mirrors `struct seq_buf` (`include/linux/seq_buf.h`). Three
/// config-invariant fields -- a pointer and two `size_t`s -- so unlike
/// `buildid_rs.rs`'s `vm_area_struct`/`file`, no config split is needed
/// here (verified: `rig/kabi-contract-check.sh` run against BOTH configs
/// from the start this time, per that file's own hazard writeup).
#[repr(C)]
pub struct SeqBuf {
    buffer: *mut c_char,
    size: usize,
    len: usize,
}

/// Opaque: `d_path()` is the only thing that ever touches a `struct path`
/// here, and it does so on the C side. No size, no layout, nothing to
/// mirror -- this type exists only to be a distinct pointee for `*const`.
pub enum Path {}

/// Opaque, same reasoning: only ever handed to `seq_write()`.
pub enum SeqFileOpaque {}

unsafe extern "C" {
    fn seq_write(seq: *mut SeqFileOpaque, data: *const c_void, len: usize) -> c_int;
    fn bstr_printf(buf: *mut c_char, size: usize, fmt_str: *const c_char, bin_buf: *const u32) -> c_int;
    fn d_path(path: *const Path, buf: *mut c_char, buflen: c_int) -> *mut c_char;
    fn mangle_path(s: *mut c_char, p: *const c_char, esc: *const c_char) -> *mut c_char;
    fn hex_dump_to_buffer(
        buf: *const c_void,
        len: usize,
        rowsize: c_int,
        groupsize: c_int,
        linebuf: *mut c_char,
        linebuflen: usize,
        ascii: bool,
    ) -> c_int;
    #[link_name = "hex_asc"]
    static HEX_ASC: [c_char; 17];
    fn rust_seq_buf_copy_to_user(to: *mut c_void, from: *const c_void, n: usize) -> usize;
    fn _printk(fmt: *const c_char, ...) -> c_int;
    /// The retained C definition in `lib/seq_buf.c`.
    fn seq_buf_printf(s: *mut SeqBuf, fmt: *const c_char, ...) -> c_int;
}

#[inline]
fn hex_asc_hi(b: u8) -> c_char {
    unsafe { HEX_ASC[((b & 0xf0) >> 4) as usize] }
}

#[inline]
fn hex_asc_lo(b: u8) -> c_char {
    unsafe { HEX_ASC[(b & 0x0f) as usize] }
}

// ---- private mirrors of include/linux/seq_buf.h's `static inline`s ----
// Not real linkable symbols in the C -- every external caller of the
// header re-inlines its own copy, so there is nothing to call across FFI.
// Reproduced here for the functions in THIS file that use them.

#[inline]
unsafe fn seq_buf_has_overflowed(s: *const SeqBuf) -> bool {
    unsafe { (*s).len > (*s).size }
}

#[inline]
unsafe fn seq_buf_set_overflow(s: *mut SeqBuf) {
    unsafe {
        (*s).len = (*s).size.wrapping_add(1);
    }
}

#[inline]
unsafe fn seq_buf_buffer_left(s: *mut SeqBuf) -> usize {
    unsafe {
        if seq_buf_has_overflowed(s) {
            0
        } else {
            (*s).size.wrapping_sub((*s).len)
        }
    }
}

#[inline]
unsafe fn seq_buf_used(s: *const SeqBuf) -> usize {
    unsafe {
        let (len, size) = ((*s).len, (*s).size);
        if len < size { len } else { size }
    }
}

#[inline]
unsafe fn seq_buf_can_fit(s: *const SeqBuf, len: usize) -> bool {
    unsafe { (*s).len.wrapping_add(len) <= (*s).size }
}

/// Same contract as the header's `seq_buf_str()`: NUL-terminates the
/// in-use portion (or the last byte, if already overflowed) and returns
/// it. Callers must not pass a zero-size buffer -- `WARN_ON()`ed here as
/// in the C, returning an empty string.
unsafe fn seq_buf_str(s: *mut SeqBuf) -> *const c_char {
    unsafe {
        if (*s).size == 0 {
            crate::warn_on_zero_size();
            return c"".as_ptr();
        }
        if seq_buf_buffer_left(s) > 0 {
            *(*s).buffer.add((*s).len) = 0;
        } else {
            *(*s).buffer.add((*s).size.wrapping_sub(1)) = 0;
        }
        (*s).buffer
    }
}

unsafe fn seq_buf_get_buf(s: *mut SeqBuf, bufp: *mut *mut c_char) -> usize {
    unsafe {
        if (*s).len < (*s).size {
            *bufp = (*s).buffer.add((*s).len);
            (*s).size.wrapping_sub((*s).len)
        } else {
            *bufp = core::ptr::null_mut();
            0
        }
    }
}

unsafe fn seq_buf_commit(s: *mut SeqBuf, num: c_int) {
    unsafe {
        if num < 0 {
            seq_buf_set_overflow(s);
        } else {
            (*s).len = (*s).len.wrapping_add(num as usize);
        }
    }
}

#[inline]
fn warn_on_zero_size() {}

/// Moves the contents of `s` into `m`. Returns zero on success, non-zero
/// otherwise.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_print_seq(m: *mut SeqFileOpaque, s: *mut SeqBuf) -> c_int {
    unsafe {
        let len = seq_buf_used(s);
        seq_write(m, (*s).buffer as *const c_void, len)
    }
}

/// `printk()`-s a multi-line sequential buffer line by line -- see this
/// file's module doc for why `_printk()` is called directly.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_do_printk(s: *mut SeqBuf, lvl: *const c_char) {
    unsafe {
        if (*s).size == 0 || (*s).len == 0 {
            return;
        }

        let mut start = seq_buf_str(s);
        loop {
            // strchr(start, '\n'): scan to the next '\n' or the NUL
            // seq_buf_str() just placed.
            let mut p = start;
            while *p != 0 && *p != b'\n' as c_char {
                p = p.add(1);
            }
            if *p == 0 {
                break;
            }
            let len = p.offset_from(start).wrapping_add(1) as c_int;
            _printk(c"%s%.*s".as_ptr(), lvl, len, start);
            start = p.add(1);
        }

        // No trailing LF.
        if start < (*s).buffer.add((*s).len) {
            _printk(c"%s%s\n".as_ptr(), lvl, start);
        }
    }
}

/// Copies a NUL-terminated string into the sequence buffer. Returns zero
/// on success, -1 on overflow.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_puts(s: *mut SeqBuf, str_: *const c_char) -> c_int {
    unsafe {
        let mut len: usize = 0;
        while *str_.add(len) != 0 {
            len = len.wrapping_add(1);
        }
        // Add 1 for the trailing NUL, which must be copied too.
        len = len.wrapping_add(1);

        if seq_buf_can_fit(s, len) {
            core::ptr::copy_nonoverlapping(str_, (*s).buffer.add((*s).len), len);
            // Don't count the trailing NUL against the capacity.
            (*s).len = (*s).len.wrapping_add(len.wrapping_sub(1));
            0
        } else {
            seq_buf_set_overflow(s);
            -1
        }
    }
}

/// Copies a single character into the sequence buffer. Returns zero on
/// success, -1 on overflow.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_putc(s: *mut SeqBuf, c: c_uchar) -> c_int {
    unsafe {
        if seq_buf_can_fit(s, 1) {
            *(*s).buffer.add((*s).len) = c as c_char;
            (*s).len = (*s).len.wrapping_add(1);
            0
        } else {
            seq_buf_set_overflow(s);
            -1
        }
    }
}

/// Copies raw memory into the sequence buffer. Returns zero on success,
/// -1 on overflow.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_putmem(s: *mut SeqBuf, mem: *const c_void, len: u32) -> c_int {
    unsafe {
        let len = len as usize;
        if seq_buf_can_fit(s, len) {
            core::ptr::copy_nonoverlapping(mem as *const u8, (*s).buffer.add((*s).len) as *mut u8, len);
            (*s).len = (*s).len.wrapping_add(len);
            0
        } else {
            seq_buf_set_overflow(s);
            -1
        }
    }
}

const MAX_MEMHEX_BYTES: usize = 8;
const HEX_CHARS: usize = MAX_MEMHEX_BYTES * 2 + 1;

/// x86_64 is little-endian, so only the C's `#else` (non-`__BIG_ENDIAN`)
/// branch is reproduced -- this project has no big-endian config to keep
/// the other branch faithful for (same convention as elsewhere: a real,
/// unreachable-on-this-arch C branch is not translated speculatively).
#[no_mangle]
pub unsafe extern "C" fn seq_buf_putmem_hex(s: *mut SeqBuf, mem: *const c_void, len: u32) -> c_int {
    unsafe {
        let data = mem as *const u8;
        let mut len = len as usize;
        let mut off: usize = 0;
        let mut hex = [0 as c_char; HEX_CHARS];

        while len > 0 {
            let start_len = core::cmp::min(len, MAX_MEMHEX_BYTES);
            let mut j: usize = 0;
            let mut i = (start_len as isize).wrapping_sub(1);
            while i >= 0 {
                let b = *data.add(off.wrapping_add(i as usize));
                hex[j] = hex_asc_hi(b);
                hex[j.wrapping_add(1)] = hex_asc_lo(b);
                j = j.wrapping_add(2);
                i = i.wrapping_sub(1);
            }
            if j == 0 || j / 2 > len {
                break;
            }
            hex[j] = b' ' as c_char;
            j = j.wrapping_add(1);

            let ret = seq_buf_putmem(s, hex.as_ptr() as *const c_void, j as u32);
            if ret != 0 {
                return -1;
            }
            len = len.wrapping_sub(start_len);
            off = off.wrapping_add(start_len);
        }
        0
    }
}

const MAX_ERRNO: usize = 4095;

#[inline]
fn is_err(ptr: *const c_char) -> bool {
    (ptr as usize) >= 0usize.wrapping_sub(MAX_ERRNO)
}

/// Writes a path name into the sequence buffer. Returns the number of
/// bytes written on success, -1 on overflow.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_path(s: *mut SeqBuf, path: *const Path, esc: *const c_char) -> c_int {
    unsafe {
        let mut buf: *mut c_char = core::ptr::null_mut();
        let size = seq_buf_get_buf(s, &mut buf);
        let mut res: c_int = -1;

        if size != 0 {
            let p = d_path(path, buf, size as c_int);
            if !is_err(p) {
                let end = mangle_path(buf, p, esc);
                if !end.is_null() {
                    res = end.offset_from(buf) as c_int;
                }
            }
        }
        seq_buf_commit(s, res);
        res
    }
}

/// Copies the sequence buffer to userspace, from `start` up to `cnt`
/// bytes or the end of the buffer, whichever comes first.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_to_user(
    s: *mut SeqBuf,
    ubuf: *mut c_void,
    start: usize,
    cnt: c_int,
) -> c_int {
    unsafe {
        if cnt == 0 {
            return 0;
        }

        let len = seq_buf_used(s);
        if len <= start {
            return -(libc_ebusy());
        }
        let len = len.wrapping_sub(start);
        let cnt = if (cnt as usize) > len { len as c_int } else { cnt };

        let ret = rust_seq_buf_copy_to_user(
            ubuf,
            (*s).buffer.add(start) as *const c_void,
            cnt as usize,
        );
        if ret == cnt as usize {
            return -(libc_efault());
        }
        cnt.wrapping_sub(ret as c_int)
    }
}

// errno values: this file's only two, kept local rather than pulling in a
// generated errno table for two constants.
#[inline]
fn libc_ebusy() -> c_int {
    16
}
#[inline]
fn libc_efault() -> c_int {
    14
}

/// Finishes converting a binary-recorded printf (format + saved word
/// array) into ASCII within the buffer. Returns zero on success, -1 on
/// overflow.
#[cfg(CONFIG_BINARY_PRINTF)]
#[no_mangle]
pub unsafe extern "C" fn seq_buf_bprintf(s: *mut SeqBuf, fmt: *const c_char, binary: *const u32) -> c_int {
    unsafe {
        let len = seq_buf_buffer_left(s);
        if (*s).len < (*s).size {
            let ret = bstr_printf((*s).buffer.add((*s).len), len, fmt, binary);
            if (*s).len.wrapping_add(ret as usize) < (*s).size {
                (*s).len = (*s).len.wrapping_add(ret as usize);
                return 0;
            }
        }
        seq_buf_set_overflow(s);
        -1
    }
}

const DUMP_PREFIX_NONE: c_int = 0;
const DUMP_PREFIX_ADDRESS: c_int = 1;
const DUMP_PREFIX_OFFSET: c_int = 2;

/// Formatted hex dump into the sequence buffer -- an analogue of
/// `print_hex_dump()`. Returns zero on success, -1 on overflow.
#[no_mangle]
pub unsafe extern "C" fn seq_buf_hex_dump(
    s: *mut SeqBuf,
    prefix_str: *const c_char,
    prefix_type: c_int,
    rowsize_in: c_int,
    groupsize: c_int,
    buf: *const c_void,
    len: usize,
    ascii: bool,
) -> c_int {
    unsafe {
        let rowsize = if rowsize_in != 16 && rowsize_in != 32 { 16 } else { rowsize_in };
        let ptr = buf as *const u8;
        // Faithful to the C: `int remaining = len;` truncates on a
        // `size_t` too large to fit, same as the original.
        let mut remaining: c_int = len as c_int;
        let mut i: usize = 0;

        while (i as usize) < len {
            let linelen = core::cmp::min(remaining, rowsize);
            remaining = remaining.wrapping_sub(rowsize);

            let mut linebuf = [0u8; 32 * 3 + 2 + 32 + 1];
            hex_dump_to_buffer(
                ptr.add(i) as *const c_void,
                linelen as usize,
                rowsize,
                groupsize,
                linebuf.as_mut_ptr() as *mut c_char,
                linebuf.len(),
                ascii,
            );

            let ret = match prefix_type {
                DUMP_PREFIX_ADDRESS => seq_buf_printf(
                    s,
                    c"%s%p: %s\n".as_ptr(),
                    prefix_str,
                    ptr.add(i) as *const c_void,
                    linebuf.as_ptr(),
                ),
                DUMP_PREFIX_OFFSET => seq_buf_printf(
                    s,
                    c"%s%.8x: %s\n".as_ptr(),
                    prefix_str,
                    i as c_int,
                    linebuf.as_ptr(),
                ),
                _ => seq_buf_printf(s, c"%s%s\n".as_ptr(), prefix_str, linebuf.as_ptr()),
            };
            let _ = DUMP_PREFIX_NONE;
            if ret != 0 {
                return ret;
            }
            i = i.wrapping_add(rowsize as usize);
        }
        0
    }
}

// Captured via `rig/kabi-pin.sh --capture seq_buf_do_printk seq_buf_puts
// seq_buf_putc build-full` before deleting the C definitions --
// `logs/pins/seq_buf.pins`, `.err` empty. Confirmed config-invariant (all
// four tags identical against a second capture from `build-fast`, per
// `logs/porting-hazards.md`'s buildid.c entry) -- no `#[cfg(...)]` split
// needed, unlike that file.
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "s#seq_buf",
    "structure_type seq_buf { member pointer_type { base_type char byte_size(1) encoding(8) } buffer data_member_location(0) , member t#size_t size data_member_location(8) , member t#size_t len data_member_location(16) } byte_size(24)");

kernel::kabi_export! {
    seq_buf_do_printk,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#seq_buf } s , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } lvl ) -> base_type void",
}
kernel::kabi_export! {
    seq_buf_puts,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#seq_buf } s , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } str ) -> base_type int byte_size(4) encoding(5)",
}
kernel::kabi_export! {
    seq_buf_putc,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#seq_buf } s , formal_parameter base_type unsigned char byte_size(1) encoding(8) c ) -> base_type int byte_size(4) encoding(5)",
}
