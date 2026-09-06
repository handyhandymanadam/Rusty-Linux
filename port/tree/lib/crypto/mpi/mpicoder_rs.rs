// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI external-representation coder -- the Rust behind
//! `lib/crypto/mpi/mpicoder.c`.
//!
//! Ported from `lib/crypto/mpi/mpicoder.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpicoder.c
//!
//! # All six symbols are `EXPORT_SYMBOL_GPL`
//!
//! Pins captured via `rig/kabi-pin.sh --capture mpi_read_raw_data
//! mpi_read_from_buffer mpi_read_buffer mpi_get_buffer mpi_write_to_sgl
//! mpi_read_raw_from_sgl build-full` before this file replaced the C
//! (`logs/pins/mpicoder.pins`, `.err` empty).
//!
//! # A genuinely different shape from the rest of `lib/crypto/mpi/`
//!
//! Every other file in this pass is pure limb arithmetic. This one is
//! wire-format code: big-endian external representation, `kmalloc`/
//! `kfree` for a plain returned buffer (not an `MPI`), and the kernel's
//! scatterlist/`sg_mapping_iter` API for the two sgl-based entry points.
//!
//! # `struct scatterlist` stays fully opaque, `struct sg_mapping_iter` does not
//!
//! `struct scatterlist` has `#ifdef CONFIG_NEED_SG_DMA_LENGTH`/
//! `CONFIG_NEED_SG_DMA_FLAGS` fields (confirmed present in this build's
//! own captured DWARF, 32 bytes/6 members) -- but this file never reads
//! a field of it, only ever passes the pointer straight through to the
//! real `sg_nents_for_len()`/`sg_miter_start()`, so its Kconfig-dependent
//! layout is irrelevant here: `ScatterlistOpaque` is a zero-sized marker.
//! `struct sg_mapping_iter` (and its nested `struct sg_page_iter`) has
//! **no** conditional fields at all (checked directly against
//! `include/linux/scatterlist.h`), and this file DOES read `.length`/
//! `.addr`/`.consumed` directly, so `SgMappingIter` mirrors it exactly,
//! `#[repr(C)]`, matching the real layout field-for-field. `sg_miter_start`/
//! `_next`/`_stop`/`sg_nents_for_len` are ordinary (non-`static`) kernel
//! functions, not macros -- no retained-thunk needed for them.
//!
//! # `kmalloc`/`kfree` reuse the existing `mpiutil.c` thunk
//!
//! `mpi_get_buffer()`'s buffer is a plain `kmalloc()`ed allocation the
//! *caller* frees with an ordinary `kfree()` (its own doc comment: "Caller
//! must free the return string") -- not an `MPI`-wrapped allocation.
//! `rust_mpi_kmalloc`/`rust_mpi_kfree` (`mpiutil.c`'s retained thunk) are
//! transparent wrappers with no bookkeeping of their own, so a pointer
//! from `rust_mpi_kmalloc` is indistinguishable from one `kmalloc()`
//! itself returned, and remains valid for an external caller's plain
//! `kfree()` -- reusing them needed no new thunk.
//!
//! # `ERR_PTR` is a trivial `static inline`, reproduced directly
//!
//! `ERR_PTR(error)` in the real `include/linux/err.h` is `(void *) error`
//! -- a bare pointer-encode of a small negative `long`, no kernel
//! machinery involved. Reproduced as a private `err_ptr()` helper; the
//! bit pattern is identical to the C's, so `IS_ERR()`/`PTR_ERR()` on the
//! caller's side see the same encoding regardless of which language
//! produced it.
//!
//! # `sg_miter_next()` after an explicit `sg_miter_stop()`, in
//! # `mpi_read_raw_from_sgl()`, is intended usage, not a bug
//!
//! `sg_miter_next()`'s own implementation (`lib/scatterlist.c`) calls
//! `sg_miter_stop()` on itself first, unconditionally, before advancing --
//! so `sg_miter_stop()` is designed to be safe to call redundantly, and
//! does not rewind the iterator's own internal page-walk position
//! (`piter`). The C's own `mpi_read_raw_from_sgl()` uses exactly this:
//! the first loop peeks into the current page to count leading zero
//! bytes and sets `miter.consumed` to just that count before calling
//! `sg_miter_stop()`, so the *second* loop's `sg_miter_next()` calls
//! continue from the same (partially-consumed) page onward rather than
//! restarting the scatterlist from the beginning. Verified against the
//! real implementation before translating, not assumed.
//!
//! # `pr_info()` reproduced via the same `_printk()` call every other
//! # file's `KERN_INFO` message already uses
//!
//! No `pr_fmt()` override in the real file, so the format string is
//! exactly the literal passed to `pr_info()`, unprefixed.
//!
//! # `mpi_get_size()`/`count_lzeros()` are `static inline`/`static`,
//! # duplicated (or ported) accordingly
//!
//! `mpi_get_size()` is `static inline` in `include/linux/mpi.h` (a
//! different header from `mpi-internal.h`), reproduced as a private
//! helper per the usual convention. `count_lzeros()` is `static` in this
//! same C file (no external caller), so it becomes an ordinary private
//! Rust function, not something needing a real symbol.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;
const MAX_EXTERN_MPI_BITS: c_uint = 16384;
const BYTES_PER_MPI_LIMB: usize = 8;
const BITS_PER_LONG: u32 = 64;

const SG_MITER_ATOMIC: c_uint = 1 << 0;
const SG_MITER_TO_SG: c_uint = 1 << 1;
const SG_MITER_FROM_SG: c_uint = 1 << 2;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly
/// per file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct McGcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Nonzero if this value is negative.
    pub sign: c_int,
    /// Flag bits; not read by the functions in this file.
    pub flags: u32,
    /// The limb array itself.
    pub d: *mut c_ulong,
}

/// Opaque: `struct scatterlist` (`include/linux/scatterlist.h`). This
/// file never reads a field of it, only forwards the pointer -- see the
/// module doc comment for why its Kconfig-conditional fields don't
/// matter here.
#[repr(C)]
pub struct ScatterlistOpaque {
    _opaque: [u8; 0],
}

/// Mirrors `struct sg_page_iter` (`include/linux/scatterlist.h`) --
/// nested inside `SgMappingIter`. No conditional fields.
#[repr(C)]
pub struct SgPageIter {
    /// `sg` holding the page.
    pub sg: *mut ScatterlistOpaque,
    /// Page offset within the sg.
    pub sg_pgoffset: c_uint,
    /// Internal: remaining sg entries.
    pub __nents: c_uint,
    /// Internal: pages to advance at the next step.
    pub __pg_advance: c_int,
}

/// Mirrors `struct sg_mapping_iter` (`include/linux/scatterlist.h`).
/// Layout-exact, `#[repr(C)]`: this file reads `.length`/`.addr`/
/// `.consumed` directly and passes `&mut` of a stack-local instance to
/// the real `sg_miter_start()`/`_next()`/`_stop()`. No conditional
/// fields anywhere in the real struct or its nested `sg_page_iter`.
#[repr(C)]
pub struct SgMappingIter {
    /// Currently mapped page (opaque `struct page *`; never dereferenced
    /// here, only round-tripped through the real sg_miter_* functions).
    pub page: *mut c_void,
    /// Pointer to the mapped area.
    pub addr: *mut c_void,
    /// Length of the mapped area.
    pub length: usize,
    /// Number of consumed bytes.
    pub consumed: usize,
    /// Page iterator.
    pub piter: SgPageIter,
    /// Internal: offset within page.
    pub __offset: c_uint,
    /// Internal: remaining bytes on page.
    pub __remaining: c_uint,
    /// Internal: flags.
    pub __flags: c_uint,
}

unsafe extern "C" {
    fn mpi_alloc(nlimbs: c_uint) -> *mut McGcryMpi;
    fn rust_mpi_kmalloc(len: usize) -> *mut c_void;
    fn rust_mpi_kfree(p: *mut c_void);
    fn _printk(fmt: *const c_char, ...) -> c_int;
    fn sg_miter_start(miter: *mut SgMappingIter, sgl: *mut ScatterlistOpaque, nents: c_uint, flags: c_uint);
    fn sg_miter_next(miter: *mut SgMappingIter) -> bool;
    fn sg_miter_stop(miter: *mut SgMappingIter);
    fn sg_nents_for_len(sg: *mut ScatterlistOpaque, len: u64) -> c_int;
}

fn count_leading_zeros(x: c_ulong) -> u32 {
    x.leading_zeros()
}

/// `ERR_PTR(error)` (`include/linux/err.h`, `static __always_inline`):
/// `(void *) error`. See the module doc comment.
fn err_ptr(error: c_int) -> *mut c_void {
    error as isize as *mut c_void
}

/// `mpi_get_size()` (`include/linux/mpi.h`, `static inline`).
///
/// # Safety
/// `a` valid.
unsafe fn mpi_get_size(a: *mut McGcryMpi) -> c_uint {
    // SAFETY: caller guarantees `a` valid.
    unsafe { (*a).nlimbs as c_uint * BYTES_PER_MPI_LIMB as c_uint }
}

/// `count_lzeros()` (`static` in the real file; no external caller).
///
/// # Safety
/// `a` valid.
unsafe fn count_lzeros(a: *mut McGcryMpi) -> c_int {
    let mut lzeros: c_int = 0;
    // SAFETY: caller guarantees `a` valid.
    let mut i = unsafe { (*a).nlimbs } - 1;
    while i >= 0 {
        // SAFETY: `i` in `0..nlimbs`.
        let alimb = unsafe { *(*a).d.add(i as usize) };
        if alimb == 0 {
            lzeros += BYTES_PER_MPI_LIMB as c_int;
        } else {
            lzeros += (count_leading_zeros(alimb) / 8) as c_int;
            break;
        }
        i -= 1;
    }
    lzeros
}

kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#uint8_t",
    "typedef_type uint8_t { t#u8 }");
kernel::kabi_rule!("type_string", "s#scatterlist",
    "structure_type scatterlist { member base_type unsigned long byte_size(8) encoding(7) page_link data_member_location(0) , member base_type unsigned int byte_size(4) encoding(7) offset data_member_location(8) , member base_type unsigned int byte_size(4) encoding(7) length data_member_location(12) , member t#dma_addr_t dma_address data_member_location(16) , member base_type unsigned int byte_size(4) encoding(7) dma_length data_member_location(24) , member base_type unsigned int byte_size(4) encoding(7) dma_flags data_member_location(28) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#dma_addr_t",
    "typedef_type dma_addr_t { t#u64 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");

kernel::kabi_export! {
    mpi_read_raw_data,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } xbuffer , formal_parameter t#size_t nbytes ) -> t#MPI",
}

/// `mpi_read_raw_data()` -- read a raw big-endian byte stream as a
/// positive integer.
///
/// # Safety
/// `xbuffer` readable for `nbytes_in` bytes.
#[no_mangle]
pub unsafe extern "C" fn mpi_read_raw_data(xbuffer: *const c_void, nbytes_in: usize) -> *mut McGcryMpi {
    let mut buffer = xbuffer as *const u8;
    let mut nbytes = nbytes_in;

    // SAFETY: caller guarantees `nbytes_in` bytes readable at `xbuffer`.
    while nbytes > 0 && unsafe { *buffer } == 0 {
        buffer = unsafe { buffer.add(1) };
        nbytes -= 1;
    }

    let mut nbits = (nbytes as u64 * 8) as c_uint;
    if nbits > MAX_EXTERN_MPI_BITS {
        unsafe { _printk(c"\x016MPI: mpi too large (%u bits)\n".as_ptr(), nbits) };
        return core::ptr::null_mut();
    }
    if nbytes > 0 {
        // SAFETY: `nbytes > 0`, so `buffer[0]` is valid.
        let b0 = unsafe { *buffer } as c_ulong;
        nbits -= count_leading_zeros(b0) - (BITS_PER_LONG - 8);
    }

    let nlimbs = ((nbytes + BYTES_PER_MPI_LIMB - 1) / BYTES_PER_MPI_LIMB) as c_uint;
    // SAFETY: FFI call; `mpi_alloc` has no preconditions beyond its own.
    let val = unsafe { mpi_alloc(nlimbs) };
    if val.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `val` freshly allocated, non-null.
    unsafe {
        (*val).nbits = nbits as c_int;
        (*val).sign = 0;
        (*val).nlimbs = nlimbs as c_int;
    }

    if nbytes > 0 {
        let mut i = (BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB) % BYTES_PER_MPI_LIMB;
        let mut j = nlimbs as usize;
        while j > 0 {
            let mut a: c_ulong = 0;
            while i < BYTES_PER_MPI_LIMB {
                a <<= 8;
                // SAFETY: still within the caller's original `nbytes_in`
                // bytes -- the total number of bytes consumed across
                // both loops here equals `nbytes`, matching the C's own
                // invariant (`j` limbs of `BYTES_PER_MPI_LIMB` bytes
                // each, minus the skip on the first iteration).
                a |= unsafe { *buffer } as c_ulong;
                buffer = unsafe { buffer.add(1) };
                i += 1;
            }
            i = 0;
            // SAFETY: `val->d` writable for `nlimbs` limbs; `j - 1` valid.
            unsafe { *(*val).d.add(j - 1) = a };
            j -= 1;
        }
    }
    val
}

kernel::kabi_export! {
    mpi_read_from_buffer,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } xbuffer , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } ret_nread ) -> t#MPI",
}

/// `mpi_read_from_buffer()` -- read a 2-byte-bit-length-prefixed MPI.
///
/// # Safety
/// `xbuffer` readable for `*ret_nread` bytes; `ret_nread` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_read_from_buffer(xbuffer: *const c_void, ret_nread: *mut c_uint) -> *mut McGcryMpi {
    // SAFETY: caller guarantees `ret_nread` valid.
    if unsafe { *ret_nread } < 2 {
        return err_ptr(-EINVAL) as *mut McGcryMpi;
    }
    let buffer = xbuffer as *const u8;
    // SAFETY: `*ret_nread >= 2`, so the first two bytes are readable.
    let nbits = unsafe { ((*buffer as c_uint) << 8) | (*buffer.add(1) as c_uint) };

    if nbits > MAX_EXTERN_MPI_BITS {
        unsafe { _printk(c"\x016MPI: mpi too large (%u bits)\n".as_ptr(), nbits) };
        return err_ptr(-EINVAL) as *mut McGcryMpi;
    }

    let nbytes = nbits.div_ceil(8);
    // SAFETY: `ret_nread` valid.
    if nbytes + 2 > unsafe { *ret_nread } {
        unsafe {
            _printk(
                c"\x016MPI: mpi larger than buffer nbytes=%u ret_nread=%u\n".as_ptr(),
                nbytes,
                *ret_nread,
            )
        };
        return err_ptr(-EINVAL) as *mut McGcryMpi;
    }

    // SAFETY: `buffer + 2` readable for `nbytes` bytes, just checked.
    let val = unsafe { mpi_read_raw_data(buffer.add(2) as *const c_void, nbytes as usize) };
    if val.is_null() {
        return err_ptr(-ENOMEM) as *mut McGcryMpi;
    }

    // SAFETY: `ret_nread` valid.
    unsafe { *ret_nread = nbytes + 2 };
    val
}

kernel::kabi_export! {
    mpi_read_buffer,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a , formal_parameter pointer_type { t#uint8_t } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) buf_len , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } nbytes , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } sign ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_read_buffer()` -- read `a` into a caller-provided buffer, msb
/// first.
///
/// # Safety
/// `a` valid; `buf` writable for `buf_len` bytes if non-null; `nbytes`,
/// `sign` valid if non-null.
#[no_mangle]
pub unsafe extern "C" fn mpi_read_buffer(
    a: *mut McGcryMpi,
    buf: *mut u8,
    buf_len: c_uint,
    nbytes: *mut c_uint,
    sign: *mut c_int,
) -> c_int {
    if buf.is_null() || nbytes.is_null() {
        return -EINVAL;
    }

    if !sign.is_null() {
        // SAFETY: `a`, `sign` valid.
        unsafe { *sign = (*a).sign };
    }

    // SAFETY: `a` valid.
    let n = unsafe { mpi_get_size(a) };
    let lzeros = unsafe { count_lzeros(a) } as c_uint;

    if buf_len < n - lzeros {
        // SAFETY: `nbytes` valid.
        unsafe { *nbytes = n - lzeros };
        return -EOVERFLOW;
    }

    let mut p = buf;
    // SAFETY: `nbytes` valid.
    unsafe { *nbytes = n - lzeros };

    // SAFETY: `a` valid.
    let mut i = unsafe { (*a).nlimbs } - 1 - (lzeros / BYTES_PER_MPI_LIMB as c_uint) as c_int;
    let mut lzeros = lzeros % BYTES_PER_MPI_LIMB as c_uint;
    while i >= 0 {
        // SAFETY: `a->d` readable at index `i`.
        let alimb = unsafe { *(*a).d.add(i as usize) }.to_be_bytes();
        let take = BYTES_PER_MPI_LIMB - lzeros as usize;
        // SAFETY: `p` writable for `take` bytes (the `buf_len` check
        // above guarantees the total across all iterations fits);
        // `alimb` is exactly `BYTES_PER_MPI_LIMB` bytes, `lzeros` of
        // which are skipped from the front, matching the C's
        // `(u8 *)&alimb + lzeros` pointer offset.
        unsafe {
            core::ptr::copy_nonoverlapping(alimb.as_ptr().add(lzeros as usize), p, take);
            p = p.add(take);
        }
        lzeros = 0;
        i -= 1;
    }
    0
}

kernel::kabi_export! {
    mpi_get_buffer,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } nbytes , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } sign ) -> pointer_type { base_type void }",
}

/// `mpi_get_buffer()` -- allocate and return a buffer with `a`'s value,
/// msb first. Caller must free the result with a plain `kfree()`.
///
/// # Safety
/// `a` valid; `sign` valid if non-null.
#[no_mangle]
pub unsafe extern "C" fn mpi_get_buffer(a: *mut McGcryMpi, nbytes: *mut c_uint, sign: *mut c_int) -> *mut c_void {
    if nbytes.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `a` valid.
    let mut n = unsafe { mpi_get_size(a) };
    if n == 0 {
        n += 1;
    }

    // SAFETY: allocating a fresh `n`-byte buffer.
    let buf = unsafe { rust_mpi_kmalloc(n as usize) };
    if buf.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `buf` writable for `n` bytes, `a` valid, `nbytes` valid.
    let ret = unsafe { mpi_read_buffer(a, buf as *mut u8, n, nbytes, sign) };
    if ret != 0 {
        // SAFETY: `buf` was allocated just above.
        unsafe { rust_mpi_kfree(buf) };
        return core::ptr::null_mut();
    }
    buf
}

kernel::kabi_export! {
    mpi_write_to_sgl,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a , formal_parameter pointer_type { s#scatterlist } sgl , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbytes , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } sign ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_write_to_sgl()` -- write `a`'s value into a scatterlist, msb
/// first, zero-padded to `nbytes`.
///
/// # Safety
/// `a` valid; `sgl` a valid scatterlist covering at least `nbytes`
/// bytes; `sign` valid if non-null.
#[no_mangle]
pub unsafe extern "C" fn mpi_write_to_sgl(
    a: *mut McGcryMpi,
    sgl: *mut ScatterlistOpaque,
    mut nbytes: c_uint,
    sign: *mut c_int,
) -> c_int {
    if !sign.is_null() {
        // SAFETY: `a`, `sign` valid.
        unsafe { *sign = (*a).sign };
    }

    // SAFETY: `a` valid.
    let n = unsafe { mpi_get_size(a) };
    if nbytes < n {
        return -EOVERFLOW;
    }

    // SAFETY: FFI call.
    let nents = unsafe { sg_nents_for_len(sgl, nbytes as u64) };
    if nents < 0 {
        return -EINVAL;
    }

    let mut miter = SgMappingIter {
        page: core::ptr::null_mut(),
        addr: core::ptr::null_mut(),
        length: 0,
        consumed: 0,
        piter: SgPageIter { sg: core::ptr::null_mut(), sg_pgoffset: 0, __nents: 0, __pg_advance: 0 },
        __offset: 0,
        __remaining: 0,
        __flags: 0,
    };
    // SAFETY: `miter` freshly initialized, `sgl` valid for `nents` entries.
    unsafe {
        sg_miter_start(&mut miter, sgl, nents as c_uint, SG_MITER_ATOMIC | SG_MITER_TO_SG);
        sg_miter_next(&mut miter);
    }
    let mut buf_len = miter.length;
    let mut p2 = miter.addr as *mut u8;

    while nbytes > n {
        let i = core::cmp::min((nbytes - n) as usize, buf_len);
        // SAFETY: `p2` writable for `buf_len` bytes, `i <= buf_len`.
        unsafe { core::ptr::write_bytes(p2, 0, i) };
        p2 = unsafe { p2.add(i) };
        nbytes -= i as c_uint;

        buf_len -= i;
        if buf_len == 0 {
            // SAFETY: `miter` valid.
            unsafe { sg_miter_next(&mut miter) };
            buf_len = miter.length;
            p2 = miter.addr as *mut u8;
        }
    }

    // SAFETY: `a` valid.
    let mut i = unsafe { (*a).nlimbs } - 1;
    while i >= 0 {
        // SAFETY: `a->d` readable at index `i`.
        let av = unsafe { *(*a).d.add(i as usize) };
        let alimb = if av != 0 { av.to_be_bytes() } else { [0u8; 8] };
        let mut p = 0usize;

        while p < alimb.len() {
            // SAFETY: `p2` writable (the `nbytes >= n` check above,
            // together with the sgl covering `nbytes` bytes, guarantees
            // room for the whole value).
            unsafe { *p2 = alimb[p] };
            p2 = unsafe { p2.add(1) };
            p += 1;
            buf_len -= 1;
            if buf_len == 0 {
                // SAFETY: `miter` valid.
                unsafe { sg_miter_next(&mut miter) };
                buf_len = miter.length;
                p2 = miter.addr as *mut u8;
            }
        }
        i -= 1;
    }

    // SAFETY: `miter` valid, started above.
    unsafe { sg_miter_stop(&mut miter) };
    0
}

kernel::kabi_export! {
    mpi_read_raw_from_sgl,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#scatterlist } sgl , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbytes ) -> t#MPI",
}

/// `mpi_read_raw_from_sgl()` -- allocate an MPI and populate it from a
/// scatterlist, msb first. See the module doc comment for why the
/// second `sg_miter_next()` loop, after an explicit `sg_miter_stop()`,
/// is intended behavior.
///
/// # Safety
/// `sgl` a valid scatterlist covering at least `nbytes` bytes.
#[no_mangle]
pub unsafe extern "C" fn mpi_read_raw_from_sgl(sgl: *mut ScatterlistOpaque, mut nbytes: c_uint) -> *mut McGcryMpi {
    let ents = unsafe { sg_nents_for_len(sgl, nbytes as u64) };
    if ents < 0 {
        return core::ptr::null_mut();
    }

    let mut miter = SgMappingIter {
        page: core::ptr::null_mut(),
        addr: core::ptr::null_mut(),
        length: 0,
        consumed: 0,
        piter: SgPageIter { sg: core::ptr::null_mut(), sg_pgoffset: 0, __nents: 0, __pg_advance: 0 },
        __offset: 0,
        __remaining: 0,
        __flags: 0,
    };
    // SAFETY: `miter` freshly initialized, `sgl` valid for `ents` entries.
    unsafe { sg_miter_start(&mut miter, sgl, ents as c_uint, SG_MITER_ATOMIC | SG_MITER_FROM_SG) };

    let mut lzeros: c_uint = 0;
    let mut len: usize = 0;
    let mut buff: *const u8 = core::ptr::null();
    while nbytes > 0 {
        while len != 0 {
            // SAFETY: `len != 0` means `buff` points at a valid byte
            // (the invariant `sg_miter_next` establishes for `addr`).
            if unsafe { *buff } != 0 || lzeros >= nbytes {
                break;
            }
            lzeros += 1;
            len -= 1;
            buff = unsafe { buff.add(1) };
        }

        if len != 0 && unsafe { *buff } != 0 {
            break;
        }

        // SAFETY: `miter` valid.
        unsafe { sg_miter_next(&mut miter) };
        buff = miter.addr as *const u8;
        len = miter.length;

        nbytes -= lzeros;
        lzeros = 0;
    }

    miter.consumed = lzeros as usize;

    nbytes -= lzeros;
    let mut nbits = nbytes * 8;
    if nbits > MAX_EXTERN_MPI_BITS {
        // SAFETY: `miter` valid, started above.
        unsafe { sg_miter_stop(&mut miter) };
        unsafe { _printk(c"\x016MPI: mpi too large (%u bits)\n".as_ptr(), nbits) };
        return core::ptr::null_mut();
    }

    if nbytes > 0 {
        // SAFETY: `nbytes > 0` here implies the loop above left `buff`
        // pointing at a real, non-zero byte (the break conditions both
        // require it).
        let b0 = unsafe { *buff } as c_ulong;
        nbits -= count_leading_zeros(b0) - (BITS_PER_LONG - 8);
    }

    // SAFETY: `miter` valid.
    unsafe { sg_miter_stop(&mut miter) };

    let nlimbs = nbytes.div_ceil(BYTES_PER_MPI_LIMB as c_uint);
    // SAFETY: FFI call.
    let val = unsafe { mpi_alloc(nlimbs) };
    if val.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `val` freshly allocated, non-null.
    unsafe {
        (*val).nbits = nbits as c_int;
        (*val).sign = 0;
        (*val).nlimbs = nlimbs as c_int;
    }

    if nbytes == 0 {
        return val;
    }

    let mut j = (nlimbs - 1) as isize;
    let mut a: c_ulong = 0;
    let mut z = (BYTES_PER_MPI_LIMB as c_uint - nbytes % BYTES_PER_MPI_LIMB as c_uint) % BYTES_PER_MPI_LIMB as c_uint;

    // SAFETY: `miter` valid (stopped above, but sg_miter_next() safely
    // resumes it -- see the module doc comment).
    while unsafe { sg_miter_next(&mut miter) } {
        buff = miter.addr as *const u8;
        let this_len = core::cmp::min(miter.length, nbytes as usize);
        nbytes -= this_len as c_uint;

        let mut x: usize = 0;
        while x < this_len {
            a <<= 8;
            // SAFETY: `x < this_len <= miter.length`, so `buff` is
            // readable here.
            a |= unsafe { *buff } as c_ulong;
            buff = unsafe { buff.add(1) };
            if (z + x as c_uint + 1) % BYTES_PER_MPI_LIMB as c_uint == 0 {
                // SAFETY: `val->d` writable for `nlimbs` limbs, `j >= 0`
                // by the same accounting the C relies on.
                unsafe { *(*val).d.offset(j) = a };
                j -= 1;
                a = 0;
            }
            x += 1;
        }
        z += x as c_uint;
    }

    val
}
