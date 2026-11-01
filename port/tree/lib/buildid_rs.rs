// SPDX-License-Identifier: GPL-2.0

//! ELF build-ID parsing -- the Rust behind `lib/buildid.c`.
//!
//! Replaces: `parse_build_id()`, `get_build_id_32()`, `get_build_id_64()`,
//! `__build_id_parse()`, and the four non-static, NOT-exported entry points
//! (`build_id_parse_nofault()`, `build_id_parse()`, `build_id_parse_file()`,
//! `build_id_parse_buf()`), plus `init_vmlinux_build_id()`/
//! `vmlinux_build_id`.
//!
//! # These four are NOT `EXPORT_SYMBOL` -- a prior version of this file
//! # wrongly claimed and pinned them as such
//!
//! `port/pristine/lib/buildid.c` has zero `EXPORT_SYMBOL` lines: all four
//! callers (`fs/proc/task_mmu.c`, `kernel/bpf/stackmap.c`,
//! `kernel/events/core.c`, `kernel/module/kallsyms.c`) are built directly
//! into `vmlinux`, never a module. An earlier version of this port
//! `kabi_export!`'d all four anyway and carried a ~460-line `kabi_rule!`
//! pin closure to support it (the recursive `s#vm_area_struct`/`s#file`
//! closure `kabi_export!`'s contract-verification needs) -- a real GOALS.md
//! boundary violation (the interface must match upstream's exported-symbol
//! set, not extend it), found by an independent from-scratch verification
//! pass (fedora-box-01, 2026-09-06) against a freshly-regenerated
//! crc-check baseline; the stale baseline this project had been checking
//! against predated this file and never caught it. Fixed by dropping all
//! four `kabi_export!`/`kabi_rule!` blocks entirely -- these functions stay
//! `#[no_mangle] pub unsafe extern "C" fn` (real, linkable, cross-file C
//! symbols, matching upstream's own non-static-but-unexported status) with
//! no CRC/MODVERSIONS contract at all, exactly like the C they replace.
//!
//! # `struct freader` and its I/O stay in C
//!
//! `freader_get_folio()`/`freader_fetch()` touch `struct file`/
//! `struct folio`/the page cache directly (`filemap_get_folio()`,
//! `kmap_local_folio()`, `secretmem_mapping()`, `__kernel_read()`) -- real
//! MM/VFS coupling, same reasoning as keeping the uaccess and
//! percpu_counter I/O layers in C for the other two hazard classes this
//! session (`logs/porting-hazards.md`). `freader_init_from_file()`/
//! `freader_init_from_mem()`/`freader_fetch()`/`freader_cleanup()`
//! (`lib/buildid.c`) are called here as ordinary `extern "C"` functions
//! over an opaque, 56-byte `Freader` -- verified against the live
//! `build-full` DWARF via `pahole -C freader`: `buf`(8)+`buf_sz`(4)+
//! `err`(4), then a union whose file-backed arm (`file`+`folio`+`addr`+
//! `folio_off`+`may_fault`, padded) is the larger of the two shapes at 40
//! bytes, for 56 total. Deliberately NOT `Mirrors`-annotated: this port
//! never reads or writes a single field of it, only allocates the right
//! amount of stack space and passes `&mut` to the retained C helpers, so
//! its contract is its SIZE, not its field layout (same reasoning as
//! `ratelimit_rs.rs`'s `RawSpinlockT`).
//!
//! # `struct vm_area_struct`/`struct file`: bindgen's copy, no pin needed
//!
//! `build_id_parse()`/`build_id_parse_nofault()` take a
//! `*mut vm_area_struct` and read exactly one field, `vm_file`.
//! `build_id_parse_file()` takes a `*mut file` directly. Both use
//! `kernel::bindings::{vm_area_struct, file}` -- bindgen's own,
//! automatically-regenerated-every-build copy of the real C definitions --
//! rather than a hand-written mirror struct, so this file's OWN spelling
//! of these types can never drift from what bindgen emits. Since none of
//! these four functions is `kabi_export!`'d (see above), no `kabi_rule!`
//! pin is needed for `vm_area_struct`/`file`'s recursive closure at all --
//! that closure only exists to satisfy `kabi_export!`'s CONTRACT STRING
//! type resolution, and there is no longer a `kabi_export!` here to
//! resolve for.
//!
//! # Arithmetic: promotion rules matched exactly, not approximated
//!
//! `parse_build_id()`'s `note_end - note_off` mixes a `u32` (`note_end`)
//! and a `loff_t`/`i64` (`note_off`) parameter; C's usual arithmetic
//! conversions promote the `u32` to `i64` (the higher-ranked type) for the
//! subtraction, and then the RESULT (signed) gets converted to `u64` when
//! compared against `sizeof(Elf32_Nhdr) + note_name_sz` (a `size_t`).  A
//! negative intermediate becomes a huge `u64` at that comparison, exactly
//! as it would in C -- reproduced with explicit `i64`/`u64` casts at each
//! step rather than staying in one type throughout, matching the C's own
//! two-step promotion, not just its net effect on well-formed input. Every
//! `check_add_overflow()` call is reproduced with an `i128` intermediate
//! (infinite-precision, matching `__builtin_add_overflow`'s own semantics
//! exactly) rather than `checked_add`/`wrapping_add` on the destination
//! type alone, since the three call sites mix operand types wider than
//! the destination.

use core::ffi::{c_int, c_uchar, c_void};
use kernel::bindings;

const BUILD_ID: u32 = 3;
const MAX_PHDR_CNT: u32 = 256;
const BUILD_ID_SIZE_MAX: u32 = 20;
const MAX_FREADER_BUF_SZ: usize = 64;

const SELFMAG: usize = 4;
const ELFMAG: [u8; SELFMAG] = *b"\x7fELF";
const EI_CLASS: usize = 4;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_NOTE: u32 = 4;

const NOTE_NAME: [u8; 4] = *b"GNU\0";
const NOTE_NAME_SZ: u32 = 4;

/// Mirrors `struct elf32_hdr` (`Elf32_Ehdr`) -- verified field-for-field
/// against `pahole -C elf32_hdr build-full/vmlinux`: 52 bytes, 14 members.
#[repr(C)]
struct Elf32Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// Mirrors `struct elf64_hdr` (`Elf64_Ehdr`) -- verified against
/// `pahole -C elf64_hdr build-full/vmlinux`: 64 bytes, 14 members.
#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// Mirrors `struct elf32_phdr` (`Elf32_Phdr`) -- verified against
/// `pahole -C elf32_phdr build-full/vmlinux`: 32 bytes, 8 members.
#[repr(C)]
struct Elf32Phdr {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

/// Mirrors `struct elf64_phdr` (`Elf64_Phdr`) -- verified against
/// `pahole -C elf64_phdr build-full/vmlinux`: 56 bytes, 8 members. Field
/// ORDER differs from the 32-bit shape (`p_flags` moves up next to
/// `p_type`) -- transcribed from the real header, not assumed parallel.
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Mirrors `struct elf32_note` (`Elf32_Nhdr`, shared verbatim by both
/// 32-bit and 64-bit ELF per the pristine C's own comment) -- verified
/// against `pahole -C elf32_note build-full/vmlinux`: 12 bytes, 3 members.
#[repr(C)]
struct Elf32Nhdr {
    n_namesz: u32,
    n_descsz: u32,
    n_type: u32,
}

const ELF32_NHDR_SZ: u32 = 12;

/// Opaque, sized mirror of `struct freader` -- see this file's module doc.
/// `pub` only because `parse_build_id()`/`get_build_id_32()`/
/// `get_build_id_64()` are (see their own doc comments for why); nothing
/// outside this crate can construct one or read a field.
#[repr(C, align(8))]
pub struct Freader {
    _opaque: [u8; 56],
}

impl Freader {
    const fn new() -> Self {
        Freader { _opaque: [0; 56] }
    }
}

// `bindings::file`/`bindings::vm_area_struct` (used below and in every
// `#[no_mangle]` entry point's signature) embed `lockdep_map`, which
// bindgen renders as a genuinely zero-field struct on this build
// (`CONFIG_LOCKDEP`/`CONFIG_DEBUG_LOCK_ALLOC` both off) -- the exact same
// shape `flex_proportions_rs.rs` found for `lock_class_key`. Rust's
// `improper_ctypes` lint flags any extern-fn signature that references a
// type containing a zero-field struct anywhere in its (possibly nested)
// definition, even when that type is only ever passed by pointer here and
// this file never touches the field itself. This is exactly what
// upstream Rust-for-Linux's own bindgen-derived code allows for the same
// reason.
#[allow(improper_ctypes)]
unsafe extern "C" {
    fn freader_init_from_file(
        r: *mut Freader,
        buf: *mut c_void,
        buf_sz: u32,
        file: *mut bindings::file,
        may_fault: bool,
    );
    fn freader_init_from_mem(r: *mut Freader, data: *const c_uchar, data_sz: u64);
    fn freader_fetch(r: *mut Freader, file_off: i64, sz: usize) -> *const c_void;
    fn freader_cleanup(r: *mut Freader);
    fn freader_get_err(r: *mut Freader) -> c_int;
}

/// `check_add_overflow(a, b, d)`: `__builtin_add_overflow` reproduced with
/// an `i128` intermediate (always enough precision for two `i64`/`u64`-or-
/// narrower operands), matching its "infinite-precision sum, then does it
/// fit the destination type" semantics exactly, rather than the DIFFERENT
/// question `checked_add` on a single fixed type would ask.
#[inline(always)]
fn add_overflows_u32(a: i128, b: i128, dst: &mut u32) -> bool {
    let sum = a + b;
    if sum < 0 || sum > u32::MAX as i128 {
        true
    } else {
        *dst = sum as u32;
        false
    }
}

#[inline(always)]
fn align4(x: u32) -> u32 {
    (x.wrapping_add(3)) & !3u32
}

/// `parse_build_id()`. `#[no_mangle]`, not `EXPORT_SYMBOL` -- not called
/// from outside this crate in the real kernel, only from `port/test/
/// buildid/`'s differential (`get_build_id_32()`/`get_build_id_64()` are
/// otherwise reachable only through the file-backed entry points, which
/// need real VFS/page-cache machinery the differential does not
/// simulate; exposing them directly lets the harness exercise them with
/// a memory-backed `Freader` instead, matching this project's established
/// "give an otherwise-unreachable-for-testing helper a real name" pattern
/// (`lib/dynamic_queue_limits.c`'s `__dql_completed_bug_on`,
/// `fprop_new_period_locked` earlier this session).
///
/// # Safety
///
/// `r` must be a valid, initialized `*mut Freader` (from
/// `freader_init_from_file()`/`freader_init_from_mem()`); `build_id` must
/// point to at least `BUILD_ID_SIZE_MAX` writable bytes; `size`, if
/// non-null, must be a valid `*mut u32`.
#[no_mangle]
pub unsafe extern "C" fn parse_build_id(
    r: *mut Freader,
    build_id: *mut u8,
    size: *mut u32,
    note_off: i64,
    note_size: u32,
) -> c_int {
    let mut note_end: u32 = 0;
    if add_overflows_u32(note_off as i128, note_size as i128, &mut note_end) {
        return -22; // -EINVAL
    }

    let mut note_off = note_off;
    loop {
        // `note_end - note_off`: note_off (i64) is the wider-ranked
        // operand, so the subtraction happens in i64; the RESULT then
        // promotes to u64 (size_t's rank) for the comparison against
        // `sizeof(Elf32_Nhdr) + note_name_sz` -- a negative i64 becomes a
        // huge u64 here, exactly as it would in C.
        let diff_i64 = (note_end as i64).wrapping_sub(note_off);
        let threshold: u64 = ELF32_NHDR_SZ as u64 + NOTE_NAME_SZ as u64;
        if (diff_i64 as u64) <= threshold {
            return -22; // -EINVAL
        }

        let nhdr = unsafe { freader_fetch(r, note_off, (ELF32_NHDR_SZ + NOTE_NAME_SZ) as usize) }
            as *const Elf32Nhdr;
        if nhdr.is_null() {
            return unsafe { freader_get_err(r) };
        }

        let name_sz = unsafe { core::ptr::read_volatile(&raw const (*nhdr).n_namesz) };
        let desc_sz = unsafe { core::ptr::read_volatile(&raw const (*nhdr).n_descsz) };

        let mut new_off: u32 = 0;
        let overflowed = add_overflows_u32(note_off as i128, ELF32_NHDR_SZ as i128, &mut new_off)
            || add_overflows_u32(new_off as i128, align4(name_sz) as i128, &mut new_off)
            || add_overflows_u32(new_off as i128, align4(desc_sz) as i128, &mut new_off)
            || new_off > note_end;
        if overflowed {
            return -22; // -EINVAL
        }

        let n_type = unsafe { core::ptr::read_volatile(&raw const (*nhdr).n_type) };
        let note_name_matches = name_sz == NOTE_NAME_SZ && {
            let data_ptr = unsafe { nhdr.add(1) } as *const u8;
            let mut eq = true;
            for i in 0..NOTE_NAME_SZ as usize {
                if unsafe { *data_ptr.add(i) } != NOTE_NAME[i] {
                    eq = false;
                    break;
                }
            }
            eq
        };

        if n_type == BUILD_ID && note_name_matches && desc_sz > 0 && desc_sz <= BUILD_ID_SIZE_MAX {
            // note_off + sizeof(Elf32_Nhdr) + ALIGN(note_name_sz, 4): the C
            // does this with plain `+`, not check_add_overflow -- by this
            // point `new_off` (computed via the SAME two additions, overflow-
            // checked above) already proves this fits, so a checked repeat
            // would be redundant; reproduced as an unchecked, matching
            // wrapping_add for exact parity, not a fresh checked_add that
            // could disagree with the C's own unchecked arithmetic here.
            let build_id_off = (note_off as u32)
                .wrapping_add(ELF32_NHDR_SZ)
                .wrapping_add(align4(NOTE_NAME_SZ));

            let data = unsafe { freader_fetch(r, build_id_off as i64, desc_sz as usize) };
            if data.is_null() {
                return unsafe { freader_get_err(r) };
            }

            unsafe {
                core::ptr::copy_nonoverlapping(data as *const u8, build_id, desc_sz as usize);
                core::ptr::write_bytes(
                    build_id.add(desc_sz as usize),
                    0,
                    BUILD_ID_SIZE_MAX.wrapping_sub(desc_sz) as usize,
                );
                if !size.is_null() {
                    *size = desc_sz;
                }
            }
            return 0;
        }

        note_off = new_off as i64;
    }
}

/// `get_build_id_32()`. Parse build ID from a 32-bit ELF. `#[no_mangle]`
/// for the same reason as `parse_build_id()`.
///
/// # Safety
/// Same as [`parse_build_id`].
#[no_mangle]
pub unsafe extern "C" fn get_build_id_32(r: *mut Freader, build_id: *mut u8, size: *mut u32) -> c_int {
    let ehdr = unsafe { freader_fetch(r, 0, core::mem::size_of::<Elf32Ehdr>()) } as *const Elf32Ehdr;
    if ehdr.is_null() {
        return unsafe { freader_get_err(r) };
    }

    // Subsequent freader_fetch() calls invalidate pointers, so remember
    // locally -- e_phnum (u16) zero-extends into the u32 local, matching
    // the C's implicit widening.
    let phnum_raw = unsafe { core::ptr::read_volatile(&raw const (*ehdr).e_phnum) };
    let phoff_raw = unsafe { core::ptr::read_volatile(&raw const (*ehdr).e_phoff) };
    let mut phnum: u32 = phnum_raw as u32;
    let phoff: u32 = phoff_raw;

    // Set upper bound on amount of segments (phdrs) we iterate.
    if phnum > MAX_PHDR_CNT {
        phnum = MAX_PHDR_CNT;
    }

    // `phoff + phnum * sizeof(Elf32_Phdr)`: sizeof() is size_t (u64 on
    // this platform), so phnum promotes to u64 for the multiply, then
    // phoff promotes to u64 for the add -- all in u64, matching C's usual
    // arithmetic conversions exactly.
    let phdr_sz = core::mem::size_of::<Elf32Phdr>() as u64;
    let sum = (phoff as u64).wrapping_add((phnum as u64).wrapping_mul(phdr_sz));
    if sum < phoff as u64 {
        return -22; // -EINVAL
    }

    for i in 0..phnum {
        let file_off = (phoff as u64).wrapping_add((i as u64).wrapping_mul(phdr_sz)) as i64;
        let phdr = unsafe { freader_fetch(r, file_off, phdr_sz as usize) } as *const Elf32Phdr;
        if phdr.is_null() {
            return unsafe { freader_get_err(r) };
        }

        // p_type is read plain, not READ_ONCE, matching the C exactly --
        // p_offset/p_filesz go through a volatile read, p_type does not.
        let p_type = unsafe { (*phdr).p_type };
        if p_type == PT_NOTE {
            let p_offset = unsafe { core::ptr::read_volatile(&raw const (*phdr).p_offset) };
            let p_filesz = unsafe { core::ptr::read_volatile(&raw const (*phdr).p_filesz) };
            if unsafe { parse_build_id(r, build_id, size, p_offset as i64, p_filesz) } == 0 {
                return 0;
            }
        }
    }
    -22 // -EINVAL
}

/// `get_build_id_64()`. Parse build ID from a 64-bit ELF. `#[no_mangle]`
/// for the same reason as `parse_build_id()`.
///
/// # Safety
/// Same as [`parse_build_id`].
#[no_mangle]
pub unsafe extern "C" fn get_build_id_64(r: *mut Freader, build_id: *mut u8, size: *mut u32) -> c_int {
    let ehdr = unsafe { freader_fetch(r, 0, core::mem::size_of::<Elf64Ehdr>()) } as *const Elf64Ehdr;
    if ehdr.is_null() {
        return unsafe { freader_get_err(r) };
    }

    let phnum_raw = unsafe { core::ptr::read_volatile(&raw const (*ehdr).e_phnum) };
    let phoff_raw = unsafe { core::ptr::read_volatile(&raw const (*ehdr).e_phoff) };
    let mut phnum: u32 = phnum_raw as u32;
    let phoff: u64 = phoff_raw;

    if phnum > MAX_PHDR_CNT {
        phnum = MAX_PHDR_CNT;
    }

    let phdr_sz = core::mem::size_of::<Elf64Phdr>() as u64;
    let sum = phoff.wrapping_add((phnum as u64).wrapping_mul(phdr_sz));
    if sum < phoff {
        return -22; // -EINVAL
    }

    for i in 0..phnum {
        let file_off = phoff.wrapping_add((i as u64).wrapping_mul(phdr_sz)) as i64;
        let phdr = unsafe { freader_fetch(r, file_off, phdr_sz as usize) } as *const Elf64Phdr;
        if phdr.is_null() {
            return unsafe { freader_get_err(r) };
        }

        let p_type = unsafe { (*phdr).p_type };
        if p_type == PT_NOTE {
            let p_offset = unsafe { core::ptr::read_volatile(&raw const (*phdr).p_offset) };
            let p_filesz = unsafe { core::ptr::read_volatile(&raw const (*phdr).p_filesz) };
            if unsafe { parse_build_id(r, build_id, size, p_offset as i64, p_filesz as u32) } == 0 {
                return 0;
            }
        }
    }
    -22 // -EINVAL
}

/// `__build_id_parse()`.
///
/// # Safety
/// `file` must be a valid, open `*mut bindings::file`; `build_id` must
/// point to at least `BUILD_ID_SIZE_MAX` writable bytes; `size`, if
/// non-null, must be a valid `*mut u32`.
unsafe fn __build_id_parse(
    file: *mut bindings::file,
    build_id: *mut u8,
    size: *mut u32,
    may_fault: bool,
) -> c_int {
    let mut r = Freader::new();
    let mut buf = [0u8; MAX_FREADER_BUF_SZ];

    unsafe {
        freader_init_from_file(
            &mut r,
            buf.as_mut_ptr() as *mut c_void,
            MAX_FREADER_BUF_SZ as u32,
            file,
            may_fault,
        )
    };

    // Fetch first 18 bytes of ELF header for checks (e_ident + e_type;
    // both header shapes agree on this much layout).
    let ehdr = unsafe {
        freader_fetch(
            &mut r,
            0,
            16 /* e_ident */ + core::mem::size_of::<u16>() /* e_type */,
        )
    } as *const Elf32Ehdr;

    let ret;
    if ehdr.is_null() {
        ret = unsafe { freader_get_err(&mut r) };
    } else {
        let e_ident = unsafe { (*ehdr).e_ident };
        let e_type = unsafe { (*ehdr).e_type };

        if e_ident[0..SELFMAG] != ELFMAG[..] {
            ret = -22; // -EINVAL
        } else if e_type != ET_EXEC && e_type != ET_DYN {
            ret = -22; // -EINVAL
        } else if e_ident[EI_CLASS] == ELFCLASS32 {
            ret = unsafe { get_build_id_32(&mut r, build_id, size) };
        } else if e_ident[EI_CLASS] == ELFCLASS64 {
            ret = unsafe { get_build_id_64(&mut r, build_id, size) };
        } else {
            ret = -22; // -EINVAL
        }
    }

    unsafe { freader_cleanup(&mut r) };
    ret
}

/// `build_id_parse_nofault()` -- Parse build ID of ELF file mapped to vma.
///
/// Assumes no page fault can be taken, so if relevant portions of ELF file
/// are not already paged in, fetching of build ID fails.
///
/// # Safety
///
/// `vma` must be a valid `*mut bindings::vm_area_struct`; `build_id` must
/// point to at least `BUILD_ID_SIZE_MAX` writable bytes; `size`, if
/// non-null, must be a valid `*mut u32` -- matching the C's own contract
/// exactly.
#[no_mangle]
pub unsafe extern "C" fn build_id_parse_nofault(
    vma: *mut bindings::vm_area_struct,
    build_id: *mut u8,
    size: *mut u32,
) -> c_int {
    let vm_file = unsafe { (*vma).vm_file };
    if vm_file.is_null() {
        return -22; // -EINVAL
    }
    unsafe { __build_id_parse(vm_file, build_id, size, false) }
}

/// `build_id_parse()` -- Parse build ID of ELF file mapped to VMA.
///
/// Assumes faultable context and can cause page faults to bring in file
/// data into page cache.
///
/// # Safety
/// Same as [`build_id_parse_nofault`].
#[no_mangle]
pub unsafe extern "C" fn build_id_parse(
    vma: *mut bindings::vm_area_struct,
    build_id: *mut u8,
    size: *mut u32,
) -> c_int {
    let vm_file = unsafe { (*vma).vm_file };
    if vm_file.is_null() {
        return -22; // -EINVAL
    }
    unsafe { __build_id_parse(vm_file, build_id, size, true) }
}

/// `build_id_parse_file()` -- Parse build ID of ELF file.
///
/// # Safety
/// `file` must be a valid, open `*mut bindings::file`; `build_id`/`size`
/// as in [`build_id_parse_nofault`].
#[no_mangle]
pub unsafe extern "C" fn build_id_parse_file(
    file: *mut bindings::file,
    build_id: *mut u8,
    size: *mut u32,
) -> c_int {
    unsafe { __build_id_parse(file, build_id, size, true) }
}

/// `build_id_parse_buf()` -- Get build ID from a buffer.
///
/// # Safety
/// `buf` must be valid for `buf_size` readable bytes; `build_id` must
/// point to at least `BUILD_ID_SIZE_MAX` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn build_id_parse_buf(
    buf: *const c_void,
    build_id: *mut u8,
    buf_size: u32,
) -> c_int {
    let mut r = Freader::new();
    unsafe { freader_init_from_mem(&mut r, buf as *const c_uchar, buf_size as u64) };
    let err = unsafe { parse_build_id(&mut r, build_id, core::ptr::null_mut(), 0, buf_size) };
    unsafe { freader_cleanup(&mut r) };
    err
}

/// `vmlinux_build_id[BUILD_ID_SIZE_MAX]`, `__ro_after_init`. Real,
/// linkable, unmangled name: read directly by other C files (not
/// EXPORT_SYMBOL, a plain `extern unsigned char vmlinux_build_id[]`
/// declaration in `include/linux/buildid.h`).
#[cfg(any(CONFIG_STACKTRACE_BUILD_ID, CONFIG_VMCORE_INFO))]
#[no_mangle]
#[link_section = ".data..ro_after_init"]
pub static mut vmlinux_build_id: [u8; BUILD_ID_SIZE_MAX as usize] = [0; BUILD_ID_SIZE_MAX as usize];

#[cfg(any(CONFIG_STACKTRACE_BUILD_ID, CONFIG_VMCORE_INFO))]
unsafe extern "C" {
    /// Linker-provided section boundaries -- addresses only, never read
    /// as data; see `init_vmlinux_build_id()`.
    static __start_notes: c_void;
    static __stop_notes: c_void;
}

/// `init_vmlinux_build_id()` -- Compute and stash the running kernel's
/// build ID.
///
/// # Safety
/// Called exactly once, at `__init` time, same as the C.
#[cfg(any(CONFIG_STACKTRACE_BUILD_ID, CONFIG_VMCORE_INFO))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn init_vmlinux_build_id() {
    let start = &raw const __start_notes as usize;
    let stop = &raw const __stop_notes as usize;
    let size = stop.wrapping_sub(start) as u32;

    unsafe {
        build_id_parse_buf(
            &raw const __start_notes as *const c_void,
            (&raw mut vmlinux_build_id) as *mut u8,
            size,
        );
    }
}

