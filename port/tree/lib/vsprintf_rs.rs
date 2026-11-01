// SPDX-License-Identifier: GPL-2.0-only

//! The buffer-formatting core of `lib/vsprintf.c` -- the Rust behind the
//! part of this file that has no `va_list` dependency.
//!
//! Replaces (from `lib/vsprintf.c`): `format_decode`, `number`,
//! `special_hex_number`, `move_right`, `widen_string`, `string_nocheck`,
//! `err_ptr`, `error_string`, `check_pointer_msg`, `check_pointer`, `string`,
//! `pointer_string`, `__ptr_to_hashval`, `ptr_to_hashval`, `default_pointer`,
//! `symbol_string`, `hex_range`, `resource_string`, `range_string`,
//! `resource_or_range`, `hex_string`, `bitmap_string`, `bitmap_list_string`,
//! `mac_address_string`, `ip4_string`, `ip6_compressed_string`,
//! `ip6_string`, `ip6_addr_string[_sa]`, `ip4_addr_string[_sa]`,
//! `ip_addr_string`, `escaped_string`, `uuid_string`, `netdev_bits`,
//! `fourcc_string`, `address_val`, `format_flags`, `flags_string` (the
//! `g`/`v` cases only, see below), `pointer`, `bstr_printf`, `spec_flag`,
//! `set_field_width`, `set_precision`, `convert_num_spec`, `decpair`,
//! `put_dec_trunc8`, `put_dec_full8`, `put_dec` (the `BITS_PER_LONG == 64`
//! arm only), `num_to_str`, `restricted_pointer` (the `%pK` seam, split
//! into a pure `restricted_pointer_decision` and an impure wrapper -- see
//! below).
//!
//! # Survey and verification plan
//!
//! Both were reviewed by rusty-linux-e6 and an adversary pass before any of
//! this was written (two rounds; see the peer messages this session, not
//! reproduced here). The two load-bearing conclusions that shape this
//! file's structure:
//!
//! 1. **`va_list` cannot reach this crate on stable Rust, and it doesn't
//!    need to.** `core::ffi::VaList`/`VaArgSafe` are `#[unstable(feature =
//!    "c_variadic", ...)]` on the pinned 1.98.0 toolchain (verified against
//!    that toolchain's own `core/src/ffi/va_list.rs`), and `c_variadic` is
//!    not in `scripts/Makefile.build`'s `rust_allowed_features`. The C's own
//!    `vbin_printf()`/`bstr_printf()` split already proves the fix:
//!    `vbin_printf()` does the one-time `va_arg()` extraction into a flat
//!    `u32 *bin_buf`, and `bstr_printf()` reads that buffer with plain
//!    pointer arithmetic -- no `va_list` at all -- while running the
//!    IDENTICAL `format_decode()`-driven dispatch `vsnprintf()` uses. So
//!    `vsnprintf()`/`vbin_printf()`/`vsscanf()` (the only three functions in
//!    this file that touch `va_arg`) stay C, as thin entry thunks calling
//!    into this crate; everything else moves here directly.
//!
//! 2. **`pointer()`'s own differential is NOT reachable through
//!    `bstr_printf()`, for most of the `%p` family.** Read directly out of
//!    `vbin_printf()`'s packing switch: only `S`/`s`/`x`/`K`/`e` (and a bare
//!    `%p`) are deferred (`save_arg(void *)`, the raw pointer stored
//!    unprocessed); every other alnum suffix calls `pointer()` DURING
//!    packing and stores the finished, already-formatted string --
//!    `bstr_printf()`'s own comment says so: "Pointer dereference was
//!    already processed". A `bstr_printf()`-shaped differential over that
//!    majority would compare two `memcpy()`s of bytes the TEST driver
//!    itself produced by calling `pointer()` during packing -- passing no
//!    matter what this crate's `pointer()` does. `port/test/vsprintf/`
//!    therefore differentially tests `pointer()` directly (its own
//!    signature, no `bin_buf`, no `va_list`) for the full `%p` corpus, and
//!    `bstr_printf()` separately for `format_decode`/`number`/`string` plus
//!    the 5 genuinely deferred rows.
//!
//! # Scope actually landed vs. deferred to a follow-up
//!
//! Given the width of the `%p` family and the very different external
//! subsystems six of its rows reach into, this pass lands the dispatch core
//! plus every `%p` row whose data is either a flat byte buffer or a
//! 1-2-field POD struct this file already needs to mirror faithfully
//! (`resource`/`range`). Six rows stay `extern "C"` calls into the retained
//! C file for a follow-up, same "separate task, not a shortcut" treatment
//! `vsscanf`/`sscanf` already got in the survey: `%pd`/`%pD`/`%pg`
//! (`dentry`/`file`/`block_device` -- dcache and block-layer structs this
//! file does not otherwise touch), `%pV` (`struct va_format` -- its handler
//! does `va_copy()`/`va_end()` on the `va_list` inside, permanently C for
//! the same reason `vsnprintf` itself is, not just deferred), `%pOF`
//! (`device_node` -- CONFIG_OF is
//! unset in BOTH this project's configs, confirmed against both `.config`s,
//! so this is dead code here regardless of which language it's in, and
//! porting dead code clears none of GOALS.md's bar), `%pfw` (`fwnode_handle`
//! -- flagged in the survey as possibly ACPI-live even without CONFIG_OF,
//! needs its own check before it's assumed dead the way `%pOF` is),
//! `%pt`/`%pC` (`rtc_time`/`time64_t`/clk -- CONFIG_COMMON_CLK is also unset
//! in both configs, so `%pC` degrades to a `ptr_to_id()` fallback either
//! way, but the RTC/time64 path is real). `flags_string`'s own `'p'` case
//! (`%pGp`, page flags) also stays C for now -- it is the one row that
//! pulls in `../mm/internal.h`'s CONFIG-dependent bit-width constants
//! (`SECTIONS_WIDTH` etc., from `page-flags-layout.h`), a different and
//! more config-sensitive dependency than the fixed `trace_print_flags`
//! tables `'g'`/`'v'` use.
//!
//! `%pK`/`restricted_pointer` landed as its own checkpoint, after the
//! buffer-core: the impure wrapper computes `irq`
//! (`in_hardirq()||in_serving_softirq()||in_nmi()`, cheap, side-effect-
//! free, safe even in NMI) FIRST, and only computes `may_reveal` (as an
//! `Option<bool>`, not a plain `bool` -- see `restricted_pointer_decision`'s
//! own doc for why `None` is not "unknown, assume false") when
//! `kptr_restrict == 1 && !irq`, preserving the C's own ordering
//! requirement that `current_cred()`/`has_capability_noaudit()` never run
//! in IRQ/NMI context at all. The pure `restricted_pointer_decision()`
//! takes that `Option<bool>` plus `kptr_restrict`/`irq`/`field_width` and
//! decides among 4 outcomes (`HashAsP`/`PkError`/`Real`/`Null` -- 3
//! distinct terminal C functions, not 3 flavors of one). The
//! `has_capability_noaudit() && uid_eq() && gid_eq()` predicate itself
//! stays a tiny C helper (`vsprintf_c_restricted_pointer_cred_ok`) --
//! real `struct cred`/LSM machinery, not reimplementable here -- and is
//! NOT unit-testable from this crate's own userspace differential (no
//! real `current`/capability system in userspace); its own 8-case matrix
//! needs a kernel-side self-test, not covered by this pass.
//!
//! `hash_pointers_finalize`/`hash_pointers_mode_parse`/
//! `no_hash_pointers_enable`/`debug_boot_weak_hash_enable`/`fill_ptr_key`/
//! `vsprintf_init_hashval` (boot-param parsing and the one-time siphash-key
//! RNG init, `subsys_initcall`) stay C: one-time boot setup, not part of
//! `format_decode`'s per-call dispatch, and the state they own
//! (`ptr_key`/`filled_random_ptr_key`/`no_hash_pointers`) is read here via
//! `extern "C" static` exactly as any other cross-file kernel global.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ulonglong, c_void};
use kernel::bindings::PAGE_SIZE;

// ---------------------------------------------------------------------------
// External state this file reads but does not own (boot-param-configured
// globals, still set by the retained C file's init-time code).
// ---------------------------------------------------------------------------

/// Mirrors `siphash_key_t` (`include/linux/siphash.h`): `struct { u64
/// key[2]; }`. Re-declared here rather than imported -- `siphash_rs.rs`
/// compiles as its own separate crate in the real kernel build, same as
/// every other cross-file dependency in this project.
#[repr(C)]
struct SiphashKey {
    key: [u64; 2],
}

extern "C" {
    /// `lib/vsprintf.c`, `bool no_hash_pointers __ro_after_init`. Real
    /// `EXPORT_SYMBOL_GPL`.
    static no_hash_pointers: bool;
    /// `lib/vsprintf.c`, boot-time siphash key state. Written once by the
    /// retained C file's `fill_ptr_key()` (a `notifier_block` callback);
    /// read-only from here.
    static filled_random_ptr_key: bool;
    /// `lib/vsprintf.c`, `static siphash_key_t ptr_key __read_mostly`.
    static ptr_key: SiphashKey;
    /// `lib/vsprintf.c`, set by the `debug_boot_weak_hash=` early param.
    static debug_boot_weak_hash: c_int;

    /// `lib/siphash.c`, now `lib/siphash_rs.rs`. Real `EXPORT_SYMBOL`.
    /// (`siphash_1u32`, `__ptr_to_hashval`'s `#else` `CONFIG_64BIT`-unset
    /// fallback, is NOT declared -- permanently dead on this project's
    /// only target, same "don't implement the dead arm" treatment
    /// `put_dec`'s own 32-bit fork already got; an unused extern is a
    /// hard error under this build's `-D warnings`.)
    fn siphash_1u64(first: u64, key: *const SiphashKey) -> u64;

    /// `lib/errname.c`, now `lib/errname_rs.rs`. Real `EXPORT_SYMBOL`, but
    /// ONLY under `CONFIG_SYMBOLIC_ERRNAME` -- checked, build-full has it
    /// (`=y`) and build-fast does NOT (`is not set`), a real RAISE-1 fork.
    /// `include/linux/errname.h` gates the declaration itself the same way;
    /// mirrored below with a `#[cfg]` rather than an unconditional extern,
    /// which would be a link error on config-fast.
    #[cfg(CONFIG_SYMBOLIC_ERRNAME)]
    fn errname(err: c_int) -> *const c_char;

    /// `lib/uuid.c`, now `lib/uuid_rs.rs`. Real (non-`static`) globals, not
    /// `EXPORT_SYMBOL`'d, but this file is `obj-y`/builtin same as that one
    /// -- an ordinary cross-object link resolves them, same reasoning
    /// `string_helpers_rs.rs` already used for `get_cmdline`.
    static guid_index: [c_uchar; 16];
    static uuid_index: [c_uchar; 16];

    /// `lib/hexdump.c`, now `lib/hexdump_rs.rs`. Real `EXPORT_SYMBOL`.
    /// (`hex_asc_upper` is NOT declared here -- this file's own `number()`
    /// needs its own local `HEX_ASC_UPPER` table for the `| locase` trick
    /// regardless, so nothing in this file ever reads the real extern.)
    static hex_asc: [c_uchar; 16];

    /// `lib/string_helpers.c`, now `lib/string_helpers_rs.rs`. Real
    /// `EXPORT_SYMBOL`.
    fn string_escape_mem(
        src: *const c_char,
        isz: usize,
        dst: *mut c_char,
        osz: usize,
        flags: c_uint,
        only: *const c_char,
    ) -> c_int;

    /// `lib/string.c`. Real `EXPORT_SYMBOL`. (`strchr`/`strcspn`/`strspn`
    /// are NOT declared here -- this pass has no caller for them; the C
    /// callers that use them, e.g. `device_node_string`'s `strcspn`/
    /// `strspn`, are C calling C, no cross-language extern needed. An
    /// unused extern is a hard error under this build's `-D warnings`.)
    /// `#[cfg(CONFIG_BINARY_PRINTF)]`: this pass's only caller is
    /// `bstr_printf`'s own module, itself gated the same way -- build-fast
    /// (no `CONFIG_BINARY_PRINTF`) would otherwise see it as unused, also
    /// a hard error here.
    #[cfg(CONFIG_BINARY_PRINTF)]
    fn strlen(s: *const c_char) -> usize;
    /// `lib/ctype.c`, now `lib/ctype_rs.rs`. Real `EXPORT_SYMBOL`.
    static _ctype: [u8; 256];

    /// `lib/find_bit.c`, now `lib/find_bit_rs.rs`. Real `EXPORT_SYMBOL`.
    /// `bitmap_list_string()`'s `for_each_set_bitrange()` expands to
    /// `find_next_bit()`/`find_next_zero_bit()` (`include/linux/find.h`),
    /// both `static __always_inline` wrappers around these two, gated by
    /// `small_const_nbits(size)` (`__builtin_constant_p(size) && size <=
    /// BITS_PER_LONG`) -- always false here, since `size` is
    /// `spec.field_width`, a runtime value, never a compile-time constant
    /// at this call site. So the wrapper's only reachable branch is the
    /// direct call to these; called directly, skipping the dead fast path.
    fn _find_next_bit(addr: *const usize, nbits: usize, start: usize) -> usize;
    fn _find_next_zero_bit(addr: *const usize, nbits: usize, start: usize) -> usize;

    /// `kernel/kallsyms.c`. Real, builtin (not `EXPORT_SYMBOL`, but linked
    /// the same ordinary cross-object way `get_cmdline` already is).
    /// `symbol_string()`'s only live arm in this project -- `CONFIG_KALLSYMS`
    /// is `=y` on both `.config`s, checked directly, so the C's `#else`
    /// (`special_hex_number` fallback) is permanently dead code here.
    fn sprint_symbol(buffer: *mut c_char, address: c_ulong) -> c_int;
    fn sprint_symbol_no_offset(buffer: *mut c_char, address: c_ulong) -> c_int;
    fn sprint_symbol_build_id(buffer: *mut c_char, address: c_ulong) -> c_int;
    fn sprint_backtrace(buffer: *mut c_char, address: c_ulong) -> c_int;
    fn sprint_backtrace_build_id(buffer: *mut c_char, address: c_ulong) -> c_int;

    /// `mm/debug.c`: `const struct trace_print_flags gfpflag_names[] = {
    /// __def_gfpflag_names, {0, NULL} };` -- a real array, but of a length
    /// this crate has no way to name (it's built from an `X-macro` list in
    /// `include/trace/events/mmflags.h`, and the C side never spells the
    /// count either, it just relies on the `{0, NULL}` sentinel). Declaring
    /// this as `[TracePrintFlags; 0]` would be wrong -- a zero-length array
    /// type does not describe "unknown length, walk until `mask == 0`".
    /// Declared instead as a single `TracePrintFlags` (the array's first
    /// element, same trick C itself uses for `extern foo[]` of unspecified
    /// length) and walked via `&gfpflag_names as *const TracePrintFlags`,
    /// exactly what `format_flags()` below does. Read through
    /// `format_flags()` only, from the `flags_string()` `'g'`/`'v'` cases;
    /// the `'p'` (page-flags) case stays C, see the module doc.
    static gfpflag_names: TracePrintFlags;
    static vmaflag_names: TracePrintFlags;

    /// `lib/vsprintf.c` (retained C, phase-2/3 follow-up): `%pd`/`%pD`/
    /// `%pg`/`%pOF`/`%pfw`/`%pt`/`%pC`/`%pK` and the page-flags arm of
    /// `%pG`, all deferred -- see the module doc for exactly why each one.
    fn vsprintf_c_dentry_name(buf: *mut c_char, end: *mut c_char, d: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_file_dentry_name(buf: *mut c_char, end: *mut c_char, f: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_bdev_name(buf: *mut c_char, end: *mut c_char, bdev: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_device_node_string(buf: *mut c_char, end: *mut c_char, dn: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_fwnode_string(buf: *mut c_char, end: *mut c_char, fwnode: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_time_and_date(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_clock(buf: *mut c_char, end: *mut c_char, clk: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char;
    fn vsprintf_c_format_page_flags(buf: *mut c_char, end: *mut c_char, flags: c_ulong) -> *mut c_char;

    /// `int kptr_restrict __read_mostly;`, `lib/vsprintf.c:857`. Real,
    /// already non-static in the pristine C, unchanged in the retained
    /// file.
    static kptr_restrict: c_int;

    /// `in_hardirq() || in_serving_softirq() || in_nmi()`,
    /// `restricted_pointer()`'s own IRQ-context check (`lib/vsprintf.c:
    /// 874`) -- cheap, side-effect-free, safe even in NMI (the C's own
    /// comment: this check must run BEFORE `current_cred()`/
    /// `has_capability_noaudit()` are touched at all, not just before
    /// their result is used, because those still have real RCU/LSM-hook
    /// side effects and `current` itself is meaningless in NMI). Kept as
    /// a tiny C helper since `in_hardirq`/`in_serving_softirq`/`in_nmi`
    /// are real kernel macros over `preempt_count()`, not reimplementable
    /// here.
    fn vsprintf_c_in_irq_context() -> bool;

    /// `has_capability_noaudit(current, CAP_SYSLOG) &&
    /// uid_eq(cred->euid, cred->uid) && gid_eq(cred->egid, cred->gid)`,
    /// `restricted_pointer()`'s own `case 1` credential check
    /// (`lib/vsprintf.c:889-893`, negated from the C's `!A || !B || !C`
    /// "set ptr = NULL" condition to this function's own "may reveal"
    /// sense). Kept as a tiny C helper: `struct cred`/`current_cred()`/
    /// `has_capability_noaudit()` are real kernel/LSM machinery, not
    /// reimplementable here, and this crate must never call it except
    /// when the caller has ALREADY confirmed `!vsprintf_c_in_irq_context()`
    /// -- see `restricted_pointer()`'s own module doc below for why.
    fn vsprintf_c_restricted_pointer_cred_ok() -> bool;
    /// `format_decode()`'s `WARN_ONCE(1, "Please remove unsupported %%%c in
    /// format string\n", *fmt.str)` -- kept as a call into the retained C
    /// file rather than faked with `kernel::kabi_warn!` (a plain `WARN`,
    /// fires every time, not once) or invented as a new "once + format"
    /// macro in `kernel::kabi`: same reasoning `lib/ratelimit_rs.rs`'s
    /// module doc already gives for `___ratelimit()`'s own `WARN_ONCE` --
    /// the bug-table entry must name the real call site's file/line, and a
    /// Rust-side reproduction would name this crate's file/line instead.
    fn vsprintf_c_format_decode_invalid_warn(c: c_int);

    /// `rust/kernel/print.rs`: the `%pA` bridge, real pre-existing
    /// `#[export]` (plain C-ABI) symbol, `CONFIG_RUST`-only (which this
    /// whole file already requires to exist at all).
    fn rust_fmt_argument(buf: *mut c_char, end: *mut c_char, ptr: *const c_void) -> *mut c_char;

    /// `%pV`'s own `struct va_format { fmt; va_list *va; }` handler stays C
    /// permanently, not just deferred -- `va_format()` itself does
    /// `va_copy()`/`va_end()` on the `va_list` inside, the same `va_list`
    /// machinery `vsnprintf`/`vbin_printf`/`vsscanf` need and that this
    /// crate cannot touch on stable Rust (module doc, point 1). `ptr` here
    /// is `*const c_void` (opaque `struct va_format *`) purely as a pass-
    /// through -- this file never looks inside it.
    fn vsprintf_c_va_format(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char;
}

/// `include/linux/errname.h`'s `#else` arm: no `CONFIG_SYMBOLIC_ERRNAME`
/// means no linkable `errname()` symbol at all, and the header's own
/// fallback always returns `NULL`. Mirrored here rather than left as a
/// missing extern, which would only fail at link time on config-fast.
#[cfg(not(CONFIG_SYMBOLIC_ERRNAME))]
#[inline]
fn errname(_err: c_int) -> *const c_char {
    core::ptr::null()
}

// ---------------------------------------------------------------------------
// struct printf_spec, enum format_state, struct fmt -- vsprintf.c:441-459,
// 2602-2606.
// ---------------------------------------------------------------------------

const FORMAT_STATE_NONE: u8 = 0;
const FORMAT_STATE_NUM: u8 = 1;
const FORMAT_STATE_WIDTH: u8 = 2;
const FORMAT_STATE_PRECISION: u8 = 3;
const FORMAT_STATE_CHAR: u8 = 4;
const FORMAT_STATE_STR: u8 = 5;
const FORMAT_STATE_PTR: u8 = 6;
const FORMAT_STATE_PERCENT_CHAR: u8 = 7;
const FORMAT_STATE_INVALID: u8 = 8;

/// Mirrors `struct printf_spec`, `lib/vsprintf.c:453-459`. `#[repr(C,
/// packed)]`: the C is itself `__packed`, and `static_assert(sizeof(struct
/// printf_spec) == 8)` right below it in the C is the ABI contract this
/// mirror has to hold -- asserted again below, on the Rust side.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PrintfSpec {
    flags: u8,
    base: u8,
    precision: i16,
    field_width: i32,
}
const _: () = assert!(core::mem::size_of::<PrintfSpec>() == 8);

const FIELD_WIDTH_MAX: i32 = (1 << 23) - 1;
const PRECISION_MAX: i16 = ((1i32 << 15) - 1) as i16;

// Flags to number(), defutil.h-style bitfield -- vsprintf.c:430-436.
const F_SIGN: u8 = 1;
const F_LEFT: u8 = 2;
const F_PLUS: u8 = 4;
const F_SPACE: u8 = 8;
const F_ZEROPAD: u8 = 16;
const F_SMALL: u8 = 32;
const F_SPECIAL: u8 = 64;

/// `struct fmt`, `lib/vsprintf.c:2602-2606`. `#[repr(C)]` and `pub`:
/// crosses the real FFI boundary now (`vsprintf_rs_format_decode`'s
/// signature), not just an internal type -- both required for
/// `-D improper-ctypes-definitions`/`-D private-interfaces`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Fmt {
    str_: *const c_char,
    state: u8,
    size: u8,
}

/// Mirrors `struct trace_print_flags`, `include/linux/tracepoint-defs.h:16-19`.
/// `pub`: crosses the real FFI boundary (`vsprintf_rs_format_flags`'s
/// `names` parameter type).
#[repr(C)]
pub struct TracePrintFlags {
    mask: c_ulong,
    name: *const c_char,
}

// ---------------------------------------------------------------------------
// spec_flag()/set_field_width()/set_precision()/convert_num_spec(),
// vsprintf.c:2608-2626, 2797-2805.
// ---------------------------------------------------------------------------

/// `spec_flag(c)`, `lib/vsprintf.c:2609-2620`.
#[inline]
fn spec_flag(c: u8) -> u8 {
    match c {
        b' ' => F_SPACE,
        b'#' => F_SPECIAL,
        b'+' => F_PLUS,
        b'-' => F_LEFT,
        b'0' => F_ZEROPAD,
        _ => 0,
    }
}

/// `set_field_width(spec, width)`, `lib/vsprintf.c:2622-2626`. `clamp()`'s
/// own definition (`include/linux/minmax.h:181-182`) is a pure comparison
/// chain -- `(val >= hi) ? hi : (val <= lo) ? lo : val` -- no arithmetic on
/// `val` at all, which is exactly what makes it safe for `width ==
/// i32::MIN`. Mirrored the same way here (never `.abs()`/negate `width`
/// itself) -- verified against the real header before writing this, not
/// assumed; the shape this closes off: a naive abs()-based clamp panics on
/// `i32::MIN` under `CONFIG_RUST_OVERFLOW_CHECKS`, in ring 0, on any printk
/// carrying an `INT_MIN` width.
fn set_field_width(spec: &mut PrintfSpec, width: i32) {
    let clamped = if width >= FIELD_WIDTH_MAX {
        FIELD_WIDTH_MAX
    } else if width <= -FIELD_WIDTH_MAX {
        -FIELD_WIDTH_MAX
    } else {
        width
    };
    spec.field_width = clamped;
    kernel::kabi_warn!(clamped != width, "field width %d out of range", width);
}

/// `set_precision(spec, prec)`, `lib/vsprintf.c:2628-2632`. NOT symmetric
/// with `set_field_width` -- the clamp floor is 0, not `-PRECISION_MAX`, so
/// a negative `prec` clamps up to 0 with NO warning (only clamping DOWN,
/// from above `PRECISION_MAX`, warns). Faithfully asymmetric.
fn set_precision(spec: &mut PrintfSpec, prec: i32) {
    let prec16 = if prec >= PRECISION_MAX as i32 {
        PRECISION_MAX
    } else if prec <= 0 {
        0
    } else {
        prec as i16
    };
    spec.precision = prec16;
    kernel::kabi_warn!((prec16 as i32) < prec, "precision %d too large", prec);
}

/// `convert_num_spec(val, size, spec)`, `lib/vsprintf.c:2797-2805`.
fn convert_num_spec(val: c_uint, size: c_int, spec: PrintfSpec) -> c_ulonglong {
    let shift = 32 - size * 8;
    let val = (val as u32).wrapping_shl(shift as u32);
    if (spec.flags & F_SIGN) == 0 {
        (val.wrapping_shr(shift as u32)) as c_ulonglong
    } else {
        ((val as i32).wrapping_shr(shift as u32)) as i64 as c_ulonglong
    }
}

// ---------------------------------------------------------------------------
// put_dec family, vsprintf.c:220-389 (BITS_PER_LONG == 64 arm only -- this
// project's only target). num_to_str, vsprintf.c:399-428.
// ---------------------------------------------------------------------------

/// `static const u16 decpair[100]`, `lib/vsprintf.c:220-233`.
const DECPAIR: [u16; 100] = {
    let mut t = [0u16; 100];
    let mut x = 0usize;
    while x < 100 {
        // `cpu_to_le16(((x%10)|((x/10)<<8)) + 0x3030)`: on this
        // little-endian target, `cpu_to_le16` is the identity.
        t[x] = (((x % 10) | ((x / 10) << 8)) as u16).wrapping_add(0x3030);
        x += 1;
    }
    t
};

/// `put_dec_trunc8(buf, r)`, `lib/vsprintf.c:241-280`. Writes through a raw
/// pointer with 2-byte `u16` stores, exactly as the C's `*((u16 *)buf) =
/// decpair[...]` does -- `buf` is only ever `tmp[]` (a local, aligned,
/// stack array) or `ip4_string`'s own aligned `temp[]` at every real call
/// site, matching the C's own alignment comment. Flattens the C's
/// goto-based fallthrough (`out_q`/`out_r` labels reused across four
/// distinct entry paths) into explicit early returns -- traced against the
/// pristine C path by path before writing, not just transliterated.
///
/// # Safety
/// `buf` must be valid for writes for at least 8 bytes, 2-byte aligned.
unsafe fn put_dec_trunc8(buf: *mut u8, r: c_uint) -> *mut u8 {
    if r < 100 {
        // SAFETY: caller's contract.
        unsafe { (buf as *mut u16).write_unaligned(DECPAIR[r as usize]) };
        return unsafe { buf.add(if r < 10 { 1 } else { 2 }) };
    }

    let q = ((r as u64).wrapping_mul(0x28f5c29)) >> 32;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(r - 100 * q as u32) as usize]) };
    let buf = unsafe { buf.add(2) };

    if q < 100 {
        unsafe { (buf as *mut u16).write_unaligned(DECPAIR[q as usize]) };
        return unsafe { buf.add(if q < 10 { 1 } else { 2 }) };
    }

    let r2 = ((q as u64).wrapping_mul(0x28f5c29)) >> 32;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(q as u32 - 100 * r2 as u32) as usize]) };
    let buf = unsafe { buf.add(2) };

    if r2 < 100 {
        unsafe { (buf as *mut u16).write_unaligned(DECPAIR[r2 as usize]) };
        return unsafe { buf.add(if r2 < 10 { 1 } else { 2 }) };
    }

    let q2 = ((r2 as u64) * 0x147b) >> 19;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(r2 as u32 - 100 * q2 as u32) as usize]) };
    let buf = unsafe { buf.add(2) };
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[q2 as usize]) };
    unsafe { buf.add(if q2 < 10 { 1 } else { 2 }) }
}

/// `put_dec_full8(buf, r)`, `lib/vsprintf.c:284-307` (`BITS_PER_LONG == 64`
/// arm). Always writes exactly 8 bytes (4 pairs), no truncation -- unlike
/// `put_dec_trunc8`, no early return.
///
/// # Safety
/// `buf` must be valid for writes for at least 8 bytes, 2-byte aligned.
unsafe fn put_dec_full8(buf: *mut u8, r: c_uint) -> *mut u8 {
    let q = ((r as u64).wrapping_mul(0x28f5c29)) >> 32;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(r - 100 * q as u32) as usize]) };
    let buf = unsafe { buf.add(2) };

    let r2 = ((q as u64).wrapping_mul(0x28f5c29)) >> 32;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(q as u32 - 100 * r2 as u32) as usize]) };
    let buf = unsafe { buf.add(2) };

    let q2 = (r2 * 0x147b) >> 19;
    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[(r2 as u32 - 100 * q2 as u32) as usize]) };
    let buf = unsafe { buf.add(2) };

    unsafe { (buf as *mut u16).write_unaligned(DECPAIR[q2 as usize]) };
    unsafe { buf.add(2) }
}

/// `put_dec(buf, n)`, `lib/vsprintf.c:309-319` (`BITS_PER_LONG == 64` arm --
/// the only one this project's x86_64-only target ever takes; the `elif
/// BITS_PER_LONG == 32` arm, `put_dec_full4`/`put_dec_helper4`/its own
/// `put_dec`, is permanently dead code here, same "not this project's
/// problem" treatment `lib/crypto/mpi`'s `BYTES_PER_MPI_LIMB` fork already
/// got.
///
/// # Safety
/// `buf` must be valid for writes for at least 20 bytes (worst case:
/// `18446744073709551615`, 20 digits), 2-byte aligned.
unsafe fn put_dec(buf: *mut u8, n: u64) -> *mut u8 {
    let mut n = n;
    let mut buf = buf;
    if n >= 100_000_000 {
        let rem = (n % 100_000_000) as c_uint;
        n /= 100_000_000;
        buf = unsafe { put_dec_full8(buf, rem) };
    }
    if n >= 100_000_000 {
        let rem = (n % 100_000_000) as c_uint;
        n /= 100_000_000;
        buf = unsafe { put_dec_full8(buf, rem) };
    }
    unsafe { put_dec_trunc8(buf, n as c_uint) }
}

/// `num_to_str(buf, size, num, width)`, `lib/vsprintf.c:399-428`. NOT
/// `EXPORT_SYMBOL` (checked: absent from the file's `EXPORT_SYMBOL*`
/// list), but real external-linkage C, called cross-file from
/// `fs/seq_file.c` (twice) and `drivers/of/unittest.c` (checked directly)
/// -- same "ordinary builtin-to-builtin linkage" category as
/// `ptr_to_hashval` above and `get_cmdline`'s own precedent
/// (`string_helpers_rs.rs`); needs `#[no_mangle] pub extern "C"`, not a
/// plain `pub fn`, to keep those callers linking -- caught only once this
/// file's dependents were cross-checked, not by the earlier survey.
///
/// Unlike every other function in this file, `buf` here is NOT
/// bounds-checked against an `end` on every write -- the C's own contract
/// is the same: the caller must have checked `len <= size` first (this
/// function does, via its own `if len > size || width > size { return 0
/// }`), and `buf`/`width` beyond that are the caller's responsibility,
/// exactly as upstream.
///
/// # Safety
/// `buf` must be valid for writes for at least `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn num_to_str(buf: *mut c_char, size: c_int, num: c_ulonglong, width: c_uint) -> c_int {
    // `put_dec` needs 2-byte alignment; `tmp`'s natural `u16` alignment
    // gives it, same as the C's `__aligned(2)`.
    let mut tmp = [0u16; 3 * core::mem::size_of::<u64>() / 2];
    let tmp_bytes = tmp.as_mut_ptr() as *mut u8;

    let len: usize = if num <= 9 {
        // SAFETY: `tmp` has room for at least 1 byte.
        unsafe { *tmp_bytes = b'0' + num as u8 };
        1
    } else {
        // SAFETY: `tmp` is sized `3 * sizeof(u64)` bytes, `put_dec`'s own
        // documented requirement.
        let end = unsafe { put_dec(tmp_bytes, num) };
        (end as usize) - (tmp_bytes as usize)
    };

    if (len as c_int) > size || (width as c_int) > size {
        return 0;
    }

    let width = if width as usize > len { width as usize - len } else { 0 };
    // SAFETY: class B (boundary), the caller's contract: `buf` valid for
    // `size` bytes, and `len + width <= size` just checked above (`width`
    // here already accounts for the truncation to `len` when `width <=
    // len`, matching the C's own `else width = 0`).
    unsafe {
        for idx in 0..width {
            *buf.add(idx) = b' ' as c_char;
        }
        for idx in 0..len {
            *buf.add(idx + width) = *tmp_bytes.add(len - idx - 1) as c_char;
        }
    }

    (len + width) as c_int
}

// ---------------------------------------------------------------------------
// number(), vsprintf.c:464-583. special_hex_number, vsprintf.c:585-596.
// ---------------------------------------------------------------------------

/// `number(buf, end, num, spec)`, `lib/vsprintf.c:464-583`. Every write is
/// `if buf < end { *buf = c } ; buf += 1` -- ported literally, since that
/// pattern (advance the logical cursor unconditionally, only touch memory
/// when in bounds) is exactly how this file computes "the length that
/// WOULD have been written" even when truncating, and is reused
/// everywhere else in this port too.
///
/// # Safety
/// `buf` must be valid for writes up to `end` (or `buf >= end`, in which
/// case nothing is written).
unsafe fn number(buf: *mut c_char, end: *mut c_char, num: c_ulonglong, spec: PrintfSpec) -> *mut c_char {
    // `tmp` needs 2-byte alignment for `put_dec`; sized `3 * sizeof(num)`
    // bytes as `u16`, same as `num_to_str`.
    let mut tmp = [0u16; 3 * core::mem::size_of::<u64>() / 2];
    let tmp_bytes = tmp.as_mut_ptr() as *mut u8;

    let need_pfx = (spec.flags & F_SPECIAL) != 0 && spec.base != 10;
    let is_zero = num == 0;
    let mut field_width = spec.field_width;
    let mut precision = spec.precision as i32;
    let mut flags = spec.flags;

    let locase = flags & F_SMALL;
    if (flags & F_LEFT) != 0 {
        flags &= !F_ZEROPAD;
    }
    let mut sign: u8 = 0;
    let mut num = num;
    if (flags & F_SIGN) != 0 {
        if (num as i64) < 0 {
            sign = b'-';
            num = (-(num as i64)) as c_ulonglong;
            field_width -= 1;
        } else if (flags & F_PLUS) != 0 {
            sign = b'+';
            field_width -= 1;
        } else if (flags & F_SPACE) != 0 {
            sign = b' ';
            field_width -= 1;
        }
    }
    if need_pfx {
        if spec.base == 16 {
            field_width -= 2;
        } else if !is_zero {
            field_width -= 1;
        }
    }

    // Generate the full string in `tmp_bytes`, in reverse order.
    let mut i: usize = 0;
    if num < spec.base as u64 {
        // SAFETY: `tmp_bytes` has room for at least 1 byte (24 total).
        unsafe { *tmp_bytes = HEX_ASC_UPPER[num as usize] | locase };
        i = 1;
    } else if spec.base != 10 {
        let mask = (spec.base as u32) - 1;
        let shift: u32 = if spec.base == 16 { 4 } else { 3 };
        loop {
            // SAFETY: at most 22 iterations for a 64-bit `num` in base 8.
            unsafe { *tmp_bytes.add(i) = HEX_ASC_UPPER[(num as u8 & mask as u8) as usize] | locase };
            i += 1;
            num >>= shift;
            if num == 0 {
                break;
            }
        }
    } else {
        // SAFETY: `tmp_bytes` is 24 bytes, `put_dec`'s own requirement.
        let end_ptr = unsafe { put_dec(tmp_bytes, num) };
        i = (end_ptr as usize) - (tmp_bytes as usize);
    }

    // "printing 100 using %2d gives 100, not 00".
    if (i as i32) > precision {
        precision = i as i32;
    }
    field_width -= precision;

    let mut buf = buf;
    if (flags & (F_ZEROPAD | F_LEFT)) == 0 {
        field_width -= 1;
        while field_width >= 0 {
            // SAFETY: class B (boundary), the caller's contract.
            if buf < end { unsafe { *buf = b' ' as c_char } };
            buf = unsafe { buf.add(1) };
            field_width -= 1;
        }
    }
    if sign != 0 {
        if buf < end { unsafe { *buf = sign as c_char } };
        buf = unsafe { buf.add(1) };
    }
    if need_pfx {
        if spec.base == 16 || !is_zero {
            if buf < end { unsafe { *buf = b'0' as c_char } };
            buf = unsafe { buf.add(1) };
        }
        if spec.base == 16 {
            if buf < end { unsafe { *buf = (b'X' | locase) as c_char } };
            buf = unsafe { buf.add(1) };
        }
    }
    if (flags & F_LEFT) == 0 {
        let c = (b' ' as u8).wrapping_add(flags & F_ZEROPAD);
        field_width -= 1;
        while field_width >= 0 {
            if buf < end { unsafe { *buf = c as c_char } };
            buf = unsafe { buf.add(1) };
            field_width -= 1;
        }
    }
    // Even more zero padding.
    precision -= 1;
    while (i as i32) <= precision {
        if buf < end { unsafe { *buf = b'0' as c_char } };
        buf = unsafe { buf.add(1) };
        precision -= 1;
    }
    // Actual digits of the result.
    while i > 0 {
        i -= 1;
        // SAFETY: `i < 24`, within `tmp_bytes`'s bounds.
        if buf < end { unsafe { *buf = *tmp_bytes.add(i) as c_char } };
        buf = unsafe { buf.add(1) };
    }
    // Trailing space padding.
    field_width -= 1;
    while field_width >= 0 {
        if buf < end { unsafe { *buf = b' ' as c_char } };
        buf = unsafe { buf.add(1) };
        field_width -= 1;
    }

    buf
}

/// `hex_asc_upper[]`, `include/linux/hex.h`-adjacent -- actually
/// `kernel.h`'s `hex_asc_upper` is `"0123456789ABCDEF"`; declared as its
/// own table here (not `extern`'d) because `number()`'s use ORs it with
/// `locase` (0x20) to get lowercase, which only works starting from the
/// UPPERCASE table (`'A' | 0x20 == 'a'`; the lowercase table's own `'a' |
/// 0x20 == 'a'` too, so either works for hex, but base-8/base-10 digits
/// need the identity `'0'..'9' | 0x20` to stay unchanged, which only holds
/// starting from the digit characters common to both tables -- the C's
/// own `hex_asc_upper[]` is exactly this table, always the upper-hex/plain
/// -digit form).
const HEX_ASC_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// `special_hex_number(buf, end, num, size)`, `lib/vsprintf.c:585-596`.
///
/// # Safety
/// As `number`.
unsafe fn special_hex_number(buf: *mut c_char, end: *mut c_char, num: c_ulonglong, size: c_int) -> *mut c_char {
    let spec = PrintfSpec {
        field_width: 2 + 2 * size,
        flags: F_SPECIAL | F_SMALL | F_ZEROPAD,
        base: 16,
        precision: -1,
    };
    unsafe { number(buf, end, num, spec) }
}

// ---------------------------------------------------------------------------
// move_right/widen_string/string_nocheck/err_ptr/error_string/
// check_pointer_msg/check_pointer/string/pointer_string, vsprintf.c:598-750.
// ---------------------------------------------------------------------------

/// `move_right(buf, end, len, spaces)`, `lib/vsprintf.c:598-614`.
///
/// # Safety
/// `buf` must be valid to read/write over `[buf, end)` when `buf < end`
/// (same "nothing to do" short-circuit as the C).
unsafe fn move_right(buf: *mut c_char, end: *mut c_char, len: c_uint, spaces: c_uint) {
    if buf >= end {
        return;
    }
    let size = (end as usize) - (buf as usize);
    if size <= spaces as usize {
        // SAFETY: caller's contract, `size` bytes from `buf`.
        unsafe { core::ptr::write_bytes(buf, b' ', size) };
        return;
    }
    let mut len = len as usize;
    if len != 0 {
        if len > size - spaces as usize {
            len = size - spaces as usize;
        }
        // SAFETY: caller's contract; `buf + spaces + len <= buf + size ==
        // end`, checked above. `memmove`-equivalent (regions can overlap).
        unsafe { core::ptr::copy(buf, buf.add(spaces as usize), len) };
    }
    // SAFETY: caller's contract, `spaces <= size`.
    unsafe { core::ptr::write_bytes(buf, b' ', spaces as usize) };
}

/// `widen_string(buf, n, end, spec)`, `lib/vsprintf.c:624-643`.
///
/// # Safety
/// `buf - n` must be valid for `move_right`'s contract when padding on the
/// left; `buf` valid up to `end` when padding on the right.
unsafe fn widen_string(buf: *mut c_char, n: c_int, end: *mut c_char, spec: PrintfSpec) -> *mut c_char {
    if n >= spec.field_width {
        return buf;
    }
    let spaces = (spec.field_width - n) as c_uint;
    if (spec.flags & F_LEFT) == 0 {
        // SAFETY: every real call site's `n` is the count of bytes just
        // written starting at `buf - n`, matching the C exactly.
        unsafe { move_right(buf.sub(n as usize), end, n as c_uint, spaces) };
        return unsafe { buf.add(spaces as usize) };
    }
    let mut buf = buf;
    let mut spaces = spaces;
    while spaces > 0 {
        spaces -= 1;
        if buf < end {
            // SAFETY: class B (boundary).
            unsafe { *buf = b' ' as c_char };
        }
        buf = unsafe { buf.add(1) };
    }
    buf
}

/// `string_nocheck(buf, end, s, spec)`, `lib/vsprintf.c:646-662`. Handles a
/// string from a well-known address -- no NULL/fault check (that's
/// `string()`/`check_pointer()`, below).
///
/// # Safety
/// `s` must be a valid NUL-terminated C string (or readable up to the first
/// of `spec.precision` bytes or a NUL, whichever comes first). `buf` valid
/// up to `end`.
unsafe fn string_nocheck(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    let mut len: c_int = 0;
    let mut lim = spec.precision as c_int;
    let mut buf = buf;
    let mut s = s;
    loop {
        let lim_was = lim;
        lim -= 1;
        if lim_was == 0 {
            break;
        }
        // SAFETY: caller's contract.
        let c = unsafe { *s };
        s = unsafe { s.add(1) };
        if c == 0 {
            break;
        }
        if buf < end {
            unsafe { *buf = c };
        }
        buf = unsafe { buf.add(1) };
        len += 1;
    }
    unsafe { widen_string(buf, len, end, spec) }
}

/// `(unsigned long)ptr >= (unsigned long)-MAX_ERRNO`, `include/linux/err.h`.
#[inline]
fn is_err_value(x: usize) -> bool {
    (x as u64) >= (0u64.wrapping_sub(4095))
}

/// `IS_ERR_OR_NULL(ptr)`, `include/linux/err.h:79-82`.
#[inline]
fn is_err_or_null(ptr: *const c_void) -> bool {
    ptr.is_null() || is_err_value(ptr as usize)
}

/// `PTR_ERR(ptr)`, `include/linux/err.h:52-55`.
#[inline]
fn ptr_err(ptr: *const c_void) -> c_long {
    ptr as c_long
}

/// `err_ptr(buf, end, ptr, spec)`, `lib/vsprintf.c:664-681`.
///
/// # Safety
/// As `number`/`string_nocheck`.
unsafe fn err_ptr(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    let err = ptr_err(ptr) as c_int;
    // SAFETY: `errname()` (real or the `#[cfg(not(...))]` null-returning
    // stub) is safe to call with any `c_int`. The `unsafe` block is only
    // load-bearing on the `CONFIG_SYMBOLIC_ERRNAME` (real `extern "C" fn`)
    // arm -- the fallback is a plain safe `fn`, so build-fast (which lacks
    // that config) sees it as unnecessary; silenced rather than split into
    // two `#[cfg]`-gated call sites for one line.
    #[allow(unused_unsafe)]
    let sym = unsafe { errname(err) };
    if !sym.is_null() {
        return unsafe { string_nocheck(buf, end, sym, spec) };
    }
    let mut spec = spec;
    spec.flags |= F_SIGN;
    spec.base = 10;
    unsafe { number(buf, end, err as i64 as c_ulonglong, spec) }
}

/// `error_string(buf, end, s, spec)`, `lib/vsprintf.c:684-696`.
///
/// # Safety
/// As `string_nocheck`.
unsafe fn error_string(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    let mut spec = spec;
    if spec.precision == -1 {
        spec.precision = (2 * core::mem::size_of::<*const c_void>()) as i16;
    }
    unsafe { string_nocheck(buf, end, s, spec) }
}

/// `check_pointer_msg(ptr)`, `lib/vsprintf.c:703-712`. "Do not call any
/// complex external code here" (the C's own comment) -- no allocation, no
/// external call, just the two checks.
fn check_pointer_msg(ptr: *const c_void) -> *const c_char {
    if ptr.is_null() {
        return c"(null)".as_ptr();
    }
    if (ptr as usize) < PAGE_SIZE as usize || is_err_value(ptr as usize) {
        return c"(efault)".as_ptr();
    }
    core::ptr::null()
}

/// `check_pointer(buf, end, ptr, spec)`, `lib/vsprintf.c:714-726`. Returns
/// `true` (C: `-EFAULT`, nonzero) when `*buf` was already written and the
/// caller should return immediately, matching every call site's `if
/// check_pointer(...) return buf;` shape.
///
/// # Safety
/// As `error_string`.
unsafe fn check_pointer(buf: &mut *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> bool {
    let err_msg = check_pointer_msg(ptr);
    if !err_msg.is_null() {
        *buf = unsafe { error_string(*buf, end, err_msg, spec) };
        return true;
    }
    false
}

/// `string(buf, end, s, spec)`, `lib/vsprintf.c:728-736`.
///
/// # Safety
/// `s` must be a valid NUL-terminated C string when not NULL/an error
/// value/below `PAGE_SIZE` (those are all caught by `check_pointer` without
/// dereferencing `s`).
unsafe fn string(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, s as *const c_void, spec) } {
        return buf;
    }
    unsafe { string_nocheck(buf, end, s, spec) }
}

/// `pointer_string(buf, end, ptr, spec)`, `lib/vsprintf.c:738-750`.
///
/// # Safety
/// As `number`.
unsafe fn pointer_string(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    let mut spec = spec;
    spec.base = 16;
    spec.flags |= F_SMALL;
    if spec.field_width == -1 {
        spec.field_width = (2 * core::mem::size_of::<*const c_void>()) as i32;
        spec.flags |= F_ZEROPAD;
    }
    unsafe { number(buf, end, ptr as usize as c_ulonglong, spec) }
}

// ---------------------------------------------------------------------------
// Hash-pointer machinery, vsprintf.c:784-855: __ptr_to_hashval/
// ptr_to_hashval/ptr_to_id/default_pointer. `restricted_pointer` (%pK)
// itself is further down, its own section, its own seam.
// ---------------------------------------------------------------------------

/// `hash_long(val, 32)`, `include/linux/hash.h:16-19,72-79` -- the
/// `BITS_PER_LONG == 64` (`hash_64`/`hash_64_generic`) arm only, this
/// project's only target, same treatment as `put_dec`'s own 64-bit-only
/// fork.
#[inline]
fn hash_long_32(val: u64) -> u32 {
    const GOLDEN_RATIO_64: u64 = 0x61C8864680B583EB;
    ((val.wrapping_mul(GOLDEN_RATIO_64)) >> (64 - 32)) as u32
}

/// `__ptr_to_hashval(ptr, hashval_out)`, `lib/vsprintf.c:785-807`
/// (`CONFIG_64BIT` arm only). Returns `Some(hashval)`, or `None` for the
/// C's `-EBUSY` ("key not yet filled").
fn ptr_to_hashval_impl(ptr: *const c_void) -> Option<c_ulong> {
    // SAFETY: `filled_random_ptr_key`/`ptr_key` are plain `extern "C"`
    // globals written once, at boot, by the retained C's `fill_ptr_key()`;
    // ordinary volatile-style read here, same as every other cross-file
    // kernel global this crate reads.
    if !unsafe { core::ptr::read_volatile(&raw const filled_random_ptr_key) } {
        return None;
    }
    // SAFETY: `ptr_key` is `'static`, initialized before
    // `filled_random_ptr_key` is set (`smp_wmb()`/`smp_rmb()` pairing in
    // the C; a plain read is the same ordering guarantee this crate's other
    // cross-file globals already rely on).
    let key = &raw const ptr_key;
    let hashval = unsafe { siphash_1u64(ptr as u64, key) };
    Some((hashval & 0xffffffff) as c_ulong)
}

/// `ptr_to_hashval(ptr, hashval_out)`, `lib/vsprintf.c:809-812`. NOT
/// `EXPORT_SYMBOL` (checked: absent from the file's `EXPORT_SYMBOL*`
/// list), but real external-linkage C, called cross-file from
/// `kernel/sched/core_sched.c` and `include/trace/events/kmem.h` (checked
/// directly) -- ordinary builtin-to-builtin linkage, same as
/// `get_cmdline`'s own precedent (`string_helpers_rs.rs`), not a KABI
/// concern. Must keep the exact C signature (`int
/// ptr_to_hashval(const void*, unsigned long *)`) for those callers to
/// link against.
///
/// # Safety
/// `hashval_out` must be valid for a write of one `c_ulong` when this
/// returns 0.
#[no_mangle]
pub unsafe extern "C" fn ptr_to_hashval(ptr: *const c_void, hashval_out: *mut c_ulong) -> c_int {
    /// `EBUSY`, `include/uapi/asm-generic/errno-base.h`.
    const EBUSY: c_int = 16;
    match ptr_to_hashval_impl(ptr) {
        Some(v) => {
            // SAFETY: caller's contract.
            unsafe { *hashval_out = v };
            0
        }
        None => -EBUSY,
    }
}

/// `ptr_to_id(buf, end, ptr, spec)`, `lib/vsprintf.c:814-842`.
///
/// # Safety
/// As `pointer_string`/`error_string`.
unsafe fn ptr_to_id(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    const STR: &[u8] = if core::mem::size_of::<*const c_void>() == 8 {
        b"(____ptrval____)\0"
    } else {
        b"(ptrval)\0"
    };

    if is_err_or_null(ptr) {
        return unsafe { pointer_string(buf, end, ptr, spec) };
    }

    // SAFETY: plain `extern "C"` global, see `ptr_to_hashval_impl`.
    if unsafe { core::ptr::read_volatile(&raw const debug_boot_weak_hash) } != 0 {
        let hashval = hash_long_32(ptr as u64);
        return unsafe { pointer_string(buf, end, hashval as usize as *const c_void, spec) };
    }

    match ptr_to_hashval_impl(ptr) {
        Some(hashval) => unsafe { pointer_string(buf, end, hashval as usize as *const c_void, spec) },
        None => {
            let mut spec = spec;
            spec.field_width = (2 * core::mem::size_of::<*const c_void>()) as i32;
            unsafe { error_string(buf, end, STR.as_ptr() as *const c_char, spec) }
        }
    }
}

/// `default_pointer(buf, end, ptr, spec)`, `lib/vsprintf.c:844-855`. The
/// `%p` handler.
///
/// # Safety
/// As `ptr_to_id`/`pointer_string`.
unsafe fn default_pointer(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    // SAFETY: plain `extern "C"` global, see `ptr_to_hashval_impl`.
    if unsafe { core::ptr::read_volatile(&raw const no_hash_pointers) } {
        return unsafe { pointer_string(buf, end, ptr, spec) };
    }
    unsafe { ptr_to_id(buf, end, ptr, spec) }
}

// ---------------------------------------------------------------------------
// symbol_string, vsprintf.c:988-1017 (CONFIG_KALLSYMS=y arm only, see the
// extern block). default_*_spec, vsprintf.c:1019-1047.
// ---------------------------------------------------------------------------

/// `KSYM_SYMBOL_LEN`, `include/linux/kallsyms.h:19-21` -- computed by hand
/// against that header (`KSYM_NAME_LEN=512`, `BITS_PER_LONG=64`,
/// `MODULE_NAME_LEN=64-sizeof(long)=56`, `BUILD_ID_SIZE_MAX=20`):
/// `21 + 511 + 2*(64*3/10) + 55 + 40 + 1 == 666`.
const KSYM_SYMBOL_LEN: usize = 666;

/// `symbol_string(buf, end, ptr, spec, fmt)`, `lib/vsprintf.c:988-1017`.
/// `__builtin_extract_return_addr(ptr)` (the `fmt[1] == 'R'` case) has no
/// x86 override anywhere in this tree (checked: no `arch/x86/include/asm/
/// *.h` redefines it) -- it's the generic compiler builtin, identity on
/// every architecture without an override. Implemented as identity here.
///
/// # Safety
/// `buf` valid up to `end`. `fmt` must point at a NUL-terminated format
/// string at least 2 bytes long (every real call site's `fmt` satisfies
/// this -- `pointer()`'s own dispatch already consumed the leading `%`).
unsafe fn symbol_string(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    // SAFETY: caller's contract.
    let (f0, f1) = unsafe { (*fmt as u8, *fmt.add(1) as u8) };
    // `__builtin_extract_return_addr`, identity on this target.
    let value = ptr as c_ulong;

    let mut sym = [0u8; KSYM_SYMBOL_LEN];
    let sym_ptr = sym.as_mut_ptr() as *mut c_char;
    // SAFETY: `sym` is `KSYM_SYMBOL_LEN` bytes, exactly what every
    // `sprint_*` function's own contract requires.
    unsafe {
        if f0 == b'B' && f1 == b'b' {
            sprint_backtrace_build_id(sym_ptr, value);
        } else if f0 == b'B' {
            sprint_backtrace(sym_ptr, value);
        } else if f0 == b'S' && (f1 == b'b' || (f1 == b'R' && *fmt.add(2) as u8 == b'b')) {
            sprint_symbol_build_id(sym_ptr, value);
        } else if f0 != b's' {
            sprint_symbol(sym_ptr, value);
        } else {
            sprint_symbol_no_offset(sym_ptr, value);
        }
    }
    unsafe { string_nocheck(buf, end, sym_ptr, spec) }
}

// `default_dec02_spec`/`default_dec04_spec` are NOT mirrored here --
// their only upstream callers (`date_str`/`time_str`) are part of the
// `%pt` seam, which stays entirely in the retained C file (which keeps
// its own copies); an unused const is a hard error under this build's
// `-D warnings`.
const DEFAULT_STR_SPEC: PrintfSpec = PrintfSpec { flags: 0, base: 0, precision: -1, field_width: -1 };
const DEFAULT_FLAG_SPEC: PrintfSpec = PrintfSpec { flags: F_SPECIAL | F_SMALL, base: 16, precision: -1, field_width: 0 };
const DEFAULT_DEC_SPEC: PrintfSpec = PrintfSpec { flags: 0, base: 10, precision: -1, field_width: 0 };

// ---------------------------------------------------------------------------
// hex_range/resource_string/range_string/resource_or_range,
// vsprintf.c:1049-1183, 2296-2303.
// ---------------------------------------------------------------------------

/// Mirrors `struct resource`, `include/linux/ioport.h:21-28`. `x86_64`-only
/// target: `resource_size_t` is `phys_addr_t`, `typedef u64` (checked:
/// `include/linux/types.h:168`, the `#else` 32-bit arm is dead here).
#[repr(C)]
struct Resource {
    start: u64,
    end: u64,
    name: *const c_char,
    flags: c_ulong,
    desc: c_ulong,
    parent: *mut Resource,
    sibling: *mut Resource,
    child: *mut Resource,
}

/// `resource_size(res)`, `include/linux/ioport.h:289-292`.
#[inline]
fn resource_size(res: &Resource) -> u64 {
    res.end.wrapping_sub(res.start).wrapping_add(1)
}

const IORESOURCE_IO: c_ulong = 0x00000100;
const IORESOURCE_MEM: c_ulong = 0x00000200;
const IORESOURCE_IRQ: c_ulong = 0x00000400;
const IORESOURCE_DMA: c_ulong = 0x00000800;
const IORESOURCE_BUS: c_ulong = 0x00001000;
const IORESOURCE_PREFETCH: c_ulong = 0x00002000;
const IORESOURCE_MEM_64: c_ulong = 0x00100000;
const IORESOURCE_WINDOW: c_ulong = 0x00200000;
const IORESOURCE_DISABLED: c_ulong = 0x10000000;
const IORESOURCE_UNSET: c_ulong = 0x20000000;

/// Mirrors `struct range`, `include/linux/range.h:6-9`.
#[repr(C)]
struct RangeStruct {
    start: u64,
    end: u64,
}

/// `hex_range(buf, end, start_val, end_val, spec)`, `lib/vsprintf.c:1049-1061`.
///
/// # Safety
/// As `number`.
unsafe fn hex_range(buf: *mut c_char, end: *mut c_char, start_val: u64, end_val: u64, spec: PrintfSpec) -> *mut c_char {
    let mut buf = unsafe { number(buf, end, start_val, spec) };
    if start_val == end_val {
        return buf;
    }
    if buf < end {
        unsafe { *buf = b'-' as c_char };
    }
    buf = unsafe { buf.add(1) };
    unsafe { number(buf, end, end_val, spec) }
}

/// `resource_string(buf, end, res, spec, fmt)`, `lib/vsprintf.c:1063-1158`.
/// `sym`'s size: the C sizes it via a `MAX()` of two nested-string-literal
/// expressions that both reduce to compile-time constants on this
/// 64-bit-only target; `256` bytes here is a deliberately generous
/// over-approximation of that same constant (comfortably above either
/// branch: `2*RSRC_BUF_SIZE=40`, `+DECODED_BUF_SIZE=76`; the flags/raw
/// branch is smaller still) -- the C's own value doesn't need reproducing
/// exactly, `sym` is a scratch buffer `string_nocheck`/`p < pend` bounds
/// every write into, same as the C's own overflow discipline.
///
/// # Safety
/// `res` must be a valid `Resource` when not caught by `check_pointer`
/// (NULL/error-value/below-`PAGE_SIZE`). `buf`/`end` as `string`.
unsafe fn resource_string(buf: *mut c_char, end: *mut c_char, res: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    const IO_SPEC: PrintfSpec = PrintfSpec { flags: F_SPECIAL | F_SMALL | F_ZEROPAD, base: 16, precision: -1, field_width: 6 };
    const MEM_SPEC: PrintfSpec = PrintfSpec { flags: F_SPECIAL | F_SMALL | F_ZEROPAD, base: 16, precision: -1, field_width: 10 };
    const BUS_SPEC: PrintfSpec = PrintfSpec { flags: F_SMALL | F_ZEROPAD, base: 16, precision: -1, field_width: 2 };
    const STR_SPEC: PrintfSpec = PrintfSpec { flags: F_LEFT, base: 0, precision: 10, field_width: -1 };

    let mut sym = [0u8; 256];
    let sym_start = sym.as_mut_ptr() as *mut c_char;
    let mut p = sym_start;
    // SAFETY: `sym` is 256 bytes.
    let pend = unsafe { sym_start.add(256) };

    // SAFETY: caller's contract.
    let decode_is_r = unsafe { *fmt as u8 == b'R' };
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, res, spec) } {
        return buf;
    }
    // SAFETY: caller's contract: `res` is a valid `Resource` past the
    // `check_pointer` gate above.
    let res = unsafe { &*(res as *const Resource) };
    let mut decode = decode_is_r;

    // SAFETY: `p == sym_start < pend` here.
    unsafe { *p = b'[' as c_char };
    p = unsafe { p.add(1) };

    let specp: PrintfSpec;
    if (res.flags & IORESOURCE_IO) != 0 {
        p = unsafe { string_nocheck(p, pend, c"io  ".as_ptr(), STR_SPEC) };
        specp = IO_SPEC;
    } else if (res.flags & IORESOURCE_MEM) != 0 {
        p = unsafe { string_nocheck(p, pend, c"mem ".as_ptr(), STR_SPEC) };
        specp = MEM_SPEC;
    } else if (res.flags & IORESOURCE_IRQ) != 0 {
        p = unsafe { string_nocheck(p, pend, c"irq ".as_ptr(), STR_SPEC) };
        specp = DEFAULT_DEC_SPEC;
    } else if (res.flags & IORESOURCE_DMA) != 0 {
        p = unsafe { string_nocheck(p, pend, c"dma ".as_ptr(), STR_SPEC) };
        specp = DEFAULT_DEC_SPEC;
    } else if (res.flags & IORESOURCE_BUS) != 0 {
        p = unsafe { string_nocheck(p, pend, c"bus ".as_ptr(), STR_SPEC) };
        specp = BUS_SPEC;
    } else {
        p = unsafe { string_nocheck(p, pend, c"??? ".as_ptr(), STR_SPEC) };
        specp = MEM_SPEC;
        decode = false;
    }
    if decode && (res.flags & IORESOURCE_UNSET) != 0 {
        p = unsafe { string_nocheck(p, pend, c"size ".as_ptr(), STR_SPEC) };
        p = unsafe { number(p, pend, resource_size(res), specp) };
    } else {
        p = unsafe { hex_range(p, pend, res.start, res.end, specp) };
    }
    if decode {
        if (res.flags & IORESOURCE_MEM_64) != 0 {
            p = unsafe { string_nocheck(p, pend, c" 64bit".as_ptr(), STR_SPEC) };
        }
        if (res.flags & IORESOURCE_PREFETCH) != 0 {
            p = unsafe { string_nocheck(p, pend, c" pref".as_ptr(), STR_SPEC) };
        }
        if (res.flags & IORESOURCE_WINDOW) != 0 {
            p = unsafe { string_nocheck(p, pend, c" window".as_ptr(), STR_SPEC) };
        }
        if (res.flags & IORESOURCE_DISABLED) != 0 {
            p = unsafe { string_nocheck(p, pend, c" disabled".as_ptr(), STR_SPEC) };
        }
    } else {
        p = unsafe { string_nocheck(p, pend, c" flags ".as_ptr(), STR_SPEC) };
        p = unsafe { number(p, pend, res.flags as c_ulonglong, DEFAULT_FLAG_SPEC) };
    }
    // SAFETY: `sym` is 256 bytes and every `string_nocheck`/`number` call
    // above bounds its own writes against `pend`; two more bytes (`]`, NUL)
    // fit with wide margin over any real formatted resource.
    unsafe {
        if p < pend {
            *p = b']' as c_char;
        }
        p = p.add(1);
        if p < pend {
            *p = 0;
        } else {
            *pend.sub(1) = 0;
        }
    }

    unsafe { string_nocheck(buf, end, sym_start, spec) }
}

/// `range_string(buf, end, range, spec, fmt)`, `lib/vsprintf.c:1160-1183`.
///
/// # Safety
/// As `resource_string`, for a `RangeStruct` in place of a `Resource`.
unsafe fn range_string(buf: *mut c_char, end: *mut c_char, range: *const c_void, spec: PrintfSpec, _fmt: *const c_char) -> *mut c_char {
    const RANGE_SPEC: PrintfSpec = PrintfSpec {
        flags: F_SPECIAL | F_SMALL | F_ZEROPAD,
        base: 16,
        precision: -1,
        field_width: 2 + 2 * core::mem::size_of::<u64>() as i32,
    };

    let mut sym = [0u8; 64];
    let sym_start = sym.as_mut_ptr() as *mut c_char;
    // SAFETY: `sym` is 64 bytes, comfortably over
    // `sizeof("[range 0x0123456789abcdef-0x0123456789abcdef]")` (48).
    let pend = unsafe { sym_start.add(64) };

    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, range, spec) } {
        return buf;
    }
    let range = unsafe { &*(range as *const RangeStruct) };

    let mut p = unsafe { string_nocheck(sym_start, pend, c"[range ".as_ptr(), DEFAULT_STR_SPEC) };
    p = unsafe { hex_range(p, pend, range.start, range.end, RANGE_SPEC) };
    unsafe {
        if p < pend {
            *p = b']' as c_char;
        }
        p = p.add(1);
        if p < pend {
            *p = 0;
        } else {
            *pend.sub(1) = 0;
        }
    }

    unsafe { string_nocheck(buf, end, sym_start, spec) }
}

/// `resource_or_range(fmt, buf, end, ptr, spec)`, `lib/vsprintf.c:2296-2303`.
///
/// # Safety
/// As `resource_string`/`range_string` (whichever this dispatches to).
unsafe fn resource_or_range(fmt: *const c_char, buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    let (f0, f1) = unsafe { (*fmt as u8, *fmt.add(1) as u8) };
    if f0 == b'r' && f1 == b'a' {
        return unsafe { range_string(buf, end, ptr, spec, fmt) };
    }
    unsafe { resource_string(buf, end, ptr, spec, fmt) }
}

// ---------------------------------------------------------------------------
// hex_string/bitmap_string/bitmap_list_string/mac_address_string,
// vsprintf.c:1185-1349.
// ---------------------------------------------------------------------------

/// `hex_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1185-1234`.
///
/// # Safety
/// `addr` must be valid to read for at least `len` bytes (`len` computed
/// from `spec.field_width`, clamped to `[1, 64]` exactly as the C) when not
/// caught by `check_pointer`.
unsafe fn hex_string(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    if spec.field_width == 0 {
        return buf;
    }
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }
    let addr = addr as *const u8;

    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    let separator: u8 = match unsafe { *fmt.add(1) as u8 } {
        b'C' => b':',
        b'D' => b'-',
        b'N' => 0,
        _ => b' ',
    };

    let len = if spec.field_width > 0 {
        core::cmp::min(spec.field_width, 64)
    } else {
        1
    };

    for i in 0..len {
        // SAFETY: `addr` valid for `len <= 64` bytes, caller's contract.
        let byte = unsafe { *addr.add(i as usize) };
        // SAFETY: `hex_asc` (`lib/hexdump.c`) is the lowercase table,
        // `hex_asc_hi`/`hex_asc_lo`'s own table (`include/linux/hex.h:8-9`)
        // -- deliberately not `HEX_ASC_UPPER`, which is `number()`'s
        // separate uppercase table.
        if buf < end {
            unsafe { *buf = hex_asc[(byte >> 4) as usize] as c_char };
        }
        buf = unsafe { buf.add(1) };
        if buf < end {
            unsafe { *buf = hex_asc[(byte & 0xf) as usize] as c_char };
        }
        buf = unsafe { buf.add(1) };

        if separator != 0 && i != len - 1 {
            if buf < end {
                unsafe { *buf = separator as c_char };
            }
            buf = unsafe { buf.add(1) };
        }
    }

    buf
}

/// `bitmap_string(buf, end, bitmap, spec, fmt)`, `lib/vsprintf.c:1236-1278`.
///
/// # Safety
/// `bitmap` must be valid to read for at least `ALIGN(nr_bits, 32) / 8`
/// bytes (`nr_bits` from `spec.field_width`, clamped `>= 0`) when not
/// caught by `check_pointer`.
unsafe fn bitmap_string(buf: *mut c_char, end: *mut c_char, bitmap: *const c_void, spec: PrintfSpec, _fmt: *const c_char) -> *mut c_char {
    const CHUNKSZ: i32 = 32;
    let nr_bits = core::cmp::max(spec.field_width, 0);

    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, bitmap, spec) } {
        return buf;
    }
    let bitmap = bitmap as *const c_ulong;

    let mut spec = PrintfSpec { flags: F_SMALL | F_ZEROPAD, base: 16, precision: -1, field_width: 0 };
    let mut first = true;

    let mut chunksz = nr_bits & (CHUNKSZ - 1);
    if chunksz == 0 {
        chunksz = CHUNKSZ;
    }

    let mut i = ((nr_bits + CHUNKSZ - 1) & !(CHUNKSZ - 1)) - CHUNKSZ;
    while i >= 0 {
        let chunkmask: u64 = (1u64 << chunksz) - 1;
        let word = (i as usize) / (c_ulong::BITS as usize);
        let bit = (i as usize) % (c_ulong::BITS as usize);
        // SAFETY: `word < ALIGN(nr_bits, BITS_PER_LONG) / BITS_PER_LONG`,
        // caller's contract on `bitmap`'s length.
        let word_val = unsafe { *bitmap.add(word) } as u64;
        let val = ((word_val >> bit) & chunkmask) as u32;

        if !first {
            if buf < end {
                unsafe { *buf = b',' as c_char };
            }
            buf = unsafe { buf.add(1) };
        }
        first = false;

        spec.field_width = (chunksz + 3) / 4;
        buf = unsafe { number(buf, end, val as c_ulonglong, spec) };

        chunksz = CHUNKSZ;
        i -= CHUNKSZ;
    }
    buf
}

/// `bitmap_list_string(buf, end, bitmap, spec, fmt)`, `lib/vsprintf.c:1280-1308`.
/// `for_each_set_bitrange()`'s comma-operator loop (`include/linux/find.h:
/// 623-628`) translated directly: `b = find_next_bit(...)`,
/// `e = find_next_zero_bit(..., b+1)`, loop while `b < size`, then
/// `b = e + 1`.
///
/// # Safety
/// As `bitmap_string`.
unsafe fn bitmap_list_string(buf: *mut c_char, end: *mut c_char, bitmap: *const c_void, spec: PrintfSpec, _fmt: *const c_char) -> *mut c_char {
    let nr_bits = core::cmp::max(spec.field_width, 0) as usize;

    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, bitmap, spec) } {
        return buf;
    }
    let bitmap = bitmap as *const usize;

    let mut first = true;
    let mut b: usize = 0;
    loop {
        // SAFETY: `find_next_bit`/`find_next_zero_bit`'s own contract:
        // `bitmap` valid for `nr_bits` bits, `b <= nr_bits` (`b` starts at
        // 0 and is only ever set to `e + 1` where `e <= nr_bits`).
        b = unsafe { _find_next_bit(bitmap, nr_bits, b) };
        let e = unsafe { _find_next_zero_bit(bitmap, nr_bits, b + 1) };
        if b >= nr_bits {
            break;
        }

        if !first {
            if buf < end {
                unsafe { *buf = b',' as c_char };
            }
            buf = unsafe { buf.add(1) };
        }
        first = false;

        buf = unsafe { number(buf, end, b as c_ulonglong, DEFAULT_DEC_SPEC) };
        if e != b + 1 {
            if buf < end {
                unsafe { *buf = b'-' as c_char };
            }
            buf = unsafe { buf.add(1) };
            buf = unsafe { number(buf, end, (e - 1) as c_ulonglong, DEFAULT_DEC_SPEC) };
        }

        b = e + 1;
    }
    buf
}

/// `mac_address_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1310-1349`.
///
/// # Safety
/// `addr` must be valid to read for at least 6 bytes when not caught by
/// `check_pointer`.
unsafe fn mac_address_string(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }
    let addr = addr as *const u8;

    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    let (f0, f1) = unsafe { (*fmt as u8, *fmt.add(1) as u8) };
    let (separator, reversed) = match f1 {
        b'F' => (b'-', false),
        b'R' => (b':', true),
        _ => (b':', false),
    };

    let mut mac_addr = [0u8; 18]; // sizeof("xx:xx:xx:xx:xx:xx")
    let mut p = mac_addr.as_mut_ptr();
    for i in 0..6usize {
        // SAFETY: `addr` valid for 6 bytes, caller's contract.
        let byte = unsafe { *addr.add(if reversed { 5 - i } else { i }) };
        // SAFETY: `p` has room: at most `6*2 + 5*1 + 1 == 18` bytes total.
        // `hex_byte_pack()`'s own table is `hex_asc` (lowercase), same as
        // `hex_string()` above -- not `HEX_ASC_UPPER`.
        unsafe {
            *p = hex_asc[(byte >> 4) as usize];
            p = p.add(1);
            *p = hex_asc[(byte & 0xf) as usize];
            p = p.add(1);
        }
        if f0 == b'M' && i != 5 {
            unsafe {
                *p = separator;
                p = p.add(1);
            }
        }
    }
    unsafe { *p = 0 };

    unsafe { string_nocheck(buf, end, mac_addr.as_ptr() as *const c_char, spec) }
}

// ---------------------------------------------------------------------------
// ip4_string/ip6_compressed_string/ip6_string/ip6_addr_string[_sa]/
// ip4_addr_string[_sa]/ip_addr_string/escaped_string, vsprintf.c:1351-1714.
// ---------------------------------------------------------------------------

/// `hex_byte_pack(buf, byte)`, `include/linux/hex.h:11-15` -- lowercase
/// (`hex_asc`).
///
/// # Safety
/// `buf` valid for writes for at least 2 bytes.
unsafe fn hex_byte_pack(buf: *mut c_char, byte: u8) -> *mut c_char {
    unsafe {
        *buf = hex_asc[(byte >> 4) as usize] as c_char;
        *buf.add(1) = hex_asc[(byte & 0xf) as usize] as c_char;
        buf.add(2)
    }
}

/// `hex_byte_pack_upper(buf, byte)`, `include/linux/hex.h:21-26`.
///
/// # Safety
/// As `hex_byte_pack`.
unsafe fn hex_byte_pack_upper(buf: *mut c_char, byte: u8) -> *mut c_char {
    unsafe {
        *buf = HEX_ASC_UPPER[(byte >> 4) as usize] as c_char;
        *buf.add(1) = HEX_ASC_UPPER[(byte & 0xf) as usize] as c_char;
        buf.add(2)
    }
}

/// `isalpha(c)`, `include/linux/ctype.h:26` (`_U|_L == 0x03`).
#[inline]
fn isalpha_byte(c: u8) -> bool {
    // SAFETY: `_ctype` is a fixed 256-entry table, `c as usize < 256`.
    (unsafe { _ctype[c as usize] } & 0x03) != 0
}

/// `ntohs`/`ntohl`: this project's only target is little-endian
/// (`x86_64`), so converting a big-endian-stored 16/32-bit value that was
/// read as a plain (native/LE) integer is exactly a byte swap -- verified
/// against the same "assume LE, document it" convention `decpair`'s
/// `cpu_to_le16`-as-identity treatment already uses.
#[inline]
fn ntohs(x: u16) -> u16 {
    x.swap_bytes()
}
#[inline]
fn ntohl(x: u32) -> u32 {
    x.swap_bytes()
}

/// `ip4_string(p, addr, fmt)`, `lib/vsprintf.c:1351-1399`. The
/// `__BIG_ENDIAN` arm of the `'h'` case is dead on this project's only
/// target (`x86_64`, little-endian) -- same treatment as `put_dec`'s own
/// 64-bit-only fork; implemented directly as the `'l'` case's `index=3,
/// step=-1`, not `#[cfg]`-gated (this is an arch check, not a Kconfig
/// symbol).
///
/// # Safety
/// `addr` valid to read for 4 bytes. `p` valid to write for at least 16
/// bytes (`"255.255.255.255\0"`). `fmt` valid to read for at least 3 bytes.
unsafe fn ip4_string(p: *mut c_char, addr: *const u8, fmt: *const c_char) -> *mut c_char {
    // SAFETY: caller's contract.
    let (f0, f2) = unsafe { (*fmt as u8, *fmt.add(2) as u8) };
    let leading_zeros = f0 == b'i';
    let (mut index, step): (i32, i32) = match f2 {
        b'h' => (3, -1), // __BIG_ENDIAN dead here, see doc comment.
        b'l' => (3, -1),
        _ => (0, 1), // 'n', 'b', default.
    };

    let mut p = p;
    for i in 0..4 {
        let mut temp = [0u16; 2]; // 4 bytes, 2-aligned, put_dec_trunc8's contract.
        let temp_bytes = temp.as_mut_ptr() as *mut u8;
        // SAFETY: caller's contract, `0 <= index <= 3`.
        let byte = unsafe { *addr.add(index as usize) };
        let end_ptr = unsafe { put_dec_trunc8(temp_bytes, byte as c_uint) };
        // `int digits`, signed, in the C -- deliberately not `usize`: the
        // `while (digits--)` idiom below transiently computes `0 - 1`
        // (discarded immediately, the loop exits without using it), which
        // is fine for a signed C `int` but panics on overflow-checked
        // `usize`. Caught by exactly this differential harness's
        // `-C overflow-checks=on` build.
        let mut digits: i32 = (end_ptr as usize as isize - temp_bytes as usize as isize) as i32;

        if leading_zeros {
            if digits < 3 {
                unsafe { *p = b'0' as c_char };
                p = unsafe { p.add(1) };
            }
            if digits < 2 {
                unsafe { *p = b'0' as c_char };
                p = unsafe { p.add(1) };
            }
        }
        // "reverse the digits in the quad" -- `while (digits--) *p++ =
        // temp[digits];`: the controlling expression's decrement happens
        // before the body runs, so the body indexes with the
        // POST-decrement value.
        loop {
            let before = digits;
            digits -= 1;
            if before == 0 {
                break;
            }
            // SAFETY: `digits < 4`, within `temp_bytes`'s bounds.
            unsafe { *p = *temp_bytes.add(digits as usize) as c_char };
            p = unsafe { p.add(1) };
        }
        if i < 3 {
            unsafe { *p = b'.' as c_char };
            p = unsafe { p.add(1) };
        }
        index += step;
    }
    unsafe { *p = 0 };
    p
}

/// `ipv6_addr_v4mapped(a)`, `include/net/ipv6.h:773-784`. `static inline`
/// in the real header -- NO linkable C symbol exists for it at all, unlike
/// most of this file's cross-file dependencies. Originally declared here
/// as an `extern "C" fn`, which type-checked and even passed this crate's
/// own userspace differential (which stubs both functions rather than
/// linking a real kernel), but failed a REAL kernel link with "undefined
/// symbol: ipv6_addr_v4mapped" -- caught by a peer session doing a full
/// build-fast/build-full link before starting other work, not by this
/// crate's own verification. Reimplemented directly against the 16-byte
/// blob instead of adding a retained-C thunk for two trivial bit tests.
/// Mirrors the header's `#else` (non-`CONFIG_HAVE_EFFICIENT_UNALIGNED_
/// ACCESS`) arm exactly -- bitwise equivalent to the single-64-bit-read
/// arm for an equals-zero check regardless of which the real header
/// compiles, so which arm is reproduced doesn't matter here.
fn ipv6_addr_v4mapped(a: &[u8; 16]) -> bool {
    let w0 = u32::from_ne_bytes([a[0], a[1], a[2], a[3]]);
    let w1 = u32::from_ne_bytes([a[4], a[5], a[6], a[7]]);
    let w2 = u32::from_ne_bytes([a[8], a[9], a[10], a[11]]);
    ((w0 | w1) | (w2 ^ 0x0000ffffu32.swap_bytes())) == 0
}

/// `ipv6_addr_is_isatap(addr)`, `include/net/addrconf.h:519-522`. Same
/// static-inline-only situation as `ipv6_addr_v4mapped` above, same fix.
fn ipv6_addr_is_isatap(a: &[u8; 16]) -> bool {
    let w2 = u32::from_ne_bytes([a[8], a[9], a[10], a[11]]);
    (w2 | 0x02000000u32.swap_bytes()) == 0x02005EFEu32.swap_bytes()
}

/// `ip6_compressed_string(p, addr)`, `lib/vsprintf.c:1401-1482`.
///
/// # Safety
/// `addr` valid to read for 16 bytes. `p` valid to write for at least 46
/// bytes (`"xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255\0"`).
// `needcolon = false;` right before the `colonpos` branch's `continue` is a
// faithful mirror of the C's own harmless dead store (overwritten by the
// next iteration's `needcolon = true;` before ever being read) -- kept
// for the direct correspondence rather than restructured away.
#[allow(unused_assignments)]
unsafe fn ip6_compressed_string(p: *mut c_char, addr: *const u8) -> *mut c_char {
    let mut in6 = [0u8; 16];
    // SAFETY: caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(addr, in6.as_mut_ptr(), 16) };

    let use_ipv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

    let range: i32 = if use_ipv4 { 6 } else { 8 };
    // `s6_addr16[i]`, converted host-order (raw big-endian bytes -- this
    // read IS the `ntohs()` C applies explicitly at use, collapsed into
    // one step; see the doc comment on the emit loop below).
    let word16 = |i: i32| -> u16 { u16::from_be_bytes([in6[2 * i as usize], in6[2 * i as usize + 1]]) };

    let mut zerolength = [0i32; 8];
    for i in 0..range {
        for j in i..range {
            if word16(j) != 0 {
                break;
            }
            zerolength[i as usize] += 1;
        }
    }
    let mut longest = 1;
    let mut colonpos: i32 = -1;
    for i in 0..range {
        if zerolength[i as usize] > longest {
            longest = zerolength[i as usize];
            colonpos = i;
        }
    }
    if longest == 1 {
        colonpos = -1;
    }

    let mut p = p;
    let mut needcolon = false;
    // `for (i = 0; i < range; i++)` with a `continue` after `i += longest
    // - 1` inside the body -- the for-loop's own `i++` still applies after
    // `continue`, so the net skip is `longest`, not `longest - 1`.
    // Translated as an explicit `while` with the increment written at
    // every exit point, matching that exactly.
    let mut i: i32 = 0;
    while i < range {
        if i == colonpos {
            if needcolon || i == 0 {
                unsafe { *p = b':' as c_char };
                p = unsafe { p.add(1) };
            }
            unsafe { *p = b':' as c_char };
            p = unsafe { p.add(1) };
            needcolon = false;
            i += longest - 1;
            i += 1;
            continue;
        }
        if needcolon {
            unsafe { *p = b':' as c_char };
            p = unsafe { p.add(1) };
            needcolon = false;
        }
        let word = word16(i);
        let hi = (word >> 8) as u8;
        let lo = (word & 0xff) as u8;
        if hi != 0 {
            if hi > 0x0f {
                p = unsafe { hex_byte_pack(p, hi) };
            } else {
                unsafe { *p = hex_asc_lo(hi) };
                p = unsafe { p.add(1) };
            }
            p = unsafe { hex_byte_pack(p, lo) };
        } else if lo > 0x0f {
            p = unsafe { hex_byte_pack(p, lo) };
        } else {
            unsafe { *p = hex_asc_lo(lo) };
            p = unsafe { p.add(1) };
        }
        needcolon = true;
        i += 1;
    }

    if use_ipv4 {
        if needcolon {
            unsafe { *p = b':' as c_char };
            p = unsafe { p.add(1) };
        }
        // SAFETY: `in6[12..16]` is the trailing 4 bytes of a 16-byte array.
        p = unsafe { ip4_string(p, in6.as_ptr().add(12), c"I4".as_ptr()) };
    }
    unsafe { *p = 0 };
    p
}

/// `hex_asc_lo(x)`, `include/linux/hex.h:8`.
#[inline]
fn hex_asc_lo(x: u8) -> c_char {
    // SAFETY: `_ctype`-style fixed 16-entry extern table read.
    (unsafe { hex_asc[(x & 0x0f) as usize] }) as c_char
}

/// `ip6_string(p, addr, fmt)`, `lib/vsprintf.c:1484-1498`.
///
/// # Safety
/// `addr` valid to read for 16 bytes. `p` valid to write for at least 40
/// bytes (`"xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx\0"`, the uncompressed
/// form -- always shorter than `ip6_compressed_string`'s own bound, so
/// every real call site's shared buffer sizing already covers it).
unsafe fn ip6_string(p: *mut c_char, addr: *const u8, fmt: *const c_char) -> *mut c_char {
    let mut p = p;
    let mut addr = addr;
    // SAFETY: caller's contract.
    let colons = unsafe { *fmt as u8 == b'I' };
    for i in 0..8 {
        // SAFETY: `addr` valid for 16 bytes total, 2 read per iteration.
        let b0 = unsafe { *addr };
        addr = unsafe { addr.add(1) };
        let b1 = unsafe { *addr };
        addr = unsafe { addr.add(1) };
        p = unsafe { hex_byte_pack(p, b0) };
        p = unsafe { hex_byte_pack(p, b1) };
        if colons && i != 7 {
            unsafe { *p = b':' as c_char };
            p = unsafe { p.add(1) };
        }
    }
    unsafe { *p = 0 };
    p
}

/// `ip6_addr_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1500-1512`.
///
/// # Safety
/// As `string_nocheck`; `addr` valid to read for 16 bytes.
unsafe fn ip6_addr_string(buf: *mut c_char, end: *mut c_char, addr: *const u8, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut ip6_addr = [0u8; 47]; // sizeof("xxxx:...:255.255.255.255")
    let sym = ip6_addr.as_mut_ptr() as *mut c_char;
    // SAFETY: caller's contract.
    let (f0, f2) = unsafe { (*fmt as u8, *fmt.add(2) as u8) };
    if f0 == b'I' && f2 == b'c' {
        unsafe { ip6_compressed_string(sym, addr) };
    } else {
        unsafe { ip6_string(sym, addr, fmt) };
    }
    unsafe { string_nocheck(buf, end, sym, spec) }
}

/// `ip4_addr_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1514-1523`.
///
/// # Safety
/// As `string_nocheck`; `addr` valid to read for 4 bytes.
unsafe fn ip4_addr_string(buf: *mut c_char, end: *mut c_char, addr: *const u8, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut ip4_addr = [0u8; 16]; // sizeof("255.255.255.255")
    let sym = ip4_addr.as_mut_ptr() as *mut c_char;
    unsafe { ip4_string(sym, addr, fmt) };
    unsafe { string_nocheck(buf, end, sym, spec) }
}

/// Mirrors `struct sockaddr_in6`, `include/uapi/linux/in6.h:50-56`. Field
/// order matches the C exactly, so `#[repr(C)]` reproduces its layout --
/// no manual offsets needed (checked: `family`(2)+`port`(2) pack into the
/// first 4 bytes with no gap, `flowinfo` is already 4-aligned, `addr` 8-
/// and `scope_id` 4-aligned, so the natural `repr(C)` layout has no
/// padding the C doesn't also have).
#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,     // __be16
    flowinfo: u32, // __be32
    addr: [u8; 16],
    scope_id: u32,
}

const IPV6_FLOWINFO_MASK: u32 = 0x0FFFFFFF;

/// `ip6_addr_string_sa(buf, end, sa, spec, fmt)`, `lib/vsprintf.c:1525-1585`.
///
/// # Safety
/// `sa` must be a valid `SockaddrIn6`. `fmt` valid to read past its first
/// `'S'` suffix letters up to (and including) the first non-alphabetic
/// byte (every real call site's format string NUL-terminates, satisfying
/// this).
unsafe fn ip6_addr_string_sa(buf: *mut c_char, end: *mut c_char, sa: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let sa = sa as *const SockaddrIn6;
    let mut have_p = false;
    let mut have_s = false;
    let mut have_f = false;
    let mut have_c = false;

    let mut ip6_addr = [0u8; 78];
    let sym_start = ip6_addr.as_mut_ptr() as *mut c_char;
    // SAFETY: `ip6_addr` is 78 bytes.
    let pend = unsafe { sym_start.add(78) };
    // SAFETY: caller's contract.
    let addr = unsafe { (*sa).addr.as_ptr() };

    // SAFETY: caller's contract, `fmt` at least 1 byte (`'I'`/`'i'`).
    let f0 = unsafe { *fmt as u8 };
    let fmt6: [u8; 2] = [f0, b'6'];

    // `fmt++;` then `while (isalpha(*++fmt))`: `fmt` starts at the original
    // `fmt[1]` (`'S'`) after the first increment; the loop's own
    // pre-increment then walks `fmt[2]`, `fmt[3]`, ... testing each.
    let mut fp = unsafe { fmt.add(1) };
    loop {
        fp = unsafe { fp.add(1) };
        // SAFETY: NUL-terminated `fmt`, contract above.
        let c = unsafe { *fp as u8 };
        if !isalpha_byte(c) {
            break;
        }
        match c {
            b'p' => have_p = true,
            b'f' => have_f = true,
            b's' => have_s = true,
            b'c' => have_c = true,
            _ => {}
        }
    }

    let have_bracket = have_p || have_s || have_f;
    let off: usize = if have_bracket {
        // SAFETY: `ip6_addr` is 78 bytes.
        unsafe { *sym_start = b'[' as c_char };
        1
    } else {
        0
    };

    let base = unsafe { sym_start.add(off) };
    let mut p = if fmt6[0] == b'I' && have_c {
        unsafe { ip6_compressed_string(base, addr) }
    } else {
        unsafe { ip6_string(base, addr, fmt6.as_ptr() as *const c_char) }
    };

    if have_bracket {
        unsafe { *p = b']' as c_char };
        p = unsafe { p.add(1) };
    }
    if have_p {
        unsafe { *p = b':' as c_char };
        p = unsafe { p.add(1) };
        let port = ntohs(unsafe { (*sa).port });
        p = unsafe { number(p, pend, port as c_ulonglong, spec) };
    }
    if have_f {
        unsafe { *p = b'/' as c_char };
        p = unsafe { p.add(1) };
        let flowinfo = ntohl(unsafe { (*sa).flowinfo }) & IPV6_FLOWINFO_MASK;
        p = unsafe { number(p, pend, flowinfo as c_ulonglong, spec) };
    }
    if have_s {
        unsafe { *p = b'%' as c_char };
        p = unsafe { p.add(1) };
        let scope_id = unsafe { (*sa).scope_id };
        p = unsafe { number(p, pend, scope_id as c_ulonglong, spec) };
    }
    unsafe { *p = 0 };

    unsafe { string_nocheck(buf, end, sym_start, spec) }
}

/// Mirrors `struct sockaddr_in`, `include/uapi/linux/in.h:260-268` --
/// fields up to `sin_addr` only (the trailing `__pad` is never read here,
/// so it doesn't need mirroring for this pointer-cast-and-read usage).
#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16, // __be16
    addr: u32, // __be32 (struct in_addr { s_addr })
}

/// `ip4_addr_string_sa(buf, end, sa, spec, fmt)`, `lib/vsprintf.c:1587-1620`.
///
/// # Safety
/// `sa` must be a valid `SockaddrIn`. `fmt` as `ip6_addr_string_sa`.
unsafe fn ip4_addr_string_sa(buf: *mut c_char, end: *mut c_char, sa: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let sa = sa as *const SockaddrIn;
    let mut have_p = false;

    let mut ip4_addr = [0u8; 23]; // sizeof("255.255.255.255")+sizeof(":12345")
    let pend = unsafe { ip4_addr.as_mut_ptr().add(23) as *mut c_char };
    // SAFETY: caller's contract; `addr` (a `__be32`) read as 4 raw bytes,
    // same convention `ip4_string` already expects.
    let addr = unsafe { &raw const (*sa).addr } as *const u8;

    let f0 = unsafe { *fmt as u8 };
    let mut fmt4: [u8; 3] = [f0, b'4', 0];

    let mut fp = unsafe { fmt.add(1) };
    loop {
        fp = unsafe { fp.add(1) };
        let c = unsafe { *fp as u8 };
        if !isalpha_byte(c) {
            break;
        }
        match c {
            b'p' => have_p = true,
            b'h' | b'l' | b'n' | b'b' => fmt4[2] = c,
            _ => {}
        }
    }

    let mut p = unsafe { ip4_string(ip4_addr.as_mut_ptr() as *mut c_char, addr, fmt4.as_ptr() as *const c_char) };
    if have_p {
        unsafe { *p = b':' as c_char };
        p = unsafe { p.add(1) };
        let port = ntohs(unsafe { (*sa).port });
        p = unsafe { number(p, pend, port as c_ulonglong, spec) };
    }
    unsafe { *p = 0 };

    unsafe { string_nocheck(buf, end, ip4_addr.as_ptr() as *const c_char, spec) }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// `ip_addr_string(buf, end, ptr, spec, fmt)`, `lib/vsprintf.c:1622-1655`.
///
/// # Safety
/// `ptr` must be valid for whichever of `SockaddrIn6`/`SockaddrIn`/a 16- or
/// 4-byte address it's read as, once past `check_pointer` -- exactly the
/// same trust boundary the C itself has (this function's contract is with
/// its callers, one layer up in `pointer()`, not something checkable here).
unsafe fn ip_addr_string(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, ptr, spec) } {
        return buf;
    }

    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    let f1 = unsafe { *fmt.add(1) as u8 };
    match f1 {
        b'6' => return unsafe { ip6_addr_string(buf, end, ptr as *const u8, spec, fmt) },
        b'4' => return unsafe { ip4_addr_string(buf, end, ptr as *const u8, spec, fmt) },
        b'S' => {
            // SAFETY: caller's contract: `ptr` is at least large enough
            // to read a `sa_family_t` at offset 0 -- the smallest of the
            // three union members the C itself relies on the same way.
            let family = unsafe { *(ptr as *const u16) };
            return match family {
                AF_INET => unsafe { ip4_addr_string_sa(buf, end, ptr, spec, fmt) },
                AF_INET6 => unsafe { ip6_addr_string_sa(buf, end, ptr, spec, fmt) },
                _ => unsafe { error_string(buf, end, c"(einval)".as_ptr(), spec) },
            };
        }
        _ => {}
    }

    // SAFETY: caller's contract, `fmt` at least 1 byte.
    let f0 = unsafe { *fmt as u8 };
    let msg = if f0 == b'i' { c"(%pi?)".as_ptr() } else { c"(%pI?)".as_ptr() };
    unsafe { error_string(buf, end, msg, spec) }
}

// ---------------------------------------------------------------------------
// escaped_string, vsprintf.c:1657-1714.
// ---------------------------------------------------------------------------

const ESCAPE_SPACE: c_uint = 1 << 0;
const ESCAPE_SPECIAL: c_uint = 1 << 1;
const ESCAPE_NULL: c_uint = 1 << 2;
const ESCAPE_OCTAL: c_uint = 1 << 3;
const ESCAPE_NP: c_uint = 1 << 4;
const ESCAPE_HEX: c_uint = 1 << 5;
const ESCAPE_ANY: c_uint = ESCAPE_SPACE | ESCAPE_OCTAL | ESCAPE_SPECIAL | ESCAPE_NULL;
const ESCAPE_ANY_NP: c_uint = ESCAPE_ANY | ESCAPE_NP;

/// `escaped_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1657-1714`.
///
/// # Safety
/// `addr` valid to read for `len` bytes (`len` from `spec.field_width`,
/// same as the C) when not caught by `check_pointer`. `fmt` valid to read
/// through its run of suffix letters up to a NUL or non-matching byte.
unsafe fn escaped_string(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    if spec.field_width == 0 {
        return buf;
    }
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }

    let mut flags: c_uint = 0;
    let mut count: usize = 1;
    loop {
        // SAFETY: caller's contract.
        let c = unsafe { *fmt.add(count) as u8 };
        count += 1;
        let matched = match c {
            b'a' => {
                flags |= ESCAPE_ANY;
                true
            }
            b'c' => {
                flags |= ESCAPE_SPECIAL;
                true
            }
            b'h' => {
                flags |= ESCAPE_HEX;
                true
            }
            b'n' => {
                flags |= ESCAPE_NULL;
                true
            }
            b'o' => {
                flags |= ESCAPE_OCTAL;
                true
            }
            b'p' => {
                flags |= ESCAPE_NP;
                true
            }
            b's' => {
                flags |= ESCAPE_SPACE;
                true
            }
            _ => false,
        };
        if !matched {
            break;
        }
    }
    if flags == 0 {
        flags = ESCAPE_ANY_NP;
    }

    let len = if spec.field_width < 0 { 1 } else { spec.field_width };

    let avail: c_int = if buf < end { ((end as usize) - (buf as usize)) as c_int } else { 0 };
    // SAFETY: `addr` valid for `len` bytes (caller's contract); `buf`
    // valid for `avail` bytes when `avail > 0` -- `string_escape_mem`'s own
    // contract, matching the C's `buf < end ? end - buf : 0` exactly.
    let written = unsafe { string_escape_mem(addr as *const c_char, len as usize, buf, avail as usize, flags, core::ptr::null()) };
    unsafe { buf.add(written as usize) }
}

// ---------------------------------------------------------------------------
// uuid_string, vsprintf.c:1735-1778.
// ---------------------------------------------------------------------------

const UUID_STRING_LEN: usize = 36;

/// `uuid_string(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1735-1778`.
///
/// # Safety
/// `addr` valid to read for 16 bytes (indexed through `index[]`, itself a
/// permutation of `0..16`) when not caught by `check_pointer`. `fmt` valid
/// to read at least 2 bytes.
unsafe fn uuid_string(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }
    let addr = addr as *const u8;

    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    let f1 = unsafe { *fmt.add(1) as u8 };
    let mut uc = false;
    let index: *const c_uchar = match f1 {
        b'L' => {
            uc = true;
            &raw const guid_index as *const c_uchar
        }
        b'l' => &raw const guid_index as *const c_uchar,
        b'B' => {
            uc = true;
            &raw const uuid_index as *const c_uchar
        }
        _ => &raw const uuid_index as *const c_uchar,
    };

    let mut uuid = [0u8; UUID_STRING_LEN + 1];
    let mut p = uuid.as_mut_ptr() as *mut c_char;
    for i in 0..16usize {
        // SAFETY: `index[i]` is a permutation entry `< 16`, `addr` valid
        // for 16 bytes (caller's contract).
        let byte = unsafe { *addr.add(*index.add(i) as usize) };
        p = if uc { unsafe { hex_byte_pack_upper(p, byte) } } else { unsafe { hex_byte_pack(p, byte) } };
        if matches!(i, 3 | 5 | 7 | 9) {
            unsafe { *p = b'-' as c_char };
            p = unsafe { p.add(1) };
        }
    }
    unsafe { *p = 0 };

    unsafe { string_nocheck(buf, end, uuid.as_ptr() as *const c_char, spec) }
}

// ---------------------------------------------------------------------------
// netdev_bits/fourcc_string/address_val, vsprintf.c:1780-1885.
// ---------------------------------------------------------------------------

/// `netdev_bits(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1780-1800`.
///
/// # Safety
/// `addr` valid to read for 8 bytes (`netdev_features_t` is `u64`) when
/// `fmt[1] == 'F'` and not caught by `check_pointer`.
unsafe fn netdev_bits(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }
    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    if unsafe { *fmt.add(1) as u8 } != b'F' {
        return unsafe { error_string(buf, end, c"(%pN?)".as_ptr(), spec) };
    }
    // SAFETY: `netdev_features_t` is `u64`; real call sites pass a
    // naturally-aligned `netdev_features_t *`, same trust the C's plain
    // dereference relies on.
    let num = unsafe { *(addr as *const u64) };
    unsafe { special_hex_number(buf, end, num, core::mem::size_of::<u64>() as c_int) }
}

/// `isascii(c)`, `include/linux/ctype.h:37`.
#[inline]
fn isascii_byte(c: u8) -> bool {
    c <= 0x7f
}
/// `isprint(c)`, `include/linux/ctype.h:30` (`_P|_U|_L|_D|_SP == 0x97`).
#[inline]
fn isprint_byte(c: u8) -> bool {
    (unsafe { _ctype[c as usize] } & 0x97) != 0
}

/// `fourcc_string(buf, end, fourcc, spec, fmt)`, `lib/vsprintf.c:1802-1860`.
/// `strcpy(p, "big-endian"/"little-endian")` -- written directly as byte
/// copies here rather than adding an `strcpy` extern for a single fixed
/// literal (this crate already has `strlen`/`strchr`/`strcspn`/`strspn`
/// externed for real cross-file uses; a one-off internal copy of a
/// compile-time-constant literal doesn't need a tenth).
///
/// # Safety
/// `fourcc` valid to read for 4 bytes (unaligned) when `fmt[1] == 'c'` and
/// not caught by `check_pointer`.
unsafe fn fourcc_string(buf: *mut c_char, end: *mut c_char, fourcc: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    if unsafe { *fmt.add(1) as u8 } != b'c' {
        return unsafe { error_string(buf, end, c"(%p4?)".as_ptr(), spec) };
    }
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, fourcc, spec) } {
        return buf;
    }

    // SAFETY: `fourcc` valid for 4 bytes, `get_unaligned()`'s own contract.
    let mut orig: u32 = unsafe { (fourcc as *const u32).read_unaligned() };
    // SAFETY: caller's contract, `fmt` at least 3 bytes when reaching here.
    let f2 = unsafe { *fmt.add(2) as u8 };
    let mut pixel_fmt = false;
    match f2 {
        b'h' => {
            // SAFETY: caller's contract, `fmt` at least 4 bytes.
            if unsafe { *fmt.add(3) as u8 } == b'R' {
                orig = orig.swap_bytes();
            }
        }
        b'l' => {} // cpu_to_le32 is identity on this little-endian target.
        b'b' => orig = orig.swap_bytes(),
        b'c' => pixel_fmt = true,
        _ => return unsafe { error_string(buf, end, c"(%p4?)".as_ptr(), spec) },
    }

    let val = if pixel_fmt { (orig & !(1u32 << 31)).swap_bytes() } else { orig };

    let mut output = [0u8; 32]; // sizeof("0123 little-endian (0x01234567)")
    let mut p = output.as_mut_ptr() as *mut c_char;
    for i in 0..4u32 {
        let c = (val >> ((3 - i) * 8)) as u8;
        unsafe { *p = if isascii_byte(c) && isprint_byte(c) { c as c_char } else { b'.' as c_char } };
        p = unsafe { p.add(1) };
    }

    if pixel_fmt {
        unsafe { *p = b' ' as c_char };
        p = unsafe { p.add(1) };
        let word: &[u8] = if (orig & (1u32 << 31)) != 0 { b"big-endian" } else { b"little-endian" };
        // SAFETY: `output` is 32 bytes; 4 (above) + up to 13 + margin below
        // fits with room to spare (checked against the C's own buffer
        // sizing, which this mirrors).
        unsafe { core::ptr::copy_nonoverlapping(word.as_ptr(), p as *mut u8, word.len()) };
        p = unsafe { p.add(word.len()) };
    }

    unsafe {
        *p = b' ' as c_char;
        p = p.add(1);
        *p = b'(' as c_char;
        p = p.add(1);
    }
    let out_end = unsafe { output.as_mut_ptr().add(32).sub(2) as *mut c_char };
    p = unsafe { special_hex_number(p, out_end, orig as c_ulonglong, core::mem::size_of::<u32>() as c_int) };
    unsafe {
        *p = b')' as c_char;
        p = p.add(1);
        *p = 0;
    }

    unsafe { string(buf, end, output.as_ptr() as *const c_char, spec) }
}

/// `address_val(buf, end, addr, spec, fmt)`, `lib/vsprintf.c:1862-1885`.
/// `dma_addr_t`/`phys_addr_t` are both `u64` on this project's only target
/// (`x86_64`: `CONFIG_ARCH_DMA_ADDR_T_64BIT`-equivalent and
/// `CONFIG_PHYS_ADDR_T_64BIT` both effectively always true; checked
/// against `include/linux/types.h`'s `#if`/`#else` forks, the 32-bit arms
/// dead here same as `put_dec`'s own). `fmt[1]`'s `'d'`-vs-`'p'`/default
/// switch is therefore never observable here: both arms read the same
/// `u64` at the same address and pass the same `size == 8` to
/// `special_hex_number` -- `fmt` is intentionally unused, not a dropped
/// dispatch.
///
/// # Safety
/// `addr` valid to read for 8 bytes when not caught by `check_pointer`.
unsafe fn address_val(buf: *mut c_char, end: *mut c_char, addr: *const c_void, spec: PrintfSpec, _fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, addr, spec) } {
        return buf;
    }
    // SAFETY: caller's contract, `fmt` at least 2 bytes; `dma_addr_t`/
    // `phys_addr_t` both `u64` here, naturally-aligned real call sites.
    let num = unsafe { *(addr as *const u64) };
    unsafe { special_hex_number(buf, end, num, core::mem::size_of::<u64>() as c_int) }
}

// ---------------------------------------------------------------------------
// format_flags/flags_string, vsprintf.c:2026-2051, 2121-2147.
// ---------------------------------------------------------------------------

/// `format_flags(buf, end, flags, names)`, `lib/vsprintf.c:2026-2051`.
///
/// # Safety
/// `names` must point at a `{0, NULL}`-sentinel-terminated array of
/// `TracePrintFlags` (`gfpflag_names`/`vmaflag_names`, the only two real
/// callers of this function in this pass -- `pageflag_names`, the third,
/// stays behind the deferred `format_page_flags` C call).
unsafe fn format_flags(buf: *mut c_char, end: *mut c_char, flags: c_ulong, names: *const TracePrintFlags) -> *mut c_char {
    let mut buf = buf;
    let mut flags = flags;
    let mut names = names;
    loop {
        // SAFETY: caller's contract: sentinel-terminated array.
        let name = unsafe { (*names).name };
        if flags == 0 || name.is_null() {
            break;
        }
        let mask = unsafe { (*names).mask };
        if (flags & mask) != mask {
            names = unsafe { names.add(1) };
            continue;
        }

        buf = unsafe { string(buf, end, name, DEFAULT_STR_SPEC) };

        flags &= !mask;
        if flags != 0 {
            if buf < end {
                unsafe { *buf = b'|' as c_char };
            }
            buf = unsafe { buf.add(1) };
        }
        names = unsafe { names.add(1) };
    }

    if flags != 0 {
        buf = unsafe { number(buf, end, flags as c_ulonglong, DEFAULT_FLAG_SPEC) };
    }
    buf
}

/// `flags_string(buf, end, flags_ptr, spec, fmt)`, `lib/vsprintf.c:2121-2147`.
/// The `'p'` (page-flags) case stays a direct call into the deferred C
/// `format_page_flags` -- see the module doc.
///
/// # Safety
/// `flags_ptr` valid to read for 8 bytes (`unsigned long`/`gfp_t`, both
/// word-sized) when not caught by `check_pointer`. `fmt` valid to read at
/// least 2 bytes.
unsafe fn flags_string(buf: *mut c_char, end: *mut c_char, flags_ptr: *const c_void, spec: PrintfSpec, fmt: *const c_char) -> *mut c_char {
    let mut buf = buf;
    if unsafe { check_pointer(&mut buf, end, flags_ptr, spec) } {
        return buf;
    }

    // SAFETY: caller's contract, `fmt` at least 2 bytes.
    match unsafe { *fmt.add(1) as u8 } {
        b'p' => {
            let flags = unsafe { *(flags_ptr as *const c_ulong) };
            unsafe { vsprintf_c_format_page_flags(buf, end, flags) }
        }
        b'v' => {
            let flags = unsafe { *(flags_ptr as *const c_ulong) };
            unsafe { format_flags(buf, end, flags, &raw const vmaflag_names) }
        }
        b'g' => {
            // SAFETY: `gfp_t` is `unsigned int` (`u32`); widened to
            // `c_ulong` exactly as the C's own `(__force unsigned
            // long)(*(gfp_t *)flags_ptr)` does.
            let flags = unsafe { *(flags_ptr as *const c_uint) } as c_ulong;
            unsafe { format_flags(buf, end, flags, &raw const gfpflag_names) }
        }
        _ => unsafe { error_string(buf, end, c"(%pG?)".as_ptr(), spec) },
    }
}

// ---------------------------------------------------------------------------
// skip_atoi, vsprintf.c:184-193. format_decode, vsprintf.c:2608-2789.
// ---------------------------------------------------------------------------

/// `isdigit(c)`, `include/linux/ctype.h:29` (`_D == 0x04`).
#[inline]
fn isdigit_byte(c: u8) -> bool {
    (unsafe { _ctype[c as usize] } & 0x04) != 0
}

/// `skip_atoi(s)`, `lib/vsprintf.c:184-193`. `*s` is advanced past the run
/// of digits consumed, matching the C's `const char **` out-param.
///
/// # Safety
/// `*s` must point into a NUL-terminated string whose first byte is a
/// digit (every real call site checks `isdigit(*fmt.str)` immediately
/// before calling this, same as the C).
unsafe fn skip_atoi(s: &mut *const c_char) -> c_int {
    let mut i: c_int = 0;
    loop {
        // SAFETY: caller's contract for the first pass; `isdigit_byte`
        // below gates every subsequent one, same as the C's `while`.
        let c = unsafe { **s } as u8;
        *s = unsafe { (*s).add(1) };
        i = i.wrapping_mul(10).wrapping_add(c as c_int - b'0' as c_int);
        if !isdigit_byte(unsafe { **s as u8 }) {
            break;
        }
    }
    i
}

/// Mirrors `struct format_state`, `lib/vsprintf.c:2732-2736`.
#[derive(Clone, Copy)]
struct FormatStateEntry {
    state: u8,
    size: u8,
    flags_or_double_size: u8,
    base: u8,
}
const FMT_STATE_ZERO: FormatStateEntry = FormatStateEntry { state: 0, size: 0, flags_or_double_size: 0, base: 0 };

/// `static const struct format_state lookup_state[256]`,
/// `lib/vsprintf.c:2737-2765`. This project's target is always LP64
/// (`x86_64`): `sizeof(long) == sizeof(long long) == sizeof(size_t) ==
/// sizeof(ptrdiff_t) == 8`, `sizeof(short) == 2`, `sizeof(char) == 1` --
/// the same fixed-width assumption `PrintfSpec`'s own `static_assert`
/// already relies on.
static LOOKUP_STATE: [FormatStateEntry; 256] = {
    let mut t = [FMT_STATE_ZERO; 256];
    // Length modifiers ("state" left 0 == FORMAT_STATE_NONE).
    t[b'l' as usize] = FormatStateEntry { state: 0, size: 8, flags_or_double_size: 8, base: 0 }; // long / long long
    t[b'L' as usize] = FormatStateEntry { state: 0, size: 8, flags_or_double_size: 0, base: 0 }; // long long
    t[b'h' as usize] = FormatStateEntry { state: 0, size: 2, flags_or_double_size: 1, base: 0 }; // short / char
    t[b'H' as usize] = FormatStateEntry { state: 0, size: 1, flags_or_double_size: 0, base: 0 }; // char
    t[b'z' as usize] = FormatStateEntry { state: 0, size: 8, flags_or_double_size: 0, base: 0 }; // size_t
    t[b't' as usize] = FormatStateEntry { state: 0, size: 8, flags_or_double_size: 0, base: 0 }; // ptrdiff_t

    // Non-numeric formats.
    t[b'c' as usize] = FormatStateEntry { state: FORMAT_STATE_CHAR, size: 0, flags_or_double_size: 0, base: 0 };
    t[b's' as usize] = FormatStateEntry { state: FORMAT_STATE_STR, size: 0, flags_or_double_size: 0, base: 0 };
    t[b'p' as usize] = FormatStateEntry { state: FORMAT_STATE_PTR, size: 0, flags_or_double_size: 0, base: 0 };
    t[b'%' as usize] = FormatStateEntry { state: FORMAT_STATE_PERCENT_CHAR, size: 0, flags_or_double_size: 0, base: 0 };

    // Numerics.
    t[b'o' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: 0, base: 8 };
    t[b'x' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: F_SMALL, base: 16 };
    t[b'X' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: 0, base: 16 };
    t[b'd' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: F_SIGN, base: 10 };
    t[b'i' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: F_SIGN, base: 10 };
    t[b'u' as usize] = FormatStateEntry { state: FORMAT_STATE_NUM, size: 0, flags_or_double_size: 0, base: 10 };
    // `%n` is deliberately absent -- falls through to the "unsupported
    // format" `WARN_ONCE` path below, same as the C.
    t
};

/// `format_decode(fmt, spec)`, `lib/vsprintf.c:2655-2789`. The C is
/// goto-based, with two labels (`precision:`, `qualifier:`) reached both
/// from the top of the function (normal fall-through) and from two early
/// "resume" checks at the very top (`fmt.state ==
/// FORMAT_STATE_WIDTH`/`FORMAT_STATE_PRECISION`, `vsnprintf`'s own re-entry
/// after fetching a `*`-width/precision argument). Translated with two
/// `bool` "already past this label" flags rather than restructuring the
/// control flow, so the point-by-point correspondence with the pristine
/// source stays checkable.
///
/// # Safety
/// `fmt.str_` must point into a NUL-terminated format string, positioned
/// consistently with `fmt.state` exactly as `vsnprintf`'s own call
/// discipline guarantees (first call: `state == FORMAT_STATE_NONE`,
/// `str_` at a fresh `%`-scan start; re-entry calls: `state ==
/// FORMAT_STATE_WIDTH`/`FORMAT_STATE_PRECISION`, `str_` immediately past
/// the `*` this same function returned early for).
unsafe fn format_decode(fmt: Fmt, spec: &mut PrintfSpec) -> Fmt {
    let mut fmt = fmt;
    let start = fmt.str_;
    let mut past_width = false;
    let mut past_precision = false;

    if fmt.state == FORMAT_STATE_WIDTH {
        if spec.field_width < 0 {
            spec.field_width = -spec.field_width;
            spec.flags |= F_LEFT;
        }
        fmt.state = FORMAT_STATE_NONE;
        past_width = true;
    } else if fmt.state == FORMAT_STATE_PRECISION {
        if spec.precision < 0 {
            spec.precision = 0;
        }
        fmt.state = FORMAT_STATE_NONE;
        past_width = true;
        past_precision = true;
    }

    if !past_width {
        fmt.state = FORMAT_STATE_NONE;

        // SAFETY: caller's contract, NUL-terminated.
        while unsafe { *fmt.str_ } != 0 {
            if unsafe { *fmt.str_ } == b'%' as c_char {
                break;
            }
            fmt.str_ = unsafe { fmt.str_.add(1) };
        }

        if fmt.str_ != start || unsafe { *fmt.str_ } == 0 {
            return fmt;
        }

        spec.flags = 0;
        loop {
            // "this also skips first '%'" -- pre-increment before reading.
            fmt.str_ = unsafe { fmt.str_.add(1) };
            let flag = spec_flag(unsafe { *fmt.str_ as u8 });
            spec.flags |= flag;
            if flag == 0 {
                break;
            }
        }

        spec.field_width = -1;
        if isdigit_byte(unsafe { *fmt.str_ as u8 }) {
            let mut s = fmt.str_;
            // SAFETY: just checked `isdigit`, caller's contract otherwise.
            let width = unsafe { skip_atoi(&mut s) };
            fmt.str_ = s;
            set_field_width(spec, width);
        } else if unsafe { *fmt.str_ } == b'*' as c_char {
            fmt.state = FORMAT_STATE_WIDTH;
            fmt.str_ = unsafe { fmt.str_.add(1) };
            return fmt;
        }
    }

    if !past_precision {
        spec.precision = -1;
        if unsafe { *fmt.str_ } == b'.' as c_char {
            fmt.str_ = unsafe { fmt.str_.add(1) };
            if isdigit_byte(unsafe { *fmt.str_ as u8 }) {
                let mut s = fmt.str_;
                let prec = unsafe { skip_atoi(&mut s) };
                fmt.str_ = s;
                set_precision(spec, prec);
            } else if unsafe { *fmt.str_ } == b'*' as c_char {
                fmt.state = FORMAT_STATE_PRECISION;
                fmt.str_ = unsafe { fmt.str_.add(1) };
                return fmt;
            }
        }
    }

    // qualifier:
    spec.base = 10;
    fmt.state = FORMAT_STATE_NUM;
    fmt.size = core::mem::size_of::<c_int>() as u8;

    // Deliberate divergence from the pristine C: the C's second lookup
    // (`p = lookup_state + *fmt.str;`) indexes with a plain (possibly
    // signed) `char`, not `(u8)` like the first lookup a few lines above
    // it -- a latent OOB-read risk for a negative `char` this Rust mirror
    // does not reproduce, indexing with `as u8` both times instead.
    let mut p = &LOOKUP_STATE[unsafe { *fmt.str_ as u8 } as usize];
    if p.size != 0 {
        fmt.size = p.size;
        // SAFETY: caller's contract, NUL-terminated (reading one byte past
        // a non-NUL `*fmt.str_` is safe: the string has at least the NUL
        // itself beyond any non-NUL byte).
        if p.flags_or_double_size != 0 && unsafe { *fmt.str_ } == unsafe { *fmt.str_.add(1) } {
            fmt.size = p.flags_or_double_size;
            fmt.str_ = unsafe { fmt.str_.add(1) };
        }
        fmt.str_ = unsafe { fmt.str_.add(1) };
        p = &LOOKUP_STATE[unsafe { *fmt.str_ as u8 } as usize];
    }
    if p.state != 0 {
        if p.base != 0 {
            spec.base = p.base;
        }
        spec.flags |= p.flags_or_double_size;
        fmt.state = p.state;
        fmt.str_ = unsafe { fmt.str_.add(1) };
        return fmt;
    }

    // SAFETY: `vsprintf_c_format_decode_invalid_warn` takes a plain `int`,
    // no preconditions beyond an ordinary FFI call.
    unsafe { vsprintf_c_format_decode_invalid_warn(*fmt.str_ as c_int) };
    fmt.state = FORMAT_STATE_INVALID;
    fmt
}

// ---------------------------------------------------------------------------
// pointer(), vsprintf.c:2369-2600 (doc comment) / 2505-2600 (body).
// ---------------------------------------------------------------------------

/// `pointer(fmt, buf, end, ptr, spec)`, `lib/vsprintf.c:2505-2600` -- the
/// full `%p` dispatch. Exported under a new name (`vsprintf_rs_pointer`,
/// not an upstream symbol -- `pointer()` was `static`, this crate boundary
/// didn't exist before) so the retained C file's `vsnprintf()`/
/// `vbin_printf()` (still C, see the module doc's point 1) can call into
/// it for their own `FORMAT_STATE_PTR` handling; `bstr_printf()` (this
/// crate, below) calls it directly.
///
/// `dereference_symbol_descriptor()` (the `'S'`/`'s'` case) is identity on
/// this project's only target: `CONFIG_HAVE_FUNCTION_DESCRIPTORS` is an
/// ia64/ppc64-ABI concept, never selected anywhere under `arch/x86`
/// (checked) -- implemented as identity, not `#[cfg]`-gated (this is an
/// arch-support fact, not a Kconfig symbol this project's two `.config`s
/// differ on).
///
/// `'g'` (`bdev_name`, `#ifdef CONFIG_BLOCK` upstream) is unconditional
/// here: `CONFIG_BLOCK=y` on both this project's `.config`s, checked
/// directly.
///
/// `'A'`'s own `IS_ENABLED(CONFIG_RUST)` guard is dropped: every config
/// this crate compiles under already has `CONFIG_RUST=y` by construction
/// (this file IS Rust code) -- the C's `!IS_ENABLED(CONFIG_RUST)` arm
/// (`WARN_ONCE` + `(%pA?)`) is dead here.
///
/// # Safety
/// `fmt` valid to read a NUL-terminated format string positioned at the
/// character right after `%p` (`pointer()`'s own contract, unchanged).
/// `buf`/`end` as `number`. `ptr` valid for whichever handler `*fmt`
/// selects -- each handler's own contract, mostly gated by
/// `check_pointer` at that handler's own top.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_pointer(fmt: *const c_char, buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    // SAFETY: caller's contract.
    let f0 = unsafe { *fmt as u8 };
    match f0 {
        b'S' | b's' | b'B' => unsafe { symbol_string(buf, end, ptr, spec, fmt) },
        b'R' | b'r' => unsafe { resource_or_range(fmt, buf, end, ptr, spec) },
        b'h' => unsafe { hex_string(buf, end, ptr, spec, fmt) },
        b'b' => {
            // SAFETY: caller's contract, `fmt` at least 2 bytes.
            if unsafe { *fmt.add(1) as u8 } == b'l' {
                unsafe { bitmap_list_string(buf, end, ptr, spec, fmt) }
            } else {
                unsafe { bitmap_string(buf, end, ptr, spec, fmt) }
            }
        }
        b'M' | b'm' => unsafe { mac_address_string(buf, end, ptr, spec, fmt) },
        b'I' | b'i' => unsafe { ip_addr_string(buf, end, ptr, spec, fmt) },
        b'E' => unsafe { escaped_string(buf, end, ptr, spec, fmt) },
        b'U' => unsafe { uuid_string(buf, end, ptr, spec, fmt) },
        b'V' => unsafe { vsprintf_c_va_format(buf, end, ptr, spec) },
        b'K' => unsafe { restricted_pointer(buf, end, ptr, spec) },
        b'N' => unsafe { netdev_bits(buf, end, ptr, spec, fmt) },
        b'4' => unsafe { fourcc_string(buf, end, ptr, spec, fmt) },
        b'a' => unsafe { address_val(buf, end, ptr, spec, fmt) },
        b'd' => unsafe { vsprintf_c_dentry_name(buf, end, ptr, spec, fmt) },
        b't' => unsafe { vsprintf_c_time_and_date(buf, end, ptr, spec, fmt) },
        b'C' => unsafe { vsprintf_c_clock(buf, end, ptr, spec, fmt) },
        b'D' => unsafe { vsprintf_c_file_dentry_name(buf, end, ptr, spec, fmt) },
        b'g' => unsafe { vsprintf_c_bdev_name(buf, end, ptr, spec, fmt) },
        b'G' => unsafe { flags_string(buf, end, ptr, spec, fmt) },
        b'O' => unsafe { vsprintf_c_device_node_string(buf, end, ptr, spec, fmt.add(1)) },
        b'f' => unsafe { vsprintf_c_fwnode_string(buf, end, ptr, spec, fmt.add(1)) },
        b'A' => unsafe { rust_fmt_argument(buf, end, ptr) },
        b'x' => unsafe { pointer_string(buf, end, ptr, spec) },
        b'e' => {
            // `%pe` with a non-`ERR_PTR` gets treated as plain `%p` --
            // `IS_ERR`, not `IS_ERR_OR_NULL` (NULL is not an err value, so
            // NULL under `%pe` goes through `default_pointer`, same as the
            // C).
            if !is_err_value(ptr as usize) {
                unsafe { default_pointer(buf, end, ptr, spec) }
            } else {
                unsafe { err_ptr(buf, end, ptr, spec) }
            }
        }
        b'u' | b'k' => {
            // SAFETY: caller's contract, `fmt` at least 2 bytes.
            if unsafe { *fmt.add(1) as u8 } == b's' {
                unsafe { string(buf, end, ptr as *const c_char, spec) }
            } else {
                unsafe { error_string(buf, end, c"(einval)".as_ptr(), spec) }
            }
        }
        _ => unsafe { default_pointer(buf, end, ptr, spec) },
    }
}

// ---------------------------------------------------------------------------
// Thin `vsprintf_rs_*` C-ABI wrappers. `vsnprintf()`/`vbin_printf()`
// (module doc point 1: stay C permanently, both still directly call
// `va_arg` inline in their own loop bodies) called `format_decode`/
// `number`/`set_field_width`/`set_precision`/`string`/`convert_num_spec`/
// `check_pointer_msg` directly as same-translation-unit `static`
// functions before this pass; now that those live here, the retained C
// file needs a named cross-object entry point for each. Each wrapper is
// the C signature exactly (raw pointers, `PrintfSpec` by value, matching
// its `#[repr(C, packed)]`/`static_assert`-pinned 8-byte layout) -- no
// `kabi_export!`/`kabi_rule!` on any of these: none were `EXPORT_SYMBOL`
// upstream (all were `static`), so this is ordinary same-subsystem
// cross-object linkage, the same category `get_cmdline` already is.
// ---------------------------------------------------------------------------

/// # Safety
/// `spec` valid for a read-write of one `PrintfSpec`. `fmt.str_` as
/// `format_decode`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_format_decode(fmt: Fmt, spec: *mut PrintfSpec) -> Fmt {
    // SAFETY: caller's contract.
    unsafe { format_decode(fmt, &mut *spec) }
}

/// # Safety
/// As `number`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_number(buf: *mut c_char, end: *mut c_char, num: c_ulonglong, spec: PrintfSpec) -> *mut c_char {
    unsafe { number(buf, end, num, spec) }
}

/// # Safety
/// `spec` valid for a read-write of one `PrintfSpec`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_set_field_width(spec: *mut PrintfSpec, width: c_int) {
    // SAFETY: caller's contract.
    unsafe { set_field_width(&mut *spec, width) }
}

/// # Safety
/// As `vsprintf_rs_set_field_width`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_set_precision(spec: *mut PrintfSpec, prec: c_int) {
    // SAFETY: caller's contract.
    unsafe { set_precision(&mut *spec, prec) }
}

/// # Safety
/// As `string`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_string(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    unsafe { string(buf, end, s, spec) }
}

/// No `# Safety` beyond an ordinary FFI call: `convert_num_spec` never
/// dereferences a pointer.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_convert_num_spec(val: c_uint, size: c_int, spec: PrintfSpec) -> c_ulonglong {
    convert_num_spec(val, size, spec)
}

/// # Safety
/// As `check_pointer_msg`: no preconditions (`ptr` is only ever compared,
/// never dereferenced).
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_check_pointer_msg(ptr: *const c_void) -> *const c_char {
    check_pointer_msg(ptr)
}

/// `check_pointer(buf, end, ptr, spec)`, `lib/vsprintf.c:714-726` -- needed
/// by several of the retained C deferred handlers (`dentry_name`,
/// `file_dentry_name`, `bdev_name`, `clock`) that call it directly, not
/// just through `string()`. Returns the C's own convention (`0`/`-EFAULT`),
/// not this file's internal `bool`.
///
/// # Safety
/// `buf` valid for a read-write of one `*mut c_char`. Otherwise as
/// `check_pointer`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_check_pointer(buf: *mut *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> c_int {
    /// `EFAULT`, `include/uapi/asm-generic/errno-base.h`.
    const EFAULT: c_int = 14;
    // SAFETY: caller's contract.
    let mut b = unsafe { *buf };
    let err = unsafe { check_pointer(&mut b, end, ptr, spec) };
    unsafe { *buf = b };
    if err {
        -EFAULT
    } else {
        0
    }
}

/// # Safety
/// As `widen_string`. Needed by `dentry_name`/`device_node_string`/
/// `fwnode_string` (still C, deferred), each of which calls it directly on
/// its own `buf - (buf - buf_start)`-shaped length, not just through
/// `string()`/`string_nocheck()`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_widen_string(buf: *mut c_char, n: c_int, end: *mut c_char, spec: PrintfSpec) -> *mut c_char {
    unsafe { widen_string(buf, n, end, spec) }
}

/// # Safety
/// As `error_string`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_error_string(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    unsafe { error_string(buf, end, s, spec) }
}

/// # Safety
/// As `string_nocheck`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_string_nocheck(buf: *mut c_char, end: *mut c_char, s: *const c_char, spec: PrintfSpec) -> *mut c_char {
    unsafe { string_nocheck(buf, end, s, spec) }
}

/// # Safety
/// As `ptr_to_id`. Needed by `clock()` (`%pC`, still C, deferred) for its
/// own `#else` (non-`CONFIG_COMMON_CLK`) arm's `return ptr_to_id(buf, end,
/// clk, spec);` -- the only arm that ever compiles on this project's
/// configs (`CONFIG_COMMON_CLK` unset on both, checked directly), since
/// that's a real `#ifdef`/`#else`, not an `IS_ENABLED()` runtime check.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_ptr_to_id(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    unsafe { ptr_to_id(buf, end, ptr, spec) }
}

// ---------------------------------------------------------------------------
// restricted_pointer() (%pK), vsprintf.c:857-904 -- the %pK seam.
// ---------------------------------------------------------------------------

/// The four terminal outcomes of `restricted_pointer()`'s `switch
/// (kptr_restrict)`, named by which of the three distinct C functions it
/// reaches -- NOT three flavors of one call, `default_pointer`/
/// `error_string`/`pointer_string` are genuinely different functions with
/// different argument shapes (`PkError`'s `field_width` is itself a
/// mutated 4th input, not expressible as a plain bool).
#[derive(Debug, PartialEq, Eq)]
enum RestrictedPointerDecision {
    /// `case 0`: `default_pointer(buf, end, ptr, spec)` -- hash the real
    /// pointer like plain `%p`.
    HashAsP,
    /// `case 1`, IRQ context: `error_string(buf, end, "pK-error", spec)`,
    /// with `spec.field_width` set to `2 * sizeof(ptr)` when the caller
    /// left it at `-1` (the C's own adjustment, done here because
    /// `error_string` only auto-adjusts `precision`, not `field_width`).
    PkError { field_width: i32 },
    /// `case 1`, not IRQ, credential check passed: `pointer_string(buf,
    /// end, ptr, spec)` with the REAL pointer.
    Real,
    /// `case 1` credential check failed, OR `case 2`/any other value:
    /// `pointer_string(buf, end, NULL, spec)`.
    Null,
}

/// Pure decision core of `restricted_pointer()`, `lib/vsprintf.c:863-901`.
/// Takes every input the impure wrapper below computed, decides which of
/// the four outcomes applies, and does nothing else -- no IRQ check, no
/// credential check, no I/O. This is what the 12-case decision matrix
/// tests directly.
///
/// `may_reveal` is `Option<bool>`, not `bool`: `None` means "the
/// credential check legitimately never ran" (either `kptr_restrict != 1`,
/// or IRQ context made it unsafe to run at all) -- NOT a placeholder for
/// "unknown, assume false". The one call site below only ever passes
/// `None` when this function's own `irq`/`kptr_restrict` inputs already
/// guarantee the `Some(_)` branch is never consulted; if some OTHER
/// caller ever violates that and reaches here with `kptr_restrict == 1`,
/// `irq == false`, `may_reveal == None`, the fail-safe (not fail-open)
/// choice is `Null`, matching "don't leak on uncertainty" -- silently
/// falling back to `Real` here would be exactly the kind of bug this
/// seam's whole redesign exists to prevent.
fn restricted_pointer_decision(kptr_restrict_val: i32, irq: bool, may_reveal: Option<bool>, field_width: i32) -> RestrictedPointerDecision {
    match kptr_restrict_val {
        0 => RestrictedPointerDecision::HashAsP,
        1 => {
            if irq {
                let field_width = if field_width == -1 {
                    2 * core::mem::size_of::<*const c_void>() as i32
                } else {
                    field_width
                };
                RestrictedPointerDecision::PkError { field_width }
            } else {
                match may_reveal {
                    Some(true) => RestrictedPointerDecision::Real,
                    Some(false) | None => RestrictedPointerDecision::Null,
                }
            }
        }
        _ => RestrictedPointerDecision::Null,
    }
}

/// `restricted_pointer(buf, end, ptr, spec)`, `lib/vsprintf.c:859-904`.
/// The impure wrapper: computes `irq` unconditionally (cheap, side-effect-
/// free, safe even in NMI), and computes `may_reveal` ONLY when
/// `kptr_restrict == 1 && !irq` -- reproducing the C's own comment
/// verbatim: "kptr_restrict==1 cannot be used in IRQ context because its
/// test for CAP_SYSLOG would be meaningless", which requires the IRQ
/// check to run BEFORE `current_cred()`/`has_capability_noaudit()` are
/// touched AT ALL, not just before their result is used --
/// `has_capability_noaudit()` still has real RCU/LSM-hook side effects
/// despite "noaudit" only suppressing the audit record, and `current`
/// itself is meaningless in NMI.
///
/// # Safety
/// As `pointer_string`/`error_string`/`default_pointer`.
unsafe fn restricted_pointer(buf: *mut c_char, end: *mut c_char, ptr: *const c_void, spec: PrintfSpec) -> *mut c_char {
    // SAFETY: no preconditions, always safe to call (including in NMI).
    let irq = unsafe { vsprintf_c_in_irq_context() };
    // SAFETY: plain `extern "C"` global, see `ptr_to_hashval_impl`'s own
    // comment on this style of read.
    let kr = unsafe { core::ptr::read_volatile(&raw const kptr_restrict) };
    let may_reveal = if kr == 1 && !irq {
        // SAFETY: only reached when `!irq`, matching this function's own
        // contract with `vsprintf_c_restricted_pointer_cred_ok` (never
        // called from IRQ/NMI context).
        Some(unsafe { vsprintf_c_restricted_pointer_cred_ok() })
    } else {
        None
    };

    match restricted_pointer_decision(kr, irq, may_reveal, spec.field_width) {
        RestrictedPointerDecision::HashAsP => unsafe { default_pointer(buf, end, ptr, spec) },
        RestrictedPointerDecision::PkError { field_width } => {
            let mut spec = spec;
            spec.field_width = field_width;
            unsafe { error_string(buf, end, c"pK-error".as_ptr(), spec) }
        }
        RestrictedPointerDecision::Real => unsafe { pointer_string(buf, end, ptr, spec) },
        RestrictedPointerDecision::Null => unsafe { pointer_string(buf, end, core::ptr::null(), spec) },
    }
}

/// Exposes `restricted_pointer_decision()`'s pure core to the userspace
/// differential harness (`port/test/vsprintf/`) without exposing the
/// impure wrapper's IRQ/credential side effects, which cannot run (and
/// would be meaningless) outside a real kernel. `RestrictedPointerDecision`
/// is encoded as a plain `c_int` (0=HashAsP, 1=PkError, 2=Real, 3=Null),
/// and the (possibly-adjusted) `field_width` is always written out
/// (unchanged from the input for the non-`PkError` variants) so the
/// harness can check that value too.
///
/// # Safety
/// `out_field_width` must be valid for a write of one `c_int`.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_restricted_pointer_decision(
    kptr_restrict_val: c_int,
    irq: bool,
    may_reveal_present: bool,
    may_reveal_value: bool,
    field_width: c_int,
    out_field_width: *mut c_int,
) -> c_int {
    let may_reveal = if may_reveal_present { Some(may_reveal_value) } else { None };
    let decision = restricted_pointer_decision(kptr_restrict_val, irq, may_reveal, field_width);
    let (tag, out_fw) = match decision {
        RestrictedPointerDecision::HashAsP => (0, field_width),
        RestrictedPointerDecision::PkError { field_width } => (1, field_width),
        RestrictedPointerDecision::Real => (2, field_width),
        RestrictedPointerDecision::Null => (3, field_width),
    };
    // SAFETY: caller's contract.
    unsafe { *out_field_width = out_fw };
    tag
}

/// # Safety
/// As `format_flags`. Needed by `format_page_flags()` (`%pGp`, still C,
/// deferred) for its own `format_flags(buf, end, main_flags,
/// pageflag_names)` call -- `pageflag_names` (`mm/debug.c`) is a different
/// `{0, NULL}`-terminated table than `gfpflag_names`/`vmaflag_names`, not
/// declared in this file at all (this function never otherwise touches
/// it), so the retained C passes its own pointer straight through.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_rs_format_flags(buf: *mut c_char, end: *mut c_char, flags: c_ulong, names: *const TracePrintFlags) -> *mut c_char {
    unsafe { format_flags(buf, end, flags, names) }
}

// ---------------------------------------------------------------------------
// bstr_printf, vsprintf.c:3252-3412. `CONFIG_BINARY_PRINTF` is `=y` on
// build-full ONLY (checked directly against both `.config`s) -- a real
// RAISE-1 fork; `vbin_printf()` stays C permanently (module doc point 1)
// and keeps its own `#ifdef CONFIG_BINARY_PRINTF` unchanged, but this
// function and its private `get_arg`-equivalents only exist under the
// same config here too, matching the C's `#endif /* CONFIG_BINARY_PRINTF
// */` at `vsprintf.c:3414` exactly.
// ---------------------------------------------------------------------------

/// `isalnum(c)`, `include/linux/ctype.h:25` (`_U|_L|_D == 0x07`).
#[cfg(CONFIG_BINARY_PRINTF)]
#[inline]
fn isalnum_byte(c: u8) -> bool {
    (unsafe { _ctype[c as usize] } & 0x07) != 0
}

/// `get_arg(type)`'s 4-byte-or-smaller branch, `lib/vsprintf.c:3268-3281`
/// -- `args = PTR_ALIGN(args, sizeof(type)); value = *(typeof(type)
/// *)args; args += sizeof(type);`, specialized to `size==4`
/// (`int`/`unsigned int`).
///
/// # Safety
/// `*args` must have at least 4 more readable bytes after 4-byte
/// alignment -- `bin_buf`'s own contract, sized by the matching
/// `vbin_printf()` call for the same format string (still C, this
/// crate never constructs a `bin_buf` itself).
#[cfg(CONFIG_BINARY_PRINTF)]
unsafe fn get_arg_i32(args: &mut *const c_uchar) -> i32 {
    let aligned = ((*args as usize) + 3) & !3usize;
    let p = aligned as *const c_uchar;
    // SAFETY: caller's contract.
    let v = unsafe { (p as *const i32).read_unaligned() };
    *args = unsafe { p.add(4) };
    v
}

/// `get_arg(char)`, `lib/vsprintf.c:3268-3281` (`sizeof(char)==1`,
/// `PTR_ALIGN` to 1 is a no-op).
///
/// # Safety
/// As `get_arg_i32`, for 1 byte.
#[cfg(CONFIG_BINARY_PRINTF)]
unsafe fn get_arg_u8(args: &mut *const c_uchar) -> u8 {
    let v = unsafe { **args };
    *args = unsafe { (*args).add(1) };
    v
}

/// `get_arg(type)`'s 8-byte branch, `lib/vsprintf.c:3271-3274` --
/// aligns to `sizeof(u32)` (4 bytes, NOT 8) and reads two separate
/// 32-bit halves (`*(u32*)&value = *(u32*)args; *((u32*)&value+1) =
/// *(u32*)(args+4);`), the mirror image of `vbin_printf`'s own
/// `save_arg`'s 8-byte write -- both sides agree on this exact layout,
/// low 32 bits first, matching this project's little-endian-only
/// target.
///
/// # Safety
/// `*args` must have at least 8 more readable bytes after 4-byte
/// alignment, same contract as `get_arg_i32`.
#[cfg(CONFIG_BINARY_PRINTF)]
unsafe fn get_arg_u64(args: &mut *const c_uchar) -> u64 {
    let aligned = ((*args as usize) + 3) & !3usize;
    let p = aligned as *const c_uchar;
    // SAFETY: caller's contract.
    let lo = unsafe { (p as *const u32).read_unaligned() };
    let hi = unsafe { (p.add(4) as *const u32).read_unaligned() };
    *args = unsafe { p.add(8) };
    ((hi as u64) << 32) | (lo as u64)
}

/// `get_arg(void *)`, the 8-byte branch (pointers are 8 bytes on this
/// project's only target).
///
/// # Safety
/// As `get_arg_u64`.
#[cfg(CONFIG_BINARY_PRINTF)]
unsafe fn get_arg_ptr(args: &mut *const c_uchar) -> *const c_void {
    (unsafe { get_arg_u64(args) }) as usize as *const c_void
}

#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_rule!("type_string", "t#__kernel_size_t", "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t", "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_rule!("type_string", "t#__u32", "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_rule!("type_string", "t#size_t", "typedef_type size_t { t#__kernel_size_t }");
#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_rule!("type_string", "t#u32", "typedef_type u32 { t#__u32 }");

#[cfg(CONFIG_BINARY_PRINTF)]
kernel::kabi_export! {
    bstr_printf,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } buf , formal_parameter t#size_t size , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } fmt_str , formal_parameter pointer_type { const_type { t#u32 } } bin_buf ) -> base_type int byte_size(4) encoding(5)",
}

/// `bstr_printf(buf, size, fmt_str, bin_buf)`, `lib/vsprintf.c:3252-3412`.
/// Captured against `build-full/lib/vsprintf.o` (`0xaf603e62`, still the
/// C definition at capture time) via `rig/kabi-pin.sh --capture
/// bstr_printf build-full`, before this function replaced it.
///
/// # Safety
/// `buf` valid for writes for `size` bytes (or `size == 0`). `fmt_str`
/// a NUL-terminated format string. `bin_buf` a binary argument buffer
/// produced by a matching `vbin_printf()` call for the SAME format
/// string -- this function's entire contract with its caller, exactly
/// as upstream (this crate cannot check it; a mismatched `bin_buf`
/// desyncs `get_arg`'s reads the same way it would in the C).
#[cfg(CONFIG_BINARY_PRINTF)]
#[no_mangle]
pub unsafe extern "C" fn bstr_printf(buf: *mut c_char, size: usize, fmt_str: *const c_char, bin_buf: *const u32) -> c_int {
    // `WARN_ON_ONCE(size > INT_MAX)`.
    if kernel::kabi_warn_on_once!(size > c_int::MAX as usize) {
        return 0;
    }

    let mut fmt = Fmt { str_: fmt_str, state: FORMAT_STATE_NONE, size: 0 };
    let mut spec = PrintfSpec { flags: 0, base: 0, precision: 0, field_width: 0 };
    let mut args = bin_buf as *const c_uchar;

    let mut str_ = buf;
    let mut size = size;
    // SAFETY: pointer-to-integer round trip only, no dereference.
    let mut end = (buf as usize).wrapping_add(size) as *mut c_char;
    // "Make sure end is always >= buf" -- `size` recomputed from the
    // clamped `end` when the raw addition would have wrapped (`(void
    // *)-1`, i.e. `usize::MAX`).
    if (end as usize) < (buf as usize) {
        end = usize::MAX as *mut c_char;
        size = (end as usize) - (buf as usize);
    }

    loop {
        // SAFETY: `fmt_str` NUL-terminated, this function's contract.
        if unsafe { *fmt.str_ } == 0 {
            break;
        }
        let old_fmt = fmt.str_;

        fmt = unsafe { format_decode(fmt, &mut spec) };
        match fmt.state {
            FORMAT_STATE_NONE => {
                let read = (fmt.str_ as usize) - (old_fmt as usize);
                if str_ < end {
                    let avail = (end as usize) - (str_ as usize);
                    let copy = if read > avail { avail } else { read };
                    // SAFETY: `copy <= avail`, `str_` valid for `avail`
                    // bytes (caller's contract); `old_fmt..+read` is
                    // within the NUL-terminated `fmt_str`.
                    unsafe { core::ptr::copy_nonoverlapping(old_fmt as *const u8, str_ as *mut u8, copy) };
                }
                str_ = (str_ as usize).wrapping_add(read) as *mut c_char;
                continue;
            }
            FORMAT_STATE_WIDTH => {
                let w = unsafe { get_arg_i32(&mut args) };
                set_field_width(&mut spec, w);
                continue;
            }
            FORMAT_STATE_PRECISION => {
                let p = unsafe { get_arg_i32(&mut args) };
                set_precision(&mut spec, p);
                continue;
            }
            FORMAT_STATE_CHAR => {
                // `while (--spec.field_width > 0)`: pre-decrement,
                // tested every iteration including the first.
                if (spec.flags & F_LEFT) == 0 {
                    loop {
                        spec.field_width -= 1;
                        if spec.field_width <= 0 {
                            break;
                        }
                        if str_ < end {
                            unsafe { *str_ = b' ' as c_char };
                        }
                        str_ = unsafe { str_.add(1) };
                    }
                }
                let c = unsafe { get_arg_u8(&mut args) };
                if str_ < end {
                    unsafe { *str_ = c as c_char };
                }
                str_ = unsafe { str_.add(1) };
                loop {
                    spec.field_width -= 1;
                    if spec.field_width <= 0 {
                        break;
                    }
                    if str_ < end {
                        unsafe { *str_ = b' ' as c_char };
                    }
                    str_ = unsafe { str_.add(1) };
                }
                continue;
            }
            FORMAT_STATE_STR => {
                let str_arg = args as *const c_char;
                // SAFETY: `args` points into `bin_buf`, at a
                // NUL-terminated string `vbin_printf`'s own
                // `FORMAT_STATE_STR` case always packs (`check_pointer_msg`
                // substitutes a real NUL-terminated fallback message for
                // NULL/fault pointers before copying) -- this function's
                // contract with its caller.
                let len = unsafe { strlen(str_arg) } + 1;
                args = unsafe { args.add(len) };
                str_ = unsafe { string(str_, end, str_arg, spec) };
                continue;
            }
            FORMAT_STATE_PTR => {
                // SAFETY: `fmt.str_` NUL-terminated, contract above.
                let fc = unsafe { *fmt.str_ as u8 };
                let mut process = false;
                match fc {
                    b'S' | b's' | b'x' | b'K' | b'e' => process = true,
                    _ => {
                        if !isalnum_byte(fc) {
                            process = true;
                        } else if str_ < end {
                            // "Pointer dereference was already
                            // processed" -- `args` here points at a
                            // pre-formatted, NUL-terminated string
                            // `vbin_printf` wrote by calling `pointer()`
                            // itself during packing (module doc point
                            // 2); copy it out verbatim.
                            let len = unsafe { strlen(args as *const c_char) };
                            let avail = (end as usize) - (str_ as usize);
                            let copy = if len > avail { avail } else { len };
                            unsafe { core::ptr::copy_nonoverlapping(args, str_ as *mut u8, copy) };
                            str_ = unsafe { str_.add(len) };
                            args = unsafe { args.add(len + 1) };
                        }
                        // Faithfully NOT advancing `str_`/`args` when
                        // `str_ >= end` here, matching the C's own `if
                        // (str < end) { ... }` gate around the entire
                        // copy-and-advance block, not just the copy.
                    }
                }
                if process {
                    let p = unsafe { get_arg_ptr(&mut args) };
                    str_ = unsafe { vsprintf_rs_pointer(fmt.str_, str_, end, p, spec) };
                }
                while isalnum_byte(unsafe { *fmt.str_ as u8 }) {
                    fmt.str_ = unsafe { fmt.str_.add(1) };
                }
                continue;
            }
            FORMAT_STATE_PERCENT_CHAR => {
                if str_ < end {
                    unsafe { *str_ = b'%' as c_char };
                }
                str_ = unsafe { str_.add(1) };
                continue;
            }
            FORMAT_STATE_INVALID => break,
            FORMAT_STATE_NUM => {
                let num: u64 = if (fmt.size as usize) > core::mem::size_of::<c_int>() {
                    unsafe { get_arg_u64(&mut args) }
                } else {
                    let v = unsafe { get_arg_i32(&mut args) };
                    convert_num_spec(v as c_uint, fmt.size as c_int, spec) as u64
                };
                str_ = unsafe { number(str_, end, num as c_ulonglong, spec) };
                continue;
            }
            _ => unreachable!(),
        }
    }

    if size > 0 {
        if str_ < end {
            unsafe { *str_ = 0 };
        } else {
            unsafe { *end.sub(1) = 0 };
        }
    }

    ((str_ as usize) - (buf as usize)) as c_int
}
