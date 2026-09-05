// SPDX-License-Identifier: GPL-2.0

//! The ABI contract a Rust symbol carries about itself.
//!
//! # The problem this solves
//!
//! Under `CONFIG_GENDWARFKSYMS` the MODVERSIONS fingerprint of an exported
//! symbol is hashed from the DWARF of whatever object carries the export. When
//! a symbol's body moves from C to Rust, one of two things happens, and
//! neither is what we want:
//!
//! 1. The `EXPORT_SYMBOL()` stays behind in a C file. Then the fingerprint is
//!    hashed from the `__gendwarfksyms_ptr_<sym>` pointer `include/linux/
//!    export.h` emits, which is typed from the C *declaration* in the header.
//!    The fingerprint survives -- but it is now a statement about a header,
//!    not about the code. **The Rust is not in the equation at all**, so the
//!    fingerprint can no longer detect a Rust body that has drifted away from
//!    the C prototype.
//!
//! 2. The export moves to Rust. Then the fingerprint is hashed from Rust
//!    DWARF, and it moves, because Rust spells the same machine types
//!    differently:
//!
//!    | | C | Rust |
//!    |---|---|---|
//!    | `unsigned char` | `base_type unsigned char byte_size(1) encoding(8)` | `base_type u8 byte_size(1) encoding(7)` |
//!
//!    Same width, same signedness, same ABI, different name *and* different
//!    `DW_ATE_*` encoding -- so a different hash, and every third-party module
//!    that used the symbol stops loading.
//!
//! # The design
//!
//! Take route 2 -- put the export on the Rust, so the Rust is what gets
//! hashed -- and carry the C spelling with it as object metadata. That is
//! [`kabi_export!`]. It emits two things into the object file:
//!
//! * a `.export_symbol` entry, byte-identical to what `EXPORT_SYMBOL()`
//!   produces in C, so `modpost` exports the symbol exactly as before;
//! * a `type_string` kABI rule in `.discard.gendwarfksyms.kabi_rules`, which
//!   tells `scripts/gendwarfksyms` to hash the C spelling of this symbol's
//!   signature instead of the Rust one.
//!
//! The contract travels with the thing making the promise. It sits three lines
//! above the signature it constrains, and when the C file is finally deleted
//! there is nothing left behind to lose.
//!
//! # Four things that are not optional
//!
//! 1. **The rules are ignored unless `gendwarfksyms` is passed `--stable`,**
//!    which is not a Kconfig symbol: `scripts/Makefile.build` passes it only
//!    when the make variable `KBUILD_GENDWARFKSYMS_STABLE` is set. Forgetting
//!    it does not fail the build; it silently changes the module ABI.
//!
//! 2. **The contract string is generated, never typed.** `rig/kabi-pin.sh
//!    --capture` derives it from the C definition, in `--symtypes` form so
//!    that referenced types appear as back-references (`s#chacha_state`)
//!    rather than being expanded inline. An expanded pin freezes the *layout*
//!    of every type it names, which masks a real ABI break; a back-reference
//!    pin leaves the layout live and still checkable.
//!
//! 3. **A pin is a literal, so it becomes a lie the moment the C declaration
//!    changes.** It would keep asserting the old fingerprint and hide a real
//!    break. `rig/kabi-pin.sh --check` re-derives and fails on drift.
//!
//! 4. **The rules never reach the kernel.** They live in a `.discard` section
//!    the linker drops -- verified: zero occurrences in `vmlinux` -- and are
//!    read by a host tool. A wrong pin can misreport the ABI; it cannot change
//!    one instruction of what runs.
//!
//! See `logs/abi-contract-design.md` in the Rusty-Linux repository for the
//! reasoning, and `scripts/gendwarfksyms/kabi.c` for the rule format.

/// Emit one kABI rule into `.discard.gendwarfksyms.kabi_rules`.
///
/// The section format is four NUL-terminated strings per entry: version, rule
/// tag, target, value. See `scripts/gendwarfksyms/kabi.c`.
///
/// This is the building block; callers want [`kabi_export!`].
#[macro_export]
macro_rules! kabi_rule {
    ($tag:literal, $target:expr, $value:expr) => {
        const _: () = {
            const RULE: &[::core::primitive::u8] =
                ::core::concat!("1\0", $tag, "\0", $target, "\0", $value, "\0").as_bytes();

            #[used]
            #[link_section = ".discard.gendwarfksyms.kabi_rules"]
            static ENTRY: [::core::primitive::u8; RULE.len()] = {
                let mut out = [0u8; RULE.len()];
                let mut i = 0;
                while i < RULE.len() {
                    out[i] = RULE[i];
                    i += 1;
                }
                out
            };
        };
    };
}

/// Export a Rust-defined symbol to the rest of the kernel, with the ABI
/// contract the C it replaced was making.
///
/// Emits a `.export_symbol` entry identical to the one `EXPORT_SYMBOL()`
/// builds in C, and a `type_string` kABI rule pinning the MODVERSIONS
/// fingerprint to the C spelling of the signature.
///
/// `license` is `""` for `EXPORT_SYMBOL` and `"GPL"` for `EXPORT_SYMBOL_GPL`;
/// `namespace` is `""` unless the C used `EXPORT_SYMBOL_NS*`. Both must match
/// the C exactly -- they decide which modules may link against the symbol.
///
/// `contract` is generated by `rig/kabi-pin.sh --capture`. Do not hand-write
/// it and do not edit it to make a check pass; see the module documentation.
///
/// # Examples
///
/// ```ignore
/// kernel::kabi_export! {
///     _bcd2bin,
///     license = "",
///     namespace = "",
///     contract = "subprogram ( formal_parameter base_type unsigned char byte_size(1) encoding(8) val ) -> base_type unsigned int byte_size(4) encoding(7)",
/// }
///
/// #[no_mangle]
/// pub extern "C" fn _bcd2bin(val: u8) -> core::ffi::c_uint {
///     ((val & 0x0f) as core::ffi::c_uint) + (val >> 4) as core::ffi::c_uint * 10
/// }
/// ```
#[macro_export]
macro_rules! kabi_export {
    ($sym:ident,
     license = $license:literal,
     namespace = $namespace:literal,
     contract = $contract:literal $(,)?) => {
        // __EXPORT_SYMBOL_REF() is `.quad` on 64-bit and `.long` on 32-bit.
        // Rather than emit untested 32-bit assembly, fail the build there.
        const _: () = ::core::assert!(
            ::core::mem::size_of::<usize>() == 8,
            "kabi_export!: .quad assumes a 64-bit pointer, see __EXPORT_SYMBOL_REF"
        );

        // Mirrors ___EXPORT_SYMBOL() in include/linux/export.h: a local label
        // __export_symbol_<sym> at the head of the entry, the license and
        // namespace as NUL-terminated strings, then an aligned pointer to the
        // symbol itself. modpost::check_export_symbol() reads exactly this.
        ::core::arch::global_asm!(
            ".section \".export_symbol\",\"a\"",
            ::core::concat!("__export_symbol_", ::core::stringify!($sym), ":"),
            ::core::concat!(".asciz \"", $license, "\""),
            ::core::concat!(".asciz \"", $namespace, "\""),
            ".balign 8",
            ::core::concat!(".quad ", ::core::stringify!($sym)),
            ".previous",
        );

        $crate::kabi_rule!("type_string", ::core::stringify!($sym), $contract);
    };
}

/// Emit a C file's `MODULE_*()` metadata from the Rust that replaced it.
///
/// # Why this is not cosmetic
///
/// `MODULE_AUTHOR()`, `MODULE_DESCRIPTION()` and `MODULE_LICENSE()` in a
/// **built-in** object are not module machinery. They expand to
/// NUL-terminated `<modname>.<tag>=<value>` strings in a `.modinfo` section,
/// the linker collects them into `vmlinux`, and kbuild extracts them into
/// `modules.builtin.modinfo`, which is installed and which userspace
/// `modinfo` reads. Deleting the C file deletes those lines.
///
/// It went unnoticed for the first ten C files this project removed —
/// `xxhash`, `arc4`, `crc16`, `rational` and the rest are simply absent from
/// `modules.builtin.modinfo` now, and no check in the tree looks at that
/// file. Recorded in `logs/deviations.md`; this macro is what stops it
/// happening again.
///
/// # The name must be given, and cannot be derived
///
/// For C, the prefix is `KBUILD_MODNAME "."`, which kbuild sets from the
/// object's name. A Rust replacement is compiled as `<base>_rs.o`, so
/// deriving it would produce `bitrev_rs.license=GPL` where the C produced
/// `bitrev.license=GPL` — a difference in the installed file. So the name is
/// a literal, and it is the name of the C file that went away.
///
/// `file` is the `MODULE_FILE` entry kbuild adds on its own: the source path
/// without its extension.
///
/// # Examples
///
/// ```ignore
/// kernel::kabi_modinfo! {
///     "bitrev",
///     file = "lib/bitrev",
///     author = "Akinobu Mita <akinobu.mita@gmail.com>",
///     description = "Bit ordering reversal functions",
///     license = "GPL",
/// }
/// ```
#[macro_export]
macro_rules! kabi_modinfo {
    ($modname:literal,
     file = $file:literal
     $(, $tag:ident = $value:literal)* $(,)?) => {
        // Mirrors __MODULE_INFO() in include/linux/moduleparam.h: a
        // NUL-terminated `<prefix><tag>=<value>` in an alloc-only,
        // byte-aligned .modinfo section. The C's is `__aligned(1)`, so no
        // .balign here either -- padding would appear in the extracted file
        // as empty strings.
        ::core::arch::global_asm!(
            ".section \".modinfo\",\"a\"",
            $( ::core::concat!(
                ".asciz \"", $modname, ".", ::core::stringify!($tag), "=", $value, "\""), )*
            ::core::concat!(".asciz \"", $modname, ".file=", $file, "\""),
            ".previous",
        );
    };
}

/// `WARN_ON_ONCE()` from `include/asm-generic/bug.h`.
///
/// # Why this is here and not in `bug.rs`
///
/// `rust/kernel/bug.rs` provides [`warn_on!`] and nothing else. Every port in
/// this project that deleted a C entry carrying a `WARN_ON_ONCE()` had to
/// either keep the C or lose the guard, and **losing it is a defect no ABI
/// check can see**: the signature is unchanged, the fingerprint does not
/// move, and the differential agrees, because a warning is not a result.
/// Seven closures did exactly that on 2026-09-04 and two of them stopped the
/// kernel booting — `logs/hooks.md`, `rig/guard-check.sh`.
///
/// # The "once" costs nothing, which is not obvious
///
/// There is no `static bool __warned` here, and none is needed. On any
/// architecture with a bug table — x86-64 included — `WARN_ON_ONCE` is
/// `__WARN_FLAGS(BUGFLAG_ONCE | BUGFLAG_TAINT(TAINT_WARN))`, and the
/// once-ness lives in the table entry: the trap handler sets `BUGFLAG_DONE`
/// the first time and skips the report afterwards. So this is the same
/// `warn_flags!` the plain `warn_on!` uses, with one more bit.
#[macro_export]
macro_rules! kabi_warn_on_once {
    ($cond:expr) => {{
        let cond = $cond;
        if cond {
            const KABI_WARN_ONCE_FLAGS: u32 =
                $crate::bindings::BUGFLAG_ONCE | $crate::bug::bugflag_taint($crate::bindings::TAINT_WARN);

            $crate::warn_flags!(KABI_WARN_ONCE_FLAGS);
        }
        cond
    }};
}

/// `WARN(cond, fmt, ...)` from `include/asm-generic/bug.h`: a warning that
/// carries a message.
///
/// Mirrors the `__WARN_printf()` an architecture with `__WARN_FLAGS` uses —
/// `__warn_printk(fmt, ...)` first, then the bug-table trap with
/// `BUGFLAG_NO_CUT_HERE`, because `__warn_printk()` has already printed the
/// "cut here" line itself. Getting that flag wrong prints the banner twice,
/// which is cosmetic, and omitting `__warn_printk` loses the message, which
/// is not: `lib/errseq.c`'s only guard is `WARN(..., "err = %d\n", err)`, and
/// the number is the whole diagnostic.
///
/// The format string is passed to a C variadic, so it must be a literal and
/// it gains a NUL here. Arguments are passed as-is and must already be the
/// types the format expects — there is no checking, exactly as in C.
///
/// # Examples
///
/// ```ignore
/// if kernel::kabi_warn!(err == 0, "err = %d\n", err) {
///     return old;
/// }
/// ```
#[macro_export]
macro_rules! kabi_warn {
    ($cond:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let cond = $cond;
        if cond {
            // SAFETY: `__warn_printk` is the kernel's own variadic printk for
            // exactly this purpose. The format string is a literal with a NUL
            // appended, and the arguments are the caller's, under the same
            // no-checking rule the C macro has.
            unsafe {
                $crate::bindings::__warn_printk(
                    ::core::concat!($fmt, "\0").as_ptr().cast(),
                    $($arg),*
                );
            }
            const KABI_WARN_FLAGS: u32 = $crate::bindings::BUGFLAG_NO_CUT_HERE
                | $crate::bug::bugflag_taint($crate::bindings::TAINT_WARN);

            $crate::warn_flags!(KABI_WARN_FLAGS);
        }
        cond
    }};
}
