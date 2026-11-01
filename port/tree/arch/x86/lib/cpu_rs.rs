// SPDX-License-Identifier: GPL-2.0

//! x86 CPUID signature decoding: family, model, stepping.
//!
//! Ported from `arch/x86/lib/cpu.c` (6.18.49), which no longer exists in the
//! CONFIG_RUST build: this file is the whole of it. All three functions decode
//! the 32-bit `CPUID.1:EAX` signature (`sig`):
//!
//! | field | bits | rule |
//! |---|---|---|
//! | stepping | 3:0 | as is |
//! | base model | 7:4 | |
//! | base family | 11:8 | |
//! | extended model | 19:16 | added as `<< 4` to the model when the family is >= 6 |
//! | extended family | 27:20 | added to the family when the base family is 0xF |
//!
//! The family >= 6 test is the kernel's (wider than the SDM's "6 or 15", so
//! AMD family 0x17+ gets its extended model); `x86_model()` calls
//! `x86_family()` exactly as the C does. The C file's three
//! `EXPORT_SYMBOL_GPL`s and their MODVERSIONS contracts are carried here by
//! `kernel::kabi_export!` (see `rust/kernel/kabi.rs`); none of the three
//! functions has a guard, a static key or a bug-table entry, so no C entry
//! stays (`logs/c-entry-rule.md`). The contract text is the C definition's
//! fingerprint (0x5308ed99, identical for all three: one `unsigned int`
//! parameter named `sig`), taken from the C object with gendwarfksyms before
//! the C was removed.
//!
//! Exhaustively checked over all 2^32 signatures against the pristine C and an
//! independent definition: `port/test/x86_cpu/run.sh`; and proved equal to the
//! bit-field specification with Z3: `logs/proofs/x86_cpu.py`.
//!
//! Replaces: arch/x86/lib/cpu.c

use core::ffi::c_uint;

kernel::kabi_export! {
    x86_family,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) sig ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// Display family of a CPUID signature (`arch/x86/include/asm/cpu.h`:
/// `unsigned int x86_family(unsigned int sig)`).
#[no_mangle]
pub extern "C" fn x86_family(sig: c_uint) -> c_uint {
    let mut x86 = (sig >> 8) & 0xf;

    if x86 == 0xf {
        x86 += (sig >> 20) & 0xff;
    }

    x86
}

kernel::kabi_export! {
    x86_model,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) sig ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// Display model of a CPUID signature.
#[no_mangle]
pub extern "C" fn x86_model(sig: c_uint) -> c_uint {
    let fam = x86_family(sig);
    let mut model = (sig >> 4) & 0xf;

    if fam >= 0x6 {
        model += ((sig >> 16) & 0xf) << 4;
    }

    model
}

kernel::kabi_export! {
    x86_stepping,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) sig ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// Stepping of a CPUID signature.
#[no_mangle]
pub extern "C" fn x86_stepping(sig: c_uint) -> c_uint {
    sig & 0xf
}
