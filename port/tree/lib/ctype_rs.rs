// SPDX-License-Identifier: GPL-2.0

//! The character-class table -- the Rust behind `lib/ctype.c`.
//!
//! Ported from `lib/ctype.c` (6.18.49), Copyright (C) 1991, 1992
//! Linus Torvalds.
//!
//! Replaces: lib/ctype.c
//!
//! # One exported array, and 296 relocations point at it
//!
//! `lib/ctype.c` defines no functions. `isalpha()`, `isdigit()`, `isspace()`
//! and the rest are macros in `include/linux/ctype.h` that index `_ctype`, so
//! this table is every character classification the kernel makes. It has the
//! highest fan-in of anything ported so far by a wide margin -- `vsprintf`,
//! `kstrtox`, `cmdline`, the filesystems and half of `drivers/` read it -- and
//! a single wrong entry is a behaviour change somewhere far away, in a path
//! whose test does not mention ctype.
//!
//! # It is DERIVED from the class rules, not transcribed
//!
//! The C is 256 entries written as `_U|_X` and friends. Copying them would be
//! 256 chances at a silent one-token error, and the previous attempt at this
//! port hit exactly that class of bug hand-copying `vsprintf`'s `decpair[]`.
//! So the table is built at compile time from the rules the rows encode, and
//! the rules are stated in the code where they can be read against
//! `include/linux/ctype.h`.
//!
//! **The Latin-1 half is where the exceptions live**, and they are the reason
//! this is worth writing out rather than waving at: 0x80..0x9f classify as
//! nothing at all; 0xa0 (NBSP) is `_S|_SP` like 0x20; and 0xd7 and 0xf7 --
//! MULTIPLICATION SIGN and DIVISION SIGN -- sit inside the uppercase and
//! lowercase runs but are punctuation, because they are the two glyphs in
//! those ranges that are not letters.
//!
//! # How the table was checked
//!
//! Two ways, and the second is the one that would catch a wrong rule:
//!
//! 1. `const` assertions below, at every class boundary and on each of the
//!    four Latin-1 exceptions.
//! 2. At port time, the `.rodata` of this object was compared byte for byte
//!    with the `.rodata` of the C object built from the same tree. Identical.
//!    That is recorded in `logs/hooks.md`, and it is what a spot check is a
//!    poor substitute for.

/// `_U` -- upper case. `include/linux/ctype.h`.
const U: u8 = 0x01;
/// `_L` -- lower case.
const L: u8 = 0x02;
/// `_D` -- decimal digit.
const D: u8 = 0x04;
/// `_C` -- control character.
const C: u8 = 0x08;
/// `_P` -- punctuation.
const P: u8 = 0x10;
/// `_S` -- white space (space, LF, tab, VT, FF, CR).
const S: u8 = 0x20;
/// `_X` -- hexadecimal digit.
const X: u8 = 0x40;
/// `_SP` -- hard space, i.e. 0x20 and 0xa0 specifically.
const SP: u8 = 0x80;

/// The class byte for one character, from the rules `lib/ctype.c`'s rows
/// encode. Read alongside that file: each `if` below is one of its comments.
const fn class(i: u8) -> u8 {
    match i {
        // 0-31 and 127 are controls; 9..13 (tab, LF, VT, FF, CR) are also
        // white space. Note 0x20 is NOT _C -- it is the first row's `_S|_SP`.
        9..=13 => C | S,
        0..=8 | 14..=31 | 127 => C,

        b' ' => S | SP,
        b'0'..=b'9' => D,
        b'A'..=b'F' => U | X,
        b'G'..=b'Z' => U,
        b'a'..=b'f' => L | X,
        b'g'..=b'z' => L,
        // Everything else below 127: the four punctuation runs 33-47, 58-64,
        // 91-96 and 123-126.
        33..=126 => P,

        // Latin-1. 0x80..0x9f are the C1 controls and the C classifies them
        // as NOTHING -- not _C, which is the trap in this half of the table.
        128..=159 => 0,
        // NBSP, treated exactly like 0x20.
        160 => S | SP,
        161..=191 => P,
        // MULTIPLICATION SIGN sits inside the uppercase run and is not a
        // letter; DIVISION SIGN does the same inside the lowercase run.
        0xd7 | 0xf7 => P,
        192..=222 => U,
        // 0xdf is sharp s and 0xff is y-diaeresis: both lower case, so the
        // run simply continues to the end.
        223..=255 => L,
    }
}

/// Build the 256-entry table at compile time.
const fn ctype_init() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;

    while i < 256 {
        t[i] = class(i as u8);
        i += 1;
    }
    t
}

// Every class boundary, and all four Latin-1 exceptions. A const assertion,
// so a wrong rule cannot be built at all. These are the values `lib/ctype.c`
// has at these indices, read off its own rows.
const _: () = {
    let t = ctype_init();
    assert!(t[0x00] == C);                 // NUL
    assert!(t[0x08] == C);                 // BS  -- control, not white space
    assert!(t[0x09] == C | S);             // TAB
    assert!(t[0x0d] == C | S);             // CR
    assert!(t[0x0e] == C);                 // SO  -- back to plain control
    assert!(t[0x1f] == C);
    assert!(t[0x20] == S | SP);            // space
    assert!(t[0x21] == P);                 // !
    assert!(t[0x2f] == P);                 // /
    assert!(t[0x30] == D);                 // 0
    assert!(t[0x39] == D);                 // 9
    assert!(t[0x3a] == P);                 // :
    assert!(t[0x40] == P);                 // @
    assert!(t[0x41] == U | X);             // A
    assert!(t[0x46] == U | X);             // F
    assert!(t[0x47] == U);                 // G
    assert!(t[0x5a] == U);                 // Z
    assert!(t[0x5b] == P);                 // [
    assert!(t[0x60] == P);                 // `
    assert!(t[0x61] == L | X);             // a
    assert!(t[0x66] == L | X);             // f
    assert!(t[0x67] == L);                 // g
    assert!(t[0x7a] == L);                 // z
    assert!(t[0x7b] == P);                 // {
    assert!(t[0x7e] == P);                 // ~
    assert!(t[0x7f] == C);                 // DEL
    assert!(t[0x80] == 0);                 // C1 controls classify as nothing
    assert!(t[0x9f] == 0);
    assert!(t[0xa0] == S | SP);            // NBSP
    assert!(t[0xa1] == P);
    assert!(t[0xbf] == P);
    assert!(t[0xc0] == U);                 // A-grave
    assert!(t[0xd6] == U);
    assert!(t[0xd7] == P);                 // MULTIPLICATION SIGN
    assert!(t[0xd8] == U);
    assert!(t[0xde] == U);
    assert!(t[0xdf] == L);                 // sharp s
    assert!(t[0xf6] == L);
    assert!(t[0xf7] == P);                 // DIVISION SIGN
    assert!(t[0xf8] == L);
    assert!(t[0xff] == L);                 // y-diaeresis
};

// The C type this contract names.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_export! {
    _ctype,
    license = "",
    namespace = "",
    contract = "variable array_type[256] { const_type { base_type unsigned char byte_size(1) encoding(8) } }",
}

/// `const unsigned char _ctype[]` from `lib/ctype.c`.
///
/// Indexed by `__ismask()` in `include/linux/ctype.h`, which every
/// `isalpha()`, `isdigit()`, `isspace()`, `isxdigit()` and `toupper()` in the
/// kernel goes through.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static _ctype: [u8; 256] = ctype_init();
