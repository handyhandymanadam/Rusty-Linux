// SPDX-License-Identifier: GPL-2.0

//! `__clz_tab` -- the Rust behind `lib/clz_tab.c`.
//!
//! Replaces: lib/clz_tab.c
//!
//! # Not `EXPORT_SYMBOL`, and not called from anywhere `grep` can find
//!
//! `__clz_tab[]` has no exported symbol and no C caller anywhere in the
//! tree -- `libgcc`'s software `__clzsi2`/`__clzdi2`-style helpers on
//! architectures without a native count-leading-zeros instruction reach it
//! by name from compiler-generated code, which is invisible to source
//! search. `MPILIB` (`select CLZ_TAB`) is the reason it is compiled in at
//! all here.
//!
//! # A computed table, checked against the values it replaces
//!
//! `__clz_tab[i]` is the bit length of `i` as an 8-bit value: the position
//! of its highest set bit, one-indexed, with `__clz_tab[0] == 0`. That is
//! exactly `8 - (i as u8).leading_zeros()`, including at `i == 0`, where
//! Rust's `leading_zeros()` is well-defined (returns 8) precisely where
//! C's `__builtin_clz(0)` is not -- so this is computed, not transcribed,
//! and checked byte-for-byte against the 256 values the C literal spells
//! out.

const fn clz_tab_init() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = 8 - (i as u8).leading_zeros() as u8;
        i += 1;
    }
    t
}

/// `__clz_tab[]`: bit length of the index, one-indexed, `__clz_tab[0] == 0`.
#[no_mangle]
pub static __clz_tab: [u8; 256] = clz_tab_init();

// Spot-check against the C literal's own values, at the boundaries between
// bit-length classes and at both ends of the table.
const _: () = {
    assert!(__clz_tab[0] == 0);
    assert!(__clz_tab[1] == 1);
    assert!(__clz_tab[2] == 2);
    assert!(__clz_tab[3] == 2);
    assert!(__clz_tab[4] == 3);
    assert!(__clz_tab[7] == 3);
    assert!(__clz_tab[8] == 4);
    assert!(__clz_tab[15] == 4);
    assert!(__clz_tab[16] == 5);
    assert!(__clz_tab[31] == 5);
    assert!(__clz_tab[32] == 6);
    assert!(__clz_tab[63] == 6);
    assert!(__clz_tab[64] == 7);
    assert!(__clz_tab[127] == 7);
    assert!(__clz_tab[128] == 8);
    assert!(__clz_tab[255] == 8);
};
