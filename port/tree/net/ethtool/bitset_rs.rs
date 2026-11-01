// SPDX-License-Identifier: GPL-2.0-only

//! The u32-bitmap helpers of the ethtool netlink bitsets -- the Rust behind part of `net/ethtool/bitset.c`.
//!
//! Ported from `net/ethtool/bitset.c` (6.18.49): the interval operations on `u32` based bitmaps (`ethnl_bitmap32_clear`, `_not_zero`, `_update`, `_test_bit`, `_equal`) and the size
//! estimate of a bitset attribute (`ethnl_bitset32_size`). In C (`bitset_glue.c`): everything that builds or parses netlink attributes (`ethnl_put_bitset32`, `ethnl_update_bitset32` and
//! its helpers, the `unsigned long` flavours, the policies) with the one-line `ethnl_lower_bits` / `ethnl_upper_bits` they still use.
//!
//! `ethnl_lower_bits(n)` is `~0 >> (32 - n % 32)`, undefined in C for `n % 32 == 0`; no caller passes that and the shift here wraps as the hardware does.
//!
//! Replaces: net/ethtool/bitset.c (the bitmap32 helpers and ethnl_bitset32_size)

use core::ffi::{c_char, c_int};

/// `ETH_GSTRING_LEN`.
const ETH_GSTRING_LEN: usize = 32;
/// `NLA_HDRLEN`: `NLA_ALIGN(sizeof(struct nlattr))`.
const NLA_HDRLEN: u32 = 4;

fn lower_bits(n: u32) -> u32 {
    (!0u32).wrapping_shr(32 - n % 32)
}

fn upper_bits(n: u32) -> u32 {
    (!0u32) << (n % 32)
}

/// `nla_total_size(payload)`: `NLA_ALIGN(NLA_HDRLEN + payload)`.
fn nla_total_size(payload: u32) -> u32 {
    payload.wrapping_add(NLA_HDRLEN).wrapping_add(3) & !3
}

/// `ethnl_bitmap32_clear()`: clear the bits `start <= i < end`, set `*mod` if one was set.
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitmap32_clear(dst: *mut u32, start: u32, end: u32, modified: *mut bool) {
    unsafe {
        let mut start_word = start / 32;
        let end_word = end / 32;

        if end <= start {
            return;
        }

        if start % 32 != 0 {
            let mut mask = upper_bits(start);
            if end_word == start_word {
                mask &= lower_bits(end);
                if *dst.add(start_word as usize) & mask != 0 {
                    *dst.add(start_word as usize) &= !mask;
                    *modified = true;
                }
                return;
            }
            if *dst.add(start_word as usize) & mask != 0 {
                *dst.add(start_word as usize) &= !mask;
                *modified = true;
            }
            start_word += 1;
        }

        let mut i = start_word;
        while i < end_word {
            if *dst.add(i as usize) != 0 {
                *dst.add(i as usize) = 0;
                *modified = true;
            }
            i += 1;
        }
        if end % 32 != 0 {
            let mask = lower_bits(end);
            if *dst.add(end_word as usize) & mask != 0 {
                *dst.add(end_word as usize) &= !mask;
                *modified = true;
            }
        }
    }
}

/// `ethnl_bitmap32_not_zero()`: is any bit with `start <= i < end` set?
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitmap32_not_zero(map: *const u32, start: u32, end: u32) -> bool {
    unsafe {
        let mut start_word = start / 32;
        let end_word = end / 32;

        if end <= start {
            return false;
        }

        if start % 32 != 0 {
            let mut mask = upper_bits(start);
            if end_word == start_word {
                mask &= lower_bits(end);
                return *map.add(start_word as usize) & mask != 0;
            }
            if *map.add(start_word as usize) & mask != 0 {
                return true;
            }
            start_word += 1;
        }

        // memchr_inv(map + start_word, '\0', (end_word - start_word) * sizeof(u32))
        let mut i = start_word;
        while i < end_word {
            if *map.add(i as usize) != 0 {
                return true;
            }
            i += 1;
        }
        if end % 32 == 0 {
            return false;
        }
        *map.add(end_word as usize) & lower_bits(end) != 0
    }
}

/// `ethnl_bitmap32_update()`: set the bits of `dst` that are set in `mask` (all of them if null) to the values from `value`; `*mod` is set if `dst` changed.
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitmap32_update(mut dst: *mut u32, mut nbits: u32, mut value: *const u32, mut mask: *const u32, modified: *mut bool) {
    unsafe {
        while nbits > 0 {
            let mut real_mask = if mask.is_null() { !0u32 } else { *mask };

            if nbits < 32 {
                real_mask &= lower_bits(nbits);
            }
            let new_value = (*dst & !real_mask) | (*value & real_mask);
            if new_value != *dst {
                *dst = new_value;
                *modified = true;
            }

            if nbits <= 32 {
                break;
            }
            dst = dst.add(1);
            nbits -= 32;
            value = value.add(1);
            if !mask.is_null() {
                mask = mask.add(1);
            }
        }
    }
}

/// `ethnl_bitmap32_test_bit()`.
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitmap32_test_bit(map: *const u32, index: u32) -> bool {
    unsafe { *map.add((index / 32) as usize) & (1u32 << (index % 32)) != 0 }
}

/// `ethnl_bitmap32_equal()`: do the first `nbits` of the two bitmaps agree?
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitmap32_equal(map1: *const u32, map2: *const u32, nbits: u32) -> bool {
    unsafe {
        let mut i = 0;
        while i < (nbits / 32) as usize {
            if *map1.add(i) != *map2.add(i) {
                return false;
            }
            i += 1;
        }
        if nbits % 32 == 0 {
            return true;
        }
        (*map1.add((nbits / 32) as usize) ^ *map2.add((nbits / 32) as usize)) & lower_bits(nbits % 32) == 0
    }
}

/// `ethnl_strz_size()`: `nla_total_size(strnlen(s, ETH_GSTRING_LEN) + 1)`.
unsafe fn strz_size(s: *const c_char) -> u32 {
    unsafe {
        let mut n = 0;
        while n < ETH_GSTRING_LEN && *s.add(n) != 0 {
            n += 1;
        }
        nla_total_size(n as u32 + 1)
    }
}

/// `ethnl_bitset32_size()`: length of the attribute `ethnl_put_bitset32()` composes for the same arguments. `names` is an array of `ETH_GSTRING_LEN` byte strings, or null.
#[no_mangle]
pub unsafe extern "C" fn ethnl_bitset32_size(val: *const u32, mask: *const u32, nbits: u32, names: *const c_char, compact: bool) -> c_int {
    unsafe {
        let mut len: u32 = 0;

        // list flag
        if mask.is_null() {
            len = len.wrapping_add(nla_total_size(4));
        }
        // size
        len = len.wrapping_add(nla_total_size(4));

        if compact {
            let nwords = nbits.wrapping_add(31) / 32;

            // value, mask
            len = len.wrapping_add((if mask.is_null() { 1u32 } else { 2u32 }).wrapping_mul(nla_total_size(nwords.wrapping_mul(4))));
        } else {
            let mut bits_len: u32 = 0;
            let mut i: u32 = 0;

            while i < nbits {
                let name = if names.is_null() { core::ptr::null() } else { names.add(i as usize * ETH_GSTRING_LEN) };

                if !ethnl_bitmap32_test_bit(if mask.is_null() { val } else { mask }, i) {
                    i += 1;
                    continue;
                }
                // index
                let mut bit_len = nla_total_size(4);
                // name
                if !name.is_null() {
                    bit_len = bit_len.wrapping_add(strz_size(name));
                }
                // value
                if !mask.is_null() && ethnl_bitmap32_test_bit(val, i) {
                    bit_len = bit_len.wrapping_add(nla_total_size(0));
                }

                // bit nest
                bits_len = bits_len.wrapping_add(nla_total_size(bit_len));
                i += 1;
            }
            // bits nest
            len = len.wrapping_add(nla_total_size(bits_len));
        }

        // outermost nest
        nla_total_size(len) as c_int
    }
}
