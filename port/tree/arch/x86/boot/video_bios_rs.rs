// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/video-bios.c (16-bit real-mode setup, code16, -Zregparm=3): the "BIOS" video card (conventional BIOS text modes
//! 0x14..0x7f, probed by trying them). Exports nothing (the C's functions are static); the only product is the `video_bios` card_info in `.videocards`
//! (card_name "BIOS", probe, set_mode, unsafe = 1, xmode_first = VIDEO_FIRST_BIOS, xmode_n = 0x80), linked last as the Makefile's order requires.
//!
//! Same sequence as the C: set_bios_mode(mode) = INT 10h AH=00 (mode), INT 10h AH=0Fh (get mode), do_restore = 1, success when the new mode (top bit masked) equals the
//! request; on failure, if the mode differs from boot_params.screen_info.orig_video_mode, the original mode is restored (INT 10h AX = orig mode); bios_probe returns 0 unless
//! the adapter is EGA/VGA, takes the heap pointer (GET_HEAP(mode_info, 0): the heap is aligned to 2 even for zero elements), tries modes 0x14..0x7f while a mode_info fits on
//! the heap, skipping modes already defined, failures, graphics (attribute controller index 0x10 bit 0, graphics controller index 6 bit 0) and cursor-location-low != 0, and
//! records each survivor (mode = 0x100 + mode, depth 0, x = rdfs16(0x44a), y = rdfs8(0x484) + 1); finally restores the saved mode. Message strings: none.
//!
//! TEST-GAP: logs/realmode-video.md (the card is `unsafe`: it is only probed after typing "scan" at the vga=ask menu; a real BIOS's response to 0x14..0x7f).
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals)]

#[path = "rm_common.rs"]
mod rm;
#[path = "rm_video.rs"]
mod vid;

use core::ffi::{c_char, c_int};
use rm::*;
use vid::*;

unsafe fn set_bios_mode(mode: u8) -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        ireg.set_al(mode); // AH=0x00 Set Video Mode
        intcall(0x10, &ireg, core::ptr::null_mut());

        ireg.set_ah(0x0f); // Get Current Video Mode
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        do_restore = 1; // Assume video contents were lost

        // Not all BIOSes are clean with the top bit
        let new_mode = oreg.assume_init_ref().al() & 0x7f;

        if new_mode == mode {
            return 0; // Mode change OK
        }

        if new_mode != bp_rd8(SI_ORIG_VIDEO_MODE) {
            // Mode setting failed, but we didn't end up where we started.  That's bad.  Try to revert to the original video mode.
            ireg.set_ax(bp_rd8(SI_ORIG_VIDEO_MODE) as u16);
            intcall(0x10, &ireg, core::ptr::null_mut());
        }
        -1
    }
}

unsafe extern "C" fn bios_set_mode(mi: *mut ModeInfo) -> c_int {
    unsafe { set_bios_mode(((*mi).mode.wrapping_sub(VIDEO_FIRST_BIOS)) as u8) }
}

unsafe extern "C" fn bios_probe() -> c_int {
    unsafe {
        let saved_mode: u8 = bp_rd8(SI_ORIG_VIDEO_MODE);
        let mut nmodes: c_int = 0;

        if adapter != ADAPTER_EGA && adapter != ADAPTER_VGA {
            return 0;
        }

        set_fs(0);
        let crtc = vga_crtc();

        video_bios.modes = get_heap(core::mem::size_of::<ModeInfo>(), core::mem::align_of::<ModeInfo>(), 0) as *mut ModeInfo;

        let mut mode: u8 = 0x14;
        while mode <= 0x7f {
            if !heap_free(core::mem::size_of::<ModeInfo>()) {
                break;
            }

            if mode_defined(VIDEO_FIRST_BIOS + mode as u16) != 0 {
                mode += 1;
                continue;
            }

            if set_bios_mode(mode) != 0 {
                mode += 1;
                continue;
            }

            // Try to verify that it's a text mode.

            // Attribute Controller: make graphics controller disabled
            if in_idx(0x3c0, 0x10) & 0x01 != 0 {
                mode += 1;
                continue;
            }

            // Graphics Controller: verify Alpha addressing enabled
            if in_idx(0x3ce, 0x06) & 0x01 != 0 {
                mode += 1;
                continue;
            }

            // CRTC cursor location low should be zero(?)
            if in_idx(crtc, 0x0f) != 0 {
                mode += 1;
                continue;
            }

            let mi = get_heap(core::mem::size_of::<ModeInfo>(), core::mem::align_of::<ModeInfo>(), 1) as *mut ModeInfo;
            (*mi).mode = VIDEO_FIRST_BIOS + mode as u16;
            (*mi).depth = 0; // text
            (*mi).x = rdfs16(0x44a);
            (*mi).y = (rdfs8(0x484) as u16).wrapping_add(1);
            nmodes += 1;
            mode += 1;
        }

        set_bios_mode(saved_mode);

        nmodes
    }
}

#[cfg_attr(not(host_mock), link_section = ".videocards")]
#[cfg_attr(host_mock, link_section = "videocards_rs")]
#[used]
static mut video_bios: CardInfo = CardInfo {
    card_name: b"BIOS\0".as_ptr() as *const c_char,
    set_mode: Some(bios_set_mode),
    probe: Some(bios_probe),
    modes: core::ptr::null_mut(),
    nmodes: 0,
    unsafe_: 1,
    xmode_first: VIDEO_FIRST_BIOS,
    xmode_n: 0x80,
};
