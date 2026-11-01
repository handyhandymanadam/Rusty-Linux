// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/video-mode.c (16-bit real-mode setup, code16, -Zregparm=3): the video mode table walker. Exports the C's globals and
//! functions: `adapter`, `force_x`, `force_y`, `do_restore`, `graphic_mode` (ints, plain `.bss`), `probe_cards`, `mode_defined`, `set_mode` (raw_set_mode and
//! vga_recalc_vertical are static in the C and private here). No message strings.
//!
//! Semantics, statement by statement from the C: probe_cards(unsafe) runs each card's probe once per class (`probed[unsafe]`), setting nmodes (0 without a probe);
//! mode_defined scans every card's modes for an exact `mode`; raw_set_mode drops the RECALC bit (0x8000), then scans cards/modes: a mode matches by menu position
//! (`mode == nmode && visible`, where visible = x || y here, and nmode counts visible modes), by its own number, or by `(y << 8) + x` compared as an INT (so a
//! resolution whose y << 8 exceeds 16 bits never matches); a match stores mi->mode in *real_mode and returns card->set_mode(mi); otherwise an unprobed mode inside a card's
//! [xmode_first, xmode_first + xmode_n) range is passed to its set_mode as a mode_info with x = y = 0 (depth left uninitialised as in the C); else -1.
//! vga_recalc_vertical (only when RECALC was requested): BIOS font size and rows from the BIOS data area (0x485/0x484, force_y overrides), `rows = rows*font - 1` (unsigned),
//! CRTC regs 0x11 (unlock), 0x12, 0x07 with the C's masks. set_mode: CURRENT_MODE -> 0; NORMAL_VGA/EXTENDED_VGA -> 80x25 / 8POINT; raw_set_mode; recalc;
//! boot_params.hdr.vid_mode = the canonical mode number.
//!
//! TEST-GAP: logs/realmode-video.md (the modes/cards a real BIOS offers; recalc on real hardware; QEMU std VGA only).
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals)]

#[path = "rm_common.rs"]
mod rm;
#[path = "rm_video.rs"]
mod vid;

use core::ffi::c_int;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use rm::*;
use vid::*;

include!(concat!(env!("RM_GEN_DIR"), "/video_gen.rs"));

#[no_mangle]
#[link_section = ".bss"]
pub static mut adapter: c_int = 0; // 0=CGA/MDA/HGC, 1=EGA, 2=VGA+
#[no_mangle]
#[link_section = ".bss"]
pub static mut force_x: c_int = 0; // Don't query the BIOS for cols/rows
#[no_mangle]
#[link_section = ".bss"]
pub static mut force_y: c_int = 0;
#[no_mangle]
#[link_section = ".bss"]
pub static mut do_restore: c_int = 0; // Screen contents changed during mode flip
#[no_mangle]
#[link_section = ".bss"]
pub static mut graphic_mode: c_int = 0; // Graphic mode with linear frame buffer

#[link_section = ".bss"]
static mut PROBED: [u8; 2] = [0; 2]; // `static u8 probed[2]` of probe_cards

/// Probe the video drivers and have them generate their mode lists.
#[no_mangle]
pub unsafe extern "C" fn probe_cards(unsafe_: c_int) {
    unsafe {
        let p = (addr_of_mut!(PROBED) as *mut u8).offset(unsafe_ as isize);
        if *p != 0 {
            return;
        }
        *p = 1;

        let mut card = cards_begin();
        let end = cards_end();
        while card < end {
            if (*card).unsafe_ == unsafe_ {
                if let Some(probe) = (*card).probe {
                    (*card).nmodes = probe();
                } else {
                    (*card).nmodes = 0;
                }
            }
            card = card.add(1);
        }
    }
}

/// Test if a mode is defined
#[no_mangle]
pub unsafe extern "C" fn mode_defined(mode: u16) -> c_int {
    unsafe {
        let mut card = cards_begin();
        let end = cards_end();
        while card < end {
            let mut mi = (*card).modes;
            let mut i: c_int = 0;
            while i < (*card).nmodes {
                if (*mi).mode == mode {
                    return 1;
                }
                i += 1;
                mi = mi.add(1);
            }
            card = card.add(1);
        }
        0
    }
}

/// Set mode (without recalc)
unsafe fn raw_set_mode(mut mode: u16, real_mode: *mut u16) -> c_int {
    unsafe {
        // Drop the recalc bit if set
        mode &= !VIDEO_RECALC;

        // Scan for mode based on fixed ID, position, or resolution
        let mut nmode: c_int = 0;
        let mut card = cards_begin();
        let end = cards_end();
        while card < end {
            let mut mi = (*card).modes;
            let mut i: c_int = 0;
            while i < (*card).nmodes {
                let visible = (*mi).x != 0 || (*mi).y != 0;

                if ((mode as c_int == nmode) && visible)
                    || mode == (*mi).mode
                    || (mode as c_int) == (((*mi).y as c_int) << 8) + (*mi).x as c_int
                {
                    *real_mode = (*mi).mode;
                    return ((*card).set_mode.unwrap_unchecked())(mi);
                }

                if visible {
                    nmode += 1;
                }
                i += 1;
                mi = mi.add(1);
            }
            card = card.add(1);
        }

        // Nothing found?  Is it an "exceptional" (unprobed) mode?
        card = cards_begin();
        while card < end {
            if (mode as c_int) >= (*card).xmode_first as c_int && (mode as c_int) < (*card).xmode_first as c_int + (*card).xmode_n as c_int {
                let mut mix = MaybeUninit::<ModeInfo>::uninit();
                let m = mix.as_mut_ptr();
                (*m).mode = mode;
                *real_mode = mode;
                (*m).x = 0;
                (*m).y = 0;
                return ((*card).set_mode.unwrap_unchecked())(m);
            }
            card = card.add(1);
        }

        // Otherwise, failure...
        -1
    }
}

/// Recalculate the vertical video cutoff (hack!)
unsafe fn vga_recalc_vertical() {
    unsafe {
        set_fs(0);
        let font_size: u32 = rdfs8(0x485) as u32; // BIOS: font size (pixels)
        let mut rows: u32 = if force_y != 0 { force_y as u32 } else { (rdfs8(0x484) as c_int + 1) as u32 }; // Text rows

        rows = rows.wrapping_mul(font_size); // Visible scan lines
        rows = rows.wrapping_sub(1); // ... minus one

        let crtc = vga_crtc();

        let mut pt = in_idx(crtc, 0x11);
        pt &= !0x80; // Unlock CR0-7
        out_idx(pt, crtc, 0x11);

        out_idx(rows as u8, crtc, 0x12); // Lower height register

        let mut ov = in_idx(crtc, 0x07); // Overflow register
        ov &= 0xbd;
        ov |= ((rows >> (8 - 1)) & 0x02) as u8;
        ov |= ((rows >> (9 - 6)) & 0x40) as u8;
        out_idx(ov, crtc, 0x07);
    }
}

/// Set mode (with recalc if specified)
#[no_mangle]
pub unsafe extern "C" fn set_mode(mut mode: u16) -> c_int {
    unsafe {
        let mut real_mode = MaybeUninit::<u16>::uninit();

        // Very special mode numbers...
        if mode == VIDEO_CURRENT_MODE {
            return 0; // Nothing to do...
        } else if mode == RM_NORMAL_VGA {
            mode = VIDEO_80X25;
        } else if mode == RM_EXTENDED_VGA {
            mode = VIDEO_8POINT;
        }

        let rv = raw_set_mode(mode, real_mode.as_mut_ptr());
        if rv != 0 {
            return rv;
        }

        if mode & VIDEO_RECALC != 0 {
            vga_recalc_vertical();
        }

        // Save the canonical mode number for the kernel, not an alias, size specification or menu position
        bp_wr16(OFF_VID_MODE, real_mode.assume_init());
        0
    }
}
