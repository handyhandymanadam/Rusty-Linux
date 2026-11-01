// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/video-vga.c (16-bit real-mode setup, code16, -Zregparm=3): the "VGA" card (CGA/MDA/HGC, EGA, VGA text modes and their
//! 8x8/9x14 font and 480-scan-line variants). Exports `vga_crtc` (video.h); everything else is static in the C. The card_info `video_vga` lives in `.videocards`
//! (this file's object is linked FIRST in the table: video-vga.o must be listed first, its probe fills `adapter`, which the others read).
//!
//! Same BIOS calls and register values as the C, in the same order (partial stores keep the other bits of `ireg`, which the C reuses between calls):
//! vga_set_basic_mode (INT 10h AX=0F00 query; mode 3 unless 3 or 7; AX=mode set; do_restore = 1), vga_set_8font (AX=1112; AX=1200 BL=20; AX=1201 BL=34; AX=0100 CX=0607),
//! vga_set_14font (AX=1111; AX=1201 BL=34; AX=0100 CX=0b0c), vga_set_80x43 (AX=1201 BL=30; AX=0003; 8font), vga_crtc (inb(0x3cc) & 1 ? 0x3d4 : 0x3b4),
//! vga_set_480_scanlines (CRTC regs 0x11,06,07,10,12,15,16 values 0c,0b,3e,ea,df,e7,04; misc output 0x3cc & 0x0d | 0xe2 -> 0x3c2), vga_set_vertical_end(lines)
//! (reg 7 = 0x3c | ((end >> 7) & 2) | ((end >> 3) & 0x40), reg 0x12 = end), 80x30 / 80x34 / 80x60, vga_set_mode (basic mode, force_x/force_y = the mode's x/y, then the
//! mode's variant), vga_probe (INT 10h AX=1200 BL=10: orig_video_ega_bx = BX; BL unchanged = CGA/MDA/HGC; else INT 10h AX=1A00: AL == 0x1a = VGA, orig_video_isVGA = 1,
//! else EGA; picks the mode list and name by adapter). No message strings except the card names "CGA/MDA/HGC", "EGA", "VGA".
//!
//! TEST-GAP: logs/realmode-video.md (QEMU std VGA reaches vga_set_basic_mode / probe / the 8POINT, 80x28... only via vga= values set in a boot; the BIOS calls are
//! SeaBIOS's; real CGA/MDA/EGA hardware is absent; the CRTC register sequences are pinned by the host differential with a port/BIOS log and the boot trace only).
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals)]

#[path = "rm_common.rs"]
mod rm;
#[path = "rm_video.rs"]
mod vid;

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rm::*;
use vid::*;

static mut vga_modes: [ModeInfo; 7] = [
    ModeInfo { mode: VIDEO_80X25, x: 80, y: 25, depth: 0 },
    ModeInfo { mode: VIDEO_8POINT, x: 80, y: 50, depth: 0 },
    ModeInfo { mode: VIDEO_80X43, x: 80, y: 43, depth: 0 },
    ModeInfo { mode: VIDEO_80X28, x: 80, y: 28, depth: 0 },
    ModeInfo { mode: VIDEO_80X30, x: 80, y: 30, depth: 0 },
    ModeInfo { mode: VIDEO_80X34, x: 80, y: 34, depth: 0 },
    ModeInfo { mode: VIDEO_80X60, x: 80, y: 60, depth: 0 },
];

static mut ega_modes: [ModeInfo; 2] = [
    ModeInfo { mode: VIDEO_80X25, x: 80, y: 25, depth: 0 },
    ModeInfo { mode: VIDEO_8POINT, x: 80, y: 43, depth: 0 },
];

static mut cga_modes: [ModeInfo; 1] = [ModeInfo { mode: VIDEO_80X25, x: 80, y: 25, depth: 0 }];

/// Set basic 80x25 mode
unsafe fn vga_set_basic_mode() -> u8 {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        // Query current mode
        ireg.set_ax(0x0f00);
        intcall(0x10, &ireg, oreg.as_mut_ptr());
        let mut mode = oreg.assume_init_ref().al();

        if mode != 3 && mode != 7 {
            mode = 3;
        }

        // Set the mode
        ireg.set_ax(mode as u16); // AH=0: set mode
        intcall(0x10, &ireg, null_mut());
        do_restore = 1;
        mode
    }
}

unsafe fn vga_set_8font() {
    unsafe {
        // Set 8x8 font - 80x43 on EGA, 80x50 on VGA
        let mut ireg = new_regs();

        // Set 8x8 font
        ireg.set_ax(0x1112);
        // ireg.bl = 0;
        intcall(0x10, &ireg, null_mut());

        // Use alternate print screen
        ireg.set_ax(0x1200);
        ireg.set_bl(0x20);
        intcall(0x10, &ireg, null_mut());

        // Turn off cursor emulation
        ireg.set_ax(0x1201);
        ireg.set_bl(0x34);
        intcall(0x10, &ireg, null_mut());

        // Cursor is scan lines 6-7
        ireg.set_ax(0x0100);
        ireg.set_cx(0x0607);
        intcall(0x10, &ireg, null_mut());
    }
}

unsafe fn vga_set_14font() {
    unsafe {
        // Set 9x14 font - 80x28 on VGA
        let mut ireg = new_regs();

        // Set 9x14 font
        ireg.set_ax(0x1111);
        // ireg.bl = 0;
        intcall(0x10, &ireg, null_mut());

        // Turn off cursor emulation
        ireg.set_ax(0x1201);
        ireg.set_bl(0x34);
        intcall(0x10, &ireg, null_mut());

        // Cursor is scan lines 11-12
        ireg.set_ax(0x0100);
        ireg.set_cx(0x0b0c);
        intcall(0x10, &ireg, null_mut());
    }
}

unsafe fn vga_set_80x43() {
    unsafe {
        // Set 80x43 mode on VGA (not EGA)
        let mut ireg = new_regs();

        // Set 350 scans
        ireg.set_ax(0x1201);
        ireg.set_bl(0x30);
        intcall(0x10, &ireg, null_mut());

        // Reset video mode
        ireg.set_ax(0x0003);
        intcall(0x10, &ireg, null_mut());

        vga_set_8font();
    }
}

/// I/O address of the VGA CRTC
#[no_mangle]
pub unsafe extern "C" fn vga_crtc() -> u16 {
    unsafe { if inb(0x3cc) & 1 != 0 { 0x3d4 } else { 0x3b4 } }
}

unsafe fn vga_set_480_scanlines() {
    unsafe {
        let crtc = vga_crtc(); // CRTC base address

        out_idx(0x0c, crtc, 0x11); // Vertical sync end, unlock CR0-7
        out_idx(0x0b, crtc, 0x06); // Vertical total
        out_idx(0x3e, crtc, 0x07); // Vertical overflow
        out_idx(0xea, crtc, 0x10); // Vertical sync start
        out_idx(0xdf, crtc, 0x12); // Vertical display end
        out_idx(0xe7, crtc, 0x15); // Vertical blank start
        out_idx(0x04, crtc, 0x16); // Vertical blank end
        let mut csel = inb(0x3cc); // CRTC miscellaneous output register
        csel &= 0x0d;
        csel |= 0xe2;
        outb(csel, 0x3c2);
    }
}

unsafe fn vga_set_vertical_end(lines: c_int) {
    unsafe {
        let end: c_int = lines - 1;

        let crtc = vga_crtc(); // CRTC base address

        let ovfw: u8 = (0x3c | ((end >> (8 - 1)) & 0x02) | ((end >> (9 - 6)) & 0x40)) as u8; // CRTC overflow register

        out_idx(ovfw, crtc, 0x07); // Vertical overflow
        out_idx(end as u8, crtc, 0x12); // Vertical display end
    }
}

unsafe fn vga_set_80x30() {
    unsafe {
        vga_set_480_scanlines();
        vga_set_vertical_end(30 * 16);
    }
}

unsafe fn vga_set_80x34() {
    unsafe {
        vga_set_480_scanlines();
        vga_set_14font();
        vga_set_vertical_end(34 * 14);
    }
}

unsafe fn vga_set_80x60() {
    unsafe {
        vga_set_480_scanlines();
        vga_set_8font();
        vga_set_vertical_end(60 * 8);
    }
}

unsafe extern "C" fn vga_set_mode(mode: *mut ModeInfo) -> c_int {
    unsafe {
        // Set the basic mode
        vga_set_basic_mode();

        // Override a possibly broken BIOS
        force_x = (*mode).x as c_int;
        force_y = (*mode).y as c_int;

        match (*mode).mode {
            VIDEO_80X25 => {}
            VIDEO_8POINT => vga_set_8font(),
            VIDEO_80X43 => vga_set_80x43(),
            VIDEO_80X28 => vga_set_14font(),
            VIDEO_80X30 => vga_set_80x30(),
            VIDEO_80X34 => vga_set_80x34(),
            VIDEO_80X60 => vga_set_80x60(),
            _ => {}
        }

        0
    }
}

static mut card_name: [*const c_char; 3] = [b"CGA/MDA/HGC\0".as_ptr() as *const c_char, b"EGA\0".as_ptr() as *const c_char, b"VGA\0".as_ptr() as *const c_char];
static mut mode_lists: [*mut ModeInfo; 3] = [core::ptr::addr_of_mut!(cga_modes) as *mut ModeInfo, core::ptr::addr_of_mut!(ega_modes) as *mut ModeInfo, core::ptr::addr_of_mut!(vga_modes) as *mut ModeInfo];
static mut mode_count: [c_int; 3] = [1, 2, 7];

/// Note: this probe includes basic information required by all systems.  It should be executed first, by making sure video-vga.c is listed first in the Makefile.
unsafe extern "C" fn vga_probe() -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        ireg.set_ax(0x1200);
        ireg.set_bl(0x10); // Check EGA/VGA
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        bp_wr16(SI_ORIG_VIDEO_EGA_BX, oreg.assume_init_ref().bx());

        // If we have MDA/CGA/HGC then BL will be unchanged at 0x10
        if oreg.assume_init_ref().bl() != 0x10 {
            // EGA/VGA
            ireg.set_ax(0x1a00);
            intcall(0x10, &ireg, oreg.as_mut_ptr());

            if oreg.assume_init_ref().al() == 0x1a {
                adapter = ADAPTER_VGA;
                bp_wr8(SI_ORIG_VIDEO_ISVGA, 1);
            } else {
                adapter = ADAPTER_EGA;
            }
        } else {
            adapter = ADAPTER_CGA;
        }

        // adapter is 0..=2 here (just assigned): unchecked indexing, as the C
        video_vga.modes = *mode_lists.get_unchecked(adapter as usize);
        video_vga.card_name = *card_name.get_unchecked(adapter as usize);
        *mode_count.get_unchecked(adapter as usize)
    }
}

#[cfg_attr(not(host_mock), link_section = ".videocards")]
#[cfg_attr(host_mock, link_section = "videocards_rs")]
#[used]
static mut video_vga: CardInfo = CardInfo {
    card_name: b"VGA\0".as_ptr() as *const c_char,
    set_mode: Some(vga_set_mode),
    probe: Some(vga_probe),
    modes: null_mut(),
    nmodes: 0,
    unsafe_: 0,
    xmode_first: 0,
    xmode_n: 0,
};
