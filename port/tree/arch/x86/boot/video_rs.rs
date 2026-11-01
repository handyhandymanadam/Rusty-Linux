// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/video.c (16-bit real-mode setup, code16, -Zregparm=3): the video mode setup the loader's `vga=` asks for.
//! Exports `set_video` (called by main()); everything else is static in the C. The helper routines of other objects it calls (probe_cards, set_mode,
//! vesa_store_edid, vga_crtc... video-mode.c / video-vesa.c, getchar/puts/printf of tty.c / printf.c, copy_*_fs of copy.S) stay behind their C symbols.
//!
//! Same sequence as the C. set_video: mode = boot_params.hdr.vid_mode; RESET_HEAP(); store_mode_params() (skipped for graphic_mode: INT 10h AH=03 cursor ->
//! orig_x/orig_y and the NOCURSOR flag (ch & 0x20, or (ch & 0x1f) > (cl & 0x1f)); AH=0F video mode/page; video_segment 0xb000 for mode 7 else 0xb800; BIOS data
//! area 0x485 font, 0x44a columns, 0x484 rows + 1 (25 on CGA), force_x/force_y override); save_screen() (cols x lines u16 cells to the heap if x*y*2 + 512 bytes are
//! free, via copy_from_fs); probe_cards(0); loop { if mode == ASK_VGA { mode = mode_menu() } if set_mode(mode) == 0 break; printf("Undefined video mode number: %x\n", mode);
//! mode = ASK_VGA }; hdr.vid_mode = mode; vesa_store_edid(); store_mode_params(); if do_restore { restore_screen() }.
//! mode_menu: puts the prompt, kbd_flush(), getchar_timeout() until ' ' or 0 (-> CURRENT_MODE) or '\r' (beep '\a' on anything else), then display_menu() / the
//! "Enter a video mode or \"scan\"..." prompt / get_entry() until the answer is not "scan" (0x1ccb7: probe_cards(1) and again). get_entry reads alphanumerics (max 4
//! kept, echoed; backspace erases with "\b \b") until '\r', echoes '\n'; empty = CURRENT_MODE; hex value of the characters (letters via `| 0x20`).
//! display_menu: header "Mode: Resolution:  Type: " once per column (3 columns when 20+ modes, else 1), each visible mode (x && y) as
//! printf("%c %03X %4dx%-7s %-6s", key char '0'..'9','a'..'z',' ', mode_id (mode or (y << 8) + x), x, "<y>" or "<y>x<depth>", card name), a newline per row.
//! restore_screen: (not for graphic_mode, needs saved data) rewrites the saved cells row by row (min(xs, saved.x) cells copied, the rest of the row blank 0x0720 via
//! the C's inline asm: `pushw %es; movw seg,%es; shrw %cx; jnc 1f; stosw; 1: rep stosl; popw %es`), clamps and restores the cursor (INT 10h AH=02), store_cursor_position().
//! All message strings are the C's, byte for byte.
//!
//! TEST-GAP: logs/realmode-video.md (the 30 s getchar_timeout expiry and keyboard behaviour of real BIOSes; screen save/restore only when a mode actually changes and
//! do_restore is set; graphic_mode; heap-too-small for the screen save; QEMU std VGA / SeaBIOS only).
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals)]

#[path = "rm_common.rs"]
mod rm;
#[path = "rm_video.rs"]
mod vid;

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rm::*;
use vid::*;

include!(concat!(env!("RM_GEN_DIR"), "/video_gen.rs"));

#[link_section = ".bss"]
static mut video_segment: u16 = 0;

unsafe fn store_cursor_position() {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        ireg.set_ah(0x03);
        intcall(0x10, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        bp_wr8(SI_ORIG_X, o.dl());
        bp_wr8(SI_ORIG_Y, o.dh());

        if o.ch() & 0x20 != 0 {
            bp_wr8(SI_FLAGS, bp_rd8(SI_FLAGS) | VIDEO_FLAGS_NOCURSOR);
        }

        if (o.ch() & 0x1f) > (o.cl() & 0x1f) {
            bp_wr8(SI_FLAGS, bp_rd8(SI_FLAGS) | VIDEO_FLAGS_NOCURSOR);
        }
    }
}

unsafe fn store_video_mode() {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        // N.B.: the saving of the video page here is a bit silly, since we pretty much assume page 0 everywhere.
        ireg.set_ah(0x0f);
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        // Not all BIOSes are clean with respect to the top bit
        bp_wr8(SI_ORIG_VIDEO_MODE, oreg.assume_init_ref().al() & 0x7f);
        bp_wr8(SI_ORIG_VIDEO_PAGE, oreg.assume_init_ref().bh());
    }
}

/// Store the video mode parameters for later usage by the kernel. This is done by asking the BIOS except for the rows/columns parameters in the default 80x25
/// mode -- these are set directly, because some very obscure BIOSes supply insane values.
unsafe fn store_mode_params() {
    unsafe {
        // For graphics mode, it is up to the mode-setting driver (currently only video-vesa.c) to store the parameters
        if graphic_mode != 0 {
            return;
        }

        store_cursor_position();
        store_video_mode();

        if bp_rd8(SI_ORIG_VIDEO_MODE) == 0x07 {
            // MDA, HGC, or VGA in monochrome mode
            video_segment = 0xb000;
        } else {
            // CGA, EGA, VGA and so forth
            video_segment = 0xb800;
        }

        set_fs(0);
        let font_size: u16 = rdfs16(0x485); // Font size, BIOS area
        bp_wr16(SI_ORIG_VIDEO_POINTS, font_size);

        let mut x: c_int = rdfs16(0x44a) as c_int;
        let mut y: c_int = if adapter == ADAPTER_CGA { 25 } else { rdfs8(0x484) as c_int + 1 };

        if force_x != 0 {
            x = force_x;
        }
        if force_y != 0 {
            y = force_y;
        }

        bp_wr8(SI_ORIG_VIDEO_COLS, x as u8);
        bp_wr8(SI_ORIG_VIDEO_LINES, y as u8);
    }
}

unsafe fn get_entry() -> u32 {
    unsafe {
        let mut entry_buf = core::mem::MaybeUninit::<[u8; 4]>::uninit();
        let eb = entry_buf.as_mut_ptr() as *mut u8;
        let mut len: c_int = 0;
        let mut key: c_int;

        loop {
            key = getchar();

            if key == b'\x08' as c_int {
                if len > 0 {
                    puts(b"\x08 \x08\0".as_ptr() as *const c_char);
                    len -= 1;
                }
            } else if (key >= b'0' as c_int && key <= b'9' as c_int)
                || (key >= b'A' as c_int && key <= b'Z' as c_int)
                || (key >= b'a' as c_int && key <= b'z' as c_int)
            {
                if (len as u32) < 4 {
                    *eb.offset(len as isize) = key as u8;
                    len += 1;
                    putchar(key);
                }
            }
            if key == b'\r' as c_int {
                break;
            }
        }
        putchar(b'\n' as c_int);

        if len == 0 {
            return VIDEO_CURRENT_MODE as u32; // Default
        }

        let mut v: u32 = 0;
        let mut i: c_int = 0;
        while i < len {
            v <<= 4;
            key = (*eb.offset(i as isize) as i8 as c_int) | 0x20;
            v = v.wrapping_add(if key > b'9' as c_int { (key - b'a' as c_int + 10) as u32 } else { (key - b'0' as c_int) as u32 });
            i += 1;
        }

        v
    }
}

unsafe fn display_menu() {
    unsafe {
        let mut nmodes: c_int = 0;
        let end = cards_end();
        let mut card = cards_begin();
        while card < end {
            nmodes += (*card).nmodes;
            card = card.add(1);
        }

        let mut modes_per_line: c_int = 1;
        if nmodes >= 20 {
            modes_per_line = 3;
        }

        let mut col: c_int = 0;
        while col < modes_per_line {
            puts(b"Mode: Resolution:  Type: \0".as_ptr() as *const c_char);
            col += 1;
        }
        putchar(b'\n' as c_int);

        col = 0;
        let mut ch: c_char = b'0' as c_char;
        card = cards_begin();
        while card < end {
            let mut mi = (*card).modes;
            let mut i: c_int = 0;
            while i < (*card).nmodes {
                let mut resbuf = core::mem::MaybeUninit::<[u8; 32]>::uninit();
                let rb = resbuf.as_mut_ptr() as *mut c_char;
                let visible = (*mi).x != 0 && (*mi).y != 0;
                let mode_id: u16 = if (*mi).mode != 0 { (*mi).mode } else { ((((*mi).y as c_int) << 8) + (*mi).x as c_int) as u16 };

                if !visible {
                    i += 1;
                    mi = mi.add(1);
                    continue; // Hidden mode
                }

                if (*mi).depth != 0 {
                    sprintf(rb, b"%dx%d\0".as_ptr() as *const c_char, (*mi).y as c_int, (*mi).depth as c_int);
                } else {
                    sprintf(rb, b"%d\0".as_ptr() as *const c_char, (*mi).y as c_int);
                }

                printf(
                    b"%c %03X %4dx%-7s %-6s\0".as_ptr() as *const c_char,
                    ch as c_int,
                    mode_id as c_int,
                    (*mi).x as c_int,
                    rb,
                    (*card).card_name,
                );
                col += 1;
                if col >= modes_per_line {
                    putchar(b'\n' as c_int);
                    col = 0;
                }

                if ch == b'9' as c_char {
                    ch = b'a' as c_char;
                } else if ch == b'z' as c_char || ch == b' ' as c_char {
                    ch = b' ' as c_char; // Out of keys...
                } else {
                    ch += 1;
                }
                i += 1;
                mi = mi.add(1);
            }
            card = card.add(1);
        }
        if col != 0 {
            putchar(b'\n' as c_int);
        }
    }
}

const fn h(x: u8) -> u32 {
    (x - b'a') as u32 + 10
}
const SCAN: u32 = (h(b's') << 12) + (h(b'c') << 8) + (h(b'a') << 4) + h(b'n');

unsafe fn mode_menu() -> u32 {
    unsafe {
        puts(b"Press <ENTER> to see video modes available, <SPACE> to continue, or wait 30 sec\n\0".as_ptr() as *const c_char);

        kbd_flush();
        loop {
            let key = getchar_timeout();
            if key == b' ' as c_int || key == 0 {
                return VIDEO_CURRENT_MODE as u32; // Default
            }
            if key == b'\r' as c_int {
                break;
            }
            putchar(7); // Beep!
        }

        loop {
            display_menu();

            puts(b"Enter a video mode or \"scan\" to scan for additional modes: \0".as_ptr() as *const c_char);
            let sel = get_entry();
            if sel != SCAN {
                return sel;
            }

            probe_cards(1);
        }
    }
}

/// Save screen content to the heap
#[repr(C)]
struct SavedScreen {
    x: c_int,
    y: c_int,
    curx: c_int,
    cury: c_int,
    data: *mut u16,
}
#[link_section = ".bss"]
static mut saved: SavedScreen = SavedScreen { x: 0, y: 0, curx: 0, cury: 0, data: null_mut() };

unsafe fn save_screen() {
    unsafe {
        // Should be called after store_mode_params()
        saved.x = bp_rd8(SI_ORIG_VIDEO_COLS) as c_int;
        saved.y = bp_rd8(SI_ORIG_VIDEO_LINES) as c_int;
        saved.curx = bp_rd8(SI_ORIG_X) as c_int;
        saved.cury = bp_rd8(SI_ORIG_Y) as c_int;

        if !heap_free(((saved.x * saved.y) as usize).wrapping_mul(2).wrapping_add(512)) {
            return; // Not enough heap to save the screen
        }

        saved.data = get_heap(2, 2, (saved.x * saved.y) as usize) as *mut u16;

        set_fs(video_segment);
        copy_from_fs(saved.data as *mut u8, 0, ((saved.x * saved.y) as usize).wrapping_mul(2));
    }
}

unsafe fn restore_screen() {
    unsafe {
        // Should be called after store_mode_params()
        let xs: c_int = bp_rd8(SI_ORIG_VIDEO_COLS) as c_int;
        let ys: c_int = bp_rd8(SI_ORIG_VIDEO_LINES) as c_int;
        let mut dst: u32 = 0;
        let mut src: *mut u16 = saved.data;

        if graphic_mode != 0 {
            return; // Can't restore onto a graphic mode
        }

        if src.is_null() {
            return; // No saved screen contents
        }

        // Restore screen contents

        set_fs(video_segment);
        let mut y: c_int = 0;
        while y < ys {
            let mut npad: c_int;

            if y < saved.y {
                let copy: c_int = if xs < saved.x { xs } else { saved.x };
                copy_to_fs(dst, src as *mut u8, (copy as usize).wrapping_mul(2));
                dst = dst.wrapping_add((copy as u32).wrapping_mul(2));
                src = src.offset(saved.x as isize);
                npad = if xs < saved.x { 0 } else { xs - saved.x };
            } else {
                npad = xs;
            }

            // Writes "npad" blank characters to video_segment:dst and advances dst
            #[cfg(not(host_mock))]
            core::arch::asm!(
                "push es",
                "mov es, dx",
                "shr cx, 1",
                "jnc 2f",
                "stosw",
                "2: rep stosd",
                "pop es",
                inout("edi") dst,
                inout("ecx") npad,
                in("dx") video_segment,
                in("eax") 0x07200720u32,
            );
            #[cfg(host_mock)]
            {
                let (d, n) = mock_blank_fill(video_segment, dst, npad as u32);
                dst = d;
                npad = n as c_int;
            }
            let _ = npad;
            y += 1;
        }

        // Restore cursor position
        if saved.curx >= xs {
            saved.curx = xs - 1;
        }
        if saved.cury >= ys {
            saved.cury = ys - 1;
        }

        let mut ireg = new_regs();
        ireg.set_ah(0x02); // Set cursor position
        ireg.set_dh(saved.cury as u8);
        ireg.set_dl(saved.curx as u8);
        intcall(0x10, &ireg, null_mut());

        store_cursor_position();
    }
}

#[cfg(host_mock)]
extern "C" {
    fn mock_blank_fill_hook(seg: u16, dst: u32, npad: u32, out: *mut u32);
}
/// host rigs only: the `rep stos` block as a function (returns the final edi and ecx)
#[cfg(host_mock)]
unsafe fn mock_blank_fill(seg: u16, dst: u32, npad: u32) -> (u32, u32) {
    unsafe {
        let mut out = [0u32; 2];
        mock_blank_fill_hook(seg, dst, npad, out.as_mut_ptr());
        (out[0], out[1])
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_video() {
    unsafe {
        let mut mode: u16 = bp_rd16(OFF_VID_MODE);

        reset_heap();

        store_mode_params();
        save_screen();
        probe_cards(0);

        loop {
            if mode == RM_ASK_VGA {
                mode = mode_menu() as u16;
            }

            if set_mode(mode) == 0 {
                break;
            }

            printf(b"Undefined video mode number: %x\n\0".as_ptr() as *const c_char, mode as c_int);
            mode = RM_ASK_VGA;
        }
        bp_wr16(OFF_VID_MODE, mode);
        vesa_store_edid();
        store_mode_params();

        if do_restore != 0 {
            restore_screen();
        }
    }
}
