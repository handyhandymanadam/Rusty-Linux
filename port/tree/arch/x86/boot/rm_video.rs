// SPDX-License-Identifier: GPL-2.0-only
//! Declarations shared by the five video ports (video.c, video-mode.c, video-vga.c, video-vesa.c, video-bios.c): video.h's structures and
//! constants, the VGA indexed-register helpers, the `boot_params.screen_info` accessors, and the callees in the other setup objects.
//! `#[path = "rm_video.rs"] mod vid;` (it itself uses rm_common.rs). Under `--cfg host_mock` (host rigs only) the console/keyboard callees and
//! the copy_*fs routines are mock hooks.
#![allow(dead_code, static_mut_refs)]

use super::rm::*;
use core::ffi::{c_char, c_int};
use core::ptr::addr_of_mut;

// video.h
pub const VIDEO_FIRST_BIOS: u16 = 0x0100;
pub const VIDEO_FIRST_VESA: u16 = 0x0200;
pub const VIDEO_80X25: u16 = 0x0f00;
pub const VIDEO_8POINT: u16 = 0x0f01;
pub const VIDEO_80X43: u16 = 0x0f02;
pub const VIDEO_80X28: u16 = 0x0f03;
pub const VIDEO_CURRENT_MODE: u16 = 0x0f04;
pub const VIDEO_80X30: u16 = 0x0f05;
pub const VIDEO_80X34: u16 = 0x0f06;
pub const VIDEO_80X60: u16 = 0x0f07;
pub const VIDEO_RECALC: u16 = 0x8000;
pub const ADAPTER_CGA: c_int = 0;
pub const ADAPTER_EGA: c_int = 1;
pub const ADAPTER_VGA: c_int = 2;

/// `struct mode_info` (video.h): 8 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModeInfo {
    pub mode: u16, // Mode number (vga= style)
    pub x: u16,    // Width, height
    pub y: u16,
    pub depth: u16, // Bits per pixel, 0 for text mode
}

/// `struct card_info` (video.h): 28 bytes on the target.
#[repr(C)]
pub struct CardInfo {
    pub card_name: *const c_char,
    pub set_mode: Option<unsafe extern "C" fn(*mut ModeInfo) -> c_int>,
    pub probe: Option<unsafe extern "C" fn() -> c_int>,
    pub modes: *mut ModeInfo,
    pub nmodes: c_int,       // Number of probed modes so far
    pub unsafe_: c_int,      // Probing is unsafe, only do after "scan"
    pub xmode_first: u16,    // Unprobed modes to try to call anyway
    pub xmode_n: u16,        // Size of unprobed mode range
}
const _: () = assert!(core::mem::size_of::<ModeInfo>() == 8);
#[cfg(not(host_mock))]
const _: () = assert!(core::mem::size_of::<CardInfo>() == 28);

// boot_params offsets (struct screen_info at 0, hdr.vid_mode, edid_info; checked against the real header by the host rigs and the asserts there)
pub const SI_ORIG_X: usize = 0;
pub const SI_ORIG_Y: usize = 1;
pub const SI_ORIG_VIDEO_PAGE: usize = 4;
pub const SI_ORIG_VIDEO_MODE: usize = 6;
pub const SI_ORIG_VIDEO_COLS: usize = 7;
pub const SI_FLAGS: usize = 8;
pub const SI_ORIG_VIDEO_EGA_BX: usize = 10;
pub const SI_ORIG_VIDEO_LINES: usize = 14;
pub const SI_ORIG_VIDEO_ISVGA: usize = 15;
pub const SI_ORIG_VIDEO_POINTS: usize = 16;
pub const SI_LFB_WIDTH: usize = 18;
pub const SI_LFB_HEIGHT: usize = 20;
pub const SI_LFB_DEPTH: usize = 22;
pub const SI_LFB_BASE: usize = 24;
pub const SI_LFB_SIZE: usize = 28;
pub const SI_LFB_LINELENGTH: usize = 36;
pub const SI_RED_SIZE: usize = 38;
pub const SI_RED_POS: usize = 39;
pub const SI_GREEN_SIZE: usize = 40;
pub const SI_GREEN_POS: usize = 41;
pub const SI_BLUE_SIZE: usize = 42;
pub const SI_BLUE_POS: usize = 43;
pub const SI_RSVD_SIZE: usize = 44;
pub const SI_RSVD_POS: usize = 45;
pub const SI_VESAPM_SEG: usize = 46;
pub const SI_VESAPM_OFF: usize = 48;
pub const SI_PAGES: usize = 50;
pub const SI_VESA_ATTRIBUTES: usize = 52;
pub const OFF_EDID_INFO: usize = 0x140;
pub const SIZEOF_EDID_INFO: usize = 128;
pub const OFF_VID_MODE: usize = 0x1fa;
pub const VIDEO_FLAGS_NOCURSOR: u8 = 1;
pub const VIDEO_TYPE_VLFB: u8 = 0x23;

extern "C" {
    pub static mut boot_params: [u8; 4096];
    pub static mut adapter: c_int;
    pub static mut force_x: c_int;
    pub static mut force_y: c_int;
    pub static mut do_restore: c_int;
    pub static mut graphic_mode: c_int;
    pub fn vga_crtc() -> u16;
}
#[cfg(not(host_mock))]
extern "C" {
    pub fn mode_defined(mode: u16) -> c_int;
    pub fn set_mode(mode: u16) -> c_int;
    pub fn probe_cards(unsafe_: c_int);
    pub fn vesa_store_edid();
    pub fn puts(s: *const c_char);
    pub fn putchar(c: c_int);
    pub fn getchar() -> c_int;
    pub fn kbd_flush();
    pub fn getchar_timeout() -> c_int;
    pub fn sprintf(buf: *mut c_char, fmt: *const c_char, ...) -> c_int;
    pub fn printf(fmt: *const c_char, ...) -> c_int;
    pub fn copy_to_fs(dst: u32, src: *mut u8, len: usize);
    pub fn copy_from_fs(dst: *mut u8, src: u32, len: usize) -> *mut u8;
    pub static mut video_cards: CardInfo;
    pub static mut video_cards_end: CardInfo;
}
// host rigs: every libc-named callee is a mock_* hook; the video_cards table is the linker's __start/__stop of a C-identifier section
#[cfg(host_mock)]
extern "C" {
    pub fn mode_defined(mode: u16) -> c_int;
    pub fn set_mode(mode: u16) -> c_int;
    pub fn probe_cards(unsafe_: c_int);
    pub fn vesa_store_edid();
    #[link_name = "mock_puts"]
    pub fn puts(s: *const c_char);
    #[link_name = "mock_putchar"]
    pub fn putchar(c: c_int);
    #[link_name = "mock_getchar"]
    pub fn getchar() -> c_int;
    #[link_name = "mock_kbd_flush"]
    pub fn kbd_flush();
    #[link_name = "mock_getchar_timeout"]
    pub fn getchar_timeout() -> c_int;
    #[link_name = "mock_sprintf"]
    pub fn sprintf(buf: *mut c_char, fmt: *const c_char, ...) -> c_int;
    #[link_name = "mock_printf"]
    pub fn printf(fmt: *const c_char, ...) -> c_int;
    #[link_name = "mock_copy_to_fs"]
    pub fn copy_to_fs(dst: u32, src: *mut u8, len: usize);
    #[link_name = "mock_copy_from_fs"]
    pub fn copy_from_fs(dst: *mut u8, src: u32, len: usize) -> *mut u8;
    #[link_name = "__start_videocards_rs"]
    pub static mut video_cards: CardInfo;
    #[link_name = "__stop_videocards_rs"]
    pub static mut video_cards_end: CardInfo;
}

/// The section the card tables live in (setup.ld collects `.videocards` between video_cards and video_cards_end; the host rig uses a C-identifier name so the
/// GNU linker defines __start_/__stop_ symbols for it).
// (the attribute is applied at each static: cfg_attr(host_mock, link_section = "videocards_rs") / link_section = ".videocards")

#[inline(always)]
pub unsafe fn outw(v: u16, port: u16) {
    unsafe { (pio_ops.f_outw.unwrap_unchecked())(v, port) }
}
/// video.h `in_idx(port, index)`
#[inline(always)]
pub unsafe fn in_idx(port: u16, index: u8) -> u8 {
    unsafe {
        outb(index, port);
        inb(port.wrapping_add(1))
    }
}
/// video.h `out_idx(v, port, index)`: `outw(index+(v << 8), port)`
#[inline(always)]
pub unsafe fn out_idx(v: u8, port: u16, index: u8) {
    unsafe { outw((index as i32 + ((v as i32) << 8)) as u16, port) }
}

#[inline(always)]
pub fn bp() -> *mut u8 {
    addr_of_mut!(boot_params) as *mut u8
}
#[inline(always)]
pub unsafe fn bp_rd8(off: usize) -> u8 {
    unsafe { bp().add(off).read() }
}
#[inline(always)]
pub unsafe fn bp_wr8(off: usize, v: u8) {
    unsafe { bp().add(off).write(v) }
}
#[inline(always)]
pub unsafe fn bp_rd16(off: usize) -> u16 {
    unsafe { bp().add(off).cast::<u16>().read_unaligned() }
}
#[inline(always)]
pub unsafe fn bp_wr16(off: usize, v: u16) {
    unsafe { bp().add(off).cast::<u16>().write_unaligned(v) }
}
#[inline(always)]
pub unsafe fn bp_wr32(off: usize, v: u32) {
    unsafe { bp().add(off).cast::<u32>().write_unaligned(v) }
}

/// Iterate `for (card = video_cards; card < video_cards_end; card++)`: the first/one-past-last card pointers.
#[inline(always)]
pub unsafe fn cards_begin() -> *mut CardInfo {
    addr_of_mut!(video_cards)
}
#[inline(always)]
pub unsafe fn cards_end() -> *mut CardInfo {
    addr_of_mut!(video_cards_end)
}
