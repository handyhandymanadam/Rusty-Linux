// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/video-vesa.c (16-bit real-mode setup, code16, -Zregparm=3): the "VESA" card (VBE text modes; graphics modes
//! only with CONFIG_BOOT_VESA_SUPPORT) and `vesa_store_edid` (the C's only non-static function; its body is empty without CONFIG_FIRMWARE_EDID).
//! The configuration switches come from the real autoconf.h through video_gen.rs (video_gen.rs.in, same C-preprocessor rule as the other *_gen.rs), so
//! the arms the C compiles out are compiled out here too (BOOT_VESA_SUPPORT: probe registers graphics modes, set_mode accepts them and
//! vesa_store_mode_params_graphics / vesa_dac_set_8bits / vesa_store_pm_info are live).
//!
//! Same sequence as the C. vesa_probe: INT 10h AX=4F00 DI=&vginfo (256 bytes: signature 'VESA' at 0, version at 4, capabilities at 10, mode-list far pointer at
//! 14 (off) / 16 (seg), total_memory at 18); not present unless AX == 0x004f, signature == 'VESA', version >= 0x0102; walks the mode list through fs:(far ptr) until
//! 0xffff while a mode_info fits on the heap; modes with bits above 0x1ff are skipped; INT 10h AX=4F01 CX=mode DI=&vminfo (256 bytes, memset first; mode_attr at 0,
//! logical_scan 16, h_res 18, v_res 20, memory_planes 24, bpp 25, memory_layout 27, image_planes 29, rmask..resv_pos 31..38, lfb_ptr 40): text modes
//! (attr & 0x15 == 0x05) are registered with depth 0; graphics (attr & 0x99 == 0x99, layout 4 or 6, 1 plane) only with BOOT_VESA_SUPPORT (depth = bpp).
//! vesa_set_mode: 4F01 again (memset first), text mode or (BOOT_VESA_SUPPORT) graphics with 0x4000 requested, INT 10h AX=4F02 BX=mode; graphic_mode = is_graphic;
//! text: force_x/force_y = x/y and do_restore = 1; graphics: vesa_store_mode_params_graphics (screen_info: isVGA = 0x23, vesa_attributes, lfb_linelength/width/height/depth,
//! pages = image_planes, lfb_base, the 8 mask/pos bytes copied from vminfo.rmask, lfb_size = total_memory; bpp <= 8: DAC to 8 bits (4F08 BH=8 when capabilities & 1,
//! else/6 bits) and zero positions; then 4F0A protected-mode info into vesapm_seg/off). vesa_store_edid (FIRMWARE_EDID): edid_info filled with 0x13, VBE < 2.0 stops, INT 10h
//! AX=4F15 (BX=0, ES=0) then BX=1 with ES:DI = ds:&edid_info.
//!
//! TEST-GAP: logs/realmode-video.md (the graphics arms and the EDID arm are compiled out of the two built configurations; QEMU std VGA has VBE and EDID only in the
//! variant build `build-vid`; real VBE BIOSes and modes; ds != 0x1000 only host).
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals)]

#[path = "rm_common.rs"]
mod rm;
#[path = "rm_video.rs"]
mod vid;

use core::ffi::{c_char, c_int};
use core::ptr::{addr_of_mut, null_mut};
use rm::*;
use vid::*;

include!(concat!(env!("RM_GEN_DIR"), "/video_gen.rs"));

// memset()/memcpy() of the C are core::ptr::write_bytes / copy_nonoverlapping (LLVM lowers them to the same libcalls, defined by copy.S).
#[inline(always)]
unsafe fn memset(s: *mut u8, c: c_int, n: usize) {
    unsafe { core::ptr::write_bytes(s, c as u8, n) }
}
#[inline(always)]
unsafe fn memcpy(d: *mut u8, s: *const u8, n: usize) {
    unsafe { core::ptr::copy_nonoverlapping(s, d, n) }
}

const SIZEOF_VGINFO: usize = 256; // struct vesa_general_info (packed)
const SIZEOF_VMINFO: usize = 256; // struct vesa_mode_info (packed)
const VESA_MAGIC: u32 = 0x4153_4556; // 'V' + ('E' << 8) + ('S' << 16) + ('A' << 24)

// vesa_general_info offsets
const VG_SIGNATURE: usize = 0;
const VG_VERSION: usize = 4;
const VG_CAPABILITIES: usize = 10;
const VG_MODE_PTR_OFF: usize = 14;
const VG_MODE_PTR_SEG: usize = 16;
const VG_TOTAL_MEMORY: usize = 18;
// vesa_mode_info offsets
const VM_MODE_ATTR: usize = 0;
const VM_LOGICAL_SCAN: usize = 16;
const VM_H_RES: usize = 18;
const VM_V_RES: usize = 20;
const VM_MEMORY_PLANES: usize = 24;
const VM_BPP: usize = 25;
const VM_MEMORY_LAYOUT: usize = 27;
const VM_IMAGE_PLANES: usize = 29;
const VM_RMASK: usize = 31;
const VM_LFB_PTR: usize = 40;

/// VESA information (`static struct vesa_general_info vginfo; static struct vesa_mode_info vminfo;`, zero-initialised: plain `.bss`)
#[link_section = ".bss"]
#[cfg_attr(host_mock, no_mangle)] // host rigs: the BIOS mock needs the buffers' addresses
pub static mut vginfo: [u8; SIZEOF_VGINFO] = [0; SIZEOF_VGINFO];
#[link_section = ".bss"]
#[cfg_attr(host_mock, no_mangle)]
pub static mut vminfo: [u8; SIZEOF_VMINFO] = [0; SIZEOF_VMINFO];

#[inline(always)]
unsafe fn vg8(off: usize) -> u8 {
    unsafe { (addr_of_mut!(vginfo) as *const u8).add(off).read() }
}
#[inline(always)]
unsafe fn vg16(off: usize) -> u16 {
    unsafe { (addr_of_mut!(vginfo) as *const u8).add(off).cast::<u16>().read_unaligned() }
}
#[inline(always)]
unsafe fn vg32(off: usize) -> u32 {
    unsafe { (addr_of_mut!(vginfo) as *const u8).add(off).cast::<u32>().read_unaligned() }
}
#[inline(always)]
unsafe fn vm8(off: usize) -> u8 {
    unsafe { (addr_of_mut!(vminfo) as *const u8).add(off).read() }
}
#[inline(always)]
unsafe fn vm16(off: usize) -> u16 {
    unsafe { (addr_of_mut!(vminfo) as *const u8).add(off).cast::<u16>().read_unaligned() }
}
#[inline(always)]
unsafe fn vm32(off: usize) -> u32 {
    unsafe { (addr_of_mut!(vminfo) as *const u8).add(off).cast::<u32>().read_unaligned() }
}

unsafe extern "C" fn vesa_probe() -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        let mut nmodes: c_int = 0;

        video_vesa.modes = get_heap(core::mem::size_of::<ModeInfo>(), core::mem::align_of::<ModeInfo>(), 0) as *mut ModeInfo;

        ireg.set_ax(0x4f00);
        ireg.set_di(addr_of_mut!(vginfo) as usize as u16);
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        if oreg.assume_init_ref().ax() != 0x004f || vg32(VG_SIGNATURE) != VESA_MAGIC || vg16(VG_VERSION) < 0x0102 {
            return 0; // Not present
        }

        set_fs(vg16(VG_MODE_PTR_SEG));
        let mut mode_ptr: u32 = vg16(VG_MODE_PTR_OFF) as u32;

        loop {
            let mode = rdfs16(mode_ptr);
            if mode == 0xffff {
                break;
            }
            mode_ptr = mode_ptr.wrapping_add(2);

            if !heap_free(core::mem::size_of::<ModeInfo>()) {
                break; // Heap full, can't save mode info
            }

            if mode & !0x1ff != 0 {
                continue;
            }

            memset(addr_of_mut!(vminfo) as *mut u8, 0, SIZEOF_VMINFO); // Just in case...

            ireg.set_ax(0x4f01);
            ireg.set_cx(mode);
            ireg.set_di(addr_of_mut!(vminfo) as usize as u16);
            intcall(0x10, &ireg, oreg.as_mut_ptr());

            if oreg.assume_init_ref().ax() != 0x004f {
                continue;
            }

            if (vm16(VM_MODE_ATTR) & 0x15) == 0x05 {
                // Text Mode, TTY BIOS supported, supported by hardware
                let mi = get_heap(core::mem::size_of::<ModeInfo>(), core::mem::align_of::<ModeInfo>(), 1) as *mut ModeInfo;
                (*mi).mode = mode.wrapping_add(VIDEO_FIRST_VESA);
                (*mi).depth = 0; // text
                (*mi).x = vm16(VM_H_RES);
                (*mi).y = vm16(VM_V_RES);
                nmodes += 1;
            } else if (vm16(VM_MODE_ATTR) & 0x99) == 0x99 && (vm8(VM_MEMORY_LAYOUT) == 4 || vm8(VM_MEMORY_LAYOUT) == 6) && vm8(VM_MEMORY_PLANES) == 1 {
                if RM_BOOT_VESA_SUPPORT {
                    // Graphics mode, color, linear frame buffer supported.  Only register the mode if if framebuffer is configured, however,
                    // otherwise the user will be left without a screen.
                    let mi = get_heap(core::mem::size_of::<ModeInfo>(), core::mem::align_of::<ModeInfo>(), 1) as *mut ModeInfo;
                    (*mi).mode = mode.wrapping_add(VIDEO_FIRST_VESA);
                    (*mi).depth = vm8(VM_BPP) as u16;
                    (*mi).x = vm16(VM_H_RES);
                    (*mi).y = vm16(VM_V_RES);
                    nmodes += 1;
                }
            }
        }

        nmodes
    }
}

unsafe extern "C" fn vesa_set_mode(mode: *mut ModeInfo) -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        let is_graphic: c_int;
        let mut vesa_mode: u16 = (*mode).mode.wrapping_sub(VIDEO_FIRST_VESA);

        memset(addr_of_mut!(vminfo) as *mut u8, 0, SIZEOF_VMINFO); // Just in case...

        ireg.set_ax(0x4f01);
        ireg.set_cx(vesa_mode);
        ireg.set_di(addr_of_mut!(vminfo) as usize as u16);
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        if oreg.assume_init_ref().ax() != 0x004f {
            return -1;
        }

        if (vm16(VM_MODE_ATTR) & 0x15) == 0x05 {
            // It's a supported text mode
            is_graphic = 0;
        } else if RM_BOOT_VESA_SUPPORT && (vm16(VM_MODE_ATTR) & 0x99) == 0x99 {
            // It's a graphics mode with linear frame buffer
            is_graphic = 1;
            vesa_mode |= 0x4000; // Request linear frame buffer
        } else {
            return -1; // Invalid mode
        }

        ireg = new_regs();
        ireg.set_ax(0x4f02);
        ireg.set_bx(vesa_mode);
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        if oreg.assume_init_ref().ax() != 0x004f {
            return -1;
        }

        graphic_mode = is_graphic;
        if is_graphic == 0 {
            // Text mode
            force_x = (*mode).x as c_int;
            force_y = (*mode).y as c_int;
            do_restore = 1;
        } else {
            // Graphics mode
            vesa_store_mode_params_graphics();
        }

        0
    }
}

/// Switch DAC to 8-bit mode
unsafe fn vesa_dac_set_8bits() {
    unsafe {
        let mut dac_size: u8 = 6;

        // If possible, switch the DAC to 8-bit mode
        if vg32(VG_CAPABILITIES) & 1 != 0 {
            let mut ireg = new_regs();
            let mut oreg = out_regs();
            ireg.set_ax(0x4f08);
            ireg.set_bh(0x08);
            intcall(0x10, &ireg, oreg.as_mut_ptr());
            if oreg.assume_init_ref().ax() == 0x004f {
                dac_size = oreg.assume_init_ref().bh();
            }
        }

        // Set the color sizes to the DAC size, and offsets to 0
        bp_wr8(SI_RED_SIZE, dac_size);
        bp_wr8(SI_GREEN_SIZE, dac_size);
        bp_wr8(SI_BLUE_SIZE, dac_size);
        bp_wr8(SI_RSVD_SIZE, dac_size);

        bp_wr8(SI_RED_POS, 0);
        bp_wr8(SI_GREEN_POS, 0);
        bp_wr8(SI_BLUE_POS, 0);
        bp_wr8(SI_RSVD_POS, 0);
    }
}

/// Save the VESA protected mode info
unsafe fn vesa_store_pm_info() {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        ireg.set_ax(0x4f0a);
        intcall(0x10, &ireg, oreg.as_mut_ptr());

        if oreg.assume_init_ref().ax() != 0x004f {
            return;
        }

        bp_wr16(SI_VESAPM_SEG, oreg.assume_init_ref().es);
        bp_wr16(SI_VESAPM_OFF, oreg.assume_init_ref().di());
    }
}

/// Save video mode parameters for graphics mode
unsafe fn vesa_store_mode_params_graphics() {
    unsafe {
        // Tell the kernel we're in VESA graphics mode
        bp_wr8(SI_ORIG_VIDEO_ISVGA, VIDEO_TYPE_VLFB);

        // Mode parameters
        bp_wr16(SI_VESA_ATTRIBUTES, vm16(VM_MODE_ATTR));
        bp_wr16(SI_LFB_LINELENGTH, vm16(VM_LOGICAL_SCAN));
        bp_wr16(SI_LFB_WIDTH, vm16(VM_H_RES));
        bp_wr16(SI_LFB_HEIGHT, vm16(VM_V_RES));
        bp_wr16(SI_LFB_DEPTH, vm8(VM_BPP) as u16);
        bp_wr16(SI_PAGES, vm8(VM_IMAGE_PLANES) as u16);
        bp_wr32(SI_LFB_BASE, vm32(VM_LFB_PTR));
        memcpy(bp().add(SI_RED_SIZE), (addr_of_mut!(vminfo) as *const u8).add(VM_RMASK), 8);

        // General parameters
        bp_wr32(SI_LFB_SIZE, vg16(VG_TOTAL_MEMORY) as u32);

        if vm8(VM_BPP) <= 8 {
            vesa_dac_set_8bits();
        }

        vesa_store_pm_info();
    }
}

/// Save EDID information for the kernel; this is invoked, separately, after mode-setting.
#[no_mangle]
pub unsafe extern "C" fn vesa_store_edid() {
    unsafe {
        if RM_FIRMWARE_EDID {
            // Apparently used as a nonsense token...
            memset(bp().add(OFF_EDID_INFO), 0x13, SIZEOF_EDID_INFO);

            if vg16(VG_VERSION) < 0x0200 {
                return; // EDID requires VBE 2.0+
            }

            let mut ireg = new_regs();
            let mut oreg = out_regs();

            ireg.set_ax(0x4f15); // VBE DDC
            // ireg.bx = 0x0000; // Report DDC capabilities
            // ireg.cx = 0; // Controller 0
            ireg.es = 0; // ES:DI must be 0 by spec
            intcall(0x10, &ireg, oreg.as_mut_ptr());

            if oreg.assume_init_ref().ax() != 0x004f {
                return; // No EDID
            }

            // BH = time in seconds to transfer EDD information
            // BL = DDC level supported

            ireg.set_ax(0x4f15); // VBE DDC
            ireg.set_bx(0x0001); // Read EDID
            // ireg.cx = 0; // Controller 0
            // ireg.dx = 0; // EDID block number
            ireg.es = ds();
            ireg.set_di(bp().add(OFF_EDID_INFO) as usize as u16); // (ES:)Pointer to block
            intcall(0x10, &ireg, oreg.as_mut_ptr());
        }
    }
}

#[cfg_attr(not(host_mock), link_section = ".videocards")]
#[cfg_attr(host_mock, link_section = "videocards_rs")]
#[used]
static mut video_vesa: CardInfo = CardInfo {
    card_name: b"VESA\0".as_ptr() as *const c_char,
    set_mode: Some(vesa_set_mode),
    probe: Some(vesa_probe),
    modes: null_mut(),
    nmodes: 0,
    unsafe_: 0,
    xmode_first: VIDEO_FIRST_VESA,
    xmode_n: 0x200,
};
