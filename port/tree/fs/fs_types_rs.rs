// SPDX-License-Identifier: GPL-2.0

//! File type conversions -- the Rust behind `fs/fs_types.c`.
//!
//! Ported from `fs/fs_types.c` (6.18.49). The file is two 8- and 16-entry lookup tables and three
//! `EXPORT_SYMBOL_GPL` functions over them: `fs_ftype_to_dtype()` (on-disk `FT_*` to `DT_*`),
//! `fs_umode_to_ftype()` (an inode mode's `S_IFMT` bits to `FT_*`) and `fs_umode_to_dtype()` (both
//! steps). Values are `include/linux/fs_types.h` (`FT_*`, `DT_*`, `S_DT`): `rig/` checks them against
//! the C by running both over every input.
//!
//! None of the three has a guard, WARN or static key, so no C entry stays: `kernel::kabi_export!`
//! carries each export and its MODVERSIONS contract (C fingerprints 0x184fc3db, 0x4ee8c5f2,
//! 0x4ee8c5f2, from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: fs/fs_types.c

use core::ffi::c_uint;

const DT_UNKNOWN: u8 = 0;
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

const FT_UNKNOWN: u8 = 0;
const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;
const FT_CHRDEV: u8 = 3;
const FT_BLKDEV: u8 = 4;
const FT_FIFO: u8 = 5;
const FT_SOCK: u8 = 6;
const FT_SYMLINK: u8 = 7;
const FT_MAX: c_uint = 8;

const S_IFMT: u16 = 0o170000;
const S_DT_SHIFT: u32 = 12;
/// `DT_MAX`: `(S_IFMT >> S_DT_SHIFT) + 1`.
const DT_MAX: usize = 16;

static FS_DTYPE_BY_FTYPE: [u8; FT_MAX as usize] = {
    let mut t = [DT_UNKNOWN; FT_MAX as usize];
    t[FT_UNKNOWN as usize] = DT_UNKNOWN;
    t[FT_REG_FILE as usize] = DT_REG;
    t[FT_DIR as usize] = DT_DIR;
    t[FT_CHRDEV as usize] = DT_CHR;
    t[FT_BLKDEV as usize] = DT_BLK;
    t[FT_FIFO as usize] = DT_FIFO;
    t[FT_SOCK as usize] = DT_SOCK;
    t[FT_SYMLINK as usize] = DT_LNK;
    t
};

static FS_FTYPE_BY_DTYPE: [u8; DT_MAX] = {
    let mut t = [FT_UNKNOWN; DT_MAX];
    t[DT_REG as usize] = FT_REG_FILE;
    t[DT_DIR as usize] = FT_DIR;
    t[DT_LNK as usize] = FT_SYMLINK;
    t[DT_CHR as usize] = FT_CHRDEV;
    t[DT_BLK as usize] = FT_BLKDEV;
    t[DT_FIFO as usize] = FT_FIFO;
    t[DT_SOCK as usize] = FT_SOCK;
    t
};

/// `S_DT(mode)`.
#[inline(always)]
fn s_dt(mode: u16) -> usize {
    ((mode & S_IFMT) >> S_DT_SHIFT) as usize
}

kernel::kabi_rule!("type_string", "t#umode_t",
    "typedef_type umode_t { base_type unsigned short byte_size(2) encoding(7) }");

kernel::kabi_export! {
    fs_ftype_to_dtype,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) filetype ) -> base_type unsigned char byte_size(1) encoding(8)",
}

/// `fs_ftype_to_dtype()`: on-disk file type (`FT_*`) to directory-entry type (`DT_*`).
#[no_mangle]
pub extern "C" fn fs_ftype_to_dtype(filetype: c_uint) -> u8 {
    if filetype >= FT_MAX {
        return DT_UNKNOWN;
    }

    FS_DTYPE_BY_FTYPE[filetype as usize]
}

kernel::kabi_export! {
    fs_umode_to_ftype,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#umode_t mode ) -> base_type unsigned char byte_size(1) encoding(8)",
}

/// `fs_umode_to_ftype()`: inode mode to on-disk file type (`FT_*`).
#[no_mangle]
pub extern "C" fn fs_umode_to_ftype(mode: u16) -> u8 {
    FS_FTYPE_BY_DTYPE[s_dt(mode)]
}

kernel::kabi_export! {
    fs_umode_to_dtype,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#umode_t mode ) -> base_type unsigned char byte_size(1) encoding(8)",
}

/// `fs_umode_to_dtype()`: inode mode to directory-entry type (`DT_*`).
#[no_mangle]
pub extern "C" fn fs_umode_to_dtype(mode: u16) -> u8 {
    fs_ftype_to_dtype(fs_umode_to_ftype(mode) as c_uint)
}
