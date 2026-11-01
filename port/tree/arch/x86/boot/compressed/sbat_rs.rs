// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/sbat.S (STUBH, Phase C): embed the SBAT data
//! (CONFIG_EFI_SBAT_FILE) in the kernel, as the ".sbat" section vmlinux.lds.S places.
//!
//! `.incbin CONFIG_EFI_SBAT_FILE` takes its file name from the build: the Makefile passes it as the
//! environment variable `STUBH_SBAT_FILE` (an ABSOLUTE path, since rustc's assembler has no `-I`;
//! the .S found it through `-I $(srctree)`). No symbols, no relocations: the object is one
//! `.sbat` section.
//! NOT ACTIVE in the stub today: boot_rust_ok excludes CONFIG_EFI_SBAT (the stub's `--gc-sections`
//! would discard an unreferenced `.sbat`, and nothing here boots an SBAT kernel), so the Makefile
//! keeps the original sbat.S object in that configuration. The Rust is object-compared anyway
//! (rig/stubh/check.sh) so it is ready when that gate is lifted.
//! TEST-GAP: not wired (see above); object-compared with a test SBAT file only.

use core::arch::global_asm;

global_asm!(
    concat!(
        "\t.pushsection \".sbat\", \"a\", @progbits\n",
        "\t.incbin \"",
        env!("STUBH_SBAT_FILE"),
        "\"\n",
        "\t.popsection\n"
    ),
    options(att_syntax)
);
