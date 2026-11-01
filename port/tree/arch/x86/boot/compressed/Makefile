# SPDX-License-Identifier: GPL-2.0
#
# linux/arch/x86/boot/compressed/Makefile
#
# create a compressed vmlinux image from the original vmlinux
#
# vmlinuz is:
#	decompression code (*.o)
#	asm globals (piggy.S), including:
#		vmlinux.bin.(gz|bz2|lzma|...)
#
# vmlinux.bin is:
#	vmlinux stripped of debugging and comments
# vmlinux.bin.all is:
#	vmlinux.bin + vmlinux.relocs
# vmlinux.bin.(gz|bz2|lzma|...) is:
#	(see scripts/Makefile.lib size_append)
#	compressed vmlinux.bin.all + u32 size of vmlinux.bin.all

targets := vmlinux vmlinux.bin vmlinux.bin.gz vmlinux.bin.bz2 vmlinux.bin.lzma \
	vmlinux.bin.xz vmlinux.bin.lzo vmlinux.bin.lz4 vmlinux.bin.zst

# CLANG_FLAGS must come before any cc-disable-warning or cc-option calls in
# case of cross compiling, as it has the '--target=' flag, which is needed to
# avoid errors with '-march=i386', and future flags may depend on the target to
# be valid.
KBUILD_CFLAGS := -m$(BITS) -O2 $(CLANG_FLAGS)
KBUILD_CFLAGS += -std=gnu11
KBUILD_CFLAGS += -fno-strict-aliasing -fPIE
KBUILD_CFLAGS += -fno-jump-tables
KBUILD_CFLAGS += -Wundef
KBUILD_CFLAGS += -DDISABLE_BRANCH_PROFILING
cflags-$(CONFIG_X86_32) := -march=i386
cflags-$(CONFIG_X86_64) := -mcmodel=small -mno-red-zone
KBUILD_CFLAGS += $(cflags-y)
KBUILD_CFLAGS += -mno-mmx -mno-sse
KBUILD_CFLAGS += -ffreestanding -fshort-wchar
KBUILD_CFLAGS += -fno-stack-protector
KBUILD_CFLAGS += $(call cc-disable-warning, address-of-packed-member)
KBUILD_CFLAGS += $(call cc-disable-warning, gnu)
KBUILD_CFLAGS += -Wno-pointer-sign
KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
KBUILD_CFLAGS += -D__DISABLE_EXPORTS
# Disable relocation relaxation in case the link is not PIE.
KBUILD_CFLAGS += $(call cc-option,-Wa$(comma)-mrelax-relocations=no)
KBUILD_CFLAGS += -include $(srctree)/include/linux/hidden.h

# sev-decode-insn.c indirectly includes inat-table.c which is generated during
# compilation and stored in $(objtree). Add the directory to the includes so
# that the compiler finds it even with out-of-tree builds (make O=/some/path).
CFLAGS_sev-handle-vc.o += -I$(objtree)/arch/x86/lib/

KBUILD_AFLAGS  := $(KBUILD_CFLAGS) -D__ASSEMBLY__

KBUILD_LDFLAGS := -m elf_$(UTS_MACHINE)
KBUILD_LDFLAGS += $(call ld-option,--no-ld-generated-unwind-info)
# Compressed kernel should be built as PIE since it may be loaded at any
# address by the bootloader.
LDFLAGS_vmlinux := -pie $(call ld-option, --no-dynamic-linker)
ifdef CONFIG_LD_ORPHAN_WARN
LDFLAGS_vmlinux += --orphan-handling=$(CONFIG_LD_ORPHAN_WARN_LEVEL)
endif
LDFLAGS_vmlinux += -z noexecstack
ifeq ($(CONFIG_LD_IS_BFD),y)
LDFLAGS_vmlinux += $(call ld-option,--no-warn-rwx-segments)
endif
ifeq ($(CONFIG_EFI_STUB),y)
# ensure that the static EFI stub library will be pulled in, even if it is
# never referenced explicitly from the startup code
LDFLAGS_vmlinux += -u efi_pe_entry
endif
LDFLAGS_vmlinux += -T

hostprogs	:= mkpiggy
HOST_EXTRACFLAGS += -I$(srctree)/tools/include

sed-voffset := -e 's/^\([0-9a-fA-F]*\) [ABbCDGRSTtVW] \(_text\|__start_rodata\|_sinittext\|__inittext_end\|__bss_start\|_end\)$$/\#define VO_\2 _AC(0x\1,UL)/p'

quiet_cmd_voffset = VOFFSET $@
      cmd_voffset = $(NM) $< | sed -n $(sed-voffset) > $@

targets += ../voffset.h

$(obj)/../voffset.h: vmlinux FORCE
	$(call if_changed,voffset)

$(obj)/misc.o: $(obj)/../voffset.h

vmlinux-objs-y := $(obj)/vmlinux.lds $(obj)/kernel_info.o $(obj)/head_$(BITS).o \
	$(obj)/misc.o $(obj)/string.o $(obj)/cmdline.o $(obj)/error.o \
	$(obj)/piggy.o $(obj)/cpuflags.o

vmlinux-objs-$(CONFIG_EARLY_PRINTK) += $(obj)/early_serial_console.o
vmlinux-objs-$(CONFIG_RANDOMIZE_BASE) += $(obj)/kaslr.o
ifdef CONFIG_X86_64
	vmlinux-objs-y += $(obj)/ident_map_64.o
	vmlinux-objs-y += $(obj)/idt_64.o $(obj)/idt_handlers_64.o
	vmlinux-objs-$(CONFIG_AMD_MEM_ENCRYPT) += $(obj)/mem_encrypt.o
	vmlinux-objs-y += $(obj)/pgtable_64.o
	vmlinux-objs-$(CONFIG_AMD_MEM_ENCRYPT) += $(obj)/sev.o $(obj)/sev-handle-vc.o
endif

vmlinux-objs-$(CONFIG_ACPI) += $(obj)/acpi.o
vmlinux-objs-$(CONFIG_INTEL_TDX_GUEST) += $(obj)/tdx.o $(obj)/tdcall.o $(obj)/tdx-shared.o
vmlinux-objs-$(CONFIG_UNACCEPTED_MEMORY) += $(obj)/mem.o

vmlinux-objs-$(CONFIG_EFI) += $(obj)/efi.o
vmlinux-libs-$(CONFIG_EFI_STUB) += $(objtree)/drivers/firmware/efi/libstub/lib.a
vmlinux-libs-$(CONFIG_X86_64)	+= $(objtree)/arch/x86/boot/startup/lib.a
vmlinux-objs-$(CONFIG_EFI_SBAT) += $(obj)/sbat.o

# ---- Pre-boot Rust probe. See logs/preboot-experiment.md. -------------------
#
# GUARDED BY CONFIG_RUST, and it was not until 2026-09-04. logs/floor.md
# RAISE 2 audited nine lib/ Makefiles for the CONFIG_RUST=n failure and this
# one was not among them -- it was written the same day, for the pre-boot
# experiment, and it is worse than any of the nine. arch/x86/boot/compressed/
# is built on EVERY x86 configuration; there is no feature symbol to turn it
# off. Measured, not reasoned:
#
#   $ make O=../../build-norust RUSTC=/nonexistent/rustc \
#         arch/x86/boot/compressed/preboot_probe.o
#   /bin/sh: line 1: /nonexistent/rustc: No such file or directory
#   make[4]: *** [.../preboot_probe.o] Error 127
#
# Note the mechanism is NOT the missing scripts/target.json that the lib/
# modules hit -- this rule brings its own preboot_target.json. It is simpler
# than that: the rules invoke $(RUSTC) unconditionally, so an x86_64 machine
# with CONFIG_RUST=n and no rustc installed cannot build its own boot stub.
#
# This stub runs BEFORE the kernel exists: no allocator, no rust/ runtime, no
# panic infrastructure, and a different code model from the kernel proper
# (-mcmodel=small here vs -mcmodel=kernel there), so rust/core.o cannot be
# reused and `core` is built again for this target.
#
# It needs nothing from the stub at link time: string.c already provides
# memcpy/memset/memmove non-static, which are the only symbols Rust codegen
# emits calls to, and the object came out with zero undefined symbols.
ifdef CONFIG_RUST
preboot_libsrc := $(shell $(RUSTC) --print sysroot)/lib/rustlib/src/rust/library
preboot_rustflags := -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
	-C debug-assertions=off -C overflow-checks=off \
	-C relocation-model=pie -Zfunction-sections=y \
	--target=$(src)/preboot_target.json

$(obj)/libcore.rlib: $(preboot_libsrc)/core/src/lib.rs FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2024 --cfg no_fp_fmt_parse \
		--crate-type=rlib --crate-name=core -o $@ $<

$(obj)/libcompiler_builtins.rlib: $(srctree)/rust/compiler_builtins.rs $(obj)/libcore.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=compiler_builtins \
		--extern core=$(obj)/libcore.rlib -o $@ $<

$(obj)/preboot_probe.o: $(src)/preboot_probe.rs $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=preboot_probe --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

vmlinux-objs-y += $(obj)/preboot_probe.o

# ---- Pre-boot XZ decoder in Rust. STATE.md W3, Adam 2026-10-02. ------------
# lib/decompress_unxz.c is #included by misc.c with STATIC defined and used to
# paste in the C engine (xz_dec_{stream,lzma2,bcj}.c). With CONFIG_RUST, the
# engine is the same Rust the running kernel uses: built here for the stub's
# target (PIE, small code model, no SSE) and linked in; XZ_BOOT_RUST tells the
# C files to take their thunk arm instead of the original-C STATIC arm. Only
# the x86 BCJ filter is enabled, exactly as decompress_unxz.c does for boot, so
# the cfg set below must stay equal to the XZ_DEC_* macros that file defines.
# Only where it has been booted: --gc-sections below could drop an EFI/SBAT entry
# point the stub's zoffset.h needs, and no EFI boot is tested here (logs/test-gaps.md),
# so an EFI_MIXED, EFI_HANDOVER_PROTOCOL or EFI_SBAT config keeps the original C engine.
# EFI_STUB itself is booted under OVMF (rig/boot.sh BOOT_EFI=1, 2026-10-03). Still off for the variants
# whose entry points the stub's zoffset.h also needs and that nothing here boots: the mixed-mode (32-bit
# firmware) entry, the handover protocol, and SBAT.
boot_rust_ok := $(if $(CONFIG_EFI_MIXED)$(CONFIG_EFI_HANDOVER_PROTOCOL)$(CONFIG_EFI_SBAT),,y)
boot_rust_on :=
boot_rust_objs :=

# --- XZ -----------------------------------------------------------------------
ifeq ($(CONFIG_KERNEL_XZ)$(boot_rust_ok),yy)
boot_rust_on := y
xz_boot_cfgs := --cfg=CONFIG_XZ_DEC_BCJ --cfg=CONFIG_XZ_DEC_X86
xz_boot_objs := $(obj)/xz_dec_stream_rs.o $(obj)/xz_dec_lzma2_rs.o $(obj)/xz_dec_bcj_rs.o

$(xz_boot_objs): $(obj)/xz_dec_%_rs.o: $(srctree)/lib/xz/xz_dec_%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) $(xz_boot_cfgs) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=xz_dec_$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

# The unxz() driver too (lib/decompress_unxz_rs.rs; the C one in decompress_unxz.c is
# compiled out by XZ_DRIVER_BOOT_RUST). --cfg=boot_stub drops its .init.text link_section.
$(obj)/decompress_unxz_rs.o: $(srctree)/lib/decompress_unxz_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --cfg=boot_stub -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=decompress_unxz_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

# The CRC32 (table + xz_crc32() + the crc32_le() the engine calls) is Rust too:
# lib/xz/xz_crc32_rs.rs, core-only, table built at compile time. decompress_unxz.c
# does not #include xz/xz_crc32.c with XZ_BOOT_RUST.
$(obj)/xz_crc32_rs.o: $(srctree)/lib/xz/xz_crc32_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=xz_crc32_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

xz_boot_objs += $(obj)/decompress_unxz_rs.o $(obj)/xz_crc32_rs.o
boot_rust_objs += $(xz_boot_objs)
CFLAGS_misc.o += -DXZ_BOOT_RUST -DXZ_DRIVER_BOOT_RUST
endif

# --- gzip (zlib inflate) ---------------------------------------------------------
# lib/decompress_inflate.c pastes in zlib_inflate/{inftrees,inffast,inflate}.c.
# With INFLATE_BOOT_RUST it pastes inflate_thunk.c instead and the engine is the
# Rust below. No cfgs: CONFIG_ZLIB_DFLTCC is s390 only and stays off.
ifeq ($(CONFIG_KERNEL_GZIP)$(boot_rust_ok),yy)
boot_rust_on := y
gz_boot_objs := $(obj)/zlib_inflate_inflate_rs.o $(obj)/zlib_inflate_inffast_rs.o $(obj)/zlib_inflate_inftrees_rs.o

$(gz_boot_objs): $(obj)/zlib_inflate_%_rs.o: $(srctree)/lib/zlib_inflate/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=zlib_inflate_$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(gz_boot_objs)
CFLAGS_misc.o += -DINFLATE_BOOT_RUST

# The driver (gzip header, fill/flush loop, error texts) is lib/decompress_inflate_rs.rs,
# the same file the running kernel uses. --cfg=boot_gunzip adds its gunzip_preboot()
# entry (the C __gunzip() with out_len), which __decompress() calls. Its
# #[link_section = ".init.text"] is renamed to .text, as for BZIP2.
gz_drv_objs := $(obj)/decompress_inflate_rs.o

$(gz_drv_objs): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --cfg=boot_gunzip -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

boot_rust_objs += $(gz_drv_objs)
CFLAGS_misc.o += -DINFLATE_DRIVER_BOOT_RUST
endif

# --- ZSTD ------------------------------------------------------------------------
# lib/decompress_unzstd.c pastes in zstd/decompress_sources.h (the whole zstd C
# decoder). With ZSTD_BOOT_RUST it pastes the C entry thunks and the zstd_* API
# wrapper instead, and the engine is the Rust below: the same lib/zstd/**/*_rs.rs
# the running kernel uses, except zstd_decompress_module_rs.rs (it needs the
# `kernel` crate; the C wrapper it replaces is pasted instead). No cfgs: the
# running kernel passes none either (DYNAMIC_BMI2 and zstd_strip_error_strings
# are never set there), and the Rust has to agree with itself.
# The stream driver is Rust too: decompress_unzstd_rs.rs, built with --cfg=boot_driver
# (adds unzstd_boot(), the out_len-taking entry __decompress() calls). Its
# #[link_section = ".init.text"] is renamed to .text for the stub, as for BZIP2.
ifeq ($(CONFIG_KERNEL_ZSTD)$(boot_rust_ok),yy)
boot_rust_on := y
zstd_c_objs := $(patsubst %,$(obj)/zstd_c_%_rs.o,entropy_common error_private zstd_common)
zstd_d_objs := $(patsubst %,$(obj)/zstd_d_%_rs.o,huf_decompress zstd_ddict zstd_decompress zstd_decompress_block)

$(zstd_c_objs): $(obj)/zstd_c_%_rs.o: $(srctree)/lib/zstd/common/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=zstd_c_$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

$(zstd_d_objs): $(obj)/zstd_d_%_rs.o: $(srctree)/lib/zstd/decompress/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=zstd_d_$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

zstd_drv_obj := $(obj)/decompress_unzstd_rs.o

$(zstd_drv_obj): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --cfg=boot_driver -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

# xxhash too: lib/xxhash_rs.rs (the Rust the running kernel uses). Its kabi_*!
# annotations come from the `kernel` crate; boot_kernel_stub.rs (no-op macros, as
# for LZ4) is built here as its own libkernel_xxh.rlib so this block does not
# depend on the LZ4 block's libkernel.rlib rule. decompress_unzstd.c does not
# #include xxhash.c with ZSTD_BOOT_RUST.
zstd_xxh_obj := $(obj)/xxhash_rs.o

$(obj)/libkernel_xxh.rlib: $(src)/boot_kernel_stub.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=kernel --extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

$(zstd_xxh_obj): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib $(obj)/libkernel_xxh.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib \
		-L dependency=$(obj) --extern kernel=$(obj)/libkernel_xxh.rlib -o $@ $<

boot_rust_objs += $(zstd_c_objs) $(zstd_d_objs) $(zstd_drv_obj) $(zstd_xxh_obj)
CFLAGS_misc.o += -DZSTD_BOOT_RUST
endif

# --- LZO ----------------------------------------------------------------------
# lib/decompress_unlzo.c pastes in lzo/lzo1x_decompress_safe.c. With
# LZO_BOOT_RUST it pastes nothing and the engine is the Rust below, which
# defines lzo1x_decompress_safe() itself. No cfgs, no extra C shims needed.
ifeq ($(CONFIG_KERNEL_LZO)$(boot_rust_ok),yy)
boot_rust_on := y
lzo_boot_objs := $(obj)/lzo1x_decompress_safe_rs.o

$(lzo_boot_objs): $(obj)/%_rs.o: $(srctree)/lib/lzo/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=lzo1x_decompress_safe_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

# The driver (container header parse, fill/flush loop, unlzo()) is
# lib/decompress_unlzo_rs.rs, the same file the running kernel uses; the C keeps only
# the boot-malloc shims and __decompress() under LZO_DRIVER_BOOT_RUST. Its
# #[link_section = ".init.text"] is renamed to .text (the stub's linker script has no
# .init.text), as for bzip2.
lzo_drv_objs := $(obj)/decompress_unlzo_rs.o

$(lzo_drv_objs): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

boot_rust_objs += $(lzo_boot_objs) $(lzo_drv_objs)
CFLAGS_misc.o += -DLZO_BOOT_RUST -DLZO_DRIVER_BOOT_RUST
endif

# --- BZIP2 --------------------------------------------------------------------
# lib/decompress_bunzip2.c is the whole C decoder under #ifdef STATIC. With
# BZIP2_BOOT_RUST it keeps only the boot-malloc shims and __decompress(); the
# engine is lib/decompress_bunzip2_rs.rs, the same file the running kernel uses.
# No cfgs. Its #[link_section = ".init.text"] (the kernel's __init) is renamed to
# .text for the stub: the stub's linker script has no .init.text, and left alone
# ld.lld warns "is being placed in '.init.text'" (orphan handling).
ifeq ($(CONFIG_KERNEL_BZIP2)$(boot_rust_ok),yy)
boot_rust_on := y
bz_boot_objs := $(obj)/decompress_bunzip2_rs.o

$(bz_boot_objs): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

boot_rust_objs += $(bz_boot_objs)
CFLAGS_misc.o += -DBZIP2_BOOT_RUST
endif

# --- LZ4 -----------------------------------------------------------------------
# lib/decompress_unlz4.c pastes in lib/lz4/lz4_decompress.c. With LZ4_BOOT_RUST it
# does not, and the one engine call it makes (LZ4_decompress_fast) resolves to
# lib/lz4/lz4_decompress_rs.rs, built here. That file's kabi_rule!/kabi_export!
# annotations come from the `kernel` crate, which the stub does not have, so
# boot_kernel_stub.rs is a crate named `kernel` holding no-op copies of those two
# macros (and, being a dependency, needs -L so rustc finds compiler_builtins
# behind it). The engine needs no cfgs and no C shims.
# RUSTY-LINUX: the driver unlz4() is also Rust here (LZ4_DRIVER_BOOT_RUST):
# lib/decompress_unlz4_rs.rs built with --cfg boot_preboot, which makes it the
# C PREBOOT arm (LZ4_decompress_fast, out_len read from input + in_len). It does
# not use the `kernel` crate, so needs no libkernel.rlib. Its .init.text is
# renamed to .text, as for BZIP2; decompress_unlz4_alloc/vfree are shims in
# decompress_unlz4.c.
ifeq ($(CONFIG_KERNEL_LZ4)$(boot_rust_ok),yy)
boot_rust_on := y
lz4_boot_objs := $(obj)/lz4_decompress_rs.o

$(obj)/libkernel.rlib: $(src)/boot_kernel_stub.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=kernel --extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

$(lz4_boot_objs): $(obj)/%_rs.o: $(srctree)/lib/lz4/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib $(obj)/libkernel.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib \
		-L dependency=$(obj) --extern kernel=$(obj)/libkernel.rlib -o $@ $<

lz4_drv_objs := $(obj)/decompress_unlz4_rs.o

$(obj)/decompress_unlz4_rs.o: $(srctree)/lib/decompress_unlz4_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=decompress_unlz4_rs --emit=obj --cfg=boot_preboot \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

boot_rust_objs += $(lz4_boot_objs) $(lz4_drv_objs)
CFLAGS_misc.o += -DLZ4_BOOT_RUST -DLZ4_DRIVER_BOOT_RUST
endif

# --- LZMA ---------------------------------------------------------------------
# lib/decompress_unlzma.c is the whole C decoder under #ifdef STATIC. With
# LZMA_BOOT_RUST it keeps only the boot-malloc shims (decompress_unlzma_alloc/
# _large_alloc, kfree, vfree) and __decompress(); the engine is
# lib/decompress_unlzma_rs.rs, the same file the running kernel uses. No cfgs.
# Its #[link_section = ".init.text"] is renamed to .text, as for BZIP2.
ifeq ($(CONFIG_KERNEL_LZMA)$(boot_rust_ok),yy)
boot_rust_on := y
lzma_boot_objs := $(obj)/decompress_unlzma_rs.o

$(lzma_boot_objs): $(obj)/%_rs.o: $(srctree)/lib/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<
	$(Q)$(OBJCOPY) --rename-section .init.text=.text $@

boot_rust_objs += $(lzma_boot_objs)
CFLAGS_misc.o += -DLZMA_BOOT_RUST
endif

# --- STUBC: the stub's own small C files, in Rust ---------------------------------
# Phase B (logs/preboot-experiment.md). error.c (warn/error[/panic]), cmdline.c,
# cpuflags.c and, with CONFIG_EARLY_PRINTK, early_serial_console.c are replaced by
# error_rs.rs / cmdline_rs.rs / cpuflags_rs.rs / early_serial_console_rs.rs, with the
# same exported symbols. The shared ../cmdline.c ../cpuflags.c ../early_serial_console.c
# are NOT touched: the 16-bit real-mode setup still compiles them. Same gate as the
# engines (boot_rust_ok); with it off, or CONFIG_RUST=n, the C objects build as before.
# CONFIG_EFI_STUB: the variadic panic() (error.c) is Rust too, see error_rs.rs.
ifeq ($(boot_rust_ok),y)
boot_rust_on := y
stubc_objs := $(obj)/error_rs.o $(obj)/cmdline_rs.o $(obj)/cpuflags_rs.o
stubc_c_objs := $(obj)/error.o $(obj)/cmdline.o $(obj)/cpuflags.o
ifdef CONFIG_EARLY_PRINTK
stubc_objs += $(obj)/early_serial_console_rs.o
stubc_c_objs += $(obj)/early_serial_console.o
endif
stubc_cfgs-$(CONFIG_EFI_STUB) += --cfg=efi_stub

$(stubc_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stubc_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(stubc_objs)
vmlinux-objs-y := $(filter-out $(stubc_c_objs),$(vmlinux-objs-y))
endif

# --- STUBD: string.c (and, with UNACCEPTED_MEMORY, mem.c) in Rust ---------------------------------------------------------
# Phase B step 2a (logs/stubd-string.md). compressed/string.c (= ../string.c plus the stub's own
# memcpy/memmove/memset) is replaced by string_rs.rs with the same exported symbols. The shared
# ../string.c is NOT touched: the 16-bit real-mode setup still compiles it. Same gate as the
# engines (boot_rust_ok); with it off, or CONFIG_RUST=n, string.o builds from C as before.
# string_rs.rs is #![no_builtins] (LLVM must not turn its loops into calls to memcpy/memset/
# strlen, i.e. to itself); --cfg=kasan adds the __mem* alias names the C defines under KASAN.
ifeq ($(boot_rust_ok),y)
boot_rust_on := y
stubd_objs := $(obj)/string_rs.o
stubd_c_objs := $(obj)/string.o
stubd_cfgs-$(CONFIG_KASAN) += --cfg=kasan
# mem.c (unaccepted-memory helpers: arch_accept_memory, init_unaccepted_memory) exists only with
# CONFIG_UNACCEPTED_MEMORY (selected by INTEL_TDX_GUEST / AMD_MEM_ENCRYPT, needs EFI_STUB).
ifdef CONFIG_UNACCEPTED_MEMORY
stubd_objs += $(obj)/mem_rs.o
stubd_c_objs += $(obj)/mem.o
stubd_cfgs-$(CONFIG_INTEL_TDX_GUEST) += --cfg=tdx_guest
stubd_cfgs-$(CONFIG_AMD_MEM_ENCRYPT) += --cfg=amd_mem_encrypt
endif

# -Zdirect-access-external-data: mem_rs.rs reads/writes the C globals boot_params_ptr and unaccepted_table.
$(stubd_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stubd_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(stubd_objs)
vmlinux-objs-y := $(filter-out $(stubd_c_objs),$(vmlinux-objs-y))
endif

# --- STUBE: idt_64.c, pgtable_64.c, ident_map_64.c in Rust (Phase B step 2b) -------
# Same gate and object swap as STUBC. The C files are 64-bit-stub only (vmlinux-objs-y lists
# them under CONFIG_X86_64). --cfg=amd_mem_encrypt mirrors CONFIG_AMD_MEM_ENCRYPT (SEV #VC
# handlers, the SME mask in the page-table masks), --cfg=x86_verbose_bootup CONFIG_X86_VERBOSE_BOOTUP; the 5-level switch needs no cfg: the C has no #ifdef for it, it is a run-time CPUID test.
ifeq ($(boot_rust_ok),y)
boot_rust_on := y
stube_objs := $(obj)/idt_64_rs.o $(obj)/pgtable_64_rs.o $(obj)/ident_map_64_rs.o
stube_c_objs := $(obj)/idt_64.o $(obj)/pgtable_64.o $(obj)/ident_map_64.o
stube_cfgs-$(CONFIG_AMD_MEM_ENCRYPT) += --cfg=amd_mem_encrypt
stube_cfgs-$(CONFIG_X86_VERBOSE_BOOTUP) += --cfg=x86_verbose_bootup

$(stube_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stube_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(stube_objs)
vmlinux-objs-y := $(filter-out $(stube_c_objs),$(vmlinux-objs-y))
endif

# --- STUBF: efi.c (CONFIG_EFI), acpi.c (CONFIG_ACPI), kaslr.c (CONFIG_RANDOMIZE_BASE) in Rust ----------------------------
# Phase B step 3 (logs/stubf-boot-protocol.md). Same gate and pattern as STUBC/STUBD: the Rust object replaces the C object
# of the same name in vmlinux-objs-y, same exported symbols. --cfg=verbose_bootup mirrors CONFIG_X86_VERBOSE_BOOTUP
# (debug_putstr() is __putstr() only then). -Zdirect-access-external-data: the files read C-owned globals.
ifeq ($(boot_rust_ok),y)
boot_rust_on := y
stubf_objs :=
stubf_c_objs :=
stubf_extra_c_objs :=
stubf_cfgs-$(CONFIG_X86_VERBOSE_BOOTUP) += --cfg=verbose_bootup
ifdef CONFIG_EFI
stubf_objs += $(obj)/efi_rs.o
stubf_c_objs += $(obj)/efi.o
endif
# acpi.c: immovable_mem[]/count_immovable_mem_regions() exist only with RANDOMIZE_BASE && MEMORY_HOTREMOVE (misc.h also CONFIG_ACPI);
# the acpi_rsdp= option needs KEXEC_CORE; the EFI arms CONFIG_EFI. MAX_NUMNODES = 1 << NODES_SHIFT reaches rustc as an env var.
stubf_cfgs-$(CONFIG_EFI) += --cfg=efi
ifdef CONFIG_ACPI
stubf_objs += $(obj)/acpi_rs.o
stubf_c_objs += $(obj)/acpi.o
ifdef CONFIG_RANDOMIZE_BASE
stubf_cfgs-$(CONFIG_MEMORY_HOTREMOVE) += --cfg=hotremove_srat
endif
stubf_cfgs-$(CONFIG_KEXEC_CORE) += --cfg=kexec_core
endif
# kaslr.c (+ the arch/x86/lib/kaslr.c, lib/ctype.c and lib/cmdline.c it #includes) -> kaslr_rs.rs. kaslr_cfg.c is a tiny C object that
# exports the preprocessor facts (build string, CONFIG_PHYSICAL_ALIGN, MAXMEM ...) the Rust reads.
# hotremove_acpi = CONFIG_MEMORY_HOTREMOVE && CONFIG_ACPI (the immovable-region loop); with RANDOMIZE_BASE it equals hotremove_srat above.
ifdef CONFIG_RANDOMIZE_BASE
stubf_objs += $(obj)/kaslr_rs.o
stubf_c_objs += $(obj)/kaslr.o
stubf_extra_c_objs += $(obj)/kaslr_cfg.o
stubf_cfgs-$(CONFIG_UNACCEPTED_MEMORY) += --cfg=unaccepted_memory
stubf_cfgs-$(CONFIG_KEXEC_HANDOVER) += --cfg=kexec_handover
ifdef CONFIG_MEMORY_HOTREMOVE
stubf_cfgs-$(CONFIG_ACPI) += --cfg=hotremove_acpi
endif
endif

$(stubf_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)STUBF_NODES_SHIFT=$(CONFIG_NODES_SHIFT) $(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stubf_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(stubf_objs)
vmlinux-objs-y := $(filter-out $(stubf_c_objs),$(vmlinux-objs-y)) $(stubf_extra_c_objs)
endif

# --- STUBG: misc.c's parse_elf() and handle_relocations() in Rust (Phase B step 4) ---------------------------------------
# misc.c itself STAYS C (it is the translation unit the lib/decompress_*.c files are #included into, and holds the boot
# malloc heap); with -DMISC_BOOT_RUST it takes the Rust functions below instead of its own static ones. misc_cfg.c exports
# the preprocessor facts (LOAD_PHYSICAL_ADDR, __START_KERNEL_map, VO___bss_start - VO__text). Same gate as STUBC..STUBF.
ifeq ($(boot_rust_ok),y)
boot_rust_on := y
stubg_objs := $(obj)/misc_rs.o
stubg_cfgs-$(CONFIG_X86_NEED_RELOCS) += --cfg=need_relocs
stubg_cfgs-$(CONFIG_RELOCATABLE) += --cfg=relocatable
stubg_cfgs-$(CONFIG_X86_VERBOSE_BOOTUP) += --cfg=verbose_bootup
# the C's #ifdef/IS_ENABLED switches (misc.h, tdx.h, ...): console_init()/early_serial_base, get_rsdp_addr(), choose_random_location(),
# early_tdx_detect(), sev_status, init_unaccepted_memory()/accept_memory()
stubg_cfgs-$(CONFIG_EARLY_PRINTK) += --cfg=early_printk
stubg_cfgs-$(CONFIG_ACPI) += --cfg=acpi
stubg_cfgs-$(CONFIG_RANDOMIZE_BASE) += --cfg=randomize_base
stubg_cfgs-$(CONFIG_INTEL_TDX_GUEST) += --cfg=tdx_guest
stubg_cfgs-$(CONFIG_AMD_MEM_ENCRYPT) += --cfg=amd_mem_encrypt
stubg_cfgs-$(CONFIG_UNACCEPTED_MEMORY) += --cfg=unaccepted_memory

$(stubg_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stubg_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

boot_rust_objs += $(stubg_objs)
vmlinux-objs-y += $(obj)/misc_cfg.o
CFLAGS_misc.o += -DMISC_BOOT_RUST
endif

# --- STUBH: the stub's assembly (.S) as Rust global_asm! (Phase C) ------------------------------------------------------
# kernel_info.S, head_64.S, idt_handlers_64.S (+ mem_encrypt.S with CONFIG_AMD_MEM_ENCRYPT, tdcall.S with CONFIG_INTEL_TDX_GUEST,
# and arch/x86/boot/startup/la57toggle.S) become <name>_rs.rs: the .S text verbatim (AT&T), the cpp macros written out, the
# header constants as `const` operands (rig/stubh/consts_check.py checks them against the headers), the #ifdef arms as
# `--cfg` flags (tested in the assembly with `.if`). The Rust object REPLACES the .S object IN PLACE in vmlinux-objs-y, so
# the link order is unchanged and the linked stub can be compared with the all-.S one: `make boot_asm_rust=` turns just
# this block off (rig/stubh/imgcmp.sh). Per-object proof against the .S object: rig/stubh/check.sh (sections, objdump -D -r,
# symbols, relocations, bytes). Same gate as STUBC..STUBG (boot_rust_ok).
# NOT converted, original .S kept: efi-mixed.S (CONFIG_EFI_MIXED) and sbat.S (CONFIG_EFI_SBAT) -- efi_mixed_rs.rs / sbat_rs.rs
# exist and are object-compared, but boot_rust_ok already keeps EFI_MIXED, EFI_HANDOVER_PROTOCOL and EFI_SBAT kernels on the C
# stub (no 32-bit OVMF, no handover loader here, and --gc-sections would drop an unreferenced .sbat), so they are not wired.
# la57toggle: the .S object lives in startup/lib.a; the Rust one is linked directly, just before that archive, so the member is never pulled.
# Config-derived numbers the headers compute (Rust cannot see the preprocessor) reach rustc as environment variables:
# CONFIG_FUNCTION_ALIGNMENT (SYM_FUNC_START alignment), CONFIG_PHYSICAL_START/ALIGN (LOAD_PHYSICAL_ADDR), and the two feature
# masks REQUIRED_MASK0/1 of the generated cpufeaturemasks.h (head_64's verify_cpu). Empty values fail the Rust build (const assert).
boot_asm_rust := $(boot_rust_ok)
ifeq ($(boot_asm_rust),y)
boot_rust_on := y
stubh_names := kernel_info head_64 idt_handlers_64
stubh_names-$(CONFIG_AMD_MEM_ENCRYPT) += mem_encrypt
stubh_names-$(CONFIG_INTEL_TDX_GUEST) += tdcall
stubh_names += $(stubh_names-y)
stubh_s_objs := $(addprefix $(obj)/,$(addsuffix .o,$(stubh_names)))
stubh_objs := $(addprefix $(obj)/,$(addsuffix _rs.o,$(stubh_names) la57toggle))
stubh_cfgs-$(CONFIG_AMD_MEM_ENCRYPT) += --cfg=amd_mem_encrypt
stubh_cfgs-$(CONFIG_RELOCATABLE) += --cfg=relocatable
stubh_cfgs-$(CONFIG_FRAME_POINTER) += --cfg=frame_pointer
stubh_cfgs-$(CONFIG_MITIGATION_SLS) += --cfg=mitigation_sls
stubh_cpufm := $(objtree)/arch/x86/include/generated/asm/cpufeaturemasks.h
stubh_mask0 := $(shell sed -n 's/^[\#]define REQUIRED_MASK0[[:space:]]*\(0x[0-9a-fA-F]*\)U.*/\1/p' $(stubh_cpufm) 2>/dev/null)
stubh_mask1 := $(shell sed -n 's/^[\#]define REQUIRED_MASK1[[:space:]]*\(0x[0-9a-fA-F]*\)U.*/\1/p' $(stubh_cpufm) 2>/dev/null)

$(stubh_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/libcore.rlib $(obj)/libcompiler_builtins.rlib FORCE
	$(Q)STUBH_FUNCTION_ALIGNMENT=$(CONFIG_FUNCTION_ALIGNMENT) STUBH_PHYSICAL_START=$(CONFIG_PHYSICAL_START) \
		STUBH_PHYSICAL_ALIGN=$(CONFIG_PHYSICAL_ALIGN) STUBH_REQUIRED_MASK0=$(stubh_mask0) STUBH_REQUIRED_MASK1=$(stubh_mask1) \
		$(RUSTC) $(preboot_rustflags) -Zdirect-access-external-data=yes $(stubh_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/libcore.rlib \
		--extern compiler_builtins=$(obj)/libcompiler_builtins.rlib -o $@ $<

vmlinux-objs-y := $(foreach o,$(vmlinux-objs-y),$(if $(filter $(o),$(stubh_s_objs)),$(o:.o=_rs.o),$(o)))
# la57toggle_rs.o goes exactly where lld extracts the .S member from startup/lib.a (right before it, after the EFI stub's lib.a),
# so the .rodata layout of the linked stub is the same as with the .S object (rig/stubh/imgcmp.sh)
vmlinux-libs-y := $(patsubst $(objtree)/arch/x86/boot/startup/lib.a,$(obj)/la57toggle_rs.o $(objtree)/arch/x86/boot/startup/lib.a,$(vmlinux-libs-y))
endif

# --- shared by every engine above -------------------------------------------------
# Only where it has been booted: --gc-sections could drop an EFI/SBAT entry point
# the stub's zoffset.h needs, and no EFI boot is tested here (logs/test-gaps.md),
# so an EFI_MIXED, EFI_HANDOVER_PROTOCOL or EFI_SBAT config keeps the original C engines.
ifneq ($(boot_rust_on),)
# The probe never called into `core`, so the rlibs above were enough for it.
# The engines do (slice bounds checks, panics), so `core` and `compiler_builtins`
# must be linked as OBJECTS -- same flags, emitted as .o.
$(obj)/core_boot.o: $(preboot_libsrc)/core/src/lib.rs FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2024 --cfg no_fp_fmt_parse \
		--crate-type=rlib --crate-name=core --emit=obj -o $@ $<

$(obj)/compiler_builtins_boot.o: $(srctree)/rust/compiler_builtins.rs $(obj)/libcore.rlib FORCE
	$(Q)$(RUSTC) $(preboot_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=compiler_builtins --emit=obj \
		--extern core=$(obj)/libcore.rlib -o $@ $<

vmlinux-objs-y += $(boot_rust_objs) $(obj)/core_boot.o $(obj)/compiler_builtins_boot.o
# core is linked as one object; --gc-sections drops the parts nothing reaches (and
# with them their data relocations, which this stub's linker script forbids).
KBUILD_LDFLAGS += --gc-sections -u kernel_info -u input_data
endif

# The C half has to go with it: misc.c calls rust_preboot_probe() and halts
# unless it returns the expected value, so with the object gone the link would
# fail. CONFIG_RUST reaches misc.c through IS_ENABLED().
endif
# -----------------------------------------------------------------------------

ifdef CONFIG_EFI_SBAT
$(obj)/sbat.o: $(CONFIG_EFI_SBAT_FILE)
AFLAGS_sbat.o += -I $(srctree)
endif

$(obj)/vmlinux: $(vmlinux-objs-y) $(vmlinux-libs-y) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_vmlinux.bin :=  -R .comment -S
$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)

targets += $(patsubst $(obj)/%,%,$(vmlinux-objs-y)) vmlinux.bin.all vmlinux.relocs

CMD_RELOCS = arch/x86/tools/relocs
quiet_cmd_relocs = RELOCS  $@
      cmd_relocs = $(CMD_RELOCS) $< > $@;$(CMD_RELOCS) --abs-relocs $<

$(obj)/vmlinux.relocs: vmlinux.unstripped FORCE
	$(call if_changed,relocs)

vmlinux.bin.all-y := $(obj)/vmlinux.bin
vmlinux.bin.all-$(CONFIG_X86_NEED_RELOCS) += $(obj)/vmlinux.relocs

$(obj)/vmlinux.bin.gz: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,gzip)
$(obj)/vmlinux.bin.bz2: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,bzip2_with_size)
$(obj)/vmlinux.bin.lzma: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,lzma_with_size)
$(obj)/vmlinux.bin.xz: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,xzkern_with_size)
$(obj)/vmlinux.bin.lzo: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,lzo_with_size)
$(obj)/vmlinux.bin.lz4: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,lz4_with_size)
$(obj)/vmlinux.bin.zst: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,zstd22_with_size)

suffix-$(CONFIG_KERNEL_GZIP)	:= gz
suffix-$(CONFIG_KERNEL_BZIP2)	:= bz2
suffix-$(CONFIG_KERNEL_LZMA)	:= lzma
suffix-$(CONFIG_KERNEL_XZ)	:= xz
suffix-$(CONFIG_KERNEL_LZO) 	:= lzo
suffix-$(CONFIG_KERNEL_LZ4) 	:= lz4
suffix-$(CONFIG_KERNEL_ZSTD)	:= zst

quiet_cmd_mkpiggy = MKPIGGY $@
      cmd_mkpiggy = $(obj)/mkpiggy $< > $@

targets += piggy.S
$(obj)/piggy.S: $(obj)/vmlinux.bin.$(suffix-y) $(obj)/mkpiggy FORCE
	$(call if_changed,mkpiggy)
