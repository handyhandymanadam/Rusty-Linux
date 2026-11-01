#
# arch/x86/boot/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1994 by Linus Torvalds
# Changed by many, many contributors over the years.
#

# If you want to preset the SVGA mode, uncomment the next line and
# set SVGA_MODE to whatever number you want.
# Set it to -DSVGA_MODE=NORMAL_VGA if you just want the EGA/VGA mode.
# The number is the same as you would ordinarily press at bootup.

SVGA_MODE	:= -DSVGA_MODE=NORMAL_VGA

targets		:= vmlinux.bin setup.bin setup.elf bzImage
targets		+= fdimage fdimage144 fdimage288 image.iso hdimage
subdir-		:= compressed

setup-y		+= a20.o bioscall.o cmdline.o copy.o cpu.o cpuflags.o cpucheck.o
setup-y		+= early_serial_console.o edd.o header.o main.o memory.o
setup-y		+= pm.o pmjump.o printf.o regs.o string.o tty.o video.o
setup-y		+= video-mode.o version.o
setup-$(CONFIG_X86_APM_BOOT) += apm.o

# The link order of the video-*.o modules can matter.  In particular,
# video-vga.o *must* be listed first, followed by video-vesa.o.
# Hardware-specific drivers should follow in the order they should be
# probed, and video-bios.o should typically be last.
setup-y		+= video-vga.o
setup-y		+= video-vesa.o
setup-y		+= video-bios.o

# ---- RUSTY-LINUX REALMODE: 16-bit setup code in Rust (STATE.md Phase D pilot) ----------------------
# The real-mode setup (this directory's *.c, linked into setup.elf at 0) is compiled with clang -m16
# -mregparm=3. Rust can target that: realmode_target.json = llvm-target i386-unknown-none-code16
# (+16bit-mode), cpu i386, 32-bit pointers; `-Zregparm=3` is the C's -mregparm=3, so a Rust
# `extern "C"` function takes its first three integer args in %eax/%edx/%ecx like the C ones, and
# LLVM's own memset/memcpy libcalls use the same convention as string.c. `core` and
# compiler_builtins are rebuilt for the target (same scheme as compressed/Makefile). Only with
# CONFIG_RUST; without it, or for any file not listed in rm_objs, the C object builds as before.
# Only a legacy-BIOS boot runs this code (EFI/OVMF skips the real-mode setup): logs/test-gaps.md.
ifdef CONFIG_RUST
rm_libsrc := $(shell $(RUSTC) --print sysroot)/lib/rustlib/src/rust/library
rm_rustflags := -Zunstable-options --sysroot=/dev/null -C opt-level=s -C panic=immediate-abort \
	-C debug-assertions=off -C overflow-checks=off -Zfunction-sections=y -Zregparm=3 \
	--target=$(src)/realmode_target.json

rm_objs := regs tty memory printf a20 cpu cpucheck cpuflags cmdline string early_serial_console pm main
# Phase D batch 3. C file names with a '-' (video-mode.c ...) have Rust files with a '_' (video_mode_rs.rs; a crate name cannot hold '-').
# edd.c is empty without CONFIG_EDD (its whole body is #if'd), and apm.c is built only with CONFIG_X86_APM_BOOT (32-bit APM): the Rust twin is swapped in under the same condition.
rm_vobjs := version video video-mode video-vga video-vesa video-bios \
	$(if $(CONFIG_EDD)$(CONFIG_EDD_MODULE),edd) $(if $(CONFIG_X86_APM_BOOT),apm)
rm_objs += $(subst -,_,$(rm_vobjs))
# the C object names (video_mode -> video-mode.o); an override `make rm_objs=` leaves both empty (all-C build)
rm_c_objs := $(addsuffix .o,$(patsubst video_%,video-%,$(rm_objs)))

$(obj)/librm_core.rlib: $(rm_libsrc)/core/src/lib.rs FORCE
	$(Q)$(RUSTC) $(rm_rustflags) --edition=2024 --cfg no_fp_fmt_parse \
		--crate-type=rlib --crate-name=core -o $@ $<

$(obj)/librm_compiler_builtins.rlib: $(srctree)/rust/compiler_builtins.rs $(obj)/librm_core.rlib FORCE
	$(Q)$(RUSTC) $(rm_rustflags) --edition=2021 --crate-type=rlib \
		--crate-name=compiler_builtins \
		--extern core=$(obj)/librm_core.rlib -o $@ $<

# Build-time data the cpu/cpucheck ports share with their C originals (RM_GEN_DIR, read by env!() in the .rs):
# cpustr.bin = the C compiler's image of x86_cap_strs[] (cpustr.h from mkcpustr; .rodata of cpustr_blob.o) and
# cpucheck_gen.rs = the required masks / feature bits / MSR numbers / config switches cpucheck.c uses, from the
# same headers by the C preprocessor (only its `pub const` lines kept, C integer suffixes stripped).
targets += cpustr_blob.o cpustr.bin cpucheck_gen.rs pm_gen.rs main_gen.rs version_gen.rs edd_gen.rs video_gen.rs
$(obj)/cpustr_blob.o: $(obj)/cpustr.h
OBJCOPYFLAGS_cpustr.bin := -O binary -j .rodata
$(obj)/cpustr.bin: $(obj)/cpustr_blob.o FORCE
	$(call if_changed,objcopy)

quiet_cmd_cpucheckgen = GEN     $@
      cmd_cpucheckgen = $(CC) -Wp,-MD,$(depfile) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) -include $(srctree)/include/linux/kconfig.h -D__KERNEL__ -E -P -x c $< | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(ULL\|UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > $@
$(obj)/cpucheck_gen.rs: $(src)/cpucheck_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
# pm_gen.rs: the boot GDT descriptors (pm.c's GDT_ENTRY(...) values), same preprocessing.
$(obj)/pm_gen.rs: $(src)/pm_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
$(obj)/pm_rs.o: $(obj)/pm_gen.rs
# main_gen.rs: CAN_USE_HEAP / OLD_CL_* and the CONFIG_X86_64 / CONFIG_APM / CONFIG_EDD switches main.c tests, same preprocessing.
$(obj)/main_gen.rs: $(src)/main_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
$(obj)/main_rs.o: $(obj)/main_gen.rs
# version_gen.rs: version.c's UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") " UTS_VERSION from the generated headers; edd_gen.rs: linux/edd.h numbers and
# CONFIG_EDD_OFF; video_gen.rs: CONFIG_BOOT_VESA_SUPPORT / CONFIG_FIRMWARE_EDID and the vga= mode numbers (same preprocessing rule).
$(obj)/version_gen.rs: $(src)/version_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
$(obj)/edd_gen.rs: $(src)/edd_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
$(obj)/video_gen.rs: $(src)/video_gen.rs.in FORCE
	$(call if_changed_dep,cpucheckgen)
$(obj)/version_rs.o: $(obj)/version_gen.rs
$(obj)/edd_rs.o: $(obj)/edd_gen.rs
$(obj)/video_rs.o $(obj)/video_mode_rs.o $(obj)/video_vga_rs.o $(obj)/video_vesa_rs.o $(obj)/video_bios_rs.o: $(obj)/video_gen.rs

$(obj)/cpu_rs.o $(obj)/cpucheck_rs.o: $(obj)/cpustr.bin $(obj)/cpucheck_gen.rs
$(obj)/cpuflags_rs.o: $(obj)/cpucheck_gen.rs

# cpuflags_rs.rs exports has_eflag() only for CONFIG_X86_32 (cpuflags.h: inline `return true` otherwise).
rm_cfg_cpuflags := $(if $(CONFIG_X86_32),--cfg rm_x86_32)

$(addprefix $(obj)/,$(addsuffix _rs.o,$(rm_objs))): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/librm_core.rlib $(obj)/librm_compiler_builtins.rlib FORCE
	$(Q)RM_GEN_DIR=$(abspath $(obj)) $(RUSTC) $(rm_rustflags) -Zcrate-attr=no_std $(rm_cfg_$*) --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/librm_core.rlib \
		--extern compiler_builtins=$(obj)/librm_compiler_builtins.rlib -o $@ $<

# Swap in place, so the link order (which matters for video-*.o) is unchanged.
setup-y := $(foreach o,$(setup-y),$(if $(filter $(o),$(rm_c_objs)),$(subst -,_,$(basename $(o)))_rs.o,$(o)))
endif
# ---- end RUSTY-LINUX REALMODE -----------------------------------------------------------------------

# ---- RUSTY-LINUX REALMODE-ASM: the real-mode assembly (.S) as 16-bit Rust global_asm! (Phase C2) -----------------------
# copy.S, bioscall.S, pmjump.S (and header.S, see below) become <name>_rs.rs: the .S text verbatim (AT&T, `.code16`), the cpp
# macros written out, the header constants as `const` operands (rig/rmasm/check.sh runs consts_check.py: every const against the
# headers). The Rust object REPLACES the .S object IN PLACE in setup-y, so the link order is unchanged and setup.elf / bzImage can be
# compared with the all-.S build: `make boot_rmasm_rust=` turns just this block off (rig/rmasm/imgcmp.sh). Per-object proof
# against the .S object: rig/rmasm/check.sh (sections, objdump -D -r, symbols, relocations, bytes). Uses the rm_rustflags and the
# librm_*.rlib of the REALMODE block above (CONFIG_RUST only).
# header.S is the bzImage's real-mode header (PE/COFF header, setup header at 0x1f1, `_start`): Rust only for CONFIG_X86_64 and when
# EFI_MIXED / EFI_HANDOVER_PROTOCOL / EFI_SBAT are off (the same configs boot_rust_ok keeps on the Rust path; the .compat / .sbat PE
# arms are written and object-compared but not booted anywhere). The numbers the C headers compute and Rust cannot see reach rustc as
# the generated header_zo.rs (zoffset.h / voffset.h through rmasm_consts.sh) and env vars (CONFIG_PHYSICAL_START/ALIGN, SVGA_MODE).
ifdef CONFIG_RUST
boot_rmasm_rust := y
ifeq ($(boot_rmasm_rust),y)
rmasm_names := copy bioscall pmjump
rmasm_hdr := $(if $(CONFIG_X86_64),$(if $(CONFIG_EFI_MIXED)$(CONFIG_EFI_HANDOVER_PROTOCOL)$(CONFIG_EFI_SBAT),,y))
rmasm_names += $(if $(rmasm_hdr),header)
rmasm_c_objs := $(addsuffix .o,$(rmasm_names))
rmasm_objs := $(addprefix $(obj)/,$(addsuffix _rs.o,$(rmasm_names)))
rmasm_cfgs-$(CONFIG_X86_64) += --cfg=x86_64
rmasm_cfgs-$(CONFIG_X86_32) += --cfg=x86_32
rmasm_cfgs-$(CONFIG_EFI_STUB) += --cfg=efi_stub
rmasm_cfgs-$(CONFIG_EFI_MIXED) += --cfg=efi_mixed
rmasm_cfgs-$(CONFIG_EFI_SBAT) += --cfg=efi_sbat
rmasm_cfgs-$(CONFIG_EFI_HANDOVER_PROTOCOL) += --cfg=efi_handover_protocol
rmasm_cfgs-$(CONFIG_RELOCATABLE) += --cfg=relocatable
rmasm_cfgs-$(CONFIG_EFI) += --cfg=efi
rmasm_cfgs-$(CONFIG_KEXEC_CORE) += --cfg=kexec_core

quiet_cmd_rmconsts = RMCONST $@
      cmd_rmconsts = sh $(src)/rmasm_consts.sh $(obj)/zoffset.h $(obj)/voffset.h > $@
# voffset.h has no rule here (compressed/Makefile makes it, before compressed/vmlinux, which zoffset.h waits for); the file is
# cheap, so it is regenerated on every build (cmd, not if_changed) rather than trusting a prerequisite list that cannot name voffset.h.
$(obj)/header_zo.rs: $(src)/rmasm_consts.sh $(obj)/zoffset.h FORCE
	$(call cmd,rmconsts)

$(rmasm_objs): $(obj)/%_rs.o: $(src)/%_rs.rs $(obj)/librm_core.rlib $(obj)/librm_compiler_builtins.rlib FORCE
	$(Q)RMASM_ZO_RS=$(abspath $(obj)/header_zo.rs) RMASM_PHYSICAL_START=$(CONFIG_PHYSICAL_START) \
		RMASM_PHYSICAL_ALIGN=$(CONFIG_PHYSICAL_ALIGN) RMASM_SVGA_MODE=$(patsubst -DSVGA_MODE=%,%,$(SVGA_MODE)) \
		$(RUSTC) $(rm_rustflags) $(rmasm_cfgs-y) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
		--crate-name=$*_rs --emit=obj \
		--extern core=$(obj)/librm_core.rlib \
		--extern compiler_builtins=$(obj)/librm_compiler_builtins.rlib -o $@ $<
$(obj)/header_rs.o: $(obj)/header_zo.rs

# Swap in place, so the link order (which matters for video-*.o) is unchanged.
setup-y := $(foreach o,$(setup-y),$(if $(filter $(o),$(rmasm_c_objs)),$(basename $(o))_rs.o,$(o)))
endif
endif
# ---- end RUSTY-LINUX REALMODE-ASM -------------------------------------------------------------------------

targets		+= $(setup-y)
hostprogs	+= mkcpustr

HOST_EXTRACFLAGS += -I$(srctree)/tools/include \
		    -include include/generated/autoconf.h \
	            -D__EXPORTED_HEADERS__

$(obj)/cpu.o: $(obj)/cpustr.h

quiet_cmd_cpustr = CPUSTR  $@
      cmd_cpustr = $(obj)/mkcpustr > $@
$(obj)/cpustr.h: $(obj)/mkcpustr FORCE
	$(call if_changed,cpustr)
targets += cpustr.h

# ---------------------------------------------------------------------------

KBUILD_CFLAGS	:= $(REALMODE_CFLAGS) -D_SETUP
KBUILD_AFLAGS	:= $(KBUILD_CFLAGS) -D__ASSEMBLY__
KBUILD_CFLAGS	+= -fno-asynchronous-unwind-tables
KBUILD_CFLAGS	+= $(CONFIG_CC_IMPLICIT_FALLTHROUGH)

$(obj)/bzImage: asflags-y  := $(SVGA_MODE)

quiet_cmd_image = BUILD   $@
      cmd_image = (dd if=$< bs=4k conv=sync status=none; cat $(filter-out $<,$(real-prereqs))) >$@

$(obj)/bzImage: $(obj)/setup.bin $(obj)/vmlinux.bin FORCE
	$(call if_changed,image)
	@$(kecho) 'Kernel: $@ is ready' ' (#'$(or $(KBUILD_BUILD_VERSION),`cat .version`)')'

OBJCOPYFLAGS_vmlinux.bin := -O binary -R .note -R .comment -S
$(obj)/vmlinux.bin: $(obj)/compressed/vmlinux FORCE
	$(call if_changed,objcopy)

SETUP_OBJS = $(addprefix $(obj)/,$(setup-y))

sed-zoffset := -e 's/^\([0-9a-fA-F]*\) [a-zA-Z] \(startup_32\|efi.._stub_entry\|efi\(32\)\?_pe_entry\|input_data\|kernel_info\|_end\|_ehead\|_text\|_e\?data\|_e\?sbat\|z_.*\)$$/\#define ZO_\2 0x\1/p'

quiet_cmd_zoffset = ZOFFSET $@
      cmd_zoffset = $(NM) $< | sed -n $(sed-zoffset) > $@

targets += zoffset.h
$(obj)/zoffset.h: $(obj)/compressed/vmlinux FORCE
	$(call if_changed,zoffset)


AFLAGS_header.o += -I$(objtree)/$(obj)
$(obj)/header.o: $(obj)/zoffset.h

LDFLAGS_setup.elf	:= -m elf_i386 -z noexecstack -T
$(obj)/setup.elf: $(src)/setup.ld $(SETUP_OBJS) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_setup.bin	:= -O binary
$(obj)/setup.bin: $(obj)/setup.elf FORCE
	$(call if_changed,objcopy)

$(obj)/compressed/vmlinux: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/compressed $@

# Set this if you want to pass append arguments to the
# bzdisk/fdimage/hdimage/isoimage kernel
FDARGS =
# Set this if you want one or more initrds included in the image
FDINITRD =

imgdeps = $(obj)/bzImage $(obj)/mtools.conf $(src)/genimage.sh

$(obj)/mtools.conf: $(src)/mtools.conf.in
	sed -e 's|@OBJ@|$(obj)|g' < $< > $@

targets += mtools.conf

# genimage.sh requires bash, but it also has a bunch of other
# external dependencies.
quiet_cmd_genimage = GENIMAGE $3
      cmd_genimage = $(BASH) $(src)/genimage.sh $2 $3 $(obj)/bzImage \
		$(obj)/mtools.conf '$(FDARGS)' $(FDINITRD)

PHONY += bzdisk fdimage fdimage144 fdimage288 hdimage isoimage

# This requires write access to /dev/fd0
# All images require syslinux to be installed; hdimage also requires
# EDK2/OVMF if the kernel is compiled with the EFI stub.
bzdisk: $(imgdeps)
	$(call cmd,genimage,bzdisk,/dev/fd0)

fdimage fdimage144: $(imgdeps)
	$(call cmd,genimage,fdimage144,$(obj)/fdimage)
	@$(kecho) 'Kernel: $(obj)/fdimage is ready'

fdimage288: $(imgdeps)
	$(call cmd,genimage,fdimage288,$(obj)/fdimage)
	@$(kecho) 'Kernel: $(obj)/fdimage is ready'

hdimage: $(imgdeps)
	$(call cmd,genimage,hdimage,$(obj)/hdimage)
	@$(kecho) 'Kernel: $(obj)/hdimage is ready'

isoimage: $(imgdeps)
	$(call cmd,genimage,isoimage,$(obj)/image.iso)
	@$(kecho) 'Kernel: $(obj)/image.iso is ready'
