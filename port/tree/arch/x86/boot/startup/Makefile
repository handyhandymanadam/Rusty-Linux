# SPDX-License-Identifier: GPL-2.0

KBUILD_AFLAGS		+= -D__DISABLE_EXPORTS
KBUILD_CFLAGS		+= -D__DISABLE_EXPORTS -mcmodel=small -fPIC \
			   -Os -DDISABLE_BRANCH_PROFILING \
			   $(DISABLE_STACKLEAK_PLUGIN) \
			   $(DISABLE_LATENT_ENTROPY_PLUGIN) \
			   -fno-stack-protector -D__NO_FORTIFY \
			   -fno-jump-tables \
			   -include $(srctree)/include/linux/hidden.h

# disable ftrace hooks and LTO
KBUILD_CFLAGS	:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out $(CC_FLAGS_LTO),$(KBUILD_CFLAGS))
KASAN_SANITIZE	:= n
KCSAN_SANITIZE	:= n
KMSAN_SANITIZE	:= n
UBSAN_SANITIZE	:= n
KCOV_INSTRUMENT	:= n

# PHASE E: gdt_idt.c and map_kernel.c are Rust under CONFIG_RUST (gdt_idt_rs.rs, logs/phase-e-pi.md). The
# CONFIG_RUST=n arm builds upstream's gdt_idt.c, which stays in the tree untouched.
# A `.pi.o` Rust object needs what the C flags above give the C objects: small code model,
# position independent code, size-optimised, no absolute relocations. kbuild's Rust flags are
# -Crelocation-model=static -Ccode-model=kernel; the later -C options win (checked: the .cmd
# line carries both and `readelf -r` of the object shows PC32 only).
# -Zdirect-access-external-data is not needed: every external symbol is addressed by an
# inline-asm `lea [rip + sym]` (the C's rip_rel_ptr()).
ifdef CONFIG_RUST
obj-$(CONFIG_X86_64)		+= gdt_idt_rs.o map_kernel_rs.o
# -Zplt=yes: a call to an extern fn (the AMD arm of map_kernel) must be a plain PLT32, not a GOT load.
# -Zmin-function-alignment: the C objects get -fmin-function-alignment (Makefile:1065); kbuild gives
# Rust nothing, which leaves every Rust function unaligned (.init.text Al=1).
pi_rustflags			:= -Crelocation-model=pic -Ccode-model=small -Copt-level=s -Zplt=yes
ifdef CONFIG_FUNCTION_ALIGNMENT
pi_rustflags			+= -Zmin-function-alignment=$(CONFIG_FUNCTION_ALIGNMENT)
endif
# CONCURRENCY CHECKER BUILDS (configs/chk-ka): this directory is KASAN_SANITIZE := n, so kbuild gives these
# two objects no -Zsanitizer, while the kernel `core` crate is built WITH -Zsanitizer=kernel-address and rustc
# refuses the mix. They run before KASAN's shadow exists and must stay uninstrumented, so the mismatch is
# intended; only under CONFIG_KASAN, so every other config is byte-for-byte unchanged.
ifdef CONFIG_KASAN
pi_rustflags			+= -Cunsafe-allow-abi-mismatch=sanitizer
endif
RUSTFLAGS_gdt_idt_rs.o		:= $(pi_rustflags)
RUSTFLAGS_map_kernel_rs.o	:= $(pi_rustflags)
else
obj-$(CONFIG_X86_64)		+= gdt_idt.o map_kernel.o
endif
obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= sme.o sev-startup.o
pi-objs				:= $(patsubst %.o,$(obj)/%.o,$(obj-y))

lib-$(CONFIG_X86_64)		+= la57toggle.o
lib-$(CONFIG_EFI_MIXED)		+= efi-mixed.o

#
# Disable objtool validation for all library code, which is intended
# to be linked into the decompressor or the EFI stub but not vmlinux
#
$(patsubst %.o,$(obj)/%.o,$(lib-y)): OBJECT_FILES_NON_STANDARD := y

#
# Invoke objtool for each object individually to check for absolute
# relocations, even if other objtool actions are being deferred.
#
$(pi-objs): objtool-enabled	= 1
$(pi-objs): objtool-args	= $(if $(delay-objtool),,$(objtool-args-y)) --noabs

#
# Confine the startup code by prefixing all symbols with __pi_ (for position
# independent). This ensures that startup code can only call other startup
# code, or code that has explicitly been made accessible to it via a symbol
# alias.
#
$(obj)/%.pi.o: OBJCOPYFLAGS := --prefix-symbols=__pi_
$(obj)/%.pi.o: $(obj)/%.o FORCE
	$(call if_changed,objcopy)

targets	+= $(obj-y)
obj-y	:= $(patsubst %.o,%.pi.o,$(obj-y))
