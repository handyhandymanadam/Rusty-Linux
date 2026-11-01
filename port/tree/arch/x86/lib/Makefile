# SPDX-License-Identifier: GPL-2.0
#
# Makefile for x86 specific library files.
#

# Produces uninteresting flaky coverage.
KCOV_INSTRUMENT_delay.o	:= n

# KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
KCSAN_SANITIZE_delay.o := n
ifdef CONFIG_KCSAN
# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
endif

inat_tables_script = $(srctree)/arch/x86/tools/gen-insn-attr-x86.awk
inat_tables_maps = $(srctree)/arch/x86/lib/x86-opcode-map.txt
quiet_cmd_inat_tables = GEN     $@
      cmd_inat_tables = $(AWK) -f $(inat_tables_script) $(inat_tables_maps) > $@

$(obj)/inat-tables.c: $(inat_tables_script) $(inat_tables_maps)
	$(call cmd,inat_tables)

$(obj)/inat.o: $(obj)/inat-tables.c
$(obj)/inat_tables_glue.o: $(obj)/inat-tables.c
$(obj)/inat_norust.o: $(obj)/inat-tables.c

clean-files := inat-tables.c

obj-$(CONFIG_SMP) += msr-smp.o cache-smp.o

lib-y := delay.o
# cpu.o is replaced by cpu_rs.o (x86_family/x86_model/x86_stepping, exported by
# the Rust object itself via kernel::kabi_export!, no C entry). The
# CONFIG_RUST=n arm builds upstream's body, installed byte-identical as
# cpu_norust.c by rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
lib-y += cpu_rs.o
else
lib-y += cpu_norust.o
endif
# cmdline.o: under CONFIG_RUST it is the C entry points (cmdline.c here is the
# glue) plus cmdline_rs.o, which holds the two scanners. The CONFIG_RUST=n arm
# builds upstream's body, installed byte-identical as cmdline_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2). Neither entry point
# is exported.
ifdef CONFIG_RUST
lib-y += cmdline.o cmdline_rs.o
else
lib-y += cmdline_norust.o
endif
# misc.o is replaced by misc_rs.o (num_digits). The CONFIG_RUST=n arm builds
# upstream's body, installed byte-identical as misc_norust.c by rig/apply.sh
# from port/pristine/ (logs/floor.md RAISE 2). num_digits is not exported, so
# there is no C entry thunk to keep.
ifdef CONFIG_RUST
lib-y += misc_rs.o
else
lib-y += misc_norust.o
endif
lib-y += usercopy_$(BITS).o usercopy.o getuser.o putuser.o
lib-y += memcpy_$(BITS).o
lib-y += pc-conf-reg.o
lib-$(CONFIG_ARCH_HAS_COPY_MC) += copy_mc.o copy_mc_64.o
# insn.o + inat.o are replaced by insn_rs.o under CONFIG_RUST (the decoder and the six
# inat_get_*() lookups; neither file has an EXPORT_SYMBOL) plus inat_tables_glue.o, which
# is only the generated opcode tables (data). Upstream's insn.c/inat.c stay in the tree
# unchanged because boot/compressed/sev-handle-vc.c #includes them. The CONFIG_RUST=n arm
# builds upstream's bodies, installed byte-identical as insn_norust.c / inat_norust.c.
ifdef CONFIG_RUST
lib-$(CONFIG_INSTRUCTION_DECODER) += insn_rs.o inat_tables_glue.o insn-eval.o
else
lib-$(CONFIG_INSTRUCTION_DECODER) += insn_norust.o inat_norust.o insn-eval.o
endif
lib-$(CONFIG_RANDOMIZE_BASE) += kaslr.o
lib-$(CONFIG_FUNCTION_ERROR_INJECTION)	+= error-inject.o
lib-$(CONFIG_MITIGATION_RETPOLINE) += retpoline.o

obj-y += msr.o msr-reg.o msr-reg-export.o hweight.o
obj-y += iomem.o

ifeq ($(CONFIG_X86_32),y)
        obj-y += atomic64_32.o
        lib-y += atomic64_cx8_32.o
        lib-y += checksum_32.o
        lib-y += strstr_32.o
        lib-y += string_32.o
        lib-y += memmove_32.o
        lib-y += cmpxchg8b_emu.o
ifneq ($(CONFIG_X86_CX8),y)
        lib-y += atomic64_386_32.o
endif
else
ifneq ($(CONFIG_GENERIC_CSUM),y)
        lib-y += csum-copy_64.o csum-wrappers_64.o
# csum-partial_64.o is replaced by csum_partial_rs.o (csum_partial and
# ip_compute_csum, exported by the Rust object itself via kernel::kabi_export!,
# no C entry). The CONFIG_RUST=n arm builds upstream's body, installed
# byte-identical as csum-partial_64_norust.c by rig/apply.sh from port/pristine/
# (logs/floor.md RAISE 2). csum-copy_64.S and csum-wrappers_64.c are other files
# and stay as they are.
ifdef CONFIG_RUST
        lib-y += csum_partial_rs.o
else
        lib-y += csum-partial_64_norust.o
endif
endif
        lib-y += clear_page_64.o copy_page_64.o
        lib-y += memmove_64.o memset_64.o
        lib-y += copy_user_64.o copy_user_uncached_64.o
        lib-y += cmpxchg16b_emu.o
        lib-y += bhi.o
endif
