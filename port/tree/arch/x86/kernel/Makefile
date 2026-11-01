# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

always-$(KBUILD_BUILTIN)	+= vmlinux.lds

CPPFLAGS_vmlinux.lds += -U$(UTS_MACHINE)

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_tsc.o = -pg
CFLAGS_REMOVE_paravirt-spinlocks.o = -pg
CFLAGS_REMOVE_pvclock.o = -pg
CFLAGS_REMOVE_kvmclock.o = -pg
CFLAGS_REMOVE_ftrace.o = -pg
CFLAGS_REMOVE_early_printk.o = -pg
CFLAGS_REMOVE_head64.o = -pg
CFLAGS_REMOVE_head32.o = -pg
CFLAGS_REMOVE_rethook.o = -pg
endif

KASAN_SANITIZE_head$(BITS).o				:= n
KASAN_SANITIZE_dumpstack.o				:= n
KASAN_SANITIZE_dumpstack_$(BITS).o			:= n
KASAN_SANITIZE_stacktrace.o				:= n
KASAN_SANITIZE_paravirt.o				:= n

# With some compiler versions the generated code results in boot hangs, caused
# by several compilation units. To be safe, disable all instrumentation.
KCSAN_SANITIZE := n
KMSAN_SANITIZE_head$(BITS).o				:= n
KMSAN_SANITIZE_nmi.o					:= n

# If instrumentation of the following files is enabled, boot hangs during
# first second.
KCOV_INSTRUMENT_head$(BITS).o				:= n
# These are called from save_stack_trace() on debug paths,
# and produce large amounts of uninteresting coverage.
KCOV_INSTRUMENT_stacktrace.o				:= n
KCOV_INSTRUMENT_dumpstack.o				:= n
KCOV_INSTRUMENT_dumpstack_$(BITS).o			:= n
KCOV_INSTRUMENT_unwind_orc.o				:= n
KCOV_INSTRUMENT_unwind_frame.o				:= n
KCOV_INSTRUMENT_unwind_guess.o				:= n

# Disable KCOV to prevent crashes during kexec: load_segments() invalidates
# the GS base, which KCOV relies on for per-CPU data.
#
# As KCOV and KEXEC compatibility should be preserved (e.g. syzkaller is
# using it to collect crash dumps during kernel fuzzing), disabling
# KCOV for KEXEC kernels is not an option. Selectively disabling KCOV
# instrumentation for individual affected functions can be fragile, while
# adding more checks to KCOV would slow it down.
#
# As a compromise solution, disable KCOV instrumentation for the whole
# source code file. If its coverage is ever needed, other approaches
# should be considered.
KCOV_INSTRUMENT_machine_kexec_64.o			:= n

CFLAGS_head32.o := -fno-stack-protector
CFLAGS_head64.o := -fno-stack-protector
CFLAGS_irq.o := -I $(src)/../include/asm/trace

obj-y			+= head_$(BITS).o
# PHASE E: head64.o is a composite when CONFIG_RUST on x86-64: head64_glue.o is upstream's head64.c
# with the early page-fault handler, clear_bss and x86_64_start_reservations removed (kept: the
# variables, x86_64_start_kernel, copy_bootdata, early_setup_idt), head64_rs.o holds those.
# CONFIG_RUST=n builds upstream's head64.c, untouched in the tree (logs/phase-e-pi.md, file 3).
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
obj-y			+= head64.o
head64-y		:= head64_glue.o head64_rs.o
CFLAGS_REMOVE_head64_glue.o = -pg
KASAN_SANITIZE_head64_glue.o	:= n
KMSAN_SANITIZE_head64_glue.o	:= n
KCOV_INSTRUMENT_head64_glue.o	:= n
# the Rust half runs before kasan_early_init() too (early #PF handler, clear_bss, reset_early_page_tables), so it needs
# the same exclusions as upstream's head64.o: found by the checker build (a KASAN kernel double-faulted in __asan_set_shadow_f2)
KASAN_SANITIZE_head64_rs.o	:= n
KMSAN_SANITIZE_head64_rs.o	:= n
KCOV_INSTRUMENT_head64_rs.o	:= n
ifdef CONFIG_KASAN
RUSTFLAGS_head64_rs.o	+= -Cunsafe-allow-abi-mismatch=sanitizer
endif
CFLAGS_head64_glue.o := -fno-stack-protector
else
obj-y			+= head$(BITS).o
endif
obj-y			+= ebda.o
# PHASE E: platform-quirks.o is platform_quirks_rs.o under CONFIG_RUST on x86-64 (the whole file is ported);
# CONFIG_RUST=n builds upstream's platform-quirks.c, untouched in the tree.
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
obj-y			+= platform_quirks_rs.o
else
obj-y			+= platform-quirks.o
endif
obj-y			+= process_$(BITS).o signal.o signal_$(BITS).o
obj-y			+= traps.o idt.o irq.o irq_$(BITS).o dumpstack_$(BITS).o
# PHASE E: idt.o is a composite when CONFIG_RUST on x86-64: idt_glue.o is upstream's idt.c without the gate writer,
# the early gate tables and the early-IDT functions' bodies (`#line` keeps upstream's file name and line numbers),
# idt_rs.o holds them. CONFIG_RUST=n builds upstream's idt.c, untouched in the tree (logs/hooks.md, idt record).
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
idt-y			:= idt_glue.o idt_rs.o
endif
obj-y			+= time.o ioport.o dumpstack.o nmi.o
obj-$(CONFIG_X86_FRED)	+= fred.o
obj-$(CONFIG_MODIFY_LDT_SYSCALL)	+= ldt.o
obj-$(CONFIG_X86_KERNEL_IBT)		+= ibt_selftest.o
obj-y			+= setup.o x86_init.o i8259.o irqinit.o
# PHASE E: x86_init.o is a composite when CONFIG_RUST on x86-64: x86_init_glue.o is upstream's x86_init.c without the six
# global no-op callbacks (`#line` keeps upstream's numbering), x86_init_rs.o holds them. CONFIG_RUST=n builds upstream's x86_init.c.
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
x86_init-y		:= x86_init_glue.o x86_init_rs.o
endif
obj-$(CONFIG_JUMP_LABEL)	+= jump_label.o
obj-$(CONFIG_IRQ_WORK)  += irq_work.o
obj-y			+= probe_roms.o
obj-$(CONFIG_X86_32)	+= sys_ia32.o
obj-$(CONFIG_IA32_EMULATION)	+= sys_ia32.o signal_32.o
obj-$(CONFIG_X86_64)	+= sys_x86_64.o
obj-$(CONFIG_X86_ESPFIX64)	+= espfix_64.o
obj-$(CONFIG_SYSFS)	+= ksysfs.o
obj-y			+= bootflag.o e820.o
# PHASE E: e820.o is a composite when CONFIG_RUST on x86-64: e820_glue.o is upstream's e820.c without the table
# logic (and with `#line` directives that keep upstream's file name and line numbers), e820_rs.o holds the logic.
# CONFIG_RUST=n builds upstream's e820.c, untouched in the tree (logs/hooks.md, e820 record).
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
e820-y			:= e820_glue.o e820_rs.o
endif
obj-y			+= pci-dma.o quirks.o kdebugfs.o
obj-y			+= alternative.o i8253.o hw_breakpoint.o
obj-y			+= tsc.o tsc_msr.o io_delay.o rtc.o
obj-y			+= resource.o
obj-y			+= irqflags.o
obj-y			+= static_call.o

obj-y				+= process.o
obj-y				+= fpu/
obj-y				+= ptrace.o
obj-$(CONFIG_X86_32)		+= tls.o
obj-$(CONFIG_IA32_EMULATION)	+= tls.o
obj-y				+= step.o
obj-$(CONFIG_INTEL_TXT)		+= tboot.o
obj-$(CONFIG_ISA_DMA_API)	+= i8237.o
obj-y				+= stacktrace.o
obj-y				+= cpu/
obj-y				+= acpi/
obj-y				+= reboot.o
obj-$(CONFIG_X86_MSR)		+= msr.o
obj-$(CONFIG_X86_CPUID)		+= cpuid.o
obj-$(CONFIG_PCI)		+= early-quirks.o
apm-y				:= apm_32.o
obj-$(CONFIG_APM)		+= apm.o
obj-$(CONFIG_SMP)		+= smp.o
obj-$(CONFIG_SMP)		+= smpboot.o
obj-$(CONFIG_X86_TSC)		+= tsc_sync.o
obj-$(CONFIG_SMP)		+= setup_percpu.o
obj-$(CONFIG_X86_MPPARSE)	+= mpparse.o
obj-y				+= apic/
obj-$(CONFIG_X86_REBOOTFIXUPS)	+= reboot_fixups_32.o
obj-$(CONFIG_DYNAMIC_FTRACE)	+= ftrace.o
obj-$(CONFIG_FUNCTION_TRACER)	+= ftrace_$(BITS).o
obj-$(CONFIG_FUNCTION_GRAPH_TRACER) += ftrace.o
obj-$(CONFIG_FTRACE_SYSCALLS)	+= ftrace.o
obj-$(CONFIG_X86_TSC)		+= trace_clock.o
obj-$(CONFIG_TRACING)		+= trace.o
obj-$(CONFIG_RETHOOK)		+= rethook.o
obj-$(CONFIG_VMCORE_INFO)	+= vmcore_info_$(BITS).o
obj-$(CONFIG_KEXEC_CORE)	+= machine_kexec_$(BITS).o
obj-$(CONFIG_KEXEC_CORE)	+= relocate_kernel_$(BITS).o
obj-$(CONFIG_KEXEC_FILE)	+= kexec-bzimage64.o
obj-$(CONFIG_CRASH_DUMP)	+= crash_dump_$(BITS).o crash.o
obj-y				+= kprobes/
obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_X86_32)		+= doublefault_32.o
obj-$(CONFIG_KGDB)		+= kgdb.o
obj-$(CONFIG_VM86)		+= vm86_32.o
obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o

obj-$(CONFIG_HPET_TIMER) 	+= hpet.o

obj-$(CONFIG_AMD_NB)		+= amd_nb.o
obj-$(CONFIG_AMD_NODE)		+= amd_node.o
obj-$(CONFIG_DEBUG_NMI_SELFTEST) += nmi_selftest.o

obj-$(CONFIG_KVM_GUEST)		+= kvm.o kvmclock.o
obj-$(CONFIG_PARAVIRT)		+= paravirt.o
obj-$(CONFIG_PARAVIRT_SPINLOCKS)+= paravirt-spinlocks.o
obj-$(CONFIG_PARAVIRT_CLOCK)	+= pvclock.o
obj-$(CONFIG_X86_PMEM_LEGACY_DEVICE) += pmem.o

obj-$(CONFIG_JAILHOUSE_GUEST)	+= jailhouse.o

obj-$(CONFIG_EISA)		+= eisa.o
obj-$(CONFIG_PCSPKR_PLATFORM)	+= pcspeaker.o

obj-$(CONFIG_X86_CHECK_BIOS_CORRUPTION) += check.o

obj-$(CONFIG_OF)			+= devicetree.o
obj-$(CONFIG_UPROBES)			+= uprobes.o

obj-$(CONFIG_PERF_EVENTS)		+= perf_regs.o
obj-$(CONFIG_SCHED_MC_PRIO)		+= itmt.o
obj-$(CONFIG_X86_UMIP)			+= umip.o

obj-$(CONFIG_UNWINDER_ORC)		+= unwind_orc.o
obj-$(CONFIG_UNWINDER_FRAME_POINTER)	+= unwind_frame.o
obj-$(CONFIG_UNWINDER_GUESS)		+= unwind_guess.o

obj-$(CONFIG_CFI)			+= cfi.o

obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o

obj-$(CONFIG_X86_CET)			+= cet.o

obj-$(CONFIG_X86_USER_SHADOW_STACK)	+= shstk.o

###
# 64 bit specific files
ifeq ($(CONFIG_X86_64),y)
	obj-$(CONFIG_AUDIT)		+= audit_64.o

	obj-$(CONFIG_GART_IOMMU)	+= amd_gart_64.o aperture_64.o

	obj-$(CONFIG_MMCONF_FAM10H)	+= mmconf-fam10h_64.o
	obj-y				+= vsmp_64.o
endif
