# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y     = fork.o exec_domain.o panic.o \
	    cpu.o exit.o softirq.o \
	    sysctl.o capability.o ptrace.o user.o \
	    signal.o sys.o umh.o workqueue.o pid.o task_work.o \
	    extable.o params.o \
	    kthread.o sys_ni.o nsproxy.o nstree.o nscommon.o \
	    ksysfs.o cred.o reboot.o \
	    async.o smpboot.o regset.o ksyms_common.o

# range.o is replaced by range_rs.o under CONFIG_RUST (add_range, add_range_with_merge, subtract_range, clean_sort_range,
# sort_range: none exported, no C entry). CONFIG_RUST=n builds upstream's body, installed byte-identical as
# range_norust.c by rig/apply.sh from port/pristine/.
ifdef CONFIG_RUST
obj-y += range_rs.o
else
obj-y += range_norust.o
endif

# PHASE E: params.o is a composite when CONFIG_RUST on x86-64: params_glue.o is upstream's params.c without the command-line
# walker (dash2underscore, parameqn, parameq, parse_one, parse_args; `#line` keeps upstream's numbering), params_rs.o holds it.
# CONFIG_RUST=n builds upstream's params.c, untouched in the tree (logs/hooks.md, params record).
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
params-y := params_glue.o params_rs.o
endif

# groups.o is a composite under CONFIG_RUST: groups_glue.o is upstream's groups.c without gid_cmp/groups_sort/groups_search,
# groups_rs.o holds those (groups_sort exported via kernel::kabi_export!). CONFIG_RUST=n builds upstream's body, installed
# byte-identical as groups_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
groups-y := groups_glue.o groups_rs.o
else
groups-y := groups_norust.o
endif
obj-$(CONFIG_MULTIUSER) += groups.o
obj-$(CONFIG_VHOST_TASK) += vhost_task.o

ifdef CONFIG_FUNCTION_TRACER
# Do not trace internal ftrace files
CFLAGS_REMOVE_irq_work.o = $(CC_FLAGS_FTRACE)
endif

# Branch profiling isn't noinstr-safe
ifdef CONFIG_TRACE_BRANCH_PROFILING
CFLAGS_context_tracking.o += -DDISABLE_BRANCH_PROFILING
endif

# Prevents flicker of uninteresting __do_softirq()/__local_bh_disable_ip()
# in coverage traces.
KCOV_INSTRUMENT_softirq.o := n
# Avoid KCSAN instrumentation in softirq ("No shared variables, all the data
# are CPU local" => assume no data races), to reduce overhead in interrupts.
KCSAN_SANITIZE_softirq.o = n
# These are called from save_stack_trace() on slub debug path,
# and produce insane amounts of uninteresting coverage.
KCOV_INSTRUMENT_extable.o := n
KCOV_INSTRUMENT_stacktrace.o := n
# Don't self-instrument.
KCOV_INSTRUMENT_kcov.o := n
# If sanitizers detect any issues in kcov, it may lead to recursion
# via printk, etc.
KASAN_SANITIZE_kcov.o := n
KCSAN_SANITIZE_kcov.o := n
UBSAN_SANITIZE_kcov.o := n
KMSAN_SANITIZE_kcov.o := n
CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector

obj-y += sched/
obj-y += locking/
obj-y += power/
obj-y += printk/
obj-y += irq/
obj-y += rcu/
obj-y += livepatch/
obj-y += dma/
obj-y += entry/
obj-y += unwind/
obj-$(CONFIG_MODULES) += module/

obj-$(CONFIG_KCMP) += kcmp.o
obj-$(CONFIG_FREEZER) += freezer.o
obj-$(CONFIG_PROFILING) += profile.o
obj-$(CONFIG_STACKTRACE) += stacktrace.o
obj-y += time/
obj-$(CONFIG_FUTEX) += futex/
obj-$(CONFIG_GENERIC_ISA_DMA) += dma.o
obj-$(CONFIG_SMP) += smp.o
ifneq ($(CONFIG_SMP),y)
obj-y += up.o
endif
obj-$(CONFIG_UID16) += uid16.o
obj-$(CONFIG_MODULE_SIG_FORMAT) += module_signature.o
# kallsyms.o is a composite under CONFIG_RUST: kallsyms_glue.o is upstream's file with the table walkers replaced by calls into kallsyms_rs.o. CONFIG_RUST=n builds upstream's body,
# installed byte-identical as kallsyms_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
kallsyms-y := kallsyms_glue.o kallsyms_rs.o
else
kallsyms-y := kallsyms_norust.o
endif
obj-$(CONFIG_KALLSYMS) += kallsyms.o
obj-$(CONFIG_KALLSYMS_SELFTEST) += kallsyms_selftest.o
obj-$(CONFIG_BSD_PROCESS_ACCT) += acct.o
obj-$(CONFIG_VMCORE_INFO) += vmcore_info.o elfcorehdr.o
obj-$(CONFIG_CRASH_RESERVE) += crash_reserve.o
obj-$(CONFIG_KEXEC_CORE) += kexec_core.o
obj-$(CONFIG_CRASH_DUMP) += crash_core.o
obj-$(CONFIG_CRASH_DM_CRYPT) += crash_dump_dm_crypt.o
obj-$(CONFIG_CRASH_DUMP_KUNIT_TEST) += crash_core_test.o
obj-$(CONFIG_KEXEC) += kexec.o
obj-$(CONFIG_KEXEC_FILE) += kexec_file.o
obj-$(CONFIG_KEXEC_ELF) += kexec_elf.o
obj-$(CONFIG_KEXEC_HANDOVER) += kexec_handover.o
obj-$(CONFIG_KEXEC_HANDOVER_DEBUG) += kexec_handover_debug.o
obj-$(CONFIG_KEXEC_HANDOVER_DEBUGFS) += kexec_handover_debugfs.o
obj-$(CONFIG_BACKTRACE_SELF_TEST) += backtracetest.o
obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_CGROUPS) += cgroup/
obj-$(CONFIG_UTS_NS) += utsname.o
# sysctl.o is a composite under CONFIG_RUST: sysctl_glue.o is upstream's file with the integer-handler text engine replaced by calls into sysctl_rs.o. CONFIG_RUST=n builds upstream's body,
# installed byte-identical as sysctl_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
sysctl-y := sysctl_glue.o sysctl_rs.o
else
sysctl-y := sysctl_norust.o
endif

# ucount.o is a composite under CONFIG_RUST: ucount_glue.o is upstream's file with the counter walks replaced by calls into ucount_rs.o. CONFIG_RUST=n builds upstream's body,
# installed byte-identical as ucount_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
ucount-y := ucount_glue.o ucount_rs.o
else
ucount-y := ucount_norust.o
endif
obj-y += ucount.o
# resource.o is a composite under CONFIG_RUST: resource_glue.o is upstream's file with the lock-free tree algorithms replaced by calls into resource_rs.o. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as resource_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
resource-y := resource_glue.o resource_rs.o
else
resource-y := resource_norust.o
endif
obj-y += resource.o
# notifier.o is a composite under CONFIG_RUST: notifier_glue.o is upstream's file without the chain core (register, unregister, call_chain, call_chain_robust), notifier_rs.o holds it.
# CONFIG_RUST=n builds upstream's body, installed byte-identical as notifier_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
notifier-y := notifier_glue.o notifier_rs.o
else
notifier-y := notifier_norust.o
endif
obj-y += notifier.o
# user_namespace.o is a composite under CONFIG_RUST: user_namespace_glue.o is upstream's file without the id-map lookups, mappings_overlap(), insert_extent(), sort_idmaps() and the
# parse / translate / sort phases of map_write(); user_namespace_rs.o holds those. CONFIG_RUST=n builds upstream's body, installed byte-identical as user_namespace_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
user_namespace-y := user_namespace_glue.o user_namespace_rs.o
else
user_namespace-y := user_namespace_norust.o
endif
obj-$(CONFIG_USER_NS) += user_namespace.o
obj-$(CONFIG_PID_NS) += pid_namespace.o
obj-$(CONFIG_IKCONFIG) += configs.o
obj-$(CONFIG_IKHEADERS) += kheaders.o
obj-$(CONFIG_SMP) += stop_machine.o
# auditfilter.o is a composite under CONFIG_RUST: auditfilter_glue.o is upstream's file with the pure checks replaced by calls into auditfilter_rs.o. CONFIG_RUST=n builds upstream's body,
# installed byte-identical as auditfilter_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
auditfilter-y := auditfilter_glue.o auditfilter_rs.o
else
auditfilter-y := auditfilter_norust.o
endif
obj-$(CONFIG_AUDIT) += audit.o auditfilter.o
obj-$(CONFIG_AUDITSYSCALL) += auditsc.o audit_watch.o audit_fsnotify.o audit_tree.o
obj-$(CONFIG_GCOV_KERNEL) += gcov/
obj-$(CONFIG_KCOV) += kcov.o
obj-$(CONFIG_KPROBES) += kprobes.o
obj-$(CONFIG_FAIL_FUNCTION) += fail_function.o
obj-$(CONFIG_KGDB) += debug/
obj-$(CONFIG_DETECT_HUNG_TASK) += hung_task.o
obj-$(CONFIG_LOCKUP_DETECTOR) += watchdog.o
obj-$(CONFIG_HARDLOCKUP_DETECTOR_BUDDY) += watchdog_buddy.o
obj-$(CONFIG_HARDLOCKUP_DETECTOR_PERF) += watchdog_perf.o
obj-$(CONFIG_SECCOMP) += seccomp.o
obj-$(CONFIG_RELAY) += relay.o
obj-$(CONFIG_SYSCTL) += utsname_sysctl.o
obj-$(CONFIG_TASK_DELAY_ACCT) += delayacct.o
obj-$(CONFIG_TASKSTATS) += taskstats.o tsacct.o
obj-$(CONFIG_TRACEPOINTS) += tracepoint.o
obj-$(CONFIG_LATENCYTOP) += latencytop.o
obj-$(CONFIG_FUNCTION_TRACER) += trace/
obj-$(CONFIG_TRACING) += trace/
obj-$(CONFIG_TRACE_CLOCK) += trace/
obj-$(CONFIG_RING_BUFFER) += trace/
obj-$(CONFIG_TRACEPOINTS) += trace/
obj-$(CONFIG_RETHOOK) += trace/
obj-$(CONFIG_IRQ_WORK) += irq_work.o
obj-$(CONFIG_CPU_PM) += cpu_pm.o
obj-$(CONFIG_BPF) += bpf/
obj-$(CONFIG_KCSAN) += kcsan/
obj-$(CONFIG_SHADOW_CALL_STACK) += scs.o
obj-$(CONFIG_HAVE_STATIC_CALL) += static_call.o
obj-$(CONFIG_HAVE_STATIC_CALL_INLINE) += static_call_inline.o
obj-$(CONFIG_CFI) += cfi.o

obj-$(CONFIG_PERF_EVENTS) += events/

obj-$(CONFIG_USER_RETURN_NOTIFIER) += user-return-notifier.o
obj-$(CONFIG_PADATA) += padata.o
obj-$(CONFIG_JUMP_LABEL) += jump_label.o
obj-$(CONFIG_CONTEXT_TRACKING) += context_tracking.o
obj-$(CONFIG_TORTURE_TEST) += torture.o

obj-$(CONFIG_HAS_IOMEM) += iomem.o
obj-$(CONFIG_RSEQ) += rseq.o
obj-$(CONFIG_WATCH_QUEUE) += watch_queue.o

obj-$(CONFIG_RESOURCE_KUNIT_TEST) += resource_kunit.o
obj-$(CONFIG_SYSCTL_KUNIT_TEST) += sysctl-test.o

CFLAGS_kstack_erase.o += $(DISABLE_KSTACK_ERASE)
CFLAGS_kstack_erase.o += $(call cc-option,-mgeneral-regs-only)
obj-$(CONFIG_KSTACK_ERASE) += kstack_erase.o
KASAN_SANITIZE_kstack_erase.o := n
KCSAN_SANITIZE_kstack_erase.o := n
KCOV_INSTRUMENT_kstack_erase.o := n

obj-$(CONFIG_SCF_TORTURE_TEST) += scftorture.o

$(obj)/configs.o: $(obj)/config_data.gz

targets += config_data config_data.gz
$(obj)/config_data.gz: $(obj)/config_data FORCE
	$(call if_changed,gzip)

filechk_cat = cat $<

$(obj)/config_data: $(KCONFIG_CONFIG) FORCE
	$(call filechk,cat)

# kheaders_data.tar.xz
$(obj)/kheaders.o: $(obj)/kheaders_data.tar.xz

quiet_cmd_kheaders_data = GEN     $@
      cmd_kheaders_data = "$<" "$@" "$(obj)/kheaders-srclist" "$(obj)/kheaders-objlist" "$(KBUILD_BUILD_TIMESTAMP)"
      cmd_kheaders_data_dep = cat $(depfile) >> $(dot-target).cmd; rm -f $(depfile)

define rule_kheaders_data
	$(call cmd_and_savecmd,kheaders_data)
	$(call cmd,kheaders_data_dep)
endef

targets += kheaders_data.tar.xz
$(obj)/kheaders_data.tar.xz: $(src)/gen_kheaders.sh $(obj)/kheaders-srclist $(obj)/kheaders-objlist $(obj)/kheaders.md5 FORCE
	$(call if_changed_rule,kheaders_data)

# generated headers in objtree
#
# include/generated/utsversion.h is ignored because it is generated
# after gen_kheaders.sh is executed. (utsversion.h is unneeded for kheaders)
filechk_kheaders_objlist = \
	for d in include "arch/$(SRCARCH)/include"; do \
		find "$${d}/generated" ! -path "include/generated/utsversion.h" -a -name "*.h" -print; \
	done

$(obj)/kheaders-objlist: FORCE
	$(call filechk,kheaders_objlist)

# non-generated headers in srctree
filechk_kheaders_srclist = \
	for d in include "arch/$(SRCARCH)/include"; do \
		find "$(srctree)/$${d}" -path "$(srctree)/$${d}/generated" -prune -o -name "*.h" -print; \
	done

$(obj)/kheaders-srclist: FORCE
	$(call filechk,kheaders_srclist)

# Some files are symlinks. If symlinks are changed, kheaders_data.tar.xz should
# be rebuilt.
filechk_kheaders_md5sum = xargs -r -a $< stat -c %N | md5sum

$(obj)/kheaders.md5: $(obj)/kheaders-srclist FORCE
	$(call filechk,kheaders_md5sum)

clean-files := kheaders.md5 kheaders-srclist kheaders-objlist
