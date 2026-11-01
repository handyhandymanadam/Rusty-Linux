# SPDX-License-Identifier: GPL-2.0
#
# Makefile for some libs needed in the kernel.
#

ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)

# Branch profiling isn't noinstr-safe
ifdef CONFIG_TRACE_BRANCH_PROFILING
CFLAGS_smp_processor_id.o += -DDISABLE_BRANCH_PROFILING
endif

# These files are disabled because they produce lots of non-interesting and/or
# flaky coverage that is not a function of syscall inputs. For example,
# rbtree can be global and individual rotations don't correlate with inputs.
#
# rbtree.o is gone (see the CONFIG_RUST arms below): this directive now
# names rbtree_rs.o in both arms, kbuild's KCOV_INSTRUMENT_<obj> mechanism
# working on the object regardless of source language.
KCOV_INSTRUMENT_string.o := n
KCOV_INSTRUMENT_rbtree_rs.o := n
KCOV_INSTRUMENT_rbtree_norust.o := n
KCOV_INSTRUMENT_list_debug.o := n
KCOV_INSTRUMENT_debugobjects.o := n
KCOV_INSTRUMENT_dynamic_debug.o := n
KCOV_INSTRUMENT_fault-inject.o := n
KCOV_INSTRUMENT_find_bit.o := n

# string.o implements standard library functions like memset/memcpy etc.
# Use -ffreestanding to ensure that the compiler does not try to "optimize"
# them into calls to themselves.
CFLAGS_string.o := -ffreestanding
CFLAGS_string_glue.o := -ffreestanding
CFLAGS_string_norust.o := -ffreestanding
KCOV_INSTRUMENT_string_glue.o := n
KCOV_INSTRUMENT_string_rs.o := n
KCOV_INSTRUMENT_string_norust.o := n

# Early boot use of cmdline, don't instrument it
ifdef CONFIG_AMD_MEM_ENCRYPT
KASAN_SANITIZE_string.o := n
KASAN_SANITIZE_string_glue.o := n
KASAN_SANITIZE_string_rs.o := n
KASAN_SANITIZE_string_norust.o := n

CFLAGS_string.o += -fno-stack-protector
endif

# ctype.o is gone: the Rust defines and exports _ctype itself and carries its
# ABI contract, via kernel::kabi_export!(). See the CONFIG_RUST arms below.
# xarray.o is likewise gone from this unconditional list: the Rust defines
# and exports all 41 of lib/xarray.c's symbols itself. See the CONFIG_RUST
# arms below (the retained xarray.o there is a small allocation thunk, not
# the original file).
#
# vsprintf.o is gone from here too: retained-C-entry-plus-Rust-body split,
# same shape as string_helpers.o -- vsnprintf/vbin_printf/vsscanf and 9
# deferred %p handlers stay C (still touch va_list, or are their own
# checkpoint), format_decode/number/pointer()/bstr_printf and everything
# else move to Rust. See the CONFIG_RUST arms below.
lib-y := \
	 irq_regs.o \
	 is_single_threaded.o \
	 nmi_backtrace.o \
	 objpool.o iomem_copy.o

lib-$(CONFIG_PRINTK) += dump_stack.o
lib-$(CONFIG_SMP) += cpumask.o
lib-$(CONFIG_MIN_HEAP) += min_heap.o

# lockref.o: where USE_CMPXCHG_LOCKREF holds (x86-64, SMP, one-word spinlock: no DEBUG_SPINLOCK / DEBUG_LOCK_ALLOC) the lock-free
# fast path is lockref_rs.o and lockref.c is the thunk-shaped entry file (static_assert of the same condition); every other build
# gets upstream's body, installed byte-identical as lockref_norust.c by rig/apply.sh.
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64)$(CONFIG_SMP)$(CONFIG_ARCH_USE_CMPXCHG_LOCKREF)$(CONFIG_DEBUG_SPINLOCK)$(CONFIG_DEBUG_LOCK_ALLOC),yyyy)
obj-y	+= lockref.o lockref_rs.o
else
obj-y	+= lockref_norust.o
endif

obj-y += kasprintf.o \
	 lwq.o \
	 percpu-refcount.o \
	 once.o refcount.o bucket_locks.o

# bitmap.o is a composite under CONFIG_RUST: bitmap_glue.o keeps the allocators (bitmap_alloc*, bitmap_free, devm_),
# bitmap_rs.o holds every bitmap operation (exported via kernel::kabi_export!). CONFIG_RUST=n builds upstream's body,
# installed byte-identical as bitmap_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
bitmap-y := bitmap_glue.o bitmap_rs.o
else
bitmap-y := bitmap_norust.o
endif
obj-y += bitmap.o
# kfifo.o likewise: kfifo_glue.o keeps allocation, the _user copies and the DMA scatterlist functions; kfifo_rs.o holds the
# copy-and-index core (exported via kernel::kabi_export!). CONFIG_RUST=n builds upstream's body, installed byte-identical as
# kfifo_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
kfifo-y := kfifo_glue.o kfifo_rs.o
else
kfifo-y := kfifo_norust.o
endif
obj-y += kfifo.o
# string.o: on x86-64 with CONFIG_RUST the generic file's functions are string_rs.o (no_builtins Rust), except sized_strscpy and
# strlcat (WARN_ON_ONCE / BUG_ON) which stay C in string_glue.o. Everything else builds upstream's body, installed
# byte-identical as string_norust.c by rig/apply.sh.
ifeq ($(CONFIG_RUST)$(CONFIG_X86_64),yy)
lib-y += string_glue.o string_rs.o
else
lib-y += string_norust.o
endif
# parser.o likewise: parser_glue.o keeps match_strdup (kmemdup_nul); parser_rs.o holds the rest (exported via
# kernel::kabi_export!). CONFIG_RUST=n builds upstream's body, installed byte-identical as parser_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
parser-y := parser_glue.o parser_rs.o
else
parser-y := parser_norust.o
endif
obj-y += parser.o
# random32.o likewise: random32_glue.o keeps the per-CPU seeding and the selftest; random32_rs.o holds prandom_u32_state and
# prandom_bytes_state (exported via kernel::kabi_export!). CONFIG_RUST=n builds upstream's body, installed byte-identical as
# random32_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
random32-y := random32_glue.o random32_rs.o
else
random32-y := random32_norust.o
endif
obj-y += random32.o
# bitmap-str.o likewise: bitmap_str_glue.o keeps the _user variants and the bitmap_print_* functions (memdup_user_nul,
# scnprintf, kasprintf); bitmap_str_rs.o holds bitmap_parselist and bitmap_parse (exported via kernel::kabi_export!).
# CONFIG_RUST=n builds upstream's body, installed byte-identical as bitmap-str_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
bitmap-str-y := bitmap_str_glue.o bitmap_str_rs.o
else
bitmap-str-y := bitmap-str_norust.o
endif
obj-y += bitmap-str.o
# usercopy.o is gone from here: retained-C-entry-plus-Rust-body split, same
# shape as strncpy_from_user.o/strnlen_user.o. See the CONFIG_RUST arms below.
# find_bit.o is gone: the Rust defines and exports its 17 symbols itself
# and carries their ABI contracts. See the CONFIG_RUST arms below.
# string_helpers.o: retained-C-entry-plus-Rust-body split, same shape as
# usercopy.o/strncpy_from_user.o just above -- the Rust defines and exports
# all 19 of its symbols itself. See the CONFIG_RUST arms below.
# hexdump.o is gone: the Rust defines and exports its seven symbols itself
# and carries their ABI contracts. See the CONFIG_RUST arms below.
obj-$(CONFIG_TEST_HEXDUMP) += test_hexdump.o
# kstrtox.o is gone the same way: 22 exported symbols plus three internal
# helpers vsprintf.c and bitmap-str.c still link against directly.
obj-$(CONFIG_FIND_BIT_BENCHMARK) += find_bit_benchmark.o
obj-$(CONFIG_FIND_BIT_BENCHMARK_RUST) += find_bit_benchmark_rust.o
obj-$(CONFIG_TEST_BPF) += test_bpf.o
test_dhry-objs := dhry_1.o dhry_2.o dhry_run.o
obj-$(CONFIG_TEST_DHRY) += test_dhry.o
obj-$(CONFIG_TEST_FIRMWARE) += test_firmware.o
obj-$(CONFIG_TEST_BITOPS) += test_bitops.o
CFLAGS_test_bitops.o += -Werror
obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
obj-$(CONFIG_TEST_IDA) += test_ida.o
obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
CFLAGS_test_ubsan.o += $(call cc-disable-warning, unused-but-set-variable)
UBSAN_SANITIZE_test_ubsan.o := y
obj-$(CONFIG_TEST_KSTRTOX) += test-kstrtox.o
obj-$(CONFIG_TEST_MIN_HEAP) += test_min_heap.o
obj-$(CONFIG_TEST_LKM) += test_module.o
obj-$(CONFIG_TEST_VMALLOC) += test_vmalloc.o
obj-$(CONFIG_TEST_RHASHTABLE) += test_rhashtable.o
obj-$(CONFIG_TEST_STATIC_KEYS) += test_static_keys.o
obj-$(CONFIG_TEST_STATIC_KEYS) += test_static_key_base.o
obj-$(CONFIG_TEST_DYNAMIC_DEBUG) += test_dynamic_debug.o

obj-$(CONFIG_TEST_BITMAP) += test_bitmap.o
ifeq ($(CONFIG_CC_IS_CLANG)$(CONFIG_KASAN),yy)
# FIXME: Clang breaks test_bitmap_const_eval when KASAN and GCOV are enabled
GCOV_PROFILE_test_bitmap.o := n
endif

obj-$(CONFIG_TEST_UUID) += test_uuid.o
obj-$(CONFIG_TEST_XARRAY) += test_xarray.o
obj-$(CONFIG_TEST_MAPLE_TREE) += test_maple_tree.o
obj-$(CONFIG_TEST_PARMAN) += test_parman.o
obj-$(CONFIG_TEST_KMOD) += test_kmod.o
obj-$(CONFIG_TEST_DEBUG_VIRTUAL) += test_debug_virtual.o
obj-$(CONFIG_TEST_MEMCAT_P) += test_memcat_p.o
obj-$(CONFIG_TEST_OBJAGG) += test_objagg.o
obj-$(CONFIG_TEST_MEMINIT) += test_meminit.o
obj-$(CONFIG_TEST_LOCKUP) += test_lockup.o
obj-$(CONFIG_TEST_HMM) += test_hmm.o
obj-$(CONFIG_TEST_FREE_PAGES) += test_free_pages.o
obj-$(CONFIG_TEST_REF_TRACKER) += test_ref_tracker.o
obj-$(CONFIG_TEST_OBJPOOL) += test_objpool.o
obj-$(CONFIG_TEST_KEXEC_HANDOVER) += test_kho.o

obj-$(CONFIG_TEST_FPU) += test_fpu.o
test_fpu-y := test_fpu_glue.o test_fpu_impl.o
CFLAGS_test_fpu_impl.o += $(CC_FLAGS_FPU)
CFLAGS_REMOVE_test_fpu_impl.o += $(CC_FLAGS_NO_FPU)

obj-y += kunit/

ifeq ($(CONFIG_DEBUG_KOBJECT),y)
CFLAGS_kobject.o += -DDEBUG
CFLAGS_kobject_uevent.o += -DDEBUG
endif

obj-$(CONFIG_DEBUG_INFO_REDUCED) += debug_info.o
CFLAGS_debug_info.o += $(call cc-option, -femit-struct-debug-detailed=any)

obj-y += math/ crc/ crypto/ tests/ vdso/

obj-$(CONFIG_HAS_IOMEM) += devres.o
obj-$(CONFIG_DEBUG_LOCKING_API_SELFTESTS) += locking-selftest.o


lib-$(CONFIG_INDIRECT_IOMEM) += logic_iomem.o

obj-$(CONFIG_TRACE_MMIO_ACCESS) += trace_readwrite.o

obj-$(CONFIG_GENERIC_HWEIGHT) += hweight.o

obj-$(CONFIG_BTREE) += btree.o
# interval_tree.o is gone: the Rust defines and exports its 7 symbols
# itself and carries their ABI contracts. See the CONFIG_RUST arms below.
# assoc_array.o likewise: assoc_array_glue.o keeps the allocation, call_rcu and BUG() helpers and the layout asserts;
# assoc_array_rs.o defines the ten public functions themselves (none is EXPORT_SYMBOL'd). CONFIG_RUST=n builds upstream's body,
# installed byte-identical as assoc_array_norust.c by rig/apply.sh.
# maple_tree.o: maple_tree_glue.o keeps the slab/sheaf, call_rcu, lock, tracepoint and BUG/WARN helpers, the 36 EXPORT_SYMBOLs as
# thunks and the layout asserts; maple_tree_rs.o is the whole algorithm. CONFIG_DEBUG_MAPLE_TREE adds the dump/validate code to
# upstream's file (not ported), so that config, like CONFIG_RUST=n, builds upstream's body, installed byte-identical as
# maple_tree_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
ifndef CONFIG_DEBUG_MAPLE_TREE
maple_tree-y := maple_tree_glue.o maple_tree_rs.o
else
maple_tree-y := maple_tree_norust.o
endif
else
maple_tree-y := maple_tree_norust.o
endif
obj-y += maple_tree.o
ifdef CONFIG_RUST
assoc_array-y := assoc_array_glue.o assoc_array_rs.o
else
assoc_array-y := assoc_array_norust.o
endif
obj-$(CONFIG_ASSOCIATIVE_ARRAY) += assoc_array.o
obj-$(CONFIG_DEBUG_PREEMPT) += smp_processor_id.o
obj-$(CONFIG_LIST_HARDENED) += list_debug.o
obj-$(CONFIG_DEBUG_OBJECTS) += debugobjects.o

# bitrev.o is gone: the Rust defines and exports byte_rev_table itself and
# carries its ABI contract, via kernel::kabi_export!(). See the CONFIG_RUST
# arms below and logs/c-entry-rule.md.
obj-$(CONFIG_LINEAR_RANGES) += linear_ranges.o
obj-$(CONFIG_PACKING)	+= packing.o
obj-$(CONFIG_PACKING_KUNIT_TEST) += packing_test.o
# genalloc.o likewise: genalloc_glue.o keeps the pool/chunk plumbing and the exported entry points (the five allocation
# algorithms are thin wrappers there; gen_pool_fixed_alloc keeps its WARN_ON); genalloc_rs.o holds the lock-free bitmap
# helpers and the algorithms' arithmetic. CONFIG_RUST=n builds upstream's body, installed byte-identical as genalloc_norust.c
# by rig/apply.sh.
ifdef CONFIG_RUST
genalloc-y := genalloc_glue.o genalloc_rs.o
else
genalloc-y := genalloc_norust.o
endif
obj-$(CONFIG_GENERIC_ALLOCATOR) += genalloc.o

obj-$(CONFIG_842_COMPRESS) += 842/
obj-$(CONFIG_842_DECOMPRESS) += 842/
obj-$(CONFIG_ZLIB_INFLATE) += zlib_inflate/
obj-$(CONFIG_ZLIB_DEFLATE) += zlib_deflate/
obj-$(CONFIG_ZLIB_DFLTCC) += zlib_dfltcc/
obj-$(CONFIG_REED_SOLOMON) += reed_solomon/
obj-$(CONFIG_BCH) += bch.o
obj-$(CONFIG_LZO_COMPRESS) += lzo/
obj-$(CONFIG_LZO_DECOMPRESS) += lzo/
obj-$(CONFIG_LZ4_COMPRESS) += lz4/
obj-$(CONFIG_LZ4HC_COMPRESS) += lz4/
obj-$(CONFIG_LZ4_DECOMPRESS) += lz4/
obj-$(CONFIG_ZSTD_COMPRESS) += zstd/
obj-$(CONFIG_ZSTD_DECOMPRESS) += zstd/
obj-$(CONFIG_XZ_DEC) += xz/
obj-$(CONFIG_RAID6_PQ) += raid6/

# decompress_inflate.o: CONFIG_RUST=n only -- see the CONFIG_RUST arms
# below. decompress_inflate.c itself stays pristine (its #ifdef STATIC arm
# is textually #include-d by arch/x86/boot/compressed/misc.c under
# CONFIG_KERNEL_GZIP, which both of this project's configs set); the
# CONFIG_RUST=y arm compiles decompress_inflate_alloc.o + the Rust instead,
# never decompress_inflate.o itself, since that would double-define
# gunzip().
# decompress_bunzip2.o: see the CONFIG_RUST arms below.
# decompress_unlzma.o: CONFIG_RUST=n only -- see the CONFIG_RUST arms
# below. decompress_unlzma.c itself stays pristine (its #ifdef STATIC arm
# is the WHOLE LZMA algorithm, not just a thin wrapper, and is textually
# #include-d by arch/x86/boot/compressed/misc.c under CONFIG_KERNEL_LZMA
# -- see logs/build-limits.md's entry on this file for why it stays
# pristine even though neither of this project's configs sets that
# symbol); the CONFIG_RUST=y arm compiles decompress_unlzma_alloc.o + the
# Rust instead, never decompress_unlzma.o itself, since that would
# double-define unlzma().
# decompress_unxz.o: see the CONFIG_RUST arms below.
# decompress_unlzo.o: see the CONFIG_RUST arms below.
# decompress_unlz4.o: see the CONFIG_RUST arms below.
# decompress_unzstd.o: see the CONFIG_RUST arms below.

obj-$(CONFIG_TEXTSEARCH) += textsearch.o
obj-$(CONFIG_TEXTSEARCH_KMP) += ts_kmp.o
obj-$(CONFIG_TEXTSEARCH_BM) += ts_bm.o
obj-$(CONFIG_TEXTSEARCH_FSM) += ts_fsm.o
obj-$(CONFIG_SMP) += percpu_counter.o
obj-$(CONFIG_AUDIT_GENERIC) += audit.o
obj-$(CONFIG_AUDIT_COMPAT_GENERIC) += compat_audit.o

obj-$(CONFIG_IOMMU_HELPER) += iommu-helper.o
obj-$(CONFIG_FAULT_INJECTION) += fault-inject.o
obj-$(CONFIG_FAULT_INJECTION_USERCOPY) += fault-inject-usercopy.o
obj-$(CONFIG_NOTIFIER_ERROR_INJECTION) += notifier-error-inject.o
obj-$(CONFIG_PM_NOTIFIER_ERROR_INJECT) += pm-notifier-error-inject.o
obj-$(CONFIG_NETDEV_NOTIFIER_ERROR_INJECT) += netdev-notifier-error-inject.o
obj-$(CONFIG_MEMORY_NOTIFIER_ERROR_INJECT) += memory-notifier-error-inject.o
obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
	of-reconfig-notifier-error-inject.o
obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o

obj-$(CONFIG_CODE_TAGGING) += codetag.o
obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o

obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_EMU) += cmpxchg-emu.o

obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
#ensure exported functions have prototypes
CFLAGS_dynamic_debug.o := -DDYNAMIC_DEBUG_MODULE

# errname.o is gone: the Rust defines and exports errname() itself and
# carries its ABI contract. See the CONFIG_RUST arms below.

# nlattr.o likewise: nlattr_glue.o keeps the exported entry points (thunks), the skb builders, nla_strdup and one helper per
# WARN/BUG/rate-limited-print site; nlattr_rs.o holds the attribute walk and the policy validation. CONFIG_RUST=n builds upstream's
# body, installed byte-identical as nlattr_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
nlattr-y := nlattr_glue.o nlattr_rs.o
else
nlattr-y := nlattr_norust.o
endif
obj-$(CONFIG_NLATTR) += nlattr.o

obj-$(CONFIG_LRU_CACHE) += lru_cache.o

obj-$(CONFIG_GENERIC_CSUM) += checksum.o

obj-$(CONFIG_GENERIC_ATOMIC64) += atomic64.o

obj-$(CONFIG_ATOMIC64_SELFTEST) += atomic64_test.o

# cpu_rmap.o: cpu_rmap_glue.o keeps the exports as thunks, cpu_rmap_update()'s mask allocation, get/put, the IRQ glue and the rust_cr_* wrappers; cpu_rmap_rs.o is
# alloc_cpu_rmap(), cpu_rmap_add() and the update algorithm. CONFIG_RUST=n builds upstream's body, installed byte-identical as cpu_rmap_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
cpu_rmap-y := cpu_rmap_glue.o cpu_rmap_rs.o
else
cpu_rmap-y := cpu_rmap_norust.o
endif
obj-$(CONFIG_CPU_RMAP) += cpu_rmap.o

obj-$(CONFIG_CLOSURES) += closure.o

# dynamic_queue_limits.o is the BUG_ON/tracepoint thunk only under
# CONFIG_RUST -- the algorithm is in dynamic_queue_limits_rs.o. See the
# CONFIG_RUST arms below.

obj-$(CONFIG_GLOB_SELFTEST) += globtest.o
obj-$(CONFIG_LIB_SELFTEST) += libtest.o
obj-$(CONFIG_LIB_STRESS) += libstress.o

obj-$(CONFIG_DIMLIB) += dim/
obj-$(CONFIG_SIGNATURE) += digsig.o

# clz_tab.o is gone: see the CONFIG_RUST arms below.

# strncpy_from_user.o/strnlen_user.o/usercopy.o: retained-C-entry-plus-Rust-body
# split. See the CONFIG_RUST arms below and each file's own header comment.


obj-$(CONFIG_SG_SPLIT) += sg_split.o
obj-$(CONFIG_SG_POOL) += sg_pool.o
obj-$(CONFIG_MEMREGION) += memregion.o
obj-$(CONFIG_STMP_DEVICE) += stmp_device.o
obj-$(CONFIG_IRQ_POLL) += irq_poll.o

obj-$(CONFIG_POLYNOMIAL) += polynomial.o

# stackdepot.c should not be instrumented or call instrumented functions.
# Prevent the compiler from calling builtins like memcmp() or bcmp() from this
# file.
CFLAGS_stackdepot.o += -fno-builtin
CFLAGS_stackdepot_glue.o += -fno-builtin
CFLAGS_stackdepot_norust.o += -fno-builtin
# stackdepot.o: stackdepot_glue.o keeps the state, init, debugfs, the exports as thunks and one-line wrappers (rust_sdw_*); stackdepot_rs.o is the
# algorithms. CONFIG_RUST=n builds upstream's body, installed byte-identical as stackdepot_norust.c by rig/apply.sh. The sanitizer opt-outs
# below apply to every member.
ifdef CONFIG_RUST
stackdepot-y := stackdepot_glue.o stackdepot_rs.o
else
stackdepot-y := stackdepot_norust.o
endif
obj-$(CONFIG_STACKDEPOT) += stackdepot.o
KASAN_SANITIZE_stackdepot_glue.o := n
KASAN_SANITIZE_stackdepot_norust.o := n
KASAN_SANITIZE_stackdepot_rs.o := n
ifdef CONFIG_KASAN
RUSTFLAGS_stackdepot_rs.o += -Cunsafe-allow-abi-mismatch=sanitizer
endif
KASAN_SANITIZE_stackdepot.o := n
# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
# recursion.
KMSAN_SANITIZE_stackdepot.o := n
KMSAN_SANITIZE_stackdepot_glue.o := n
KMSAN_SANITIZE_stackdepot_norust.o := n
KMSAN_SANITIZE_stackdepot_rs.o := n
KCOV_INSTRUMENT_stackdepot.o := n
KCOV_INSTRUMENT_stackdepot_glue.o := n
KCOV_INSTRUMENT_stackdepot_norust.o := n
KCOV_INSTRUMENT_stackdepot_rs.o := n

obj-$(CONFIG_REF_TRACKER) += ref_tracker.o

libfdt_files = fdt.o fdt_ro.o fdt_wip.o fdt_rw.o fdt_sw.o fdt_strerror.o \
	       fdt_empty_tree.o fdt_addresses.o
$(foreach file, $(libfdt_files), \
	$(eval CFLAGS_$(file) = -I $(srctree)/scripts/dtc/libfdt))
lib-$(CONFIG_LIBFDT) += $(libfdt_files)

obj-$(CONFIG_BOOT_CONFIG) += bootconfig.o
obj-$(CONFIG_BOOT_CONFIG_EMBED) += bootconfig-data.o

$(obj)/bootconfig-data.o: $(obj)/default.bconf

targets += default.bconf
filechk_defbconf = cat $(or $(real-prereqs), /dev/null)
$(obj)/default.bconf: $(CONFIG_BOOT_CONFIG_EMBED_FILE) FORCE
	$(call filechk,defbconf)

obj-$(CONFIG_RBTREE_TEST) += rbtree_test.o
obj-$(CONFIG_INTERVAL_TREE_TEST) += interval_tree_test.o

obj-$(CONFIG_PERCPU_TEST) += percpu_test.o

# asn1_decoder.o is gone: the Rust defines and exports asn1_ber_decoder()
# itself and carries its ABI contract, via kernel::kabi_export!(). See
# the CONFIG_RUST arms below.
obj-$(CONFIG_ASN1_ENCODER) += asn1_encoder.o

obj-$(CONFIG_FONT_SUPPORT) += fonts/

# oid_registry.o is gone under CONFIG_RUST: the Rust defines and exports
# look_up_OID/parse_OID/sprint_oid itself, with the OID tables generated
# directly from oid_registry_data.c's OWN generator's output (see
# logs/porting-hazards.md's "header the tarball doesn't ship" hazard class)
# rather than transcribed. See the CONFIG_RUST arms below and
# oid_registry_rs.rs's module doc.
#
# The CONFIG_RUST=n arm still needs oid_registry_data.c generated: its
# oid_registry_norust.c is byte-identical pristine C, `#include`ing that
# generated file by its original name, in the same directory -- this
# generation rule has to survive for that arm even though nothing under
# CONFIG_RUST triggers it any more.
$(obj)/oid_registry_norust.o: $(obj)/oid_registry_data.c

$(obj)/oid_registry_data.c: $(srctree)/include/linux/oid_registry.h \
			    $(src)/build_OID_registry
	$(call cmd,build_OID_registry)

quiet_cmd_build_OID_registry = GEN     $@
      cmd_build_OID_registry = perl $(src)/build_OID_registry $< $@

clean-files	+= oid_registry_data.c

obj-$(CONFIG_UBSAN) += ubsan.o

UBSAN_SANITIZE_ubsan.o := n
KASAN_SANITIZE_ubsan.o := n
KCSAN_SANITIZE_ubsan.o := n
CFLAGS_ubsan.o := -fno-stack-protector $(DISABLE_KSTACK_ERASE)

obj-$(CONFIG_SBITMAP) += sbitmap.o

obj-$(CONFIG_PARMAN) += parman.o

# group_cpus.o: group_cpus_glue.o keeps group_cpus_evenly() (the allocation scaffolding, which depends on CONFIG_CPUMASK_OFFSTACK, and the
# export) and one-line wrappers for the configuration-dependent accessors; group_cpus_rs.o is the grouping algorithm. The !CONFIG_SMP
# variant (everything in one group) and CONFIG_RUST=n build upstream's body, installed byte-identical as group_cpus_norust.c.
ifdef CONFIG_RUST
ifdef CONFIG_SMP
group_cpus-y := group_cpus_glue.o group_cpus_rs.o
else
group_cpus-y := group_cpus_norust.o
endif
else
group_cpus-y := group_cpus_norust.o
endif
obj-y += group_cpus.o

# scatterlist.o: scatterlist_glue.o keeps every exported entry point as a thunk, the allocator-shaped functions and one-line wrappers
# for the configuration-dependent header inlines; scatterlist_rs.o is the algorithms; scatterlist_extract.o is upstream's
# extract_iter_to_sg() and helpers unchanged (they walk iov_iter / folio_queue / xarray). CONFIG_RUST=n builds upstream's body,
# installed byte-identical as scatterlist_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
scatterlist-y := scatterlist_glue.o scatterlist_rs.o scatterlist_extract.o
else
scatterlist-y := scatterlist_norust.o
endif
obj-y += scatterlist.o

# GCC library routines
obj-$(CONFIG_GENERIC_LIB_ASHLDI3) += ashldi3.o
obj-$(CONFIG_GENERIC_LIB_ASHRDI3) += ashrdi3.o
obj-$(CONFIG_GENERIC_LIB_LSHRDI3) += lshrdi3.o
obj-$(CONFIG_GENERIC_LIB_MULDI3) += muldi3.o
obj-$(CONFIG_GENERIC_LIB_CMPDI2) += cmpdi2.o
obj-$(CONFIG_GENERIC_LIB_UCMPDI2) += ucmpdi2.o
obj-$(CONFIG_OBJAGG) += objagg.o

# pldmfw library
obj-$(CONFIG_PLDMFW) += pldmfw/

obj-$(CONFIG_GENERIC_LIB_DEVMEM_IS_ALLOWED) += devmem_is_allowed.o

# fw_table.o is gone: the Rust defines acpi_parse_entries_array/
# cdat_table_parse directly (neither is EXPORT_SYMBOL_FWTBL_LIB actually
# expands to on this config -- CONFIG_ACPI_TABLE_LIB is unset -- so
# there is no kabi contract to carry). See the CONFIG_RUST arms below.

subdir-$(CONFIG_FORTIFY_SOURCE) += test_fortify

# ---------------------------------------------------------------------------
# THE RUST PORT, AND THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2.
#
# Six architectures select HAVE_RUST. Every other one -- s390, powerpc, mips,
# sparc, parisc, sh -- is CONFIG_RUST=n and has no Rust target at all, and so
# is any x86_64 machine whose owner turns it off. A ported module that only
# builds with CONFIG_RUST=y is a module that has been removed from those
# architectures, and for a long time these lists added the .rs objects
# unconditionally.
#
# The `else` arm compiles <base>_norust.o, and <base>_norust.c is installed by
# rig/apply.sh as a byte-identical copy of port/pristine/ -- the sha256-verified
# upstream body out of the tarball. It is a separate FILENAME because a
# thunk-shaped port occupies the original path: lib/glob.c here is our two
# entry symbols, and upstream's lib/glob.c is a different file with the same
# name. It is generated on every apply and never committed, so it cannot drift
# and there is no second copy of upstream in git.
#
# THE C ARM IS UPSTREAM, UNMODIFIED, AND THAT IS THE WHOLE CLAIM RAISE 2 RESTS
# ON. rig/pristine-check.sh guards it.
ifdef CONFIG_RUST

lib-y                            += plist.o plist_rs.o earlycpio.o earlycpio_rs.o \
                                    win_minmax_rs.o
lib-$(CONFIG_UNION_FIND)         += union_find_rs.o
obj-y                            += bcd_rs.o sort.o sort_rs.o list_sort_rs.o \
                                    clz_ctz.o clz_ctz_rs.o bsearch_rs.o \
                                    memweight.o memweight_rs.o base64_rs.o
obj-$(CONFIG_CHECK_SIGNATURE)    += check_signature.o check_signature_rs.o
obj-$(CONFIG_XXHASH)             += xxhash_rs.o
obj-$(CONFIG_GLOB)               += glob.o glob_rs.o
obj-$(CONFIG_GENERIC_NET_UTILS)  += net_utils_rs.o
obj-$(CONFIG_UCS2_STRING)        += ucs2_string.o ucs2_string_rs.o
obj-$(CONFIG_BITREVERSE)         += bitrev_rs.o
obj-y                            += uuid_rs.o
lib-y                            += ctype_rs.o
obj-y                            += hexdump_rs.o
obj-y                            += siphash_rs.o
lib-y                            += cmdline_rs.o
obj-y                            += llist_rs.o debug_locks_rs.o
obj-y                            += errseq_rs.o
obj-$(CONFIG_HAS_IOMEM)          += iomap_copy_rs.o
obj-y                            += kstrtox_rs.o
lib-$(CONFIG_CLZ_TAB)            += clz_tab_rs.o
obj-y                            += bust_spinlocks_rs.o
lib-y                            += decompress_rs.o
lib-$(CONFIG_DECOMPRESS_GZIP)    += decompress_inflate_alloc.o decompress_inflate_rs.o
lib-$(CONFIG_DECOMPRESS_LZMA)    += decompress_unlzma_alloc.o decompress_unlzma_rs.o
lib-$(CONFIG_DECOMPRESS_BZIP2)   += decompress_bunzip2.o decompress_bunzip2_rs.o
lib-$(CONFIG_DECOMPRESS_LZ4)     += decompress_unlz4.o decompress_unlz4_rs.o
lib-$(CONFIG_DECOMPRESS_LZO)     += decompress_unlzo.o decompress_unlzo_rs.o
lib-$(CONFIG_DECOMPRESS_XZ)      += decompress_unxz.o decompress_unxz_rs.o
lib-$(CONFIG_DECOMPRESS_ZSTD)    += decompress_unzstd.o decompress_unzstd_rs.o
lib-y                            += rbtree_rs.o
lib-y                            += timerqueue_rs.o
lib-y                            += xarray.o xarray_rs.o
lib-y                            += extable.o extable_rs.o
obj-y                            += sys_info_rs.o
obj-y                            += generic-radix-tree.o generic_radix_tree_rs.o
obj-$(CONFIG_SYMBOLIC_ERRNAME)   += errname_rs.o
obj-$(CONFIG_OID_REGISTRY)       += oid_registry_rs.o
obj-y                            += find_bit_rs.o
obj-$(CONFIG_DQL)                += dynamic_queue_limits.o dynamic_queue_limits_rs.o
obj-$(CONFIG_ASN1)                += asn1_decoder_rs.o
obj-$(CONFIG_INTERVAL_TREE)      += interval_tree_rs.o
obj-$(CONFIG_GENERIC_STRNCPY_FROM_USER) += strncpy_from_user.o strncpy_from_user_rs.o
obj-$(CONFIG_GENERIC_STRNLEN_USER)      += strnlen_user.o strnlen_user_rs.o
obj-y                                    += usercopy.o usercopy_rs.o
obj-$(CONFIG_FIRMWARE_TABLE)            += fw_table_rs.o
lib-y                            += ratelimit.o ratelimit_rs.o
lib-y                            += flex_proportions.o flex_proportions_rs.o
obj-y                            += buildid.o buildid_rs.o
obj-y                            += string_helpers.o string_helpers_rs.o
lib-y                            += vsprintf.o vsprintf_rs.o vsprintf_scan_rs.o
lib-y                            += seq_buf.o seq_buf_rs.o
obj-$(CONFIG_GENERIC_IOMAP)      += iomap.o iomap_rs.o
lib-$(CONFIG_GENERIC_BUG)        += bug.o bug_rs.o

else

lib-y                            += plist_norust.o earlycpio_norust.o \
                                    win_minmax_norust.o
lib-$(CONFIG_UNION_FIND)         += union_find_norust.o
obj-y                            += bcd_norust.o sort_norust.o list_sort_norust.o \
                                    clz_ctz_norust.o bsearch_norust.o \
                                    memweight_norust.o base64_norust.o
obj-$(CONFIG_CHECK_SIGNATURE)    += check_signature_norust.o
obj-$(CONFIG_XXHASH)             += xxhash_norust.o
obj-$(CONFIG_GLOB)               += glob_norust.o
obj-$(CONFIG_GENERIC_NET_UTILS)  += net_utils_norust.o
obj-$(CONFIG_UCS2_STRING)        += ucs2_string_norust.o
obj-$(CONFIG_BITREVERSE)         += bitrev_norust.o
obj-y                            += uuid_norust.o
lib-y                            += ctype_norust.o
obj-y                            += hexdump_norust.o
obj-y                            += siphash_norust.o
lib-y                            += cmdline_norust.o
obj-y                            += llist_norust.o debug_locks_norust.o
obj-y                            += errseq_norust.o
obj-$(CONFIG_HAS_IOMEM)          += iomap_copy_norust.o
obj-y                            += kstrtox_norust.o
lib-$(CONFIG_CLZ_TAB)            += clz_tab_norust.o
obj-y                            += bust_spinlocks_norust.o
lib-y                            += decompress_norust.o
lib-$(CONFIG_DECOMPRESS_GZIP)    += decompress_inflate.o
lib-$(CONFIG_DECOMPRESS_LZMA)    += decompress_unlzma.o
lib-$(CONFIG_DECOMPRESS_BZIP2)   += decompress_bunzip2_norust.o
lib-$(CONFIG_DECOMPRESS_LZ4)     += decompress_unlz4_norust.o
lib-$(CONFIG_DECOMPRESS_LZO)     += decompress_unlzo_norust.o
lib-$(CONFIG_DECOMPRESS_XZ)      += decompress_unxz_norust.o
lib-$(CONFIG_DECOMPRESS_ZSTD)    += decompress_unzstd_norust.o
lib-y                            += rbtree_norust.o
lib-y                            += timerqueue_norust.o
lib-y                            += xarray_norust.o
lib-y                            += extable_norust.o
obj-y                            += sys_info_norust.o
obj-y                            += generic-radix-tree_norust.o
obj-$(CONFIG_SYMBOLIC_ERRNAME)   += errname_norust.o
obj-$(CONFIG_OID_REGISTRY)       += oid_registry_norust.o
obj-y                            += find_bit_norust.o
obj-$(CONFIG_DQL)                += dynamic_queue_limits_norust.o
obj-$(CONFIG_ASN1)                += asn1_decoder_norust.o
obj-$(CONFIG_INTERVAL_TREE)      += interval_tree_norust.o
obj-$(CONFIG_GENERIC_STRNCPY_FROM_USER) += strncpy_from_user_norust.o
obj-$(CONFIG_GENERIC_STRNLEN_USER)      += strnlen_user_norust.o
obj-y                                    += usercopy_norust.o
obj-$(CONFIG_FIRMWARE_TABLE)            += fw_table_norust.o
lib-y                            += ratelimit_norust.o
lib-y                            += flex_proportions_norust.o
obj-y                            += buildid_norust.o
obj-y                            += string_helpers_norust.o
lib-y                            += vsprintf_norust.o
lib-y                            += seq_buf_norust.o
obj-$(CONFIG_GENERIC_IOMAP)      += iomap_norust.o
lib-$(CONFIG_GENERIC_BUG)        += bug_norust.o

endif
# ---------------------------------------------------------------------------

# rhashtable.o: rhashtable_glue.o keeps the exported entry points as thunks, the lockdep exports, rht_bucket_nested() (it owns a static) and
# one-line wrappers (rust_rhw_*) for the configuration-dependent header inlines (bucket bit-lock, rcu, mutex/spinlock/workqueue, tagged
# allocation, lists); rhashtable_rs.o is the algorithms. CONFIG_RUST=n builds upstream's body, installed byte-identical as
# rhashtable_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
rhashtable-y := rhashtable_glue.o rhashtable_rs.o
else
rhashtable-y := rhashtable_norust.o
endif
obj-y += rhashtable.o

# iov_iter.o: iov_iter_glue.o is upstream's file with the iterator bookkeeping (advance, revert, single_seg_count, alignment,
# gap_alignment, npages, restore) replaced by thunks and rust_iw_* wrappers; iov_iter_rs.o is that bookkeeping. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as iov_iter_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
iov_iter-y := iov_iter_glue.o iov_iter_rs.o
else
iov_iter-y := iov_iter_norust.o
endif
obj-y += iov_iter.o

# idr.o: idr_glue.o is upstream's file with the four IDA functions (ida_alloc_range, ida_find_first_range, ida_free, ida_destroy) replaced by
# thunks and rust_ida_* wrappers; idr_rs.o is those four. The IDR half stays C (it sits on radix-tree.c). CONFIG_RUST=n builds upstream's body,
# installed byte-identical as idr_norust.c by rig/apply.sh. (Moved from lib-y to obj-y so the composite is built the same way as its neighbours.)
ifdef CONFIG_RUST
idr-y := idr_glue.o idr_rs.o
else
idr-y := idr_norust.o
endif
obj-y += idr.o

# radix-tree.o: radix-tree_glue.o keeps the node cache and per-CPU preload, call_rcu freeing, the exports as thunks and the BUG/WARN wrappers; radix_tree_rs.o is the tree
# algorithms and idr_get_free()/idr_destroy(). CONFIG_RUST=n builds upstream's body, installed byte-identical as radix-tree_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
radix-tree-y := radix-tree_glue.o radix_tree_rs.o
else
radix-tree-y := radix-tree_norust.o
endif
obj-y += radix-tree.o

# klist.o: klist_glue.o keeps klist_init() (lockdep key per call site), klist_remove() (sleeps), the exports as thunks and rust_kl_* wrappers; klist_rs.o is the rest.
# CONFIG_RUST=n builds upstream's body, installed byte-identical as klist_norust.c by rig/apply.sh. (Moved from lib-y to obj-y so the composite is built like its neighbours.)
ifdef CONFIG_RUST
klist-y := klist_glue.o klist_rs.o
else
klist-y := klist_norust.o
endif
obj-y += klist.o

# kobject.o: kobject_glue.o keeps what takes `...`/va_list, kset_init(), the static kobj_types, the exports as thunks and the rust_ko_* wrappers; kobject_rs.o is the
# rest. CONFIG_RUST=n -- or CONFIG_DEBUG_KOBJECT=y, whose pr_debug sites the Rust arm does not carry -- builds upstream's body, installed byte-identical as
# kobject_norust.c by rig/apply.sh. (Moved from lib-y to obj-y so the composite is built like its neighbours.)
ifeq ($(CONFIG_RUST)$(CONFIG_DEBUG_KOBJECT),y)
kobject-y := kobject_glue.o kobject_rs.o
else
kobject-y := kobject_norust.o
endif
obj-y += kobject.o

# kobject_uevent.o: kobject_uevent_glue.o is upstream's file with the synthetic-uevent parser and zap_modalias_env() replaced by thunks, plus rust_ue_* wrappers;
# kobject_uevent_rs.o is those. CONFIG_RUST=n -- or CONFIG_DEBUG_KOBJECT=y -- builds upstream's body, installed byte-identical as kobject_uevent_norust.c by rig/apply.sh.
ifeq ($(CONFIG_RUST)$(CONFIG_DEBUG_KOBJECT),y)
kobject_uevent-y := kobject_uevent_glue.o kobject_uevent_rs.o
else
kobject_uevent-y := kobject_uevent_norust.o
endif
obj-y += kobject_uevent.o

# argv_split.o: argv_split_glue.o keeps the exports as thunks and the allocator wrappers; argv_split_rs.o is the splitting. CONFIG_RUST=n builds upstream's body, installed
# byte-identical as argv_split_norust.c by rig/apply.sh. (Moved from lib-y to obj-y so the composite is built like its neighbours.)
ifdef CONFIG_RUST
argv_split-y := argv_split_glue.o argv_split_rs.o
else
argv_split-y := argv_split_norust.o
endif
obj-y += argv_split.o

# logic_pio.o: logic_pio_glue.o keeps the exports as thunks, the BUILD_LOGIC_IO accessors and the rust_lp_* wrappers; logic_pio_rs.o is the registry and the
# translations. CONFIG_RUST=n builds upstream's body, installed byte-identical as logic_pio_norust.c by rig/apply.sh. (Moved from lib-y to obj-y.)
ifdef CONFIG_RUST
logic_pio-y := logic_pio_glue.o logic_pio_rs.o
else
logic_pio-y := logic_pio_norust.o
endif
obj-y += logic_pio.o

# memcat_p.o: memcat_p_glue.o keeps the export as a thunk and the kmalloc_array() wrapper; memcat_p_rs.o is the merge. CONFIG_RUST=n builds upstream's body, installed
# byte-identical as memcat_p_norust.c by rig/apply.sh. (Moved from lib-y to obj-y.)
ifdef CONFIG_RUST
memcat_p-y := memcat_p_glue.o memcat_p_rs.o
else
memcat_p-y := memcat_p_norust.o
endif
obj-y += memcat_p.o

# dec_and_lock.o: dec_and_lock_glue.o keeps the four exports as thunks and the lock wrappers; dec_and_lock_rs.o is the decrement/lock logic. CONFIG_RUST=n builds upstream's
# body, installed byte-identical as dec_and_lock_norust.c by rig/apply.sh. (Moved from lib-y to obj-y.)
ifdef CONFIG_RUST
dec_and_lock-y := dec_and_lock_glue.o dec_and_lock_rs.o
else
dec_and_lock-y := dec_and_lock_norust.o
endif
obj-y += dec_and_lock.o

# rcuref.o: rcuref_glue.o keeps the two exports as thunks and the WARN_ONCE sites; rcuref_rs.o is the two slow paths. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as rcuref_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
rcuref-y := rcuref_glue.o rcuref_rs.o
else
rcuref-y := rcuref_norust.o
endif
obj-y += rcuref.o

# sbitmap.o: sbitmap_glue.o keeps init, the seq_file output, the wait-queue plumbing, the exports as thunks and the one-line wrappers; sbitmap_rs.o is the
# algorithms. CONFIG_RUST=n builds upstream's body, installed byte-identical as sbitmap_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
sbitmap-y := sbitmap_glue.o sbitmap_rs.o
else
sbitmap-y := sbitmap_norust.o
endif

# refcount.o: refcount_glue.o keeps the exports as thunks, the lock-taking dec_and_lock* functions and the WARN_ONCE sites; refcount_rs.o is warn_saturate,
# dec_if_one and dec_not_one. CONFIG_RUST=n builds upstream's body, installed byte-identical as refcount_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
refcount-y := refcount_glue.o refcount_rs.o
else
refcount-y := refcount_norust.o
endif

# lwq.o: lwq_glue.o keeps the exports as thunks, the lock calls and the CONFIG_LWQ_TEST module; lwq_rs.o is the two dequeue functions. CONFIG_RUST=n
# builds upstream's body, installed byte-identical as lwq_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
lwq-y := lwq_glue.o lwq_rs.o
else
lwq-y := lwq_norust.o
endif

# bch.o: bch_glue.o keeps the four exports as thunks, kmalloc/kzalloc/kfree and the WARN site; bch_rs.o is everything else. CONFIG_RUST=n and
# CONFIG_BCH_CONST_PARAMS (fixed m and t compiled in, which the Rust does not model) build upstream's body, installed byte-identical as bch_norust.c by
# rig/apply.sh.
ifeq ($(CONFIG_RUST)$(CONFIG_BCH_CONST_PARAMS),y)
bch-y := bch_glue.o bch_rs.o
else
bch-y := bch_norust.o
endif

# bootconfig.o: bootconfig_glue.o keeps the state, the memblock allocation, the exports as __init thunks and the two snprintf users; bootconfig_rs.o is the parser,
# tree builder, verifier, init/exit and the node accessors and finders (all in .init.text). CONFIG_RUST=n builds upstream's body, installed byte-identical as
# bootconfig_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
bootconfig-y := bootconfig_glue.o bootconfig_rs.o
else
bootconfig-y := bootconfig_norust.o
endif

# percpu-refcount.o: percpu-refcount_glue.o keeps the exports as thunks, the global lock / wait queue and the rust_prw_* wrappers; percpu_refcount_rs.o is the state
# machine. CONFIG_RUST=n builds upstream's body, installed byte-identical as percpu-refcount_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
percpu-refcount-y := percpu-refcount_glue.o percpu_refcount_rs.o
else
percpu-refcount-y := percpu-refcount_norust.o
endif
