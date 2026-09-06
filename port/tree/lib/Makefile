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
KCOV_INSTRUMENT_string.o := n
KCOV_INSTRUMENT_rbtree.o := n
KCOV_INSTRUMENT_list_debug.o := n
KCOV_INSTRUMENT_debugobjects.o := n
KCOV_INSTRUMENT_dynamic_debug.o := n
KCOV_INSTRUMENT_fault-inject.o := n
KCOV_INSTRUMENT_find_bit.o := n

# string.o implements standard library functions like memset/memcpy etc.
# Use -ffreestanding to ensure that the compiler does not try to "optimize"
# them into calls to themselves.
CFLAGS_string.o := -ffreestanding

# Early boot use of cmdline, don't instrument it
ifdef CONFIG_AMD_MEM_ENCRYPT
KASAN_SANITIZE_string.o := n

CFLAGS_string.o += -fno-stack-protector
endif

# ctype.o is gone: the Rust defines and exports _ctype itself and carries its
# ABI contract, via kernel::kabi_export!(). See the CONFIG_RUST arms below.
lib-y := string.o vsprintf.o \
	 rbtree.o radix-tree.o xarray.o \
	 maple_tree.o idr.o irq_regs.o argv_split.o \
	 is_single_threaded.o kobject_uevent.o \
	 dec_and_lock.o \
	 nmi_backtrace.o memcat_p.o \
	 objpool.o iomem_copy.o

lib-$(CONFIG_PRINTK) += dump_stack.o
lib-$(CONFIG_SMP) += cpumask.o
lib-$(CONFIG_MIN_HEAP) += min_heap.o

lib-y	+= kobject.o klist.o
obj-y	+= lockref.o

obj-y += parser.o random32.o \
	 kasprintf.o bitmap.o scatterlist.o \
	 iov_iter.o \
	 lwq.o kfifo.o \
	 percpu-refcount.o rhashtable.o \
	 once.o refcount.o rcuref.o bucket_locks.o \
	 bitmap-str.o
# usercopy.o is gone from here: retained-C-entry-plus-Rust-body split, same
# shape as strncpy_from_user.o/strnlen_user.o. See the CONFIG_RUST arms below.
# find_bit.o is gone: the Rust defines and exports its 17 symbols itself
# and carries their ABI contracts. See the CONFIG_RUST arms below.
obj-y += string_helpers.o
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

lib-y += logic_pio.o

lib-$(CONFIG_INDIRECT_IOMEM) += logic_iomem.o

obj-$(CONFIG_TRACE_MMIO_ACCESS) += trace_readwrite.o

obj-$(CONFIG_GENERIC_HWEIGHT) += hweight.o

obj-$(CONFIG_BTREE) += btree.o
# interval_tree.o is gone: the Rust defines and exports its 7 symbols
# itself and carries their ABI contracts. See the CONFIG_RUST arms below.
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

obj-$(CONFIG_NLATTR) += nlattr.o

obj-$(CONFIG_LRU_CACHE) += lru_cache.o

obj-$(CONFIG_GENERIC_CSUM) += checksum.o

obj-$(CONFIG_GENERIC_ATOMIC64) += atomic64.o

obj-$(CONFIG_ATOMIC64_SELFTEST) += atomic64_test.o

obj-$(CONFIG_CPU_RMAP) += cpu_rmap.o

obj-$(CONFIG_CLOSURES) += closure.o

# dynamic_queue_limits.o is the BUG_ON/tracepoint thunk only under
# CONFIG_RUST -- the algorithm is in dynamic_queue_limits_rs.o. See the
# CONFIG_RUST arms below.

obj-$(CONFIG_GLOB_SELFTEST) += globtest.o
obj-$(CONFIG_LIB_SELFTEST) += libtest.o

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
obj-$(CONFIG_STACKDEPOT) += stackdepot.o
KASAN_SANITIZE_stackdepot.o := n
# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
# recursion.
KMSAN_SANITIZE_stackdepot.o := n
KCOV_INSTRUMENT_stackdepot.o := n

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

obj-y += group_cpus.o

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
lib-y                            += timerqueue_rs.o
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
lib-y                            += timerqueue_norust.o
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
lib-y                            += seq_buf_norust.o
obj-$(CONFIG_GENERIC_IOMAP)      += iomap_norust.o
lib-$(CONFIG_GENERIC_BUG)        += bug_norust.o

endif
# ---------------------------------------------------------------------------
