# SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
# ################################################################
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.
# ################################################################
obj-$(CONFIG_ZSTD_COMPRESS) += zstd_compress.o
obj-$(CONFIG_ZSTD_DECOMPRESS) += zstd_decompress.o
obj-$(CONFIG_ZSTD_COMMON) += zstd_common.o

zstd_compress-y := \
		zstd_compress_module.o \
		compress/fse_compress.o \
		compress/hist.o \
		compress/huf_compress.o \
		compress/zstd_compress.o \
		compress/zstd_compress_literals.o \
		compress/zstd_compress_sequences.o \
		compress/zstd_compress_superblock.o \
		compress/zstd_double_fast.o \
		compress/zstd_fast.o \
		compress/zstd_lazy.o \
		compress/zstd_ldm.o \
		compress/zstd_opt.o \
		compress/zstd_preSplit.o \

# decompress/huf_decompress.o IS GONE, not renamed -- the lib/union_find shape,
# the same one common/fse_decompress.c took. huf_decompress.c defined NINE
# globals and nm says NOT ONE of them is EXPORT_SYMBOL'd, so none carries a
# MODVERSIONS CRC and GOALS.md §1's entry-thunk constraint does not reach any of
# them. decompress/huf_decompress_rs.rs defines all nine directly under their
# own names:
#
#   HUF_decompress1X1_DCtx_wksp    <- zstd_decompress_block.o
#   HUF_decompress1X_usingDTable   <- zstd_decompress_block.o
#   HUF_decompress4X_hufOnly_wksp  <- zstd_decompress_block.o
#   HUF_decompress4X_usingDTable   <- zstd_decompress_block.o
#   HUF_readDTableX2_wksp          <- zstd_decompress.o
#   HUF_readDTableX1_wksp, HUF_decompress1X2_DCtx_wksp,
#   HUF_decompress1X_DCtx_wksp, HUF_selectDecoder  <- nothing, kernel-wide
#
# There is no C left to compile. The .c file is kept in the tree as a signpost
# only. Contrast common/entropy_common.c, which HAS to stay because
# zstd_common_module.c exports its three symbols.
#
# ZSTD_ENABLE_ASM_X86_64_BMI2 is a hard `#define 0` in
# common/portability_macros.h, so the hand-written assembly decoder loops were
# never compiled into this kernel and are NOT ported. The C fast loops are.
# DYNAMIC_BMI2 is 1 on x86-64, so the _bmi2 bodies are real; the port keeps that
# axis with #[target_feature(enable = "lzcnt,bmi1,bmi2")] wrappers over
# #[inline(always)] bodies, verified by disassembly (lzcnt/tzcnt/shlx/shrx in
# every _bmi2 and _fast body, bsr in every default body).
#
# ONE INTERNAL FFI WALL REMAINS, deliberately: huf_decompress_rs.rs still calls
# the C symbol HUF_readStats_wksp, i.e. the thunk in common/entropy_common.c
# whose body is already Rust (rust_HUF_readStats_wksp in
# common/entropy_common_rs.rs). The thunk exists only to carry the exported
# symbol's DWARF for GENDWARFKSYMS; a later change can point the call at the
# Rust body directly and erase the crossing without touching the thunk.
#
# decompress/zstd_decompress_block.o IS GONE, not renamed -- same lib/union_find
# shape as huf_decompress.o just above: nm on the pristine .c says zero
# EXPORT_SYMBOL, so none of its globals carries a MODVERSIONS CRC and none needs
# a thunk. decompress/zstd_decompress_block_rs.rs defines all five under their
# own names (ZSTD_decompressBlock_internal, ZSTD_checkContinuity,
# ZSTD_buildFSETable, ZSTD_getcBlockSize, ZSTD_decodeSeqHeaders <- all called
# from zstd_decompress.o), and calls back into huf_decompress_rs.rs's own
# HUF_decompress1X1_DCtx_wksp/HUF_decompress1X_usingDTable/
# HUF_decompress4X_hufOnly_wksp/HUF_decompress4X_usingDTable directly -- one
# more internal FFI wall erased, per the zstd Makefile's own convention above.
#
# decompress/zstd_ddict.o IS GONE, not renamed -- same lib/union_find shape as
# every other file in this directory: nm on the pristine .c says zero
# EXPORT_SYMBOL. decompress/zstd_ddict_rs.rs defines all nine of its C-callable
# functions under their own names (ZSTD_DDict_dictContent, ZSTD_DDict_dictSize,
# ZSTD_copyDDictParameters, ZSTD_createDDict[_advanced/_byReference],
# ZSTD_initStaticDDict, ZSTD_freeDDict, ZSTD_estimateDDictSize,
# ZSTD_sizeof_DDict, ZSTD_getDictID_fromDDict), all called from
# zstd_decompress.o (ZSTD_createDDict_advanced/ZSTD_freeDDict also directly
# from zstd_decompress_module.o), and calls back the other way into
# ZSTD_loadDEntropy -- currently zstd_decompress.c's, C either way for now,
# resolving to its Rust body with no thunk whenever that file's own port
# lands, same as every other cross-file call in this subsystem.
#
# zstd_decompress.c is still C and unported (in progress elsewhere).
# CONFIG_RUST=n falls back to the pristine decompress/huf_decompress.c,
# decompress/zstd_decompress_block.c and decompress/zstd_ddict.c, all
# byte-identical to the tarball -- see the note on RAISE 2 below.
ifdef CONFIG_RUST
zstd_decompress-y := \
		zstd_decompress_module.o \
		decompress/huf_decompress_rs.o \
		decompress/zstd_ddict_rs.o \
		decompress/zstd_decompress.o \
		decompress/zstd_decompress_block_rs.o \

else
zstd_decompress-y := \
		zstd_decompress_module.o \
		decompress/huf_decompress.o \
		decompress/zstd_ddict.o \
		decompress/zstd_decompress.o \
		decompress/zstd_decompress_block.o \

endif

# ---------------------------------------------------------------------------
# CONFIG_RUST=n, and why the upstream .c files here are byte-identical to the
# tarball.
#
# logs/floor.md RAISE 2: every architecture the kernel supports must still
# build whether or not it can compile Rust. Six architectures `select
# HAVE_RUST`; the rest are forced to CONFIG_RUST=n, and so is any x86_64 user
# who simply turns it off. Adam ruled the fix on 2026-09-03: a per-module C
# fallback.
#
# THE OBSTACLE THAT RULING DID NOT ANTICIPATE. The fallback compiles the
# ORIGINAL C -- but the thunk-shaped ports had overwritten it. entropy_common.c
# went from 341 lines to 101, and fse_decompress.c's 316-line body was replaced
# by a signpost. There was nothing left to fall back TO. (lib/xz and
# lib/zlib_inflate escaped this only by luck: their C bodies survive behind
# `#ifdef STATIC` because the boot decompressor textually includes them.)
#
# So the arrangement here inverts the convention: the upstream file stays
# EXACTLY as the tarball has it, and the port ADDS a *_thunk.c beside it. The
# Makefile is the only thing that chooses. That buys three things a
# `#ifndef CONFIG_RUST` block inside each file would not:
#
#   - the C arm cannot drift from upstream, because it IS upstream, byte for
#     byte, and rig/apply.sh compares the sha256 it reads back;
#   - the diff against the tarball shrinks to added files plus a Makefile;
#   - neither arm is cluttered with the other's preprocessor.
#
# It is a change of convention from lib/xz and lib/zlib_inflate, which put
# their thunks in the original file. Those had no choice. This is Adam's call
# to generalise or not; lib/zstd is the worked example.
#
# WITH RUST: common/entropy_common_thunk.c and common/zstd_common_thunk.c are
# the mandatory entry thunks. FSE_readNCount, HUF_readStats and
# HUF_readStats_wksp (zstd_common_module.c:21-23) and ZSTD_isError,
# ZSTD_getErrorName and ZSTD_getErrorCode (:24-26) are EXPORT_SYMBOL_GPL'd, so
# under CONFIG_GENDWARFKSYMS their MODVERSIONS CRCs come from the DWARF of the
# definition and the definitions must stay C. The bodies are the rust_*
# functions in the _rs.rs files.
#
# common/fse_decompress.c and common/error_private.c have NO Rust-arm object at
# all: nothing they define is exported, so entropy_common_rs.rs and
# error_private_rs.rs define those symbols directly under their own names --
# the lib/union_find shape. The two .c files are compiled only in the C arm.
#
# The two ported files are ONE Rust object each, and entropy_common_rs.rs holds
# BOTH entropy_common.c and fse_decompress.c on purpose: as C they were
# mutually recursive across the TU boundary -- entropy_common.o called
# FSE_decompress_wksp_bmi2, fse_decompress.o called FSE_readNCount_bmi2 -- and
# one crate erases both internal FFI walls at once. That is what GOALS.md §1
# measures.
#
# common/debug.o is in BOTH arms and is still C in both, deliberately. At
# DEBUGLEVEL 0 -- what the kernel builds -- the whole file is #if'd out and the
# object carries zero bytes of text, data and bss. There is nothing to port.
ifdef CONFIG_RUST
zstd_common-y := \
		zstd_common_module.o \
		common/debug.o \
		common/entropy_common_thunk.o \
		common/entropy_common_rs.o \
		common/error_private_rs.o \
		common/zstd_common_thunk.o \
		common/zstd_common_rs.o \

else
zstd_common-y := \
		zstd_common_module.o \
		common/debug.o \
		common/entropy_common.o \
		common/error_private.o \
		common/fse_decompress.o \
		common/zstd_common.o \

endif
