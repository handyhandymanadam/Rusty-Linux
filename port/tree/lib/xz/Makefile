# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_XZ_DEC) += xz_dec.o
# xz_dec_stream.c IS a thunk file. xz_dec_{init,run,reset,end} are
# EXPORT_SYMBOL'd from xz_dec_syms.c, so under CONFIG_GENDWARFKSYMS their
# MODVERSIONS CRCs come from the DWARF of the C definitions and must stay C.
# The bodies are in xz_dec_stream_rs.rs. See lib/xz/xz_dec_stream.c.
xz_dec-y := xz_dec_syms.o

# xz_dec_bcj.c is NOT a thunk. None of xz_dec_bcj_{run,reset,create} is
# EXPORT_SYMBOL'd, so none has a MODVERSIONS CRC and GOALS.md §1's entry-thunk
# constraint does not reach them: xz_dec_stream.c links straight to the Rust,
# the lib/union_find shape.
#
# What is left in the C is the pre-boot body behind #ifdef STATIC, which
# lib/decompress_unxz.c textually #includes, and xz_dec_bcj_create() -- an
# allocation whose other half is already C (xz_private.h defines
# xz_dec_bcj_end(s) as kfree(s)). See lib/xz/xz_dec_bcj_rs.rs.

obj-$(CONFIG_XZ_DEC_TEST) += xz_dec_test.o

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
xz_dec-y                    += xz_dec_stream.o xz_dec_stream_rs.o \
                               xz_dec_lzma2.o xz_dec_lzma2_rs.o
xz_dec-$(CONFIG_XZ_DEC_BCJ) += xz_dec_bcj.o xz_dec_bcj_rs.o
else
xz_dec-y                    += xz_dec_stream_norust.o xz_dec_lzma2_norust.o
xz_dec-$(CONFIG_XZ_DEC_BCJ) += xz_dec_bcj_norust.o
endif
