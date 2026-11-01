# SPDX-License-Identifier: GPL-2.0-only
#
# This is a modified version of zlib, which does all memory
# allocation ahead of time.
#
# This is the compression code, see zlib_inflate for the
# decompression code.
#

obj-$(CONFIG_ZLIB_DEFLATE) += zlib_deflate.o

# deftree.o IS GONE, not renamed -- the lib/union_find shape, the same one
# lib/zstd/decompress/huf_decompress.o and zstd_decompress_block.o took. nm
# on the pristine .c says none of deftree.c's six globals
# (zlib_tr_init/_tally/_flush_block/_align/_stored_block/_stored_type_only)
# is EXPORT_SYMBOL'd -- deflate_syms.c's six EXPORT_SYMBOLs all belong to
# deflate.c's own functions, not deftree.c's -- so deftree_rs.rs defines all
# six directly under their own names, and deflate.c (unmodified, still C)
# calls straight into the Rust with no thunk.
#
# deflate.c IS GONE from the CONFIG_RUST=y list as well: deflate_rs.rs is the
# compressor, and deflate_glue.c keeps the six EXPORT_SYMBOL'd C entry
# definitions (their MODVERSIONS CRCs come from the DWARF of the definition;
# deflate_syms.c is untouched) -- the lib/zlib_inflate/inflate_thunk.c shape.
#
# CONFIG_RUST=n falls back to the pristine deflate.c and deftree.c below, byte-identical
# to the tarball -- same convention lib/zstd/Makefile uses and explains at
# length: the upstream file stays exactly as the tarball has it, and the
# Makefile is the only thing that chooses.
ifdef CONFIG_RUST
zlib_deflate-objs := deflate_glue.o deflate_rs.o deftree_rs.o deflate_syms.o
else
zlib_deflate-objs := deflate.o deftree.o deflate_syms.o
endif
