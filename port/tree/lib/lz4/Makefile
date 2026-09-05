# SPDX-License-Identifier: GPL-2.0-only
ccflags-y += -O3

obj-$(CONFIG_LZ4_COMPRESS) += lz4_compress.o
obj-$(CONFIG_LZ4HC_COMPRESS) += lz4hc_compress.o

# lz4_decompress.c IS NOT COMPILED HERE ANY MORE, and it is not edited either.
# The eight entry points are EXPORT_SYMBOL'd, so GOALS.md §1 requires C entry
# symbols; they live in lz4_decompress_thunk.c and the bodies are Rust. The
# thunks cannot go in lz4_decompress.c because kbuild will not build a
# composite object whose name matches one of its members, and renaming the
# module would change what modprobe(8) is asked for.
#
# So lib/lz4/lz4_decompress.c stays byte-for-byte upstream's, compiled only by
# lib/decompress_unlz4.c's textual #include for the pre-boot decompressor --
# which means, unlike lib/lzo's and lib/xz's retained bodies, it CANNOT drift
# from what upstream ships. Neither of this project's configs sets
# CONFIG_KERNEL_LZ4, so nothing here compiles it. See logs/build-limits.md.
obj-$(CONFIG_LZ4_DECOMPRESS) += lz4_decompress.o

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
lz4_decompress-objs := lz4_decompress_rs.o
else
lz4_decompress-objs := lz4_decompress_norust.o
endif
