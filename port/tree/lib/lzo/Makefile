# SPDX-License-Identifier: GPL-2.0-only
lzo_compress-objs := lzo1x_compress.o lzo1x_compress_safe.o

# lzo1x_decompress_safe.c keeps its EXPORT_SYMBOL_GPL'd entry symbol -- it has
# a MODVERSIONS CRC, so GOALS.md §1's constraint binds and the C cannot go.
# It also still holds the original body behind #ifdef STATIC, for the pre-boot
# decompressor that lib/decompress_unlzo.c builds. See the comment there.

obj-$(CONFIG_LZO_COMPRESS) += lzo_compress.o
obj-$(CONFIG_LZO_DECOMPRESS) += lzo_decompress.o

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
lzo_decompress-objs := lzo1x_decompress_safe.o lzo1x_decompress_safe_rs.o
else
lzo_decompress-objs := lzo1x_decompress_safe_norust.o
endif
