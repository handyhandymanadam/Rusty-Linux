# SPDX-License-Identifier: GPL-2.0-only
#
# This is a modified version of zlib, which does all memory
# allocation ahead of time.
#
# This is only the decompression, see zlib_deflate for the
# the compression
#
# Decompression needs to be serialized for each memory
# allocation.
#
# (The upsides of the simplification is that you can't get in
# any nasty situations wrt memory management, and that the
# uncompression can be done without blocking on allocation).
#

obj-$(CONFIG_ZLIB_INFLATE) += zlib_inflate.o

# ---------------------------------------------------------------------------
# CONFIG_RUST=n, and why inflate.c here is the upstream body again.
#
# logs/floor.md RAISE 2, ruled by Adam 2026-09-04. Six architectures select
# HAVE_RUST; every other one is forced to CONFIG_RUST=n, and so is any x86_64
# user who turns it off. Without the arms below this directory does not build
# at all there.
#
# THE OBSTACLE, and this directory is where it bites hardest. The fallback has
# to compile the ORIGINAL C -- and the thunk-shaped ports had overwritten it.
# inflate.c used to carry the upstream body behind `#ifdef STATIC` and the
# thunks behind `#else`, so the arm obj-y compiles had no body to fall back to.
# The arrangement Adam ruled: the upstream file goes back to the upstream body,
# and the port ADDS inflate_thunk.c beside it. One file now serves both the
# pre-boot textual include and the C-only build, and this Makefile is the only
# thing that chooses.
#
# inflate.c is NOT byte-identical to the tarball, and that is the one exception
# in the tree: it carries the `copy > whave` hunk from upstream/zlib-inflate-oob/
# (Adam's call, 2026-09-03). Its header says so. Everything else here --
# inffast.c, inftrees.c -- IS byte-identical, checked by sha256 against
# port/pristine/.
#
# WITH RUST. inffast.o and inftrees.o are GONE, not wrapped: inflate_fast() and
# zlib_inflate_table() are global but not EXPORT_SYMBOL'd, so neither carries a
# MODVERSIONS CRC and GOALS.md §1's entry-thunk constraint does not reach them.
# Their only caller, zlib_inflate(), links straight to the Rust -- the
# lib/union_find shape.
#
# inflate_thunk.o holds the six entry points that ARE EXPORT_SYMBOL'd
# (inflate_syms.c), whose CRCs come from the DWARF of the definition. Two of
# the six are not thunks at all: zlib_inflate_workspacesize() and
# zlib_inflateInit2() need struct inflate_workspace's layout, which under
# CONFIG_ZLIB_DFLTCC depends on PAGE_SIZE.
#
# NEITHER ARM DELETES A FILE FROM THE TREE, and that is not an oversight:
# lib/decompress_inflate.c textually #includes inftrees.c, inffast.c and
# inflate.c under #ifdef STATIC, and both of this project's configs set
# CONFIG_KERNEL_GZIP, so those copies ARE compiled -- into
# arch/x86/boot/compressed/misc.o -- in BOTH arms. Dropping a file from a
# Makefile does not delete it. The kernel image is decompressed by the C; the
# initramfs and everything after it by the Rust.
#
# What is left as C in the Rust arm: inflate_syms.c (a list of EXPORT_SYMBOL
# lines), infutil.c (which kmallocs), and those two layout-bound functions.
ifdef CONFIG_RUST
zlib_inflate-objs := inffast_rs.o inflate_thunk.o inflate_rs.o infutil.o \
		     inftrees_rs.o inflate_syms.o
else
zlib_inflate-objs := inffast.o inflate.o infutil.o \
		     inftrees.o inflate_syms.o
endif
