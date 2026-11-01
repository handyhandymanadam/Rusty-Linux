# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-$(CONFIG_BLOCK) += core.o
obj-$(CONFIG_ACORN_PARTITION) += acorn.o
obj-$(CONFIG_AMIGA_PARTITION) += amiga.o
obj-$(CONFIG_ATARI_PARTITION) += atari.o
obj-$(CONFIG_AIX_PARTITION) += aix.o
obj-$(CONFIG_CMDLINE_PARTITION) += cmdline.o
obj-$(CONFIG_MAC_PARTITION) += mac.o
obj-$(CONFIG_LDM_PARTITION) += ldm.o
obj-$(CONFIG_MSDOS_PARTITION) += msdos.o
obj-$(CONFIG_OF_PARTITION) += of.o
obj-$(CONFIG_OSF_PARTITION) += osf.o
obj-$(CONFIG_SGI_PARTITION) += sgi.o
obj-$(CONFIG_SUN_PARTITION) += sun.o
obj-$(CONFIG_ULTRIX_PARTITION) += ultrix.o
obj-$(CONFIG_IBM_PARTITION) += ibm.o
# efi.o is a composite under CONFIG_RUST: efi_glue.o is upstream's efi.c with the pure checks calling efi_rs.o; CONFIG_RUST=n builds upstream's body, installed byte-identical as
# efi_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
efi-y := efi_glue.o efi_rs.o
else
efi-y := efi_norust.o
endif
obj-$(CONFIG_EFI_PARTITION) += efi.o
obj-$(CONFIG_KARMA_PARTITION) += karma.o
obj-$(CONFIG_SYSV68_PARTITION) += sysv68.o
