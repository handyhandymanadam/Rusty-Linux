# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ext4-filesystem routines.
#

obj-$(CONFIG_EXT4_FS) += ext4.o

# hash.o is a composite under CONFIG_RUST: hash_glue.o is upstream's hash.c without the hash algorithms, hash_rs.o holds them. CONFIG_RUST=n builds upstream's body,
# installed byte-identical as hash_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
ext4-hash := hash_glue.o hash_rs.o
else
ext4-hash := hash_norust.o
endif


ext4-y	:= balloc.o bitmap.o block_validity.o dir.o ext4_jbd2.o extents.o \
		extents_status.o file.o fsmap.o fsync.o $(ext4-hash) ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_hurd.o xattr_trusted.o \
		xattr_user.o fast_commit.o orphan.o

ext4-$(CONFIG_EXT4_FS_POSIX_ACL)	+= acl.o
ext4-$(CONFIG_EXT4_FS_SECURITY)		+= xattr_security.o
ext4-inode-test-objs			+= inode-test.o
obj-$(CONFIG_EXT4_KUNIT_TESTS)		+= ext4-inode-test.o
ext4-$(CONFIG_FS_VERITY)		+= verity.o
ext4-$(CONFIG_FS_ENCRYPTION)		+= crypto.o
