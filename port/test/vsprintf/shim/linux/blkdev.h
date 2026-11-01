/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_BLKDEV_H
#define _SHIM_VSPRINTF_LINUX_BLKDEV_H
/* %pg (bdev_name) is deferred -- unexercised by this harness's corpus. */
struct gendisk {
	char disk_name[32];
};
struct block_device {
	struct gendisk *bd_disk;
};
static inline bool bdev_is_partition(const struct block_device *bdev) { return false; }
static inline int bdev_partno(const struct block_device *bdev) { return 0; }
#endif
