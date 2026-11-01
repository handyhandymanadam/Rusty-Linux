// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RUST PORT (block/partitions/efi.c, 6.18.49): the pure checks (protective MBR, GPT header checks, is_pte_valid, compare_gpts, the label conversion) are in efi_rs.rs; this file keeps all
 * reading of the disk and the partition table walk. Upstream's whole file is installed as efi_norust.c for CONFIG_RUST=n.
 */
/************************************************************
 * EFI GUID Partition Table handling
 *
 * http://www.uefi.org/specs/
 * http://www.intel.com/technology/efi/
 *
 * efi.[ch] by Matt Domsch <Matt_Domsch@dell.com>
 *   Copyright 2000,2001,2002,2004 Dell Inc.
 *
 * TODO:
 *
 * Changelog:
 * Mon August 5th, 2013 Davidlohr Bueso <davidlohr@hp.com>
 * - detect hybrid MBRs, tighter pMBR checking & cleanups.
 *
 * Mon Nov 09 2004 Matt Domsch <Matt_Domsch@dell.com>
 * - test for valid PMBR and valid PGPT before ever reading
 *   AGPT, allow override with 'gpt' kernel command line option.
 * - check for first/last_usable_lba outside of size of disk
 *
 * Tue  Mar 26 2002 Matt Domsch <Matt_Domsch@dell.com>
 * - Ported to 2.5.7-pre1 and 2.5.7-dj2
 * - Applied patch to avoid fault in alternate header handling
 * - cleaned up find_valid_gpt
 * - On-disk structure and copy in memory is *always* LE now - 
 *   swab fields as needed
 * - remove print_gpt_header()
 * - only use first max_p partition entries, to keep the kernel minor number
 *   and partition numbers tied.
 *
 * Mon  Feb 04 2002 Matt Domsch <Matt_Domsch@dell.com>
 * - Removed __PRIPTR_PREFIX - not being used
 *
 * Mon  Jan 14 2002 Matt Domsch <Matt_Domsch@dell.com>
 * - Ported to 2.5.2-pre11 + library crc32 patch Linus applied
 *
 * Thu Dec 6 2001 Matt Domsch <Matt_Domsch@dell.com>
 * - Added compare_gpts().
 * - moved le_efi_guid_to_cpus() back into this file.  GPT is the only
 *   thing that keeps EFI GUIDs on disk.
 * - Changed gpt structure names and members to be simpler and more Linux-like.
 * 
 * Wed Oct 17 2001 Matt Domsch <Matt_Domsch@dell.com>
 * - Removed CONFIG_DEVFS_VOLUMES_UUID code entirely per Martin Wilck
 *
 * Wed Oct 10 2001 Matt Domsch <Matt_Domsch@dell.com>
 * - Changed function comments to DocBook style per Andreas Dilger suggestion.
 *
 * Mon Oct 08 2001 Matt Domsch <Matt_Domsch@dell.com>
 * - Change read_lba() to use the page cache per Al Viro's work.
 * - print u64s properly on all architectures
 * - fixed debug_printk(), now Dprintk()
 *
 * Mon Oct 01 2001 Matt Domsch <Matt_Domsch@dell.com>
 * - Style cleanups
 * - made most functions static
 * - Endianness addition
 * - remove test for second alternate header, as it's not per spec,
 *   and is unnecessary.  There's now a method to read/write the last
 *   sector of an odd-sized disk from user space.  No tools have ever
 *   been released which used this code, so it's effectively dead.
 * - Per Asit Mallick of Intel, added a test for a valid PMBR.
 * - Added kernel command line option 'gpt' to override valid PMBR test.
 *
 * Wed Jun  6 2001 Martin Wilck <Martin.Wilck@Fujitsu-Siemens.com>
 * - added devfs volume UUID support (/dev/volumes/uuids) for
 *   mounting file systems by the partition GUID. 
 *
 * Tue Dec  5 2000 Matt Domsch <Matt_Domsch@dell.com>
 * - Moved crc32() to linux/lib, added efi_crc32().
 *
 * Thu Nov 30 2000 Matt Domsch <Matt_Domsch@dell.com>
 * - Replaced Intel's CRC32 function with an equivalent
 *   non-license-restricted version.
 *
 * Wed Oct 25 2000 Matt Domsch <Matt_Domsch@dell.com>
 * - Fixed the last_lba() call to return the proper last block
 *
 * Thu Oct 12 2000 Matt Domsch <Matt_Domsch@dell.com>
 * - Thanks to Andries Brouwer for his debugging assistance.
 * - Code works, detects all the partitions.
 *
 ************************************************************/
#include <linux/kernel.h>
#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include "check.h"
#include "efi.h"

/* This allows a kernel command line option 'gpt' to override
 * the test for invalid PMBR.  Not __initdata because reloading
 * the partition tables happens after init too.
 */
static int force_gpt;
static int __init
force_gpt_fn(char *str)
{
	force_gpt = 1;
	return 1;
}
__setup("gpt", force_gpt_fn);


/**
 * efi_crc32() - EFI version of crc32 function
 * @buf: buffer to calculate crc32 of
 * @len: length of buf
 *
 * Description: Returns EFI-style CRC32 value for @buf
 * 
 * This function uses the little endian Ethernet polynomial
 * but seeds the function with ~0, and xor's with ~0 at the end.
 * Note, the EFI Specification, v1.02, has a reference to
 * Dr. Dobbs Journal, May 1994 (actually it's in May 1992).
 */
static inline u32
efi_crc32(const void *buf, unsigned long len)
{
	return (crc32(~0L, buf, len) ^ ~0L);
}

/**
 * last_lba(): return number of last logical block of device
 * @disk: block device
 * 
 * Description: Returns last LBA value on success, 0 on error.
 * This is stored (by sd and ide-geometry) in
 *  the part[0] entry for this disk, and is the number of
 *  physical sectors available on the disk.
 */
static u64 last_lba(struct gendisk *disk)
{
	return div_u64(bdev_nr_bytes(disk->part0),
		       queue_logical_block_size(disk->queue)) - 1ULL;
}

/* RUST-WRAPPERS BEGIN: the pure checks are in efi_rs.rs; the functions below are thin calls into it. */
int rust_efi_is_pmbr_valid(const u8 *mbr);
int rust_efi_gpt_header_check(u8 *gpt, u64 lba, u64 lastlba, u32 ssz);
int rust_efi_is_pte_valid(const u8 *pte, u64 lastlba);
int rust_efi_compare_gpts(const u8 *pgpt, const u8 *agpt, u64 lastlba);
void rust_efi_utf16_le_to_7bit(const u16 *in, u32 size, u8 *out);
u32 rust_efi_crc32(const void *buf, u32 len);
void rust_efi_warn(int which, u64 a, u64 b);

/* efi_rs.rs hard-codes these layouts. */
static_assert(sizeof(gpt_header) == 92 && offsetof(gpt_header, signature) == 0 && offsetof(gpt_header, header_size) == 12 && offsetof(gpt_header, header_crc32) == 16 &&
	      offsetof(gpt_header, my_lba) == 24 && offsetof(gpt_header, alternate_lba) == 32 && offsetof(gpt_header, first_usable_lba) == 40 && offsetof(gpt_header, last_usable_lba) == 48 &&
	      offsetof(gpt_header, disk_guid) == 56 && offsetof(gpt_header, num_partition_entries) == 80 && offsetof(gpt_header, sizeof_partition_entry) == 84 &&
	      offsetof(gpt_header, partition_entry_array_crc32) == 88);
static_assert(sizeof(gpt_entry) == 128 && offsetof(gpt_entry, partition_type_guid) == 0 && offsetof(gpt_entry, starting_lba) == 32 && offsetof(gpt_entry, ending_lba) == 40);
static_assert(sizeof(gpt_mbr_record) == 16 && offsetof(gpt_mbr_record, os_type) == 4 && offsetof(gpt_mbr_record, starting_lba) == 8 && offsetof(legacy_mbr, partition_record) == 446 &&
	      offsetof(legacy_mbr, signature) == 510);
static_assert(GPT_HEADER_SIGNATURE == 0x5452415020494645ULL && MSDOS_MBR_SIGNATURE == 0xaa55 && EFI_PMBR_OSTYPE_EFI_GPT == 0xEE && GPT_MBR_PROTECTIVE == 1 && GPT_MBR_HYBRID == 2 &&
	      GPT_PRIMARY_PARTITION_TABLE_LBA == 1);

u32 rust_efi_crc32(const void *buf, u32 len)
{
	return efi_crc32(buf, len);
}

/* The pr_warn() lines of compare_gpts(), in the order of the rust numbering. */
void rust_efi_warn(int which, u64 a, u64 b)
{
	switch (which) {
	case 0:
		pr_warn("GPT:Primary header LBA != Alt. header alternate_lba\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 1:
		pr_warn("GPT:Primary header alternate_lba != Alt. header my_lba\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 2:
		pr_warn("GPT:first_usable_lbas don't match.\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 3:
		pr_warn("GPT:last_usable_lbas don't match.\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 4:
		pr_warn("GPT:disk_guids don't match.\n");
		break;
	case 5:
		pr_warn("GPT:num_partition_entries don't match: "
		       "0x%x != 0x%x\n", (u32)a, (u32)b);
		break;
	case 6:
		pr_warn("GPT:sizeof_partition_entry values don't match: "
		       "0x%x != 0x%x\n", (u32)a, (u32)b);
		break;
	case 7:
		pr_warn("GPT:partition_entry_array_crc32 values don't match: "
		       "0x%x != 0x%x\n", (u32)a, (u32)b);
		break;
	case 8:
		pr_warn("GPT:Primary header thinks Alt. header is not at the end of the disk.\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 9:
		pr_warn("GPT:Alternate GPT header not at the end of the disk.\n");
		pr_warn("GPT:%lld != %lld\n", (unsigned long long)a, (unsigned long long)b);
		break;
	case 10:
		pr_warn("GPT: Use GNU Parted to correct GPT errors.\n");
		break;
	}
}
/* RUST-WRAPPERS END */

static int is_pmbr_valid(legacy_mbr *mbr, sector_t total_sectors)
{
	return rust_efi_is_pmbr_valid((const u8 *)mbr);
}

/**
 * read_lba(): Read bytes from disk, starting at given LBA
 * @state: disk parsed partitions
 * @lba: the Logical Block Address of the partition table
 * @buffer: destination buffer
 * @count: bytes to read
 *
 * Description: Reads @count bytes from @state->disk into @buffer.
 * Returns number of bytes read on success, 0 on error.
 */
static size_t read_lba(struct parsed_partitions *state,
		       u64 lba, u8 *buffer, size_t count)
{
	size_t totalreadcount = 0;
	sector_t n = lba *
		(queue_logical_block_size(state->disk->queue) / 512);

	if (!buffer || lba > last_lba(state->disk))
                return 0;

	while (count) {
		int copied = 512;
		Sector sect;
		unsigned char *data = read_part_sector(state, n++, &sect);
		if (!data)
			break;
		if (copied > count)
			copied = count;
		memcpy(buffer, data, copied);
		put_dev_sector(sect);
		buffer += copied;
		totalreadcount +=copied;
		count -= copied;
	}
	return totalreadcount;
}

/**
 * alloc_read_gpt_entries(): reads partition entries from disk
 * @state: disk parsed partitions
 * @gpt: GPT header
 * 
 * Description: Returns ptes on success,  NULL on error.
 * Allocates space for PTEs based on information found in @gpt.
 * Notes: remember to free pte when you're done!
 */
static gpt_entry *alloc_read_gpt_entries(struct parsed_partitions *state,
					 gpt_header *gpt)
{
	size_t count;
	gpt_entry *pte;

	if (!gpt)
		return NULL;

	count = (size_t)le32_to_cpu(gpt->num_partition_entries) *
                le32_to_cpu(gpt->sizeof_partition_entry);
	if (!count)
		return NULL;
	pte = kmalloc(count, GFP_KERNEL);
	if (!pte)
		return NULL;

	if (read_lba(state, le64_to_cpu(gpt->partition_entry_lba),
			(u8 *) pte, count) < count) {
		kfree(pte);
                pte=NULL;
		return NULL;
	}
	return pte;
}

/**
 * alloc_read_gpt_header(): Allocates GPT header, reads into it from disk
 * @state: disk parsed partitions
 * @lba: the Logical Block Address of the partition table
 * 
 * Description: returns GPT header on success, NULL on error.   Allocates
 * and fills a GPT header starting at @ from @state->disk.
 * Note: remember to free gpt when finished with it.
 */
static gpt_header *alloc_read_gpt_header(struct parsed_partitions *state,
					 u64 lba)
{
	gpt_header *gpt;
	unsigned ssz = queue_logical_block_size(state->disk->queue);

	gpt = kmalloc(ssz, GFP_KERNEL);
	if (!gpt)
		return NULL;

	if (read_lba(state, lba, (u8 *) gpt, ssz) < ssz) {
		kfree(gpt);
                gpt=NULL;
		return NULL;
	}

	return gpt;
}

/**
 * is_gpt_valid() - tests one GPT header and PTEs for validity
 * @state: disk parsed partitions
 * @lba: logical block address of the GPT header to test
 * @gpt: GPT header ptr, filled on return.
 * @ptes: PTEs ptr, filled on return.
 *
 * Description: returns 1 if valid,  0 on error.
 * If valid, returns pointers to newly allocated GPT header and PTEs.
 */
static int is_gpt_valid(struct parsed_partitions *state, u64 lba,
			gpt_header **gpt, gpt_entry **ptes)
{
	u32 crc;
	u64 lastlba, pt_size;

	if (!ptes)
		return 0;
	if (!(*gpt = alloc_read_gpt_header(state, lba)))
		return 0;

	/* Check the GUID Partition Table signature */
	lastlba = last_lba(state->disk);
	if (rust_efi_gpt_header_check((u8 *)*gpt, lba, lastlba, queue_logical_block_size(state->disk->queue)))
		goto fail;

	pt_size = (u64)le32_to_cpu((*gpt)->num_partition_entries) *
		le32_to_cpu((*gpt)->sizeof_partition_entry);
	if (pt_size > KMALLOC_MAX_SIZE) {
		pr_debug("GUID Partition Table is too large: %llu > %lu bytes\n",
			 (unsigned long long)pt_size, KMALLOC_MAX_SIZE);
		goto fail;
	}

	if (!(*ptes = alloc_read_gpt_entries(state, *gpt)))
		goto fail;

	/* Check the GUID Partition Entry Array CRC */
	crc = efi_crc32((const unsigned char *) (*ptes), pt_size);

	if (crc != le32_to_cpu((*gpt)->partition_entry_array_crc32)) {
		pr_debug("GUID Partition Entry Array CRC check failed.\n");
		goto fail_ptes;
	}

	/* We're done, all's well */
	return 1;

 fail_ptes:
	kfree(*ptes);
	*ptes = NULL;
 fail:
	kfree(*gpt);
	*gpt = NULL;
	return 0;
}

/**
 * is_pte_valid() - tests one PTE for validity
 * @pte:pte to check
 * @lastlba: last lba of the disk
 *
 * Description: returns 1 if valid,  0 on error.
 */
static inline int
is_pte_valid(const gpt_entry *pte, const u64 lastlba)
{
	return rust_efi_is_pte_valid((const u8 *)pte, lastlba);
}

/**
 * compare_gpts() - Search disk for valid GPT headers and PTEs
 * @pgpt: primary GPT header
 * @agpt: alternate GPT header
 * @lastlba: last LBA number
 *
 * Description: Returns nothing.  Sanity checks pgpt and agpt fields
 * and prints warnings on discrepancies.
 * 
 */
static void
compare_gpts(gpt_header *pgpt, gpt_header *agpt, u64 lastlba)
{
	rust_efi_compare_gpts((const u8 *)pgpt, (const u8 *)agpt, lastlba);
}

/**
 * find_valid_gpt() - Search disk for valid GPT headers and PTEs
 * @state: disk parsed partitions
 * @gpt: GPT header ptr, filled on return.
 * @ptes: PTEs ptr, filled on return.
 *
 * Description: Returns 1 if valid, 0 on error.
 * If valid, returns pointers to newly allocated GPT header and PTEs.
 * Validity depends on PMBR being valid (or being overridden by the
 * 'gpt' kernel command line option) and finding either the Primary
 * GPT header and PTEs valid, or the Alternate GPT header and PTEs
 * valid.  If the Primary GPT header is not valid, the Alternate GPT header
 * is not checked unless the 'gpt' kernel command line option is passed.
 * This protects against devices which misreport their size, and forces
 * the user to decide to use the Alternate GPT.
 */
static int find_valid_gpt(struct parsed_partitions *state, gpt_header **gpt,
			  gpt_entry **ptes)
{
	int good_pgpt = 0, good_agpt = 0, good_pmbr = 0;
	gpt_header *pgpt = NULL, *agpt = NULL;
	gpt_entry *pptes = NULL, *aptes = NULL;
	legacy_mbr *legacymbr;
	struct gendisk *disk = state->disk;
	const struct block_device_operations *fops = disk->fops;
	sector_t total_sectors = get_capacity(state->disk);
	u64 lastlba;

	if (!ptes)
		return 0;

	lastlba = last_lba(state->disk);
        if (!force_gpt) {
		/* This will be added to the EFI Spec. per Intel after v1.02. */
		legacymbr = kzalloc(sizeof(*legacymbr), GFP_KERNEL);
		if (!legacymbr)
			goto fail;

		read_lba(state, 0, (u8 *)legacymbr, sizeof(*legacymbr));
		good_pmbr = is_pmbr_valid(legacymbr, total_sectors);
		kfree(legacymbr);

		if (!good_pmbr)
			goto fail;

		pr_debug("Device has a %s MBR\n",
			 good_pmbr == GPT_MBR_PROTECTIVE ?
						"protective" : "hybrid");
	}

	good_pgpt = is_gpt_valid(state, GPT_PRIMARY_PARTITION_TABLE_LBA,
				 &pgpt, &pptes);
        if (good_pgpt)
		good_agpt = is_gpt_valid(state,
					 le64_to_cpu(pgpt->alternate_lba),
					 &agpt, &aptes);
        if (!good_agpt && force_gpt)
                good_agpt = is_gpt_valid(state, lastlba, &agpt, &aptes);

	if (!good_agpt && force_gpt && fops->alternative_gpt_sector) {
		sector_t agpt_sector;
		int err;

		err = fops->alternative_gpt_sector(disk, &agpt_sector);
		if (!err)
			good_agpt = is_gpt_valid(state, agpt_sector,
						 &agpt, &aptes);
	}

        /* The obviously unsuccessful case */
        if (!good_pgpt && !good_agpt)
                goto fail;

        compare_gpts(pgpt, agpt, lastlba);

        /* The good cases */
        if (good_pgpt) {
                *gpt  = pgpt;
                *ptes = pptes;
                kfree(agpt);
                kfree(aptes);
		if (!good_agpt)
                        pr_warn("Alternate GPT is invalid, using primary GPT.\n");
                return 1;
        }
        else if (good_agpt) {
                *gpt  = agpt;
                *ptes = aptes;
                kfree(pgpt);
                kfree(pptes);
		pr_warn("Primary GPT is invalid, using alternate GPT.\n");
                return 1;
        }

 fail:
        kfree(pgpt);
        kfree(agpt);
        kfree(pptes);
        kfree(aptes);
        *gpt = NULL;
        *ptes = NULL;
        return 0;
}

/**
 * utf16_le_to_7bit(): Naively converts a UTF-16LE string to 7-bit ASCII characters
 * @in: input UTF-16LE string
 * @size: size of the input string
 * @out: output string ptr, should be capable to store @size+1 characters
 *
 * Description: Converts @size UTF16-LE symbols from @in string to 7-bit
 * ASCII characters and stores them to @out. Adds trailing zero to @out array.
 */
static void utf16_le_to_7bit(const __le16 *in, unsigned int size, u8 *out)
{
	rust_efi_utf16_le_to_7bit((const u16 *)in, size, out);
}

/**
 * efi_partition - scan for GPT partitions
 * @state: disk parsed partitions
 *
 * Description: called from check.c, if the disk contains GPT
 * partitions, sets up partition entries in the kernel.
 *
 * If the first block on the disk is a legacy MBR,
 * it will get handled by msdos_partition().
 * If it's a Protective MBR, we'll handle it here.
 *
 * We do not create a Linux partition for GPT, but
 * only for the actual data partitions.
 * Returns:
 * -1 if unable to read the partition table
 *  0 if this isn't our partition table
 *  1 if successful
 *
 */
int efi_partition(struct parsed_partitions *state)
{
	gpt_header *gpt = NULL;
	gpt_entry *ptes = NULL;
	u32 i;
	unsigned ssz = queue_logical_block_size(state->disk->queue) / 512;

	if (!find_valid_gpt(state, &gpt, &ptes) || !gpt || !ptes) {
		kfree(gpt);
		kfree(ptes);
		return 0;
	}

	pr_debug("GUID Partition Table is valid!  Yea!\n");

	for (i = 0; i < le32_to_cpu(gpt->num_partition_entries) && i < state->limit-1; i++) {
		struct partition_meta_info *info;
		unsigned label_max;
		u64 start = le64_to_cpu(ptes[i].starting_lba);
		u64 size = le64_to_cpu(ptes[i].ending_lba) -
			   le64_to_cpu(ptes[i].starting_lba) + 1ULL;

		if (!is_pte_valid(&ptes[i], last_lba(state->disk)))
			continue;

		put_partition(state, i+1, start * ssz, size * ssz);

		/* If this is a RAID volume, tell md */
		if (!efi_guidcmp(ptes[i].partition_type_guid, PARTITION_LINUX_RAID_GUID))
			state->parts[i + 1].flags = ADDPART_FLAG_RAID;

		info = &state->parts[i + 1].info;
		efi_guid_to_str(&ptes[i].unique_partition_guid, info->uuid);

		/* Naively convert UTF16-LE to 7 bits. */
		label_max = min(ARRAY_SIZE(info->volname) - 1,
				ARRAY_SIZE(ptes[i].partition_name));
		utf16_le_to_7bit(ptes[i].partition_name, label_max, info->volname);
		state->parts[i + 1].has_info = true;
	}
	kfree(ptes);
	kfree(gpt);
	strlcat(state->pp_buf, "\n", PAGE_SIZE);
	return 1;
}
