#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- efi_glue.c = upstream block/partitions/efi.c with the pure checks (protective MBR, GPT header checks, is_pte_valid, compare_gpts, utf16_le_to_7bit) replaced by calls into efi_rs.rs."""
import sys
s = open(sys.argv[1]).read()
def cut(first, last_sig, repl):
    """replace from the start of `first` through the end of the function whose signature starts at last_sig by repl"""
    global s
    a = s.index(first); k = s.index(last_sig, a); e = s.index("\n}\n", k) + 3
    s = s[:a] + repl + s[e:]
# 1. pmbr_part_valid + is_pmbr_valid
a = s.index("static inline int pmbr_part_valid("); k = s.index("static int is_pmbr_valid("); e = s.index("\n}\n", k) + 3
s = s[:a] + "static int is_pmbr_valid(legacy_mbr *mbr, sector_t total_sectors)\n{\n\treturn rust_efi_is_pmbr_valid((const u8 *)mbr);\n}\n" + s[e:]
# 2. header checks in is_gpt_valid
a = s.index("\tif (le64_to_cpu((*gpt)->signature) != GPT_HEADER_SIGNATURE) {")
b = s.index("\tpt_size = (u64)le32_to_cpu((*gpt)->num_partition_entries) *")
s = s[:a] + "\tlastlba = last_lba(state->disk);\n\tif (rust_efi_gpt_header_check((u8 *)*gpt, lba, lastlba, queue_logical_block_size(state->disk->queue)))\n\t\tgoto fail;\n\n" + s[b:]
s = s.replace("\tu32 crc, origcrc;\n", "\tu32 crc;\n", 1)
# 3. is_pte_valid
a = s.index("static inline int\nis_pte_valid("); e = s.index("\n}\n", a) + 3
s = s[:a] + "static inline int\nis_pte_valid(const gpt_entry *pte, const u64 lastlba)\n{\n\treturn rust_efi_is_pte_valid((const u8 *)pte, lastlba);\n}\n" + s[e:]
# 4. compare_gpts
a = s.index("static void\ncompare_gpts("); e = s.index("\n}\n", a) + 3
s = s[:a] + "static void\ncompare_gpts(gpt_header *pgpt, gpt_header *agpt, u64 lastlba)\n{\n\trust_efi_compare_gpts((const u8 *)pgpt, (const u8 *)agpt, lastlba);\n}\n" + s[e:]
# 5. utf16_le_to_7bit
a = s.index("static void utf16_le_to_7bit("); e = s.index("\n}\n", a) + 3
s = s[:a] + "static void utf16_le_to_7bit(const __le16 *in, unsigned int size, u8 *out)\n{\n\trust_efi_utf16_le_to_7bit((const u16 *)in, size, out);\n}\n" + s[e:]
wr = r'''/* RUST-WRAPPERS BEGIN: the pure checks are in efi_rs.rs; the functions below are thin calls into it. */
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

'''
a = s.index("static int is_pmbr_valid(")
s = s[:a] + wr + s[a:]
note = "// SPDX-License-Identifier: GPL-2.0-or-later\n/*\n * RUST PORT (block/partitions/efi.c, 6.18.49): the pure checks (protective MBR, GPT header checks, is_pte_valid, compare_gpts, the label conversion) are in efi_rs.rs; this file keeps all\n * reading of the disk and the partition table walk. Upstream's whole file is installed as efi_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-or-later\n", note, 1) if s.startswith("// SPDX-License-Identifier: GPL-2.0-or-later\n") else note + s
open(sys.argv[2], "w").write(s)
