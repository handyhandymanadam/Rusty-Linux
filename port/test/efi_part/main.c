/* GPT differential: the pristine checks of block/partitions/efi.c (ARM_REF) against efi_rs.rs through the glue (ARM_RS). Random protective, hybrid and invalid MBRs; valid GPT headers (real CRCs)
 * with one field at a time corrupted, truncated header sizes, block sizes from 512 to 4096, usable ranges on and past the disk; partition entries with null and non-null type GUIDs and ranges
 * on and off the disk; primary / alternate header pairs differing in any set of fields; UTF-16 labels with high bits, control characters and NULs. Results, the header bytes after the check
 * (the CRC field is zeroed during the check and must be restored) and every warning line are printed.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include "linux/efi.h"
#include "efi.h"
unsigned int g_ssz; u64 g_lastlba; struct parsed_partitions g_state;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static void hexs(const void *p, size_t n) { const u8 *q = p; size_t i; for (i = 0; i < n; i++) printf("%02x", q[i]); }
static void mkhdr(u8 *b, u64 lba, u64 last, unsigned ssz)
{
	gpt_header *h = (gpt_header *)b; u32 crc;
	memset(b, 0, 4096);
	h->signature = GPT_HEADER_SIGNATURE; h->revision = 0x10000; h->header_size = 92; h->my_lba = lba; h->alternate_lba = rnd(2) ? last : 1; h->first_usable_lba = 34; h->last_usable_lba = last - 33;
	{ int i; for (i = 0; i < 16; i++) h->disk_guid.b[i] = rnd(256); }
	h->partition_entry_lba = 2; h->num_partition_entries = 128; h->sizeof_partition_entry = 128; h->partition_entry_array_crc32 = (u32)rnd64();
	h->header_crc32 = 0; crc = efi_crc32(b, h->header_size); h->header_crc32 = crc;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 60000, it, pc = 0;
	static const unsigned ssizes[] = { 512, 1024, 2048, 4096 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		u8 hb[4096], hb2[4096], mb[512], pte[128]; unsigned ssz = ssizes[rnd(4)]; u64 last = rnd(8) == 0 ? rnd64() >> rnd(60) : 1000 + rnd(1u << 20), lba = rnd(3) ? 1 : rnd(100); int rc, k;
		gpt_header *h = (gpt_header *)hb;
		/* protective / hybrid MBR */
		memset(mb, 0, sizeof mb); { legacy_mbr *m = (legacy_mbr *)mb; for (k = 0; k < 4; k++) { m->partition_record[k].os_type = rnd(3) == 0 ? 0xEE : rnd(3) == 0 ? 0 : rnd(256); m->partition_record[k].starting_lba = rnd(3) ? 1 : rnd(5); m->partition_record[k].size_in_lba = (u32)rnd64(); } m->signature = rnd(8) ? 0xaa55 : rnd(65536); }
		rc = is_pmbr_valid(rnd(10) == 0 ? NULL : (legacy_mbr *)mb, last + 1); if (prove && pc++ == 3) rc++;
		printf("%ld pmbr %d\n", it, rc);
		/* header checks */
		mkhdr(hb, lba, last, ssz);
		{ int cs = rnd(18);
		switch (cs) {
		case 0: h->signature ^= 1ull << rnd(64); break;
		case 1: h->header_size = rnd(2) ? rnd(200) : ssz + rnd(3) - 1; break;
		case 2: h->header_crc32 ^= 1u << rnd(32); break;
		case 3: h->my_lba = rnd(2) ? lba + 1 + rnd(5) : lba - 1 - rnd(lba > 1 ? 1 : 0); break;
		case 10: h->first_usable_lba = h->last_usable_lba = last; break;
		case 11: h->last_usable_lba = last; break;
		case 12: h->first_usable_lba = last; break;
		case 4: h->first_usable_lba = last + rnd(3); break;
		case 5: h->last_usable_lba = last + rnd(3); break;
		case 6: h->last_usable_lba = h->first_usable_lba - 1 - rnd(3); break;
		case 7: h->sizeof_partition_entry = rnd(2) ? 127 : 256; break;
		case 8: hb[rnd(92)] ^= 1 << rnd(8); break;
		case 9: if (h->header_size > 92 && h->header_size <= ssz) {} h->header_size = 92 + rnd(100); { u32 c; h->header_crc32 = 0; c = efi_crc32(hb, h->header_size <= 4096 ? h->header_size : 92); h->header_crc32 = c; } break;
		default: break;
		}
		if (cs != 2 && cs != 8 && cs != 9 && cs != 0 && cs != 1) { u32 c; unsigned hs = h->header_size; h->header_crc32 = 0; c = efi_crc32(hb, hs <= 4096 ? hs : 92); h->header_crc32 = c; }
		}
		memcpy(hb2, hb, sizeof hb);
		g_ssz = ssz; g_lastlba = last; g_state.disk = (struct gendisk_ *)&g_state;
		rc = header_check((gpt_header *)hb2, lba, last, ssz);
		printf("  header_check lba=%llu ssz=%u -> %d crc=%08x bytes=", (unsigned long long)lba, ssz, rc, ((gpt_header *)hb2)->header_crc32); hexs(hb2, 96); printf("\n");
		/* pte */
		memset(pte, 0, sizeof pte);
		if (rnd(4)) for (k = 0; k < 16; k++) pte[k] = rnd(256);
		if (rnd(10) == 0) memset(pte, 0, 16);
		((gpt_entry *)pte)->starting_lba = rnd(3) ? rnd((unsigned)last + 1) : last + rnd(3); ((gpt_entry *)pte)->ending_lba = rnd(3) ? rnd((unsigned)last + 1) : last + rnd(3);
		printf("  pte last=%llu -> %d\n", (unsigned long long)last, is_pte_valid((const gpt_entry *)pte, last));
		/* compare_gpts */
		mkhdr(hb, 1, last, ssz); memcpy(hb2, hb, 92);
		{ gpt_header *p = (gpt_header *)hb, *a = (gpt_header *)hb2; int m = rnd(4);
		  p->alternate_lba = last; a->my_lba = last; a->alternate_lba = 1;
		  while (m--) switch (rnd(10)) { case 0: a->alternate_lba += rnd(2) ? 1 + rnd(3) : -1 - rnd(3); break; case 1: a->my_lba += rnd(2) ? 1 + rnd(3) : -1 - rnd(3); break; case 2: a->first_usable_lba += rnd(2) ? 1 : -1; break; case 3: a->last_usable_lba += rnd(2) ? 1 : -1; break;
			case 4: a->disk_guid.b[rnd(16)] ^= 1; break; case 5: a->num_partition_entries += rnd(2) ? 1 : -1; break; case 6: a->sizeof_partition_entry += rnd(2) ? 1 : -1; break; case 7: a->partition_entry_array_crc32 += rnd(2) ? 1 : -1; break;
			case 8: p->alternate_lba = rnd(2) ? last - 1 - rnd(3) : last + 1 + rnd(3); break; default: a->my_lba = rnd(2) ? last + 1 + rnd(3) : last - 1 - rnd(3); break; }
		  printf("  compare:\n"); compare_gpts(rnd(20) == 0 ? NULL : p, rnd(20) == 0 ? NULL : a, last); }
		/* label */
		{ u16 lab[40]; u8 out[48]; unsigned sz = rnd(37), i; for (i = 0; i < 40; i++) lab[i] = rnd(3) ? 0x20 + rnd(100) : rnd(4) ? rnd(0x100) : (u16)rnd64(); memset(out, 0xaa, sizeof out); utf16_le_to_7bit(lab, sz, out); printf("  label %u ", sz); hexs(out, sz + 1); printf(" %02x\n", out[sz + 1]); }
	}
	return 0;
}
