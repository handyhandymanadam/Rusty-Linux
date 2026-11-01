/* ext4 dirhash differential: the pristine __ext4fs_dirhash and its algorithms (ARM_REF) against hash_rs.rs plus the glue's dispatch (ARM_RS). Random names of 0..130 bytes (exact-size heap
 * buffers; high-bit bytes, so signed and unsigned versions differ), every hash version 0..8 (6 is siphash with and without a key, 7 and 8 are invalid), seeds NULL / all zero / random /
 * one non-zero word. Prints the result code, the hash, the minor hash and the warning count.   usage: t SHARD (env EH_N, EH_PROVE) */
#include "refshim.h"
int has_key_g, warns;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("EH_N") ? atol(getenv("EH_N")) : 150000; int prove = getenv("EH_PROVE") != NULL; long i; static int pc;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < n; i++) {
		int len = rnd(4) ? (int)rnd(40) : (int)rnd(131), j, ver = rnd(10) < 8 ? (int)rnd(6) : (int)rnd(9), rc; unsigned char *nm = malloc(len ? len : 1); struct dx_hash_info h; u32 seed[4], *sp = NULL; struct inode ino; struct super_block sb;
		ino.i_sb = &sb;
		for (j = 0; j < len; j++) nm[j] = rnd(3) ? (unsigned char)(32 + rnd(95)) : (unsigned char)rnd(256);
		switch (rnd(4)) { case 0: sp = NULL; break; case 1: memset(seed, 0, sizeof seed); sp = seed; break; case 2: for (j = 0; j < 4; j++) seed[j] = (u32)rnd64(); sp = seed; break;
		default: memset(seed, 0, sizeof seed); seed[rnd(4)] = (u32)rnd64() | 1; sp = seed; }
		h.hash = 0xdeadbeef; h.minor_hash = 0xfeedface; h.hash_version = ver; h.seed = sp; has_key_g = rnd(2); warns = 0;
		rc = __ext4fs_dirhash(&ino, (const char *)nm, len, &h); if (prove && pc++ == 3) h.hash++;
		printf("%ld len=%d v=%d seed=%d key=%d -> %d %08x %08x w=%d\n", i, len, ver, sp ? (int)(seed[0] | seed[1] | seed[2] | seed[3] ? 2 : 1) : 0, has_key_g, rc, h.hash, h.minor_hash, warns);
		free(nm);
	}
	return 0;
}
