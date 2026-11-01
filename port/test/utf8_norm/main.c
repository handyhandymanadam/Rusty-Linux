/* utf8 normalization differential: pristine fs/unicode/utf8-norm.c (ARM_REF) against utf8_norm_rs.rs (ARM_RS), both on the real shipped tables (utf8data.c_shipped). Random strings
 * from a repertoire of ASCII, Latin-1 precomposed and combining marks of many classes, Hangul syllables and jamo, compatibility ideographs, newer-than-version code points, 4-byte
 * characters, stray continuation bytes, truncated sequences and raw bytes; for every Unicode version of the table and both normalizations: utf8version_is_supported, utf8nlen with
 * several lengths, and the whole utf8byte stream of a cursor.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "utf8n.h"
#ifdef ARM_REF
#include SRCFILE
#endif
extern const struct utf8data_table utf8_data_table;
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static const struct utf8data *find_table_version(const struct utf8data *table, size_t nr_entries, unsigned int version)
{
	size_t i = nr_entries - 1;
	while (version < table[i].maxage) i--;
	if (version > table[i].maxage) return NULL;
	return &table[i];
}
static int load(struct unicode_map *um, unsigned version)
{
	memset(um, 0, sizeof *um); um->version = version; um->tables = &utf8_data_table;
	if (!utf8version_is_supported(um, version)) return 0;
	um->ntab[UTF8_NFDI] = find_table_version(um->tables->utf8nfdidata, um->tables->utf8nfdidata_size, version);
	um->ntab[UTF8_NFDICF] = find_table_version(um->tables->utf8nfdicfdata, um->tables->utf8nfdicfdata_size, version);
	return um->ntab[0] && um->ntab[1];
}
static size_t enc(unsigned char *p, unsigned cp)
{
	if (cp < 0x80) { p[0] = cp; return 1; }
	if (cp < 0x800) { p[0] = 0xC0 | cp >> 6; p[1] = 0x80 | (cp & 63); return 2; }
	if (cp < 0x10000) { p[0] = 0xE0 | cp >> 12; p[1] = 0x80 | (cp >> 6 & 63); p[2] = 0x80 | (cp & 63); return 3; }
	p[0] = 0xF0 | cp >> 18; p[1] = 0x80 | (cp >> 12 & 63); p[2] = 0x80 | (cp >> 6 & 63); p[3] = 0x80 | (cp & 63); return 4;
}
static unsigned pickcp(void)
{
	static const unsigned lst[] = { 0x41, 0x61, 0x7a, 0xc0, 0xc5, 0xe9, 0xdf, 0x130, 0x1e9e, 0x300, 0x301, 0x302, 0x308, 0x323, 0x327, 0x334, 0x345, 0x344, 0x34f, 0x5b0, 0x5b4, 0x64b, 0x93c, 0xe38, 0xf71,
		0x1100, 0x1161, 0x11a8, 0x1e0a, 0x1e63, 0x1f80, 0x1fbc, 0x2126, 0x212b, 0x2160, 0x3042, 0x3099, 0x309a, 0xf900, 0xfa10, 0xfb01, 0xfb1d, 0xfe20, 0xff21, 0x10400, 0x1d15e, 0x1d1bb, 0x1f600, 0x2f800, 0x13a0, 0xab70, 0x1c80, 0x0345 };
	switch (rnd(8)) {
	case 0: return 0x20 + rnd(95);
	case 1: case 2: case 3: return lst[rnd(sizeof lst / sizeof *lst)];
	case 4: return 0xac00 + rnd(11172);
	case 5: return 0x300 + rnd(0x70);
	case 6: return rnd(2) ? rnd(0x3000) : 0x10000 + rnd(0x20000);
	default: return 0xe000 + rnd(0x2000);
	}
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 30000, it, pc = 0;
	size_t nv = utf8_data_table.utf8agetab_size, v;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	{	/* every code point of this shard's slice, alone, for the newest version and a middle one, both normalizations; plus odd versions and a NULL / over-long cursor */
		struct unicode_map um; unsigned cp, vers[2] = { utf8_data_table.utf8agetab[nv - 1], utf8_data_table.utf8agetab[nv / 2] }; int vi, nn;
		for (vi = 0; vi < 2; vi++) {
			if (!load(&um, vers[vi])) { printf("sweep no %x\n", vers[vi]); continue; }
			for (cp = shard; cp < 0x110000; cp += 4) {
				unsigned char t[8]; size_t l = enc(t, cp); struct utf8cursor c; int b, st = 0;
				t[l] = 0; t[l + 1] = 0;
				for (nn = 0; nn < 2; nn++) {
					printf("%x v=%x n=%d nlen=%zd:", cp, vers[vi], nn, utf8nlen(&um, nn, (char *)t, l));
					if (!utf8ncursor(&c, &um, nn, (char *)t, l)) while (st++ < 40 && (b = utf8byte(&c)) > 0) printf(" %02x", b);
					printf("\n"); st = 0;
				}
			}
		}
		for (vi = 0; vi < 6; vi++) { unsigned vv[6] = { 0, 1, 0x10000, 0x0c0100, 0xffffffff, 0x0c0000 }; struct unicode_map u2; printf("load %x -> %d\n", vv[vi], load(&u2, vv[vi])); }
		{ struct utf8cursor c; struct unicode_map u2; load(&u2, vers[0]); printf("null cursor %d\n", utf8ncursor(&c, &u2, 0, NULL, 3));
		  printf("huge cursor %d\n", utf8ncursor(&c, &u2, 0, "abc", (size_t)1 << 32 | 3)); printf("cont cursor %d\n", utf8ncursor(&c, &u2, 0, "\x80z", 2)); printf("cont cursor0 %d\n", utf8ncursor(&c, &u2, 0, "\x80z", 0)); }
	}
	for (it = 0; it < n; it++) {
		unsigned char tmp[512]; size_t len = 0; int k, nch = 1 + rnd(8);
		for (k = 0; k < nch && len < 400; k++) {
			unsigned r = rnd(20);
			if (r == 0) { static const unsigned char sp[] = { 0xc0, 0xc1, 0xe0, 0xf0, 0xf4, 0xf8, 0xfc, 0xfe, 0xff, 0x80, 0xbf }; tmp[len++] = rnd(2) ? sp[rnd(sizeof sp)] : 0x80 + rnd(64); }
			else if (r == 1) tmp[len++] = rnd(256);
			else if (r == 2) { unsigned char t[4]; size_t l = enc(t, pickcp()); size_t cut = 1 + rnd(l); memcpy(tmp + len, t, cut); len += cut; }
			else len += enc(tmp + len, pickcp());
		}
		if (rnd(25) == 0 && len) tmp[rnd(len)] = 0;
		tmp[len] = 0;
		{
			size_t sl = strlen((char *)tmp); char *s = malloc(sl + 1); memcpy(s, tmp, sl + 1);
			for (v = 0; v < nv; v++) {
				unsigned ver = utf8_data_table.utf8agetab[v]; struct unicode_map um; int nn;
				if (ver == 0 || (v % 3 && rnd(3))) continue;
				if (!load(&um, ver)) { printf("%ld v=%x no\n", it, ver); continue; }
				for (nn = 0; nn < 2; nn++) {
					size_t lens[3] = { sl, sl ? rnd(sl + 1) : 0, (size_t)-1 }; int li; struct utf8cursor c; int rc, b, steps = 0;
					for (li = 0; li < 3; li++) {
						ssize_t r2 = utf8nlen(&um, nn, s, lens[li]); if (prove && pc++ == 3) r2++;
						printf("%ld v=%x n=%d len=%zu nlen=%zd\n", it, ver, nn, lens[li], r2);
					}
					{
						size_t cl = rnd(3) == 0 ? (sl ? rnd(sl + 1) : 0) : sl;
						rc = utf8ncursor(&c, &um, nn, s, cl); printf("  cursor len=%zu rc=%d:", cl, rc);
						if (!rc) while (steps++ < 1200 && (b = utf8byte(&c)) > 0) printf(" %02x", b);
						printf(" end=%d\n", rc ? 0 : b);
					}
				}
			}
			free(s);
		}
	}
	return 0;
}
