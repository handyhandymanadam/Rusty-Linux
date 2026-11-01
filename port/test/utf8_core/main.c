/* utf8-core differential: the pristine comparison / folding / hashing functions (ARM_REF) against utf8_core_rs.rs through the glue thunks (ARM_RS), both on the pristine utf8-norm.c and the real
 * tables. Strings from a repertoire of accents, ligatures, Hangul and stray bytes (as in the utf8_norm test); pairs that are equal, case variants, different normalization forms of one text and
 * unrelated ones; destination buffers of every size (including exactly the output size and one less); salts.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include "utf8n.h"
#include "../utf8_norm/main_common.h"
#include SRCFILE
extern const struct utf8data_table utf8_data_table;
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
static void hexs(const unsigned char *p, size_t n) { size_t i; for (i = 0; i < n; i++) printf("%02x", p[i]); }
static size_t mkstr(unsigned char *tmp)
{
	size_t len = 0; int k, nch = 1 + rnd(7);
	for (k = 0; k < nch && len < 200; k++) {
		unsigned r = rnd(20);
		if (r == 0) { static const unsigned char sp[] = { 0xc0, 0xe0, 0xf0, 0xff, 0x80, 0xbf }; tmp[len++] = sp[rnd(6)]; }
		else if (r == 1) tmp[len++] = rnd(256);
		else if (r == 2) { unsigned char t[4]; size_t l = enc(t, pickcp()); size_t cut = 1 + rnd(l); memcpy(tmp + len, t, cut); len += cut; }
		else len += enc(tmp + len, pickcp());
	}
	if (rnd(40) == 0 && len) tmp[rnd(len)] = 0;
	tmp[len] = 0;
	return strlen((char *)tmp);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 40000, it, pc = 0;
	struct unicode_map um;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	if (!load(&um, utf8_data_table.utf8agetab[utf8_data_table.utf8agetab_size - 1])) return 2;
	for (it = 0; it < n; it++) {
		unsigned char a[512], b[512], d[512], buf[512]; size_t la = mkstr(a), lb; int rc, rc2; struct qstr q1, q2, qcf; struct qstr qh;
		switch (rnd(5)) {
		case 0: memcpy(b, a, la + 1); lb = la; break;
		case 1: memcpy(b, a, la + 1); lb = la; if (lb) { size_t i; for (i = 0; i < lb; i++) if (b[i] >= 'a' && b[i] <= 'z' && rnd(2)) b[i] -= 32; } break;
		case 2: lb = mkstr(b); break;
		case 3: { /* the same text with e + U+0301 spelled composed / decomposed */
			size_t i, j = 0; for (i = 0; i < la && j < 480; i++) { if (a[i] == 'e' && rnd(2)) { b[j++] = 0xc3; b[j++] = 0xa9; } else b[j++] = a[i]; } b[j] = 0; lb = j; break; }
		default: memcpy(b, a, la + 1); lb = la; if (lb) b[rnd(lb)] ^= 0x20; break;
		}
		q1.name = a; q1.len = la; q1.hash = 0; q2.name = b; q2.len = lb; q2.hash = 0;
		if (rnd(8) == 0 && la) q1.len = rnd(la + 1);
		printf("%ld validate %d\n", it, utf8_validate(&um, &q1));
		rc = utf8_strncmp(&um, &q1, &q2); if (prove && pc++ == 3) rc++;
		printf("  strncmp %d strncasecmp %d\n", rc, utf8_strncasecmp(&um, &q1, &q2));
		{
			size_t dl = rnd(4) == 0 ? rnd(8) : 512; memset(d, 0x55, sizeof d);
			rc = utf8_casefold(&um, &q1, d, dl); printf("  casefold dl=%zu -> %d ", dl, rc); hexs(d, dl < 40 ? dl : 40); printf("\n");
			memset(d, 0x55, sizeof d);
			if (rc > 0 && rnd(2)) { dl = rc + rnd(2); } else dl = rnd(4) == 0 ? rnd(8) : 512;
			rc2 = utf8_normalize(&um, &q1, d, dl); printf("  normalize dl=%zu -> %d ", dl, rc2); hexs(d, dl < 40 ? dl : 40); printf("\n");
		}
		{
			unsigned long salt = rnd(2) ? 0 : (unsigned long)rnd64(); qh = q1; qh.hash = 0xdeadbeef;
			rc = utf8_casefold_hash(&um, (void *)salt, &qh); printf("  hash salt=%lx -> %d %08x\n", salt, rc, qh.hash);
		}
		{
			memset(buf, 0, sizeof buf); rc = utf8_casefold(&um, &q2, buf, sizeof buf); /* a valid folded string, or garbage */
			if (rc < 0) { memcpy(buf, b, lb + 1); }
			qcf.name = buf; qcf.len = strlen((char *)buf); qcf.hash = 0;
			if (rnd(4) == 0 && qcf.len) buf[rnd(qcf.len)] ^= 1;
			printf("  folded-cmp %d\n", utf8_strncasecmp_folded(&um, &qcf, &q1));
		}
	}
	return 0;
}
