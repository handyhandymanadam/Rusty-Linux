/* auditfilter differential: the pristine pure checks (ARM_REF: ref.c extracted from the pristine file) against auditfilter_rs.rs plus the glue thunks (ARM_RS). audit_field_valid is run
 * over every combination of filter list 0..9, every known field type plus unknown ones, operators 0..9 and the interesting values; the comparators over every operator (valid and not) and
 * edge values; audit_to_op over the table and random values; parent_len and audit_compare_dname_path over random paths of '/' and letters (trailing and double slashes, empty, a single
 * slash, parent length given or AUDIT_NAME_FULL) with exact-size buffers.   usage: t SHARD (env AF_N, AF_PROVE) */
#include "refshim.h"
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static u32 val32(void) { static const u32 e[] = { 0, 1, 2, 15, 16, 25, 26, 45, 46, 0x7fffffff, 0x80000000u, 0xffffffffu, 0xf000, 0x10000, 0xe000, 0x1000, 0xfff0 }; return rnd(3) ? e[rnd(sizeof e / sizeof e[0])] : (u32)rnd64(); }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("AF_N") ? atol(getenv("AF_N")) : 40000; int prove = getenv("AF_PROVE") != NULL; long i; static int pc;
	static const u32 types[] = { AUDIT_MSGTYPE, AUDIT_FSTYPE, AUDIT_PERM, AUDIT_FILTERKEY, AUDIT_ARG0, AUDIT_ARG1, AUDIT_ARG2, AUDIT_ARG3, AUDIT_PERS, AUDIT_DEVMINOR, AUDIT_UID, AUDIT_EUID, AUDIT_SUID,
	    AUDIT_FSUID, AUDIT_LOGINUID, AUDIT_OBJ_UID, AUDIT_GID, AUDIT_EGID, AUDIT_SGID, AUDIT_FSGID, AUDIT_OBJ_GID, AUDIT_PID, AUDIT_PPID, AUDIT_DEVMAJOR, AUDIT_EXIT, AUDIT_SUCCESS, AUDIT_INODE,
	    AUDIT_SESSIONID, AUDIT_SUBJ_SEN, AUDIT_SUBJ_CLR, AUDIT_OBJ_LEV_LOW, AUDIT_OBJ_LEV_HIGH, AUDIT_SADDR_FAM, AUDIT_SUBJ_USER, AUDIT_SUBJ_ROLE, AUDIT_SUBJ_TYPE, AUDIT_OBJ_USER, AUDIT_OBJ_ROLE,
	    AUDIT_OBJ_TYPE, AUDIT_WATCH, AUDIT_DIR, AUDIT_LOGINUID_SET, AUDIT_ARCH, AUDIT_FILETYPE, AUDIT_FIELD_COMPARE, AUDIT_EXE, 27, 99, 114, 199, 204, 211, 1000, 0xffffffffu };
	static const u32 vals[] = { 0, 1, 2, 15, 16, 25, 26, 45, 46, 0xf000, 0x10000, 0x8000, 0xffffffffu };
	unsigned a, b, c, d; static const char al[] = "/ab"; (void)shard;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	if (shard == 0) {   /* exhaustive field validity */
		for (a = 0; a < 10; a++) for (b = 0; b < sizeof types / sizeof types[0]; b++) for (c = 0; c < 10; c++) for (d = 0; d < sizeof vals / sizeof vals[0]; d++) {
			struct audit_entry e; struct audit_field f; int r; e.rule.listnr = a; f.type = types[b]; f.op = c; f.val = vals[d];
			r = audit_field_valid(&e, &f); if (prove && pc++ == 3) r++;
			printf("V %u %u %u %u -> %d\n", a, types[b], c, vals[d], r);
		}
	}
	for (i = 0; i < n; i++) {
		int k = rnd(5);
		if (k == 0) {
			u32 l = val32(), r = val32(), op = rnd(4) ? rnd(9) : rnd(20); kuid_t kl = { l }, kr = { r }; kgid_t gl = { l }, gr = { r }; int x;
			if (rnd(3) == 0) r = l; if (rnd(5) == 0) r = l & val32();
			kr.val = gr.val = r; x = audit_comparator(l, op, r); if (prove && pc++ == 3) x++;
			printf("%ld C %u %u %u -> %d %d %d\n", i, l, op, r, x, audit_uid_comparator(kl, op, kr), audit_gid_comparator(gl, op, gr));
		} else if (k == 1) {
			u32 op = rnd(2) ? audit_ops[rnd(8)] : (u32)rnd64(); printf("%ld O %u -> %u\n", i, op, audit_to_op(op));
		} else if (k == 2) {
			struct audit_entry e; struct audit_field f; e.rule.listnr = rnd(10); f.type = types[rnd(sizeof types / sizeof types[0])]; f.op = rnd(10); f.val = val32();
			printf("%ld V %u %u %u %u -> %d\n", i, e.rule.listnr, f.type, f.op, f.val, audit_field_valid(&e, &f));
		} else {
			size_t pl = rnd(14), dl = rnd(8), j; char *path = malloc(pl + 1); unsigned char *dn = malloc(dl ? dl : 1); struct qstr q; int pr, r; int parentlen;
			for (j = 0; j < pl; j++) path[j] = al[rnd(rnd(3) ? 3 : 2)]; path[pl] = 0; for (j = 0; j < dl; j++) dn[j] = al[1 + rnd(2)];
			if (rnd(2) && pl >= dl) { /* make the last component match the name */ size_t m = pl; while (m > 0 && path[m - 1] == '/') m--; if (m >= dl) memcpy(path + m - dl, dn, dl); }
			q.name = dn; q.len = dl; pr = parent_len(path); parentlen = rnd(2) ? AUDIT_NAME_FULL : (int)rnd(pl + 1);
			r = audit_compare_dname_path(&q, path, parentlen);
			printf("%ld P [%s] [%.*s] pl=%d -> %d %d\n", i, path, (int)dl, dn, parentlen, pr, r < 0 ? -1 : r > 0 ? 1 : 0);
			free(path); free(dn);
		}
	}
	return 0;
}
