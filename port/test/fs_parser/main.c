/* fs_parser differential: the pristine fs_parser.c parsing code (ARM_REF) against fs_parser_rs.rs through the glue's thunks and wrappers (ARM_RS). A specification table with every parameter kind
 * (flags, flags with "no" negation, bool, u32 in bases 0/8/10/16, s32, u64, enum, string, blob, fd, file-or-string, uid, gid, deprecated, can-be-empty, duplicate names with and without a flag
 * form) is matched against random parameters (every value type; strings of numbers in several bases and with junk, empty, overflowing; names with and without the "no" prefix and near misses);
 * every result, every converted value and every log line is printed.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
int log_n; u32 uid_limit = 100;
int kstrtouint(const char *s, unsigned int base, unsigned int *res) { unsigned long long v; int rc = kstrtoull(s, base, &v); if (rc) return rc; if ((unsigned int)v != v) return -ERANGE; *res = v; return 0; }
int kstrtoint(const char *s, unsigned int base, int *res) { long long v; char *e; if (!*s) return -EINVAL; if (base != 0 && base != 10 && base != 16 && base != 8) return -EINVAL; errno = 0; v = strtoll(s, &e, base); if (*e || e == s || errno) return -EINVAL; if ((int)v != v) return -ERANGE; *res = v; return 0; }
int kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
	char *e; unsigned long long v; const char *t = s;
	if (!*s) return -EINVAL;
	if (*t == '-') return -EINVAL;
	if (*t == '+') t++;
	if (!*t || *t == ' ') return -EINVAL;
	errno = 0; v = strtoull(t, &e, base); if (errno) return -ERANGE; if (*e == '\n' && !e[1]) e++; if (*e || e == t) return -EINVAL;
	*res = v; return 0;
}
const struct constant_table bool_names[] = { { "0", false }, { "1", true }, { "false", false }, { "no", false }, { "true", true }, { "yes", true }, { } };
#include SRCFILE
static const struct constant_table fruit[] = { { "apple", 1 }, { "pear", 2 }, { "fig", 3 }, { "", 9 }, { } };
static int dummy_blockdev(struct p_log *l, const struct fs_parameter_spec *p, struct fs_parameter *a, struct fs_parse_result *r) { return 0; }
#define SPEC(n, t, o, f, d) { .name = n, .type = t, .opt = o, .flags = f, .data = d }
static const struct fs_parameter_spec desc[] = {
	SPEC("flag", NULL, 1, 0, NULL), SPEC("nflag", NULL, 2, fs_param_neg_with_no, NULL), SPEC("bool", fs_param_is_bool, 3, 0, NULL), SPEC("boolE", fs_param_is_bool, 4, fs_param_can_be_empty, NULL),
	SPEC("u32", fs_param_is_u32, 5, 0, (void *)0), SPEC("oct", fs_param_is_u32, 6, 0, (void *)8), SPEC("dec", fs_param_is_u32, 7, fs_param_can_be_empty, (void *)10), SPEC("hex", fs_param_is_u32, 8, 0, (void *)16),
	SPEC("s32", fs_param_is_s32, 9, 0, NULL), SPEC("u64", fs_param_is_u64, 10, fs_param_can_be_empty, NULL), SPEC("enum", fs_param_is_enum, 11, 0, fruit), SPEC("str", fs_param_is_string, 12, 0, NULL),
	SPEC("strE", fs_param_is_string, 13, fs_param_can_be_empty, NULL), SPEC("blob", fs_param_is_blob, 14, 0, NULL), SPEC("fd", fs_param_is_fd, 15, 0, NULL), SPEC("fdE", fs_param_is_fd, 16, fs_param_can_be_empty, NULL),
	SPEC("fos", fs_param_is_file_or_string, 17, 0, NULL), SPEC("uid", fs_param_is_uid, 18, 0, NULL), SPEC("gid", fs_param_is_gid, 19, 0, NULL), SPEC("old", fs_param_is_u32, 20, fs_param_deprecated, (void *)0),
	SPEC("both", NULL, 21, 0, NULL), SPEC("both", fs_param_is_string, 22, 0, NULL), SPEC("onlyval", fs_param_is_u32, 23, fs_param_neg_with_no, (void *)0), SPEC("nflag2", NULL, 24, 0, NULL), SPEC("blk", dummy_blockdev, 25, 0, NULL), SPEC("", NULL, 26, fs_param_neg_with_no, NULL), { }
};
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static const char *values[] = { "", "0", "1", "7", "10", "0x1f", "0755", "017", "08", "12abc", "-5", "+5", "4294967295", "4294967296", "2147483647", "2147483648", "-2147483648", "99999999999999999999", "18446744073709551615", "apple", "pear", "fig", "none", "yes", "no", "true", "false", " 5", "5\n", "5 ", "ff", "FF", "0xFF", "100", "99", "101" };
static const char *keys[] = { "flag", "noflag", "nflag", "nonflag", "nflag2", "nonflag2", "bool", "nobool", "boolE", "u32", "oct", "dec", "hex", "s32", "u64", "enum", "str", "strE", "blob", "fd", "fdE", "fos", "uid", "gid", "old", "both", "noboth", "onlyval", "noonlyval", "no", "n", "nox", "blk", "missing", "" };
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 150000, it, pc = 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		struct fs_parameter par; struct fs_parse_result res; struct p_log log = { rnd(3) ? "fs" : NULL, NULL }; int rc; char sbuf[64]; static char blob[4] = "bl"; static int filedummy;
		memset(&par, 0, sizeof par); memset(&res, 0x5a, sizeof res);
		par.key = rnd(8) == 0 ? "" : keys[rnd(sizeof keys / sizeof *keys)];
		switch (rnd(8)) {
		case 0: par.type = fs_value_is_flag; break;
		case 1: case 2: case 3: case 4: par.type = fs_value_is_string; strcpy(sbuf, values[rnd(sizeof values / sizeof *values)]); par.string = sbuf; break;
		case 5: par.type = fs_value_is_blob; par.blob = blob; par.size = 2; break;
		case 6: par.type = fs_value_is_file; par.file = &filedummy; par.dirfd = rnd(4) == 0 ? -1 : rnd(3) == 0 ? (int)rnd64() : rnd(100); break;
		default: par.type = fs_value_is_undefined; break;
		}
		uid_limit = rnd(3) ? 100 : 5000;
		rc = __fs_parse(&log, desc, &par, &res); if (prove && pc++ == 3) rc++;
		printf("%ld %s type=%d -> %d neg=%d v32=%u v64=%llu hi=%08x\n", it, par.key, par.type, rc, res.negated, res.uint_32, (unsigned long long)res.uint_64, (unsigned)(res.uint_64 >> 32));
		if (rnd(6) == 0) printf("  const %d %d %d\n", lookup_constant(fruit, values[rnd(sizeof values / sizeof *values)], -7), lookup_constant(bool_names, values[rnd(sizeof values / sizeof *values)], -1), lookup_constant(fruit, "", 5));
	}
	return 0;
}
