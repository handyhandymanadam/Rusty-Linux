#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- fs_parser_glue.c = upstream fs/fs_parser.c with lookup_constant(), __fs_parse() and the fs_param_is_*() converters turned into thunks over fs_parser_rs.rs, plus the
rust_fp_* wrappers. bool_names, fs_lookup_param() and fs_validate_description() are upstream's."""
import sys
s = open(sys.argv[1]).read()
def body(sig_start, new_body):
    global s
    a = s.index(sig_start); b = s.index("{", a); e = s.index("\n}\n", b) + 3
    s = s[:b] + new_body + s[e - 2:]
# the static helpers are gone with their users
for sig in ("static const struct constant_table *\n__lookup_constant(", "static inline bool is_flag(", "static const struct fs_parameter_spec *fs_lookup_key(", "static int fs_param_bad_value("):
    a = s.index(sig); e = s.index("\n}\n", a) + 3
    # drop a preceding doc comment block if it belongs to the function
    s = s[:a] + s[e:].lstrip("\n")
body("int lookup_constant(", "{\n\treturn rust_lookup_constant(tbl, name, not_found);\n")
body("int __fs_parse(", "{\n\treturn rust___fs_parse(log, desc, param, result);\n")
body("int fs_param_is_bool(", "{\n\treturn rust_fs_param_is_bool(log, p, param, result, bool_names);\n")
for fn in ("u32", "s32", "u64", "enum", "uid", "gid", "fd"):
    sig = "int fs_param_is_%s(" % fn
    body(sig, "{\n\treturn rust_fs_param_is_%s(log, p, param, result);\n" % fn)
body("int fs_param_is_string(", "{\n\treturn rust_fs_param_is_string(log, p, param);\n")
body("int fs_param_is_blob(", "{\n\treturn rust_fs_param_is_blob(log, param);\n")
body("int fs_param_is_file_or_string(", "{\n\treturn rust_fs_param_is_file_or_string(log, p, param, result);\n")
wr = r'''/* RUST-WRAPPERS BEGIN: the parsing logic is in fs_parser_rs.rs; the exported functions below are thunks over it. */
int rust_lookup_constant(const struct constant_table *tbl, const char *name, int not_found);
int rust___fs_parse(struct p_log *log, const struct fs_parameter_spec *desc, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_bool(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result, const struct constant_table *bool_names);
int rust_fs_param_is_u32(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_s32(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_u64(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_enum(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_string(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param);
int rust_fs_param_is_blob(struct p_log *log, struct fs_parameter *param);
int rust_fs_param_is_fd(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_file_or_string(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_uid(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);
int rust_fs_param_is_gid(struct p_log *log, const struct fs_parameter_spec *p, struct fs_parameter *param, struct fs_parse_result *result);

int rust_fp_type(const struct fs_parameter *param);
const char *rust_fp_key(const struct fs_parameter *param);
const char *rust_fp_string(const struct fs_parameter *param);
int rust_fp_dirfd(const struct fs_parameter *param);
int rust_fp_inval(struct p_log *log, int which, const char *key);
void rust_fp_warn_deprecated(struct p_log *log, const char *key);
int rust_fp_make_kuid(u32 v, u32 *out);
int rust_fp_make_kgid(u32 v, u32 *out);

/* fs_parser_rs.rs hard-codes these layouts and values. */
static_assert(sizeof(struct constant_table) == 16 && offsetof(struct constant_table, name) == 0 && offsetof(struct constant_table, value) == 8);
static_assert(sizeof(struct fs_parameter_spec) == 32 && offsetof(struct fs_parameter_spec, name) == 0 && offsetof(struct fs_parameter_spec, type) == 8 && offsetof(struct fs_parameter_spec, opt) == 16 &&
	      offsetof(struct fs_parameter_spec, flags) == 18 && offsetof(struct fs_parameter_spec, data) == 24);
static_assert(sizeof(struct fs_parse_result) == 16 && offsetof(struct fs_parse_result, negated) == 0 && offsetof(struct fs_parse_result, uint_64) == 8);
static_assert(fs_param_neg_with_no == 0x2 && fs_param_can_be_empty == 0x4 && fs_param_deprecated == 0x8);
static_assert(fs_value_is_flag == 1 && fs_value_is_string == 2 && fs_value_is_blob == 3 && fs_value_is_file == 5 && ENOPARAM == 519);

int rust_fp_type(const struct fs_parameter *param)
{
	return param->type;
}

const char *rust_fp_key(const struct fs_parameter *param)
{
	return param->key;
}

const char *rust_fp_string(const struct fs_parameter *param)
{
	return param->string;
}

int rust_fp_dirfd(const struct fs_parameter *param)
{
	return param->dirfd;
}

int rust_fp_inval(struct p_log *log, int which, const char *key)
{
	switch (which) {
	case 0:
		return inval_plog(log, "Unexpected value for '%s'", key);
	case 1:
		return inval_plog(log, "Bad value for '%s'", key);
	case 2:
		return inval_plog(log, "Invalid uid '%s'", key);
	default:
		return inval_plog(log, "Invalid gid '%s'", key);
	}
}

void rust_fp_warn_deprecated(struct p_log *log, const char *key)
{
	warn_plog(log, "Deprecated parameter '%s'", key);
}

int rust_fp_make_kuid(u32 v, u32 *out)
{
	kuid_t uid = make_kuid(current_user_ns(), v);

	if (!uid_valid(uid))
		return 0;
	*out = __kuid_val(uid);
	return 1;
}

int rust_fp_make_kgid(u32 v, u32 *out)
{
	kgid_t gid = make_kgid(current_user_ns(), v);

	if (!gid_valid(gid))
		return 0;
	*out = __kgid_val(gid);
	return 1;
}
/* RUST-WRAPPERS END */

'''
a = s.index("int lookup_constant(")
# insert before the doc comment that precedes lookup_constant
c = s.rindex("/**\n * lookup_constant", 0, a)
s = s[:c] + wr + s[c:]
note = "// SPDX-License-Identifier: GPL-2.0-or-later\n/*\n * RUST PORT (fs/fs_parser.c, 6.18.49): the parsing logic is in fs_parser_rs.rs; the exported functions stay here as thunks (so their MODVERSIONS fingerprints keep coming from the C\n * definitions), with the printf-style log messages, make_kuid / make_kgid and the bit-field accessors as rust_fp_* wrappers. Upstream's whole file is installed as fs_parser_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-or-later\n", note, 1)
open(sys.argv[2], "w").write(s)
