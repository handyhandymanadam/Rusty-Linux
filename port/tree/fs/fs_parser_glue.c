// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RUST PORT (fs/fs_parser.c, 6.18.49): the parsing logic is in fs_parser_rs.rs; the exported functions stay here as thunks (so their MODVERSIONS fingerprints keep coming from the C
 * definitions), with the printf-style log messages, make_kuid / make_kgid and the bit-field accessors as rust_fp_* wrappers. Upstream's whole file is installed as fs_parser_norust.c for CONFIG_RUST=n.
 */
/* Filesystem parameter parser.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/namei.h>
#include "internal.h"

const struct constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "false",	false },
	{ "no",		false },
	{ "true",	true },
	{ "yes",	true },
	{ },
};
EXPORT_SYMBOL(bool_names);

/* RUST-WRAPPERS BEGIN: the parsing logic is in fs_parser_rs.rs; the exported functions below are thunks over it. */
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

/**
 * lookup_constant - Look up a constant by name in an ordered table
 * @tbl: The table of constants to search.
 * @name: The name to look up.
 * @not_found: The value to return if the name is not found.
 */
int lookup_constant(const struct constant_table *tbl, const char *name, int not_found)
{
	return rust_lookup_constant(tbl, name, not_found);
}
EXPORT_SYMBOL(lookup_constant);

/*
 * __fs_parse - Parse a filesystem configuration parameter
 * @log: The filesystem context to log errors through.
 * @desc: The parameter description to use.
 * @param: The parameter.
 * @result: Where to place the result of the parse
 *
 * Parse a filesystem configuration parameter and attempt a conversion for a
 * simple parameter for which this is requested.  If successful, the determined
 * parameter ID is placed into @result->key, the desired type is indicated in
 * @result->t and any converted value is placed into an appropriate member of
 * the union in @result.
 *
 * The function returns the parameter number if the parameter was matched,
 * -ENOPARAM if it wasn't matched and @desc->ignore_unknown indicated that
 * unknown parameters are okay and -EINVAL if there was a conversion issue or
 * the parameter wasn't recognised and unknowns aren't okay.
 */
int __fs_parse(struct p_log *log,
	     const struct fs_parameter_spec *desc,
	     struct fs_parameter *param,
	     struct fs_parse_result *result)
{
	return rust___fs_parse(log, desc, param, result);
}
EXPORT_SYMBOL(__fs_parse);

/**
 * fs_lookup_param - Look up a path referred to by a parameter
 * @fc: The filesystem context to log errors through.
 * @param: The parameter.
 * @want_bdev: T if want a blockdev
 * @flags: Pathwalk flags passed to filename_lookup()
 * @_path: The result of the lookup
 */
int fs_lookup_param(struct fs_context *fc,
		    struct fs_parameter *param,
		    bool want_bdev,
		    unsigned int flags,
		    struct path *_path)
{
	struct filename *f;
	bool put_f;
	int ret;

	switch (param->type) {
	case fs_value_is_string:
		f = getname_kernel(param->string);
		if (IS_ERR(f))
			return PTR_ERR(f);
		param->dirfd = AT_FDCWD;
		put_f = true;
		break;
	case fs_value_is_filename:
		f = param->name;
		put_f = false;
		break;
	default:
		return invalf(fc, "%s: not usable as path", param->key);
	}

	ret = filename_lookup(param->dirfd, f, flags, _path, NULL);
	if (ret < 0) {
		errorf(fc, "%s: Lookup failure for '%s'", param->key, f->name);
		goto out;
	}

	if (want_bdev &&
	    !S_ISBLK(d_backing_inode(_path->dentry)->i_mode)) {
		path_put(_path);
		_path->dentry = NULL;
		_path->mnt = NULL;
		errorf(fc, "%s: Non-blockdev passed as '%s'",
		       param->key, f->name);
		ret = -ENOTBLK;
	}

out:
	if (put_f)
		putname(f);
	return ret;
}
EXPORT_SYMBOL(fs_lookup_param);

int fs_param_is_bool(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_bool(log, p, param, result, bool_names);
}
EXPORT_SYMBOL(fs_param_is_bool);

int fs_param_is_u32(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_u32(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_u32);

int fs_param_is_s32(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_s32(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_s32);

int fs_param_is_u64(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_u64(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_u64);

int fs_param_is_enum(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_enum(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_enum);

int fs_param_is_string(struct p_log *log, const struct fs_parameter_spec *p,
		       struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_string(log, p, param);
}
EXPORT_SYMBOL(fs_param_is_string);

int fs_param_is_blob(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_blob(log, param);
}
EXPORT_SYMBOL(fs_param_is_blob);

int fs_param_is_fd(struct p_log *log, const struct fs_parameter_spec *p,
		  struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_fd(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_fd);

int fs_param_is_file_or_string(struct p_log *log,
			       const struct fs_parameter_spec *p,
			       struct fs_parameter *param,
			       struct fs_parse_result *result)
{
	return rust_fs_param_is_file_or_string(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_file_or_string);

int fs_param_is_uid(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_uid(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_uid);

int fs_param_is_gid(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	return rust_fs_param_is_gid(log, p, param, result);
}
EXPORT_SYMBOL(fs_param_is_gid);

int fs_param_is_blockdev(struct p_log *log, const struct fs_parameter_spec *p,
		  struct fs_parameter *param, struct fs_parse_result *result)
{
	return 0;
}
EXPORT_SYMBOL(fs_param_is_blockdev);

int fs_param_is_path(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	return 0;
}
EXPORT_SYMBOL(fs_param_is_path);

#ifdef CONFIG_VALIDATE_FS_PARSER
/**
 * fs_validate_description - Validate a parameter specification array
 * @name: Owner name of the parameter specification array
 * @desc: The parameter specification array to validate.
 */
bool fs_validate_description(const char *name,
	const struct fs_parameter_spec *desc)
{
	const struct fs_parameter_spec *param, *p2;
	bool good = true;

	for (param = desc; param->name; param++) {
		/* Check for duplicate parameter names */
		for (p2 = desc; p2 < param; p2++) {
			if (strcmp(param->name, p2->name) == 0) {
				if (is_flag(param) != is_flag(p2))
					continue;
				pr_err("VALIDATE %s: PARAM[%s]: Duplicate\n",
				       name, param->name);
				good = false;
			}
		}
	}
	return good;
}
#endif /* CONFIG_VALIDATE_FS_PARSER */
