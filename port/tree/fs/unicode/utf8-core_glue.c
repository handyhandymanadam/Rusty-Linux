/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RUST PORT (fs/unicode/utf8-core.c, 6.18.49): the cursor loops of the comparison, folding and hashing functions are in utf8_core_rs.rs; the exported functions stay here as thunks
 * (so their MODVERSIONS fingerprints keep coming from the C definitions). Upstream's whole file is installed as utf8-core_norust.c for CONFIG_RUST=n.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/errno.h>
#include <linux/stringhash.h>

#include "utf8n.h"

/* RUST-WRAPPERS BEGIN: the cursor loops are in utf8_core_rs.rs; the exported functions below are thunks over it. */
int rust_utf8_validate(const struct unicode_map *um, const unsigned char *name, unsigned int len);
int rust_utf8_strncmp(const struct unicode_map *um, const unsigned char *name1, unsigned int len1, const unsigned char *name2, unsigned int len2);
int rust_utf8_strncasecmp(const struct unicode_map *um, const unsigned char *name1, unsigned int len1, const unsigned char *name2, unsigned int len2);
int rust_utf8_strncasecmp_folded(const struct unicode_map *um, const unsigned char *cf, const unsigned char *name, unsigned int len);
int rust_utf8_casefold(const struct unicode_map *um, const unsigned char *name, unsigned int len, unsigned char *dest, size_t dlen);
int rust_utf8_normalize(const struct unicode_map *um, const unsigned char *name, unsigned int len, unsigned char *dest, size_t dlen);
int rust_utf8_casefold_hash(const struct unicode_map *um, const void *salt, const unsigned char *name, unsigned int len, u32 *hash);
u32 rust_u8c_end_name_hash(unsigned long hash);

u32 rust_u8c_end_name_hash(unsigned long hash)
{
	return end_name_hash(hash);
}
/* RUST-WRAPPERS END */

int utf8_validate(const struct unicode_map *um, const struct qstr *str)
{
	return rust_utf8_validate(um, str->name, str->len);
}
EXPORT_SYMBOL(utf8_validate);

int utf8_strncmp(const struct unicode_map *um,
		 const struct qstr *s1, const struct qstr *s2)
{
	return rust_utf8_strncmp(um, s1->name, s1->len, s2->name, s2->len);
}
EXPORT_SYMBOL(utf8_strncmp);

int utf8_strncasecmp(const struct unicode_map *um,
		     const struct qstr *s1, const struct qstr *s2)
{
	return rust_utf8_strncasecmp(um, s1->name, s1->len, s2->name, s2->len);
}
EXPORT_SYMBOL(utf8_strncasecmp);

/* String cf is expected to be a valid UTF-8 casefolded
 * string.
 */
int utf8_strncasecmp_folded(const struct unicode_map *um,
			    const struct qstr *cf,
			    const struct qstr *s1)
{
	return rust_utf8_strncasecmp_folded(um, cf->name, s1->name, s1->len);
}
EXPORT_SYMBOL(utf8_strncasecmp_folded);

int utf8_casefold(const struct unicode_map *um, const struct qstr *str,
		  unsigned char *dest, size_t dlen)
{
	return rust_utf8_casefold(um, str->name, str->len, dest, dlen);
}
EXPORT_SYMBOL(utf8_casefold);

int utf8_casefold_hash(const struct unicode_map *um, const void *salt,
		       struct qstr *str)
{
	u32 hash;
	int rc = rust_utf8_casefold_hash(um, salt, str->name, str->len, &hash);

	if (!rc)
		str->hash = hash;
	return rc;
}
EXPORT_SYMBOL(utf8_casefold_hash);

int utf8_normalize(const struct unicode_map *um, const struct qstr *str,
		   unsigned char *dest, size_t dlen)
{
	return rust_utf8_normalize(um, str->name, str->len, dest, dlen);
}
EXPORT_SYMBOL(utf8_normalize);

static const struct utf8data *find_table_version(const struct utf8data *table,
		size_t nr_entries, unsigned int version)
{
	size_t i = nr_entries - 1;

	while (version < table[i].maxage)
		i--;
	if (version > table[i].maxage)
		return NULL;
	return &table[i];
}

struct unicode_map *utf8_load(unsigned int version)
{
	struct unicode_map *um;

	um = kzalloc(sizeof(struct unicode_map), GFP_KERNEL);
	if (!um)
		return ERR_PTR(-ENOMEM);
	um->version = version;

	um->tables = symbol_request(utf8_data_table);
	if (!um->tables)
		goto out_free_um;

	if (!utf8version_is_supported(um, version))
		goto out_symbol_put;
	um->ntab[UTF8_NFDI] = find_table_version(um->tables->utf8nfdidata,
			um->tables->utf8nfdidata_size, um->version);
	if (!um->ntab[UTF8_NFDI])
		goto out_symbol_put;
	um->ntab[UTF8_NFDICF] = find_table_version(um->tables->utf8nfdicfdata,
			um->tables->utf8nfdicfdata_size, um->version);
	if (!um->ntab[UTF8_NFDICF])
		goto out_symbol_put;
	return um;

out_symbol_put:
	symbol_put(utf8_data_table);
out_free_um:
	kfree(um);
	return ERR_PTR(-EINVAL);
}
EXPORT_SYMBOL(utf8_load);

void utf8_unload(struct unicode_map *um)
{
	if (um) {
		symbol_put(utf8_data_table);
		kfree(um);
	}
}
EXPORT_SYMBOL(utf8_unload);

/**
 * utf8_parse_version - Parse a UTF-8 version number from a string
 *
 * @version: input string
 *
 * Returns the parsed version on success, negative code on error
 */
int utf8_parse_version(char *version)
{
	substring_t args[3];
	unsigned int maj, min, rev;
	static const struct match_token token[] = {
		{1, "%d.%d.%d"},
		{0, NULL}
	};

	if (match_token(version, token, args) != 1)
		return -EINVAL;

	if (match_int(&args[0], &maj) || match_int(&args[1], &min) ||
	    match_int(&args[2], &rev))
		return -EINVAL;

	return UNICODE_AGE(maj, min, rev);
}
EXPORT_SYMBOL(utf8_parse_version);
