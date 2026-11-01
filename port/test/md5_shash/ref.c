/* The pristine crypto/md5.c helpers, compiled as-is (extracted), exposed. */
#include <crypto/md5.h>
#include <linux/string.h>
#include <stddef.h>
#include "EXTRACT"
int c_export(const struct md5_ctx *c, void *o) { return __crypto_md5_export(c, o); }
int c_import(struct md5_ctx *c, const void *i) { return __crypto_md5_import(c, i); }
int c_export_core(const struct md5_ctx *c, void *o) { return __crypto_md5_export_core(c, o); }
int c_import_core(struct md5_ctx *c, const void *i) { return __crypto_md5_import_core(c, i); }
