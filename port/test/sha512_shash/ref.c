/* The pristine crypto/sha512.c helpers, compiled as-is (extracted), exposed. */
#include <crypto/sha2.h>
#include <linux/string.h>
#include <stddef.h>
#include "EXTRACT"
int c_export(const struct __sha512_ctx *c, void *o) { return __crypto_sha512_export(c, o); }
int c_import(struct __sha512_ctx *c, const void *i) { return __crypto_sha512_import(c, i); }
int c_export_core(const struct __sha512_ctx *c, void *o) { return __crypto_sha512_export_core(c, o); }
int c_import_core(struct __sha512_ctx *c, const void *i) { return __crypto_sha512_import_core(c, i); }
