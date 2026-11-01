/* The real glue slice (ft/it data + crypto_aes_set_key + the C thunks) over the shim,
 * linked against the Rust crypto_aes_rs_encrypt/decrypt. */
#include "shim.h"
void crypto_aes_rs_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void crypto_aes_rs_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
#include "SLICE"
void subj_enc(struct crypto_aes_ctx *c, u8 *o, const u8 *i) { struct crypto_tfm t = { c }; crypto_aes_encrypt(&t, o, i); }
void subj_dec(struct crypto_aes_ctx *c, u8 *o, const u8 *i) { struct crypto_tfm t = { c }; crypto_aes_decrypt(&t, o, i); }
int subj_setkey(struct crypto_aes_ctx *c, const u8 *k, unsigned n) { struct crypto_tfm t = { c }; return crypto_aes_set_key(&t, k, n); }
u32 subj_ft(unsigned k, unsigned x) { return crypto_ft_tab[k][x]; }
u32 subj_it(unsigned k, unsigned x) { return crypto_it_tab[k][x]; }
