/* The PRISTINE crypto/aes_generic.c block code (sliced), exported names renamed by
 * run.sh (-D) so it can sit beside the glue's data. */
#include "shim.h"
#include "SLICE"
void ref_enc(struct crypto_aes_ctx *c, u8 *o, const u8 *i) { struct crypto_tfm t = { c }; crypto_aes_encrypt(&t, o, i); }
void ref_dec(struct crypto_aes_ctx *c, u8 *o, const u8 *i) { struct crypto_tfm t = { c }; crypto_aes_decrypt(&t, o, i); }
u32 ref_ft(unsigned k, unsigned x) { return crypto_ft_tab[k][x]; }
u32 ref_it(unsigned k, unsigned x) { return crypto_it_tab[k][x]; }
u32 ref_fl(unsigned k, unsigned x) { return crypto_fl_tab[k][x]; }
u32 ref_il(unsigned k, unsigned x) { return crypto_il_tab[k][x]; }
