# SPDX-License-Identifier: GPL-2.0
#
# Cryptographic API
#

obj-$(CONFIG_CRYPTO) += crypto.o
crypto-y := api.o cipher.o

obj-$(CONFIG_CRYPTO_ENGINE) += crypto_engine.o
obj-$(CONFIG_CRYPTO_FIPS) += fips.o

crypto_algapi-$(CONFIG_PROC_FS) += proc.o
crypto_algapi-y := algapi.o scatterwalk.o $(crypto_algapi-y)
obj-$(CONFIG_CRYPTO_ALGAPI2) += crypto_algapi.o

obj-$(CONFIG_CRYPTO_AEAD2) += aead.o
obj-$(CONFIG_CRYPTO_GENIV) += geniv.o

crypto_skcipher-y += lskcipher.o
crypto_skcipher-y += skcipher.o

obj-$(CONFIG_CRYPTO_SKCIPHER2) += crypto_skcipher.o
ifeq ($(CONFIG_BPF_SYSCALL),y)
obj-$(CONFIG_CRYPTO_SKCIPHER2) += bpf_crypto_skcipher.o
endif

obj-$(CONFIG_CRYPTO_SEQIV) += seqiv.o
obj-$(CONFIG_CRYPTO_ECHAINIV) += echainiv.o

crypto_hash-y += ahash.o
crypto_hash-y += shash.o
obj-$(CONFIG_CRYPTO_HASH2) += crypto_hash.o

obj-$(CONFIG_CRYPTO_AKCIPHER2) += akcipher.o
obj-$(CONFIG_CRYPTO_SIG2) += sig.o
obj-$(CONFIG_CRYPTO_KPP2) += kpp.o
obj-$(CONFIG_CRYPTO_HKDF) += hkdf.o

dh_generic-y := dh.o
dh_generic-y += dh_helper.o
obj-$(CONFIG_CRYPTO_DH) += dh_generic.o

$(obj)/rsapubkey.asn1.o: $(obj)/rsapubkey.asn1.c $(obj)/rsapubkey.asn1.h
$(obj)/rsaprivkey.asn1.o: $(obj)/rsaprivkey.asn1.c $(obj)/rsaprivkey.asn1.h
$(obj)/rsa_helper.o: $(obj)/rsapubkey.asn1.h $(obj)/rsaprivkey.asn1.h
$(obj)/rsa_helper_glue.o: $(obj)/rsapubkey.asn1.h $(obj)/rsaprivkey.asn1.h
$(obj)/rsa_helper_norust.o: $(obj)/rsapubkey.asn1.h $(obj)/rsaprivkey.asn1.h

rsa_generic-y := rsapubkey.asn1.o
rsa_generic-y += rsaprivkey.asn1.o
# rsa.o is replaced when CONFIG_RUST by rsa_glue.o (upstream's file: the akcipher_alg table, rsa_init/exit and
# one-line wrappers) + rsa_rs.o (the RSA primitive, key loading and size rules). CONFIG_RUST=n builds upstream's
# file, installed byte-identical as rsa_norust.c by rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
rsa_generic-y += rsa_glue.o rsa_rs.o
else
rsa_generic-y += rsa_norust.o
endif
# rsa_helper is a composite when CONFIG_RUST: rsa_helper_glue.o keeps the two exported parse entry
# points (one asn1_ber_decoder() call each), rsa_helper_rs.o holds the eight rsa_get_* ASN.1 field
# callbacks. CONFIG_RUST=n builds upstream's file, installed byte-identical as rsa_helper_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
rsa_generic-y += rsa_helper_glue.o rsa_helper_rs.o
else
rsa_generic-y += rsa_helper_norust.o
endif
rsa_generic-y += rsa-pkcs1pad.o
rsa_generic-y += rsassa-pkcs1.o
obj-$(CONFIG_CRYPTO_RSA) += rsa_generic.o

$(obj)/ecdsasignature.asn1.o: $(obj)/ecdsasignature.asn1.c $(obj)/ecdsasignature.asn1.h
$(obj)/ecdsa-x962.o: $(obj)/ecdsasignature.asn1.h
ecdsa_generic-y += ecdsa.o
ecdsa_generic-y += ecdsa-x962.o
ecdsa_generic-y += ecdsa-p1363.o
ecdsa_generic-y += ecdsasignature.asn1.o
obj-$(CONFIG_CRYPTO_ECDSA) += ecdsa_generic.o

crypto_acompress-y := acompress.o
crypto_acompress-y += scompress.o
obj-$(CONFIG_CRYPTO_ACOMP2) += crypto_acompress.o

cryptomgr-y := algboss.o testmgr.o

obj-$(CONFIG_CRYPTO_MANAGER2) += cryptomgr.o
obj-$(CONFIG_CRYPTO_USER) += crypto_user.o
obj-$(CONFIG_CRYPTO_CMAC) += cmac.o
# cmac.o is a composite when CONFIG_RUST: cmac_glue.o is upstream's file with the
# subkey derivation and the final-block xor replaced by calls, cmac_rs.o holds them.
# CONFIG_RUST=n builds upstream's file, installed byte-identical as cmac_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
cmac-y += cmac_glue.o cmac_rs.o
else
cmac-y += cmac_norust.o
endif
obj-$(CONFIG_CRYPTO_HMAC) += hmac.o
# hmac.o is a composite when CONFIG_RUST: hmac_glue.o is upstream's file with the
# duplicated ipad/opad derivation replaced by a call, hmac_rs.o holds that
# derivation. CONFIG_RUST=n builds upstream's file, installed byte-identical as
# hmac_norust.c by rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
hmac-y += hmac_glue.o hmac_rs.o
else
hmac-y += hmac_norust.o
endif
obj-$(CONFIG_CRYPTO_XCBC) += xcbc.o
obj-$(CONFIG_CRYPTO_NULL) += crypto_null.o
obj-$(CONFIG_CRYPTO_MD4) += md4.o
obj-$(CONFIG_CRYPTO_MD5) += md5.o
# md5.o is a composite when CONFIG_RUST: md5_glue.o keeps the shash_alg table,
# module glue and one-line callbacks, md5_shash_rs.o holds the state
# import/export bodies and the exported md5_zero_message_hash. CONFIG_RUST=n
# builds upstream's file, installed byte-identical as md5_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
md5-y += md5_glue.o md5_shash_rs.o
else
md5-y += md5_norust.o
endif
obj-$(CONFIG_CRYPTO_RMD160) += rmd160.o
obj-$(CONFIG_CRYPTO_SHA1) += sha1.o
obj-$(CONFIG_CRYPTO_SHA256) += sha256.o
# sha256.o is a composite when CONFIG_RUST: sha256_glue.o keeps the shash_alg
# table, module glue, one-line callbacks and the zero-message hash tables,
# sha256_shash_rs.o holds the state import/export bodies. CONFIG_RUST=n builds
# upstream's file, installed byte-identical as sha256_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
sha256-y += sha256_glue.o sha256_shash_rs.o
else
sha256-y += sha256_norust.o
endif
obj-$(CONFIG_CRYPTO_SHA512) += sha512.o
# sha512.o is a composite when CONFIG_RUST: sha512_glue.o keeps the shash_alg
# table, module glue, one-line callbacks and the zero-message hash tables,
# sha512_shash_rs.o holds the state import/export bodies. CONFIG_RUST=n builds
# upstream's file, installed byte-identical as sha512_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
sha512-y += sha512_glue.o sha512_shash_rs.o
else
sha512-y += sha512_norust.o
endif
obj-$(CONFIG_CRYPTO_SHA3) += sha3_generic.o
obj-$(CONFIG_CRYPTO_SM3_GENERIC) += sm3_generic.o
obj-$(CONFIG_CRYPTO_STREEBOG) += streebog_generic.o
obj-$(CONFIG_CRYPTO_WP512) += wp512.o
CFLAGS_wp512.o := $(call cc-option,-fno-schedule-insns)  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=79149
obj-$(CONFIG_CRYPTO_BLAKE2B) += blake2b_generic.o
CFLAGS_blake2b_generic.o := -Wframe-larger-than=4096 #  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105930
obj-$(CONFIG_CRYPTO_ECB) += ecb.o
# ecb.o is a composite when CONFIG_RUST: ecb_glue.o is upstream's file with the block loop of
# crypto_ecb_crypt() replaced by a call, ecb_rs.o holds the loop. CONFIG_RUST=n builds upstream's
# file, installed byte-identical as ecb_norust.c by rig/apply.sh from port/pristine/
# (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
ecb-y += ecb_glue.o ecb_rs.o
else
ecb-y += ecb_norust.o
endif
obj-$(CONFIG_CRYPTO_CBC) += cbc.o
# cbc.o is a composite when CONFIG_RUST: cbc_glue.o is upstream's file with the four chaining loops
# replaced by calls, cbc_rs.o holds them. CONFIG_RUST=n builds upstream's file, installed
# byte-identical as cbc_norust.c by rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
cbc-y += cbc_glue.o cbc_rs.o
else
cbc-y += cbc_norust.o
endif
obj-$(CONFIG_CRYPTO_PCBC) += pcbc.o
obj-$(CONFIG_CRYPTO_CTS) += cts.o
obj-$(CONFIG_CRYPTO_LRW) += lrw.o
obj-$(CONFIG_CRYPTO_XTS) += xts.o
obj-$(CONFIG_CRYPTO_CTR) += ctr.o
# ctr.o is a composite when CONFIG_RUST: ctr_glue.o is upstream's file with the block
# loops and the RFC 3686 counter block replaced by calls, ctr_rs.o holds them.
# CONFIG_RUST=n builds upstream's file, installed byte-identical as ctr_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
ctr-y += ctr_glue.o ctr_rs.o
else
ctr-y += ctr_norust.o
endif
obj-$(CONFIG_CRYPTO_XCTR) += xctr.o
obj-$(CONFIG_CRYPTO_HCTR2) += hctr2.o
obj-$(CONFIG_CRYPTO_ADIANTUM) += adiantum.o
obj-$(CONFIG_CRYPTO_NHPOLY1305) += nhpoly1305.o
obj-$(CONFIG_CRYPTO_GCM) += gcm.o
obj-$(CONFIG_CRYPTO_CCM) += ccm.o
obj-$(CONFIG_CRYPTO_CHACHA20POLY1305) += chacha20poly1305.o
obj-$(CONFIG_CRYPTO_AEGIS128) += aegis128.o
aegis128-y := aegis128-core.o

ifeq ($(ARCH),arm)
CFLAGS_aegis128-neon-inner.o += -ffreestanding -march=armv8-a -mfloat-abi=softfp
CFLAGS_aegis128-neon-inner.o += -mfpu=crypto-neon-fp-armv8
aegis128-$(CONFIG_CRYPTO_AEGIS128_SIMD) += aegis128-neon.o aegis128-neon-inner.o
endif
ifeq ($(ARCH),arm64)
aegis128-cflags-y := -ffreestanding -mcpu=generic+crypto
aegis128-cflags-$(CONFIG_CC_IS_GCC) += -ffixed-q16 -ffixed-q17 -ffixed-q18 \
				       -ffixed-q19 -ffixed-q20 -ffixed-q21 \
				       -ffixed-q22 -ffixed-q23 -ffixed-q24 \
				       -ffixed-q25 -ffixed-q26 -ffixed-q27 \
				       -ffixed-q28 -ffixed-q29 -ffixed-q30 \
				       -ffixed-q31
CFLAGS_aegis128-neon-inner.o += $(aegis128-cflags-y)
CFLAGS_REMOVE_aegis128-neon-inner.o += -mgeneral-regs-only
aegis128-$(CONFIG_CRYPTO_AEGIS128_SIMD) += aegis128-neon.o aegis128-neon-inner.o
endif
# Enable <arm_neon.h>
CFLAGS_aegis128-neon-inner.o += -isystem $(shell $(CC) -print-file-name=include)

obj-$(CONFIG_CRYPTO_PCRYPT) += pcrypt.o
obj-$(CONFIG_CRYPTO_CRYPTD) += cryptd.o
obj-$(CONFIG_CRYPTO_DES) += des_generic.o
obj-$(CONFIG_CRYPTO_FCRYPT) += fcrypt.o
obj-$(CONFIG_CRYPTO_BLOWFISH) += blowfish_generic.o
obj-$(CONFIG_CRYPTO_BLOWFISH_COMMON) += blowfish_common.o
obj-$(CONFIG_CRYPTO_TWOFISH) += twofish_generic.o
obj-$(CONFIG_CRYPTO_TWOFISH_COMMON) += twofish_common.o
obj-$(CONFIG_CRYPTO_SERPENT) += serpent_generic.o
CFLAGS_serpent_generic.o := $(call cc-option,-fsched-pressure)  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=79149
obj-$(CONFIG_CRYPTO_AES) += aes_generic.o
CFLAGS_aes_generic.o := $(call cc-option,-fno-code-hoisting) # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83356
CFLAGS_aes_generic_glue.o := $(call cc-option,-fno-code-hoisting) # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83356
CFLAGS_aes_generic_norust.o := $(call cc-option,-fno-code-hoisting) # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83356
obj-$(CONFIG_CRYPTO_SM4) += sm4.o
obj-$(CONFIG_CRYPTO_SM4_GENERIC) += sm4_generic.o
obj-$(CONFIG_CRYPTO_AES_TI) += aes_ti.o
obj-$(CONFIG_CRYPTO_CAMELLIA) += camellia_generic.o
obj-$(CONFIG_CRYPTO_CAST_COMMON) += cast_common.o
obj-$(CONFIG_CRYPTO_CAST5) += cast5_generic.o
obj-$(CONFIG_CRYPTO_CAST6) += cast6_generic.o
obj-$(CONFIG_CRYPTO_ARC4) += arc4.o
obj-$(CONFIG_CRYPTO_TEA) += tea.o
obj-$(CONFIG_CRYPTO_KHAZAD) += khazad.o
obj-$(CONFIG_CRYPTO_ANUBIS) += anubis.o
obj-$(CONFIG_CRYPTO_SEED) += seed.o
obj-$(CONFIG_CRYPTO_ARIA) += aria_generic.o
obj-$(CONFIG_CRYPTO_CHACHA20) += chacha.o
CFLAGS_chacha.o += -DARCH=$(ARCH)
obj-$(CONFIG_CRYPTO_DEFLATE) += deflate.o
obj-$(CONFIG_CRYPTO_MICHAEL_MIC) += michael_mic.o
obj-$(CONFIG_CRYPTO_CRC32C) += crc32c-cryptoapi.o
crc32c-cryptoapi-y := crc32c.o
obj-$(CONFIG_CRYPTO_CRC32) += crc32-cryptoapi.o
crc32-cryptoapi-y := crc32.o
obj-$(CONFIG_CRYPTO_AUTHENC) += authenc.o authencesn.o
obj-$(CONFIG_CRYPTO_KRB5ENC) += krb5enc.o
obj-$(CONFIG_CRYPTO_LZO) += lzo.o lzo-rle.o
obj-$(CONFIG_CRYPTO_LZ4) += lz4.o
obj-$(CONFIG_CRYPTO_LZ4HC) += lz4hc.o
obj-$(CONFIG_CRYPTO_XXHASH) += xxhash_generic.o
obj-$(CONFIG_CRYPTO_842) += 842.o
obj-$(CONFIG_CRYPTO_RNG2) += rng.o
obj-$(CONFIG_CRYPTO_ANSI_CPRNG) += ansi_cprng.o
obj-$(CONFIG_CRYPTO_DRBG) += drbg.o
obj-$(CONFIG_CRYPTO_JITTERENTROPY) += jitterentropy_rng.o
CFLAGS_jitterentropy.o = -O0
KASAN_SANITIZE_jitterentropy.o = n
UBSAN_SANITIZE_jitterentropy.o = n
jitterentropy_rng-y := jitterentropy.o jitterentropy-kcapi.o
obj-$(CONFIG_CRYPTO_JITTERENTROPY_TESTINTERFACE) += jitterentropy-testing.o
obj-$(CONFIG_CRYPTO_BENCHMARK) += tcrypt.o
obj-$(CONFIG_CRYPTO_GHASH) += ghash-generic.o
obj-$(CONFIG_CRYPTO_POLYVAL) += polyval-generic.o
obj-$(CONFIG_CRYPTO_USER_API) += af_alg.o
obj-$(CONFIG_CRYPTO_USER_API_HASH) += algif_hash.o
obj-$(CONFIG_CRYPTO_USER_API_SKCIPHER) += algif_skcipher.o
obj-$(CONFIG_CRYPTO_USER_API_RNG) += algif_rng.o
obj-$(CONFIG_CRYPTO_USER_API_AEAD) += algif_aead.o
obj-$(CONFIG_CRYPTO_ZSTD) += zstd.o
obj-$(CONFIG_CRYPTO_ECC) += ecc.o
obj-$(CONFIG_CRYPTO_ESSIV) += essiv.o

ecdh_generic-y += ecdh.o
ecdh_generic-y += ecdh_helper.o
obj-$(CONFIG_CRYPTO_ECDH) += ecdh_generic.o

$(obj)/ecrdsa_params.asn1.o: $(obj)/ecrdsa_params.asn1.c $(obj)/ecrdsa_params.asn1.h
$(obj)/ecrdsa_pub_key.asn1.o: $(obj)/ecrdsa_pub_key.asn1.c $(obj)/ecrdsa_pub_key.asn1.h
$(obj)/ecrdsa.o: $(obj)/ecrdsa_params.asn1.h $(obj)/ecrdsa_pub_key.asn1.h
ecrdsa_generic-y += ecrdsa.o
ecrdsa_generic-y += ecrdsa_params.asn1.o
ecrdsa_generic-y += ecrdsa_pub_key.asn1.o
obj-$(CONFIG_CRYPTO_ECRDSA) += ecrdsa_generic.o

#
# generic algorithms and the async_tx api
#
obj-$(CONFIG_XOR_BLOCKS) += xor.o
obj-$(CONFIG_ASYNC_CORE) += async_tx/
obj-$(CONFIG_ASYMMETRIC_KEY_TYPE) += asymmetric_keys/
crypto_simd-y := simd.o
obj-$(CONFIG_CRYPTO_SIMD) += crypto_simd.o

#
# Key derivation function
#
obj-$(CONFIG_CRYPTO_KDF800108_CTR) += kdf_sp800108.o

obj-$(CONFIG_CRYPTO_KRB5) += krb5/

# sha3_generic.o is a composite when CONFIG_RUST: sha3_glue.o keeps the
# shash_alg table, module glue, the three entry functions and the
# EXPORT_SYMBOL(crypto_sha3_init); sha3_rs.o holds Keccak-f[1600], absorb,
# padding and squeeze. CONFIG_RUST=n builds upstream's file, installed
# byte-identical as sha3_generic_norust.c by rig/apply.sh from port/pristine/.
ifdef CONFIG_RUST
sha3_generic-y += sha3_glue.o sha3_rs.o
else
sha3_generic-y += sha3_generic_norust.o
endif

# lzo.o is a composite when CONFIG_RUST: lzo_glue.o keeps the scomp_alg table,
# module glue, alloc_ctx/free_ctx (kvmalloc is a macro) and the callbacks;
# lzo_rs.o holds the compress/decompress helpers. CONFIG_RUST=n builds upstream's
# file, installed byte-identical as lzo_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
lzo-y += lzo_glue.o lzo_rs.o
else
lzo-y += lzo_norust.o
endif

# lzo-rle.o: same shape as lzo.o above (lzorle_glue.o + lzorle_rs.o; norust arm
# is the pristine file installed as lzo-rle_norust.c).
ifdef CONFIG_RUST
lzo-rle-y += lzorle_glue.o lzorle_rs.o
else
lzo-rle-y += lzo-rle_norust.o
endif

# aes_generic.o is a composite when CONFIG_RUST: aes_generic_glue.o keeps the
# EXPORT_SYMBOL_GPL tables crypto_ft_tab/crypto_it_tab, crypto_aes_set_key, the
# crypto_alg table, module glue and one-line callbacks; aes_generic_rs.o holds
# the block encrypt/decrypt and the private last-round tables. CONFIG_RUST=n
# builds upstream's file, installed byte-identical as aes_generic_norust.c by
# rig/apply.sh from port/pristine/. The object name stays aes_generic.o.
ifdef CONFIG_RUST
aes_generic-y += aes_generic_glue.o aes_generic_rs.o
else
aes_generic-y += aes_generic_norust.o
endif

# ghash-generic.o: composite when CONFIG_RUST (ghash_glue.o = shash_alg table,
# module glue and the five callbacks; ghash_rs.o = block loop, setkey protocol,
# exit). The GF(2^128) multiply is lib/crypto/gf128mul.c, still C.
ifdef CONFIG_RUST
ghash-generic-y += ghash_glue.o ghash_rs.o
else
ghash-generic-y += ghash-generic_norust.o
endif
