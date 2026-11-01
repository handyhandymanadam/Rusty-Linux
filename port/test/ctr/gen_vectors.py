#!/usr/bin/env python3
"""gen_vectors.py: print the vector tables of test_ctr() in lib/libtest.c, computed with `openssl enc -aes-N-ctr`
(OpenSSL: shares nothing with the kernel), and ASSERT that the NIST SP 800-38A F.5.1/F.5.3/F.5.5 published ciphertexts
and the RFC 3686 section 6 test vectors #1-#3 (published values) are what OpenSSL printed, so a wrong transcription of
either side fails here, not in the kernel.   usage: python3 gen_vectors.py > table.inc"""
import subprocess, sys
KEYS = {16: "2b7e151628aed2a6abf7158809cf4f3c",
        24: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        32: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"}
PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
NIST_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
CARRY_IV = bytes(range(12)) + bytes.fromhex("fffffffe")        # low 32 bits wrap after 2 blocks, carry into byte 11
WRAP_IV = b"\xff" * 16                                          # the whole 128-bit counter wraps to 0
PUB = {  # SP 800-38A F.5.1, F.5.3, F.5.5: 64-byte ciphertexts
    16: "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    24: "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    32: "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
}
RFC = [  # RFC 3686 section 6: (key, nonce, iv, plaintext, ciphertext)
    ("ae6852f8121067cc4bf7a5765577f39e", "00000030", "0000000000000000", bytes.fromhex("53696e676c6520626c6f636b206d7367"), "e4095d4fb7a7b3792d6175a3261311b8"),
    ("7e24067817fae0d743d6ce1f32539163", "006cb6db", "c0543b59da48d90b", bytes(range(32)), "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28"),
    ("7691be035e5020a8ac6e618529f9a0dc", "00e0017b", "27777f3f4a1786f0", bytes(range(36)), "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f"),
]
def ctr(key, iv, msg):
    r = subprocess.run(["openssl", "enc", f"-aes-{len(key)*8}-ctr", "-K", key.hex(), "-iv", iv.hex()], input=msg, capture_output=True, check=True)
    return r.stdout.hex()
def pattern(n): return bytes((i * 29 + 5) & 0xff for i in range(n))
print("/* ctr(aes): { key bytes, iv kind (0 NIST f0..ff, 1 carries out of the low 32 bits, 2 all 0xff), message kind (0 NIST prefix, 1 pattern), length, ciphertext } */")
print("static const struct ctr_vec ctr_vecs[] __initconst = {")
n = 0
for kb, kh in KEYS.items():
    key = bytes.fromhex(kh)
    ct = ctr(key, NIST_IV, PT)
    assert ct == PUB[kb], "NIST F.5 AES-%d mismatch: openssl %s" % (kb * 8, ct)
    for ivk, iv in ((0, NIST_IV), (1, CARRY_IV), (2, WRAP_IV)):
        for mk, ml in ((0, 64), (0, 33), (1, 1), (1, 15), (1, 16), (1, 17), (1, 48), (1, 100)):
            if ivk == 0 and (mk, ml) == (1, 48): continue
            msg = PT[:ml] if mk == 0 else pattern(ml)
            print('\t{ %d, %d, %d, %d, "%s" },' % (kb, ivk, mk, ml, ctr(key, iv, msg))); n += 1
print("};")
print("/* rfc3686(ctr(aes)): { key bytes (without nonce), nonce, iv, plaintext kind (0 = \"Single block msg\", 1 = 00 01 02 ..), length, ciphertext } */")
print("static const struct rfc3686_vec rfc3686_vecs[] __initconst = {")
for kh, nonce, ivh, pt, want in RFC:
    key = bytes.fromhex(kh)
    ct = ctr(key, bytes.fromhex(nonce) + bytes.fromhex(ivh) + b"\x00\x00\x00\x01", pt)
    assert ct == want, "RFC 3686 vector mismatch: %s vs %s" % (ct, want)
    print('\t{ "%s", "%s", "%s", %d, %d, "%s" },' % (kh, nonce, ivh, 0 if pt.startswith(b"Single") else 1, len(pt), ct))
# computed (not published) vectors with 192- and 256-bit keys, 3 lengths each
for kb, kh in ((24, KEYS[24]), (32, KEYS[32])):
    key = bytes.fromhex(kh)
    nonce = bytes.fromhex("e0a1b2c3"); iv = bytes.fromhex("0102030405060708")
    for ml in (16, 36, 50):
        pt = bytes(range(ml))
        print('\t{ "%s", "%s", "%s", 1, %d, "%s" },' % (kh, nonce.hex(), iv.hex(), ml, ctr(key, nonce + iv + b"\x00\x00\x00\x01", pt)))
print("};")
