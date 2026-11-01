#!/usr/bin/env python3
"""gen_vectors.py <ecb|cbc>: print the vector table of test_ecb() / test_cbc() in lib/libtest.c, every ciphertext computed
with `openssl enc -aes-N-ecb|cbc` (OpenSSL: shares nothing with the kernel), and ASSERT that the NIST SP 800-38A
F.1.1/F.1.3/F.1.5 (ECB) and F.2.1/F.2.3/F.2.5 (CBC) published 64-byte ciphertexts are what OpenSSL printed, so a wrong
transcription of either side fails here, not in the kernel.   usage: python3 gen_vectors.py cbc > table.inc"""
import subprocess, sys
mode = sys.argv[1]
assert mode in ("ecb", "cbc")
KEYS = {16: "2b7e151628aed2a6abf7158809cf4f3c",
        24: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        32: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"}
PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
NIST_IV = bytes(range(16))
FF_IV = b"\xff" * 16
PUB = {
    "ecb": {16: "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
            24: "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
            32: "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"},
    "cbc": {16: "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
            24: "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
            32: "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"},
}[mode]
def enc(key, iv, msg):
    cmd = ["openssl", "enc", f"-aes-{len(key)*8}-{mode}", "-K", key.hex(), "-nopad"]
    if mode == "cbc": cmd += ["-iv", iv.hex()]
    r = subprocess.run(cmd, input=msg, capture_output=True, check=True)
    return r.stdout.hex()
def pattern(n): return bytes((i * 29 + 5) & 0xff for i in range(n))
print(f"/* {mode}(aes): {{ key bytes, iv kind (0 NIST 00..0f, 1 all 0xff; unused by ecb), message kind (0 NIST prefix, 1 pattern), length, ciphertext }} */")
print(f"static const struct bm_vec {mode}_vecs[] __initconst = {{")
n = 0
for kb, kh in KEYS.items():
    key = bytes.fromhex(kh)
    ct = enc(key, NIST_IV, PT)
    assert ct == PUB[kb], "NIST AES-%d %s mismatch: openssl %s" % (kb * 8, mode, ct)
    lens0 = (64, 32, 16, 48)
    for ml in lens0:
        print('\t{ %d, 0, 0, %d, "%s" },' % (kb, ml, enc(key, NIST_IV, PT[:ml]))); n += 1
    for ivk, iv in ((0, NIST_IV), (1, FF_IV)):
        if mode == "ecb" and ivk == 1: continue
        for ml in (16, 48, 80, 160):
            print('\t{ %d, %d, 1, %d, "%s" },' % (kb, ivk, ml, enc(key, iv, pattern(ml)))); n += 1
print("};")
print("generated %d vectors; NIST SP 800-38A published values asserted" % n, file=sys.stderr)
