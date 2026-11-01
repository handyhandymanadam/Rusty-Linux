#!/usr/bin/env python3
"""gen_vectors.py: print the AES-CMAC vector table of test_cmac() in lib/libtest.c, computed with `openssl mac`
(OpenSSL CMAC: an implementation that shares nothing with the kernel), and ASSERT that the NIST SP 800-38B Appendix D
published MACs (AES-128/192/256, message lengths 0, 16, 40, 64) are what OpenSSL printed -- so a wrong transcription
of either side fails here, not in the kernel.   usage: python3 gen_vectors.py > table.inc"""
import subprocess, sys
KEYS = {
    16: "2b7e151628aed2a6abf7158809cf4f3c",
    24: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    32: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
}
NIST_MSG = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
PUB = {  # SP 800-38B Appendix D examples: (keybytes, mlen) -> MAC
    (16, 0): "bb1d6929e95937287fa37d129b756746", (16, 16): "070a16b46b4d4144f79bdd9dd04a287c",
    (16, 40): "dfa66747de9ae63030ca32611497c827", (16, 64): "51f0bebf7e3b9d92fc49741779363cfe",
    (24, 0): "d17ddf46adaacde531cac483de7a9367", (24, 16): "9e99a7bf31e710900662f65e617c5184",
    (24, 40): "8a1de5be2eb31aad089a82e6ee908b0e", (24, 64): "a1d5df0eed790f794d77589659f39a11",
    (32, 0): "028962f61b7bf89efc6b551f4667d983", (32, 16): "28a7023f452e8f82bd4bf28d8c37c35c",
    (32, 40): "aaf3d8f1de5640c232f5b169b9c911e6", (32, 64): "e1992190549f6ed5696a2c056c315410",
}
def cmac(key, msg):
    r = subprocess.run(["openssl", "mac", "-cipher", f"AES-{len(key)*8}-CBC", "-macopt", "hexkey:" + key.hex(), "CMAC"],
                       input=msg, capture_output=True, check=True)
    return r.stdout.decode().strip().lower()
def pattern(n): return bytes((i * 29 + 5) & 0xff for i in range(n))
rows = []
for kb, kh in KEYS.items():
    key = bytes.fromhex(kh)
    for ml in (0, 16, 40, 64):
        m = cmac(key, NIST_MSG[:ml])
        assert m == PUB[(kb, ml)], f"NIST mismatch AES-{kb*8} len {ml}: openssl {m} published {PUB[(kb, ml)]}"
        rows.append((kb, 0, ml, m))
    for ml in (1, 7, 8, 15, 17, 31, 32, 33, 47, 48, 63, 65, 100):
        rows.append((kb, 1, ml, cmac(key, pattern(ml))))
for kb, kind, ml, m in rows:
    print(f'\t{{ {kb}, {kind}, {ml}, "{m}" }},')
print("generated %d vectors; NIST SP 800-38B published values asserted" % len(rows), file=sys.stderr)
