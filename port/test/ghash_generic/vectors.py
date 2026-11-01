#!/usr/bin/env python3
"""GHASH reference per NIST SP 800-38D (Algorithm 1, bitwise, no tables) and
random vectors from it: 'H_hex msg_hex digest_hex' per line ('-' = empty msg).
The reference is checked first against the GCM spec's Test Case 2 value."""
import random, sys
R = 0xe1 << 120
def mul(x, y):                       # block multiply in GF(2^128), x,y as 128-bit ints (bit 0 = MSB)
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1: z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z
def ghash(h, msg):
    if len(msg) % 16: msg = msg + bytes(16 - len(msg) % 16)
    y = 0
    for i in range(0, len(msg), 16):
        y = mul(y ^ int.from_bytes(msg[i:i + 16], "big"), h)
    return y.to_bytes(16, "big")
H = int("66e94bd4ef8a2c3b884cfa59ca342b2e", 16)
X = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78" + "00000000000000000000000000000080")
assert ghash(H, X).hex() == "f38cbb1ad69223dcc3457ae5b6b0f885", "reference disagrees with GCM spec test case 2"
assert ghash(H, b"") == bytes(16)
random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
lens = sorted(set(list(range(0, 80)) + [127, 128, 129, 255, 256, 257, 1000, 1023, 1024, 1025]))
out = []
for n in lens:
    for _ in range(4):
        h = bytes(random.getrandbits(8) for _ in range(16))
        m = bytes(random.getrandbits(8) for _ in range(n))
        out.append("%s %s %s" % (h.hex(), m.hex() or "-", ghash(int.from_bytes(h, "big"), m).hex()))
for h in (bytes(16), b"\xff" * 16, bytes([0x80]) + bytes(15), bytes(15) + b"\x01"):
    for n in (0, 1, 15, 16, 17, 32, 48):
        for b in (0, 255):
            m = bytes([b]) * n
            out.append("%s %s %s" % (h.hex(), m.hex() or "-", ghash(int.from_bytes(h, "big"), m).hex()))
print("\n".join(out))
