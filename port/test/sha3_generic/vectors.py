#!/usr/bin/env python3
"""Emit 'alg msglen_hex ... ' vectors with the digest from hashlib (the oracle
that is neither the C nor the Rust): 'alg hexmsg hexdigest' per line."""
import hashlib, random, sys
random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
rates = {"sha3_224": 144, "sha3_256": 136, "sha3_384": 104, "sha3_512": 72}
lens = set(range(0, 420))
for r in rates.values():
    for k in (1, 2, 3, 4):
        for d in (-2, -1, 0, 1, 2):
            lens.add(max(0, r * k + d))
lens |= {1000, 1023, 1024, 1025, 4095, 4096, 4097}
out = []
for alg in rates:
    for n in sorted(lens):
        for _ in range(3 if n < 420 else 1):
            m = bytes(random.getrandbits(8) for _ in range(n))
            out.append("%s %s %s" % (alg, m.hex() or "-", getattr(hashlib, alg)(m).hexdigest()))
    # all-0x00 and all-0xff messages at the boundaries
    for n in (0, 1, rates[alg] - 1, rates[alg], rates[alg] + 1, 2 * rates[alg] - 1):
        for b in (0, 255):
            m = bytes([b]) * n
            out.append("%s %s %s" % (alg, m.hex() or "-", getattr(hashlib, alg)(m).hexdigest()))
print("\n".join(out))
