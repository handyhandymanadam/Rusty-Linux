#!/usr/bin/env python3
# craft.py <bzImage> <stub vmlinux> <out> <magic|align|phnum0>
# Replace the compressed payload of a gzip bzImage by a gzip stream of a tiny synthetic "kernel" that makes parse_elf() fail:
#   magic : 4 KiB of 'A' (not an ELF)           -> "Kernel is not a valid ELF file"
#   align : ELF header + one PT_LOAD, p_align 0x1000 -> "Alignment of LOAD segment isn't multiple of 2MB"
# The stream is padded with zeros to the original payload length (input_len stays valid).
import sys, subprocess, struct, gzip, io
bzp, stub, out, kind = sys.argv[1:5]
bz = bytearray(open(bzp, "rb").read())
pm = ((bz[0x1f1] or 4) + 1) * 512
sym = {l.split()[2]: int(l.split()[0], 16) for l in subprocess.check_output(["nm", stub]).decode().splitlines() if len(l.split()) == 3}
s, e = pm + sym["input_data"], pm + sym["input_data_end"]
assert bz[s:s+2] == b"\x1f\x8b", "payload is not gzip"
if kind == "magic":
    img = b"A" * 4096
elif kind == "align":
    eh = bytearray(64); eh[0:4] = b"\x7fELF"; eh[4:7] = bytes([2, 1, 1])
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 62, 1, 0x1000000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0xffffffff81000000, 0x1000000, 0x100, 0x100, 0x1000)
    img = bytes(eh) + ph + b"\0" * 256
else:
    sys.exit("kind")
z = io.BytesIO()
with gzip.GzipFile(fileobj=z, mode="wb", mtime=0, compresslevel=9) as g: g.write(img)
z = z.getvalue()
assert len(z) <= e - s, (len(z), e - s)
bz[s:e] = z + b"\0" * (e - s - len(z))
open(out, "wb").write(bz)
print(kind, "payload replaced:", len(z), "bytes of", e - s)
