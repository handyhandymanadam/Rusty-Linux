#!/usr/bin/env python3
# corrupt.py <bzImage> <compressed/vmlinux> <out> [offset] : flip one byte of the compressed payload:
# at <offset> bytes after the payload start if given (14 = inside the first block's tables: ALWAYS breaks the stream),
# else in the middle (can land in literal data that decodes "fine" and then the kernel simply boots).
import sys,subprocess
bzp=sys.argv[1]; stub=sys.argv[2]; out=sys.argv[3]
bz=bytearray(open(bzp,"rb").read())
ss=bz[0x1f1] or 4
pm=(ss+1)*512
nm=subprocess.check_output(["nm",stub]).decode()
sym={l.split()[2]:int(l.split()[0],16) for l in nm.splitlines() if len(l.split())==3}
start=pm+sym["input_data"]; end=pm+sym["input_data_end"]
print("payload file range",hex(start),hex(end),"magic",bz[start:start+3].hex())
assert bz[start:start+2] in (b"\x1f\x8b",b"BZ",b"\x5d\x00",b"\xfd7",b"\x89L",b"\x02\x21",b"\x28\xb5") or True
mid=start+int(sys.argv[4]) if len(sys.argv)>4 else (start+end)//2
print("flip at",hex(mid),hex(bz[mid]),"->",hex(bz[mid]^0xff)); bz[mid]^=0xff
open(out,"wb").write(bz)
