#!/usr/bin/env python3
"""bootconfig-append.py INITRD CONFIG -- append CONFIG to INITRD the way tools/bootconfig does (and init/main.c get_boot_config_from_initrd() reads):
   <config text, NUL terminated, NUL padded so the whole file stays 4-byte aligned> <le32 size> <le32 checksum> "#BOOTCONFIG\\n"
   size covers the text and its padding, the checksum is the byte sum of exactly those bytes."""
import struct, sys
initrd, cfg = sys.argv[1], sys.argv[2]
data = open(cfg, 'rb').read() + b'\0'
cur = len(open(initrd, 'rb').read())
pad = (-(cur + len(data) + 8 + 12)) % 4
data += b'\0' * pad
csum = sum(data) & 0xffffffff
with open(initrd, 'ab') as f:
    f.write(data + struct.pack('<II', len(data), csum) + b'#BOOTCONFIG\n')
