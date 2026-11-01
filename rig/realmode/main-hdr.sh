#!/usr/bin/env bash
# main-hdr.sh <in.bzImage> <out.bzImage> <version-hex e.g. 0x0200|0x0201> [setup_move_size-hex]
# Patch the setup header's `version` (u16 at file offset 0x206, after "HdrS") so QEMU's -kernel loader treats the image as an OLD boot protocol:
#   0x0200: no CAN_USE_HEAP, no heap_end_ptr, no cmd_line_ptr; QEMU stores the OLD-STYLE command line protocol instead (u16 0xA33F at 0x20, u16
#           offset of the command line at 0x22, relative to the setup segment) and loads the setup at 0x90000 (seg 0x9000) -> main.c prints
#           "WARNING: Ancient bootloader..." and runs the old-cmdline branch of copy_boot_params();
#   0x0201: CAN_USE_HEAP + heap_end_ptr (= cmdline_addr - real_addr - 0x200) set by QEMU, still the old-style command line, setup at 0x90000.
# The optional 4th argument patches hdr.setup_move_size (u16 at 0x212), which QEMU does not touch: a large value makes `cl_offset < setup_move_size` true (cmdline_seg = ds()).
python3 - "$@" <<'PY'
import sys,struct
d=bytearray(open(sys.argv[1],'rb').read())
assert d[0x1fe:0x200]==b'\x55\xaa' and d[0x202:0x206]==b'HdrS'
old=struct.unpack_from('<H',d,0x206)[0]
struct.pack_into('<H',d,0x206,int(sys.argv[3],16))
if len(sys.argv)>4: struct.pack_into('<H',d,0x212,int(sys.argv[4],16))
open(sys.argv[2],'wb').write(d)
print('patched: version %#06x -> %s%s'%(old,sys.argv[3],(', setup_move_size -> '+sys.argv[4]) if len(sys.argv)>4 else ''))
PY
