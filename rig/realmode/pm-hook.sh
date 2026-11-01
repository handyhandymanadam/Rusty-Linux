#!/usr/bin/env bash
# pm-hook.sh <in.bzImage> <out.bzImage> -- patch the setup header so hdr.realmode_swtch (u32 at file offset 0x208, a far pointer off16:seg16)
# points at a stub in the bootsector area (bstext, bytes 0x20.., never executed with -kernel: QEMU enters at 0x1020:0), which QEMU loads
# with the rest of the setup at 0x10000: seg 0x1000, off 0x20. Stub (code16, called with `lcallw`, returns with `lret`):
#     mov al,0x4b ; mov dx,0xe9 ; out dx,al            marker: one byte 'K' on port 0xe9 (observable: kvm_pio trace, isa-debugcon)
#     mov eax,0x11111111 ; mov ebx,0x22222222 ; mov ecx,0x33333333 ; mov edx,0x44444444      clobbers exactly the declared eax ebx ecx edx
#     lret
python3 - "$1" "$2" <<'PY'
import sys,struct
d=bytearray(open(sys.argv[1],'rb').read())
stub=bytes.fromhex('b04b'+'bae900'+'ee'+'66b811111111'+'66bb22222222'+'66b933333333'+'66ba44444444'+'cb')
OFF=0x20
assert d[0x1fe:0x200]==b'\x55\xaa' and d[0x202:0x206]==b'HdrS'
assert struct.unpack_from('<I',d,0x208)[0]==0, 'realmode_swtch not zero in the unpatched image'
d[OFF:OFF+len(stub)]=stub                      # inside .bstext (bytes 0..495): unused when entered at 0x200
struct.pack_into('<HH',d,0x208,OFF,0x1000)     # off, seg
open(sys.argv[2],'wb').write(d)
print('patched: realmode_swtch =',d[0x208:0x20c].hex(),'stub',stub.hex())
PY
