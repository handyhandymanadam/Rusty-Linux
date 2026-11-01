#!/usr/bin/env bash
# run-video-diff.sh [scenarios-per-variant] [seed] -- lockstep differential of the five video ports (port/tree/arch/x86/boot/video*_rs.rs) against the ORIGINAL video.c, video-mode.c,
# video-vga.c, video-vesa.c, video-bios.c, both built for the HOST with mocks for every outside effect (rig/realmode/video-diff.c), in the 4 configuration variants of video-vesa.c
# (CONFIG_BOOT_VESA_SUPPORT x CONFIG_FIRMWARE_EDID; neither is set in the two built configurations). The C text is compiled UNCHANGED against the stand-in boot.h of mkstub.py, except:
#   (1) the inline asm block of restore_screen() (16-bit `pushw %es ... rep stosl`, which cannot run in a host process) is replaced by a call of mock_blank_fill_c(), the harness's
#       model of that block (the Rust's asm block is replaced by the same model under --cfg host_mock). The REAL asm is covered by the QEMU boot compare and the object disassembly.
# Symbol renames are done on the compiled C objects (objcopy --redefine-sym), not with -D (a macro would also rename the card_info members .set_mode/.probe). The .videocards section is
# named `videocards_c` / `videocards_rs` on the host so the GNU linker defines __start_/__stop_ symbols. SABOTAGE=sed-expr applies to a copy of the Rust (all five files).
# VARIANTS="0 1 2 3" restricts the variants (bit0 = BOOT_VESA_SUPPORT, bit1 = FIRMWARE_EDID).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
SRC=$root/src/linux; B=$root/build-fast
KINC="-I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$B/arch/x86/include/generated/uapi -I$B/include/generated/uapi"
GINC="-I$SRC/arch/x86/include -I$SRC/include $KINC -I$B/arch/x86/include/generated -I$B/include/generated"
T=$(mktemp -d); trap 'rm -rf $T' EXIT
python3 "$here/mkstub.py" "$root" "$T"; cp "$SRC/arch/x86/boot/io.h" "$T/io.h"
for f in video video-mode video-vga video-vesa video-bios; do cp "$SRC/arch/x86/boot/$f.c" "$T/$f.c"; done
cp "$SRC/arch/x86/boot/video.h" "$SRC/arch/x86/boot/vesa.h" "$T/"
python3 - "$T/video.c" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p).read()
pat=re.compile(r'asm volatile\("pushw %%es ; "\s+"movw %2,%%es ; "\s+"shrw %%cx ; "\s+"jnc 1f ; "\s+"stosw \\n\\t"\s+"1: rep stosl ; "\s+"popw %%es"\s+: "\+D" \(dst\), "\+c" \(npad\)\s+: "bdS" \(video_segment\),\s+"a" \(0x07200720\)\);')
assert len(pat.findall(s))==1, "asm block not found exactly once"
s=pat.sub('{ unsigned int _d = dst, _n = npad; mock_blank_fill_c(video_segment, &_d, &_n); dst = _d; npad = _n; }',s)
s='extern void mock_blank_fill_c(unsigned short, unsigned int *, unsigned int *);\n'+s
open(p,'w').write(s)
PY
cp "$root/port/tree/arch/x86/boot/"{video_rs.rs,video_mode_rs.rs,video_vga_rs.rs,video_vesa_rs.rs,video_bios_rs.rs,rm_common.rs,rm_video.rs,video_gen.rs.in} "$T/"
if [ -n "${SABOTAGE:-}" ]; then for f in video video_mode video_vga video_vesa video_bios; do cp "$T/${f}_rs.rs" "$T/${f}_rs.before"; sed -i "$SABOTAGE" "$T/${f}_rs.rs"; done
  c=0; for f in video video_mode video_vga video_vesa video_bios; do cmp -s "$T/${f}_rs.rs" "$T/${f}_rs.before" || c=1; done; [ $c = 1 ] || { echo "SABOTAGE did not change any file"; exit 2; }; fi
if [ -n "${CSABOTAGE:-}" ]; then for f in video video-mode video-vga video-vesa video-bios; do cp "$T/$f.c" "$T/$f.before"; sed -i "$CSABOTAGE" "$T/$f.c"; done; fi
cat > "$T/video_all.rs" <<'RS'
#![allow(dead_code, static_mut_refs, unused_parens, non_upper_case_globals, unused_unsafe, unused_imports, unused_mut, unused_variables)]
#[path = "video_rs.rs"] mod video_rs;
#[path = "video_mode_rs.rs"] mod video_mode_rs;
#[path = "video_vga_rs.rs"] mod video_vga_rs;
#[path = "video_vesa_rs.rs"] mod video_vesa_rs;
#[path = "video_bios_rs.rs"] mod video_bios_rs;
RS
rc=0
for v in ${VARIANTS:-0 1 2 3}; do
  V=$((v&1)); E=$(((v>>1)&1)); D=$T/v$v; mkdir -p $D
  CFG=""; [ $V = 1 ] && CFG="$CFG -DCONFIG_BOOT_VESA_SUPPORT=1"; [ $E = 1 ] && CFG="$CFG -DCONFIG_FIRMWARE_EDID=1"
  clang -I$T/inc $GINC $CFG -D__KERNEL__ -E -P -x c "$T/video_gen.rs.in" | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(ULL\|UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > $D/video_gen.rs
  CCF="-O1 -w -fwrapv -fno-pie -I$T/inc -I$T $KINC -I$SRC/arch/x86/include $CFG -D_SETUP -DHOST_VIDEOCARDS_SECTION=\"videocards_c\""
  objs=""
  for f in video video-mode video-vga video-vesa video-bios; do clang $CCF -c "$T/$f.c" -o "$D/$f.o"; objs="$objs $D/$f.o"; done
  # one combined relocatable C object: rename the exported/undefined symbols, then link-resolve (ld -r) so statics stay local
  ld -r -o "$D/c_all.o" $D/video-vga.o $D/video-vesa.o $D/video-bios.o $D/video.o $D/video-mode.o
  objcopy --globalize-symbol=vginfo --globalize-symbol=vminfo "$D/c_all.o"
  R=""; for s in adapter force_x force_y do_restore graphic_mode probe_cards mode_defined set_mode vga_crtc vesa_store_edid set_video vginfo vminfo; do R="$R --redefine-sym $s=c_$s"; done
  for s in printf:mock_printf sprintf:mock_sprintf puts:mock_puts putchar:mock_putchar getchar:mock_getchar kbd_flush:mock_kbd_flush getchar_timeout:mock_getchar_timeout copy_to_fs:mock_copy_to_fs copy_from_fs:mock_copy_from_fs boot_params:c_boot_params _end:host_end video_cards:__start_videocards_c video_cards_end:__stop_videocards_c; do R="$R --redefine-sym ${s%%:*}=${s##*:}"; done
  objcopy $R "$D/c_all.o" "$D/c_all2.o"
  RO=""
  for f in video video_mode video_vga video_vesa video_bios; do
    RM_GEN_DIR=$D RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=lib --emit=obj -C opt-level=2 -C panic=abort -C debug-assertions=off -C overflow-checks=off --cfg host_mock \
        --crate-name=${f}_rs -o "$D/${f}_rs.o" "$T/${f}_rs.rs" 2>"$D/rustc-$f.log" || { cat "$D/rustc-$f.log"; exit 3; }
  done
  # link order = the Makefile's setup-y order: video-vga, video-vesa, video-bios decide the card table order
  RO="$D/video_vga_rs.o $D/video_vesa_rs.o $D/video_bios_rs.o $D/video_rs.o $D/video_mode_rs.o"
  clang -O2 -w -fno-pie -no-pie -I$T/inc $KINC "$here/video-diff.c" -o "$D/h" "$D/c_all2.o" $RO -lpthread -ldl -lm 2>$D/link.log || { cat $D/link.log | head -30; exit 4; }
  echo "== variant $v: BOOT_VESA_SUPPORT=$V FIRMWARE_EDID=$E"
  "$D/h" "${1:-20000}" "${2:-1}" || rc=1
done
exit $rc
