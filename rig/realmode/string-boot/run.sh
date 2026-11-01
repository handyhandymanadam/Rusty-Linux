#!/usr/bin/env bash
# run.sh [rs.o] -- in-guest differential: boots a tiny boot-sector test image under QEMU (KVM host CPU, and TCG with SMP=tcg) that runs the REAL 16-bit
# objects arch/x86/boot/string.o (C, built here with the exact kbuild command of build-fast; symbols c_*) and string_rs.o (Rust, from build-fast or $1;
# symbols rs_*) side by side on random + directed inputs. Output over COM1; the guest exits through isa-debug-exit (0x10 = pass, 0x11 = mismatches).
# Needs build-fast/arch/x86/boot/string_rs.o (after rig/realmode/bz.sh rs ...). Env: TCG=1 also runs under TCG (-cpu qemu32); SABOTAGE=<sed> / RS_SRC=<file> rebuild the Rust object from a sabotaged copy.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../../.." && pwd)
b="$root/build-fast"; T=$(mktemp -d); trap 'rm -rf $T' EXIT
RS=${1:-$b/arch/x86/boot/string_rs.o}
cmd="$b/arch/x86/boot/.string.o.cmd"
line=$(head -1 "$cmd" | sed 's/^savedcmd_[^ ]* := //'); line=${line//-Wp,-MMD,arch\/x86\/boot\/.string.o.d/}
c_line=${line//-c -o arch\/x86\/boot\/string.o *\/string.c/-c -o $T/string_c.o $root/src/linux/arch/x86/boot/string.c}
t_line=${line//-c -o arch\/x86\/boot\/string.o *\/string.c/-c -o $T/test.o $here/test.c}
(cd "$b" && eval "$c_line" && eval "$t_line")
objcopy --prefix-symbols=c_ "$T/string_c.o" "$T/c.o"
if [ -n "${SABOTAGE:-}" ]; then   # SABOTAGE=<sed expr>: rebuild the Rust object from a sabotaged copy of the tree file with the Makefile's rm_rustflags
  . "$root/kbuild-env.sh" >/dev/null 2>&1
  cp "${RS_SRC:-$root/port/tree/arch/x86/boot/string_rs.rs}" "$T/string_rs.rs"; sed -i "$SABOTAGE" "$T/string_rs.rs"
  cmp -s "$T/string_rs.rs" "${RS_SRC:-$root/port/tree/arch/x86/boot/string_rs.rs}" && { echo "SABOTAGE changed nothing"; exit 3; }
  RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -C opt-level=s -C panic=immediate-abort -C debug-assertions=off -C overflow-checks=off \
     -Zfunction-sections=y -Zregparm=3 --target="$root/port/tree/arch/x86/boot/realmode_target.json" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=string_rs \
     --emit=obj --extern core="$b/arch/x86/boot/librm_core.rlib" --extern compiler_builtins="$b/arch/x86/boot/librm_compiler_builtins.rlib" -o "$T/rs_sab.o" "$T/string_rs.rs" 2>&1 | grep -E "^error" -A6 || true
  RS="$T/rs_sab.o"; echo "SABOTAGE applied: $SABOTAGE"
fi
objcopy --prefix-symbols=rs_ "$RS" "$T/rs.o"
as --32 -o "$T/head.o" "$here/head.S"
ld -m elf_i386 -T "$here/link.ld" -o "$T/test.elf" "$T/head.o" "$T/test.o" "$T/c.o" "$T/rs.o"
objcopy -O binary "$T/test.elf" "$T/test.bin"
sz=$(stat -c %s "$T/test.bin"); nsect=$(( (sz + 511) / 512 ))
echo "test image: $sz bytes ($nsect sectors); _end=$(nm "$T/test.elf" | awk '$3=="_end"{print $1}')"
[ $nsect -le 120 ] || { echo "image too big"; exit 1; }
as --32 --defsym NSECT=$nsect -o "$T/s1.o" "$here/stage1.S"
ld -m elf_i386 -e _s -Ttext 0x7c00 -o "$T/s1.elf" "$T/s1.o"; objcopy -O binary -j .text "$T/s1.elf" "$T/s1.bin"
[ "$(stat -c %s "$T/s1.bin")" = 512 ] || { echo "boot sector is not 512 bytes"; exit 1; }
{ cat "$T/s1.bin"; cat "$T/test.bin"; } > "$T/disk.img"; truncate -s $(( (nsect + 1) * 512 )) "$T/disk.img"
run() { # name qemu-cpu-args
  rm -f "$T/serial"; set +e
  timeout 300 qemu-system-x86_64 $2 -m 64 -display none -no-reboot -drive file="$T/disk.img",format=raw,if=ide \
     -device isa-debug-exit,iobase=0xf4,iosize=4 -serial file:"$T/serial" </dev/null >/dev/null 2>&1
  rc=$?; set -e
  echo "[$1] qemu exit=$rc (guest code $(( (rc - 1) / 2 )) = 0x$(printf %x $(( (rc - 1) / 2 ))); 0x10 pass, 0x11 mismatches)"; cat "$T/serial" | tr -d '\r' | sed 's/^/    /'
  [ $rc = 33 ] || return 1
}
rcall=0
run kvm "-enable-kvm -cpu host" || rcall=1
[ -n "${TCG:-}" ] && { run tcg "-cpu qemu32" || rcall=1; }
[ $rcall = 0 ] && echo "STRING-BOOT OK" || echo "STRING-BOOT FAILED"
exit $rcall
