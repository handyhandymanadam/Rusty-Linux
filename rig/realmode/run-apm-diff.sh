#!/usr/bin/env bash
# run-apm-diff.sh [scenarios] [seed] -- lockstep differential of port/tree/arch/x86/boot/apm_rs.rs against the original arch/x86/boot/apm.c (UNCHANGED; only query_apm_bios and
# boot_params are renamed by -D) on the host with a mocked INT 15h BIOS (rig/realmode/apm-diff.c). SABOTAGE=sed-expr applies to a copy of the Rust.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
SRC=$root/src/linux; B=$root/build-fast
KINC="-I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$B/arch/x86/include/generated/uapi -I$B/include/generated/uapi"
T=$(mktemp -d); trap 'rm -rf $T' EXIT
python3 "$here/mkstub.py" "$root" "$T"; cp "$SRC/arch/x86/boot/io.h" "$T/io.h"
cp "$SRC/arch/x86/boot/apm.c" "$T/apm_c.c"
cp "$root/port/tree/arch/x86/boot/"{apm_rs.rs,rm_common.rs} "$T/"
if [ -n "${SABOTAGE:-}" ]; then cp "$T/apm_rs.rs" "$T/apm_rs.before"; sed -i "$SABOTAGE" "$T/apm_rs.rs"; cmp -s "$T/apm_rs.rs" "$T/apm_rs.before" && { echo "SABOTAGE did not change the file"; exit 2; }; fi
D=$T/o; mkdir -p $D
clang -O1 -w -fwrapv -fno-pie -I$T/inc -I$T $KINC -D_SETUP -DHOST_VIDEOCARDS_SECTION=\"videocards_c\" -Dquery_apm_bios=c_query_apm_bios -Dboot_params=c_boot_params -D_end=host_end -c "$T/apm_c.c" -o "$D/c_apm.o"
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib -C opt-level=2 -C panic=abort --cfg host_mock \
    --crate-name=apm_rs -o "$D/libapm_rs.a" "$T/apm_rs.rs" 2>"$D/rustc.log" || { cat "$D/rustc.log"; exit 3; }
clang -O2 -w -fno-pie -no-pie -I$T/inc $KINC "$here/apm-diff.c" -o "$D/h" "$D/c_apm.o" "$D/libapm_rs.a" -lpthread -ldl -lm
"$D/h" "${1:-100000}" "${2:-1}"
