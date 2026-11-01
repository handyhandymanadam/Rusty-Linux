#!/usr/bin/env bash
# run-edd-diff.sh [scenarios] [seed] -- lockstep differential of port/tree/arch/x86/boot/edd_rs.rs against the original arch/x86/boot/edd.c, both built for the HOST with
# mocks for every outside effect (BIOS INT 13h with up to 16 drives, the cmdline lookups, printf, ds()). The C is the original edd.c compiled with CONFIG_EDD=1, against the
# stand-in boot.h of mkstub.py (verbatim extraction of the real definitions); only renames by -D (query_edd, boot_params, printf) plus ONE mechanical edit of the C text:
#     (char *)(size_t)boot_params.hdr.heap_end_ptr   ->   (char *)mock_heap_limit((size_t)boot_params.hdr.heap_end_ptr)
# because on the host `_end` is a real pointer >= 64 KiB, so the 16-bit heap_end_ptr could never be above it; mock_heap_limit() rebases the value into the "target _end ==
# 0x5200" coordinates the real setup lives in (the Rust, under --cfg host_mock, calls the same hook). The real address arithmetic (_end ~ 0x5200, heap_end_ptr ~ 0xfe00)
# is only exercised by the QEMU boot compare (logs/realmode-edd.md). SABOTAGE=sed-expr applies to a copy of the Rust; CSABOTAGE to a copy of the C (negative control).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
SRC=$root/src/linux; B=$root/build-fast
KINC="-I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$B/arch/x86/include/generated/uapi -I$B/include/generated/uapi"
GINC="-I$SRC/arch/x86/include -I$SRC/include $KINC -I$B/arch/x86/include/generated -I$B/include/generated"
T=$(mktemp -d); trap 'rm -rf $T' EXIT
python3 "$here/mkstub.py" "$root" "$T"; cp "$SRC/arch/x86/boot/io.h" "$T/io.h"
cp "$SRC/arch/x86/boot/edd.c" "$T/edd_c.c"
n=$(grep -c '(char \*)(size_t)boot_params.hdr.heap_end_ptr' "$T/edd_c.c"); [ "$n" = 1 ] || { echo "heap_end_ptr line not found exactly once ($n)"; exit 2; }
sed -i 's/(char \*)(size_t)boot_params.hdr.heap_end_ptr/(char *)mock_heap_limit((size_t)boot_params.hdr.heap_end_ptr)/' "$T/edd_c.c"
sed -i '1i extern unsigned long mock_heap_limit(unsigned long);' "$T/edd_c.c"
if [ -n "${CSABOTAGE:-}" ]; then cp "$T/edd_c.c" "$T/edd_c.before"; sed -i "$CSABOTAGE" "$T/edd_c.c"; cmp -s "$T/edd_c.c" "$T/edd_c.before" && { echo "CSABOTAGE did not change the file"; exit 2; }; fi
cp "$root/port/tree/arch/x86/boot/"{edd_rs.rs,rm_common.rs,edd_gen.rs.in} "$T/"
if [ -n "${SABOTAGE:-}" ]; then cp "$T/edd_rs.rs" "$T/edd_rs.before"; sed -i "$SABOTAGE" "$T/edd_rs.rs"; cmp -s "$T/edd_rs.rs" "$T/edd_rs.before" && { echo "SABOTAGE did not change the file"; exit 2; }; fi
# the Rust's host hooks: printf and the heap limit
python3 - "$T/edd_rs.rs" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
s=s.replace('''#[cfg(host_mock)]
extern "C" {
    fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn printf(fmt: *const c_char, ...) -> c_int;''','''#[cfg(host_mock)]
extern "C" {
    fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    #[link_name = "mock_printf"]
    fn printf(fmt: *const c_char, ...) -> c_int;''')
open(p,'w').write(s)
PY
cp "$T/edd_rs.rs" "$T/edd_rs.run.rs"
CC="clang -O1 -w -fwrapv -fno-pie -I$T/inc -I$T $KINC -DCONFIG_EDD=1 -D_SETUP -DHOST_VIDEOCARDS_SECTION=\"videocards_c\""
D=$T/o; mkdir -p $D
clang -I$T/inc $GINC -D__KERNEL__ -DCONFIG_EDD=1 -E -P -x c "$T/edd_gen.rs.in" | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(ULL\|UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > $D/edd_gen.rs
$CC -Dquery_edd=c_query_edd -Dboot_params=c_boot_params -Dprintf=mock_printf -D_end=host_end -c "$T/edd_c.c" -o "$D/c_edd.o"
RM_GEN_DIR=$D RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib -C opt-level=2 -C panic=abort --cfg host_mock \
    --crate-name=edd_rs -o "$D/libedd_rs.a" "$T/edd_rs.rs" 2>"$D/rustc.log" || { cat "$D/rustc.log"; exit 3; }
clang -O2 -w -fno-pie -no-pie -I$T/inc $KINC "$here/edd-diff.c" -o "$D/h" "$D/c_edd.o" "$D/libedd_rs.a" -lpthread -ldl -lm
if [ -n "${HOSTDBG:-}" ]; then cp -r $D /tmp/edd-dbg; fi
"$D/h" "${1:-100000}" "${2:-1}"
