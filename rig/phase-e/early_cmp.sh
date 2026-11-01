#!/usr/bin/env bash
# Userspace differential for main_rs.rs (early command-line pass of init/main.c) vs the real C.  early_cmp.sh [--sabotage-only]   env: N cases
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${MAIN_RS:-$root/port/tree/init/main_rs.rs}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/params_gen.py" "$root/port/pristine/kernel/params.c" "$root/src/linux/lib/cmdline.c" "$out/params.inc"
python3 "$here/early_gen.py" "$root/port/pristine/init/main.c" "$out/early.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1); C cut unedited: params+next_arg $(wc -l < "$out/params.inc") lines, main.c early pass $(wc -l < "$out/early.inc") lines"
CCF="-O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-implicit-function-declaration -Wno-int-conversion -I$here"
build() {  # build <rs> <exe>
    cc $CCF -DPARAMSINC="\"$out/params.inc\"" -c -o "$2.p.o" "$here/params_ref.c"
    cc $CCF -DEARLYINC="\"$out/early.inc\"" -c -o "$2.e.o" "$here/early_ref.c"
    sed "s|MAINRS|$1|" "$here/early_cmp.rs" > "$2.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$2.p.o" -C link-arg="$2.e.o" --crate-name earlycmp -o "$2" "$2.cmp.rs" 2>&1 | grep -E "^error" -A8 || true
}
if [ "${1:-}" != "--sabotage-only" ]; then build "$RS" "$out/t"; "$out/t"; fi
if [ "${1:-}" = "--sabotage" ] || [ "${1:-}" = "--sabotage-only" ]; then
python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys, os
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("early-flag", "if (*p).early != 0 && parameq", "if (*p).early == 0 && parameq"),
 ("early-ignored", "if (*p).early != 0 && parameq", "if parameq"),
 ("no-parameq", "(*p).early != 0 && parameq(param, (*p).name) &&", "(*p).early != 0 &&"),
 ("setup-nonzero", "((*p).setup_func)(val) != 0", "((*p).setup_func)(val) == 0"),
 ("msg-text", "Malformed early option '%s'", "Malformed early options '%s'"),
 ("msg-level", "\\x014Malformed", "\\x013Malformed"),
 ("msg-arg", "c\"\\x014Malformed early option '%s'\\n\".as_ptr(), param)", "c\"\\x014Malformed early option '%s'\\n\".as_ptr(), val)"),
 ("loop-end", "while p < end {", "while p.add(1) < end {"),
 ("loop-step", "p = p.add(1);", "p = p.add(2);"),
 ("return", "    0\n}\n\n/// `parse_early_options()`", "    1\n}\n\n/// `parse_early_options()`"),
 ("doing-EQUIV", "c\"early options\"", "c\"early option\""),
 ("done-check", "if DONE != 0 {", "if false {"),
 ("done-set", "        DONE = 1;", "        DONE = 0;"),
 ("size", "sized_strscpy(tmp, (&raw const boot_command_line) as *const c_char, COMMAND_LINE_SIZE);", "sized_strscpy(tmp, (&raw const boot_command_line) as *const c_char, COMMAND_LINE_SIZE - 1);"),
 ("const-size", "const COMMAND_LINE_SIZE: usize = 2048;", "const COMMAND_LINE_SIZE: usize = 1024;"),
 ("no-copy", "sized_strscpy(tmp, (&raw const boot_command_line) as *const c_char, COMMAND_LINE_SIZE);\n", "\n"),
 ("min-level-EQUIV", "core::ptr::null(), 0, 0, 0, core::ptr::null_mut(), Some(do_early_param)", "core::ptr::null(), 0, 1, 0, core::ptr::null_mut(), Some(do_early_param)"),
 ("no-handler", "core::ptr::null_mut(), Some(do_early_param))", "core::ptr::null_mut(), None)"),
 ("offset-func", "const OBS_SETUP_FUNC: usize = 8;", "const OBS_SETUP_FUNC: usize = 16;"),
]
caught = 0; equiv = 0
for name, a, b in M:
    a = a.replace("\\n", "\n") if "\\x01" not in a else a.replace("\\n\"", "\\n\"")
    # patterns containing a literal backslash-n inside a Rust string must stay literal: only translate the `\n}` structural ones
    a2 = a if name in ("msg-level", "msg-arg") else a
    if name in ("return",): a2 = a.replace("\\n", "\n")
    if src.count(a2) < 1:
        a2 = a2.replace("\\n", "\n")
    if src.count(a2) < 1: print(f"mutant {name:14s} PATTERN MISSING"); sys.exit(2)
    b2 = b if name in ("msg-level", "msg-arg") else b.replace("\\n", "\n")
    open(f"{out}/m.rs", "w").write(src.replace(a2, b2, 1))
    exe = f"{out}/m"
    ccf = f"-O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-implicit-function-declaration -Wno-int-conversion -I{here}"
    subprocess.run(["bash", "-c", f"cc {ccf} -DPARAMSINC='\"{out}/params.inc\"' -c -o {exe}.p.o {here}/params_ref.c && cc {ccf} -DEARLYINC='\"{out}/early.inc\"' -c -o {exe}.e.o {here}/early_ref.c && sed 's|MAINRS|{out}/m.rs|' {here}/early_cmp.rs > {exe}.cmp.rs"], check=True)
    r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test", "-C", "relocation-model=static", "-C", "link-arg=-no-pie",
                        "-C", f"link-arg={exe}.p.o", "-C", f"link-arg={exe}.e.o", "--crate-name", "earlycmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
    if r.returncode and name == "offset-func":   # the compile-time layout assert refuses it: caught before any run
        caught += 1; print(f"mutant {name:14s} CAUGHT (compile-time assert)"); continue
    if r.returncode: print(f"mutant {name:14s} COMPILE-FAIL"); print(r.stderr.decode()[-500:]); continue
    r = subprocess.run([exe], env={"N": "20000"}, capture_output=True)
    st = "CAUGHT" if r.returncode else "*** NOT CAUGHT"
    if "EQUIV" in name:  # doing-EQUIV: `doing` only reaches messages parse_args prints on errors, which do_early_param never returns; min-level-EQUIV: levels are only compared against table entries and the table is empty
        equiv += 1; st = "equivalent (expected not caught)" if not r.returncode else "*** EQUIVALENT MUTANT WAS CAUGHT"
    elif r.returncode: caught += 1
    print(f"mutant {name:14s} {st}")
print(f"sabotage: {caught} of {len(M) - equiv} non-equivalent mutants caught, {equiv} equivalent"); sys.exit(0 if caught == len(M) - equiv else 1)
PY
fi
