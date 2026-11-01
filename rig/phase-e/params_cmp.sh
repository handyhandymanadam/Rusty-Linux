#!/usr/bin/env bash
# Userspace differential for params_rs.rs vs the real C cut out of the pristine params.c / lib/cmdline.c.  params_cmp.sh [--sabotage]   env: N cases
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${PARAMS_RS:-$root/port/tree/kernel/params_rs.rs}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/params_gen.py" "$root/port/pristine/kernel/params.c" "$root/src/linux/lib/cmdline.c" "$out/params.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1); C cut unedited (pristine params.c + next_arg): $(wc -l < "$out/params.inc") lines"
build() {  # build <rs> <exe>
    cc -O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -Wno-unused-variable -Wno-implicit-function-declaration -I"$here" -DPARAMSINC="\"$out/params.inc\"" -c -o "$2.ref.o" "$here/params_ref.c"
    sed "s|PARAMSRS|$1|" "$here/params_cmp.rs" > "$2.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test --cfg CONFIG_SYSFS \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$2.ref.o" --crate-name paramscmp -o "$2" "$2.cmp.rs" 2>&1 | grep -E "^error" -A8 || true
}
if [ "${1:-}" != "--sabotage-only" ]; then build "$RS" "$out/t"; "$out/t"; fi
if [ "${1:-}" = "--sabotage" ] || [ "${1:-}" = "--sabotage-only" ]; then
python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("dash-map", "if c == b'-' {\\n        b'_'", "if c == b'-' {\\n        b'-'"),
 ("dash-map2-EQUIV", "if c == b'-' {\\n        b'_'", "if c == b'_' {\\n        b'-'"),
 ("parameqn-bound", "while i < n {\\n        // SAFETY: caller contract (the C", "while i + 1 < n {\\n        // SAFETY: caller contract (the C"),
 ("parameqn-ne", "if dash2underscore(x) != dash2underscore(y) {", "if x != y {"),
 ("parameq-nonul", "unsafe { parameqn(a, b, len.wrapping_add(1)) }", "unsafe { parameqn(a, b, len) }"),
 ("level-lt", "if level < min_level || level > max_level {", "if level <= min_level || level > max_level {"),
 ("level-gt", "if level < min_level || level > max_level {", "if level < min_level || level >= max_level {"),
 ("level-or", "if level < min_level || level > max_level {", "if level < min_level {"),
 ("noarg-inv", "val.is_null() && ops.flags & KERNEL_PARAM_OPS_FL_NOARG == 0", "val.is_null() && ops.flags & KERNEL_PARAM_OPS_FL_NOARG != 0"),
 ("noarg-ret", "return -EINVAL;", "return -ENOENT;"),
 ("unsafe-ret", "-EPERM }", "-EINVAL }"),
 ("no-lock", "kernel_param_lock((*p).module);\\n", "\\n"),
 ("no-unlock", "kernel_param_unlock((*p).module);\\n", "\\n"),
 ("lock-other-mod", "kernel_param_lock((*p).module);", "kernel_param_lock(core::ptr::null_mut());"),
 ("skip-check", "if param_check_unsafe(p) {", "if true {"),
 ("first-only", "        i = i.wrapping_add(1);\\n    }\\n\\n    if let Some(f)", "        return -ENOENT;\\n    }\\n\\n    if let Some(f)"),
 ("unknown-skip", "if let Some(f) = handle_unknown {", "if let Some(f) = handle_unknown.filter(|_| false) {"),
 ("unknown-code", "    -ENOENT\\n}\\n\\n/// `val ?: \"\"`", "    -EINVAL\\n}\\n\\n/// `val ?: \"\"`"),
 ("dashdash-val", "if val.is_null() && unsafe { is_dashdash(param) } {", "if unsafe { is_dashdash(param) } {"),
 ("dashdash-single", "*s as u8 == b'-' && *s.add(1) as u8 == b'-' && *s.add(2) == 0", "*s as u8 == b'-' && *s.add(1) as u8 == b'-'"),
 ("dashdash-ret", "return if !err.is_null() { err } else { args };", "return args;"),
 ("dashdash-ret2", "return if !err.is_null() { err } else { args };", "return err;"),
 ("irq-warn-off", "if irq_was_disabled && !irqs_disabled() {", "if false {"),
 ("irq-warn-inv", "if irq_was_disabled && !irqs_disabled() {", "if !irq_was_disabled && !irqs_disabled() {"),
 ("irq-before", "let irq_was_disabled = irqs_disabled();", "let irq_was_disabled = true;"),
 ("continue-nonzero", "0 => continue,", "0 => { err = core::ptr::null_mut(); continue }"),
 ("enoent-msg", "Unknown parameter", "Unknown parameters"),
 ("enospc-msg", "too large for parameter", "too big for parameter"),
 ("einval-msg", "invalid for parameter", "invalid for parameters"),
 ("warn-msg", "enabled irq's!", "enabled irqs!"),
 ("lvl-err", "\\x013%s: Unknown", "\\x014%s: Unknown"),
 ("lvl-warn", "\\x014%s: option", "\\x013%s: option"),
 ("enospc-val", "doing, v, param) };", "doing, param, param) };"),
 ("noval-null", "let v = if val.is_null() { EMPTY.as_ptr() as *const c_char }", "let v = if val.is_null() { param as *const c_char }"),
 ("err-sticky", "err = ret as isize as *mut c_char; // ERR_PTR(ret)", "err = if err.is_null() { ret as isize as *mut c_char } else { err };"),
 ("err-nonneg", "err = ret as isize as *mut c_char; // ERR_PTR(ret)", "err = (-ret) as isize as *mut c_char;"),
 ("skip-lead", "let mut args = unsafe { skip_spaces(args) };", "let mut args = args;"),
 ("max-level-arg", "parse_one(param, val, doing, params, num, min_level, max_level, arg, unknown)", "parse_one(param, val, doing, params, num, min_level, min_level, arg, unknown)"),
 ("arg-null", "parse_one(param, val, doing, params, num, min_level, max_level, arg, unknown)", "parse_one(param, val, doing, params, num, min_level, max_level, core::ptr::null_mut(), unknown)"),
 ("num-1", "while i < num_params {", "while i + 1 < num_params {"),
]
caught = 0; equiv = 0
for name, a, b in M:
    a = a.replace("\\n", "\n"); b = b.replace("\\n", "\n")
    if src.count(a) < 1: print(f"mutant {name:18s} PATTERN MISSING"); sys.exit(2)
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1))
    exe = f"{out}/m"
    subprocess.run(["bash", "-c", f"cc -O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-implicit-function-declaration -I{here} -DPARAMSINC='\"{out}/params.inc\"' -c -o {exe}.ref.o {here}/params_ref.c && sed 's|PARAMSRS|{out}/m.rs|' {here}/params_cmp.rs > {exe}.cmp.rs"], check=True)
    r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test", "--cfg", "CONFIG_SYSFS",
                        "-C", "relocation-model=static", "-C", "link-arg=-no-pie", "-C", f"link-arg={exe}.ref.o", "--crate-name", "paramscmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
    if r.returncode: print(f"mutant {name:18s} COMPILE-FAIL"); print(r.stderr.decode()[-600:]); continue
    r = subprocess.run([exe], env={"N": "20000"}, capture_output=True)
    st = "CAUGHT" if r.returncode else "*** NOT CAUGHT"
    if "EQUIV" in name:  # provably equivalent: mapping '_' to '-' instead of '-' to '_' defines the same equality (both sides are mapped)
        equiv += 1; st = "equivalent (expected not caught)" if not r.returncode else "*** EQUIVALENT MUTANT WAS CAUGHT"
    elif r.returncode: caught += 1
    print(f"mutant {name:18s} {st}")
print(f"sabotage: {caught} of {len(M) - equiv} non-equivalent mutants caught, {equiv} equivalent"); sys.exit(0 if caught == len(M) - equiv else 1)
PY
fi
