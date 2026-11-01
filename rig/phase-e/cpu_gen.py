#!/usr/bin/env python3
"""cpu_gen.py <pristine common.c> <out.inc> [--bugs --kernel KTREE --prelude P.inc --match M.inc]: the REAL C of the functions common_rs.rs replaces, cut by markers out of the pristine
file with nothing edited except two things: `static` is removed from `default_cpu`, `this_cpu` and `cpu_devs` (which also gets four canary slots, `[X86_VENDOR_NUM + 4]`) (and from `cpu_set_bug_bits`
with --bugs), exactly as common_glue.c does, so that the Rust side and the harness reach the same objects. Cut: default_init(),
default_cpu, this_cpu; cpu_devs; cpuid_dependent_features + filter_cpuid_features; get_cpu_vendor .. get_cpu_address_sizes
(cpu_detect, apply_forced_caps, init_speculation_control, get_cpu_cap); detect_nopl .. early_cpu_init (parse_set_clear_cpuid,
cpu_parse_early_param, early_identify_cpu, init_cpu_devs). With --bugs: the cpu_set_bug_bits group too (see cpu_gen_bugs below)."""
import sys
src = open(sys.argv[1]).read().split('\n')
bugs = '--bugs' in sys.argv        # the cpu_set_bug_bits group (always, in cpu_cmp.sh)
def idx(m, frm=0):
    for k in range(frm, len(src)):
        if m in src[k]: return k
    raise SystemExit('marker missing: ' + m)
def endb(frm, tok='}'):
    for k in range(frm, len(src)):
        if src[k] == tok: return k
    raise SystemExit('end missing')
def blk(a, b): return src[a:b + 1]
def unstatic(lines, name):
    for i, l in enumerate(lines):
        if name in l and l.startswith('static '): lines[i] = l[len('static '):]; return
    raise SystemExit('no static ' + name)
out = []
b = blk(idx('static void default_init'), idx('static const struct cpu_dev *this_cpu')); unstatic(b, 'default_cpu'); unstatic(b, 'this_cpu'); out += b
b = blk(idx('static const struct cpu_dev *cpu_devs[X86_VENDOR_NUM]'), idx('static const struct cpu_dev *cpu_devs[X86_VENDOR_NUM]')); unstatic(b, 'cpu_devs')
b[0] = b[0].replace('cpu_devs[X86_VENDOR_NUM]', 'cpu_devs[X86_VENDOR_NUM + 4]')   # 4 canary slots after the array: an out-of-bounds store of init_cpu_devs() shows
out += b
a = idx('struct cpuid_dependent_feature {'); out += blk(a - 5, endb(idx('static void filter_cpuid_features')))
out += blk(idx('void get_cpu_vendor(struct cpuinfo_x86 *c)'), endb(idx('void get_cpu_address_sizes(struct cpuinfo_x86 *c)')))
out += blk(idx(' * The NOPL instruction is supposed to exist') - 1, endb(idx('void __init early_cpu_init(void)')))
if bugs:
    k0 = idx('#define NO_SPECULATION'); k1 = endb(idx('static void __init cpu_set_bug_bits'))
    b = blk(k0, k1); unstatic(b, 'cpu_set_bug_bits'); unstatic(b, 'cpu_vuln_whitelist[]'); unstatic(b, 'cpu_vuln_blacklist[]'); unstatic(b, 'cpu_latest_microcode[]'); out += b
open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
if bugs:
    # prelude.inc: struct x86_cpu_id + the wildcard defines (include/linux/mod_devicetable.h) and the VFM / X86_MATCH_* macros (asm/cpu_device_id.h), cut from the kernel's own
    # headers (the only edits: the #include lines are dropped, intel-family.h is the real header), and match.inc: x86_match_cpu() of arch/x86/kernel/cpu/match.c
    kt = sys.argv[sys.argv.index('--kernel') + 1]
    md = open(kt + '/include/linux/mod_devicetable.h').read().split('\n')
    a = next(i for i, l in enumerate(md) if l.startswith('struct x86_cpu_id {')); e = next(i for i in range(a, len(md)) if md[i] == '};')
    w0 = next(i for i, l in enumerate(md) if l.startswith('#define X86_VENDOR_ANY')); w1 = next(i for i, l in enumerate(md) if l.startswith('#define X86_CPU_TYPE_ANY'))
    pre = md[a:e + 1] + md[w0:w1 + 1]
    cd = open(kt + '/arch/x86/include/asm/cpu_device_id.h').read().split('\n')
    c0 = next(i for i, l in enumerate(cd) if l.startswith('#define VFM_MODEL_BIT')); c1 = next(i for i, l in enumerate(cd) if l.startswith('extern const struct x86_cpu_id *x86_match_cpu'))
    for l in cd[c0:c1]:
        if l.startswith('#include <linux/mod_devicetable.h>') or l.startswith('#include <asm/processor.h>'): continue
        pre.append(l)
    open(sys.argv[sys.argv.index('--prelude') + 1], 'w').write('\n'.join(pre) + '\n')
    mt = open(kt + '/arch/x86/kernel/cpu/match.c').read().split('\n')
    m0 = next(i for i, l in enumerate(mt) if l.startswith('static bool x86_match_vendor_cpu_type')); m1 = next(i for i, l in enumerate(mt) if l.startswith('EXPORT_SYMBOL(x86_match_cpu)'))
    open(sys.argv[sys.argv.index('--match') + 1], 'w').write('\n'.join(mt[m0:m1]) + '\n')
