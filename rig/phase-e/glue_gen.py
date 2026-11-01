#!/usr/bin/env python3
"""glue_gen.py: regenerate port/tree/arch/x86/kernel/idt_glue.c, port/tree/kernel/params_glue.c, ..., port/tree/arch/x86/kernel/cpu/common_glue.c from the pristine files (the Rust-owned
functions cut out, `#line` directives keeping upstream's numbering). Run from the repo root."""
def load(p): return open(p).read().split('\n')
def idx(src, marker, frm=0):
    for k in range(frm, len(src)):
        if marker in src[k]: return k
    raise SystemExit('marker missing: ' + marker)
def endb(src, frm, tok='}'):
    for k in range(frm, len(src)):
        if src[k] == tok: return k
    raise SystemExit('end missing')
# ---- idt.c
src = load('port/pristine/arch/x86/kernel/idt.c')
L = lambda n: f'#line {n+1} "arch/x86/kernel/idt.c"'
k_early = idx(src, 'static const __initconst struct idt_data early_idts[]'); b1s = k_early - 4; b1e = endb(src, k_early, '};')
k_ft = idx(src, 'static __init void', idx(src, 'idt_is_f00f_address')); k_ft_end = endb(src, k_ft)
k_si = idx(src, 'static __init void set_intr_gate')
k_et_doc = idx(src, '/**', k_si); k_et = idx(src, 'void __init idt_setup_early_traps', k_et_doc); k_et_end = endb(src, k_et)
k_pf_tab = idx(src, 'static const __initconst struct idt_data early_pf_idts[]'); k_pf_s = k_pf_tab - 4; k_pf_tab_end = endb(src, k_pf_tab, '};')
k_pf = idx(src, 'void __init idt_setup_early_pf'); k_pf_end = endb(src, k_pf)
k_eh = idx(src, 'void __init idt_setup_early_handler'); k_eh_end = endb(src, k_eh)
inc_end = idx(src, '#define DPL0')
keep = []; emit = keep.extend
emit(src[:inc_end]); emit([L(inc_end)])
emit(src[inc_end:b1s]); emit(['/* early_idts[] lives in idt_rs.rs */']); emit([L(b1e + 1)])
emit(src[b1e + 1:k_ft])
emit(['extern void idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size, bool sys);',
      '/* the early-IDT group is Rust (idt_rs.rs); these wrappers exist because idt_table and idt_descr are static here */',
      'extern void idt_setup_early_traps_rs(gate_desc *idt, struct desc_ptr *descr);',
      'extern void idt_setup_early_pf_rs(gate_desc *idt);',
      'extern void idt_setup_early_handler_rs(gate_desc *idt, struct desc_ptr *descr);'])
emit([L(k_ft_end + 1)]); emit(src[k_ft_end + 1:k_et_doc])
emit(src[k_et_doc:k_et]); emit(['void __init idt_setup_early_traps(void)', '{', '\tidt_setup_early_traps_rs(idt_table, &idt_descr);', '}']); emit([L(k_et_end + 1)])
emit(src[k_et_end + 1:k_pf_s])
emit(['/* early_pf_idts[] lives in idt_rs.rs */']); emit([L(k_pf_tab_end + 1)])
emit(src[k_pf_tab_end + 1:k_pf]); emit(['void __init idt_setup_early_pf(void)', '{', '\tidt_setup_early_pf_rs(idt_table);', '}']); emit([L(k_pf_end + 1)])
emit(src[k_pf_end + 1:k_eh]); emit(['void __init idt_setup_early_handler(void)', '{', '\tidt_setup_early_handler_rs(idt_table, &idt_descr);', '}']); emit([L(k_eh_end + 1)])
emit(src[k_eh_end + 1:])
hdr = ['/* SPDX-License-Identifier: GPL-2.0-only */', '/*', ' * arch/x86/kernel/idt.c with the Rust-owned functions removed (idt_rs.rs holds them): idt_setup_from_table(),',
       ' * the early_idts[] / early_pf_idts[] tables and the bodies of idt_setup_early_traps(), idt_setup_early_pf() and',
       " * idt_setup_early_handler(). `#line` keeps upstream's file name and line numbers for what remains (WARN_ON in",
       ' * idt_install_sysvec(), the BUG_ON of init_idt_data() inlined into set_intr_gate()). Everything else is upstream\'s text.', ' */']
open('port/tree/arch/x86/kernel/idt_glue.c', 'w').write('\n'.join(hdr + keep))
# ---- params.c
src = load('port/pristine/kernel/params.c')
a = idx(src, 'static char dash2underscore'); b = idx(src, 'static bool param_check_unsafe'); c = idx(src, 'static int parse_one')
d = idx(src, 'char *parse_args'); e = endb(src, d)
L = lambda n: f'#line {n+1} "kernel/params.c"'
keep = src[:a] + ['/* dash2underscore(), parameqn(), parameq() live in params_rs.rs */', L(b)] + ['bool param_check_unsafe(const struct kernel_param *kp);  /* called by params_rs.rs */', 'bool param_check_unsafe(const struct kernel_param *kp)'] + src[b + 1:c] + ['/* parse_one() and parse_args() live in params_rs.rs */', L(e + 1)] + src[e + 1:]
hdr = ['/* SPDX-License-Identifier: GPL-2.0-or-later */', '/* kernel/params.c with the command-line walker removed (params_rs.rs holds dash2underscore, parameqn, parameq, parse_one, parse_args);',
       " * param_check_unsafe() lost its `static` because the Rust parse_one() calls it. `#line` keeps upstream's numbering. */", '#line 1 "kernel/params.c"']
open('port/tree/kernel/params_glue.c', 'w').write('\n'.join(hdr + keep))
# ---- x86_init.c: the six global one-line no-ops
src = load('port/pristine/arch/x86/kernel/x86_init.c')
DROP = ('void x86_init_noop(void) { }', 'void __init x86_init_uint_noop(unsigned int unused) { }', 'bool __init bool_x86_init_noop(void) { return false; }',
        'void x86_op_int_noop(int cpu) { }', 'int set_rtc_noop(const struct timespec64 *now) { return -EINVAL; }', 'void get_rtc_noop(struct timespec64 *now) { }')
res = ['/* SPDX-License-Identifier: GPL-2.0-only */', "/* arch/x86/kernel/x86_init.c with the six global no-op callbacks removed (x86_init_rs.rs holds them); `#line` keeps upstream's numbering. */",
       '#line 1 "arch/x86/kernel/x86_init.c"']
last = False
for i, l in enumerate(src):
    if l in DROP:
        assert l in DROP; last = True; continue
    if last:
        res.append(f'#line {i+1} "arch/x86/kernel/x86_init.c"'); last = False
    res.append(l)
open('port/tree/arch/x86/kernel/x86_init_glue.c', 'w').write('\n'.join(res))
# ---- init/main.c: the early command-line pass (do_early_param, parse_early_options, parse_early_param), one contiguous block
src = load('port/pristine/init/main.c')
a = idx(src, '/* Check for early params. */'); b = endb(src, idx(src, 'void __init parse_early_param'))
keep = src[:a] + ['/* do_early_param(), parse_early_options(), parse_early_param() live in main_rs.rs */', f'#line {b+2} "init/main.c"'] + src[b + 1:]
hdr = ['/* SPDX-License-Identifier: GPL-2.0-only */', "/* init/main.c with the early command-line pass removed (main_rs.rs holds do_early_param, parse_early_options, parse_early_param); `#line` keeps upstream's numbering. */",
       '#line 1 "init/main.c"']
open('port/tree/init/main_glue.c', 'w').write('\n'.join(hdr + keep))
# ---- arch/x86/kernel/cpu/common.c: the CPUID decode group + early identification (common_rs.rs); everything else stays
src = load('port/pristine/arch/x86/kernel/cpu/common.c')
L = lambda n: f'#line {n+1} "arch/x86/kernel/cpu/common.c"'
H = '__attribute__((visibility("hidden")))'
def sub(line_marker, old, new):
    k = idx(src, line_marker); assert old in src[k], (line_marker, src[k]); src[k] = src[k].replace(old, new)
sub('static const struct cpu_dev default_cpu = {', 'static const struct cpu_dev default_cpu = {', f'const struct cpu_dev default_cpu {H} = {{')
sub('static const struct cpu_dev *this_cpu = &default_cpu;', 'static const struct cpu_dev *this_cpu', f'const struct cpu_dev *this_cpu {H}')
sub('static const struct cpu_dev *cpu_devs[X86_VENDOR_NUM] = {};', 'static const struct cpu_dev *cpu_devs[X86_VENDOR_NUM]', f'const struct cpu_dev *cpu_devs[X86_VENDOR_NUM] {H}')
sub('static const __initconst struct x86_cpu_id cpu_vuln_whitelist[] = {', 'static const __initconst struct x86_cpu_id cpu_vuln_whitelist[]', f'const __initconst struct x86_cpu_id cpu_vuln_whitelist[] {H}')
sub('static const struct x86_cpu_id cpu_vuln_blacklist[] __initconst = {', 'static const struct x86_cpu_id cpu_vuln_blacklist[]', f'const struct x86_cpu_id cpu_vuln_blacklist[] {H}')
sub('static struct x86_cpu_id cpu_latest_microcode[] = {', 'static struct x86_cpu_id cpu_latest_microcode[]', f'struct x86_cpu_id cpu_latest_microcode[] {H}')
a1 = idx(src, 'struct cpuid_dependent_feature {') - 5; assert src[a1] == '/*', src[a1]
a1e = endb(src, idx(src, 'static void filter_cpuid_features'))
b0 = idx(src, 'void get_cpu_vendor(struct cpuinfo_x86 *c)'); b1 = endb(src, idx(src, 'void get_cpu_address_sizes(struct cpuinfo_x86 *c)'))
d1 = idx(src, 'static bool __init cpu_matches'); d1e = endb(src, d1)
d2 = idx(src, 'static bool arch_cap_mmio_immune'); d2e = endb(src, idx(src, 'static bool __init vulnerable_to_its'))
d3 = idx(src, 'static bool __init cpu_has_old_microcode'); d3e = endb(src, idx(src, 'static void __init cpu_set_bug_bits'))
c0 = idx(src, ' * The NOPL instruction is supposed to exist') - 1; assert src[c0] == '/*', src[c0]
assert d1e < d2 < d2e < d3 < d3e < c0
c1 = endb(src, idx(src, 'void __init early_cpu_init(void)'))
pre_c = src[b1 + 1:d1] + ['/* cpu_matches() lives in common_rs.rs */', L(d1e + 1)] + src[d1e + 1:d2] + ['/* arch_cap_mmio_immune(), vulnerable_to_rfds(), vulnerable_to_its() live in common_rs.rs */', L(d2e + 1)] + src[d2e + 1:d3] + \
        ['/* cpu_has_old_microcode() and cpu_set_bug_bits() live in common_rs.rs */', L(d3e + 1)] + src[d3e + 1:c0]
keep = src[:a1] + ['/* filter_cpuid_features() lives in common_rs.rs (global, hidden); identify_cpu() calls it */', 'void filter_cpuid_features(struct cpuinfo_x86 *c, bool warn);', 'void apply_forced_caps(struct cpuinfo_x86 *c);', L(a1e + 1)] + src[a1e + 1:b0] + \
       ['/* get_cpu_vendor(), cpu_detect(), apply_forced_caps(), init_speculation_control(), get_cpu_cap(), get_cpu_address_sizes() live in common_rs.rs */', L(b1 + 1)] + pre_c + \
       ['/* detect_nopl(), parse_set_clear_cpuid(), cpu_parse_early_param(), early_identify_cpu(), init_cpu_devs(), early_cpu_init() live in common_rs.rs */', L(c1 + 1)] + src[c1 + 1:]
keep += ['', '/* The WARN_ON(alternatives_patched) of setup_force_cpu_cap(), called by the Rust arm (common_rs.rs) when a feature is first forced after the alternatives were patched. */',
         f'#line {len(src) + 1} "arch/x86/kernel/cpu/common.c"', 'void x86_force_cap_warn(void);', 'void x86_force_cap_warn(void)', '{', '\tWARN_ON(alternatives_patched);', '}']
hdr = ['/* SPDX-License-Identifier: GPL-2.0-only */', "/* arch/x86/kernel/cpu/common.c with the CPUID decode group and the early identification removed (common_rs.rs holds them); the statics those functions share with the rest",
       " * (default_cpu, this_cpu, cpu_devs and the three x86_cpu_id tables) are global with hidden visibility. `#line` keeps upstream's file name and line numbers. */", '#line 1 "arch/x86/kernel/cpu/common.c"']
open('port/tree/arch/x86/kernel/cpu/common_glue.c', 'w').write('\n'.join(hdr + keep) + '\n')
