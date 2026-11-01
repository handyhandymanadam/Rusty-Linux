/* Lockstep differential: C cpu.c + cpucheck.c (c_validate_cpu, c_check_cpu, c_check_knl_erratum, c_show_cap_strs)
 * against the Rust cpu_rs.rs + cpucheck_rs.rs (validate_cpu, check_cpu, check_knl_erratum, rs_show_cap_strs),
 * both built for the HOST against one device model: get_cpuflags()/cpu/cpu_vendor (cpuflags.c's real logic, driven by a random
 * CPU), rdmsr/wrmsr (a few modelled MSRs), cpuid leaf 1 (Transmeta), cmdline_find_option_bool, has_eflag (32-bit only),
 * and the console (puts/printf/putchar/sprintf). Per scenario every API is run from a reset state for BOTH implementations;
 * every device call (kind + all arguments + results) goes into an event list, every printed byte into an output buffer;
 * return values, the out-parameters, the err_flags words and the final `cpu` struct are compared too.
 * Also: the show_cap_strs walker against a straightforward reference (all 22x32 single bits, random multi-bit words, all
 * ones) and the table facts the walk relies on (sorted, last entry (21,31) present, every read inside the table). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#ifndef RIG_NCAPINTS
#error RIG_NCAPINTS
#endif
typedef uint32_t u32;
struct cpu_features { int level, family, model; u32 flags[RIG_NCAPINTS]; };
struct cpu_features cpu;
u32 cpu_vendor[3];

int c_validate_cpu(void), validate_cpu(void);
int c_check_cpu(int *, int *, u32 **), check_cpu(int *, int *, u32 **);
int c_check_knl_erratum(void), check_knl_erratum(void);
void c_show_cap_strs(const u32 *), rs_show_cap_strs(const u32 *);

static uint64_t rs;
static uint64_t rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }
static int pick(int n){ return (int)(rnd()%(uint64_t)n); }

/* ---- scenario: one CPU + device behaviour ---- */
static const u32 VEND[5][3] = {  /* in cpu_vendor[] order (ebx, edx, ecx of leaf 0): A32 words as in cpucheck.c */
  {0x68747541,0x69746e65,0x444d4163},   /* AuthenticAMD */
  {0x746e6543,0x48727561,0x736c7561},   /* CentaurHauls */
  {0x756e6547,0x54656e69,0x3638784d},   /* GenuineTMx86 */
  {0x756e6547,0x49656e69,0x6c65746e},   /* GenuineIntel */
  {0x756e6547,0x20656e69,0x20202020}};  /* something else */
struct scen {
  int has_id, fpu, reload, ac, forcepae;
  u32 max_intel, max_amd, tfms, f0, f1, f4, f6, f16, vend[3];
  u32 hwcr_l, hwcr_h, fcr_l, fcr_h, tm_l, tm_h, tm_unmasked_edx;
  int pre_family, pre_model;               /* check_knl_erratum standalone: cpu.family/model preset */
} S;
static u32 REQ0 = RIG_R0, REQ1 = RIG_R1, REQ4 = RIG_R4, REQ6 = RIG_R6, REQ16 = RIG_R16;
enum { XMM = 25, XMM2 = 26, CX8 = 8, PAE = 6, LM = 29 };

static void gen_scen(void){
  memset(&S, 0, sizeof S);
  S.has_id = pick(10) != 0; S.fpu = pick(8) != 0; S.reload = pick(3) == 0; S.ac = pick(4) != 0;
  S.forcepae = (int[]){0,1,-1,2}[pick(4)];
  int v = pick(8);
  if (v < 5) memcpy(S.vend, VEND[v], 12);
  else if (v == 5) { memcpy(S.vend, VEND[pick(4)], 12); S.vend[pick(3)] = (u32)rnd(); }   /* near miss */
  else { S.vend[0] = (u32)rnd(); S.vend[1] = (u32)rnd(); S.vend[2] = (u32)rnd(); }
  u32 mi[] = {0,1,7,0xffff,0x10000,0x80000000u,(u32)rnd()}; S.max_intel = pick(4) ? 1 + pick(20) : mi[pick(7)];
  u32 ma[] = {0,0x80000000u,0x80000001u,0x8000ffff,0x80010000u,(u32)rnd()}; S.max_amd = pick(3) ? 0x80000001u + pick(8) : ma[pick(6)];
  int fam = (int[]){3,4,5,6,6,6,15,pick(16)}[pick(8)], model = (int[]){9,13,9,13,0x57,pick(16),pick(16)}[pick(7)];
  int ext = pick(4) == 0 ? 0 : (model == 0x57 ? 5 : pick(16));
  int mnib = model == 0x57 ? 7 : model & 15;
  S.tfms = ((u32)ext << 16) | ((u32)fam << 8) | ((u32)mnib << 4) | (u32)pick(16);
  if (pick(3) == 0) S.tfms = (u32)rnd();
  /* flag words: mostly "everything required present", then knock out a chosen set */
  u32 x = (u32)rnd();
  S.f0 = (REQ0 | (u32)rnd()) & ~0u; S.f1 = REQ1 | (u32)rnd(); S.f4 = REQ4 | (u32)rnd(); S.f6 = REQ6 | (u32)rnd(); S.f16 = REQ16 | (u32)rnd();
  if (pick(2)) S.f1 |= 1u << LM;             /* long mode usually present when tested */
  switch (pick(10)) {
  case 0: break;
  case 1: S.f0 &= ~((1u<<XMM)|(1u<<XMM2)); break;
  case 2: S.f0 &= ~(1u<<XMM); break;
  case 3: S.f0 &= ~(1u<<XMM2); break;
  case 4: S.f0 &= ~(1u<<CX8); break;
  case 5: S.f0 &= ~(1u<<PAE); break;
  case 6: S.f0 &= ~(REQ0 & x); break;
  case 7: S.f1 &= ~(REQ1 & x); S.f4 &= ~(REQ4 & (u32)rnd()); break;
  case 8: S.f6 &= ~(REQ6 & x); S.f16 &= ~(REQ16 & (u32)rnd()); S.f0 &= ~(1u<<CX8); break;
  default: S.f0 = (u32)rnd(); S.f1 = (u32)rnd(); S.f4 = (u32)rnd(); S.f6 = (u32)rnd(); S.f16 = (u32)rnd(); break;
  }
  S.hwcr_l = (u32)rnd(); S.hwcr_h = (u32)rnd(); S.fcr_l = (u32)rnd(); S.fcr_h = (u32)rnd();
  S.tm_l = (u32)rnd(); S.tm_h = (u32)rnd();
  S.tm_unmasked_edx = pick(2) ? (S.f0 | REQ0) : (u32)rnd();
  S.pre_family = pick(3) ? 6 : pick(16); S.pre_model = pick(2) ? 0x57 : pick(0x100);
  /* aim half of the scenarios at one vendor branch of check_cpu: everything present except the branch's trigger */
  int t = pick(8);
  if (t < 4) {
    S.has_id = 1; S.max_intel = 1 + pick(10); S.max_amd = 0x80000001u + pick(4); S.fpu = 1;
    S.f0 = REQ0 | (u32)rnd(); S.f1 = REQ1 | (u32)rnd() | (1u << LM); S.f4 = REQ4 | (u32)rnd(); S.f6 = REQ6 | (u32)rnd(); S.f16 = REQ16 | (u32)rnd();
    S.f0 |= 1u;
    if (t == 0) { memcpy(S.vend, VEND[0], 12); S.f0 &= ~(((u32)(pick(3) + 1) & 3) << XMM); if (!(~S.f0 & ((1u<<XMM)|(1u<<XMM2)))) S.f0 &= ~(1u<<XMM2); }
    if (t == 1) { memcpy(S.vend, VEND[1], 12); S.f0 &= ~(1u << CX8); S.tfms = (S.tfms & ~0xf0f00u) | ((u32)(pick(2) ? 6 : 3 + pick(4)) << 8); }
    if (t == 2) { memcpy(S.vend, VEND[2], 12); S.f0 &= ~(REQ0 & (u32)rnd() & (u32)rnd()); if (!(~S.f0 & REQ0)) S.f0 &= ~(1u << CX8); }
    if (t == 3) { memcpy(S.vend, VEND[3], 12); S.f0 &= ~(1u << PAE); S.f1 &= ~(1u << LM); S.tfms = (6u << 8) | ((u32)(pick(2) ? 9 : 13) << 4) | (S.tfms & 0xf); }
  }
}

/* ---- device model state, event + output logs ---- */
#define EVMAX 4096
struct ev { int k; uint64_t a, b, c; };
struct run { struct ev e[EVMAX]; int n; char out[8192]; int outn; int ret, lv, rl, efnull; u32 ef[RIG_NCAPINTS]; struct cpu_features cpu; int ret2, lv2, rl2, ef2null; } R[2];
static struct run *cur;
static int loaded, hwcr_cleared15;
static u32 msr_l[3], msr_h[3];
static void ev(int k, uint64_t a, uint64_t b, uint64_t c){ if (cur->n < EVMAX) { cur->e[cur->n].k=k; cur->e[cur->n].a=a; cur->e[cur->n].b=b; cur->e[cur->n].c=c; } cur->n++; }
static void emit(const char *s, int n){ if (cur->outn + n < (int)sizeof cur->out) { memcpy(cur->out + cur->outn, s, n); cur->outn += n; cur->out[cur->outn] = 0; } }
static uint64_t hstr(const char *s){ uint64_t h = 1469598103934665603ULL; while (*s) h = (h ^ (unsigned char)*s++) * 1099511628211ULL; return h; }
int mock_printf(const char *fmt, ...){ char b[256]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap); ev(1, hstr(fmt), hstr(b), n); emit(b, n); return n; }
int mock_sprintf(char *buf, const char *fmt, ...){ va_list ap; va_start(ap, fmt); int n = vsprintf(buf, fmt, ap); va_end(ap); ev(2, hstr(fmt), hstr(buf), n); return n; }
void mock_puts(const char *s){ ev(3, hstr(s), strlen(s), 0); emit(s, (int)strlen(s)); }
void mock_putchar(int c){ ev(4, (uint64_t)(unsigned)c, 0, 0); char ch = (char)c; emit(&ch, 1); }
int mock_cmdline_find_option_bool(const char *o){ ev(5, hstr(o), (uint64_t)(unsigned)S.forcepae, 0); return S.forcepae; }
unsigned char mock_has_eflag(unsigned long m){
#if RIG_X86_64
  (void)m; return 1;      /* the C header's inline: constant true (the Rust does not call it at all) */
#else
  ev(6, m, (uint64_t)S.ac, 0); return S.ac != 0;
#endif
}
static int msr_idx(unsigned r){ return r == 0xc0010015u ? 0 : r == 0x1107u ? 1 : r == 0x80860004u ? 2 : -1; }
void mock_rdmsr(unsigned reg, unsigned *l, unsigned *h){
  int i = msr_idx(reg);
  if (i >= 0) { *l = msr_l[i]; *h = msr_h[i]; } else { *l = reg * 2654435761u; *h = reg ^ 0xdeadbeefu; }
  ev(7, reg, *l, *h);
}
void mock_wrmsr(unsigned reg, unsigned l, unsigned h){
  int i = msr_idx(reg); ev(8, reg, l, h);
  if (i >= 0) { msr_l[i] = l; msr_h[i] = h; }
  if (reg == 0xc0010015u && !(l & (1u << 15))) hwcr_cleared15 = 1;
}
unsigned mock_cpuid1(unsigned level, unsigned *edx){
  /* Transmeta: leaf 1 edx as seen while the feature-mask MSR is all ones */
  *edx = (msr_l[2] == 0xffffffffu) ? S.tm_unmasked_edx : cpu.flags[0];
  ev(9, level, *edx, msr_l[2] == 0xffffffffu); return level;
}
/* cpuflags.c's get_cpuflags(), same logic and order; the CPU is the scenario. */
void get_cpuflags(void){
  ev(10, (uint64_t)loaded, 0, 0);
  if (loaded && !S.reload) return;
  loaded = 1;
  if (S.fpu) cpu.flags[0] |= 1u;
  if (S.has_id) {
    cpu_vendor[0] = S.vend[0]; cpu_vendor[2] = S.vend[2]; cpu_vendor[1] = S.vend[1];
    if (S.max_intel >= 1 && S.max_intel <= 0xffff) {
      cpu.flags[4] = S.f4; cpu.flags[0] = S.f0;
      if (hwcr_cleared15) cpu.flags[0] |= (1u << XMM) | (1u << XMM2);   /* "AMD turned SSE on" once the HWCR bit is cleared */
      cpu.level = (S.tfms >> 8) & 15; cpu.family = cpu.level; cpu.model = (S.tfms >> 4) & 15;
      if (cpu.level >= 6) cpu.model += ((S.tfms >> 16) & 0xf) << 4;
    }
    if (S.max_intel >= 7) cpu.flags[16] = S.f16;
    if (S.max_amd >= 0x80000001u && S.max_amd <= 0x8000ffffu) { cpu.flags[6] = S.f6; cpu.flags[1] = S.f1; }
  }
}
static void reset(struct run *r, int family_preset){
  memset(&cpu, 0, sizeof cpu); memset(cpu_vendor, 0, sizeof cpu_vendor);
  loaded = 0; hwcr_cleared15 = 0;
  msr_l[0] = S.hwcr_l; msr_h[0] = S.hwcr_h; msr_l[1] = S.fcr_l; msr_h[1] = S.fcr_h; msr_l[2] = S.tm_l; msr_h[2] = S.tm_h;
  r->n = 0; r->outn = 0; r->out[0] = 0; cur = r;
  if (family_preset) { cpu.family = S.pre_family; cpu.model = S.pre_model; cpu.level = 6; memcpy(cpu_vendor, S.vend, 12); }
}

static int cmp_run(const char *what, struct run *a, struct run *b, int checkcpu, int checkout){
  if (a->n != b->n) { printf("  %s: event count C=%d Rust=%d\n", what, a->n, b->n); return 1; }
  for (int i = 0; i < a->n && i < EVMAX; i++)
    if (a->e[i].k != b->e[i].k || a->e[i].a != b->e[i].a || a->e[i].b != b->e[i].b || a->e[i].c != b->e[i].c) {
      printf("  %s: event %d C=(%d,%llx,%llx,%llx) Rust=(%d,%llx,%llx,%llx)\n", what, i, a->e[i].k, (unsigned long long)a->e[i].a, (unsigned long long)a->e[i].b, (unsigned long long)a->e[i].c,
             b->e[i].k, (unsigned long long)b->e[i].a, (unsigned long long)b->e[i].b, (unsigned long long)b->e[i].c); return 1; }
  if (a->outn != b->outn || memcmp(a->out, b->out, a->outn)) { printf("  %s: printed output differs\n   C:    [%.*s]\n   Rust: [%.*s]\n", what, a->outn, a->out, b->outn, b->out); return 1; }
  if (a->ret != b->ret) { printf("  %s: return C=%d Rust=%d\n", what, a->ret, b->ret); return 1; }
  if (checkcpu) {
    if (a->lv != b->lv || a->rl != b->rl || a->efnull != b->efnull || (!a->efnull && memcmp(a->ef, b->ef, sizeof a->ef))) { printf("  %s: out params differ lv %d/%d rl %d/%d efnull %d/%d\n", what, a->lv, b->lv, a->rl, b->rl, a->efnull, b->efnull); return 1; }
    if (memcmp(&a->cpu, &b->cpu, sizeof a->cpu)) { printf("  %s: final cpu struct differs\n", what); return 1; }
  }
  (void)checkout; return 0;
}

static uint64_t n_events, n_calls, n_out, br_amd, br_via, br_tm, br_pm, br_pm_force, br_knl, br_err1, br_ret0, br_ret1, br_msg_lvl, br_msg_feat, br_unnamed, w_unnamed;
static int run_one(void){
  int bad = 0; struct run *r;
  for (int api = 0; api < 4; api++) {
    for (int w = 0; w < 2; w++) {
      r = &R[w]; reset(r, api == 2);
      switch (api) {
      case 0: { int lv = 0x5a5a, rl = 0x5a5a; u32 *ef = (u32 *)0x1234; r->ret = w ? check_cpu(&lv, &rl, &ef) : c_check_cpu(&lv, &rl, &ef);
                r->lv = lv; r->rl = rl; r->efnull = ef == NULL; memset(r->ef, 0, sizeof r->ef); if (ef) memcpy(r->ef, ef, sizeof r->ef); r->cpu = cpu; break; }
      case 1: { r->ret = w ? check_cpu(NULL, NULL, NULL) : c_check_cpu(NULL, NULL, NULL); r->lv = r->rl = 0; r->efnull = 1; r->cpu = cpu; break; }
      case 2: r->ret = w ? check_knl_erratum() : c_check_knl_erratum(); r->lv = r->rl = 0; r->efnull = 1; r->cpu = cpu; break;
      case 3: r->ret = w ? validate_cpu() : c_validate_cpu(); r->lv = r->rl = 0; r->efnull = 1; r->cpu = cpu; break;
      }
    }
    static const char *nm[] = {"check_cpu", "check_cpu(NULLs)", "check_knl_erratum", "validate_cpu"};
    if (cmp_run(nm[api], &R[0], &R[1], api < 2, 1)) bad = 1;
    n_calls++; n_events += R[1].n; n_out += R[1].outn;
    if (api == 0) {
      /* branch statistics from the C run's event log (what the device saw) */
      int hw = 0, fc = 0, tm = 0, pae = 0;
      for (int i = 0; i < R[0].n; i++) { if (R[0].e[i].k == 7 && R[0].e[i].a == 0xc0010015u) hw = 1; if (R[0].e[i].k == 7 && R[0].e[i].a == 0x1107u) fc = 1; if (R[0].e[i].k == 7 && R[0].e[i].a == 0x80860004u) tm = 1; if (R[0].e[i].k == 5) pae = 1; }
      br_amd += hw; br_via += fc; br_tm += tm; br_pm += pae; if (pae && S.forcepae) br_pm_force++;
      if (R[0].ret == 0) br_ret0++; else br_ret1++;
    }
    if (api == 2 && R[0].outn) br_knl++;
    if (api == 3) { if (getenv("RIGDBG") && R[0].outn && pick(500)==0) printf("[sample] %.*s\n", R[0].outn, R[0].out); if (strstr(R[0].out, "requires an")) br_msg_lvl++; if (strstr(R[0].out, "following features")) br_msg_feat++; if (strstr(R[0].out, "following")) { for (char *p = R[0].out; *p; p++) if (p[0]>='0'&&p[0]<='9'&&p[1]==':') { br_unnamed++; break; } } }
  }
  return bad;
}

/* ---- walker tests ---- */
static unsigned char *tab; static long tabn; static char *names[RIG_NCAPINTS][32];
static void load_table(const char *path){
  FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
  tab = malloc(1 << 16); tabn = (long)fread(tab, 1, 1 << 16, f); fclose(f);
}
/* parse + check the facts show_cap_strs relies on; returns non-zero on violation */
static int check_table(void){
  long p = 0; int last = -1, n = 0;
  while (p < tabn) {
    if (p + 3 > tabn) { printf("TABLE: truncated entry header at %ld\n", p); return 1; }
    int i = tab[p], j = tab[p+1]; long q = p + 2; while (q < tabn && tab[q]) q++;
    if (q >= tabn) { printf("TABLE: unterminated string at %ld\n", p); return 1; }
    if (i >= RIG_NCAPINTS || j >= 32) { printf("TABLE: key out of range %d:%d\n", i, j); return 1; }
    int key = i * 32 + j; if (key <= last) { printf("TABLE: not strictly increasing at %d:%d\n", i, j); return 1; }
    last = key; names[i][j] = strdup((char *)tab + p + 2); n++; p = q + 1;
  }
  if (last != RIG_NCAPINTS * 32 - 1) { printf("TABLE: last entry key %d != %d (unconditional last entry missing)\n", last, RIG_NCAPINTS * 32 - 1); return 1; }
  printf("table: %ld bytes, %d entries, sorted, last entry %d:31, every string NUL-terminated inside the table\n", tabn, n, RIG_NCAPINTS - 1);
  return 0;
}
/* bounds-instrumented replica of the C pointer walk: every read index must be < tabn (independent of err_flags) */
static int walk_bounds(long *maxread){
  long m = 0; const unsigned char *s = tab; long p = 0;
#define RD(ix) ({ long _i = (ix); if (_i >= tabn || _i < 0) { printf("WALK reads past table at %ld\n", _i); return 1; } if (_i > m) m = _i; s[_i]; })
  for (int i = 0; i < RIG_NCAPINTS; i++)
    for (int j = 0; j < 32; j++) {
      if (RD(p) < i || (RD(p) == i && RD(p+1) < j)) { p += 2; while (RD(p++)) ; }
      (void)RD(p); (void)RD(p+1); (void)RD(p+2);
    }
  *maxread = m; return 0;
}
static char wbuf_c[2][RIG_NCAPINTS * 32 * 24 + 64];
static int walker_case(const u32 *w){
  char ref[RIG_NCAPINTS * 32 * 24 + 64]; int rn = 0;
  for (int i = 0; i < RIG_NCAPINTS; i++) for (int j = 0; j < 32; j++) if (w[i] >> j & 1) {
    if (names[i][j] && names[i][j][0]) rn += sprintf(ref + rn, "%s ", names[i][j]); else { rn += sprintf(ref + rn, "%d:%d ", i, j); w_unnamed++; } }
  struct run *r = &R[0]; reset(r, 0); c_show_cap_strs(w); memcpy(wbuf_c[0], r->out, r->outn); int cn = r->outn; int ce = r->n;
  r = &R[1]; reset(r, 0); rs_show_cap_strs(w); int rsn = r->outn; int re = r->n;
  if (cn != rn || memcmp(wbuf_c[0], ref, rn)) { printf("WALKER C differs from reference\n  C  [%.*s]\n  ref[%.*s]\n", cn, wbuf_c[0], rn, ref); return 1; }
  if (rsn != rn || memcmp(R[1].out, ref, rn)) { printf("WALKER Rust differs from reference\n  Rs [%.*s]\n  ref[%.*s]\n", rsn, R[1].out, rn, ref); return 1; }
  if (ce != re) { printf("WALKER event count C=%d Rust=%d\n", ce, re); return 1; }
  return 0;
}

int main(int argc, char **argv){
  int N = argc > 1 ? atoi(argv[1]) : 20000; rs = argc > 2 ? strtoull(argv[2], 0, 0) | 1 : 88172645463325252ULL;
  const char *tpath = argc > 3 ? argv[3] : "cpustr.bin"; int mism = 0;
  load_table(tpath); if (check_table()) return 1;
  long mr; if (walk_bounds(&mr)) return 1; printf("walk: highest table index read = %ld of %ld (all 704 positions, independent of err_flags)\n", mr, tabn - 1);
  /* walker: single bits, all ones, random */
  long wc = 0; u32 w[RIG_NCAPINTS];
  for (int i = 0; i < RIG_NCAPINTS; i++) for (int j = 0; j < 32; j++) { memset(w, 0, sizeof w); w[i] = 1u << j; mism += walker_case(w); wc++; }
  memset(w, 0, sizeof w); mism += walker_case(w); wc++;
  memset(w, 0xff, sizeof w); mism += walker_case(w); wc++;
  for (int t = 0; t < 20000; t++) { for (int i = 0; i < RIG_NCAPINTS; i++) { u32 x = (u32)rnd(); int d = pick(4); if (d == 0) x &= (u32)rnd(); if (d == 1) x &= (u32)rnd() & (u32)rnd(); if (d == 2) x = 0; w[i] = x; } mism += walker_case(w); wc++; }
  printf("walker: %ld cases (704 single bits, empty, all-ones, 20000 random multi-bit) C == Rust == reference, \"%%d:%%d \" fallback words produced=%llu, mismatches=%d\n", wc, (unsigned long long)w_unnamed, mism);
  /* whole-API lockstep */
  int bad = 0; long first = -1; uint64_t seed0 = rs;
  for (int s = 0; s < N; s++) { gen_scen(); uint64_t keep = rs; if (run_one()) { if (!bad) { first = s; printf("  (first mismatch: scenario %d, rng state after generation %llx; seed arg %llu)\n", s, (unsigned long long)keep, (unsigned long long)seed0); } bad++; } }
  printf("lockstep: %d scenarios x 4 APIs (%llu calls), %llu device events, %llu printed bytes; branches seen (C run, check_cpu): amd-msr=%llu via-msr=%llu transmeta-msr=%llu pentiumM=%llu (forcepae asked=%llu); ret0=%llu ret-1=%llu; validate_cpu: level-msg=%llu features-msg=%llu (of which with an unnamed-bit \"n:m\" word=%llu); knl-text=%llu; mismatches=%d\n",
         N, (unsigned long long)n_calls, (unsigned long long)n_events, (unsigned long long)n_out, (unsigned long long)br_amd, (unsigned long long)br_via, (unsigned long long)br_tm, (unsigned long long)br_pm, (unsigned long long)br_pm_force,
         (unsigned long long)br_ret0, (unsigned long long)br_ret1, (unsigned long long)br_msg_lvl, (unsigned long long)br_msg_feat, (unsigned long long)br_unnamed, (unsigned long long)br_knl, bad);
  (void)first;
  return (bad || mism) ? 1 : 0;
}
