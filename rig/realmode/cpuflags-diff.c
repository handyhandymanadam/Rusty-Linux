/* Lockstep differential: arch/x86/boot/cpuflags.c (C original, renamed c_*) against cpuflags_rs.rs (host_mock build), both
 * driven by ONE device model: cr0, the x87 probe (fninit/fnstsw/fnstcw: the "+m" inputs are logged), EFLAGS (pushfd/popfd
 * toggle, i386 variant only), and cpuid (any leaf/subleaf; documented leaves return scenario data, every other register is
 * noise so a wrong leaf/subleaf/register choice shows). Per scenario both implementations run from the same pre-filled
 * cpu/cpu_vendor/loaded_flags; get_cpuflags() is called 1..3 times (the CPU model is changed between calls to prove the
 * once-only latch); every device call (kind + all args + results) goes into an event list; the final cpu struct, cpu_vendor,
 * loaded_flags, EFLAGS and cr0 are compared. An independent reference (ref_get, written from what the C text means) must
 * also agree with both. Direct tests: cpuid_count() (all four outputs, random leaf/subleaf) and, in the i386 variant,
 * has_eflag(mask) for random masks (result, events, EFLAGS restored). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef RIG_NCAPINTS
#error RIG_NCAPINTS
#endif
#ifndef RIG_I386
#error RIG_I386
#endif
typedef uint32_t u32;
struct cpu_features { int level, family, model; u32 flags[RIG_NCAPINTS]; };
extern struct cpu_features c_cpu, cpu;
extern u32 c_cpu_vendor[3], cpu_vendor[3];
extern _Bool c_loaded_flags, rs_loaded_flags;
void c_get_cpuflags(void), get_cpuflags(void);
void c_cpuid_count(u32, u32, u32 *, u32 *, u32 *, u32 *), cpuid_count(u32, u32, u32 *, u32 *, u32 *, u32 *);
#if RIG_I386
unsigned char c_has_eflag(unsigned long), has_eflag(u32);
#endif

static uint64_t rs_;
static uint64_t rnd(void){ rs_^=rs_<<13; rs_^=rs_>>7; rs_^=rs_<<17; return rs_; }
static int pick(int n){ return (int)(rnd()%(uint64_t)n); }
static uint64_t mix(uint64_t x){ x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x; }

#define CR0_EM 4u
#define CR0_TS 8u
#define EFL_ID (1u<<21)
struct scen {
  u32 cr0; int fpu_kind; uint16_t fsw_out, fcw_out;   /* x87: kind 0 absent (words untouched), 1 present (0,0x37f), 2 given words */
  u32 eflags, eflw;                                   /* EFLAGS value and writable-bits mask */
  u32 max_intel, max_amd, vend[3], tfms, l1ebx, l1ecx, l1edx, l7ecx, l7other[3], l8eax, l81eax, l81ebx, l81ecx, l81edx, salt;
  int hits_mod;                                       /* change the CPU after the first get_cpuflags call */
};
static struct scen S, S0;
static void gen(void){
  struct scen *s = &S0; memset(s, 0, sizeof *s);
  u32 c[] = {0, CR0_EM, CR0_TS, CR0_EM|CR0_TS, 0x80000011u, 0x80000011u|CR0_EM, 0x60000010u|CR0_TS, 0x1, (u32)rnd()};
  s->cr0 = c[pick(9)] | (pick(4)==0 ? (u32)rnd() : 0);
  s->fpu_kind = pick(5) ? (pick(6) ? 1 : 0) : 2;
  { uint16_t fsws[] = {0, 0, 1, 0x8000, 0x4000, (uint16_t)rnd()}; uint16_t fcws[] = {0x37f, 0x3f, 0x103f, 0x1000, 0x0, 0x13f, 0x7f, 0x137f, 0x2000, 0xffff, (uint16_t)rnd()};
    s->fsw_out = fsws[pick(6)]; s->fcw_out = fcws[pick(11)]; }
  s->eflags = (u32)rnd(); s->eflw = (u32)rnd() & ~EFL_ID; if (pick(5)) s->eflw |= EFL_ID; if (!pick(8)) s->eflw |= 0xffffffffu;
  u32 mi[] = {0,1,2,6,7,8,0xffff,0x10000,0xffffffffu,0x80000000u,(u32)rnd()};
  static const u32 sm[] = {1,2,3,5,6,7,0xd,0x14,0x16,0x20};
  s->max_intel = pick(5) ? sm[pick(10)] : mi[pick(11)];
  u32 ma[] = {0,0x7fffffffu,0x80000000u,0x80000001u,0x80000008u,0x8000ffffu,0x80010000u,0xffffffffu,(u32)rnd()};
  s->max_amd = pick(5) ? 0x80000001u + pick(10) : ma[pick(9)];
  static const u32 V[4][3] = {{0x756e6547,0x49656e69,0x6c65746e},{0x68747541,0x69746e65,0x444d4163},{0x746e6543,0x48727561,0x736c7561},{0x756e6547,0x54656e69,0x3638784d}};
  if (pick(3)) memcpy(s->vend, V[pick(4)], 12); else { s->vend[0]=(u32)rnd(); s->vend[1]=(u32)rnd(); s->vend[2]=(u32)rnd(); }
  static const int fams[] = {0,3,4,5,5,6,6,6,0xf,0xf,0xf,0};
  int fam = fams[pick(12)]; if (fam == 0 && pick(2)) fam = pick(16);
  u32 ext_fam = pick(3) ? 0 : (u32)pick(256), ext_mod = pick(3) ? 0 : (u32)pick(16), mod = (u32)pick(16), step = (u32)pick(16);
  s->tfms = (ext_fam << 20) | (ext_mod << 16) | ((u32)(pick(4)==0 ? pick(16) : 0) << 12) | ((u32)fam << 8) | (mod << 4) | step;
  if (pick(4) == 0) s->tfms = (u32)rnd();
  s->l1ebx = (u32)rnd(); s->l1ecx = (u32)rnd(); s->l1edx = (u32)rnd(); s->l7ecx = (u32)rnd();
  for (int i = 0; i < 3; i++) s->l7other[i] = (u32)rnd();
  s->l8eax = (u32)rnd(); s->l81eax = (u32)rnd(); s->l81ebx = (u32)rnd(); s->l81ecx = (u32)rnd(); s->l81edx = (u32)rnd(); s->salt = (u32)rnd();
  s->hits_mod = pick(2);
}
static void mutate_model(void){   /* a different CPU after the first call: a once-only latch ignores it. Deterministic (S.salt). */
  uint64_t m = mix(S.salt);
  S.max_intel = (u32)m % 30; S.vend[0] ^= 0x55; S.tfms = (u32)(m >> 8); S.l1ecx ^= 0xffffffffu; S.l1edx ^= 0xffffffffu; S.l7ecx ^= 0x1234;
  S.max_amd = 0x80000001u + (u32)(m >> 40) % 4; S.l81ecx ^= 0xffffffffu; S.l81edx ^= 0xffffffffu; S.cr0 ^= CR0_EM; S.fpu_kind = (S.fpu_kind == 1) ? 0 : 1;
  S.eflw ^= EFL_ID;
}

#define EVMAX 256
struct ev { int k; uint64_t a, b, c; };
struct run { struct ev e[EVMAX]; int n; struct cpu_features cpu; u32 vend[3]; int loaded; u32 efl, cr0; _Bool ret; u32 o[4]; } R[2];
static struct run *cur;
static void ev(int k, uint64_t a, uint64_t b, uint64_t c){ if (cur->n < EVMAX) { struct ev *e = &cur->e[cur->n]; e->k=k; e->a=a; e->b=b; e->c=c; } cur->n++; }
static u32 vcr0, veflags; static uint64_t n_events;
u32 mock_read_cr0(void){ ev(1, vcr0, 0, 0); return vcr0; }
void mock_write_cr0(u32 v){ ev(2, v, 0, 0); vcr0 = v; }
void mock_fpu(uint16_t *fsw, uint16_t *fcw){
  ev(3, ((uint64_t)*fsw << 16) | *fcw, vcr0, 0);   /* the "+m" inputs (both must be 0xffff) and cr0 as the probe would see it */
  if (S.fpu_kind == 1) { *fsw = 0; *fcw = 0x37f; } else if (S.fpu_kind == 2) { *fsw = S.fsw_out; *fcw = S.fcw_out; }
}
u32 mock_eflags_get(void){ ev(4, veflags, 0, 0); return veflags; }
void mock_eflags_set(u32 v){ ev(5, v, 0, 0); veflags = (veflags & ~S.eflw) | (v & S.eflw); }
void mock_cpuid(u32 id, u32 cnt, u32 *a, u32 *b, u32 *c, u32 *d){
  u32 ra, rb, rc, rd;
  if (id == 0)               { ra = S.max_intel; rb = S.vend[0]; rd = S.vend[1]; rc = S.vend[2]; if (cnt) ra ^= 0x1000; }
  else if (id == 1)          { ra = S.tfms; rb = S.l1ebx; rc = S.l1ecx; rd = S.l1edx; if (cnt) rc ^= 0x2000; }
  else if (id == 7)          { ra = S.l7other[0]; rb = S.l7other[1]; rc = cnt ? (u32)mix(S.salt ^ cnt) : S.l7ecx; rd = S.l7other[2]; }
  else if (id == 0x80000000u){ ra = S.max_amd; rb = S.l8eax; rc = S.l81ebx ^ 1; rd = S.l81ebx ^ 2; }
  else if (id == 0x80000001u){ ra = S.l81eax; rb = S.l81ebx; rc = S.l81ecx; rd = S.l81edx; if (cnt) rd ^= 0x80; }
  else { uint64_t m = mix(((uint64_t)id << 32 | cnt) ^ S.salt); ra = (u32)m; rb = (u32)(m >> 32); rc = (u32)mix(m); rd = (u32)(mix(m) >> 32); }
  ev(6, ((uint64_t)id << 32) | cnt, ((uint64_t)ra << 32) | rb, ((uint64_t)rc << 32) | rd);
  *a = ra; *b = rb; *c = rc; *d = rd;
}

/* independent reference of what one first get_cpuflags() call leaves behind */
static int ref_get(struct cpu_features *c, u32 *v, int has_id, u32 *cr0_out){
  int cw = 0; *cr0_out = S.cr0;
  if (S.cr0 & (CR0_EM | CR0_TS)) { cw = 1; *cr0_out = S.cr0 & ~(CR0_EM | CR0_TS); }
  uint16_t fsw = 0xffff, fcw = 0xffff;
  if (S.fpu_kind == 1) { fsw = 0; fcw = 0x37f; } else if (S.fpu_kind == 2) { fsw = S.fsw_out; fcw = S.fcw_out; }
  if (fsw == 0 && (fcw & 0x103f) == 0x3f) c->flags[0] |= 1;
  if (!has_id) return cw;
  v[0] = S.vend[0]; v[1] = S.vend[1]; v[2] = S.vend[2];
  if (S.max_intel >= 1 && S.max_intel <= 0xffff) {
    c->flags[0] = S.l1edx; c->flags[4] = S.l1ecx;
    int fam = (S.tfms >> 8) & 15, mod = (S.tfms >> 4) & 15;
    c->level = fam; c->family = fam; c->model = mod;
    if (fam >= 6) c->model = mod + 16 * (int)((S.tfms >> 16) & 15);
  }
  if (S.max_intel >= 7) c->flags[16] = S.l7ecx;
  if (S.max_amd >= 0x80000001u && S.max_amd <= 0x8000ffffu) { c->flags[6] = S.l81ecx; c->flags[1] = S.l81edx; }
  return cw;
}

static int diff_runs(const char *what, struct run *a, struct run *b){
  if (a->n != b->n) { printf("  %s: event count %d vs %d\n", what, a->n, b->n); return 1; }
  for (int i = 0; i < a->n && i < EVMAX; i++) if (memcmp(&a->e[i], &b->e[i], sizeof a->e[i])) {
    printf("  %s: event %d (%d,%llx,%llx,%llx) vs (%d,%llx,%llx,%llx)\n", what, i, a->e[i].k, (unsigned long long)a->e[i].a, (unsigned long long)a->e[i].b, (unsigned long long)a->e[i].c,
           b->e[i].k, (unsigned long long)b->e[i].a, (unsigned long long)b->e[i].b, (unsigned long long)b->e[i].c); return 1; }
  if (memcmp(&a->cpu, &b->cpu, sizeof a->cpu)) { printf("  %s: cpu struct differs\n", what); return 1; }
  if (memcmp(a->vend, b->vend, 12)) { printf("  %s: cpu_vendor differs\n", what); return 1; }
  if (a->loaded != b->loaded || a->efl != b->efl || a->cr0 != b->cr0 || a->ret != b->ret || memcmp(a->o, b->o, 16)) { printf("  %s: loaded/eflags/cr0/ret/out differ\n", what); return 1; }
  return 0;
}
static void snap(struct run *r, struct cpu_features *c, u32 *v, int loaded){ r->cpu = *c; memcpy(r->vend, v, 12); r->loaded = loaded; r->efl = veflags; r->cr0 = vcr0; }

static uint64_t st_calls, st_nofpu, st_fpuok, st_cr0w, st_noid, st_l1, st_l1skip, st_lvl6, st_l7, st_amd, st_amdskip, st_lat, st_f15, st_ext, st_ci, st_he, st_he_t;
static int bad_total;
static int one(void){
  int bad = 0; gen();
  struct cpu_features pre; u32 prev[3];
  for (size_t i = 0; i < sizeof pre / 4; i++) ((u32 *)&pre)[i] = pick(2) ? 0 : (u32)rnd();
  for (int i = 0; i < 3; i++) prev[i] = pick(2) ? 0 : (u32)rnd();
  if (!pick(3)) { memset(&pre, 0, sizeof pre); memset(prev, 0, 12); }
  int ncalls = 1 + pick(3);
  int has_id = 1;
#if RIG_I386
  { u32 after = (S0.eflags & ~S0.eflw) | ((S0.eflags ^ EFL_ID) & S0.eflw); has_id = ((S0.eflags ^ after) & EFL_ID) != 0; }
#endif
  S = S0;
  struct cpu_features refc = pre; u32 refv[3], cro; memcpy(refv, prev, 12);
  int cw = ref_get(&refc, refv, has_id, &cro);
  st_calls++; st_cr0w += cw; st_noid += !has_id; st_lat += ncalls > 1;
  { uint16_t fsw = 0xffff, fcw = 0xffff; if (S.fpu_kind == 1) { fsw = 0; fcw = 0x37f; } else if (S.fpu_kind == 2) { fsw = S.fsw_out; fcw = S.fcw_out; }
    int ok = fsw == 0 && (fcw & 0x103f) == 0x3f; st_fpuok += ok; st_nofpu += !ok; }
  if (has_id) { int l1 = S.max_intel >= 1 && S.max_intel <= 0xffff; st_l1 += l1; st_l1skip += !l1; st_l7 += S.max_intel >= 7;
    int am = S.max_amd >= 0x80000001u && S.max_amd <= 0x8000ffffu; st_amd += am; st_amdskip += !am;
    if (l1) { int f = (S.tfms >> 8) & 15; st_lvl6 += f >= 6; st_f15 += f == 15; st_ext += f >= 6 && ((S.tfms >> 16) & 15) != 0; } }
  for (int w = 0; w < 2; w++) {
    S = S0; cur = &R[w]; cur->n = 0; vcr0 = S.cr0; veflags = S.eflags;
    struct cpu_features *cp = w ? &cpu : &c_cpu; u32 *vp = w ? cpu_vendor : c_cpu_vendor; _Bool *lf = w ? &rs_loaded_flags : &c_loaded_flags;
    *cp = pre; memcpy(vp, prev, 12); *lf = 0;
    for (int k = 0; k < ncalls; k++) { if (k == 1 && S.hits_mod) mutate_model(); if (w) get_cpuflags(); else c_get_cpuflags(); }
    snap(cur, cp, vp, *lf); n_events += cur->n;
  }
  bad |= diff_runs("get_cpuflags", &R[0], &R[1]);
  /* reference: cpu struct, vendor, cr0 (the C/Rust first call), loaded flag */
  if (memcmp(&R[0].cpu, &refc, sizeof refc) || memcmp(R[0].vend, refv, 12) || !R[0].loaded) { printf("  reference model disagrees with C (cpu/vendor/loaded)\n"); bad = 1; }
  if (S0.hits_mod == 0 || ncalls == 1) { if (R[0].cr0 != cro) { printf("  reference cr0 %x vs %x\n", cro, R[0].cr0); bad = 1; } }
  /* direct cpuid_count */
  S = S0;
  for (int t = 0; t < 4; t++) {
    u32 id = pick(3) ? (u32[]){0,1,7,0x80000000u,0x80000001u,2,4,0xb}[pick(8)] : (u32)rnd(), cnt = pick(2) ? 0 : (u32)rnd();
    for (int w = 0; w < 2; w++) { cur = &R[w]; cur->n = 0; u32 *o = cur->o; o[0]=o[1]=o[2]=o[3]=0xa5a5a5a5u;
      if (w) cpuid_count(id, cnt, &o[0], &o[1], &o[2], &o[3]); else c_cpuid_count(id, cnt, &o[0], &o[1], &o[2], &o[3]);
      memset(&cur->cpu, 0, sizeof cur->cpu); memset(cur->vend, 0, 12); cur->loaded = 0; cur->efl = veflags; cur->cr0 = vcr0; cur->ret = 0; }
    bad |= diff_runs("cpuid_count", &R[0], &R[1]); st_ci++;
  }
#if RIG_I386
  for (int t = 0; t < 4; t++) {
    u32 mask = pick(3) == 0 ? EFL_ID : pick(2) ? (1u << pick(32)) : (u32)rnd();
    for (int w = 0; w < 2; w++) { S = S0; cur = &R[w]; cur->n = 0; veflags = S.eflags; vcr0 = 0;
      cur->ret = w ? has_eflag(mask) : c_has_eflag(mask);
      memset(&cur->cpu, 0, sizeof cur->cpu); memset(cur->vend, 0, 12); cur->loaded = 0; cur->efl = veflags; cur->cr0 = 0; memset(cur->o, 0, 16); }
    bad |= diff_runs("has_eflag", &R[0], &R[1]); st_he++;
    { u32 after = (S0.eflags & ~S0.eflw) | ((S0.eflags ^ mask) & S0.eflw); int exp = ((S0.eflags ^ after) & mask) != 0;   /* reference: toggle visible iff a mask bit is writable */
      st_he_t += exp; if ((R[0].ret != 0) != exp) { printf("  has_eflag reference: C %d expected %d\n", R[0].ret, exp); bad = 1; } }
  }
#endif
  return bad;
}
int main(int argc, char **argv){
  long n = argc > 1 ? atol(argv[1]) : 20000; rs_ = (argc > 2 ? strtoull(argv[2], 0, 0) : 1) * 0x9e3779b97f4a7c15ULL | 1;
  long mism = 0, shown = 0;
  for (long i = 0; i < n; i++) { if (one()) { mism++; if (++shown >= 5) break; } }
  printf("cpuflags-diff: i386=%d NCAPINTS=%d scenarios=%ld calls=%llu events=%llu | fpu ok %llu / absent-or-bad %llu, cr0 rewritten %llu, no-CPUID %llu, leaf1 %llu / skipped %llu, level>=6 %llu (family 15 %llu, ext-model!=0 %llu), leaf7 %llu, ext leaf %llu / skipped %llu, repeated calls %llu, cpuid_count tests %llu, has_eflag tests %llu (toggle seen %llu)\n",
         RIG_I386, RIG_NCAPINTS, n, (unsigned long long)st_calls, (unsigned long long)n_events, (unsigned long long)st_fpuok, (unsigned long long)st_nofpu, (unsigned long long)st_cr0w, (unsigned long long)st_noid,
         (unsigned long long)st_l1, (unsigned long long)st_l1skip, (unsigned long long)st_lvl6, (unsigned long long)st_f15, (unsigned long long)st_ext, (unsigned long long)st_l7, (unsigned long long)st_amd, (unsigned long long)st_amdskip,
         (unsigned long long)st_lat, (unsigned long long)st_ci, (unsigned long long)st_he, (unsigned long long)st_he_t);
  printf("mismatches=%ld\n", mism); return mism != 0;
}
