/* Lockstep differential: C a20.c (as c_enable_a20) vs Rust a20_rs.rs (enable_a20) against one simulated
 * PC: A20 gate + 1 MiB wrap, 8042 KBC, port 0x92, BIOS INT 15h AX=2401, port 0x80 delay. Every port access
 * (in/out, port, value), BIOS call (int no + all input registers), segment load and fs/gs memory access is
 * folded into a hash and (first 2M events) stored; the two runs must give identical event streams and
 * identical return values and final memory. Device behaviour is drawn from a seeded RNG, so both runs see the
 * same device as long as they perform the same accesses. */
#include "boot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int c_enable_a20(void); int enable_a20(void);
struct port_io_ops pio_ops;
static uint64_t rs;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs;}
static int pick(int n){return (int)(rnd()%n);}
/* scenario */
static int a20_init, bios_works, bios_delay, kbc_works, kbc_delay, fast_works, fast_delay, st_mode, st_settle, st_pff, st_pobf, st_pibf;
static int fastbit_required;
static uint32_t ivt0, hi0;
/* state */
static int a20, pending, countdown, kbc_cmd_d1, nst;
static u8 p92, p60;
static u16 fsr, gsr;
static uint8_t mem[0x110000];
static uint64_t hash, nev; static uint64_t *rec; static uint64_t recn; static int replay; static uint64_t first_bad; static uint64_t mism;
#define REC_MAX 2000000
static void ev(uint64_t a, uint64_t b, uint64_t c){
	uint64_t x=(a<<48)^(b<<32)^c^(nev*0x9e3779b97f4a7c15ULL);
	hash=(hash^x)*0x100000001b3ULL; hash^=hash>>29;
	if(nev<REC_MAX){ if(!replay) rec[nev]=x; else if(rec[nev]!=x && !mism){mism=1; first_bad=nev;} }
	nev++;
}
static void arm(int delay){ if(a20) return; if(delay==0) a20=1; else { pending=1; countdown=delay; } }
static uint32_t lin(u16 seg, u32 off){ uint32_t l=((uint32_t)seg<<4)+off; if(!a20) l&=0xfffff; return l; }
static uint32_t rd32(uint32_t l){ uint32_t v; memcpy(&v,&mem[l],4); return v; }
void mock_set_fs(u16 s){ fsr=s; ev(1,s,0); }
void mock_set_gs(u16 s){ gsr=s; ev(2,s,0); }
u32 mock_rdfs32(u32 a){ u32 v=rd32(lin(fsr,a)); ev(3,a,v); return v; }
void mock_wrfs32(u32 v,u32 a){ ev(4,a,v); memcpy(&mem[lin(fsr,a)],&v,4); }
u32 mock_rdgs32(u32 a){
	u32 v=rd32(lin(gsr,a)); ev(5,a,v);
	if(pending && --countdown<=0){ pending=0; a20=1; } /* delayed gate: opens after N gs reads */
	return v;
}
void initregs(struct biosregs *r){ memset(r,0,sizeof *r); r->eflags|=1; r->ds=r->es=0x1234; r->fs=fsr; r->gs=gsr; }
void intcall(u8 n,const struct biosregs *i,struct biosregs *o){
	ev(6,n,i->eax); ev(7,i->edi^i->esi^i->ebp, i->ebx^i->ecx^i->edx^i->eflags^((uint64_t)i->fs<<20)^((uint64_t)i->gs<<4)^i->ds^i->es);
	if(o) abort();
	if(n==0x15 && (i->eax&0xffff)==0x2401 && bios_works) arm(bios_delay);
}
static u8 f_inb(u16 port){
	u8 v=0;
	if(port==0x64){
		nst++;
		if(nst>st_settle && st_mode==3) v=0;
		else switch(st_mode){
			case 0: v=0; break; case 1: v=0xff; break; case 2: v=2; break; case 4: v=1; break;
			default: { int r=pick(100); if(r<st_pff) v=0xff; else { v=0; if(pick(100)<st_pobf) v|=1; if(pick(100)<st_pibf) v|=2; } }
		}
	} else if(port==0x60) v=(u8)rnd();
	else if(port==0x92) v=p92;
	ev(8,port,v); return v;
}
static void f_outb(u8 v,u16 port){
	ev(9,port,v);
	if(port==0x64){ kbc_cmd_d1 = (v==0xd1); }
	else if(port==0x60){ if(kbc_cmd_d1 && v==0xdf && kbc_works) arm(kbc_delay); kbc_cmd_d1=0; }
	else if(port==0x92){ p92=v; if((v&2) && fast_works) arm(fast_delay); }
}
static void setup(uint64_t seed, int kind){
	rs=seed*0x9e3779b97f4a7c15ULL+88172645463325252ULL; for(int i=0;i<8;i++) rnd();
	a20_init=(kind==1); bios_works=pick(3)==0; bios_delay=pick(2)?0:pick(200); kbc_works=pick(2); kbc_delay=pick(2)?0:pick(2000);
	fast_works=pick(2); fast_delay=pick(2)?0:pick(50000);
	st_mode=pick(6); if(st_mode==5) st_mode=3; st_settle=pick(4)?pick(300):pick(200000); st_pff=pick(3)?pick(5):50; st_pobf=pick(100); st_pibf=pick(100);
	if(kind==0||kind==3||kind==4){ int w=pick(3); if(w==0) bios_works=1; else if(w==1) kbc_works=1; else fast_works=1; }
	if(kind==4) { fast_works=1; fast_delay=pick(3)?0:pick(50000); }
	if(kind==2){ bios_works=kbc_works=fast_works=0; st_mode=pick(2)?0:1; }          /* never */
	if(kind==3){ st_mode=3; st_settle=pick(40); st_pff=0; }                         /* chatty then ready */
	if(kind==4){ st_mode=pick(2)?2:4; }                                             /* KBC stuck busy / stuck full */
	uint32_t ivt = pick(4)==0 ? 0xffffffffu : pick(8)==0 ? 0xfffffff0u+pick(16) : (uint32_t)rnd();
	ivt0=ivt; hi0=(uint32_t)rnd();
	memset(mem,0,sizeof mem); memcpy(&mem[0x200],&ivt0,4); memcpy(&mem[0x100210],&hi0,4);
	/* with A20 off, FFFF:0210 aliases 0x200+... = 0000:0200 (0xffff0+0x210 = 0x100200 -> 0x200) */
	a20=a20_init; pending=0; countdown=0; kbc_cmd_d1=0; nst=0; p92=(u8)rnd(); fsr=0x55; gsr=0x66; hash=0xcbf29ce484222325ULL; nev=0;
}
int main(int argc,char**argv){
	long N=argc>1?atol(argv[1]):2000; long nnever=argc>2?atol(argv[2]):2;
	rec=malloc(REC_MAX*sizeof *rec); pio_ops.f_inb=f_inb; pio_ops.f_outb=f_outb;
	long bad=0, ret0=0, retm1=0; uint64_t maxev=0; long cnt[5]={0};
	for(long it=0; it<N+nnever; it++){
		int kind = it>=N ? 2 : (it%5==1?1: it%5==3?3: it%5==4?4:0);
		uint64_t seed=it+1; if(kind==2 && it>=N) kind=2; else if(kind==2) kind=0;
		setup(seed,kind); replay=0; mism=0; int rc=c_enable_a20(); uint64_t hc=hash,nc=nev; int fs1=fsr,gs1=gsr,a1=a20;
		uint8_t m1[0x300]; memcpy(m1,mem,0x300); uint32_t hi1=rd32(0x100210);
		setup(seed,kind); replay=1; int rr=enable_a20(); uint64_t hr=hash,nr=nev;
		int same = rc==rr && hc==hr && nc==nr && !mism && fs1==fsr && gs1==gsr && a1==a20 && !memcmp(m1,mem,0x300) && hi1==rd32(0x100210);
		if(!same){ bad++; if(bad<10) printf("MISMATCH it=%ld kind=%d rc=%d/%d nev=%lu/%lu hash=%d firstbad=%lu\n",it,kind,rc,rr,nc,nr,hc==hr,first_bad); }
		if(rc==0) ret0++; else retm1++; if(nc>maxev) maxev=nc; cnt[kind]++;
		/* the C's contract: rc==0 iff A20 really on at exit; and the test word restored */
		if((rc==0) != (a20!=0)) { printf("MODEL: rc=%d a20=%d kind=%d it=%ld\n",rc,a20,kind,it); bad++; }
		uint32_t cur; memcpy(&cur,&mem[0x200],4); if(cur!=ivt0){ printf("test word not restored it=%ld\n",it); bad++; }
	}
	printf("a20 differential: %ld scenarios (kinds A20-off-random=%ld already-on=%ld never-enable=%ld kbc-chatty=%ld kbc-stuck=%ld), rc0=%ld rc-1=%ld, max events/run=%lu, mismatches=%ld\n",
		N+nnever,cnt[0],cnt[1],cnt[2],cnt[3],cnt[4],ret0,retm1,maxev,bad);
	return bad!=0;
}
