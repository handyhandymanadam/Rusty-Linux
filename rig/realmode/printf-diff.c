#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef int (*fn_t)(char *, const char *, ...);
int c_sprintf(char *, const char *, ...);
int rs_dummy;
extern int sprintf_rs(char*, const char*, ...) __asm__("sprintf");
static uint64_t rs=88172645463325252ULL;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs;}
static int pick(int n){return (int)(rnd()%n);}
static const char *strs[]={"","a","hello","video mode","0123456789abcdefghij","%d","  sp  ","VESA","x\ty"};
static const int ivals[]={0,1,-1,7,8,9,10,15,16,255,256,-255,12345,-12345,65535,65536,32767,32768,-32768,2147483647,(int)0x80000000,100000,-100000,0x7fff,0xffff,(int)0xdeadbeef,42,-42};
#define NI (sizeof(ivals)/sizeof(ivals[0]))
int main(int argc,char**argv){
  long N=argc>1?atol(argv[1]):100000; long bad=0, withnum=0;
  static char bc[8192], br[8192];
  for(long it=0;it<N;it++){
    char fmt[128]; int fl=0; uint64_t slotsC[6]={0},slotsR[6]={0}; int ns=0; int nconv=1+pick(3);
    int nC=0,nR=0; int nused=0; int ok=1;
    for(int c=0;c<nconv && ok;c++){
      if(pick(3)==0){ const char *lit[]={"x","ab "," [","] ",": "}; fl+=snprintf(fmt+fl,40,"%s",lit[pick(5)]); } // libc sprintf: harness only
      fmt[fl++]='%';
      const char *fch="-+ #0"; int nf=pick(3); for(int i=0;i<nf;i++) fmt[fl++]=fch[pick(5)];
      int wstar=0,pstar=0; int wv=0,pv=0;
      int r=pick(4);
      if(r==0){ fl+=snprintf(fmt+fl,40,"%d",pick(30)); }
      else if(r==1){ fmt[fl++]='*'; wstar=1; }
      r=pick(4);
      if(r==0){ fl+=snprintf(fmt+fl,40,".%d",pick(30)); }
      else if(r==1){ fmt[fl++]='.'; fmt[fl++]='*'; pstar=1; }
      else if(r==2){ fmt[fl++]='.'; }
      char q=0; r=pick(5); if(r==0)q='h'; else if(r==1)q='l'; else if(r==2&&0)q='L';
      if(q) fmt[fl++]=q;
      const char *convs="cspnxXdiuo%dxsu?"; char cv=convs[pick(16)];
      if(cv=='p'&&!(q==0)) q=0, fl--; // drop qualifier for p
      fmt[fl++]=cv;
      if(wstar){ if(ns>=6){ok=0;break;} int v=pick(60)-15; slotsC[ns]=slotsR[ns]=(uint64_t)(uint32_t)v; ns++; }
      if(pstar){ if(ns>=6){ok=0;break;} int v=pick(50)-8; slotsC[ns]=slotsR[ns]=(uint64_t)(uint32_t)v; ns++; }
      if(cv=='%'||cv=='?'){ continue; }
      if(ns>=6){ok=0;break;}
      if(cv=='s'){ const char*s=strs[pick(9)]; slotsC[ns]=slotsR[ns]=(uint64_t)(uintptr_t)s; }
      else if(cv=='n'){ if(q=='l'){ok=0;break;} slotsC[ns]=(uint64_t)(uintptr_t)&nC; slotsR[ns]=(uint64_t)(uintptr_t)&nR; }
      else if(cv=='p'){ /* needs explicit width to avoid host 16-digit default: force width by post-check */
        uint32_t v=(uint32_t)rnd(); slotsC[ns]=slotsR[ns]=v; }
      else if(cv=='c'){ int v=ivals[pick(NI)]; slotsC[ns]=slotsR[ns]=(uint64_t)(uint32_t)v; }
      else { int v=ivals[pick(NI)];
        int isl=(q=='l'); int sgn=(cv=='d'||cv=='i');
        uint64_t sv;
        if(isl&&sgn) sv=(uint64_t)(int64_t)v;      /* sign-extended int32 */
        else if(isl)  sv=(uint64_t)(uint32_t)v;    /* zero-extended */
        else sv=(uint64_t)(uint32_t)v;
        slotsC[ns]=slotsR[ns]=sv; }
      ns++;
    }
    if(!ok) continue;
    fmt[fl]=0;
    /* skip %p without explicit width: host sizeof(void*)=8 vs target 4 (documented difference) */
    if(strchr(fmt,'p')){ int skip=0; for(char*p=fmt;*p;p++) if(*p=='%'){ char*t=p+1; while(*t&&strchr("-+ #0",*t))t++; if(*t=='p'||(*t=='.'&&0)) skip=1; if(*t=='p'&&0) skip=0;} if(skip) continue; }
    memset(bc,0x5a,sizeof bc); memset(br,0x5a,sizeof br); nC=nR=-77;
    int rc=((fn_t)c_sprintf)(bc,fmt,slotsC[0],slotsC[1],slotsC[2],slotsC[3],slotsC[4],slotsC[5]);
    int rr=((fn_t)sprintf_rs)(br,fmt,slotsR[0],slotsR[1],slotsR[2],slotsR[3],slotsR[4],slotsR[5]);
    withnum++;
    if(rc!=rr||memcmp(bc,br,sizeof bc)||nC!=nR){ if(bad<10){ fprintf(stderr,"MISMATCH fmt=[%s] rc=%d rr=%d C=[%s] R=[%s] n=%d/%d\n",fmt,rc,rr,bc,br,nC,nR);} bad++; }
  }
  fprintf(stderr,"cases=%ld mismatches=%ld\n",withnum,bad); return bad!=0;
}
