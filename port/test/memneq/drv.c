#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned long c_memneq(const void *a, const void *b, size_t size);
unsigned long __crypto_memneq(const void *a, const void *b, size_t size);

static unsigned long rs(const void*a,const void*b,size_t n){return __crypto_memneq(a,b,n);}

/* buffer whose END is flush against a PROT_NONE guard page */
static unsigned char *guarded(size_t cap, unsigned char **base_out)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t pages = (cap + ps - 1) / ps;
    unsigned char *m = mmap(NULL, (pages+1)*ps, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(2); }
    if (mprotect(m + pages*ps, ps, PROT_NONE)) { perror("mprotect"); exit(2); }
    *base_out = m;
    return m + pages*ps;   /* one past the last readable byte */
}

static uint64_t s = 0x123456789abcdefULL;
static uint64_t rnd(void){ s^=s<<13; s^=s>>7; s^=s<<17; return s; }

int main(void)
{
    unsigned long mism = 0, cases = 0;
    unsigned char A[512], B[512];

    /* 1. exhaustive-ish random corpus, sizes 0..300, all 8 alignments */
    for (int rep = 0; rep < 400; rep++) {
        for (size_t i = 0; i < sizeof A; i++) { A[i] = rnd(); B[i] = A[i]; }
        for (size_t n = 0; n <= 300; n++) {
            for (int oa = 0; oa < 8; oa++) for (int ob = 0; ob < 8; ob++) {
                const void *pa = A+oa, *pb = B+ob;
                unsigned long c = c_memneq(pa,pb,n), r = rs(pa,pb,n);
                cases++;
                if (c != r) { if (mism<10) printf("MISMATCH equal n=%zu oa=%d ob=%d c=%#lx r=%#lx\n",n,oa,ob,c,r); mism++; }
            }
            /* now perturb: flip one random bit inside the window */
            if (n) {
                size_t bit = rnd() % (n*8);
                B[bit/8] ^= 1u << (bit%8);
                for (int oa = 0; oa < 8; oa++) for (int ob = 0; ob < 8; ob++) {
                    const void *pa = A+oa, *pb = B+ob;
                    unsigned long c = c_memneq(pa,pb,n), r = rs(pa,pb,n);
                    cases++;
                    if (c != r) { if (mism<10) printf("MISMATCH diff n=%zu oa=%d ob=%d c=%#lx r=%#lx\n",n,oa,ob,c,r); mism++; }
                }
                B[bit/8] ^= 1u << (bit%8);
            }
        }
    }

    /* 2. every single-bit difference, size 16, both alignments swept */
    for (size_t i = 0; i < 16; i++) B[i] = A[i] = rnd();
    for (int bit = 0; bit < 128; bit++) {
        B[bit/8] ^= 1u << (bit%8);
        unsigned long c = c_memneq(A,B,16), r = rs(A,B,16);
        cases++;
        if (c != r) { printf("MISMATCH 16 bit=%d c=%#lx r=%#lx\n",bit,c,r); mism++; }
        if (c == 0) { printf("BUG: 16-byte single-bit diff reported equal, bit=%d\n", bit); mism++; }
        B[bit/8] ^= 1u << (bit%8);
    }

    /* 3. NULL, size 0 */
    { unsigned long c = c_memneq(NULL,NULL,0), r = rs(NULL,NULL,0);
      printf("NULL/0: c=%#lx r=%#lx\n", c, r); if (c!=r) mism++; }

    /* 4. overlapping buffers */
    for (size_t n = 0; n <= 64; n++)
        for (int d = 0; d <= 8; d++) {
            unsigned long c = c_memneq(A, A+d, n), r = rs(A, A+d, n);
            cases++; if (c!=r) { printf("MISMATCH overlap n=%zu d=%d\n",n,d); mism++; }
        }

    /* 5. guard-page over-read check: buffer ends exactly at a PROT_NONE page */
    {
        unsigned char *ba, *bb, *ea, *eb;
        ea = guarded(4096, &ba); eb = guarded(4096, &bb);
        for (size_t n = 0; n <= 300; n++) {
            unsigned char *pa = ea - n, *pb = eb - n;
            memcpy(pa, "\x5a", n?1:0);
            unsigned long c = c_memneq(pa,pb,n), r = rs(pa,pb,n);
            cases++; if (c!=r) { printf("MISMATCH guard n=%zu c=%#lx r=%#lx\n",n,c,r); mism++; }
        }
        printf("guard-page pass: no fault, sizes 0..300 flush to PROT_NONE\n");
    }

    printf("cases=%lu mismatches=%lu\n", cases, mism);
    return mism != 0;
}
