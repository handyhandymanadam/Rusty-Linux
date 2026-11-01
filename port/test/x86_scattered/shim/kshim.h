#ifndef KSHIM_H
#define KSHIM_H
#include <stdint.h>
#include <string.h>
typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#include "x86features.h"
struct cpuinfo_x86 { unsigned char hdr[48]; uint32_t x86_capability[26]; };
enum cpuid_regs_idx { CPUID_EAX = 0, CPUID_EBX, CPUID_ECX, CPUID_EDX };
void test_cpuid(uint32_t op, uint32_t count, uint32_t *o);
static inline uint32_t kshim_cpuid_eax(uint32_t op) { uint32_t o[4]; test_cpuid(op, 0, o); return o[0]; }
static inline void cpuid_count(uint32_t op, uint32_t count, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) { uint32_t o[4]; test_cpuid(op, count, o); *a = o[0]; *b = o[1]; *c = o[2]; *d = o[3]; }
static inline void set_cpu_cap(struct cpuinfo_x86 *c, unsigned bit) { __atomic_fetch_or((uint64_t *)((char *)c + 48) + bit / 64, 1ULL << (bit % 64), __ATOMIC_SEQ_CST); }
#endif
