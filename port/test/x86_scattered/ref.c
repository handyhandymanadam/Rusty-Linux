/* the pristine scattered.c with the kernel's header world replaced by shim/ */
#include "kshim.h"
#define cpuid_eax kshim_cpuid_eax
#include SCATTERED_C
