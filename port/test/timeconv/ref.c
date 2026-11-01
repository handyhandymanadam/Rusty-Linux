/* the pristine file, unmodified, with the kernel headers replaced by shim/kshim.h */
#define _LINUX_TIME_H
#include "kshim.h"
#define __KSHIM_SKIP(x)
#include TIMECONV_C
