/* Just enough for fs/fs_types.c: the REAL include/linux/fs_types.h supplies FT_*, DT_*, S_DT; only types/export are stubbed */
#include <stdint.h>
typedef unsigned short umode_t;
#define S_IFMT  00170000
#include "../../../../../src/linux/include/linux/fs_types.h"
