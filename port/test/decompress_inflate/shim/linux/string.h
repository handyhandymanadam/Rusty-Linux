/* Userspace shim: the differential harness compiles the PRISTINE
 * lib/zlib_inflate C files, which want kernel headers. Only what they use.
 */
#ifndef _SHIM_LINUX_STRING_H
#define _SHIM_LINUX_STRING_H
#include <string.h>
#endif
