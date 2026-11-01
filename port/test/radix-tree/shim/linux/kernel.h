/* the shared base without the xarray harness's small chunk: the real XA_CHUNK_SHIFT (6) is what the Rust is built for */
#include "../../../common/shim/linux/kernel.h"
#define CONFIG_XARRAY_MULTI 1
#define CONFIG_BASE_SMALL 0
