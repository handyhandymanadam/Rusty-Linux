// One real, shared ktime_get() -- see shim/linux/dim.h's comment. Linked
// once into the differential binary; both the pristine C's rdma_dim/dim
// and the Rust probe call this exact symbol, driven by g_fake_time.
#include "shim/linux/dim.h"

ktime_t g_fake_time;

ktime_t ktime_get(void)
{
	return g_fake_time;
}
