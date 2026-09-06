#pragma once
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int : (-!!(e)); }) * 0)
