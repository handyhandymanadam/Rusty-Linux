#include <string.h>
#define get_unaligned(ptr) ({ __typeof__(*(ptr)) __v; memcpy(&__v, (ptr), sizeof __v); __v; })
