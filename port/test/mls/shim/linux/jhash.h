#include <stdint.h>
static inline uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t c) { return (a * 31 + b) * 31 + c; }
