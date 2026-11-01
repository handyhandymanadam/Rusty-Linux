#include "shim.h"
#include GLUE_RSA
struct akcipher_alg *r_alg(void) { return &rsa; }
