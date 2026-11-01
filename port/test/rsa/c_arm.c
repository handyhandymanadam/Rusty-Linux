#include "shim.h"
#include PRISTINE_RSA
struct akcipher_alg *c_alg(void) { return &rsa; }
