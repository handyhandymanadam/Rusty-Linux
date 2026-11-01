#ifndef SHIM_SERVICES_H
#define SHIM_SERVICES_H
#include "security.h"
struct avtab_node;
void services_compute_xperms_drivers(struct extended_perms *xperms, struct avtab_node *node);
void services_compute_xperms_decision(struct extended_perms_decision *xpermd, struct avtab_node *node);
#endif
