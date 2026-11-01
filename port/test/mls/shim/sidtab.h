#ifndef SHIM_SIDTAB_H
#define SHIM_SIDTAB_H
struct sidtab { int dummy; };
struct context;
struct context *sidtab_search(struct sidtab *s, u32 sid);
#endif
