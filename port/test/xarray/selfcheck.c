/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME
 * pristine C, so `run.sh --selfcheck` exercises every line of main.c
 * with an arm that cannot disagree. Proves the plumbing, not the port.
 */
#include <linux/xarray.h>

extern void *ref_xas_load(struct xa_state *);
void *rs_xas_load(struct xa_state *xas) { return ref_xas_load(xas); }
extern void ref_xas_destroy(struct xa_state *);
void rs_xas_destroy(struct xa_state *xas) { ref_xas_destroy(xas); }
extern bool ref_xas_nomem(struct xa_state *, gfp_t);
bool rs_xas_nomem(struct xa_state *xas, gfp_t gfp) { return ref_xas_nomem(xas, gfp); }
extern void *ref_xas_store(struct xa_state *, void *);
void *rs_xas_store(struct xa_state *xas, void *entry) { return ref_xas_store(xas, entry); }
extern bool ref_xas_get_mark(const struct xa_state *, xa_mark_t);
bool rs_xas_get_mark(const struct xa_state *xas, xa_mark_t m) { return ref_xas_get_mark(xas, m); }
extern void ref_xas_set_mark(const struct xa_state *, xa_mark_t);
void rs_xas_set_mark(const struct xa_state *xas, xa_mark_t m) { ref_xas_set_mark(xas, m); }
extern void ref_xas_clear_mark(const struct xa_state *, xa_mark_t);
void rs_xas_clear_mark(const struct xa_state *xas, xa_mark_t m) { ref_xas_clear_mark(xas, m); }
extern void ref_xas_init_marks(const struct xa_state *);
void rs_xas_init_marks(const struct xa_state *xas) { ref_xas_init_marks(xas); }
extern void ref_xas_split_alloc(struct xa_state *, void *, unsigned int, gfp_t);
void rs_xas_split_alloc(struct xa_state *xas, void *e, unsigned int o, gfp_t g) { ref_xas_split_alloc(xas, e, o, g); }
extern void ref_xas_split(struct xa_state *, void *, unsigned int);
void rs_xas_split(struct xa_state *xas, void *e, unsigned int o) { ref_xas_split(xas, e, o); }
extern unsigned int ref_xas_try_split_min_order(unsigned int);
unsigned int rs_xas_try_split_min_order(unsigned int o) { return ref_xas_try_split_min_order(o); }
extern void ref_xas_try_split(struct xa_state *, void *, unsigned int);
void rs_xas_try_split(struct xa_state *xas, void *e, unsigned int o) { ref_xas_try_split(xas, e, o); }
extern int ref_xas_get_order(struct xa_state *);
int rs_xas_get_order(struct xa_state *xas) { return ref_xas_get_order(xas); }
extern void *ref_xas_find(struct xa_state *, unsigned long);
void *rs_xas_find(struct xa_state *xas, unsigned long max) { return ref_xas_find(xas, max); }
extern void *ref_xas_find_marked(struct xa_state *, unsigned long, xa_mark_t);
void *rs_xas_find_marked(struct xa_state *xas, unsigned long max, xa_mark_t m) { return ref_xas_find_marked(xas, max, m); }
extern void *ref_xas_find_conflict(struct xa_state *);
void *rs_xas_find_conflict(struct xa_state *xas) { return ref_xas_find_conflict(xas); }
extern void *ref___xas_prev(struct xa_state *);
void *rs___xas_prev(struct xa_state *xas) { return ref___xas_prev(xas); }
extern void *ref___xas_next(struct xa_state *);
void *rs___xas_next(struct xa_state *xas) { return ref___xas_next(xas); }
extern void ref_xas_create_range(struct xa_state *);
void rs_xas_create_range(struct xa_state *xas) { ref_xas_create_range(xas); }
extern void ref_xas_pause(struct xa_state *);
void rs_xas_pause(struct xa_state *xas) { ref_xas_pause(xas); }

extern void *ref_xa_load(struct xarray *, unsigned long);
void *rs_xa_load(struct xarray *xa, unsigned long i) { return ref_xa_load(xa, i); }
extern void *ref___xa_erase(struct xarray *, unsigned long);
void *rs___xa_erase(struct xarray *xa, unsigned long i) { return ref___xa_erase(xa, i); }
extern void *ref_xa_erase(struct xarray *, unsigned long);
void *rs_xa_erase(struct xarray *xa, unsigned long i) { return ref_xa_erase(xa, i); }
extern void *ref___xa_store(struct xarray *, unsigned long, void *, gfp_t);
void *rs___xa_store(struct xarray *xa, unsigned long i, void *e, gfp_t g) { return ref___xa_store(xa, i, e, g); }
extern void *ref_xa_store(struct xarray *, unsigned long, void *, gfp_t);
void *rs_xa_store(struct xarray *xa, unsigned long i, void *e, gfp_t g) { return ref_xa_store(xa, i, e, g); }
extern void *ref___xa_cmpxchg(struct xarray *, unsigned long, void *, void *, gfp_t);
void *rs___xa_cmpxchg(struct xarray *xa, unsigned long i, void *o, void *e, gfp_t g) { return ref___xa_cmpxchg(xa, i, o, e, g); }
extern int ref___xa_insert(struct xarray *, unsigned long, void *, gfp_t);
int rs___xa_insert(struct xarray *xa, unsigned long i, void *e, gfp_t g) { return ref___xa_insert(xa, i, e, g); }
extern void *ref_xa_store_range(struct xarray *, unsigned long, unsigned long, void *, gfp_t);
void *rs_xa_store_range(struct xarray *xa, unsigned long f, unsigned long l, void *e, gfp_t g) { return ref_xa_store_range(xa, f, l, e, g); }
extern int ref_xa_get_order(struct xarray *, unsigned long);
int rs_xa_get_order(struct xarray *xa, unsigned long i) { return ref_xa_get_order(xa, i); }
extern void ref___xa_set_mark(struct xarray *, unsigned long, xa_mark_t);
void rs___xa_set_mark(struct xarray *xa, unsigned long i, xa_mark_t m) { ref___xa_set_mark(xa, i, m); }
extern void ref___xa_clear_mark(struct xarray *, unsigned long, xa_mark_t);
void rs___xa_clear_mark(struct xarray *xa, unsigned long i, xa_mark_t m) { ref___xa_clear_mark(xa, i, m); }
extern bool ref_xa_get_mark(struct xarray *, unsigned long, xa_mark_t);
bool rs_xa_get_mark(struct xarray *xa, unsigned long i, xa_mark_t m) { return ref_xa_get_mark(xa, i, m); }
extern void ref_xa_set_mark(struct xarray *, unsigned long, xa_mark_t);
void rs_xa_set_mark(struct xarray *xa, unsigned long i, xa_mark_t m) { ref_xa_set_mark(xa, i, m); }
extern void ref_xa_clear_mark(struct xarray *, unsigned long, xa_mark_t);
void rs_xa_clear_mark(struct xarray *xa, unsigned long i, xa_mark_t m) { ref_xa_clear_mark(xa, i, m); }
extern void *ref_xa_find(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
void *rs_xa_find(struct xarray *xa, unsigned long *ip, unsigned long max, xa_mark_t f) { return ref_xa_find(xa, ip, max, f); }
extern void *ref_xa_find_after(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
void *rs_xa_find_after(struct xarray *xa, unsigned long *ip, unsigned long max, xa_mark_t f) { return ref_xa_find_after(xa, ip, max, f); }
extern unsigned int ref_xa_extract(struct xarray *, void **, unsigned long, unsigned long, unsigned int, xa_mark_t);
unsigned int rs_xa_extract(struct xarray *xa, void **d, unsigned long s, unsigned long m, unsigned int n, xa_mark_t f) { return ref_xa_extract(xa, d, s, m, n, f); }
extern void ref_xa_destroy(struct xarray *);
void rs_xa_destroy(struct xarray *xa) { ref_xa_destroy(xa); }
extern void ref_xa_delete_node(struct xa_node *, xa_update_node_t);
void rs_xa_delete_node(struct xa_node *n, xa_update_node_t u) { ref_xa_delete_node(n, u); }
extern int ref___xa_alloc(struct xarray *, u32 *, void *, struct xa_limit, gfp_t);
int rs___xa_alloc(struct xarray *xa, u32 *id, void *e, struct xa_limit l, gfp_t g) { return ref___xa_alloc(xa, id, e, l, g); }
extern int ref___xa_alloc_cyclic(struct xarray *, u32 *, void *, struct xa_limit, u32 *, gfp_t);
int rs___xa_alloc_cyclic(struct xarray *xa, u32 *id, void *e, struct xa_limit l, u32 *n, gfp_t g) { return ref___xa_alloc_cyclic(xa, id, e, l, n, g); }
