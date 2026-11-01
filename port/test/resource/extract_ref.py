#!/usr/bin/env python3
"""extract_ref.py PRISTINE resource.c OUT.c -- the tree algorithms of the PRISTINE kernel/resource.c as a standalone reference (locks are no-ops in the shim)."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
i = s.index("#define for_each_resource"); j = s.index("\n\n", i)
parts = [fn("static struct resource *next_resource("), s[i:j] + "\n",
         fn("static bool is_type_match("), fn("static struct resource * __request_resource("), fn("static int __release_resource("),
         fn("static void __release_child_resources("), fn("static int find_next_iomem_res("), fn("static int __region_intersects("),
         fn("static void resource_clip("), fn("static int __find_resource_space("), fn("static int reallocate_resource("),
         fn("static struct resource * __insert_resource("), fn("static int __adjust_resource("), fn("resource_size_t resource_alignment(")]
tail = '''
struct resource *ref_request(struct resource *r, struct resource *n) { return __request_resource(r, n); }
int ref_release(struct resource *o, bool c) { return __release_resource(o, c); }
void ref_release_children(struct resource *r) { __release_child_resources(r); }
int ref_find_next(struct resource *io, resource_size_t s, resource_size_t e, unsigned long f, unsigned long d, struct resource *r) { iomem_resource = *io; return find_next_iomem_res(s, e, f, d, r); }
int ref_region(struct resource *p, resource_size_t s, size_t z, unsigned long f, unsigned long d) { return __region_intersects(p, s, z, f, d); }
int ref_find_space(struct resource *r, struct resource *o, struct resource *n, resource_size_t z, struct resource_constraint *c) { return __find_resource_space(r, o, n, z, c); }
int ref_reallocate(struct resource *r, struct resource *o, resource_size_t z, struct resource_constraint *c) { return reallocate_resource(r, o, z, c); }
struct resource *ref_insert(struct resource *p, struct resource *n) { return __insert_resource(p, n); }
int ref_adjust(struct resource *r, resource_size_t s, resource_size_t z) { return __adjust_resource(r, s, z); }
resource_size_t ref_alignment(struct resource *r) { return resource_alignment(r); }
'''
open(sys.argv[2], "w").write('#include "refshim.h"\n' + "\n".join(parts) + tail)
