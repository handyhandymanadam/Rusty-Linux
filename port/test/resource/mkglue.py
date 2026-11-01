#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- resource_glue.c = upstream with the tree algorithms replaced by calls into resource_rs.rs (see kernel/resource_rs.rs)."""
import sys, re
s = open(sys.argv[1]).read()

def span(sig):
    i = s.index(sig)
    # include a directly preceding comment block (/** ... */ or /* ... */) that ends right before the signature
    j = s.index("\n}\n", i) + 3
    return i, j

def replace(sig, new):
    global s
    i, j = span(sig)
    s = s[:i] + new + s[j:]

def remove(sig):
    replace(sig, "")

remove("static bool is_type_match(")
remove("static void resource_clip(")
replace("static struct resource * __request_resource(", '''static struct resource * __request_resource(struct resource *root, struct resource *new)
{
	return rust_res_request(root, new);
}
''')
replace("static int __release_resource(", '''static int __release_resource(struct resource *old, bool release_child)
{
	return rust_res_release(old, release_child);
}
''')
replace("static void __release_child_resources(", '''static void __release_child_resources(struct resource *r)
{
	rust_res_release_children(r);
}
''')
replace("static int find_next_iomem_res(", '''static int find_next_iomem_res(resource_size_t start, resource_size_t end,
			       unsigned long flags, unsigned long desc,
			       struct resource *res)
{
	int ret;

	read_lock(&resource_lock);
	ret = rust_res_find_next(&iomem_resource, start, end, flags, desc, res);
	read_unlock(&resource_lock);
	return ret;
}
''')
replace("static int __region_intersects(", '''static int __region_intersects(struct resource *parent, resource_size_t start,
			       size_t size, unsigned long flags,
			       unsigned long desc)
{
	return rust_res_region_intersects(parent, start, size, flags, desc);
}
''')
replace("static int __find_resource_space(", '''static int __find_resource_space(struct resource *root, struct resource *old,
				 struct resource *new, resource_size_t size,
				 struct resource_constraint *constraint)
{
	return rust_res_find_space(root, old, new, size, constraint);
}
''')
replace("static int reallocate_resource(", '''static int reallocate_resource(struct resource *root, struct resource *old,
			       resource_size_t newsize,
			       struct resource_constraint *constraint)
{
	int err;

	write_lock(&resource_lock);
	err = rust_res_reallocate(root, old, newsize, constraint);
	write_unlock(&resource_lock);
	return err;
}
''')
replace("static struct resource * __insert_resource(", '''static struct resource * __insert_resource(struct resource *parent, struct resource *new)
{
	return rust_res_insert(parent, new);
}
''')
replace("static int __adjust_resource(", '''static int __adjust_resource(struct resource *res, resource_size_t start,
				resource_size_t size)
{
	return rust_res_adjust(res, start, size);
}
''')
replace("resource_size_t resource_alignment(", '''resource_size_t resource_alignment(struct resource *res)
{
	return rust_res_alignment(res);
}
''')

protos = '''
/* The tree algorithms are in resource_rs.rs. */
struct resource *rust_res_request(struct resource *root, struct resource *new);
int rust_res_release(struct resource *old, bool release_child);
void rust_res_release_children(struct resource *r);
int rust_res_find_next(struct resource *iomem, resource_size_t start, resource_size_t end, unsigned long flags, unsigned long desc, struct resource *res);
int rust_res_region_intersects(struct resource *parent, resource_size_t start, size_t size, unsigned long flags, unsigned long desc);
int rust_res_find_space(struct resource *root, struct resource *old, struct resource *new, resource_size_t size, struct resource_constraint *constraint);
int rust_res_reallocate(struct resource *root, struct resource *old, resource_size_t newsize, struct resource_constraint *constraint);
struct resource *rust_res_insert(struct resource *parent, struct resource *new);
int rust_res_adjust(struct resource *res, resource_size_t start, resource_size_t size);
resource_size_t rust_res_alignment(struct resource *res);
void rust_res_warn_dup(void);
void rust_res_bug(void);
void rust_res_dbg_release(struct resource *r);
resource_size_t rust_res_alignf(resource_alignf alignf, void *data, const struct resource *avail, resource_size_t size, resource_size_t align);
void rust_res_arch_remove_reservations(struct resource *r);

void rust_res_warn_dup(void) { WARN_ON(1); }
void rust_res_bug(void) { BUG(); }
void rust_res_dbg_release(struct resource *r) { printk(KERN_DEBUG "release child resource %pR\\n", r); }
resource_size_t rust_res_alignf(resource_alignf alignf, void *data, const struct resource *avail, resource_size_t size, resource_size_t align)
{
	return alignf(data, avail, size, align);
}
void __weak arch_remove_reservations(struct resource *avail);
void rust_res_arch_remove_reservations(struct resource *r) { arch_remove_reservations(r); }
'''
m = "static DEFINE_RWLOCK(resource_lock);\n"
s = s.replace(m, m + protos, 1)
hdr = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (kernel/resource.c, 6.18.49): the lock-free tree algorithms (request, release, insert, adjust, search, region_intersects, free-space search, reallocate) are in\n * resource_rs.rs. This file keeps everything else as upstream has it (rwlock, allocation, /proc/iomem, devres, request_region, hot-remove, exports) and calls the Rust\n * from the same places. Upstream's whole file is installed as resource_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", hdr, 1)
open(sys.argv[2], "w").write(s)
