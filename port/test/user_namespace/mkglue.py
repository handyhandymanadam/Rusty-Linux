#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- user_namespace_glue.c = upstream minus the moved id-map machinery (see user_namespace_rs.rs)."""
import sys
L = open(sys.argv[1]).read().split("\n")
def find(s, start=0):
    for i in range(start, len(L)):
        if L[i].startswith(s): return i
    raise SystemExit("marker not found: " + s)
# 1. idmap_key .. map_id_up
a = find("/*", find("EXPORT_SYMBOL(__put_user_ns)") + 1)
assert "struct idmap_key - holds" in L[a + 1], L[a + 1]
b = find("u32 map_id_up(struct uid_gid_map *map, u32 id)")
while L[b] != "}": b += 1
thunks = '''u32 rust_map_id_down(struct uid_gid_map *map, u32 id);
u32 rust_map_id_range_up(struct uid_gid_map *map, u32 id, u32 count);
u32 rust_map_id_up(struct uid_gid_map *map, u32 id);

u32 map_id_down(struct uid_gid_map *map, u32 id)
{
	return rust_map_id_down(map, id);
}

u32 map_id_range_up(struct uid_gid_map *map, u32 id, u32 count)
{
	return rust_map_id_range_up(map, id, count);
}

u32 map_id_up(struct uid_gid_map *map, u32 id)
{
	return rust_map_id_up(map, id);
}'''.split("\n")
# 2. mappings_overlap .. sort_idmaps
c = find("static bool mappings_overlap(")
d = find("static int sort_idmaps(")
while L[d] != "}": d += 1
wrappers = '''/* Wrappers for what the Rust cannot name: configuration-dependent allocator / lib calls and the kernel's _ctype table. */
void *rust_un_bsearch(const void *key, const void *base, size_t num,
		      int (*cmp)(const void *, const void *));
struct uid_gid_extent *rust_un_alloc_extents(size_t n);
struct uid_gid_extent *rust_un_dup_extents(const struct uid_gid_extent *src, size_t n);
bool rust_un_isspace(char c);

void *rust_un_bsearch(const void *key, const void *base, size_t num,
		      int (*cmp)(const void *, const void *))
{
	return bsearch(key, base, num, sizeof(struct uid_gid_extent), cmp);
}

struct uid_gid_extent *rust_un_alloc_extents(size_t n)
{
	return kmalloc_array(n, sizeof(struct uid_gid_extent), GFP_KERNEL);
}

struct uid_gid_extent *rust_un_dup_extents(const struct uid_gid_extent *src, size_t n)
{
	return kmemdup_array(src, n, sizeof(struct uid_gid_extent), GFP_KERNEL);
}

bool rust_un_isspace(char c)
{
	return isspace(c);
}

int rust_userns_parse(char *kbuf, struct uid_gid_map *new_map);
int rust_userns_remap(struct uid_gid_map *new_map, struct uid_gid_map *parent_map);
int rust_userns_sort(struct uid_gid_map *map);'''.split("\n")
out = L[:a] + thunks + L[b + 1:c] + wrappers + L[d + 1:]
s = "\n".join(out)
# 3. map_write: the parse loop, the remap loop, sort_idmaps call
p0 = s.index("\t/* Parse the user data */\n")
p1 = s.index("\t/* Be very certain the new map actually exists */\n")
p2 = s.index("\tret = -EPERM;\n\t/* Validate the user is allowed")
s = s[:p0] + "\t/* Parse the user data */\n\tret = rust_userns_parse(kbuf, &new_map);\n\tif (ret < 0)\n\t\tgoto out;\n\n" + s[p2:]
q0 = s.index("\tret = -EPERM;\n\t/* Map the lower ids from the parent")
q1 = s.index("\t/*\n\t * If we want to use binary search for lookup")
s = s[:q0] + "\t/* Map the lower ids from the parent user namespace to the\n\t * kernel global id space.\n\t */\n\tret = rust_userns_remap(&new_map, parent_map);\n\tif (ret < 0)\n\t\tgoto out;\n\n" + s[q1:]
s = s.replace("ret = sort_idmaps(&new_map);", "ret = rust_userns_sort(&new_map);")
loc = "\tstruct uid_gid_map new_map;\n\tunsigned idx;\n\tstruct uid_gid_extent extent;\n\tchar *kbuf, *pos, *next_line;\n"
assert loc in s
s = s.replace(loc, "\tstruct uid_gid_map new_map;\n\tchar *kbuf;\n")
hdr = '''// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (kernel/user_namespace.c, 6.18.49): the id-map lookups (map_id_down/up, map_id_range_up and their bsearch / scan helpers), mappings_overlap(), insert_extent(),
 * sort_idmaps() and the parsing, translating and sorting phases of map_write() are in user_namespace_rs.rs. This file keeps the rest as upstream has it (capabilities,
 * credentials, files, seq_file, work queues, ucounts, the make_k*id() / from_k*id() family), the three lookup functions as thunks, and wrappers for configuration-
 * dependent calls. Upstream's whole file is installed as user_namespace_norust.c for CONFIG_RUST=n.
 */
'''
assert s.startswith("// SPDX-License-Identifier: GPL-2.0-only\n")
open(sys.argv[2], "w").write(hdr + s[len("// SPDX-License-Identifier: GPL-2.0-only\n"):])
