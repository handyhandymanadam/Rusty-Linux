#!/usr/bin/env python3
"""extract_ref.py PRISTINE user_namespace.c OUT.c -- slice the id-map machinery and the parse / remap phases of map_write() out of the PRISTINE file into a standalone reference."""
import sys
s = open(sys.argv[1]).read()
def cut(a, b, incl_end=False):
    i = s.index(a); j = s.index(b, i)
    return s[i:j]
# idmap_key .. map_id_up (functions, static)
lookup = cut("struct idmap_key {", "/**\n *\tmake_kuid - Map")
# mappings_overlap .. sort_idmaps
build = cut("static bool mappings_overlap(", "/**\n * verify_root_map()")
parse = cut("\t/* Parse the user data */\n", "\tret = -EPERM;\n\t/* Validate the user is allowed")
remap = cut("\t/* Map the lower ids from the parent user namespace", "\t/*\n\t * If we want to use binary search for lookup")
pre = open(sys.argv[2] + ".pre").read() if False else ""
out = '''#include "refshim.h"
''' + lookup + "\n" + build + '''
int ref_parse(char *kbuf, struct uid_gid_map *np)
{
#define new_map (*np)
	int ret = -EINVAL;
	char *pos, *next_line;
	struct uid_gid_extent extent;
''' + parse.replace("\t/* Parse the user data */\n", "") + '''	return 0;
out:
	return ret;
#undef new_map
}

int ref_remap(struct uid_gid_map *np, struct uid_gid_map *parent_map)
{
#define new_map (*np)
	unsigned idx;
	int ret = -EPERM;
''' + remap.replace("goto out;", "return -EPERM;") + '''	return 0;
#undef new_map
	(void)ret;
}
int ref_sort(struct uid_gid_map *m) { return sort_idmaps(m); }
u32 ref_down(struct uid_gid_map *m, u32 id) { return map_id_down(m, id); }
u32 ref_up(struct uid_gid_map *m, u32 id) { return map_id_up(m, id); }
'''
open(sys.argv[2], "w").write(out)
