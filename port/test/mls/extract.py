#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the functions of the PRISTINE mls.c (C side), or the same names as the glue's wrappers plus the Rust externs (Rust side: nothing but the sidtab wrapper), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
    protos = "".join(l + "\n" for l in """int mls_compute_context_len(struct policydb *p, struct context *context);
void mls_sid_to_context(struct policydb *p, struct context *context, char **scontext);
int mls_range_set(struct context *context, struct mls_range *range);
int mls_setup_user_range(struct policydb *p, struct context *fromcon, struct user_datum *user, struct context *usercon);
int mls_convert_context(struct policydb *oldp, struct policydb *newp, struct context *oldc, struct context *newc);
int mls_compute_sid(struct policydb *p, struct context *scontext, struct context *tcontext, u16 tclass, u32 specified, struct context *newcontext, bool sock);""".split("\n"))
    body += "\n" + protos
else:
    a = s.index("int mls_compute_context_len("); b = s.index("#ifdef CONFIG_NETLABEL")
    body = s[a:b]
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "sidtab.h"\n#include "mls.h"\n#include "policydb.h"\n#include "context.h"\n' + body)
