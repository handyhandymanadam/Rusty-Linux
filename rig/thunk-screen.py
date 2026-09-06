#!/usr/bin/env python3
"""thunk-screen.py <port-tree> -- see rig/thunk-screen.sh."""
import os, re, sys
port = sys.argv[1]
GUARD=re.compile(r'WARN|BUG_ON|BUG\(|panic|static_branch|static_key|unlikely|likely'
                 r'|spin_lock|preempt_|local_irq|rcu_|might_sleep|kmalloc|kfree|vmalloc'
                 r'|^\s*#\s*(if|ifdef|ifndef|else|elif)|memset|memcpy|sizeof|\bNULL\b')
def strip(src):
    out=[];i=0;n=len(src)
    while i<n:
        if src.startswith("/*",i):
            j=src.find("*/",i+2); i=n if j<0 else j+2; out.append("\n"*src.count("\n",i-1,i))
        elif src.startswith("//",i):
            j=src.find("\n",i); i=n if j<0 else j
        else:
            out.append(src[i]); i+=1
    return "".join(out)
rows=[]
for base,_d,files in os.walk(port):
    for f in sorted(files):
        if not f.endswith(".c"): continue
        p=os.path.join(base,f); rel=os.path.relpath(p,port)
        src=open(p,errors="replace").read()
        if "rust_" not in src: continue
        code=strip(src)
        lines=code.split("\n")
        # brace-match each top-level function definition
        i=0
        while i<len(lines):
            m=re.match(r'^[A-Za-z_][A-Za-z0-9_ \*]*\b([a-zA-Z_][A-Za-z0-9_]*)\s*\(', lines[i])
            if m and not lines[i].rstrip().endswith(";"):
                depth=0; started=False; body=[]; j=i
                while j<len(lines):
                    body.append(lines[j])
                    depth+=lines[j].count("{")-lines[j].count("}")
                    if "{" in lines[j]: started=True
                    if started and depth<=0: break
                    j+=1
                text="\n".join(body)
                if "rust_" in text:
                    inner="\n".join(body[1:-1]) if len(body)>2 else ""
                    stmts=[l.strip() for l in inner.split("\n") if l.strip() and l.strip() not in "{}"]
                    hits=[s for s in stmts if GUARD.search(s)]
                    rows.append((rel,m.group(1),len(stmts),hits))
                i=j
            i+=1
counts={}
print("%-42s %-32s %-16s %s" % ("FILE","C ENTRY","VERDICT","WHY"))
for rel,fn,n,hits in sorted(rows):
    verdict = "PASS-THROUGH" if n<=1 and not hits else ("REVIEW (%d stmt)"%n if not hits else "DO NOT CLOSE")
    print("%-42s %-32s %-16s %s" % (rel,fn,verdict, "; ".join(hits[:2])[:70]))
    counts[verdict.split()[0]] = counts.get(verdict.split()[0],0)+1


print()
print("%d C entries call into Rust: %d PASS-THROUGH, %d REVIEW, %d DO NOT CLOSE"
      % (len(rows), counts.get("PASS-THROUGH",0), counts.get("REVIEW",0),
         counts.get("DO",0)))
print("PASS-THROUGH means this check saw nothing in the body. It does not\n"
      "know about __weak, __pure, or an exported data symbol the entry\n"
      "passes down. Read the file before you delete it.")
