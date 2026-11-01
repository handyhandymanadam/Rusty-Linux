#!/usr/bin/env python3
"""mergeblk.py <branch> <BLOCKNAME> : after `git merge --no-commit <branch>`, rebuild the stub Makefile as
master's version with ONE block (# --- NAME ...) replaced by the branch's version, check ifeq/endif balance."""
import subprocess,re,sys
br,name=sys.argv[1],sys.argv[2]
P='port/tree/arch/x86/boot/compressed/Makefile'
ours=subprocess.check_output(['git','show','HEAD:'+P]).decode()
theirs=subprocess.check_output(['git','show',br+':'+P]).decode()
def block(t):
    m=re.search(r'^# --- '+re.escape(name)+r'\b.*?(?=^# --- )',t,flags=re.S|re.M)
    assert m,("block not found",name); return m
a,b=block(ours),block(theirs)
new=ours[:a.start()]+b.group(0)+ours[a.end():]
d=0
for l in new.split('\n'):
    t=l.strip()
    if re.match(r'(ifdef|ifndef|ifeq|ifneq)\b',t): d+=1
    elif t=='endif': d-=1
assert d==0,("unbalanced",d)
open(P,'w').write(new); print("block",name,"replaced; balanced")
