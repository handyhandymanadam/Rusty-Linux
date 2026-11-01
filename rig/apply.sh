#!/usr/bin/env bash
# apply.sh [--check]
#
# Install the ported files from port/tree/ into the kernel tree.
#
# WHY THIS EXISTS, and why it is not the tooling trap
#   src/ is gitignored -- the kernel tree is not ours to version. So the
#   ported Rust and the C files it replaces have to live somewhere that IS
#   versioned, and something has to put them in the tree. That is this, and
#   it is the whole of it. It builds nothing, checks nothing, and guards
#   nothing.
#
#   Files under port/tree/ mirror kernel paths and are stored WHOLE, not as
#   patches. A patch that half-applies is a class of failure this project
#   does not need; a whole file either matches the tree or does not.
#
# WHAT IT REPORTS
#   The sha256 it READ BACK from the kernel tree after copying, alongside the
#   sha256 of the source. Not "copied 3 files". A tool reporting success is
#   not evidence that it worked (notes/PRIOR-ART.md §3).
#
#   --check  compare only; copy nothing. Exit 1 if the tree differs.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tree="$root/src/linux"
port="$root/port/tree"
pristine="$root/port/pristine"
check=0
[ "${1:-}" = "--check" ] && check=1

[ -d "$tree" ] || { echo "no kernel tree at $tree"; exit 2; }

rc=0
printf '%-8s %-16s %-16s %s\n' STATE SOURCE INTREE PATH
while IFS= read -r -d '' f; do
    rel=${f#"$port"/}
    dst="$tree/$rel"
    a=$(sha256sum "$f" | cut -c1-16)

    if [ "$check" -eq 0 ]; then
        mkdir -p "$(dirname "$dst")"
        cp -- "$f" "$dst"
    fi

    if [ -e "$dst" ]; then b=$(sha256sum "$dst" | cut -c1-16); else b="ABSENT"; fi

    if [ "$a" = "$b" ]; then state=same; else state=DIFFERS; rc=1; fi
    printf '%-8s %-16s %-16s %s\n' "$state" "$a" "$b" "$rel"
done < <(find "$port" -type f -print0 | sort -z)

# ---------------------------------------------------------------------------
# THE CONFIG_RUST=n ARM. logs/floor.md RAISE 2.
#
# Every ported module has to build on the architectures that have no Rust --
# s390, powerpc, mips, sparc and the rest -- and on any x86_64 machine whose
# owner turns CONFIG_RUST off. The C for that arm has to come from somewhere,
# and the one place it cannot come from is port/tree/: those files are ours,
# they are edited, and RAISE 2 rests on the claim that the fallback CANNOT
# DRIFT FROM UPSTREAM BECAUSE IT IS UPSTREAM.
#
# port/pristine/ is that upstream, sha256-verified out of the tarball. So each
# pristine lib/ body is also installed as <base>_norust.c -- byte-identical
# content at a filename the Makefile can choose independently of the ported
# one. The two cannot collide, which matters because a thunk-shaped port
# OCCUPIES the original path: port/tree/lib/glob.c is our two entry symbols,
# and upstream's lib/glob.c is a different file with the same name.
#
# It is generated on every apply and never committed, so it cannot go stale
# and there is no second copy of upstream in git. The sha of each is printed
# below next to the sha of the pristine file it came from; they must match.
echo
printf '%-8s %-16s %-16s %s\n' STATE PRISTINE INTREE 'PATH (CONFIG_RUST=n arm)'
n_nr=0
while IFS= read -r -d '' f; do
    rel=${f#"$pristine"/}
    # lib/ plus the step-4 directories outside it (arch/x86/lib, fs/nls, crypto).
    case "$rel" in lib/*|arch/x86/lib/*|fs/nls/*|crypto/*|kernel/time/*|kernel/range.c|fs/fs_types.c|fs/fs_parser.c|block/partitions/efi.c|kernel/groups.c|kernel/user_namespace.c|kernel/notifier.c|kernel/resource.c|kernel/ucount.c|kernel/sysctl.c|kernel/kallsyms.c|kernel/auditfilter.c|fs/ext4/hash.c|security/selinux/ss/ebitmap.c|security/selinux/ss/avtab.c|security/selinux/ss/hashtab.c|security/selinux/ss/symtab.c|security/selinux/ss/conditional.c|security/selinux/ss/mls.c|net/ethtool/bitset.c|kernel/sched/pelt.c|kernel/sched/loadavg.c|kernel/sched/cputime.c|net/ipv4/tcp_cubic.c|net/ipv4/tcp_bic.c|net/ipv4/tcp_illinois.c|net/ipv4/tcp_htcp.c|fs/unicode/utf8-norm.c|fs/unicode/utf8-core.c|net/core/utils.c|arch/x86/kernel/cpu/scattered.c) ;; *) continue;; esac
    dir=$(dirname "$rel"); bn=$(basename "$rel" .c)
    dst="$tree/$dir/${bn}_norust.c"
    a=$(sha256sum "$f" | cut -c1-16)
    if [ "$check" -eq 0 ]; then
        mkdir -p "$(dirname "$dst")"
        cp -- "$f" "$dst"
    fi
    if [ -e "$dst" ]; then b=$(sha256sum "$dst" | cut -c1-16); else b="ABSENT"; fi
    if [ "$a" = "$b" ]; then state=same; else state=DIFFERS; rc=1; fi
    n_nr=$((n_nr + 1))
    [ "$state" = same ] || printf '%-8s %-16s %-16s %s\n' "$state" "$a" "$b" \
        "$dir/${bn}_norust.c"
done < <(find "$pristine" -name '*.c' -print0 2>/dev/null | sort -z)
printf '%d upstream bodies installed as *_norust.c for the CONFIG_RUST=n arm\n' "$n_nr"

exit $rc
