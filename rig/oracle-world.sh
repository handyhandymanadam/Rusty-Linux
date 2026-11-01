#!/usr/bin/env bash
# rig/oracle-world.sh <outdir> [module ...]   -- see logs/floor.md RULE T4.
#
# Run before a change to the test shims, run after, diff. Two artifacts, and
# they are NOT the same kind of claim:
#
#   <mod>.tu   the emitted TOKEN STREAM of every oracle translation unit.
#              HARD GATE. Byte-identical == the oracle compiles the same code.
#
#   <mod>.inc  the set of files the preprocessor actually RESOLVED (cc -H),
#              depth-normalised. REVIEWED BY A HUMAN, not gated: a shim
#              refactor moves definitions between files on purpose, so this
#              diff is SUPPOSED to be non-empty. Read it; confirm every move
#              is one you meant.
#
# HOW IT FINDS THE TRANSLATION UNITS. It does not glob, and it does not carry
# its own copy of the flags. It puts a logging `cc` on PATH, runs the real
# harness, and replays every invocation that had a .c in it -- so the TU set,
# the -I ordering, the -D renames, -DSTATIC=1, -DCONFIG_64BIT=1 and both
# CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS arms all come from the harness itself
# and cannot drift away from it.
#
# The first version DID glob, and an adversarial review on 2026-09-03 found
# that its lz4 coverage was one dead file plus one proxy and zero of the three
# real TUs; that it omitted -DCONFIG_64BIT=1, the single flag lz4's run.sh
# documents as load-bearing; that it missed zlib's -DSTATIC=1 pre-boot arm
# entirely; and that it swallowed preprocessor failures silently. Hence this.
#
# LIMITS, stated so this is not overclaimed. It verifies the token stream of
# the TUs the harness actually built, in the configurations it actually built
# them. It says nothing about: #if branches no enumerated configuration
# reaches; optimisation level, target flags or link order (none survive -E);
# the Rust arm; the harness's own comparison logic; or whether the oracle was
# ever correct. It is a NO-REGRESSION check on preprocessed text. It preserves
# a wrong oracle with exactly the same fidelity as a right one.
set -uo pipefail
root=${ORACLE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
dst=$1; shift
# DISCOVERED, not listed. The hardcoded default here read
#   "lib lz4 lzo xz zlib_inflate glob math"
# and had gone stale by three modules -- xz_stream, xz_lzma2 and zstd_entropy
# all had harnesses this check never once ran. A stale list does not fail; it
# passes, quietly, over a smaller world than it claims. That is notes/STATUS.md
# lesson 9 wearing rig clothes, so the list is now derived from what exists.
mods=${*:-$(for d in "$root"/port/test/*/; do
                [ -x "$d/run.sh" ] && basename "$d"
            done | tr "\n" " ")}
mkdir -p "$dst"
REALCC=$(PATH=$(echo "$PATH" | tr ":" "\n" | grep -v ccache | paste -sd:) command -v cc)
wrap=$(mktemp -d); trap 'rm -rf "$wrap"' EXIT
cat > "$wrap/cc" <<W
#!/usr/bin/env bash
printf '%q ' "\$@" >> "\$CCLOG"; echo >> "\$CCLOG"
exec $REALCC "\$@"
W
chmod +x "$wrap/cc"

fail=0; done_any=0
for m in $mods; do
  [ -x "$root/port/test/$m/run.sh" ] || { echo "*** NO HARNESS: $m (root=$root -- set ORACLE_ROOT?)" >&2; fail=1; continue; }
  log=$(mktemp); : > "$dst/$m.tu"; : > "$dst/$m.inc"; : > "$dst/$m.cfg"
  CCLOG=$log PATH="$wrap:$PATH" "$root/port/test/$m/run.sh" >/dev/null 2>&1
  n=0
  while IFS= read -r line; do
    eval "set -- $line"
    srcs=(); flags=(); skip=0
    for a in "$@"; do
      if [ "$skip" = 1 ]; then skip=0; continue; fi
      case "$a" in
        -o) skip=1 ;;
        -c) ;;
        *.c) srcs+=("$a") ;;
        *) flags+=("$a") ;;
      esac
    done
    [ ${#srcs[@]} -eq 0 ] && continue
    for f in "${srcs[@]}"; do
      [ -f "$f" ] || continue
      n=$((n+1))
      # The tag names the TU and the -D flags (which select code paths). It
      # deliberately EXCLUDES -I: adding an include directory is a legitimate
      # change that must not trip the gate by appearing in a header line, and
      # its real effect shows up in the token stream and in <mod>.inc anyway.
      tag="${f#$root/} :: $(for a in "${flags[@]}"; do case "$a" in -D*) printf '%s ' "$a";; esac; done)"
      # keep #pragma (it survives preprocessing and can change layout);
      # drop only '# 123 "file"' line markers, whose information goes to .inc
      { echo "### $tag"
        "$REALCC" -E "${flags[@]}" "$f" 2>/dev/null | grep -v '^# ' | sed '/^$/d'
      } >> "$dst/$m.tu"
      { echo "### $tag"
        "$REALCC" -E -H "${flags[@]}" "$f" 2>&1 >/dev/null \
          | grep '^\.* /' | sed 's/^\.* //' | sed "s|$root|<root>|" | sort -u
      } >> "$dst/$m.inc"
      # floor.md criterion 8: which CONFIG_* this TU actually sees. The
      # differential CANNOT catch a configuration mismatch -- measured on
      # 2026-09-03, sabotaging sort_rs.rs to ignore efficient_unaligned
      # entirely still passed, because both strategies sort correctly. So the
      # only thing that can enforce criterion 8 is this list, compared against
      # the kernel .config.
      { echo "### $tag"
        "$REALCC" -E -dM "${flags[@]}" "$f" 2>/dev/null \
          | grep -oE '^#define (CONFIG_|XZ_)[A-Z0-9_]+' | sed 's/^#define //' | sort -u
      } >> "$dst/$m.cfg"
    done
  done < "$log"
  rm -f "$log"
  # A TU that fails to preprocess leaves a bare '### ' header. Silence is the
  # one thing this check must never report as success.
  empty=$(awk '/^### /{if(prev=="###")e++; prev="###"; next}{prev=""}END{print e+0}' "$dst/$m.tu")
  printf '%-14s %3s TUs' "$m" "$n"
  if [ "$n" -eq 0 ]; then echo "   *** NO TRANSLATION UNITS CAPTURED ***"; fail=1
  elif [ "$empty" -gt 0 ]; then echo "   *** $empty EMPTY (preprocessing failed) ***"; fail=1
  else echo "   ok"; done_any=1; fi
done
[ "$done_any" = 1 ] || { echo "*** NOTHING WAS CHECKED ***" >&2; fail=1; }
exit $fail
