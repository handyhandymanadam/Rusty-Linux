#!/usr/bin/env bash
# sab-run.sh <runner> <scenarios> <sed-expr>... -- run a host differential once per sabotage (SABOTAGE=expr on the Rust), print one line each: CAUGHT / SURVIVED.
r=$1; n=$2; shift 2; c=0; s=0
for e in "$@"; do
  out=$(SABOTAGE="$e" "$r" "$n" 7 2>&1 | tail -n 3); 
  if echo "$out" | grep -q 'did not change'; then echo "NOCHANGE  $e"; continue; fi
  if echo "$out" | grep -q 'mismatches=0\b' && ! echo "$out" | grep -q 'DIFFERS'; then echo "SURVIVED  $e"; s=$((s+1));
  elif echo "$out" | grep -q 'error:\|error\[\|undefined reference\|Segmentation fault'; then echo "BUILDFAIL $e"; else echo "CAUGHT    $e"; c=$((c+1)); fi
done
echo "caught=$c survived=$s"
