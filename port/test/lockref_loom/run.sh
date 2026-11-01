#!/bin/bash
# run.sh [--sabotage]: loom explores every interleaving of a 3-thread model whose loop text is generated from lockref_rs.rs.
# --sabotage: replace the cmpxchg with load+store (a lost-update bug); the test must FAIL.
set -e
cd "$(dirname "$0")"
python3 gen_model.py ../../tree/lib/lockref_rs.rs src/model.rs
if [ "$1" = "--sabotage" ]; then
  python3 - <<'PY'
s = open("src/model.rs").read()
old = "match word.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {\n                    Ok(_) => return Outcome::Done(new_count),\n                    Err(cur) => old = cur,"
assert old in s.replace("/* try_cmpxchg() refreshes `old` */",""), "mutation site not found"
s = s.replace("word.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)",
  "{ let cur = word.load(Ordering::Relaxed); if cur == old { word.store(new, Ordering::Relaxed); Ok(old) } else { Err(cur) } }")
open("src/model.rs","w").write(s)
PY
  if cargo test --release --test loom 2>&1 | tail -5 | grep -q "FAILED\|failed"; then echo "SABOTAGE CAUGHT"; else echo "SABOTAGE NOT CAUGHT"; exit 1; fi
  python3 gen_model.py ../../tree/lib/lockref_rs.rs src/model.rs
else
  cargo test --release --test loom 2>&1 | tail -6
fi
