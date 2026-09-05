#!/usr/bin/env bash
# progress.sh -- how much of lib/ is Rust. See rig/progress.py for the rules.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
exec python3 "$root/rig/progress.py" "$root"
