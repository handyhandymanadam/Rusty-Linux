#!/usr/bin/env python3
"""Append a run to logs/quick-perf.tsv, rig-stamped.

NOT CITABLE. GOALS.md §4: this file is a development instrument. Its rows
are comparable to each other on one rig and to nothing else -- above all not
to logs/system-perf.tsv.
"""
import datetime
import sys

root, control_f, series_f, machine, cpu, rustc, cc = sys.argv[1:8]


def parse(path):
    out = {}
    for line in open(path):
        f = line.split()
        if len(f) >= 4 and f[1].replace(".", "").isdigit():
            out[f[0]] = (float(f[1]), float(f[2]), float(f[3]))
    return out


control = parse(control_f)
series = parse(series_f)
today = datetime.date.today().isoformat()
stamp = f"{machine} | {cpu} | {rustc} | {cc}"

rows = []
for name, (ca, cb, ratio) in control.items():
    rows.append((today, "1", name, stamp, "control", "ratio", f"{ratio:.4f}"))
for name, (ca, cb, ratio) in series.items():
    rows.append((today, "1", name, stamp, "rust_vs_c", "ratio", f"{ratio:.4f}"))
    rows.append((today, "1", name, stamp, "c", "seconds", f"{ca:.6f}"))
    rows.append((today, "1", name, stamp, "rust", "seconds", f"{cb:.6f}"))

with open(root + "/logs/quick-perf.tsv", "a") as fh:
    for r in rows:
        fh.write("\t".join(r) + "\n")

worst = max((abs(v[2] - 1.0), k) for k, v in control.items())
print(f"\nkerf: worst control deviation {worst[0] * 100:.2f}% ({worst[1]})")
print(f"appended {len(rows)} rows to logs/quick-perf.tsv")
