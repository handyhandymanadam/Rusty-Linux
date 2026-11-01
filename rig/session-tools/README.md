# session-tools -- scripts the 2026-10-02/03 worker session used every merge

Kept because they lived only in a temp folder. Paths inside point at that session's scratch dir and the
main checkout; adjust `S=` before reuse.

| file | what it does |
|---|---|
| mergeblk.py | after `git merge --no-commit <branch>`, rebuild the boot-stub Makefile as master's version with ONE `# --- NAME` block replaced by the branch's, and check if/endif balance (a hand merge once dropped two `endif`s) |
| gate.sh | apply, build build-fast and build-full, boot, crc-check |
| verify.sh | codec-check 7/7, CONFIG_RUST=n builds+boots per codec, then gate.sh |
| verify2.sh | verify.sh + the EFI (OVMF) 7/7 run |
| parity.sh | C-stub vs Rust-stub corrupted-payload serial-output matrix (uses rig/stubc-parity/) |

Order that worked: `rig/apply.sh` first (boot.sh refuses a drifted tree), check build rc before believing a
boot (boot.sh boots a stale image after a failed build), never run two builds on one build dir.
