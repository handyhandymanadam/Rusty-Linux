# Rusty-Linux

Porting the Linux kernel's `lib/` from C to Rust — one function at a time, in
a kernel that has to keep building, booting, and running an ordinary
userspace after every single change.

This is not a rewrite-and-hope-it-works project. Every port is checked
against the C it replaced with a userspace differential harness, verified
present and reached in a booted `vmlinux`, and checked to preserve the
kernel's module ABI (MODVERSIONS) byte for byte. The tooling and the
discipline that came out of building it this way turned out to be as
interesting as the port itself — that's most of what this repo is about.

## Status

Snapshot of 2026-10-31 (the previous one was 2026-09-06). Numbers are
`rig/progress.sh`'s own output on this tree, not hand-copied forward.

| | files | lines |
|---|---|---|
| `lib/` candidates ported (both buildable configurations) | 145 / 145 — **100.0%** | 63,524 / 63,524 — **100.0%** |

Of those 145 files, 98 have their C deleted outright; 47 keep a C entry
that the port could not close. The fraction is 100% of the
*candidates*, not of every file under `lib/`: code that neither verified
configuration compiles on x86-64 (raid6's per-instruction-set SIMD variants,
`crc/riscv`, `crc/s390`, `fdt*.c`, `vdso/`, options nothing turns on) is
deferred, not excluded, until there is a cross-architecture test strategy.
`drivers/` stays permanently out of scope for the reason given in the first
snapshot: drivers consume `lib/` through the same MODVERSIONS ABI this
project already verifies on every build.

Latest gate result (last finished module, `net/ipv4/tcp_htcp.c`): in-kernel
self-test suite 1,957 passed / 0 failed on the full configuration, 1,190 / 0
on the fast configuration, exported-symbol fingerprint changes 0, the
`CONFIG_RUST=n` fallback still builds, and all 85 sabotage mutants of the
module's harness are caught.

## What has been added since the first snapshot

The first snapshot covered `lib/`. The port now reaches beyond it, one
module at a time, under the same loop (differential test, integrate, build
both configurations, boot, check the Rust was reached, check the ABI):

| area | Rust files | examples |
|---|---|---|
| `lib/` | 156 | decompressors (gzip/inflate, bzip2, lz4, lzo, xz, zstd), sort, glob, plist, lockref, string helpers, radix-tree, rbtree, xarray, MPI, checksums |
| `arch/x86` | 64 | real-mode boot code (A20, APM, EDD, video, memory map, command line), the compressed-kernel boot stub (page tables, KASLR, EFI, early IDT), CPU feature detection, e820, instruction decoder |
| `kernel/` | 20 | scheduler load average, PELT and cputime arithmetic; clocksource, timer, NTP and time conversions; user namespaces, resource tree, sysctl, kallsyms, audit filter |
| `crypto/` | 15 | AES, CBC, CTR, ECB, CMAC, GHASH, HMAC, MD5, SHA-256/512, SHA-3, LZO, RSA helpers |
| `fs/` | 10 | mount-parameter parsing, ext4 directory hash, NLS code pages, Unicode UTF-8 normalisation and folding |
| `net/` | 6 | TCP congestion control (BIC, CUBIC, H-TCP, Illinois), ethtool bitsets, network utilities |
| `security/` | 6 | SELinux policy structures (avtab, ebitmap, hashtab, symtab, MLS, conditionals) |
| `block/`, `init/` | 2 | GPT partition validation, init |

Across `port/tree`: 281 Rust files, about 138,000 lines, and about 160
per-module test harnesses in `port/test`. Other additions:

- **Pre-boot Rust.** The kernel's pre-boot XZ decompressor engine is Rust,
  linked through rules in the boot stub's Makefile; the real-mode and
  compressed-stub boot code have Rust ports in the tree as well. A defect found on the way: five ported decompressors had lost
  their pre-boot arm, so five `KERNEL_*` compression choices did not build;
  restored and covered by `rig/codec-check.sh`.
- **More of the verification rig**: a KASAN-instrumented build, a build with
  no Rust at all (`CONFIG_RUST=n`) as the control, the pristine C baseline
  kernels, GPT disk images for the partition code (`rig/disk-check.sh`), a
  module-load check, and a gate script that runs build, boot and fingerprint
  check as one step.
- **Cross-architecture rigs**: `qemu-system-aarch64` and `qemu-system-riscv64`
  test rigs (`rig/boot-arm64.sh`, `configs/arm64*.fragment`, and the riscv64
  equivalents). The riscv64 build of the ported tree boots with the Rust
  reached and shows 0 changed, 0 added, 0 removed exported-symbol
  fingerprints.
- **Sabotage checks for every harness** (the "capable of disagreeing"
  principle below), with mutant counts recorded per module.

Parked work that is not finished is not in this repository (for example, the
`tcp_westwood` port was still being wired in at the time of this snapshot).

## Benchmarks

There is one published performance series, and it is deliberately modest.

**Boot to userspace**, `rig/boot.sh`, five runs per row, QEMU/KVM, 1 GiB, 2
CPUs, Linux 6.18.49, rustc 1.98.0, wall clock at 0.1 s resolution. Recorded
2026-09-02 and 2026-09-03; **not re-run for this snapshot**.

| ported modules | functions in Rust | `config-fast` boot | `config-full` boot |
|---|---|---|---|
| 0 (pure C baseline) | 0 | 0.4 s | 1.5 s |
| 1 (`lib/glob`) | — | 0.4 s | 1.4 s |
| 25 | 53 | 0.4 s | 1.5 s |
| 38 | 73 | 0.4 s | 1.5 s |

What this does and does not say: the instrument reports to 0.1 s on a
0.4 s boot, so it cannot resolve one module. It says nothing broke and
nothing moved by a tenth of a second, including after `sort()` and the first
decompressor (on the path that unpacks the initramfs) became Rust. It is
**not** a claim that any module is faster. A per-module microbenchmark rig
exists (`rig/perf/`, one binary with both arms chosen at runtime, worst
control deviation 0.99%) but its Rust arms are built without the kernel's
overflow checks, so its numbers are optimistic and are not published here.

## Why this is hard in a way that isn't obvious

Porting a function's logic from C to Rust is the easy 80%. The hard part is
everything the kernel expects a `lib/` function to keep being true after the
port:

- **The exported-symbol fingerprint (MODVERSIONS) must not move**, or every
  third-party kernel module built against the old headers refuses to load.
  Rust spells identical machine types differently than C at the DWARF level,
  which moves the fingerprint by default — see [`ARCHITECTURE.md`](docs/ARCHITECTURE.md)
  for how this project keeps it pinned.
- **A small C wrapper (a "thunk") often has to stay**, and it usually isn't
  a no-op — deleting one blindly can delete a bounds check, a `WARN_ON`, or a
  fast-path dispatch that was hiding in what looked like boilerplate. See
  [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`FINDINGS.md`](docs/FINDINGS.md).
- **The kernel's own build system doesn't have an opt-out.** `CONFIG_RUST=n`
  has to keep working — for any x86-64 user, not just other architectures —
  so every ported file needs a C fallback that can't drift from upstream.
- **A test that agrees with itself isn't a test.** Every differential harness
  here is checked, once, to be *capable of disagreeing* (a one-bit sabotage
  run that must produce a mismatch) before its clean run is trusted at all.

## Principles

- **The C is a reference implementation, not a specification to
  transliterate.** Where a better implementation exists — different
  algorithm, different data layout — it gets written, as long as the
  observable interface, memory layout, and write-ordering the kernel depends
  on don't move.
- **A green result that cannot distinguish "it works" from "it isn't there"
  is worse than a red one.** Every module has to prove its Rust is actually
  compiled into the tested kernel and actually reached at runtime — not just
  that behavior looks right, because a kernel has passed every behavioral
  check here once while containing no Rust at all.
- **The bar rises when a defect gets through it, never on a schedule or a
  hunch.** See [`FINDINGS.md`](docs/FINDINGS.md) for the concrete defects
  that forced each addition to the verification floor.
- **Build a tool only when a defect gets through.** An earlier attempt at
  this kind of project spent the majority of its effort on verification
  apparatus before a single module had cleared every gate. Progress here is
  measured in ported modules, not in defenses against hypothetical ones.

## How every change is verified

A function-level test proves the new Rust body computes the same thing as
the old C body. It proves nothing about whether that body is actually part
of the kernel a user would run. This project has hit that gap directly —
see the RAISE 4 story in [`FINDINGS.md`](docs/FINDINGS.md), where a
one-character build-config typo caused a kernel to pass every behavioral
check while containing zero lines of the tested Rust — so the loop every
single ported function goes through doesn't stop at a passing test:

    replace one function
      → differential test        against the real C, on a real corpus
      → integrate into the kernel tree
      → build a full kernel, both standard configurations
      → boot it
      → verify userspace comes up and the Rust symbol was actually reached

That last pair of steps runs continuously, not as an occasional integration
check — every module that counts as "ported" in the status table above has
a boot log showing the full kernel building, booting, and running an
ordinary userspace (`init`, a shell, coreutils) with that change in it. A
differential test that never runs against a real boot can't catch the class
of defect where the *build* silently didn't include the change at all; a
boot that never checks *which* code actually ran can't catch a build that
technically succeeded while quietly falling back to the old C. This project
checks both, on every change, because it has needed both at least once.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how a Rust-defined kernel
  symbol keeps the kernel's module ABI intact, how a C file gets deleted
  outright without losing behavior nobody remembered was there, and the
  pattern used for functions with an architecture-specific fast path.
- [`docs/FINDINGS.md`](docs/FINDINGS.md) — real defects found along the way,
  in the port, in the project's own tooling, and in the kernel's fingerprint
  machinery itself — what looked wrong, what it actually was, and the
  general lesson each one left behind — plus some open theory about where
  the remaining constraints on this kind of work are permanent versus just
  where the tooling happens to be today.
- [`docs/TOOLING-GAPS.md`](docs/TOOLING-GAPS.md) — where the current Rust-for-Linux
  and kernel build tooling made this harder than it needed to be, the
  workaround used here, and the specific upstream patch that would remove
  the workaround.
- [`docs/BIBLIOGRAPHY.md`](docs/BIBLIOGRAPHY.md) — the papers, talks, and
  RFCs this project actually read and used, and specifically what each one
  contributed.

## On AI assistance

Large parts of this port — the mechanical translation, the verification
tooling, the differential harnesses — were built with AI assistance
(Claude). Every commit that involved it says so in its trailer. The
engineering judgment calls — what the interface boundary is, when a
divergence from the C is acceptable, when a result is trustworthy enough to
build on — were made by a human, and the discipline in `docs/` above exists
specifically because "the tool said it worked" was, more than once, not
actually true until someone checked.

## Provenance

This is a fresh attempt; an earlier one is documented (and its lessons
carried forward) at
[handyhandymanadam/linux-rust-port](https://github.com/handyhandymanadam/linux-rust-port).
Its single biggest finding shaped how this project is built: across every
defect found in three days of that attempt, none were in the ported
algorithm code — all of them were in the verification apparatus around it.
That's the reason this project's rule is to build a check only after a
defect gets through, not before.
