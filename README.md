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

As of this snapshot:

| | files | lines |
|---|---|---|
| Ported (`config-full`, the authoritative build) | 58 / 125 buildable — **46.4%** | 13,252 / 40,532 — **32.7%** |
| Ported (full candidate set) | 62 / 245 — 25.3% | 14,023 / 111,982 — 12.5% |

`config-full` is the number that matters: it's the kernel configuration this
project treats as authoritative, versus `config-fast`, a smaller build used
for quick iteration. The candidate-set percentage is smaller because it
includes files that don't compile on x86-64 at all yet (see below) — porting
one of those wouldn't be progress toward a kernel that boots, so it isn't
counted as any.

**Out of scope, deliberately:**
- **`drivers/`** — permanently out. Drivers are `lib/`'s *consumers* through
  the same MODVERSIONS ABI this project already verifies on every build;
  porting a driver too would prove nothing the ABI check doesn't already
  prove, and most of `drivers/` ships as loadable modules anyway.
- **Architecture-specific code no available build compiles** (`raid6/`'s
  per-instruction-set SIMD variants, `crc/riscv`, `crc/s390`, `fdt*.c`,
  `fonts/`, `vdso/`) — 116 files, 70,679 lines. Not excluded, just deferred:
  there's no boot to put them in and no test to run them against without a
  cross-architecture QEMU strategy this project hasn't built yet.

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
