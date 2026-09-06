# Tooling gaps

Where the current state of Rust-for-Linux and the kernel's own build tooling
made this harder than it needed to be — what broke, what this project did
about it, and what upstream change would remove the workaround entirely.
These are written as patch/feature-request shapes on purpose: several of
these are small, mechanical, and — as far as this project has found —
unfiled.

**Status: none of these have been submitted upstream yet.** Every "upstream
fix" below is this project's own read of the problem, worked out well
enough to build a local workaround and to test it against this project's
own build — that is not the same bar as a patch someone has actually stood
behind in front of the people who maintain the code. Before any of these
becomes an actual submission, it gets re-checked independently first, the
same discipline applied to every other load-bearing claim in this project
(see [`FINDINGS.md`](FINDINGS.md) for what happens when that step gets
skipped). Treat this document as "here's what we found and how we'd frame
it," not "here's a queue of patches in flight."

## `gendwarfksyms` only reads the first rules section in an object

**The limitation.** A symbol's kABI rules (see
[`ARCHITECTURE.md`](ARCHITECTURE.md)) live in a linker section named
`.discard.gendwarfksyms.kabi_rules`. C's compiler merges multiple
same-named sections from one translation unit into one; `rustc` marks a
`#[used]` static with `SHF_GNU_RETAIN`, which forces each one into its own
separate section instead. `gendwarfksyms`'s rule reader opens the *first*
matching section and stops — so for any Rust object with more than one
kABI rule, every rule after the first was silently ignored.

**The workaround.** Patched the copy of `scripts/gendwarfksyms/kabi.c` this
project's build tree carries, to read every section matching the name rather
than stopping at the first.

**The upstream fix.** The same patch, upstreamed: iterate all sections with
the given name instead of opening the first match. Small, mechanical, and a
real correctness bug independent of anything Rust-specific — the fix
matters for any object where the linker declines to merge same-named
sections, which `SHF_GNU_RETAIN` isn't the only way to trigger.

## `KBUILD_GENDWARFKSYMS_STABLE` doesn't participate in kbuild's rebuild tracking

**The limitation.** Rule processing is gated behind a make variable,
`KBUILD_GENDWARFKSYMS_STABLE`, checked by `scripts/Makefile.build`. kbuild's
incremental-build mechanism (`if_changed`) decides whether to re-run a
compile step by comparing the *previous* command line against the current
one — but this variable isn't part of what it tracks. The practical effect:
building once without the variable set, then fixing that and rebuilding,
produces **no rebuild at all** — the object is already up to date as far as
`if_changed` can tell, so a real correction to the build configuration is
silently not applied.

**The workaround.** Manual awareness plus a full clean rebuild whenever this
specific flag changes, and a project-level check that reads the *actual*
built object's rule sections rather than trusting that the flag took effect.

**The upstream fix.** Fold `KBUILD_GENDWARFKSYMS_STABLE` into the tracked
command-line state `if_changed` hashes — the same mechanism that already
correctly detects a changed `-D` flag or a changed optimization level should
detect this one too.

## No symbol-versioning step for a generic `.rs` object build rule

**The limitation.** `rust/Makefile` runs `gendwarfksyms` as part of building
the `kernel` crate's own objects, but the generic rule used to build an
arbitrary `.rs` file elsewhere in the tree (`rule_rustc_o_rs`) had no
equivalent step at all — so a `lib/`-ported `.rs` file's exported symbols
never reached the fingerprinting tool in the first place, independent of any
of the rule-reading bugs above.

**The workaround.** Added the missing symbol-versioning invocation to the
generic Rust object build rule this project's tree carries.

**The upstream fix.** The same addition made generically available: any
`.rs` object that exports symbols under `CONFIG_GENDWARFKSYMS` should get
the same treatment `rust/Makefile` already gives kernel-crate objects,
regardless of which Makefile it's built from.

## `CONFIG_LTO_CLANG` + Rust + `CONFIG_MODVERSIONS`: unlocked for C, still blocked for Rust

**The limitation.** `CONFIG_GENDWARFKSYMS depends on !LTO`, with the
documented reason "requires ELF object files" — true of a normal LTO build,
which emits bitcode instead. `-ffat-lto-objects` resolves that for C (see
[`FINDINGS.md`](FINDINGS.md)) by emitting an ELF object that also carries a
bitcode section. **Rust objects still don't join the kernel's actual LTO
graph even once that's fixed**, for a separate, independent reason: the
kernel's LTO compiler flags are added only to `KBUILD_CFLAGS`, never to
`KBUILD_RUSTFLAGS`.

The good news, found by checking rather than assuming: the kernel already
builds with `-flto=thin`, not full LTO — and **thin LTO is specifically the
mode that supports cross-language inlining**; full LTO does not (see
[`FINDINGS.md`](FINDINGS.md)). So this isn't a request to change the
kernel's LTO strategy, only to extend the flags it already uses to
`rustc`. Doing that runs into one concrete, well-understood blocker: getting
`rustc` to emit LTO-compatible objects requires `-Clinker-plugin-lto`, and
turning that on makes `rust/Makefile`'s post-processing step on `core.o` —
an `objcopy --redefine-sym` pass renaming a handful of compiler intrinsics —
fail immediately, because that rewrite operates on a finished ELF object and
cannot be applied to LLVM bitcode. A second, separate obstacle applies
specifically to building Rust as a loadable module under LTO: the kernel's
module-linking step uses `ld -r`, which cannot combine bitcode either.

Neither obstacle is new. Andreas Hindborg (Samsung) hit both, by name, in
2023, and listed the `objcopy --redefine-sym` rewrite as an open problem
with no proposed fix on a public conference slide; that work was never
merged, and the kernel reportedly didn't boot on real hardware in that
configuration at the time. Current upstream Rust-for-Linux work (a queued
patch series for a later kernel release) takes a narrower, different path —
recovering inlining of specific C helper functions into Rust via a
crate-local `llvm-link` step — which doesn't put Rust objects into the
kernel-wide LTO graph either. This project's own conclusion, stated
plainly: **both remaining obstacles are kbuild plumbing, not compiler or
linker limitations.** Nothing at the LLVM level stands in the way — a small,
isolated program was used to confirm the compiler and linker genuinely will
constant-fold and inline across the language boundary once bitcode from
both sides reaches the linker together.

**The workaround.** LTO stays C-only in the standard build. A further pass
tracked down and worked around both remaining obstacles well enough to
produce a real, booting, in-kbuild kernel with genuine cross-language
inlining working in both directions and every one of 13,774 ABI
fingerprints unchanged. That work lives on a separate branch, not the main
porting line, pending further review — see [`FINDINGS.md`](FINDINGS.md) for
the measured (modest, and not consistently positive) performance
implications, which is the honest reason it isn't a priority to merge yet
even though the mechanism itself is now proven to work in a real kernel.

**The upstream fix, in three parts.** (1) Extend the kernel's existing thin
LTO flag plumbing (`CC_FLAGS_LTO`) to `KBUILD_RUSTFLAGS` when
`CONFIG_LTO_CLANG_THIN` is set — no change to *which* LTO mode the kernel
uses, just making Rust participate in the one already chosen. (2) Move the
compiler-intrinsic renaming `rust/Makefile` currently does via
`objcopy --redefine-sym` to before codegen (renaming the symbols at the
source or `#[export_name]` level) or defer it until after LTO has already
produced final objects, so it no longer needs to operate on bitcode at all.
(3) For the module-linking path specifically, replace or wrap the `ld -r`
step with something bitcode-aware (`llvm-link`, as Hindborg's 2023 work
already demonstrated as a workaround) when building Rust objects under LTO.

## No minimal, opt-out `CONFIG_RUST` build mode

**The limitation.** Enabling `CONFIG_RUST` at all currently pulls in the
full `rust/kernel` support crate and its transitive dependencies
unconditionally — measured at roughly a thousand exported symbols published
into the running kernel that this project's freestanding, `no_std` ported
code references *none* of. There's no Kconfig-level way to say "I want Rust
object files in this build, but not the standard kernel abstraction crate."

**The workaround.** Not pursued as a build-time change yet — this project
measured three ways to shrink or eliminate the unused export surface
(enabling `CONFIG_TRIM_UNUSED_KSYMS`, dropping the crate's exports object
from the link entirely, or building a genuinely minimal `rust/` support
tree) and confirmed all three build, link, and boot correctly while keeping
every already-ported symbol reachable. None has been adopted in the main
line pending a decision about the tradeoff (the leanest options make any
future `=m` Rust kernel module a hard build failure rather than a graceful
degradation).

**The upstream fix / feature request.** A genuinely minimal Rust-support
Kconfig option — build the toolchain plumbing (`core`, `alloc` if needed,
`compiler_builtins`, and the mechanism this project's own
`kernel::kabi_export!` builds on) without the full `kernel` abstraction
crate and its exports. Useful for exactly this project's shape of work:
freestanding leaf-function ports that don't need driver-facing kernel
abstractions at all.

## Pre-boot has no Rust runtime, which forces C to stay in four decompressors

**The limitation.** The kernel's pre-boot decompression stub
(`arch/x86/boot/compressed/`, and equivalents) runs before the kernel proper
exists — no allocator, no panic handler, none of the setup a normal
`no_std` Rust crate expects. Four of this project's decompressor modules
(`zlib_inflate`, `lzo`, `xz`, `lz4`) are `#include`d a second time, verbatim
in C, into that pre-boot environment via a textual-inclusion pattern the
kernel already uses for exactly this reason. That second copy is compiled
by neither of this project's standard build configurations and exercised by
none of its tests, purely because there's nowhere to run a Rust version of
it.

**The workaround.** A separate, deliberately scoped experiment confirmed
`no_std` Rust genuinely *can* run in that pre-boot environment — linked,
executed, and its return value checked by the boot stub before it halts —
which removes the "is this even possible" question. Actually rewriting the
pre-boot copies to Rust is intentionally not started as a side effect of
ordinary module porting; it's large enough (and touches early-boot failure
modes carefully) to be its own deliberate piece of work.

**What upstream could do.** Nothing is strictly broken here — this is a
capability gap, not a bug. A documented, supported pattern for a minimal
`no_std` Rust presence in `arch/*/boot/compressed/` (rather than each
project reverse-engineering what the linker script and boot stub will
tolerate) would make this a much smaller lift for any kernel Rust effort
that touches early boot code, not just this one.

## Self-test module output quality

**The limitation.** Some of the kernel's own runtime self-test modules
(the older `module_init()`-based style, as opposed to `KUnit`) only ever
print a message on *failure* — a bare `WARN()` naming the failing case —
and never print anything at all on success. That makes them weak as an
automated proof caller: a CI system watching kernel boot logs cannot
distinguish "this test ran and every case passed" from "this test's config
option silently isn't set and it never ran at all," short of grepping for
the specific config-dependent module-load message.

**The workaround.** This project's own boot-log tooling treats "config
option is on, module loaded, and no failure message appeared" as a pass —
which is correct, but weaker evidence than a test that states its own case
count on success the way `KUnit`-style tests do.

**The upstream fix.** A small, mechanical patch to each affected
self-test's `module_init()` function: print a one-line summary (total
cases, cases passed) unconditionally, the same shape `KUnit` output already
provides. Low-risk, and it would benefit anyone running these tests in an
automated pipeline, not just this project.

## `core`'s new float `ClampBounds` impls broke linking on soft-float freestanding targets — RESOLVED upstream, not by us

**The limitation.** Moving from rustc 1.98.0 stable to a 1.100.0 nightly, the
kernel's link step started failing:

    ld.lld: undefined symbol: fmaximum_numf, fminimum_numf, __gtsf2,
                              fmaximum_num,  fminimum_num,  __gtdf2

Traced to new concrete `ClampBounds` impls for `f32`/`f64` added to `core`
(`core/src/cmp/clamp.rs`). Being concrete rather than generic, they were
unconditionally codegen'd into every `core.o`, and they pulled in soft-float
runtime calls the kernel's `-mmx,+soft-float` build of `core` never provides.
1.98.0 predates the file entirely and links cleanly; the break was
nightly-only, and this project stayed on 1.98.0 specifically because of it.

**The workaround.** None needed beyond staying off the affected nightlies —
1.98.0 stable was already the pinned toolchain for unrelated reasons.

**The upstream fix.** Raised as a question, not a bug report, since we
weren't sure whether a `no_std`/no-builtins freestanding target routing
around new `core` float functionality was expected friction or a real gap.
The answer came back within the day: [rust-lang/rust#162191](https://github.com/rust-lang/rust/pull/162191),
marking the affected methods `#[inline]` so they're only codegen'd where
actually reachable — merged 2026-09-04. Verified directly rather than taken
on trust: pulled the first nightly containing the fix and ran a full kernel
build against it in a scratch directory, `rust/core.o` through a clean
`bzImage` link with zero undefined-symbol errors, where the same build
failed one nightly earlier. This project remains on 1.98.0 regardless —
nothing forces a move off a working stable toolchain — but nightly is no
longer a hazard if a reason to move ever comes up. Left here as a data point
on turnaround, not as an open gap.
