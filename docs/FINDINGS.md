# Findings

Concrete defects found along the way — in the port, in this project's own
verification tooling, and in the kernel's fingerprinting machinery itself —
what they looked like, what they actually were, and the general lesson each
one left behind. Most of the numbering below follows this project's internal
findings log; **two entries are withheld** pending responsible disclosure of
real upstream bugs they document — see the note at the end.

## A whole class of raw-pointer aliasing UB, found by a five-minute grep rule this project didn't have until it needed it

This project's toolchain runs no Miri anywhere — differential testing proves
two implementations agree on output, which structurally cannot see undefined
behavior that doesn't (yet) change output. A pattern showed up repeatedly in
files that take a C-style `*mut State` and reborrow it as `&mut State` partway
through a function: `let d = unsafe { &mut *state }`, followed later by a call
that takes the *original* raw pointer and does its own reborrow, followed by
more uses of `d`. Under the aliasing model both rustc and Miri assume (Stacked
/ Tree Borrows), the callee's reborrow invalidates `d`; every use of `d` after
that call is a use of a pointer the model considers dead, independent of
whether it happens to still compile to correct code today.

One instance was found first by direct review. Rather than fix it and move
on, it became a rule: `grep -n 'let .* = unsafe { &mut \*'`, then for each hit
check whether the binding shadows the pointer's own name (safe by
construction — the raw pointer becomes unnameable for the rest of the
function) and, where it doesn't, whether the original raw pointer gets passed
to another call before the reborrow's last use. Run once across every ported
file (109 files, 56 candidate reborrow sites, all inspected), it found **five
real instances** across four different files, each fixed the same way — read
what's needed into locals before the call, re-borrow fresh afterward, so the
raw pointer is never live across a call that might reborrow it too.

**The general lesson:** a differential test suite with excellent coverage
answers "does this compute the right answer," never "is this actually
allowed." Those are different questions, and a test suite that only asks the
first one will pass indefinitely on code that violates the second. The fix
here wasn't a bigger test corpus — it was a five-line grep applied uniformly,
because the shape of the bug was mechanical even though nothing in the
toolchain flags it automatically.

## A safe C convention that becomes undefined behavior on direct translation: `(NULL, 0)`

A common C idiom for "empty buffer, don't care about the pointer":

    while (len--) { /* use *p, then */ p++; }

When `len == 0`, `p` is never dereferenced, so callers routinely pass
`(NULL, 0)` and it is completely well-defined — an ordinary, widely-relied-on
convention, not an edge case anyone is being careless about. Translating the
same `(ptr, len)` pair directly into `std::slice::from_raw_parts(p, len)`
does not preserve that: `from_raw_parts` requires a non-null, aligned pointer
*regardless of length*, so a null `p` at `len == 0` is undefined behavior —
silent in a release build, an immediate abort with `-C debug-assertions=on`.
Reproduced directly against this project's pinned toolchain, not assumed.

Found in one file by review; a retroactive grep across already-merged code
turned up roughly eighteen more instances of the same shape. The fix, applied
going forward, is to guard the zero-length case explicitly before
constructing the slice:

    let s: &[u8] = if len == 0 { &[] } else { unsafe { slice::from_raw_parts(p, len) } };

**The general lesson:** a translation that is locally faithful — same
pointer, same length, same operation — can still change a call's UB
contract, because Rust's safe-construction preconditions are sometimes
strictly stronger than what the equivalent C ever required. "It's the same
pointer and the same length" is not the same claim as "it's the same
contract."

## A Rust kernel can have module versioning and full LTO at the same time

`CONFIG_GENDWARFKSYMS` (the tool that fingerprints exported symbols by
reading DWARF) is documented as incompatible with `CONFIG_LTO_CLANG`,
because LTO builds emit LLVM bitcode instead of finished ELF objects, and the
fingerprinting tool needs an ELF object to read.

That's a statement about a tool's input format, not a fundamental conflict —
an exported interface is fixed before any optimizer runs, so there's no
principled reason optimization should touch a symbol's ABI. Clang's
`-ffat-lto-objects` flag, present in the toolchain this project pins but used
nowhere in the mainline kernel build, emits a real ELF object that *also*
carries an LTO bitcode section in the same file. Three lines of
Kconfig/Makefile changes later, a kernel builds and boots with
`CONFIG_RUST=y`, `CONFIG_LTO_CLANG_THIN=y`, `CONFIG_MODVERSIONS=y`, and
`CONFIG_GENDWARFKSYMS=y` simultaneously — with every one of 13,774 exported
symbol fingerprints identical to a non-LTO control build. Verified genuinely
functional, not just present-but-inert, with a small two-file program where
the linker provably constant-folds an expression across the LTO boundary
only when the fat-object path is used.

See [`TOOLING-GAPS.md`](TOOLING-GAPS.md) for what this does and doesn't
unlock for Rust specifically.

## The ABI contract can live with the Rust, and the C file deleted outright

Covered in depth in [`ARCHITECTURE.md`](ARCHITECTURE.md). The headline
result: 14 C files deleted outright, 44 exported symbols moved into Rust,
every fingerprint unchanged — including a case where a kernel module
importing a symbol with *zero* C definition anywhere in the tree loads and
runs correctly.

## Two latent bugs found in the kernel's own fingerprinting tool

Also covered in [`ARCHITECTURE.md`](ARCHITECTURE.md): `gendwarfksyms` reading
only the first of several same-named rule sections (because Rust's
`#[used]` statics get linker flags that prevent the section-merging C
relies on), and the flag that enables rule processing being invisible to
kbuild's incremental-rebuild tracking, so a build made without it survives
its own correction silently.

## Why a fingerprint actually moves: parameter names, not type spelling

The intuitive explanation — "Rust spells `unsigned char` as `u8`, so the
hash changes" — is a plausible theory that turned out to be wrong in the
specific case that mattered most. With the `EXPORT_SYMBOL()` left behind in
a thin C shim and the real body in Rust, the DWARF available to hash is a
bare function-pointer type carrying **no parameter names at all**, and the
kernel's fingerprint hash includes parameter names. Chasing the wrong theory
cost 29 written pins that solved nothing, one of which had a real cost: it
froze a struct's memory layout in the fingerprinting tool's eyes, which
would have silently hidden a genuine 64-byte-to-128-byte growth in that
struct if one had occurred later.

## Cross-language inlining: the real blocker was never where it looked

The intuitive suspect for "why doesn't a C caller ever get a Rust callee
inlined into it" is that the optimizer looks at the Rust body, judges it too
costly, and declines — a normal, sensible compiler decision. **That
suspicion was written down as the explanation once, and it was wrong**: no
cost model ever evaluated those functions at all. Reading ThinLTO's own
import index directly showed the *importer* — the earlier stage that decides
which function bodies even get offered to the inliner — refusing them
outright, 6 to 20 times over its default size threshold, before any
inlining decision was made. The conclusion ("the inliner won't take these")
happened to be correct; the reasoning behind it hadn't actually run.

Separating "does the toolchain support this at all" from "does the kernel's
actual build use it" turned up the real, narrower blocker. Full LTO — one
whole-program optimization pass — genuinely does **not** inline across a
Rust/C boundary; one call instruction always remains, no matter what. Thin
LTO — multiple smaller, independently-optimized units gaining visibility
into each other's definitions — **does**: a Rust function's arithmetic
folded directly into the calling C function, constants propagated, a loop
unrolled, no call instruction left, verified end to end in a real linked
binary. That distinction matters immediately, because **the kernel already
builds with thin LTO** (`-flto=thin -fsplit-lto-unit`) — the project isn't
choosing between two options, it's already on the one that works.

What's left blocking Rust from actually joining that graph in a real kernel
build turned out to be two purely mechanical kbuild steps, not a compiler or
linker limitation at all — see [`TOOLING-GAPS.md`](TOOLING-GAPS.md) for
what they are. Once both were worked around, a genuinely booting kernel was
produced with cross-language inlining working in both directions and every
one of 13,774 exported-symbol fingerprints unchanged — kept on a separate
branch pending further review, not yet part of the main porting effort,
because the measured payoff at realistic in-tree call-site density is small
and inconsistent in sign (from roughly +0.02% to −0.4% depending on how hard
the inliner is forced), which is the honest reason it isn't a priority yet
even though the mechanism itself is proven.

## A defect class no ABI check can see

Covered in depth in [`ARCHITECTURE.md`](ARCHITECTURE.md): closing a
retained C "thunk" that looked like a pass-through but wasn't. Two of seven
such closures stopped the kernel from booting; every one of the seven had a
byte-identical function signature before and after, which is exactly why no
fingerprint check caught any of them.

## A Rust-containing kernel that is byte-for-byte ABI-identical with Rust compiled out

Building the same source tree with `CONFIG_RUST=n` produces a kernel with
**zero** Rust symbols and **3,894 of 3,894** exported-symbol fingerprints
identical to a pristine upstream kernel built from the same configuration —
confirming the C fallback described in [`ARCHITECTURE.md`](ARCHITECTURE.md)
really is behaviorally invisible when it's supposed to be. Its first boot
immediately failed one self-test, which was itself informative: a test
asserted `__ctzsi2(0) == 32`, a guarantee only the Rust port actually makes.
Upstream's C implementation of the same operation compiles to a single `bsf`
instruction on an input of zero, which is undefined behavior on this
architecture — and a sibling test for the 64-bit version of the same
operation *passed* against that same undefined construct, by accident, on
this toolchain and this input. The test needed narrowing to only apply under
the configuration that actually provides the guarantee.

## The floor rose six times, each time because a specific defect got through

The criteria a module has to satisfy before it counts as "ported" started at
five (builds, boots, userspace works, module ABI holds, and — not a test in
itself, but the thing that makes the other four mean anything — the Rust
symbol is actually present in the built kernel and actually reached at
runtime). Six more were added, and every one of them was forced by a real,
already-observed failure, not written speculatively:

1. **Builds under every Kconfig combination a file's own code reads, not
   just the project's two standard build configurations** — forced when a
   port shipped with a `#[cfg]` guard on its *use* of a value but not on the
   value's own definition; it built clean under both standard
   configurations and failed only under a third combination neither of them
   happened to exercise.
2. **Builds with `CONFIG_RUST=n`** — forced when every ported Makefile was
   found to add its Rust object files unconditionally, meaning the build
   failed immediately the moment Rust support was turned off, on any
   architecture, not just ones without a working Rust target. This is the
   fallback pattern documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).
3. **The differential test's C oracle has to be compiled in the same
   Kconfig configuration the tested kernel actually uses** — forced by a
   harness whose oracle silently exercised a different code path (a
   slow/portable path) than the one the kernel under test actually took (a
   fast, architecture-specific path); both sides "agreed" only because both
   implementations happened to be independently correct on that path, not
   because the comparison was checking what it claimed to check.
4. **Every ported file's Rust symbols must be traced as genuinely present
   and linked into the exact `vmlinux` that was tested** — forced by a
   deliberate one-character sabotage of a Makefile's `CONFIG_RUST` guard,
   which caused the build to silently select the C fallback while the Rust
   config option stayed on. The resulting kernel built, booted, faulted
   nowhere, and passed every self-test — with zero lines of the tested Rust
   actually compiled into it. The C had been doing all the work the entire
   time, undetected by anything except reading the linked binary's own
   symbol table directly.
5. **Agrees byte-for-byte on a big-endian target** — forced by realizing
   nothing in the project had ever run on a big-endian machine, despite
   `lib/`'s dense use of explicitly little-endian-assuming code. First
   cross-architecture run under emulation found a real bug — not in the
   port, but in a *test harness's own oracle*, whose "read this as a
   little-endian value" helper was a bare native-order `memcpy` that only
   happened to be correct on a little-endian host. No differential test
   could ever have caught this, because both arms being compared used the
   same broken helper.
6. **Every Rust struct claiming to mirror a C struct's memory layout is
   checked against that struct's actual compiled geometry, not just
   believed** — forced by realizing several dozen such structs existed and
   none had ever been checked against the real, built kernel's debug info.
   The checker built for this immediately caught its own first use's
   mistake: a struct size mismatch that looked alarming turned out to be two
   *different*, legitimately same-named structs in different translation
   units, which taught the checker to refuse to judge on genuine ambiguity
   rather than report a false alarm.

## When both implementations agree and the comparison was still wrong

A differential test proves two implementations produce the same answer to
the same question. It can't notice when the question itself is malformed —
when both arms share a bug, or when the comparison only looks at part of
what actually matters.

Two concrete instances, beyond the Kconfig-mismatch case in RAISE 3 above:

- **A struct's uninitialized padding bytes**, invisible to a test that only
  compares a function's *return value*. A Rust port correctly set every
  named field of a state struct but, unlike the C's `memset`-the-whole-thing
  initialization, left trailing padding bytes uninitialized. Every hash
  output produced by the struct agreed across nearly ten thousand test
  cases — the bug only surfaced because one test happened to compare the
  *entire struct*, byte for byte, after each operation, rather than just the
  function's return value. In the kernel, a raw `memcpy` of that struct
  elsewhere in the codebase would have propagated uninitialized stack memory
  wherever the struct was copied to. The general lesson kept from this:
  wherever a port writes into a caller-owned struct, the test needs to
  compare the whole struct, not just the values the function hands back.
- **A build step that silently dropped the very config options gating the
  tests meant to prove the port worked.** A script that restored pristine
  upstream Kconfig files as a side effect of an unrelated task quietly
  dropped three Kconfig symbols that had lost their menu prompts in the
  process — including the ones enabling the self-tests meant to verify the
  port. The resulting build was clean, booted, and reported zero
  fingerprint changes across all 13,781 exported symbols — truthfully, on a
  kernel that no longer contained the tested code at all. It was caught only
  because the test harness distinguishes an explicit "this test did not run"
  state from "this test passed," so a missing test couldn't be silently
  misread as a passing one.

## A real bug found in mainline Linux itself, not in the port

Writing a differential test for `lib/plist.c` — comparing this project's
Rust port against the original C on the same inputs — surfaced a case where
*the pristine, unmodified C* produced an unsorted result, independent of the
port entirely. A shortcut added to `plist_requeue()` in early 2025 assumed a
node's "next" pointer in its priority bucket's ring always points forward
within the list; from the *last* priority bucket, that ring wraps back to
the *first* bucket, and the shortcut silently computed the wrong insertion
point instead. Every bucket except the last one is unaffected, which is
exactly the shape of bug a benchmark measuring elapsed time — as the
original optimization's submission did — would never notice, since it never
checked the resulting order.

The reachable consequence: `mm/swapfile.c` uses this function to rotate its
per-NUMA-node list of same-priority swap devices, so a system with three or
more swap devices, at least two of them sharing the lowest priority, can
have its swap-device rotation silently corrupted. Before sending anything,
an independent review caught that the first draft of the reachability
analysis was itself wrong — it named a two-device configuration as
sufficient, which turns out to be safe for a different, non-obvious reason
(with only one priority bucket in play, the affected data structure is
never linked into the ring at all). That correction happened before
anything left the project, which is the point of having a second reviewer
check a disclosure's technical claims before they become permanent in a
sent message.

The fix was sent to the function's maintainer and the relevant kernel
mailing lists on 2026-09-03 and is publicly archived at
[lore.kernel.org](https://lore.kernel.org/all/20260903222456.1881786-1-handyhandyman.adam@gmail.com/).

## Deliberate divergences, tracked so they don't get silently "fixed back"

Not every difference from the original C is a bug. When a port deliberately
does something different from upstream for a good reason, it's recorded with
a specific rebase-time action, checked mechanically by diffing the whole
source tree against a checksum-verified copy of the original release — so
the next person who updates to a newer kernel version knows exactly what to
re-examine, rather than a divergence just sitting there until someone
"fixes" it back to match upstream without knowing why it was there.

Two examples worth calling out:

- **A fast path deliberately not reproduced.** One hashing algorithm's C
  implementation has a fast path, enabled by a Kconfig option both of this
  project's build configurations turn on, that reads up to seven bytes past
  the end of a buffer and relies on the architecture's exception-table
  machinery to catch the resulting page fault and recover. Reproducing that
  from Rust means hand-authoring exception-table entries via inline
  assembly; getting it wrong produces an unhandled fault inside a hash
  function instead of a compile error. The safer, portable byte-at-a-time
  path is used unconditionally instead — verified to produce identical
  output to the fast path, and to pass the algorithm's own upstream
  correctness test — with the omission and its reasoning recorded rather
  than silently accepted as "close enough."
- **An alternative to the kernel's C-declaration-based symbol versioning was
  tested and deliberately abandoned.** Switching the fingerprinting
  mechanism to one that hashes C *declarations* instead of DWARF from
  compiled *definitions* would remove the need for a C entry thunk on every
  exported symbol, since a body moving to Rust would no longer touch any
  header. The mechanism was confirmed to work. It was abandoned the same
  day: roughly a fifth of the kernel's exported symbols turn out to get a
  fingerprint that's a pure function of the symbol's *name*, with zero type
  information, because of how the Rust-support code currently declares its
  own exports — meaning a signature change to one of those symbols wouldn't
  move its fingerprint at all, and a stale third-party module would load and
  call it with the wrong arguments. That's precisely the failure module
  versioning exists to prevent.

## Theory and open predictions

Some of what came out of this work is a prediction rather than a settled
result — a model of where a payoff should show up, checked as far as
current evidence allows, with the boundary of that evidence stated
explicitly rather than left implicit.

### Where cross-language inlining would actually pay off

Forcing the inliner to cross the Rust/C boundary was measured at four
different call-site densities, and the cost fell monotonically as crossings
got more frequent relative to the work done per crossing: **+6.1%, +2.9%,
then a genuine −0.4% win** at the densest point tested (roughly the
per-block granularity real in-tree consumers like `squashfs`, `zram`, and
`ubifs` actually use). That trend line is the prediction: **the payoff is a
function of crossings per unit of work, not a fixed number**, and this
project's own code sits deliberately at the low-crossing end of that curve —
whole files are ported as units, so hot loops stay inside one Rust crate
where the compiler already inlines them without any kbuild change at all,
and what actually crosses a crate boundary tends to be one substantial
function call per unit of work, not a tight inner loop.

The falsifiable version of that prediction: a part of the kernel with
fine-grained, frequently-crossed boundaries between small hot functions
would land on the other side of that curve, where forcing cross-language
inlining is a real win rather than a rounding error. `lib/` is close to the
kernel's least performance-sensitive code by construction — this project
hasn't yet reached a subsystem shaped the way the model predicts would
matter. That's a prediction to test against future work, not a claim
already checked.

One concrete workaround already forced by this gap, worth naming as a cost
of the *current* state rather than a design choice: two of this project's
`lib/zstd` ports each carry their **own private copy** of a handful of the
hottest, smallest bit-reading helper functions, specifically so each copy
stays inside its own crate and inlinable, rather than crossing a crate
boundary uninlined. That duplication is exactly the kind of cost joining
the kernel's real LTO graph (see [`TOOLING-GAPS.md`](TOOLING-GAPS.md)) would
remove — the case for finishing that kbuild work is code size and
maintainability, not the speedup measured above.

### Which C/Rust interop constraints are permanent, and which are just where the tooling is today

A natural question once several of these constraints had been measured
individually: do they exist because Rust fundamentally has to coexist
carefully with C, and does that pressure ease off as more of the kernel
becomes Rust? Laid out side by side, with a measured cost or an explicit
"no measurable cost" for each:

| Constraint | Measured cost | Does it loosen? |
|---|---|---|
| Mandatory C entry thunk per exported symbol (MODVERSIONS) | A fraction of a cycle on a dependency chain, hidden entirely when not on a hot path | Only if the fingerprinting tool is taught to treat equivalent C/Rust types as identical |
| Overflow checks enabled on Rust arithmetic | Below measurement noise across six workloads; two were *faster* with checks on | It shouldn't loosen — there's no cost to trade away |
| No Rust runtime before the kernel proper exists | ~270 lines of C retained in four decompressors, compiled and tested by neither build configuration | Only once pre-boot gains a real Rust runtime — see [`TOOLING-GAPS.md`](TOOLING-GAPS.md) |
| Architecture forks for unaligned memory access | None remaining — already collapsed to a single portable helper | Already resolved |

The pattern across all four: **no interop constraint measured here has an
actual performance cost.** What they cost is engineering structure and
effort — a thunk to write, a fallback path to maintain — not runtime speed.
That's a testable claim, not an assumption, and it would take a genuinely
hot subsystem (which `lib/` mostly isn't) to falsify it.

### Crate granularity: measure before restructuring

Every ported file currently compiles as its own separate Rust crate. That
means every call between two ported files is a cross-crate call — not
inlinable under the current build, and each one needs its own `unsafe`
block at the FFI boundary even when both sides are this project's own Rust.
Whether fusing related files into fewer, larger crates would reduce the
`unsafe` count, shrink compiled code size, or actually let anything inline
is an open, deliberately *unmeasured* question — the project's working rule
is to measure the effect on one already-finished, self-contained group of
files before deciding whether to restructure anything larger, rather than
restructuring first on the assumption that fewer crates must be better.

---

**A note on what's not here yet.** Two real bugs found the same way — both
upstream, both present in mainline, neither introduced by this port — are
withheld from this document until responsible disclosure has actually
happened: one in `lib/zlib_inflate/inflate.c`, and a second, found more
recently, in `lib/zstd`'s dictionary-hash-set probing logic. Both will be
added here once that's done.
