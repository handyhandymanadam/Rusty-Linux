# Bibliography

External sources this project actually used — read, tested against, or
cited as prior art — and specifically what each one contributed. Where a
source is referenced by title alone in this project's working notes without
full author/venue metadata on hand, that's noted rather than guessed at.

## Papers and theses

**Chris Lattner, *LLVM: An Infrastructure for Multi-Stage Optimization*.**
M.S. thesis, Dept. of Computer Science, University of Illinois at
Urbana-Champaign, 2002. [PDF](https://llvm.org/pubs/2002-12-LattnerMSThesis.pdf).

*How it was applied*: this 23-year-old design document names the
architecture the project's own C/Rust arrangement had, without noticing it,
fallen into — "traditional compilers break the compilation process into two
steps: compile and link," with the linker doing little more than
concatenating objects and resolving symbols. Reading it against the
project's own separate-per-file Rust crates identified exactly which later
optimization stage (the thesis's "link time," where whole-program IR is
still available) cross-language inlining structurally requires, and which
stage this project's build was actually stopping at. It reframed "why won't
this inline" from a vague toolchain complaint into a specific, checkable
claim about which compilation stage was missing — which is what led to
testing whether the LTO graph could be extended to include Rust at all (see
[`FINDINGS.md`](FINDINGS.md) and [`TOOLING-GAPS.md`](TOOLING-GAPS.md)).

**Hongyu Li, Liwei Guo, Yexuan Yang, Shangguang Wang, Mengwei Xu, *An
Empirical Study of Rust-for-Linux: The Success, Dissatisfaction, and
Compromise*.** USENIX ATC '24 (Best Paper).
[PDF](https://www.usenix.org/system/files/atc24-li-hongyu.pdf).

*How it was applied*: confirmed that the current, real Rust-for-Linux
project already made a deliberate cost/benefit call this project
independently arrived at from a different direction — wrapping C's
`static inline` functions in non-inlined Rust functions rather than fighting
the toolchain to inline across the boundary, because "current Rust lacks a
convenient mechanism for inlining FFIs of C functions." Used as a data point
about accepted cost, not copied as a policy — this project went on to
measure the actual size of that cost for its own workload rather than
assume the tradeoff was the same one everywhere (see the crossover analysis
in [`FINDINGS.md`](FINDINGS.md)).

**Yuchen Zhang, Yunhang Zhang, Georgios Portokalidis, Jun Xu, *Towards
Understanding the Runtime Performance of Rust*.** ASE '22.
[PDF](https://dl.acm.org/doi/pdf/10.1145/3551349.3559494).

*How it was applied*: its finding that the common claim "Rust outperforms C
partly because it inlines more aggressively" has no supporting data behind
it — stated in the paper itself — was the direct prompt to stop assuming
cross-language inlining would be a meaningful win and instead measure it
directly for this project's own code shape. The measurement (see
[`FINDINGS.md`](FINDINGS.md)) came back small and inconsistent in sign at
this project's current call-site density, consistent with there being no
free-standing "Rust is faster because it inlines more" effect to inherit
just by porting code.

**Andreas Hindborg (Samsung), *Inlining and LTO for Rust Kernel Modules*.**
Kangrejos 2023.
[PDF](https://kangrejos.com/2023/Inlining%20and%20LTO%20for%20Rust%20Kernel%20Modules.pdf).

*How it was applied*: this project independently rediscovered the exact
blocker this talk names on its "caveats" slide — an `objcopy --redefine-sym`
step in the kernel's Rust build that renames compiler intrinsics on a
finished ELF object, which breaks the moment that object is LLVM bitcode
instead. Finding this talk after the fact confirmed the blocker was real,
already known, and still unresolved three years later — and its `llvm-link`
workaround for combining bitcode at the module-linking step is what this
project's own working-but-unmerged fix for the same problem is modeled on.
See [`TOOLING-GAPS.md`](TOOLING-GAPS.md) for the specific patch shape this
points at.

**Miloš Svoboda et al., *A Pointer-Ownership Model for C Inspired by
Rust* (POM).** LCTES '26, pp. 97–111. DOI:
[10.1145/3814943.3816182](https://doi.org/10.1145/3814943.3816182).

*How it was applied*: a static-analysis paper about annotating plain C with
Rust-style ownership and checking the annotations with a SAT solver over
LLVM IR — not directly applicable to this project's problem (porting to
real Rust, not annotating C in place). What transferred was the *method*,
not the subject: checking an ownership-adjacent property by reasoning over
LLVM IR rather than source, on the same LLVM this project's C and Rust both
compile through. That observation — that clang and rustc share one LLVM and
so their IR could in principle interoperate directly — is what prompted
testing whether `llvm-link` could join a C module and a Rust module at all,
which led to the fat-LTO-objects and cross-language inlining findings above.

**Wang et al., *EvoC2Rust: A Skeleton-guided Framework for Project-Level
C-to-Rust Translation*.** ICSE-SEIP '26 (Shanghai Jiao Tong University +
Huawei).

*How it was applied*: read specifically to compare methodology against this
project's own. Its headline evaluation metric — "97% semantic accuracy" — is
a line-level diff against an LLM-generated reference translation that is
itself never executed, and its only behavioral check runs pre-existing Rust
unit tests, averaging under one test per translated function, without ever
running the original C. Read against this project's own bar (a userspace
differential harness comparing actual execution against the actual pristine
C, on a corpus large enough to be checked for adequacy, verified capable of
disagreeing before its clean result is trusted) this became the concrete
justification, written down, for why a considerably heavier verification
process is the right tradeoff here: a project could score 97% by that
paper's measure while containing every divergence this project's own
differential testing has actually found and fixed.

**RFC 1951 (DEFLATE Compressed Data Format Specification).**
[RFC 1951](https://www.rfc-editor.org/rfc/rfc1951).

*How it was applied*: used as the specification `lib/zlib_inflate` is
actually checked against, not the vendored C implementation — the C is a
reference implementation of a public format, and where its behavior on
malformed input is ambiguous or wrong, the RFC (not the C) is the authority
this project's port is verified to match.

**RFC 6229 (Test Vectors for the Stream Cipher RC4)** and **RFC 8439
(ChaCha20 and Poly1305 for IETF Protocols).**

*How they were applied*: used as independent, externally-sourced test
vectors for `lib/crypto/arc4` and `lib/crypto/chacha`/`poly1305`
respectively, specifically because a value taken from outside the tree
cannot agree with a self-consistent bug shared by both the C and the Rust
arm of a differential test — see the "read expectations out of an oracle,
never hand-reason them" discipline in [`FINDINGS.md`](FINDINGS.md), which
this same principle motivated project-wide.

## Kernel documentation

**`Documentation/process/security-bugs.rst`**, upstream Linux kernel tree.

*How it was applied*: its requirement that an AI-assisted vulnerability
finding be treated as a public disclosure, not a private one, is the reason
a real bug found in `lib/zlib_inflate/inflate.c` during this project's
testing is being routed to a public patch posting rather than a private
report to the kernel security team, once it's ready to send — see
[`FINDINGS.md`](FINDINGS.md).

## Prior art

**[handyhandymanadam/linux-rust-port](https://github.com/handyhandymanadam/linux-rust-port)**
— an earlier attempt at the same kind of project, by the same author.

*How it was applied*: its single largest finding — that every defect found
across several days of that effort was in the verification apparatus, none
in the ported algorithm code itself — is the direct reason this project's
standing rule is to build a check only once a defect has actually gotten
through, never speculatively. See the closing section of
[`README.md`](../README.md).
