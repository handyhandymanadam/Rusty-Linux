# Architecture

Three mechanisms make it possible to move a kernel function's *body* from C
to Rust — including deleting the C file outright — without breaking anything
that depends on the function still looking like it did before:

1. [Keeping the module ABI fingerprint pinned when the export moves to Rust](#keeping-the-module-abi-fingerprint-pinned)
2. [A C fallback that can't drift, for every architecture Rust doesn't reach](#the-c-fallback-that-cant-drift)
3. [Telling a real thunk from a load-bearing one before deleting it](#telling-a-real-thunk-from-a-load-bearing-one)

## Keeping the module ABI fingerprint pinned

### The problem

Under `CONFIG_MODVERSIONS` with `CONFIG_GENDWARFKSYMS`, every symbol the
kernel exports to modules carries a fingerprint — a CRC — computed by hashing
the DWARF debug info of whatever object *defines* that symbol. A third-party
kernel module built against a given kernel's headers embeds the fingerprints
it expects; if a symbol's fingerprint has changed, the module refuses to
load, because the kernel can no longer promise the function still means what
the module thinks it means.

That's exactly the promise a straight C-to-Rust port has to keep. And by
default, it can't: Rust and C spell identical machine types differently at
the DWARF level.

```
C:    base_type unsigned char byte_size(1) encoding(8)
Rust: base_type u8            byte_size(1) encoding(7)
```

Same width, same signedness, same ABI — different name, different
`DW_ATE_*` encoding, different hash. Move a function's body to Rust with no
further work, and every third-party module using that symbol stops loading,
even though nothing about the function's actual behavior or calling
convention changed.

It is tempting to conclude the fix is "teach the fingerprinting tool to treat
`u8` and `unsigned char` as equivalent." That was tried, in effect, and it's
the wrong shape: with the `EXPORT_SYMBOL()` left in a C shim and only the
*body* in Rust, the DWARF available to hash is a bare function-pointer type
with **no parameter names at all** — and the fingerprint includes parameter
names. Twenty-nine pins were written to paper over a mismatch that a type
name never actually caused; the real cause was the C shim's declaration
losing the information the hash needs, not Rust choosing different type
names. Worse, one of those pins accidentally froze a struct's memory layout,
which would have silently hidden a real 64-byte-to-128-byte growth in that
struct later. Wrong theory, wrong fix, and the wrong fix was actively unsafe.

### The fix

Put the export on the Rust side, so the hash is taken from Rust DWARF — and
carry the *original C signature* as metadata that travels with the export,
so the fingerprinting tool hashes the C spelling instead of the Rust one.

```rust
kernel::kabi_export! {
    _bcd2bin,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned char \
                 byte_size(1) encoding(8) val ) -> base_type unsigned int \
                 byte_size(4) encoding(7)",
}

#[no_mangle]
pub extern "C" fn _bcd2bin(val: u8) -> core::ffi::c_uint {
    ((val & 0x0f) as core::ffi::c_uint) + (val >> 4) as core::ffi::c_uint * 10
}
```

`kabi_export!` emits two things directly into the compiled Rust object:

- a `.export_symbol` entry, byte-identical to what C's `EXPORT_SYMBOL()`
  macro produces, so the kernel's module post-processor (`modpost`) exports
  the symbol exactly as it did before;
- a `type_string` rule in a linker-discarded section
  (`.discard.gendwarfksyms.kabi_rules`), read only by the host-side
  `gendwarfksyms` tool, telling it: for this symbol, hash *this* string
  instead of the Rust DWARF.

Two properties make this safe rather than a hand-wavy escape hatch:

- **The contract string is never hand-typed.** It's generated from a
  *compiled C object* — not a header, which as above doesn't carry parameter
  names — by a tool that captures the exact type string the fingerprinting
  tool would have hashed from the original C definition, back-references and
  all. A separate check re-derives every contract from pristine upstream C
  and diffs it against what's checked in; it only ever reports a mismatch,
  never silently "corrects" one.
- **The rule never reaches the running kernel.** It lives in a
  linker-discarded section — verified empirically to have zero occurrences
  in a linked `vmlinux` — and is read only by a host build tool. A wrong pin
  can misreport the kernel's ABI to that tool; it cannot change one
  instruction of what actually runs.

### Generating the pins, and keeping them honest across a kernel rebase

A hand-written pin is a liability: the moment upstream's C declaration
changes — a parameter added, a type widened — a hand-typed pin keeps
asserting the *old* fingerprint, and now it's actively hiding a real ABI
break instead of preventing one. So a pin is never typed by hand, and there
are two separate tools, one for each direction:

- **Capture** compiles the relevant C object (from a byte-for-byte checksum-verified
  extraction of the upstream release, not the working tree, so nothing
  already touched by this project can leak into what's supposed to be the
  reference) and runs the kernel's own fingerprinting tool against it in
  its back-reference output form — the same form the pins have to be
  written in, since an expanded form would freeze the layout of every type
  the signature mentions rather than leaving it live and checkable. The
  output is the literal `kernel::kabi_export!` block, generated, not
  composed.
- **Contract-check** does the same derivation again, independently, and
  diffs the result against whatever is currently committed in the Rust
  source. It never edits a pin — it only ever reports a disagreement.

That second tool is what makes rebasing to a newer kernel version tractable
instead of quietly dangerous. When the vendored kernel tree is updated, the
checksum-verified upstream C is updated with it; running contract-check
against the new tree re-derives every pinned contract from the *new*
upstream signatures and prints exactly which symbols' pins no longer match —
each one either a genuine upstream signature change (which needs a human
decision about how the Rust side should change too) or, in the common case,
nothing at all, because most functions don't change shape between releases.
Either way, the alternative — a pin nobody re-checks — is the one that fails
silently: it keeps compiling, keeps producing a fingerprint, and that
fingerprint is simply wrong the moment upstream moved out from under it.

Two sibling macros close gaps in the same family of problem:

- **`kabi_modinfo!`** replays a deleted C file's `MODULE_AUTHOR()` /
  `MODULE_DESCRIPTION()` / `MODULE_LICENSE()` metadata. These aren't module
  machinery in a built-in kernel — they're strings the linker collects into
  `vmlinux` and kbuild extracts into `modules.builtin.modinfo`, which is
  installed and which the `modinfo` tool reads. Deleting the C file silently
  deletes those lines; this went unnoticed for the first four C files this
  project removed before anything caught it.
- **`kabi_warn!` / `kabi_warn_on_once!`** give a Rust port a real `WARN()` —
  bug-table entry, taint flag, the actual diagnostic message — because the
  upstream Rust kernel support at the time only shipped a bare `warn_on!`
  with no message. Losing a `WARN()`'s message during a port is invisible to
  every ABI check (the signature doesn't change) and invisible to most
  functional tests (a warning doesn't change a return value) — see
  [`FINDINGS.md`](FINDINGS.md) for what this specifically prevented.

### Along the way: two real bugs found in the kernel's own fingerprinting tool

Building this mechanism surfaced defects in `gendwarfksyms` itself, not in
the port:

- It reads only the **first** rules section in an object and stops. GCC
  merges same-named sections from C into one; `rustc` marks a `#[used]`
  static `SHF_GNU_RETAIN`, which forces one section per rule instead — so
  half of every multi-rule contract was being silently ignored until this
  was found and worked around.
- The kbuild flag that turns rule-processing on
  (`KBUILD_GENDWARFKSYMS_STABLE`) is invisible to kbuild's own
  incremental-rebuild tracking (`if_changed`). A build made without the flag
  set survives its own correction — flipping the flag on and rebuilding does
  nothing, because kbuild doesn't consider the command line to have changed.

See [`TOOLING-GAPS.md`](TOOLING-GAPS.md) for the specific upstream patches
these point at.

## The C fallback that can't drift

`CONFIG_RUST=n` has to keep working. Not as an other-architecture edge case —
any x86-64 user can set it — and this project's Makefiles were, for a while,
unconditionally adding the `.rs` objects to every build, which meant the
kernel simply failed to build the moment `CONFIG_RUST` was off (see
[`FINDINGS.md`](FINDINGS.md), RAISE 2).

The fix is mechanical and applied per Makefile:

```make
ifdef CONFIG_RUST
obj-y += kstrtox_rs.o
else
obj-y += kstrtox_norust.o
endif
```

`<base>_norust.c` is not committed to the repository. It's regenerated on
every build-preparation pass as a byte-for-byte copy of the file extracted
straight from the upstream kernel tarball, whose checksum is verified against
the published release. It needs a different filename than the original
because the port itself may occupy that path with a thunk-shaped C file — so
`lib/foo.c` (this project's C) and `lib/foo_norust.c` (verbatim upstream) can
coexist without collision. Because it's generated fresh every time rather
than hand-maintained, it cannot drift from upstream, and there is no second,
independent copy of upstream C sitting in this repository's history to fall
out of sync.

## Telling a real thunk from a load-bearing one

In this project's vocabulary, a **thunk** is a small C function retained
after its logic moved to Rust — usually because it's the mandatory entry
point an `EXPORT_SYMBOL()` needs, or because it dispatches to
architecture-specific code Rust doesn't reach yet.

The dangerous assumption is that a thunk which merely calls straight through
to the Rust function is doing nothing, so deleting it is safe. Seven times,
that assumption was wrong, and none of the seven were caught by any
signature check or ABI check, because **the signature genuinely didn't
change** — only the behavior did.

Two examples:

- `gcd()`'s thunk carried `if (!a || !b) return a | b;` and a
  jump-label-patched dispatch to an architecture-optimized implementation.
  Deleting it left the Rust body running unconditionally — and `gcd(x, 0)`
  spun forever in it.
- `ucs2_strscpy()`'s thunk carried `if (count == 0 || WARN_ON_ONCE(count > INT_MAX)) return -E2BIG;`. Deleting it removed the only bounds check
  standing between a caller and a subtraction that then overflowed.

Two of the seven closures stopped the kernel from booting; the rest silently
dropped `WARN_ON`/`BUG_ON` guards that no functional test happened to
exercise. In every case, the exported function's *signature* was
byte-identical before and after, so the fingerprint check this project
already had — the mechanism described above — read `0 changed` throughout.
A CRC proves an interface didn't move. It says nothing about whether the
behavior behind that interface still matches.

The tool this project built in response runs in two passes, and neither
alone is sufficient:

- **Pass 1** diffs a to-be-closed thunk's original C body against a set of
  guard shapes (`WARN_ON`, `BUG_ON`, `static_branch` dispatch, `unlikely`
  hints, early-return validation) and requires each one to either survive
  somewhere in the tree or be listed in a human-reviewed exception file with
  a stated reason (a branch hint, a config fork now expressed as a Rust
  `#[cfg]`, or a guard deliberately not reproduced and recorded as a
  documented divergence).
- **Pass 2** catches what Pass 1 structurally can't: a guard the port itself
  *moved* rather than dropped — for example relocating a `WARN_ON_ONCE()`
  from a `static` helper into the newly-exported Rust entry point when that
  helper stopped being C. It checks that any comment in the tree *claiming*
  a guard exists is backed by an actual guard, rather than checking the
  guard's continued existence directly.

Run against the pre-fix history, Pass 1 alone found 7 of 7 by symbol; Pass 2
alone found 7 of 7 by file; each pass is blind to what the other catches.
Together, they're what makes closing the next thunk something other than
hoping the signature staying the same means the behavior did too.

## The pattern for an architecture-specific fast path

Some functions in `lib/crypto` (hash and cipher primitives) have a shape
neither of the mechanisms above covers directly: a portable reference
implementation, plus a `static` (not exported) dispatcher that picks a
hand-written SIMD implementation at boot via a jump label, wrapped in
floating-point-register save/restore calls a Rust body has no reason to
duplicate.

Because the dispatcher is `static`, nothing outside its own C file can call
it — which means Rust can't call it either, and the C file can't be deleted
without losing the SIMD path entirely.

The resolution keeps a small C file — typically under 60 lines — that:

- keeps the `#include` of the architecture-specific SIMD header exactly as
  upstream wrote it;
- adds one new, non-exported wrapper function that gives the `static`
  dispatcher a linkable name;
- calls into Rust for the portable body and for every symbol that's actually
  exported to the rest of the kernel.

Rust ends up owning the algorithm and every public entry point; C is reduced
to the minimum needed to keep the SIMD dispatch mechanism working. Verifying
the portable Rust path is actually reachable — not dead code kept alive only
by the test corpus's specific choice of inputs — used a targeted sabotage of
the portable path and confirmed exactly one existing kernel self-test failed:
the one that specifically forces execution from a context where SIMD
registers aren't usable (hard interrupt context) and the dispatcher has to
fall back.
