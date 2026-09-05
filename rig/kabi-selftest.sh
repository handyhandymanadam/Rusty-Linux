#!/usr/bin/env bash
# kabi-selftest.sh [build-dir]
#
# PROVE THE kabi_export! MECHANISM CAN FAIL.
#
# rust/kernel/kabi.rs makes a Rust object carry its own EXPORT_SYMBOL() entry
# and its own MODVERSIONS contract. Everything about that is silent when it
# breaks: a pin that is not read, a rule section that is not scanned, a
# --stable that was not passed. All of them leave a building, booting kernel
# whose module ABI has quietly moved.
#
# So this does not check that the mechanism works. It breaks it, six ways, and
# checks that each break is VISIBLE. A case that reports `MISSED` is a hole in
# the guard, not a failure of this script.
#
# It works on a standalone probe object rather than the kernel: same rustc,
# same macros (rust/kernel/kabi.rs is textually included), same gendwarfksyms
# binary the build uses. That keeps it a few seconds rather than a rebuild,
# and it exercises the macro source itself rather than a copy of it.
#
# The in-tree wiring -- scripts/Makefile.build calling gendwarfksyms at all --
# is NOT covered here. That is rig/crc-check.sh after a build.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:-build-fast}
G="$root/$build/scripts/gendwarfksyms/gendwarfksyms"
KABI_RS="$root/port/tree/rust/kernel/kabi.rs"
RUSTC="$HOME/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc"

[ -x "$G" ] || { echo "no gendwarfksyms at $G -- build $build first"; exit 2; }
[ -r "$KABI_RS" ] || { echo "no $KABI_RS"; exit 2; }
[ -x "$RUSTC" ] || { echo "no rustc at $RUSTC"; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kabi-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# The C spellings, exactly as lib/bcd.c produced them before it was deleted.
C_BCD2BIN='subprogram ( formal_parameter base_type unsigned char byte_size(1) encoding(8) val ) -> base_type unsigned int byte_size(4) encoding(7)'
C_BIN2BCD='subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) val ) -> base_type unsigned char byte_size(1) encoding(8)'
# What the C kernel hashes them to. Not derived here on purpose: a constant
# this script cannot recompute is a constant it cannot rationalise away.
CRC_BCD2BIN=0x605be21c
CRC_BIN2BCD=0xf664d2df

# probe <out.o> <contract-bcd2bin> <contract-bin2bcd> <rust-param-type>
#
# Two exported symbols, so that a tool reading only the first rule section
# still looks correct on one of them -- which is exactly how the real bug
# hid. <rust-param-type> is _bcd2bin's parameter type, so a case can make the
# Rust body disagree with its own contract.
probe() {
    local out=$1 c1=$2 c2=$3 ptype=$4
    {
        echo '#![no_std]'
        echo '#![crate_type = "rlib"]'
        echo '#[panic_handler]'
        echo 'fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }'
        # The real macros, not a copy of them. Its //! module docs would be
        # inner attributes in the wrong position here, so they become // .
        # $KABI_SRC is $KABI_RS except where a case deliberately breaks the macro.
        sed 's|^//!|//|' "${KABI_SRC:-$KABI_RS}"
        cat <<RS
kabi_export! { _bcd2bin, license = "", namespace = "", contract = "$c1", }
#[no_mangle]
pub extern "C" fn _bcd2bin(val: $ptype) -> u32 { val as u32 }

kabi_export! { _bin2bcd, license = "", namespace = "", contract = "$c2", }
#[no_mangle]
pub extern "C" fn _bin2bcd(val: u32) -> u8 { val as u8 }
RS
    } > "$tmp/probe.rs"
    "$RUSTC" --edition 2021 -C debuginfo=2 -C panic=abort \
        --emit=obj="$out" "$tmp/probe.rs" 2>"$tmp/rustc.err"
}

# ver <object> <symbol> [extra gendwarfksyms args...]
#
# Prints the fingerprint, or nothing. NOTHING IS NOT A FINGERPRINT: every
# caller must check, because "gendwarfksyms rejected the object" and "the
# fingerprint moved" both come back as a string that differs from the expected
# one, and only one of those is the thing being tested. An adversarial review
# on 2026-09-04 made case 1's sabotage a pin gendwarfksyms rejects outright,
# and the case reported `caught` having measured nothing.
ver() {
    local obj=$1 sym=$2; shift 2
    printf '%s\n' "$sym" | "$G" "$@" --dump-versions "$obj" 2>/dev/null \
        | sed -n "s/^#SYMVER $sym //p"
}

# moved <case> <stands-for> <got> <want> [note]
#   ok      when <got> is a real fingerprint and differs from <want>
#   MISSED  when it matches, OR when there is no fingerprint at all
moved() {
    local case=$1 stands=$2 got=$3 want=$4 note=${5:-}
    if [ -z "$got" ]; then
        verdict "$case" "$stands" MISSED \
            "gendwarfksyms produced no fingerprint -- the case did not run${note:+ ($note)}"
    elif [ "$got" != "$want" ]; then
        verdict "$case" "$stands" ok "fingerprint $got vs $want"
    else
        verdict "$case" "$stands" MISSED "fingerprint unchanged at $got"
    fi
}

# built <what>  -- the last probe/rustc call must have succeeded
built() {
    if [ "$1" -ne 0 ]; then
        echo "*** probe failed to compile ($2):"
        sed 's/^/      /' "$tmp/rustc.err" | head -5
        exit 2
    fi
}

caught=0; missed=0
verdict() { # <case> <stands-for> <ok|MISSED> <detail>
    if [ "$3" = ok ]; then
        caught=$((caught+1)); printf '%-22s %-42s caught\n' "$1" "$2"
    else
        missed=$((missed+1)); printf '%-22s %-42s *** MISSED\n' "$1" "$2"
    fi
    [ -n "${4:-}" ] && printf '      %s\n' "$4"
    return 0
}

echo "=== baseline: an honest object must reproduce the C fingerprints"
probe "$tmp/good.o" "$C_BCD2BIN" "$C_BIN2BCD" u8 || {
    echo "probe failed to compile:"; cat "$tmp/rustc.err"; exit 2; }
g1=$(ver "$tmp/good.o" _bcd2bin --stable)
g2=$(ver "$tmp/good.o" _bin2bcd --stable)
printf '    _bcd2bin %s   _bin2bcd %s\n' "$g1" "$g2"
if [ "$g1" != "$CRC_BCD2BIN" ] || [ "$g2" != "$CRC_BIN2BCD" ]; then
    echo "*** BASELINE IS ALREADY WRONG -- expected $CRC_BCD2BIN / $CRC_BIN2BCD"
    echo "*** every case below is meaningless until that is fixed"
    exit 1
fi
nsec=$(readelf -SW "$tmp/good.o" | grep -c 'gendwarfksyms\.kabi_rules')
printf '    %s rule section(s) in the object\n' "$nsec"
[ "$nsec" -ge 2 ] || echo "    NOTE: fewer than 2 -- the multi-section case below proves nothing"
echo

echo "CASE                   STANDS FOR                                 VERDICT"

# 1. The contract is wrong. The single most likely human error: a pin edited
#    to make something pass.
probe "$tmp/c1.o" "${C_BCD2BIN/unsigned char/unsigned short}" "$C_BIN2BCD" u8
built $? "case 1"
moved wrong-contract "a pin edited to say something else" \
    "$(ver "$tmp/c1.o" _bcd2bin --stable)" "$CRC_BCD2BIN"

# 2. --stable not passed: KBUILD_GENDWARFKSYMS_STABLE forgotten. Builds fine,
#    boots fine, module ABI moves.
moved no-stable-flag "KBUILD_GENDWARFKSYMS_STABLE forgotten" \
    "$(ver "$tmp/good.o" _bcd2bin)" "$CRC_BCD2BIN"

# 3. No contract at all -- the symbol exported straight from Rust DWARF. This
#    is what every thunk-free port would silently do without kabi_export!.
{
    echo '#![no_std]'; echo '#![crate_type = "rlib"]'
    echo '#[panic_handler]'; echo 'fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }'
    echo '#[no_mangle] pub extern "C" fn _bcd2bin(val: u8) -> u32 { val as u32 }'
} > "$tmp/bare.rs"
"$RUSTC" --edition 2021 -C debuginfo=2 -C panic=abort \
    --emit=obj="$tmp/bare.o" "$tmp/bare.rs" 2>"$tmp/rustc.err"
built $? "case 3"
moved no-contract "Rust exported with no pin at all" \
    "$(ver "$tmp/bare.o" _bcd2bin --stable)" "$CRC_BCD2BIN"

# 4. Only the FIRST rule section is read. This IS the upstream bug fixed in
#    scripts/gendwarfksyms/kabi.c, reproduced rather than described: a copy of
#    the tool is built with the loop stopping after one section, exactly as
#    kabi_read_rules() did before, and asked the same question.
#
#    An earlier version of this case tried to strip the sections with
#    llvm-objcopy instead. objcopy REFUSED (the DWARF relocates against the
#    rule statics), the output file was never created, and the empty result
#    compared unequal to the expected fingerprint -- so the case "passed"
#    having run nothing. Hence the emptiness assertions below.
src=$root/port/tree/scripts/gendwarfksyms
if [ -d "$src" ] && [ -d "$root/src/linux/scripts/gendwarfksyms" ]; then
    mkdir -p "$tmp/gdk"
    cp "$root"/src/linux/scripts/gendwarfksyms/*.c "$root"/src/linux/scripts/gendwarfksyms/*.h "$tmp/gdk/" 2>/dev/null
    # Put back the one-section-only behaviour, and nothing else.
    perl -0pi -e 's/(kabi_parse_rules\(rule_data->d_buf, shdr->sh_size\);\n\t\tfound\+\+;)/$1\n\t\tbreak;/' "$tmp/gdk/kabi.c"
    if grep -q 'found++;$' "$tmp/gdk/kabi.c" && grep -A1 'found++;' "$tmp/gdk/kabi.c" | grep -q 'break;'; then
        if cc -o "$tmp/gdk/gdk" "$tmp"/gdk/*.c -I"$tmp/gdk" -I"$root/src/linux/scripts/include" \
                -ldw -lelf -lz 2>"$tmp/gdk.err"; then
            a=$(printf '_bcd2bin\n' | "$tmp/gdk/gdk" --stable --dump-versions "$tmp/good.o" 2>/dev/null | sed -n 's/^#SYMVER _bcd2bin //p')
            b=$(printf '_bin2bcd\n' | "$tmp/gdk/gdk" --stable --dump-versions "$tmp/good.o" 2>/dev/null | sed -n 's/^#SYMVER _bin2bcd //p')
            if [ -z "$a" ] || [ -z "$b" ]; then
                verdict rules-not-read "only the first rule section consulted" MISSED \
                    "the one-section build produced no fingerprint at all -- case did not run"
            elif [ "$a" = "$CRC_BCD2BIN" ] && [ "$b" = "$CRC_BIN2BCD" ]; then
                verdict rules-not-read "only the first rule section consulted" MISSED \
                    "both still correct ($a $b) -- reading one section was enough, so this object does not test it"
            else
                verdict rules-not-read "only the first rule section consulted" ok \
                    "one pin silently lost: _bcd2bin $a _bin2bcd $b (want $CRC_BCD2BIN $CRC_BIN2BCD)"
            fi
        else
            verdict rules-not-read "only the first rule section consulted" MISSED \
                "could not build the one-section variant: $(head -1 "$tmp/gdk.err")"
        fi
    else
        verdict rules-not-read "only the first rule section consulted" MISSED \
            "could not inject the one-section behaviour -- kabi.c no longer has the expected shape"
    fi
else
    verdict rules-not-read "only the first rule section consulted" MISSED \
        "no gendwarfksyms source to build a variant from"
fi

# 5. The export entry PAIRING, not its dimensions.
#
#    An earlier version of this case asserted the section size, the label
#    count and the reloc count. An adversarial review pointed the entry at the
#    wrong function -- a one-line edit to kabi.rs, `.quad $sym` -> `.quad
#    _bin2bcd` -- and all three numbers were unchanged, so the case reported
#    `caught` while a genuine break walked past it. Renaming the label
#    (__export_symbol_x__bcd2bin) passed too.
#
#    What actually matters is what modpost checks: the label
#    __export_symbol_<name> must sit at the head of an entry whose pointer
#    relocates to <name>. So that is what is asserted -- the label suffixes and
#    the relocation targets must be the same set, and paired at the right
#    offsets.
pairing() { # <object> -> prints "ok" or the reason it is not
    local obj=$1 out="" lbl off sym roff rsym
    # label offset -> suffix
    while read -r off _t name; do
        case "$name" in __export_symbol_*) ;; *) continue;; esac
        lbl=${name#__export_symbol_}
        # the pointer sits 8 bytes into the 16-byte entry
        roff=$(printf '%016x' $(( 0x$off + 8 )))
        rsym=$(readelf -rW "$obj" |
               awk -v want="$roff" '
                   /^Relocation section .\.rela\.export_symbol/ {f=1; next}
                   /^Relocation section/ {f=0}
                   f && $1 == want { print $5 }')
        [ "$rsym" = "$lbl" ] || out="$out ${name}->${rsym:-<none>}"
    done < <(nm "$obj" | grep ' __export_symbol_')
    # and no relocation may point somewhere no label claims
    while read -r rsym; do
        nm "$obj" | grep -q " __export_symbol_$rsym\$" ||
            out="$out reloc-to-${rsym}-with-no-label"
    done < <(readelf -rW "$obj" |
             awk '/^Relocation section .\.rela\.export_symbol/ {f=1; next}
                  /^Relocation section/ {f=0}
                  f && /R_X86_64_64/ { print $5 }')
    [ -z "$out" ] && echo ok || echo "$out"
}

p5=$(pairing "$tmp/good.o")
nlbl=$(nm "$tmp/good.o" | grep -c ' __export_symbol_')
if [ "$p5" = ok ] && [ "$nlbl" -eq 2 ]; then r=ok; else r=MISSED; fi
verdict export-entry-sound "an honest object pairs label to pointer" $r \
    "$nlbl labels (want 2), pairing: $p5"

# 5b. The same assertion against the break that beat the old case: the export
#     entry pointing at a different function than its label names.
mkdir -p "$tmp/sab"
sed 's|::core::concat!(".quad ", ::core::stringify!($sym)),|::core::concat!(".quad _bin2bcd"),|' \
    "$KABI_RS" > "$tmp/sab/kabi.rs"
if ! cmp -s "$KABI_RS" "$tmp/sab/kabi.rs"; then
    KABI_SRC="$tmp/sab/kabi.rs" probe "$tmp/c5.o" "$C_BCD2BIN" "$C_BIN2BCD" u8
    rc=$?
    if [ "$rc" -ne 0 ]; then
        verdict export-points-elsewhere "the entry names one symbol, points at another" \
            MISSED "sabotaged probe did not compile -- case did not run"
    else
        p5b=$(pairing "$tmp/c5.o")
        [ "$p5b" != ok ] && r=ok || r=MISSED
        verdict export-points-elsewhere "the entry names one symbol, points at another" $r \
            "pairing: $p5b"
    fi
else
    verdict export-points-elsewhere "the entry names one symbol, points at another" \
        MISSED "could not sabotage the .quad line -- kabi.rs no longer has the expected shape"
fi

# 6. THE ONE THE FINGERPRINT CANNOT CATCH, stated so nobody assumes otherwise.
#    A pin is an override: change the Rust signature and leave the contract
#    alone, and the fingerprint does not move. What DOES move is the unpinned
#    string, and comparing the two is the check that has to exist.
probe "$tmp/c6.o" "$C_BCD2BIN" "$C_BIN2BCD" u64
built $? "case 6"
pinned=$(ver "$tmp/c6.o" _bcd2bin --stable)
live=$(ver "$tmp/c6.o" _bcd2bin)
livegood=$(ver "$tmp/good.o" _bcd2bin)
if [ "$pinned" = "$CRC_BCD2BIN" ] && [ "$live" != "$livegood" ]; then r=ok; else r=MISSED; fi
verdict drift-behind-pin "Rust body drifts, contract unchanged" $r \
    "fingerprint still $pinned -- only the UNPINNED string moved ($livegood -> $live)"

echo
printf '%d caught, %d MISSED\n' "$caught" "$missed"
[ "$missed" -eq 0 ] || echo '*** a break in the kABI contract mechanism is not visible'
exit "$missed"
