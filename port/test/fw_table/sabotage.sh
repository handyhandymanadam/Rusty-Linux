#!/usr/bin/env bash
# port/test/fw_table/sabotage.sh -- a SMOKE TEST ON THE HARNESS.
#
# READ logs/floor.md RULE T2 BEFORE QUOTING ANY NUMBER THIS PRINTS. The score
# is not a stopping rule and must not be cited as one. Absolute mutation
# scores are not interpretable (Just et al., FSE 2014, §2.5), the largest
# fault class mutation cannot represent is "the fix was to re-implement the
# algorithm" -- which is what a C-to-Rust port IS -- and a hand-picked list is
# not a systematic operator set. The only question this answers is: CAN THIS
# HARNESS SEE ANYTHING AT ALL?
#
# A COMPILE ERROR IS NOT A CATCH. A SEGFAULT and a TIMEOUT are weaker catches
# than a reported mismatch: they say the port broke without saying the
# comparison could see the difference. All three are labelled, because a
# suite that reports one number cannot tell you which kind of evidence it
# has. The timeout is real evidence of one specific thing -- removing the
# zero-length guard makes the walk advance by nothing and loop forever, which
# is exactly what that guard is in the C for.
#
# `--both` applies the same slip to the pristine C AND the Rust, leaving the
# arms in agreement, so only the guard-page stage -- which is not a
# comparison -- can notice. That is the demonstration that this harness is
# more than two parsers comparing notes.
#
# WHAT CANNOT BE SABOTAGED HERE, and it is worth knowing which way the gap
# runs: the byte-order conversions. `u16::from_le`/`u32::from_le` are the
# identity on this host, so removing one changes nothing any arm can see.
# That is a property of running little-endian, not a gap in the corpus --
# logs/floor.md RAISE 5 is the answer to it and this harness has not had one.
set -uo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/fw_table"
RS="$root/port/tree/lib/fw_table_rs.rs"
work="${TMPDIR:-/tmp}/fw_table-sabotage.$$"
mkdir -p "$work"; trap 'rm -rf "$work"' EXIT

both=0
[ "${1:-}" = "--both" ] && both=1

caught=0; missed=0; compile=0; n=0

# What noticed, strongest first. `grep -oE` takes the leftmost match in a
# line rather than the first alternative, so the patterns are tried in
# separate passes -- one alternation would report the guard page's own
# catches as ordinary mismatches.
verdict() {
    local log=$1 rc=$2 w
    if [ "$rc" = 124 ]; then
        echo "TIMEOUT (the walk hangs)"; return
    fi
    if grep -q 'Segmentation fault\|core dumped' "$log"; then
        echo "SIGSEGV / guard page"; return
    fi
    w=$(grep -m1 -oE 'GEOMETRY: [^:]+' "$log")
    [ -n "$w" ] || w=$(grep -m1 -oE 'MISMATCH: [a-z/-]+' "$log")
    echo "${w:-?}"
}

run_slip() {
    local name=$1 expr=$2 predict=$3
    local copy="$work/mutant.rs" log="$work/log"

    n=$((n + 1))
    cp "$RS" "$copy"
    sed -i "$expr" "$copy"
    if cmp -s "$RS" "$copy"; then
        printf '%2d  %-40s *** SED MATCHED NOTHING -- not applied\n' "$n" "$name"
        missed=$((missed + 1)); return
    fi

    timeout 300 env FW_TABLE_RS="$copy" "$here/run.sh" > "$log" 2>&1
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        printf '%2d  %-40s NOT CAUGHT   (expected: %s)\n' "$n" "$name" "$predict"
        missed=$((missed + 1)); return
    fi
    if grep -qE '^error(\[|:)|aborting due to' "$log"; then
        printf '%2d  %-40s COMPILE ERROR -- not a catch\n' "$n" "$name"
        compile=$((compile + 1)); missed=$((missed + 1)); return
    fi
    printf '%2d  %-40s caught by %-26s (predicted %s)\n' \
        "$n" "$name" "$(verdict "$log" "$rc")" "$predict"
    caught=$((caught + 1))
}

echo "sabotage suite for lib/fw_table.c -- a smoke test on the harness,"
echo "NOT a stopping rule. See logs/floor.md RULE T2."
echo

# --- signature dispatch -----------------------------------------------------
run_slip "sig: compares three bytes, not four" \
    's|for (i, &want) in sig.iter().enumerate() {|for (i, \&want) in sig.iter().take(3).enumerate() {|' \
    "return / handler calls"
run_slip "sig: CDAT falls through to COMMON" \
    's|^        if sig_matches(id, b"CDAT") {$|        if false {|' \
    "return / handler calls"
run_slip "sig: HMAT is matched as HMAP" \
    's|if sig_matches(id, b"HMAT") {|if sig_matches(id, b"HMAP") {|' \
    "return / handler calls"

# --- where each family keeps its type --------------------------------------
run_slip "type: HMAT read as u8, not u16" \
    's|ptr::read_unaligned(ptr::addr_of!((\*h).hmat.r#type)) as usize|ptr::read_unaligned(ptr::addr_of!((*h).hmat.r#type)) as u8 as usize|' \
    "handler calls"
run_slip "type: PRMT reports its revision" \
    's|^            SubtableType::Prmt => 0,$|            SubtableType::Prmt => ptr::read_unaligned(ptr::addr_of!((*h).prmt.revision)) as usize,|' \
    "handler calls"
run_slip "type: CEDT read from offset 1" \
    's|ptr::read_unaligned(ptr::addr_of!((\*h).cedt.r#type)) as usize|ptr::read_unaligned(ptr::addr_of!((*h).cedt.reserved)) as usize|' \
    "handler calls"

# --- where each family keeps its length ------------------------------------
run_slip "len: COMMON length read as the type" \
    's|ptr::read_unaligned(ptr::addr_of!((\*h).common.length)) as usize|ptr::read_unaligned(ptr::addr_of!((*h).common.r#type)) as usize|' \
    "handler calls"
run_slip "len: HMAT length read as u16" \
    's|ptr::read_unaligned(ptr::addr_of!((\*h).hmat.length)) as usize|(ptr::read_unaligned(ptr::addr_of!((*h).hmat.length)) as u16) as usize|' \
    "handler calls"
run_slip "len: PRMT length off by one" \
    's|ptr::read_unaligned(ptr::addr_of!((\*h).prmt.length)) as usize|ptr::read_unaligned(ptr::addr_of!((*h).prmt.length)) as usize + 1|' \
    "handler calls"
run_slip "len: CDAT length read as CEDT's" \
    's|u16::from_le(ptr::read_unaligned(ptr::addr_of!((\*h).cdat.length))) as usize|ptr::read_unaligned(ptr::addr_of!((*h).cdat.reserved)) as usize|' \
    "handler calls"

# --- header sizes and the root length --------------------------------------
run_slip "hdrsz: HMAT header is 4, not 8" \
    's|SubtableType::Hmat => core::mem::size_of::<AcpiHmatStructure>(),|SubtableType::Hmat => 4,|' \
    "return / handler calls"
run_slip "hdrsz: COMMON header is 4, not 2" \
    's|SubtableType::Common => core::mem::size_of::<AcpiSubtableHeader>(),|SubtableType::Common => 4,|' \
    "return / handler calls"
run_slip "root: the CDAT/ACPI length test is inverted" \
    's|^        if ty == SubtableType::Cdat {$|        if ty != SubtableType::Cdat {|' \
    "return / handler calls"

# --- the walk ---------------------------------------------------------------
run_slip "walk: loop guard is <=, not <" \
    's|while (entry.hdr as usize).wrapping_add(subtable_len) < table_end {|while (entry.hdr as usize).wrapping_add(subtable_len) <= table_end {|' \
    "handler calls / guard page"
run_slip "walk: advances by the header size, not the entry" \
    's|entry.hdr =\n|XX|; s|(entry.hdr as usize).wrapping_add(entry_len) as \*mut AcpiSubtableHeaders|(entry.hdr as usize).wrapping_add(subtable_len) as *mut AcpiSubtableHeaders|' \
    "handler calls"
run_slip "walk: first entry is at the table start" \
    's|hdr: (table_header as usize).wrapping_add(table_size) as \*mut AcpiSubtableHeaders,|hdr: { let _ = table_size; table_header as *mut AcpiSubtableHeaders },|' \
    "handler calls"
run_slip "walk: max_length never truncates" \
    's|^        if max_length != 0 \&\& max_length < table_len {$|        if false {|' \
    "return / handler calls"
# The zero-length guard exists in the C to stop an infinite loop, so removing
# it produces one rather than a wrong answer. Predicted, and labelled, as the
# hang it is.
run_slip "walk: zero-length guard tests 1, not 0" \
    's|^            if entry_len == 0 {$|            if entry_len == 1 {|' \
    "TIMEOUT"

# --- counting and the handler contract -------------------------------------
run_slip "count: no break, so one entry matches many procs" \
    's|^                break;$|                continue;|' \
    "proc\[i\].count"
run_slip "count: max_entries==0 no longer means unlimited" \
    's|if max_entries == 0 \|\| (count as c_uint) < max_entries {|if (count as c_uint) < max_entries {|' \
    "handler calls"
run_slip "count: the < max_entries test is <=" \
    's|if max_entries == 0 \|\| (count as c_uint) < max_entries {|if max_entries == 0 \|\| (count as c_uint) <= max_entries {|' \
    "handler calls"
# The two UNSIGNED comparisons, which had no slip at all until adversarial
# review demonstrated that the corpus could not reach them: max_entries never
# exceeded 5, and below 2^31 a signed and an unsigned comparison give the
# same answer for every count. drv.c's directed/max-entries-big shapes close
# it. This is NOT the same shape as the sign-extension note below -- nothing
# bounds a caller's max_entries, so this one is reachable.
run_slip "count: max_entries compared as signed (<)" \
    's|if max_entries == 0 \|\| (count as c_uint) < max_entries {|if max_entries == 0 \|\| count < max_entries as c_int {|' \
    "directed/max-entries-big"
run_slip "count: max_entries compared as signed (>)" \
    's|if max_entries != 0 \&\& (count as c_uint) > max_entries {|if max_entries != 0 \&\& count > max_entries as c_int {|' \
    "directed/max-entries-big"
run_slip "count: the warn test is >=, not >" \
    's|if max_entries != 0 \&\& (count as c_uint) > max_entries {|if max_entries != 0 \&\& (count as c_uint) >= max_entries {|' \
    "diagnostic text"
run_slip "count: proc[i].count not incremented" \
    's|(\*p).count = (\*p).count.wrapping_add(1);|let _ = \&(*p).count;|' \
    "proc\[i\].count"
# NO SLIP FOR THE SIGN-EXTENSION, and that is a property of the code rather
# than a gap in this corpus. `acpi_get_entry_type()` returns a value read from
# a u8 or u16 field, so it is at most 65535. A negative `proc[i].id`
# sign-extends to at least 2^63 and zero-extends to at least 2^31; NEITHER can
# ever equal an entry type. No input distinguishes the two conversions, so a
# slip for it would sit here permanently uncaught while saying nothing about
# the harness. Same shape as inftrees.c:290-293 in logs/hooks.md: recorded
# with its reasoning so nobody adds it back. The port still spells the
# conversion the C's way, because it is real -- not because it is observable.

# --- call_handler -----------------------------------------------------------
run_slip "call: handler_arg is preferred to handler" \
    's|^        if let Some(h) = (\*proc_entry).handler {$|        if let Some(h) = (*proc_entry).handler_arg { return h(hdr, (*proc_entry).arg, end); }\n        if let Some(h) = (*proc_entry).handler {|' \
    "handler calls"
run_slip "call: no handler at all succeeds" \
    's|^        -EINVAL\n|XX|; /fn call_handler/,/^}/ s|^        -EINVAL$|        0|' \
    "return"
run_slip "call: a SUCCEEDING handler aborts the walk" \
    's|if call_handler(p, entry.hdr, table_end) != 0 {|if call_handler(p, entry.hdr, table_end) == 0 {|' \
    "return"

# --- the diagnostics --------------------------------------------------------
run_slip "diag: pr_err prints three signature bytes, not four" \
    's|3\[%4.4s:0x%02x\] Invalid zero length|3[%3.3s:0x%02x] Invalid zero length|' \
    "diagnostic text"
run_slip "diag: pr_warn reports count, not the excess" \
    's|count.wrapping_sub(max_entries as c_int),|count,|' \
    "diagnostic text"
run_slip "diag: the error level byte says warning" \
    's|u{1}3\[%4.4s:0x%02x\] Invalid zero length|u{1}4[%4.4s:0x%02x] Invalid zero length|' \
    "diagnostic text"

# --- cdat_table_parse -------------------------------------------------------
run_slip "cdat: root header size is the union's, not CDAT's" \
    's|core::mem::size_of::<AcpiTableCdat>(),|core::mem::size_of::<FwTableHeader>(),|' \
    "return / handler calls"
run_slip "cdat: the NULL check is dropped" \
    's|^        if table_header.is_null() {$|        if false {|' \
    "SIGSEGV"
run_slip "cdat: proc.id is not the requested type" \
    's|^            id: ty as c_int,$|            id: { let _ = ty; 0 },|' \
    "handler calls"

# ---------------------------------------------------------------------------
# --both: the same slip in BOTH arms. Only the guard page can then see it.
# ---------------------------------------------------------------------------
run_both() {
    local name=$1 rsexpr=$2 cexpr=$3 expect=$4
    local rscopy="$work/mutant.rs" log="$work/log"
    local cdir="$work/c"

    n=$((n + 1))
    rm -rf "$cdir"; mkdir -p "$cdir"
    cp "$root/port/pristine/lib/fw_table.c" "$cdir/fw_table.c"
    cp "$RS" "$rscopy"
    cp "$cdir/fw_table.c" "$work/corig"

    sed -i "$rsexpr" "$rscopy"
    sed -i "$cexpr" "$cdir/fw_table.c"

    if cmp -s "$RS" "$rscopy"; then
        printf '%2d  %-40s *** RUST SED MATCHED NOTHING\n' "$n" "$name"
        missed=$((missed + 1)); return
    fi
    if cmp -s "$work/corig" "$cdir/fw_table.c"; then
        printf '%2d  %-40s *** C SED MATCHED NOTHING -- arms not both wrong\n' \
            "$n" "$name"
        missed=$((missed + 1)); return
    fi

    timeout 300 env FW_TABLE_RS="$rscopy" FW_TABLE_C="$cdir/fw_table.c" \
        "$here/run.sh" > "$log" 2>&1
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        printf '%2d  %-40s NOT CAUGHT   (only %s could have)\n' \
            "$n" "$name" "$expect"
        missed=$((missed + 1)); return
    fi
    if grep -qE '^error(\[|:)|aborting due to' "$log"; then
        printf '%2d  %-40s COMPILE ERROR -- not a catch\n' "$n" "$name"
        compile=$((compile + 1)); missed=$((missed + 1)); return
    fi
    printf '%2d  %-40s caught by %-26s (%s)\n' \
        "$n" "$name" "$(verdict "$log" "$rc")" "$expect"
    caught=$((caught + 1))
}

if [ "$both" = 1 ]; then
    echo
    echo "--both: the SAME slip in the C and the Rust. The arms agree, so only"
    echo "the guard page -- which is not a comparison -- can see anything."
    echo

    # Drop `subtable_len` from the loop guard in both arms. The walk then
    # reads a subtable header that begins inside the table and ends past
    # table_end. Both arms read the same bytes and agree perfectly; the only
    # thing that can notice is the page after the last one.
    run_both "both: loop guard ignores the header size" \
        's|while (entry.hdr as usize).wrapping_add(subtable_len) < table_end {|while { let _ = subtable_len; (entry.hdr as usize) < table_end } {|' \
        's|while (((unsigned long)entry.hdr) + subtable_len < table_end) {|while (((unsigned long)entry.hdr) < table_end) {|' \
        "the guard-page stage"
fi

echo
echo "slips $n   caught $caught   missed $missed   (of the missed, $compile were compile errors)"
[ "$missed" -eq 0 ]
