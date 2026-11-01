#!/usr/bin/env python3
"""e820_mutants.py RS GLUE OUTDIR RUSTC HERE ROOT : sabotage e820_rs.rs (and the glue's BUG_ON wrappers) one edit at a time;
every mutant must be CAUGHT (the differential exits non-zero) by at least one configuration."""
import subprocess, sys, os
rs_path, glue_path, out, rustc, here, root = sys.argv[1:7]
rs = open(rs_path).read(); glue = open(glue_path).read()
N = os.environ.get("MUT_N", "20000")
CONFIGS = [(12, 1), (131, 0), (5, 0)]
# (name, file 'rs'|'glue', old, new)
M = [
 # --- constants / layout
 ("type-ram", "rs", "const E820_TYPE_RAM: u32 = 1;", "const E820_TYPE_RAM: u32 = 6;"),
 ("type-acpi", "rs", "const E820_TYPE_ACPI: u32 = 3;", "const E820_TYPE_ACPI: u32 = 4;"),
 ("type-reserved", "rs", "const E820_TYPE_RESERVED: u32 = 2;", "const E820_TYPE_RESERVED: u32 = 3;"),
 ("type-pram", "rs", "const E820_TYPE_PRAM: u32 = 12;", "const E820_TYPE_PRAM: u32 = 11;"),
 ("type-soft", "rs", "const E820_TYPE_SOFT_RESERVED: u32 = 0xefff_ffff;", "const E820_TYPE_SOFT_RESERVED: u32 = 0xefff_fffe;"),
 ("einval", "rs", "const EINVAL: i32 = 22;", "const EINVAL: i32 = 21;"),
 ("page-shift", "rs", "const PAGE_SHIFT: u32 = 12;", "const PAGE_SHIFT: u32 = 13;"),
 ("lowmem", "rs", "const LOWMEMSIZE: u64 = 0x9f000;", "const LOWMEMSIZE: u64 = 0xa0000;"),
 ("highmem", "rs", "const HIGH_MEMORY: u64 = 0x100000;", "const HIGH_MEMORY: u64 = 0x100001;"),
 ("gap-end", "rs", "const MAX_GAP_END: u64 = 0x1_0000_0000;", "const MAX_GAP_END: u64 = 0xffff_ffff;"),
 ("entry-size", "rs", "const ENTRY_SIZE: usize = 20;", "const ENTRY_SIZE: usize = 19;"),
 ("bp-entries", "rs", "const BP_E820_ENTRIES: usize = 0x1e8;", "const BP_E820_ENTRIES: usize = 0x1e9;"),
 ("bp-table", "rs", "const BP_E820_TABLE: usize = 0x2d0;", "const BP_E820_TABLE: usize = 0x2d4;"),
 ("bp-alt", "rs", "const BP_ALT_MEM_K: usize = 0x1e0;", "const BP_ALT_MEM_K: usize = 0x1e4;"),
 ("bp-ext", "rs", "const BP_EXT_MEM_K: usize = 0x2;", "const BP_EXT_MEM_K: usize = 0x3;"),
 # --- queries
 ("any-end", "rs", "if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) <= start {\n                continue;\n            }\n            return true;", "if (*e).addr > end || (*e).addr.wrapping_add((*e).size) <= start {\n                continue;\n            }\n            return true;"),
 ("any-start", "rs", "if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) <= start {\n                continue;\n            }\n            return true;", "if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) < start {\n                continue;\n            }\n            return true;"),
 ("any-type", "rs", "if typ != 0 && (*e).typ != typ {\n                continue;\n            }\n            if (*e).addr >= end", "if (*e).typ != typ {\n                continue;\n            }\n            if (*e).addr >= end"),
 ("all-move", "rs", "if (*e).addr <= start {\n                start = (*e).addr.wrapping_add((*e).size);", "if (*e).addr < start {\n                start = (*e).addr.wrapping_add((*e).size);"),
 ("all-done", "rs", "if start >= end {\n                return e;", "if start > end {\n                return e;"),
 ("all-wrap", "rs", "if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) <= start {\n                continue;\n            }\n            // If the region is at", "if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) < start {\n                continue;\n            }\n            // If the region is at"),
 ("entry-type-neg", "rs", "-EINVAL\n        } else {", "EINVAL\n        } else {"),
 ("raw-uses-main", "rs", "unsafe { mapped_any(e820_table_firmware, start, end, typ) }", "unsafe { mapped_any(e820_table, start, end, typ) }"),
 # --- add
 ("add-full", "rs", "if (x as i64 as u64) >= e820_table_max_entries as u64 {", "if (x as i64 as u64) > e820_table_max_entries as u64 {"),
 ("add-msg-level", "rs", 'c"\\x013too many entries; ignoring', 'c"\\x014too many entries; ignoring'),
 ("add-msg-end", "rs", "start.wrapping_add(size).wrapping_sub(1),\n            );\n            return;", "start.wrapping_add(size),\n            );\n            return;"),
 ("add-store", "rs", "(*e).typ = typ;\n        (*table).nr_entries", "(*e).typ = typ ^ 1;\n        (*table).nr_entries"),
 ("add-nr", "rs", "(*table).nr_entries = (*table).nr_entries.wrapping_add(1);", "(*table).nr_entries = (*table).nr_entries.wrapping_add(2);"),
 # --- print
 ("print-fmt", "rs", "%#018Lx-%#018Lx] ", "%#016Lx-%#018Lx] "),
 ("print-level", "rs", 'c"\\x016%s: [mem', 'c"\\x017%s: [mem'),
 ("print-end", "rs", "(*e).addr.wrapping_add((*e).size).wrapping_sub(1),\n            );\n            print_type", "(*e).addr.wrapping_add((*e).size),\n            );\n            print_type"),
 ("ptype-usable", "rs", 'c"\\x01cusable"', 'c"\\x01cUsable"'),
 ("ptype-soft", "rs", 'c"\\x01csoft reserved"', 'c"\\x01csoft-reserved"'),
 ("ptype-nvs", "rs", 'c"\\x01cACPI NVS"', 'c"\\x01cACPI nvs"'),
 ("ptype-pers", "rs", "E820_TYPE_PMEM | E820_TYPE_PRAM =>", "E820_TYPE_PMEM =>"),
 ("ptype-unk", "rs", 'c"\\x01ctype %u"', 'c"\\x01ctype %d"'),
 ("ptype-cont", "rs", 'printk!(c"\\x01c\\n");\n            i = i.wrapping_add(1);', 'printk!(c"\\n");\n            i = i.wrapping_add(1);'),
 # --- sanitiser
 ("nomerge-pram", "rs", "typ == E820_TYPE_PRAM || typ == E820_TYPE_SOFT_RESERVED", "typ == E820_TYPE_SOFT_RESERVED"),
 ("nomerge-soft", "rs", "typ == E820_TYPE_PRAM || typ == E820_TYPE_SOFT_RESERVED", "typ == E820_TYPE_PRAM"),
 ("cp-order", "rs", "return if aa > ba { 1 } else { -1 };", "return if aa > ba { -1 } else { 1 };"),
 ("cp-tie", "rs", "((aa != (*(*ap).entry).addr) as c_int).wrapping_sub((ba != (*(*bp).entry).addr) as c_int)", "((ba != (*(*bp).entry).addr) as c_int).wrapping_sub((aa != (*(*ap).entry).addr) as c_int)"),
 ("cp-tie-zero", "rs", "((aa != (*(*ap).entry).addr) as c_int).wrapping_sub((ba != (*(*bp).entry).addr) as c_int)", "0"),
 ("wrap-check", "rs", "if (*e).addr.wrapping_add((*e).size) < (*e).addr {\n                return -1;", "if (*e).addr.wrapping_add((*e).size) <= (*e).addr {\n                return -1;"),
 ("skip-empty", "rs", "if (*e).size != 0 {\n                (**cp", "if (*e).size > 1 {\n                (**cp"),
 ("cp-end-addr", "rs", "(**cp.add(chg_idx as usize)).addr = (*e).addr.wrapping_add((*e).size);", "(**cp.add(chg_idx as usize)).addr = (*e).addr.wrapping_add((*e).size).wrapping_sub(1);"),
 ("is-start", "rs", "if (*c).addr == (*(*c).entry).addr {", "if (*c).addr != (*(*c).entry).addr {"),
 ("overlap-swap", "rs", "*ol.add(i as usize) = *ol.add(overlap_entries.wrapping_sub(1) as usize);", "*ol.add(i as usize) = *ol.add(0);"),
 ("overlap-dec", "rs", "overlap_entries = overlap_entries.wrapping_sub(1);\n            }", "overlap_entries = overlap_entries.wrapping_sub(0);\n            }"),
 ("type-max", "rs", "if (**ol.add(i as usize)).typ > current_type {", "if (**ol.add(i as usize)).typ < current_type {"),
 ("last-type", "rs", "if last_type != 0 {\n                    (*ne", "if current_type != 0 {\n                    (*ne"),
 ("merge-cond", "rs", "if current_type != last_type || nomerge(current_type) {", "if current_type != last_type {"),
 ("size-nonzero", "rs", "if (*ne.add(new_nr_entries as usize)).size != 0 {", "if (*ne.add(new_nr_entries as usize)).size > 0x1000 {"),
 ("max-break", "rs", "if new_nr_entries >= max_nr_entries {\n                            break;", "if new_nr_entries > max_nr_entries {\n                            break;"),
 ("max-break2", "rs", "if new_nr_entries >= max_nr_entries {\n                            break;", "if new_nr_entries + 1 >= max_nr_entries {\n                            break;"),
 ("new-addr", "rs", "(*ne.add(new_nr_entries as usize)).addr = (*c).addr;", "(*ne.add(new_nr_entries as usize)).addr = last_addr;"),
 ("last-addr", "rs", "last_addr = (*c).addr;\n                }", "last_addr = last_addr;\n                }"),
 ("copy-count", "rs", "(new_nr_entries as usize).wrapping_mul(ENTRY_SIZE),\n        );", "(new_nr_entries as usize).wrapping_mul(ENTRY_SIZE).wrapping_sub(ENTRY_SIZE * ((new_nr_entries > 0) as usize)),\n        );"),
 ("nr-store", "rs", "(*table).nr_entries = new_nr_entries;\n\n        0", "(*table).nr_entries = new_nr_entries.wrapping_sub((new_nr_entries > 1) as u32);\n\n        0"),
 ("sort-size", "rs", "core::mem::size_of::<*mut E820ChangeMember>(),\n            cpcompare,", "core::mem::size_of::<*mut E820ChangeMember>() / 2,\n            cpcompare,"),
 ("sort-n", "rs", "chg_nr as usize,\n            core::mem::size_of", "(chg_nr as usize).wrapping_sub(1),\n            core::mem::size_of"),
 ("update-print-ret", "rs", "if e820__update_table(e820_table) != 0 {\n            return;", "if e820__update_table(e820_table) == 0 {\n            return;"),
 ("update-print-msg", "rs", 'c"\\x016modified physical RAM map:\\n"', 'c"\\x016Modified physical RAM map:\\n"'),
 ("update-print-who", "rs", 'e820__print_table(c"modified"', 'e820__print_table(c"user"'),
 # --- append / memory_setup_default
 ("append-ovf", "rs", "if start > end && size != 0 {", "if start >= end && size != 0 {"),
 ("append-ovf2", "rs", "if start > end && size != 0 {", "if start > end {"),
 ("append-n", "rs", "if nr_entries < 2 {\n        return -1;", "if nr_entries < 1 {\n        return -1;"),
 ("append-step", "rs", "e = e.add(1);\n            n = n.wrapping_sub(1);", "e = e.add(1);\n            n = n.wrapping_sub(2);"),
 ("setup-cmp", "rs", "if alt_mem_k < ext_mem_k as u32 {", "if alt_mem_k <= ext_mem_k as u32 {"),
 ("setup-shift", "rs", "range_add(e820_table, HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);", "range_add(e820_table, HIGH_MEMORY, mem_size << 11, E820_TYPE_RAM);"),
 ("setup-low", "rs", "range_add(e820_table, 0, LOWMEMSIZE, E820_TYPE_RAM);", "range_add(e820_table, 0, LOWMEMSIZE, E820_TYPE_RESERVED);"),
 ("setup-nr0", "rs", "(*e820_table).nr_entries = 0;\n            range_add", "range_add"),
 ("setup-who88", "rs", 'c"BIOS-88"', 'c"BIOS-87"'),
 ("setup-whoe801", "rs", 'c"BIOS-e801"', 'c"BIOS-e800"'),
 ("setup-update", "rs", "// We just appended a lot of ranges, sanitize the table:\n        e820__update_table(e820_table);", "// We just appended a lot of ranges, sanitize the table:\n"),
 # --- update / remove
 ("upd-clamp", "rs", "if size > (u64::MAX - start) {\n            size = u64::MAX - start;\n        }\n\n        let end = start.wrapping_add(size);\n        printk!(c\"\\x017e820: update", "if size >= (u64::MAX - start) {\n            size = u64::MAX - start;\n        }\n\n        let end = start.wrapping_add(size);\n        printk!(c\"\\x017e820: update"),
 ("upd-msg", "rs", 'c"\\x017e820: update [mem', 'c"\\x016e820: update [mem'),
 ("upd-arrow", "rs", 'c"\\x01c ==> "', 'c"\\x01c => "'),
 ("upd-old", "rs", "if (*e).typ != old_type {\n                continue;\n            }\n\n            let entry_end = (*e).addr.wrapping_add((*e).size);\n\n            // Completely covered by new range?", "if (*e).typ == old_type {\n                continue;\n            }\n\n            let entry_end = (*e).addr.wrapping_add((*e).size);\n\n            // Completely covered by new range?"),
 ("upd-cov1", "rs", "if (*e).addr >= start && entry_end <= end {\n                (*e).typ = new_type;", "if (*e).addr > start && entry_end <= end {\n                (*e).typ = new_type;"),
 ("upd-cov2", "rs", "if (*e).addr >= start && entry_end <= end {\n                (*e).typ = new_type;", "if (*e).addr >= start && entry_end < end {\n                (*e).typ = new_type;"),
 ("upd-cov-sum", "rs", "real_updated_size = real_updated_size.wrapping_add((*e).size);\n                continue;", "continue;"),
 ("upd-inner1", "rs", "if (*e).addr < start && entry_end > end {\n                range_add(table, start, size, new_type);", "if (*e).addr <= start && entry_end > end {\n                range_add(table, start, size, new_type);"),
 ("upd-inner2", "rs", "if (*e).addr < start && entry_end > end {\n                range_add(table, start, size, new_type);", "if (*e).addr < start && entry_end >= end {\n                range_add(table, start, size, new_type);"),
 ("upd-inner-add2", "rs", "range_add(table, end, entry_end.wrapping_sub(end), (*e).typ);\n                (*e).size = start", "range_add(table, end, entry_end.wrapping_sub(end), old_type);\n                (*e).size = start"),
 ("upd-inner-size", "rs", "(*e).size = start.wrapping_sub((*e).addr);\n                real_updated_size", "(*e).size = start;\n                real_updated_size"),
 ("upd-inner-sum", "rs", "real_updated_size = real_updated_size.wrapping_add(size);\n                continue;", "real_updated_size = real_updated_size.wrapping_add(size).wrapping_add(1);\n                continue;"),
 ("upd-fs", "rs", "let final_start = if start > (*e).addr { start } else { (*e).addr };\n            let final_end = if end < entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            range_add(table", "let final_start = if start < (*e).addr { start } else { (*e).addr };\n            let final_end = if end < entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            range_add(table"),
 ("upd-fe", "rs", "let final_end = if end < entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            range_add(table", "let final_end = if end > entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            range_add(table"),
 ("upd-empty", "rs", "if final_start >= final_end {\n                continue;\n            }\n\n            range_add(table", "if final_start > final_end {\n                continue;\n            }\n\n            range_add(table"),
 ("upd-part-sum", "rs", "real_updated_size = real_updated_size.wrapping_add(final_end.wrapping_sub(final_start));\n\n            // Left", "real_updated_size = real_updated_size.wrapping_add(final_end.wrapping_sub(final_start)).wrapping_sub(1);\n\n            // Left"),
 ("upd-part-size", "rs", "(*e).size = (*e).size.wrapping_sub(final_end.wrapping_sub(final_start));\n            if (*e).addr < final_start {\n                continue;\n            }\n\n            (*e).addr = final_end;\n        }\n        real_updated_size", "(*e).size = (*e).size.wrapping_sub(final_end.wrapping_sub(final_start)).wrapping_add(1);\n            if (*e).addr < final_start {\n                continue;\n            }\n\n            (*e).addr = final_end;\n        }\n        real_updated_size"),
 ("upd-head-tail", "rs", "if (*e).addr < final_start {\n                continue;\n            }\n\n            (*e).addr = final_end;\n        }\n        real_updated_size", "if (*e).addr <= final_start {\n                continue;\n            }\n\n            (*e).addr = final_end;\n        }\n        real_updated_size"),
 ("upd-new-addr", "rs", "(*e).addr = final_end;\n        }\n        real_updated_size", "(*e).addr = final_end.wrapping_add(1);\n        }\n        real_updated_size"),
 ("upd-reread", "rs", "let mut i: u32 = 0;\n        while i < (*table).nr_entries {\n            let e = ent(table, i as usize);\n            i = i.wrapping_add(1);\n\n            if (*e).typ != old_type {", "let mut i: u32 = 0;\n        let nr0 = (*table).nr_entries;\n        while i < nr0 {\n            let e = ent(table, i as usize);\n            i = i.wrapping_add(1);\n\n            if (*e).typ != old_type {"),
 ("rem-clamp", "rs", "if size > (u64::MAX - start) {\n            size = u64::MAX - start;\n        }\n\n        let end = start.wrapping_add(size);\n        printk!(c\"\\x017e820: remove", "if size >= (u64::MAX - start) {\n            size = u64::MAX - start;\n        }\n\n        let end = start.wrapping_add(size);\n        printk!(c\"\\x017e820: remove"),
 ("rem-msg", "rs", 'c"\\x017e820: remove [mem', 'c"\\x017e820: removed [mem'),
 ("rem-print-type", "rs", "if check_type {\n            print_type(old_type);", "if !check_type {\n            print_type(old_type);"),
 ("rem-check", "rs", "if check_type && (*e).typ != old_type {", "if (*e).typ != old_type {"),
 ("rem-cov", "rs", "if (*e).addr >= start && entry_end <= end {\n                real_removed_size", "if (*e).addr > start && entry_end <= end {\n                real_removed_size"),
 ("rem-memset", "rs", "core::ptr::write_bytes(e.cast::<u8>(), 0, ENTRY_SIZE);", "core::ptr::write_bytes(e.cast::<u8>(), 0, ENTRY_SIZE - 1);"),
 ("rem-inner", "rs", "if (*e).addr < start && entry_end > end {\n                range_add(e820_table", "if (*e).addr < start && entry_end >= end {\n                range_add(e820_table"),
 ("rem-inner-type", "rs", "range_add(e820_table, end, entry_end.wrapping_sub(end), (*e).typ);\n                (*e).size = start.wrapping_sub((*e).addr);\n                real_removed_size", "range_add(e820_table, end, entry_end.wrapping_sub(end), old_type);\n                (*e).size = start.wrapping_sub((*e).addr);\n                real_removed_size"),
 ("rem-inner-sum", "rs", "real_removed_size = real_removed_size.wrapping_add(size);", "real_removed_size = real_removed_size.wrapping_add(size).wrapping_add(1);"),
 ("rem-part-sum", "rs", "real_removed_size = real_removed_size.wrapping_add(final_end.wrapping_sub(final_start));", "real_removed_size = real_removed_size.wrapping_add(final_end.wrapping_sub(final_start)).wrapping_add(1);"),
 ("rem-part-addr", "rs", "(*e).addr = final_end;\n        }\n        real_removed_size", "(*e).addr = final_start;\n        }\n        real_removed_size"),
 ("rem-fs", "rs", "let final_start = if start > (*e).addr { start } else { (*e).addr };\n            let final_end = if end < entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            real_removed_size", "let final_start = if start > (*e).addr { (*e).addr } else { start };\n            let final_end = if end < entry_end { end } else { entry_end };\n            if final_start >= final_end {\n                continue;\n            }\n\n            real_removed_size"),
 # --- the PCI gap, end pfn
 ("gap-last", "rs", "if last > end {\n                let gap", "if last >= end {\n                let gap"),
 ("gap-ge", "rs", "if gap >= *gapsize {", "if gap > *gapsize {"),
 ("gap-start", "rs", "if start < last {\n                last = start;", "if start <= last {\n                last = start.wrapping_add(0);\n            }\n            if start < last && false {\n                last = start;"),
 ("gap-last-min", "rs", "if start < last {\n                last = start;", "if start > last {\n                last = start;"),
 ("gap-size0", "rs", "let mut gapsize: u64 = 0x400000;", "let mut gapsize: u64 = 0x400001;"),
 ("gap-nf", "rs", "gapstart = (max_pfn << PAGE_SHIFT).wrapping_add(1024 * 1024);", "gapstart = (max_pfn << PAGE_SHIFT).wrapping_add(1024 * 1023);"),
 ("gap-msg1", "rs", "Cannot find an available gap in the 32-bit address range", "Cannot find an available gap in the 32-bit address space"),
 ("gap-msg2", "rs", "PCI devices with unassigned 32-bit BARs may not work!", "PCI devices with unassigned 32-bit BARs may not work"),
 ("gap-msg3", "rs", "\\x016[mem %#010lx-%#010lx] available for PCI devices", "\\x016[mem %#010lx-%#010lx] available for PCI device"),
 ("gap-pci", "rs", "pci_mem_start = gapstart;", "pci_mem_start = gapstart.wrapping_add(1);"),
 ("gap-end", "rs", "gapstart.wrapping_add(gapsize).wrapping_sub(1),\n        );", "gapstart.wrapping_add(gapsize),\n        );"),
 ("pfn-type", "rs", "if (*e).typ != E820_TYPE_RAM && (*e).typ != E820_TYPE_ACPI {", "if (*e).typ != E820_TYPE_RAM {"),
 ("pfn-start", "rs", "if start_pfn >= limit_pfn {", "if start_pfn > limit_pfn {"),
 ("pfn-end", "rs", "if end_pfn > limit_pfn {\n                last_pfn = limit_pfn;", "if end_pfn >= limit_pfn {\n                last_pfn = limit_pfn;"),
 ("pfn-break", "rs", "last_pfn = limit_pfn;\n                break;", "last_pfn = limit_pfn;"),
 ("pfn-max", "rs", "if end_pfn > last_pfn {\n                last_pfn = end_pfn;", "if end_pfn >= last_pfn + 1 && end_pfn > 5 {\n                last_pfn = end_pfn;"),
 ("pfn-arch", "rs", "if last_pfn > max_arch_pfn {", "if last_pfn >= max_arch_pfn.wrapping_add(1).wrapping_sub(2) {"),
 ("pfn-msg", "rs", "last_pfn = %#lx max_arch_pfn = %#lx", "last_pfn = %#lx max_arch_pfn = %lx"),
 # --- parsing
 ("memopt-null", "rs", "if p.is_null() {\n            return -EINVAL;\n        }\n\n        if streq(p, b\"nopentium\")", "if streq(p, b\"nopentium\")"),
 ("memopt-nopent", "rs", 'b"nopentium"', 'b"nopentiun"'),
 ("memopt-warn", "rs", "mem=nopentium ignored! (only supported on x86_32)", "mem=nopentium ignored! (only supported on x86-32)"),
 ("memopt-warn-lvl", "rs", '\\x014mem=nopentium', '\\x013mem=nopentium'),
 ("memopt-userdef", "rs", "e820_userdef = 1;\n        let mut pp", "let mut pp"),
 ("memopt-zero", "rs", "if mem_size == 0 {\n            return -EINVAL;", "if mem_size == 1 {\n            return -EINVAL;"),
 ("memopt-remove", "rs", "e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, true);\n\n        #[cfg(CONFIG_MEMORY_HOTPLUG)]", "e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, false);\n\n        #[cfg(CONFIG_MEMORY_HOTPLUG)]"),
 ("memopt-hp", "rs", "max_mem_size = mem_size;", "max_mem_size = mem_size.wrapping_add(1);"),
 ("memmap-exact", "rs", "(*e820_table).nr_entries = 0;\n                e820_userdef = 1;\n                return 0;", "e820_userdef = 1;\n                return 0;"),
 ("memmap-exact-ud", "rs", "(*e820_table).nr_entries = 0;\n                e820_userdef = 1;", "(*e820_table).nr_entries = 0;"),
 ("memmap-exact-8", "rs", "while i < 8 {\n                if *p.add(i) as u8 != lit[i]", "while i < 7 {\n                if *p.add(i) as u8 != lit[i]"),
 ("memmap-oldp", "rs", "if p == oldp {\n            return -EINVAL;", "if p != oldp {\n            return -EINVAL;"),
 ("memmap-ud", "rs", "e820_userdef = 1;\n        let c = *p as u8;", "let c = *p as u8;"),
 ("memmap-at", "rs", "if c == b'@' {\n            let start_at = memparse(p.add(1), &mut p);\n            e820__range_add(start_at, mem_size, E820_TYPE_RAM);", "if c == b'@' {\n            let start_at = memparse(p.add(1), &mut p);\n            e820__range_add(mem_size, start_at, E820_TYPE_RAM);"),
 ("memmap-hash", "rs", "E820_TYPE_ACPI);\n        } else if c == b'$'", "E820_TYPE_RESERVED);\n        } else if c == b'$'"),
 ("memmap-dollar", "rs", "E820_TYPE_RESERVED);\n        } else if c == b'!'", "E820_TYPE_ACPI);\n        } else if c == b'!'"),
 ("memmap-bang", "rs", "E820_TYPE_PRAM);\n        } else if c == b'%'", "E820_TYPE_RAM);\n        } else if c == b'%'"),
 ("memmap-from", "rs", "if *p as u8 == b'-' {\n                from = simple_strtoull(p.add(1), &mut p, 0) as u32;", "if *p as u8 == b'+' {\n                from = simple_strtoull(p.add(1), &mut p, 0) as u32;"),
 ("memmap-to", "rs", "if *p as u8 == b'+' {\n                to = simple_strtoull(p.add(1), &mut p, 0) as u32;", "if *p as u8 == b'-' {\n                to = simple_strtoull(p.add(1), &mut p, 0) as u32;"),
 ("memmap-trunc", "rs", "from = simple_strtoull(p.add(1), &mut p, 0) as u32;", "from = simple_strtoull(p.add(1), &mut p, 0) as u8 as u32;"),
 ("memmap-tail", "rs", "if *p != 0 {\n                return -EINVAL;\n            }\n            if from != 0 && to != 0", "if *p != 1 {\n                return -EINVAL;\n            }\n            if from != 0 && to != 0"),
 ("memmap-both", "rs", "if from != 0 && to != 0 {", "if from != 0 || to != 0 {"),
 ("memmap-to-add", "rs", "} else if to != 0 {\n                e820__range_add(start_at, mem_size, to);", "} else if to != 0 {\n                e820__range_add(start_at, mem_size, E820_TYPE_RAM);"),
 ("memmap-from-rem", "rs", "e820__range_remove(start_at, mem_size, from, true);", "e820__range_remove(start_at, mem_size, from, false);"),
 ("memmap-nocheck", "rs", "e820__range_remove(start_at, mem_size, 0, false);", "e820__range_remove(start_at, mem_size, 0, true);"),
 ("memmap-else", "rs", "} else {\n            e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, true);\n        }\n\n        if *p == 0", "} else {\n            e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, false);\n        }\n\n        if *p == 0"),
 ("memmap-ret", "rs", "if *p == 0 {\n            0\n        } else {\n            -EINVAL\n        }\n    }\n}\n\n#[cfg(not(kani))]\nextern", "if *p != 0 {\n            0\n        } else {\n            -EINVAL\n        }\n    }\n}\n\nextern"),
 ("opt-comma", "rs", "while *k != 0 && *k as u8 != b',' {", "while *k != 0 && *k as u8 != b';' {"),
 ("opt-cut", "rs", "*k = 0;\n                k.add(1)", "k.add(1)"),
 ("opt-next", "rs", "k.add(1)\n            } else {\n                core::ptr::null_mut()", "k.add(2)\n            } else {\n                core::ptr::null_mut()"),
 # --- glue (the BUG_ON wrappers; same file:line as upstream)
 ("glue-bug-update-line", "glue", '#line 334 "arch/x86/kernel/e820.c"', '#line 335 "arch/x86/kernel/e820.c"'),
 ("glue-bug-range-line", "glue", '#line 468 "arch/x86/kernel/e820.c"', '#line 469 "arch/x86/kernel/e820.c"'),
 ("glue-bug-range-file", "glue", '#line 468 "arch/x86/kernel/e820.c"', '#line 468 "arch/x86/kernel/e820_glue.c"'),
 ("glue-bug-cond", "glue", "BUG_ON(table->nr_entries > max_nr_entries);", "BUG_ON(table->nr_entries >= max_nr_entries);"),
 ("glue-lt2", "glue", "if (table->nr_entries < 2)\n\t\treturn -1;", "if (table->nr_entries < 3)\n\t\treturn -1;"),
 ("glue-max", "glue", "return e820_update_table_rs(table, max_nr_entries,", "return e820_update_table_rs(table, max_nr_entries - 1,"),
 ("glue-rangeupd-bug", "glue", "BUG_ON(old_type == new_type);", "BUG_ON(old_type != new_type);"),
 ("glue-maxpfn", "glue", "return e820_end_ram_pfn_rs(MAX_ARCH_PFN, MAX_ARCH_PFN);", "return e820_end_ram_pfn_rs(MAX_ARCH_PFN + 1, MAX_ARCH_PFN);"),
 ("glue-lowpfn", "glue", "return e820_end_ram_pfn_rs(1UL << (32 - PAGE_SHIFT), MAX_ARCH_PFN);", "return e820_end_ram_pfn_rs(1UL << (31 - PAGE_SHIFT), MAX_ARCH_PFN);"),
]
# mutants that are provably equivalent (the program cannot tell them apart); reported, not counted as misses
EQUIV = {
 "upd-clamp": "size == ULLONG_MAX - start: the clamp assigns the value it already has",
 "rem-clamp": "same as upd-clamp",
 "upd-inner-add2": "at that point entry->type == old_type (the entry was selected by it), so the two spellings are one value",
 "upd-reread": "entries appended by the loop carry new_type (!= old_type) or lie at/after `end`, so visiting them changes nothing",
 "gap-last": "last == end gives gap 0, which can never be >= the initial gapsize 0x400000",
 "pfn-end": "end_pfn == limit_pfn: the `>` arm sets last_pfn = limit_pfn and breaks, the fall-through sets last_pfn = end_pfn == limit_pfn and no later entry can exceed it",
 "gap-start": "start == last assigns last the value it already has",
 "memmap-ret": "parse_memmap_one()'s return value is dropped by its only caller parse_memmap_opt(); unobservable (kept faithful)",
}
only = os.environ.get("ONLY")
caught = missed = equiv = 0; notrun = []
for name, which, old, new in M:
    if only and only not in name: continue
    src = rs if which == "rs" else glue
    if src.count(old) != 1:
        print(f"mutant {name:22s} PATTERN-COUNT {src.count(old)} (fix the mutant)"); notrun.append(name); continue
    mrs = rs if which != "rs" else rs.replace(old, new, 1)
    mgl = glue if which != "glue" else glue.replace(old, new, 1)
    open(f"{out}/m.rs", "w").write(mrs); open(f"{out}/m_glue.c", "w").write(mgl)
    os.makedirs(f"{out}/mg", exist_ok=True)
    subprocess.run(["python3", f"{here}/e820_gen.py", f"{root}/port/pristine/arch/x86/kernel/e820.c", f"{out}/m_glue.c", f"{root}/port/pristine/lib/cmdline.c", f"{out}/mg"], check=True, capture_output=True, env={**os.environ, "E820_GEN_LAX": "1"})
    res = []
    for emax, hp in CONFIGS:
        exe = f"{out}/mx"
        sh = f"""set -e; cd {out}
CF="-O2 -fwrapv -fno-strict-aliasing -w -I{here}"
RENAMES=""; for n in e820_table e820_table_kexec e820_table_firmware pci_mem_start e820__mapped_raw_any e820__mapped_any e820__mapped_all e820__get_entry_type e820__range_add e820__print_table e820__update_table e820__range_update e820__range_update_table e820__range_remove e820__update_table_print e820__setup_pci_gap e820__end_of_ram_pfn e820__end_of_low_ram_pfn e820__memory_setup_default; do RENAMES="$RENAMES -D$n=c_$n"; done
cc $CF -DEMAX={emax} -DHP={hp} -DREFINC='"{out}/ref.inc"' $RENAMES -c -o {exe}.ref.o {here}/e820_ref.c
cc $CF -DEMAX={emax} -DHP={hp} -DGLUEINC='"{out}/mg/glue.inc"' -c -o {exe}.gl.o {here}/e820_gl.c
cc $CF -DEMAX={emax} -DHP={hp} -DMEMPARSE_INC='"{out}/memparse.inc"' -c -o {exe}.env.o {here}/e820_env.c
cc $CF -DEMAX={emax} -DHP={hp} -I{out}/fake -DSORTC='"{root}/port/pristine/lib/sort.c"' -c -o {exe}.sort.o {here}/e820_sort.c
sed "s|E820RS|{out}/m.rs|" {here}/e820_cmp.rs > {exe}.cmp.rs
{rustc} --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test {"--cfg CONFIG_MEMORY_HOTPLUG" if hp else ""} -C relocation-model=static -C link-arg=-no-pie -C link-arg={exe}.ref.o -C link-arg={exe}.gl.o -C link-arg={exe}.env.o -C link-arg={exe}.sort.o --crate-name e820cmp -o {exe} {exe}.cmp.rs 2>&1 | grep -E '^error' -A5 && exit 3 || true
N={N} {exe} >/dev/null 2>&1"""
        r = subprocess.run(["bash", "-c", sh], capture_output=True)
        if r.returncode == 3: res.append("COMPILE-FAIL"); break
        res.append("caught" if r.returncode else "ok")
        if r.returncode: break
    st = "CAUGHT" if "caught" in res else ("COMPILE-FAIL" if "COMPILE-FAIL" in res else "*** NOT CAUGHT")
    if st == "*** NOT CAUGHT" and name in EQUIV:
        st = "EQUIVALENT (" + EQUIV[name] + ")"; equiv += 1
    elif st == "CAUGHT": caught += 1
    else: missed += 1
    print(f"mutant {name:22s} {st}  ({','.join(res)})", flush=True)
print(f"sabotage: {caught} of {caught + missed} non-equivalent mutants caught, {equiv} proved equivalent (above), {len(notrun)} pattern problems {notrun}")
sys.exit(0 if (missed == 0 and not notrun) else 1)
