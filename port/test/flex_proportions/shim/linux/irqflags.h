#pragma once
/* Real arch_local_irq_save/restore execute cli/sti -- privileged
 * instructions that fault immediately in userspace. Shimmed as no-ops
 * here, exactly like raw_spin_lock_irqsave's shim: what this harness
 * tests is fprop_new_period()'s own arithmetic and control flow (via
 * fprop_new_period_locked() on the Rust side, since the REAL, shipped
 * fprop_new_period() cannot be called in userspace at all -- see
 * flex_proportions_rs.rs's own doc comment on that split), not whether
 * cli/sti execute -- that's arch/x86/include/asm/irqflags.h, unchanged,
 * and reachability is verified for real in ring 0 by sabotage-and-reboot
 * instead. */
#define local_irq_save(flags) do { (flags) = 0; } while (0)
#define local_irq_restore(flags) do { (void)(flags); } while (0)
