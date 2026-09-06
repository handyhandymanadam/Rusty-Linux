#pragma once
/* CONFIG_PCI is not defined for this harness (see run.sh), so
 * pci_iounmap()'s #ifdef CONFIG_PCI block never compiles here and
 * `struct pci_dev` is never actually needed -- pci_iounmap() is not
 * ported and not differentially tested (drv.c's header comment).
 */
struct pci_dev;
