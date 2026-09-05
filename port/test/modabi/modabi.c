// SPDX-License-Identifier: GPL-2.0
/*
 * modabi.ko -- an out-of-tree module that IMPORTS symbols Rust defines and
 * exports, so that "the fingerprint is unchanged" becomes "a module built
 * against that fingerprint loads and the symbol works".
 *
 * _bcd2bin and _bin2bcd have no C definition anywhere in the tree. Their
 * bodies, their EXPORT_SYMBOL() entries and their MODVERSIONS contracts all
 * come from lib/bcd_rs.rs via kernel::kabi_export!(). If the export entry
 * were malformed, this would not link; if the fingerprint were missing or
 * wrong, insmod would refuse with "no symbol version" or "disagrees about
 * version of symbol".
 */
#include <linux/bcd.h>
#include <linux/init.h>
#include <linux/module.h>

static int __init modabi_init(void)
{
	unsigned int bad = 0;
	unsigned int i;

	/* Round-trip every value the C promises: 0..99. */
	for (i = 0; i <= 99; i++) {
		unsigned char packed = _bin2bcd(i);

		if (_bcd2bin(packed) != i)
			bad++;
	}

	pr_info("MODTEST modabi: bcd round-trip %u/%u ok, %u bad\n",
		100 - bad, 100u, bad);
	pr_info("MODTEST modabi: _bin2bcd(42)=0x%02x _bcd2bin(0x42)=%u\n",
		_bin2bcd(42), _bcd2bin(0x42));
	pr_info("MODTEST modabi: %s\n", bad ? "FAIL" : "PASS");
	return 0;
}

static void __exit modabi_exit(void) { }

module_init(modabi_init);
module_exit(modabi_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Imports Rust-exported _bcd2bin/_bin2bcd to prove the kABI contract");
