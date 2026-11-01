# SPDX-License-Identifier: GPL-2.0
#
# Makefile for native language support
#

obj-$(CONFIG_NLS)		+= nls_base.o
# nls_base.o is a composite when CONFIG_RUST: nls_base_glue.o keeps the registry
# (spinlock, table list, module refcounts); nls_base_rs.o is the four UTF
# conversion functions and their exports. CONFIG_RUST=n builds upstream,
# installed byte-identical as nls_base_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
nls_base-y			:= nls_base_glue.o nls_base_rs.o
else
nls_base-y			:= nls_base_norust.o
endif

obj-$(CONFIG_NLS_CODEPAGE_437)	+= nls_cp437.o
# nls_cp437.o is a composite when CONFIG_RUST, like nls_ascii below:
# nls_cp437_glue.o (module_init/exit, MODULE_*, register_nls()) + nls_cp437_rs.o
# (tables, uni2char/char2uni, struct nls_table). CONFIG_RUST=n builds upstream's
# body, installed as nls_cp437_norust.c by rig/apply.sh from port/pristine/.
ifdef CONFIG_RUST
nls_cp437-y			:= nls_cp437_glue.o nls_cp437_rs.o
else
nls_cp437-y			:= nls_cp437_norust.o
endif
obj-$(CONFIG_NLS_CODEPAGE_737)	+= nls_cp737.o
obj-$(CONFIG_NLS_CODEPAGE_775)	+= nls_cp775.o
obj-$(CONFIG_NLS_CODEPAGE_850)	+= nls_cp850.o
obj-$(CONFIG_NLS_CODEPAGE_852)	+= nls_cp852.o
obj-$(CONFIG_NLS_CODEPAGE_855)	+= nls_cp855.o
obj-$(CONFIG_NLS_CODEPAGE_857)	+= nls_cp857.o
obj-$(CONFIG_NLS_CODEPAGE_860)	+= nls_cp860.o
obj-$(CONFIG_NLS_CODEPAGE_861)	+= nls_cp861.o
obj-$(CONFIG_NLS_CODEPAGE_862)	+= nls_cp862.o
obj-$(CONFIG_NLS_CODEPAGE_863)	+= nls_cp863.o
obj-$(CONFIG_NLS_CODEPAGE_864)	+= nls_cp864.o
obj-$(CONFIG_NLS_CODEPAGE_865)	+= nls_cp865.o
obj-$(CONFIG_NLS_CODEPAGE_866)	+= nls_cp866.o
obj-$(CONFIG_NLS_CODEPAGE_869)	+= nls_cp869.o
obj-$(CONFIG_NLS_CODEPAGE_874)	+= nls_cp874.o
obj-$(CONFIG_NLS_CODEPAGE_932)	+= nls_cp932.o nls_euc-jp.o
obj-$(CONFIG_NLS_CODEPAGE_936)	+= nls_cp936.o
obj-$(CONFIG_NLS_CODEPAGE_949)	+= nls_cp949.o
obj-$(CONFIG_NLS_CODEPAGE_950)	+= nls_cp950.o
obj-$(CONFIG_NLS_CODEPAGE_1250) += nls_cp1250.o
obj-$(CONFIG_NLS_CODEPAGE_1251)	+= nls_cp1251.o
obj-$(CONFIG_NLS_ASCII)		+= nls_ascii.o
# nls_ascii.o is a composite when CONFIG_RUST (same shape as nls_utf8 below):
# nls_ascii_glue.o keeps module_init/exit, MODULE_* and register_nls();
# nls_ascii_rs.o holds the tables, uni2char/char2uni and the struct nls_table.
# CONFIG_RUST=n builds upstream's body, installed byte-identical as
# nls_ascii_norust.c by rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2).
ifdef CONFIG_RUST
nls_ascii-y			:= nls_ascii_glue.o nls_ascii_rs.o
else
nls_ascii-y			:= nls_ascii_norust.o
endif
obj-$(CONFIG_NLS_ISO8859_1)	+= nls_iso8859-1.o
# nls_iso8859-1.o is a composite when CONFIG_RUST, like nls_ascii above. The Rust
# and glue files use '_' (a crate name cannot contain '-'); upstream's body is
# installed as nls_iso8859-1_norust.c for CONFIG_RUST=n.
ifdef CONFIG_RUST
nls_iso8859-1-y			:= nls_iso8859_1_glue.o nls_iso8859_1_rs.o
else
nls_iso8859-1-y			:= nls_iso8859-1_norust.o
endif
obj-$(CONFIG_NLS_ISO8859_2)	+= nls_iso8859-2.o
obj-$(CONFIG_NLS_ISO8859_3)	+= nls_iso8859-3.o
obj-$(CONFIG_NLS_ISO8859_4)	+= nls_iso8859-4.o
obj-$(CONFIG_NLS_ISO8859_5)	+= nls_iso8859-5.o
obj-$(CONFIG_NLS_ISO8859_6)	+= nls_iso8859-6.o
obj-$(CONFIG_NLS_ISO8859_7)	+= nls_iso8859-7.o
obj-$(CONFIG_NLS_ISO8859_8)	+= nls_cp1255.o
obj-$(CONFIG_NLS_ISO8859_9)	+= nls_iso8859-9.o
obj-$(CONFIG_NLS_ISO8859_13)	+= nls_iso8859-13.o
obj-$(CONFIG_NLS_ISO8859_14)	+= nls_iso8859-14.o
obj-$(CONFIG_NLS_ISO8859_15)	+= nls_iso8859-15.o
obj-$(CONFIG_NLS_KOI8_R)	+= nls_koi8-r.o
obj-$(CONFIG_NLS_KOI8_U)	+= nls_koi8-u.o nls_koi8-ru.o
obj-$(CONFIG_NLS_UTF8)		+= nls_utf8.o
# nls_utf8.o is a composite when CONFIG_RUST: nls_utf8_glue.o keeps only what a
# Rust body cannot express (module_init/exit, MODULE_*, and the register_nls()
# macro, which names THIS_MODULE), nls_utf8_rs.o holds uni2char/char2uni, the
# identity table and the struct nls_table itself. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as nls_utf8_norust.c by
# rig/apply.sh from port/pristine/ (logs/floor.md RAISE 2). A composite's
# source file is not nls_utf8.c, so upstream's stays in the tree, unused.
ifdef CONFIG_RUST
nls_utf8-y			:= nls_utf8_glue.o nls_utf8_rs.o
else
nls_utf8-y			:= nls_utf8_norust.o
endif
obj-$(CONFIG_NLS_MAC_CELTIC)    += mac-celtic.o
obj-$(CONFIG_NLS_MAC_CENTEURO)  += mac-centeuro.o
obj-$(CONFIG_NLS_MAC_CROATIAN)  += mac-croatian.o
obj-$(CONFIG_NLS_MAC_CYRILLIC)  += mac-cyrillic.o
obj-$(CONFIG_NLS_MAC_GAELIC)    += mac-gaelic.o
obj-$(CONFIG_NLS_MAC_GREEK)     += mac-greek.o
obj-$(CONFIG_NLS_MAC_ICELAND)   += mac-iceland.o
obj-$(CONFIG_NLS_MAC_INUIT)     += mac-inuit.o
obj-$(CONFIG_NLS_MAC_ROMANIAN)  += mac-romanian.o
obj-$(CONFIG_NLS_MAC_ROMAN)     += mac-roman.o
obj-$(CONFIG_NLS_MAC_TURKISH)   += mac-turkish.o
obj-$(CONFIG_NLS_UCS2_UTILS)		+= nls_ucs2_utils.o
