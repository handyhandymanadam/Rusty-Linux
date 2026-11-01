# SPDX-License-Identifier: GPL-2.0
# Font handling

font-objs := fonts.o

font-objs-$(CONFIG_FONT_SUN8x16)   += font_sun8x16.o
font-objs-$(CONFIG_FONT_SUN12x22)  += font_sun12x22.o
font-objs-$(CONFIG_FONT_8x8)       += font_8x8.o

# font_8x16.o is gone: pure data (one 4096-byte glyph array, one exported
# struct font_desc, no functions at all), thunk-free -- the Rust defines
# and exports font_vga_8x16 itself and carries its ABI contract, via
# kernel::kabi_export!(). <base>_norust.c below is installed by
# rig/apply.sh from port/pristine/, byte-identical upstream, RAISE 2
# (logs/floor.md) -- same convention as every other ported file here,
# despite this Makefile's own font-objs-y indirection being unlike the
# plain lib-y/obj-y seen elsewhere.
ifdef CONFIG_RUST
font-objs-$(CONFIG_FONT_8x16)      += font_8x16_rs.o
else
font-objs-$(CONFIG_FONT_8x16)      += font_8x16_norust.o
endif

font-objs-$(CONFIG_FONT_6x11)      += font_6x11.o
font-objs-$(CONFIG_FONT_7x14)      += font_7x14.o
font-objs-$(CONFIG_FONT_10x18)     += font_10x18.o
font-objs-$(CONFIG_FONT_PEARL_8x8) += font_pearl_8x8.o
font-objs-$(CONFIG_FONT_ACORN_8x8) += font_acorn_8x8.o
font-objs-$(CONFIG_FONT_MINI_4x6)  += font_mini_4x6.o
font-objs-$(CONFIG_FONT_6x10)      += font_6x10.o
font-objs-$(CONFIG_FONT_TER16x32)  += font_ter16x32.o
font-objs-$(CONFIG_FONT_6x8)       += font_6x8.o

font-objs += $(font-objs-y)

obj-$(CONFIG_FONT_SUPPORT)         += font.o
