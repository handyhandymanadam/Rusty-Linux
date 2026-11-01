/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Byte-exact check for lib/fonts/font_8x16.c -> lib/fonts/font_8x16_rs.rs.
 * Not a differential in the usual sense of this project's harnesses --
 * there is no algorithm here, just a 4096-byte glyph array and one
 * struct -- so this dumps every field plus every glyph byte plus the
 * extra[]/REFCOUNT negative-offset ABI detail (font_8x16_rs.rs's own
 * module doc explains it) to stdout, from the REAL pristine C. run.sh
 * does the same from the Rust side (layout_probe.rs) and diffs the two
 * outputs directly -- same shape as port/test/xarray/layout/.
 */
#include <stdio.h>
#include <linux/font.h>

extern const struct font_desc font_vga_8x16;

int main(void)
{
	const struct font_desc *fd = &font_vga_8x16;
	const unsigned char *data = fd->data;
	unsigned int i;

	printf("idx=%d\n", fd->idx);
	printf("name=%s\n", fd->name);
	printf("width=%u\n", fd->width);
	printf("height=%u\n", fd->height);
	printf("charcount=%u\n", fd->charcount);
	printf("pref=%d\n", fd->pref);
	printf("REFCOUNT=%d\n", REFCOUNT(fd->data));
	printf("FNTSIZE=%d\n", FNTSIZE(fd->data));
	printf("FNTCHARCNT=%d\n", FNTCHARCNT(fd->data));
	printf("FNTSUM=%d\n", FNTSUM(fd->data));
	for (i = 0; i < 4096; i++)
		printf("data[%u]=%02x\n", i, data[i]);
	return 0;
}
