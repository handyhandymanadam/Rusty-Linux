/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Textually includes the pristine lib/buildid.c UNCHANGED (matching the
 * decompressor STATIC-include pattern already used elsewhere in this
 * kernel tree, logs/trusted-surface.md's "B1" backlog entry) so this file
 * can expose get_build_id_32()/get_build_id_64()/parse_build_id()/
 * freader_init_from_mem() -- all `static` in the real file -- under real,
 * linkable, differently-named wrappers, WITHOUT modifying the pristine
 * source at all: the #include brings them into this translation unit's
 * scope, and the wrappers below just forward to them by their real names.
 */
#include "buildid.c"

long pristine_get_build_id_32(struct freader *r, unsigned char *build_id, __u32 *size)
{
	return get_build_id_32(r, build_id, size);
}

long pristine_get_build_id_64(struct freader *r, unsigned char *build_id, __u32 *size)
{
	return get_build_id_64(r, build_id, size);
}

long pristine_parse_build_id(struct freader *r, unsigned char *build_id, __u32 *size,
			      long note_off, unsigned int note_size)
{
	return parse_build_id(r, build_id, size, note_off, note_size);
}

void pristine_freader_init_from_mem(struct freader *r, const char *data, unsigned long data_sz)
{
	freader_init_from_mem(r, data, data_sz);
}

int pristine_freader_size(void)
{
	return (int)sizeof(struct freader);
}
