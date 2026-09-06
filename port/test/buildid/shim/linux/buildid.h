#pragma once
#include <linux/types.h>

#define BUILD_ID_SIZE_MAX 20

struct file; /* forward decl only -- pointer use is fine before linux/fs.h */
struct vm_area_struct {
	struct file *vm_file;
};

int build_id_parse(struct vm_area_struct *vma, unsigned char *build_id, __u32 *size);
int build_id_parse_file(struct file *file, unsigned char *build_id, __u32 *size);
int build_id_parse_nofault(struct vm_area_struct *vma, unsigned char *build_id, __u32 *size);
int build_id_parse_buf(const void *buf, unsigned char *build_id, u32 buf_size);
