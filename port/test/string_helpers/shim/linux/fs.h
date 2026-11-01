/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_FS_H
#define _SHIM_LINUX_FS_H

struct file;
struct task_struct;

extern char *file_path(struct file *filp, char *buf, int buflen);
extern int get_cmdline(struct task_struct *task, char *buffer, int buflen);

#endif
