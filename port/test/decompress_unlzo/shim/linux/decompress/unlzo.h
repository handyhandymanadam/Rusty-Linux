#ifndef _SHIM_UNLZO_H
#define _SHIM_UNLZO_H
int unlzo(unsigned char *inbuf, long len,
	long (*fill)(void*, unsigned long),
	long (*flush)(void*, unsigned long),
	unsigned char *output,
	long *pos,
	void(*error)(char *x));
#endif
