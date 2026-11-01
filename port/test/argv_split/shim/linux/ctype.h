/* the kernel's isspace(): _ctype makes \t \n \v \f \r, ' ' and 0xa0 spaces (libc's isspace() would not take 0xa0) */
#ifndef SH_CTYPE_H
#define SH_CTYPE_H
static inline int ke_isspace(int c) { unsigned char u = (unsigned char)c; return (u >= 9 && u <= 13) || u == ' ' || u == 0xa0; }
#define isspace(c) ke_isspace(c)
#endif
