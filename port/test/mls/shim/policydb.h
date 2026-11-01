#ifndef SHIM_POLICYDB_H
#define SHIM_POLICYDB_H
#include "refshim.h"
#include "security.h"
#include "ebitmap.h"
#include "symtab.h"
#include "mls_types.h"
#define AVTAB_TRANSITION 0x0010
#define AVTAB_MEMBER	 0x0020
#define AVTAB_CHANGE	 0x0040
#define DEFAULT_SOURCE_LOW	1
#define DEFAULT_SOURCE_HIGH	2
#define DEFAULT_SOURCE_LOW_HIGH 3
#define DEFAULT_TARGET_LOW	4
#define DEFAULT_TARGET_HIGH	5
#define DEFAULT_TARGET_LOW_HIGH 6
#define DEFAULT_GLBLUB		7
#define OBJECT_R_VAL 1
#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES   2
#define SYM_TYPES   3
#define SYM_USERS   4
#define SYM_BOOLS   5
#define SYM_LEVELS  6
#define SYM_CATS    7
#define SYM_NUM	    8
struct level_datum { struct mls_level level; unsigned char isalias; };
struct cat_datum { u32 value; unsigned char isalias; };
struct user_datum { u32 value; u32 bounds; struct ebitmap roles; struct mls_range range; struct mls_level dfltlevel; };
struct class_datum { u16 value; char *comkey; void *comdatum; struct symtab permissions; void *constraints; void *validatetrans; char default_user; char default_role; char default_type; char default_range; };
struct range_trans { u32 source_type; u32 target_type; u16 target_class; };
/* the real layout up to process_class (checked by the glue's static_asserts, which the Rust side's build runs) */
struct policydb {
	int mls_enabled;
	struct symtab symtab[SYM_NUM];
	char **sym_val_to_name[SYM_NUM];
	struct class_datum **class_val_to_struct;
	void *role_val_to_struct;
	struct user_datum **user_val_to_struct;
	char pad[598 - 288];
	u16 process_class;
};
#define p_classes symtab[SYM_CLASSES]
#define p_users	  symtab[SYM_USERS]
#define p_levels  symtab[SYM_LEVELS]
#define p_cats	  symtab[SYM_CATS]
static inline char *sym_name(struct policydb *p, unsigned int sym_num, unsigned int element_nr) { return p->sym_val_to_name[sym_num][element_nr]; }
struct mls_range *policydb_rangetr_search(struct policydb *p, struct range_trans *key);
#endif
