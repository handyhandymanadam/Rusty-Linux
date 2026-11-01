# SPDX-License-Identifier: GPL-2.0
#
# Makefile for building the SELinux module as part of the kernel tree.
#

# NOTE: There are a number of improvements that can be made to this Makefile
# once the kernel requires make v4.3 or greater; the most important feature
# lacking in older versions of make is support for grouped targets.  These
# improvements are noted inline in the Makefile below ...

obj-$(CONFIG_SECURITY_SELINUX) := selinux.o

ccflags-y := -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include

ccflags-$(CONFIG_SECURITY_SELINUX_DEBUG) += -DDEBUG

# ss/ebitmap.o is a composite under CONFIG_RUST: ebitmap_glue.o is upstream's ebitmap.c without the bitmap functions, ebitmap_rs.o holds them. CONFIG_RUST=n builds
# upstream's body, installed byte-identical as ebitmap_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
selinux-ebitmap := ss/ebitmap_glue.o ss/ebitmap_rs.o
else
selinux-ebitmap := ss/ebitmap_norust.o
endif

# ss/avtab.o likewise: avtab_glue.o + avtab_rs.o, or avtab_norust.o.
ifdef CONFIG_RUST
selinux-avtab := ss/avtab_glue.o ss/avtab_rs.o
else
selinux-avtab := ss/avtab_norust.o
endif

# ss/hashtab.o and ss/symtab.o likewise.
ifdef CONFIG_RUST
selinux-hashtab := ss/hashtab_glue.o ss/hashtab_rs.o ss/symtab_glue.o ss/symtab_rs.o
else
selinux-hashtab := ss/hashtab_norust.o ss/symtab_norust.o
endif

# ss/conditional.o likewise.
ifdef CONFIG_RUST
selinux-conditional := ss/conditional_glue.o ss/conditional_rs.o
else
selinux-conditional := ss/conditional_norust.o
endif

# ss/mls.o likewise.
ifdef CONFIG_RUST
selinux-mls := ss/mls_glue.o ss/mls_rs.o
else
selinux-mls := ss/mls_norust.o
endif

selinux-y := avc.o hooks.o selinuxfs.o netlink.o nlmsgtab.o netif.o \
	     netnode.o netport.o status.o \
	     $(selinux-ebitmap) $(selinux-hashtab) ss/sidtab.o $(selinux-avtab) \
	     ss/policydb.o ss/services.o $(selinux-conditional) $(selinux-mls) ss/context.o

selinux-$(CONFIG_SECURITY_NETWORK_XFRM) += xfrm.o
selinux-$(CONFIG_NETLABEL) += netlabel.o
selinux-$(CONFIG_SECURITY_INFINIBAND) += ibpkey.o
selinux-$(CONFIG_IMA) += ima.o

genhdrs := flask.h av_permissions.h

# see the note above, replace the dependency rule with the one below:
#  $(addprefix $(obj)/,$(selinux-y)): $(addprefix $(obj)/,$(genhdrs))
$(addprefix $(obj)/,$(selinux-y)): $(obj)/flask.h

quiet_cmd_genhdrs = GEN     $(addprefix $(obj)/,$(genhdrs))
      cmd_genhdrs = $< $(addprefix $(obj)/,$(genhdrs))

targets += $(genhdrs)

# see the note above, replace the 'flask.h' rule with the line below:
#  $(addprefix $(obj)/,$(genhdrs)) &: $(obj)/genheaders FORCE
$(obj)/flask.h: $(obj)/genheaders FORCE
	$(call if_changed,genhdrs)

hostprogs := genheaders
HOST_EXTRACFLAGS += -I$(srctree)/security/selinux/include
