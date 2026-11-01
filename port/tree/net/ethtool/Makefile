# SPDX-License-Identifier: GPL-2.0-only

obj-y				+= ioctl.o common.o

obj-$(CONFIG_ETHTOOL_NETLINK)	+= ethtool_nl.o

# bitset.o is a composite under CONFIG_RUST: bitset_glue.o is upstream's bitset.c without the u32-bitmap helpers and ethnl_bitset32_size(), bitset_rs.o holds them.
# CONFIG_RUST=n builds upstream's body, installed byte-identical as bitset_norust.c by rig/apply.sh.
ifdef CONFIG_RUST
ethtool-bitset := bitset_glue.o bitset_rs.o
else
ethtool-bitset := bitset_norust.o
endif

ethtool_nl-y	:= netlink.o $(ethtool-bitset) strset.o linkinfo.o linkmodes.o rss.o \
		   linkstate.o debug.o wol.o features.o privflags.o rings.o \
		   channels.o coalesce.o pause.o eee.o tsinfo.o cabletest.o \
		   tunnels.o fec.o eeprom.o stats.o phc_vclocks.o mm.o \
		   module.o cmis_fw_update.o cmis_cdb.o pse-pd.o plca.o \
		   phy.o tsconfig.o
