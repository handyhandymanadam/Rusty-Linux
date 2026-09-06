#
# DIM Dynamic Interrupt Moderation library
#

obj-$(CONFIG_DIMLIB) += dimlib.o

# dim.o is gone: dim_calc_stats/dim_on_top/dim_turn/dim_park_on_top/
# dim_park_tired move into dim_rs.o, kabi contracts via kernel::kabi_export!
# (see dim_rs.rs). rdma_dim.c stays paired with its own CONFIG_RUST arm
# below since it depends on dim_rs.rs's symbols directly; net_dim.c is
# struct net_device-coupled and out of scope, unconditional either way.
ifdef CONFIG_RUST
dimlib-y := dim_rs.o net_dim.o rdma_dim_rs.o rdma_dim_thunk.o
else
dimlib-y := dim_norust.o net_dim.o rdma_dim_norust.o
endif
