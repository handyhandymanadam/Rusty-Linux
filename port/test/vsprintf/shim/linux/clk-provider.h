/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_CLK_PROVIDER_H
#define _SHIM_LINUX_CLK_PROVIDER_H
/* CONFIG_COMMON_CLK stays undefined in this harness (matches both this
 * project's real .config's -- checked), so clock()'s __clk_get_name()
 * branch is never compiled; nothing to declare here. */
#endif
