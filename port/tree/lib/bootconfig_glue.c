// SPDX-License-Identifier: GPL-2.0
/*
 * Extra Boot Config
 * Masami Hiramatsu <mhiramat@kernel.org>
 */

/*
 * NOTE: This is only for tools/bootconfig, because tools/bootconfig will
 * run the parser sanity test.
 * This does NOT mean lib/bootconfig.c is available in the user space.
 * However, if you change this file, please make sure the tools/bootconfig
 * has no issue on building and running.
 */
#include <linux/bootconfig.h>

/*
 * RUST PORT (lib/bootconfig.c, 6.18.49): the parser, the tree builder and verifier, xbc_init / _xbc_exit and every accessor and finder are in
 * bootconfig_rs.rs, in .init.text like the C they replace. This file keeps the state (all __initdata, handed to the Rust as pointers by rust_xbc_state()),
 * the memblock allocation, the exports as one-line __init thunks, the embedded-config accessor, and the two functions that use the variadic snprintf
 * (xbc_node_compose_key_after, xbc_snprint_cmdline) with the name buffer they share. Every WARN_ON site is a one-line wrapper (the warning now names this
 * file -- recorded divergence). Upstream's whole file is installed as bootconfig_norust.c for CONFIG_RUST=n.
 */

#ifdef __KERNEL__
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/string.h>

#ifdef CONFIG_BOOT_CONFIG_EMBED
/* embedded_bootconfig_data is defined in bootconfig-data.S */
extern __visible const char embedded_bootconfig_data[];
extern __visible const char embedded_bootconfig_data_end[];

const char * __init xbc_get_embedded_bootconfig(size_t *size)
{
	*size = embedded_bootconfig_data_end - embedded_bootconfig_data;
	return (*size) ? embedded_bootconfig_data : NULL;
}
#endif
#endif

/* XBC state, see bootconfig_rs.rs */
static struct xbc_node *xbc_nodes __initdata;
static int xbc_node_num __initdata;
static char *xbc_data __initdata;
static size_t xbc_data_size __initdata;
static struct xbc_node *last_parent __initdata;
static const char *xbc_err_msg __initdata;
static int xbc_err_pos __initdata;
static int open_brace[XBC_DEPTH_MAX] __initdata;
static int brace_index __initdata;

#ifdef __KERNEL__
static inline void * __init xbc_alloc_mem(size_t size)
{
	return memblock_alloc(size, SMP_CACHE_BYTES);
}

static inline void __init xbc_free_mem(void *addr, size_t size, bool early)
{
	if (early)
		memblock_free(addr, size);
	else if (addr)
		memblock_free_late(__pa(addr), size);
}

#else /* !__KERNEL__ */

static inline void *xbc_alloc_mem(size_t size)
{
	return malloc(size);
}

static inline void xbc_free_mem(void *addr, size_t size, bool early)
{
	free(addr);
}
#endif

static_assert(sizeof(struct xbc_node) == 8 && offsetof(struct xbc_node, next) == 0 && offsetof(struct xbc_node, child) == 2 &&
	      offsetof(struct xbc_node, parent) == 4 && offsetof(struct xbc_node, data) == 6);
static_assert(XBC_VALUE == 0x8000 && XBC_DATA_MAX == 0x7fff && XBC_NODE_MAX == 8192 && XBC_KEYLEN_MAX == 256 && XBC_DEPTH_MAX == 16);
static_assert(_U == 0x01 && _L == 0x02 && _D == 0x04 && _P == 0x10 && _S == 0x20 && _SP == 0x80);

struct rust_xbc_state_s {
	struct xbc_node **nodes;
	int *node_num;
	char **data;
	size_t *data_size;
	struct xbc_node **last_parent;
	const char **err_msg;
	int *err_pos;
	int *open_brace;
	int *brace_index;
};
static struct rust_xbc_state_s xbc_state __initdata = {
	&xbc_nodes, &xbc_node_num, &xbc_data, &xbc_data_size, &last_parent, &xbc_err_msg, &xbc_err_pos, open_brace, &brace_index,
};

const struct rust_xbc_state_s * __init rust_xbc_state(void);
void * __init rust_xbcw_alloc(size_t size);
void __init rust_xbcw_free(void *addr, size_t size, bool early);
bool rust_xbcw_warn_data(bool cond);
bool rust_xbcw_warn_leaf(bool cond);
bool rust_xbcw_warn_kv(bool cond);
bool rust_xbcw_warn_init_node(bool cond);
int rust_xbc_get_info(int *node_size, size_t *data_size);
struct xbc_node *rust_xbc_root_node(void);
int rust_xbc_node_index(struct xbc_node *node);
struct xbc_node *rust_xbc_node_get_parent(struct xbc_node *node);
struct xbc_node *rust_xbc_node_get_child(struct xbc_node *node);
struct xbc_node *rust_xbc_node_get_next(struct xbc_node *node);
const char *rust_xbc_node_get_data(struct xbc_node *node);
struct xbc_node *rust_xbc_node_find_subkey(struct xbc_node *parent, const char *key);
const char *rust_xbc_node_find_value(struct xbc_node *parent, const char *key, struct xbc_node **vnode);
struct xbc_node *rust_xbc_node_find_next_leaf(struct xbc_node *root, struct xbc_node *node);
const char *rust_xbc_node_find_next_key_value(struct xbc_node *root, struct xbc_node **leaf);
void rust_xbc_exit(bool early);
int rust_xbc_init(const char *data, size_t size, const char **emsg, int *epos);

const struct rust_xbc_state_s * __init rust_xbc_state(void)
{
	return &xbc_state;
}

void * __init rust_xbcw_alloc(size_t size) { return xbc_alloc_mem(size); }
void __init rust_xbcw_free(void *addr, size_t size, bool early) { xbc_free_mem(addr, size, early); }
bool rust_xbcw_warn_data(bool cond) { return WARN_ON(cond); }
bool rust_xbcw_warn_leaf(bool cond) { return WARN_ON(cond); }
bool rust_xbcw_warn_kv(bool cond) { return WARN_ON(cond); }
bool rust_xbcw_warn_init_node(bool cond) { return WARN_ON(cond); }


/**
 * xbc_get_info() - Get the information of loaded boot config
 * @node_size: A pointer to store the number of nodes.
 * @data_size: A pointer to store the size of bootconfig data.
 *
 * Get the number of used nodes in @node_size if it is not NULL,
 * and the size of bootconfig data in @data_size if it is not NULL.
 * Return 0 if the boot config is initialized, or return -ENODEV.
 */
int __init xbc_get_info(int *node_size, size_t *data_size)
{
	return rust_xbc_get_info(node_size, data_size);
}

struct xbc_node * __init xbc_root_node(void)
{
	return rust_xbc_root_node();
}

int __init xbc_node_index(struct xbc_node *node)
{
	return rust_xbc_node_index(node);
}

struct xbc_node * __init xbc_node_get_parent(struct xbc_node *node)
{
	return rust_xbc_node_get_parent(node);
}

struct xbc_node * __init xbc_node_get_child(struct xbc_node *node)
{
	return rust_xbc_node_get_child(node);
}

struct xbc_node * __init xbc_node_get_next(struct xbc_node *node)
{
	return rust_xbc_node_get_next(node);
}

const char * __init xbc_node_get_data(struct xbc_node *node)
{
	return rust_xbc_node_get_data(node);
}

struct xbc_node * __init
xbc_node_find_subkey(struct xbc_node *parent, const char *key)
{
	return rust_xbc_node_find_subkey(parent, key);
}

const char * __init
xbc_node_find_value(struct xbc_node *parent, const char *key,
		    struct xbc_node **vnode)
{
	return rust_xbc_node_find_value(parent, key, vnode);
}

/**
 * xbc_node_compose_key_after() - Compose partial key string of the XBC node
 * @root: Root XBC node
 * @node: Target XBC node.
 * @buf: A buffer to store the key.
 * @size: The size of the @buf.
 *
 * Compose the partial key of the @node into @buf, which is starting right
 * after @root (@root is not included.) If @root is NULL, this returns full
 * key words of @node.
 * Returns the total length of the key stored in @buf. Returns -EINVAL
 * if @node is NULL or @root is not the ancestor of @node or @root is @node,
 * or returns -ERANGE if the key depth is deeper than max depth.
 * This is expected to be used with xbc_find_node() to list up all (child)
 * keys under given key.
 */
int __init xbc_node_compose_key_after(struct xbc_node *root,
				      struct xbc_node *node,
				      char *buf, size_t size)
{
	uint16_t keys[XBC_DEPTH_MAX];
	int depth = 0, ret = 0, total = 0;

	if (!node || node == root)
		return -EINVAL;

	if (xbc_node_is_value(node))
		node = xbc_node_get_parent(node);

	while (node && node != root) {
		keys[depth++] = xbc_node_index(node);
		if (depth == XBC_DEPTH_MAX)
			return -ERANGE;
		node = xbc_node_get_parent(node);
	}
	if (!node && root)
		return -EINVAL;

	while (--depth >= 0) {
		node = xbc_nodes + keys[depth];
		ret = snprintf(buf, size, "%s%s", xbc_node_get_data(node),
			       depth ? "." : "");
		if (ret < 0)
			return ret;
		if (ret >= size) {
			size = 0;
		} else {
			size -= ret;
			buf += ret;
		}
		total += ret;
	}

	return total;
}

struct xbc_node * __init xbc_node_find_next_leaf(struct xbc_node *root,
						 struct xbc_node *node)
{
	return rust_xbc_node_find_next_leaf(root, node);
}

const char * __init xbc_node_find_next_key_value(struct xbc_node *root,
						 struct xbc_node **leaf)
{
	return rust_xbc_node_find_next_key_value(root, leaf);
}

static char xbc_namebuf[XBC_KEYLEN_MAX] __initdata;

#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

/**
 * xbc_snprint_cmdline() - Render bootconfig keys under @root as a cmdline string
 * @buf: Destination buffer (may be NULL when @size is 0 to query the length)
 * @size: Size of @buf in bytes
 * @root: Subtree root whose key=value pairs should be rendered
 *
 * Walk all key/value pairs under @root and emit them as a space-separated
 * cmdline string into @buf. Values containing whitespace are quoted with
 * double quotes. Returns the number of bytes that would be written if @buf
 * were large enough (matching snprintf semantics), or a negative errno on
 * failure.
 */
int __init xbc_snprint_cmdline(char *buf, size_t size, struct xbc_node *root)
{
	struct xbc_node *knode, *vnode;
	const char *val, *q;
	size_t len = 0;
	int ret;

	/*
	 * Track the running written length rather than advancing @buf, so we
	 * never form "buf + size" or "buf += ret" while @buf is NULL (the
	 * size-probe call passes buf=NULL, size=0). NULL pointer arithmetic
	 * is undefined behavior and trips host UBSan / FORTIFY_SOURCE when
	 * this renderer runs at kernel build time. snprintf(NULL, 0, ...)
	 * itself is well defined and returns the would-be length.
	 */
	xbc_node_for_each_key_value(root, knode, val) {
		ret = xbc_node_compose_key_after(root, knode,
					xbc_namebuf, XBC_KEYLEN_MAX);
		if (ret < 0)
			return ret;

		vnode = xbc_node_get_child(knode);
		if (!vnode) {
			ret = snprintf(buf ? buf + len : NULL, rest(len, size),
				       "%s ", xbc_namebuf);
			if (ret < 0)
				return ret;
			len += ret;
			continue;
		}
		xbc_array_for_each_value(vnode, val) {
			/*
			 * For prettier and more readable /proc/cmdline, only
			 * quote the value when necessary, i.e. when it contains
			 * whitespace.
			 */
			q = strpbrk(val, " \t\r\n") ? "\"" : "";
			ret = snprintf(buf ? buf + len : NULL, rest(len, size),
				       "%s=%s%s%s ", xbc_namebuf, q, val, q);
			if (ret < 0)
				return ret;
			len += ret;
		}
	}

	return len;
}
#undef rest

void __init _xbc_exit(bool early)
{
	rust_xbc_exit(early);
}

int __init xbc_init(const char *data, size_t size, const char **emsg, int *epos)
{
	return rust_xbc_init(data, size, emsg, epos);
}
