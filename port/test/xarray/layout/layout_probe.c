/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Layout test 1/2: full-struct offset/sizeof comparison between the
 * REAL C (via the real include/linux/xarray.h, not the differential's
 * shim) and xarray_rs.rs's #[repr(C)] mirrors, for BOTH
 * CONFIG_BASE_SMALL arms. Compiled twice (see run.sh), once per arm,
 * with -DCONFIG_BASE_SMALL=0 or =1 so the real header's own #ifndef
 * XA_CHUNK_SHIFT / IS_ENABLED(CONFIG_BASE_SMALL) logic picks the shift
 * -- this test does NOT use the differential harness's XA_CHUNK_SHIFT=4
 * override (see layout/shim/linux/kernel.h's own comment): the point
 * here is the REAL kernel layout, not the corpus-depth one.
 *
 * Prints one line per field/struct as "name=value"; layout_check.py
 * parses both this program's output and the Rust probe's, and fails
 * loudly on any mismatch, including sizeof (a width error on the last
 * field or trailing padding is not caught by individual offsets alone)
 * and the two unions (private_list/rcu_head, tags/marks) explicitly,
 * not by same-size-coincidence.
 */
#include <linux/xarray.h>
#include <stdio.h>
#include <stddef.h>

int main(void)
{
	printf("XA_CHUNK_SHIFT=%d\n", (int)XA_CHUNK_SHIFT);
	printf("XA_CHUNK_SIZE=%d\n", (int)XA_CHUNK_SIZE);
	printf("XA_MARK_LONGS=%d\n", (int)XA_MARK_LONGS);

	printf("sizeof(struct xarray)=%zu\n", sizeof(struct xarray));
	printf("offsetof(xarray,xa_flags)=%zu\n", offsetof(struct xarray, xa_flags));
	printf("offsetof(xarray,xa_head)=%zu\n", offsetof(struct xarray, xa_head));
	printf("sizeof(spinlock_t)=%zu\n", sizeof(spinlock_t));

	printf("sizeof(struct xa_node)=%zu\n", sizeof(struct xa_node));
	printf("offsetof(xa_node,shift)=%zu\n", offsetof(struct xa_node, shift));
	printf("offsetof(xa_node,offset)=%zu\n", offsetof(struct xa_node, offset));
	printf("offsetof(xa_node,count)=%zu\n", offsetof(struct xa_node, count));
	printf("offsetof(xa_node,nr_values)=%zu\n", offsetof(struct xa_node, nr_values));
	printf("offsetof(xa_node,parent)=%zu\n", offsetof(struct xa_node, parent));
	printf("offsetof(xa_node,array)=%zu\n", offsetof(struct xa_node, array));
	printf("offsetof(xa_node,private_list)=%zu\n", offsetof(struct xa_node, private_list));
	printf("offsetof(xa_node,rcu_head)=%zu\n", offsetof(struct xa_node, rcu_head));
	printf("sizeof(xa_node.private_list)=%zu\n", sizeof(((struct xa_node *)0)->private_list));
	printf("sizeof(xa_node.rcu_head)=%zu\n", sizeof(((struct xa_node *)0)->rcu_head));
	printf("offsetof(xa_node,slots)=%zu\n", offsetof(struct xa_node, slots));
	printf("sizeof(xa_node.slots)=%zu\n", sizeof(((struct xa_node *)0)->slots));
	printf("offsetof(xa_node,tags)=%zu\n", offsetof(struct xa_node, tags));
	printf("offsetof(xa_node,marks)=%zu\n", offsetof(struct xa_node, marks));
	printf("sizeof(xa_node.tags)=%zu\n", sizeof(((struct xa_node *)0)->tags));
	printf("sizeof(xa_node.marks)=%zu\n", sizeof(((struct xa_node *)0)->marks));

	printf("sizeof(struct xa_state)=%zu\n", sizeof(struct xa_state));
	printf("offsetof(xa_state,xa)=%zu\n", offsetof(struct xa_state, xa));
	printf("offsetof(xa_state,xa_index)=%zu\n", offsetof(struct xa_state, xa_index));
	printf("offsetof(xa_state,xa_shift)=%zu\n", offsetof(struct xa_state, xa_shift));
	printf("offsetof(xa_state,xa_sibs)=%zu\n", offsetof(struct xa_state, xa_sibs));
	printf("offsetof(xa_state,xa_offset)=%zu\n", offsetof(struct xa_state, xa_offset));
	printf("offsetof(xa_state,xa_pad)=%zu\n", offsetof(struct xa_state, xa_pad));
	printf("offsetof(xa_state,xa_node)=%zu\n", offsetof(struct xa_state, xa_node));
	printf("offsetof(xa_state,xa_alloc)=%zu\n", offsetof(struct xa_state, xa_alloc));
	printf("offsetof(xa_state,xa_update)=%zu\n", offsetof(struct xa_state, xa_update));
	printf("offsetof(xa_state,xa_lru)=%zu\n", offsetof(struct xa_state, xa_lru));

	return 0;
}
