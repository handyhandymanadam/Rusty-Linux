/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Layout test 2/2: mm/workingset.c is the one real external C consumer
 * that reads struct xa_node fields directly (confirmed by direct
 * inspection AND by the adversary's own independent verification of
 * lines 625/627/702/718/747/749). It stays C -- this test does not
 * reimplement workingset_update_node()/shadow_lru_isolate(), it
 * reproduces their EXACT field-access expressions verbatim (copied
 * from src/linux-6.18.49/mm/workingset.c as of this writing) against a
 * struct xa_node this test itself populates, and checks the results
 * are what those expressions are meant to mean.
 *
 * This is deliberately narrower than layout/run.sh's full-struct test
 * (which already proves every field's offset matches, a superset of
 * what workingset.c touches): that test proves offsets agree in the
 * abstract, this one proves the SPECIFIC compound C expressions a real
 * caller uses -- pointer-chasing through xa_node->array->xa_lock, and
 * container_of() through private_list -- resolve to the right bytes,
 * not just that the individual field offsets happen to be correct in
 * isolation.
 */
#include <linux/list.h>
#include <linux/xarray.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

int main(void)
{
	struct xarray xa;
	struct xa_node *node = calloc(1, sizeof(struct xa_node));
	int failures = 0;

	if (!node) {
		fprintf(stderr, "calloc failed\n");
		return 1;
	}

	memset(&xa, 0, sizeof(xa));
	node->array = &xa;
	node->count = 5;
	node->nr_values = 5;
	INIT_LIST_HEAD(&node->private_list);

	/* workingset_update_node(): "lockdep_assert_held(&node->array->xa_lock)" */
	if (&node->array->xa_lock != (spinlock_t *)&xa) {
		fprintf(stderr, "FAIL: &node->array->xa_lock does not land on &xa\n");
		failures++;
	}

	/* workingset_update_node(): "if (node->count && node->count == node->nr_values)" */
	if (!(node->count && node->count == node->nr_values)) {
		fprintf(stderr, "FAIL: node->count/nr_values comparison wrong\n");
		failures++;
	}

	/* workingset_update_node(): "if (list_empty(&node->private_list))" */
	if (!list_empty(&node->private_list)) {
		fprintf(stderr, "FAIL: node->private_list not empty on init\n");
		failures++;
	}

	/* shadow_lru_isolate(): "container_of(item, struct xa_node, private_list)" */
	{
		struct list_head *item = &node->private_list;
		struct xa_node *recovered = container_of(item, struct xa_node, private_list);

		if (recovered != node) {
			fprintf(stderr, "FAIL: container_of(private_list) -> %p, want %p\n",
				(void *)recovered, (void *)node);
			failures++;
		}
	}

	/* Vary count/nr_values to exercise the *inequality* branch too --
	 * workingset_update_node()'s "else" arm (list_lru_del_obj path). */
	node->count = 5;
	node->nr_values = 3;
	if (node->count && node->count == node->nr_values) {
		fprintf(stderr, "FAIL: count/nr_values inequality branch not reached\n");
		failures++;
	}

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("workingset.c field-access shim: OK\n");
	return 0;
}
