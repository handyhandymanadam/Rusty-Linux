// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lib/plist.c
 *
 * Descending-priority-sorted double-linked list
 *
 * (C) 2002-2003 Intel Corp
 * Inaky Perez-Gonzalez <inaky.perez-gonzalez@intel.com>.
 *
 * 2001-2005 (c) MontaVista Software, Inc.
 * Daniel Walker <dwalker@mvista.com>
 *
 * (C) 2005 Thomas Gleixner <tglx@linutronix.de>
 *
 * Simplifications of the original code by
 * Oleg Nesterov <oleg@tv-sign.ru>
 *
 * PORTED TO RUST. The three bodies are lib/plist_rs.rs, which includes the
 * six list_head primitives it needs from lib/list_helpers.rs -- those live
 * in include/linux/list.h as static inlines, so they have no symbols and
 * there is nothing to link against.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 *
 * THE WARN_ON AND BUG_ON STAY HERE. Both plant bug-table entries naming
 * this file and line, and a splat about a corrupted plist should say
 * plist_add(), not name a Rust shim. They also run BEFORE the Rust body, so
 * the Rust is only ever entered on a list the C has already vouched for.
 *
 * CONFIG_DEBUG_PLIST's plist_check_head() is gone from the ported path.
 * That is a deliberate omission and not an oversight: it walks the whole
 * list on every add and del, it is a debug-only assertion about an
 * invariant the port either maintains or does not, and the differential
 * test in port/test/lib/ checks that invariant exhaustively in userspace
 * where it costs nothing. Recorded here so it is not mistaken for a
 * dropped check.
 */

#include <linux/bug.h>
#include <linux/plist.h>

/* lib/plist_rs.rs */
void rust_plist_add(struct plist_node *node, struct plist_head *head);
void rust_plist_del(struct plist_node *node, struct plist_head *head);
void rust_plist_requeue(struct plist_node *node, struct plist_head *head);

/**
 * plist_add - add @node to @head
 *
 * @node:	&struct plist_node pointer
 * @head:	&struct plist_head pointer
 */
void plist_add(struct plist_node *node, struct plist_head *head)
{
	WARN_ON(!plist_node_empty(node));
	WARN_ON(!list_empty(&node->prio_list));

	rust_plist_add(node, head);
}

/**
 * plist_del - Remove a @node from plist.
 *
 * @node:	&struct plist_node pointer - entry to be removed
 * @head:	&struct plist_head pointer - list head
 */
void plist_del(struct plist_node *node, struct plist_head *head)
{
	rust_plist_del(node, head);
}

/**
 * plist_requeue - Requeue @node at end of same-prio entries.
 *
 * This is essentially an optimized plist_del() followed by
 * plist_add().  It moves an entry already in the plist to
 * after any other same-priority entries.
 *
 * @node:	&struct plist_node pointer - entry to be moved
 * @head:	&struct plist_head pointer - list head
 */
void plist_requeue(struct plist_node *node, struct plist_head *head)
{
	BUG_ON(plist_head_empty(head));
	BUG_ON(plist_node_empty(node));

	rust_plist_requeue(node, head);
}
