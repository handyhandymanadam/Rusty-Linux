// SPDX-License-Identifier: GPL-2.0

//! Disjoint-set (union-find) over caller-owned nodes.
//!
//! Ported from `lib/union_find.c` (6.18.49).
//!
//! # This one has no C entry symbol, and that is not an oversight
//!
//! `uf_find()` and `uf_union()` are global but **not** `EXPORT_SYMBOL`. The
//! constraint that forces a C thunk everywhere else in this port is
//! `CONFIG_GENDWARFKSYMS` computing a MODVERSIONS CRC from DWARF type names,
//! and a symbol that is not exported has no CRC. So these two are defined
//! here outright and `lib/union_find.c` is gone from the build; callers link
//! straight to the Rust with no trampoline.
//!
//! # Layout is the caller's
//!
//! `struct uf_node` is embedded in the caller's own structures and
//! initialised by the `UF_INIT_NODE` macro in `include/linux/union_find.h`.
//! GOALS.md §5 puts that squarely out of bounds: the `#[repr(C)]` below has
//! to match that header field for field, and nothing here may reorder,
//! resize or add to it.
//!
//! Replaces: lib/union_find.c

/// Mirrors `struct uf_node` in `include/linux/union_find.h`.
#[repr(C)]
pub struct UfNode {
    /// Parent in the forest; a root points at itself.
    pub parent: *mut UfNode,
    /// Upper bound on the height of this subtree.
    pub rank: core::ffi::c_uint,
}

/// Find the root of `node`'s set, compressing the path on the way.
///
/// # Safety
/// `node` must be non-null and point at an initialised [`UfNode`] whose
/// parent chain is well-formed — every node reachable from it is live and
/// its root points at itself. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn uf_find(node: *mut UfNode) -> *mut UfNode {
    let mut node = node;

    // SAFETY: the caller guarantees the chain is well-formed and live, so
    // every pointer dereferenced here is valid. The loop terminates because
    // a well-formed chain ends at a node that is its own parent.
    unsafe {
        while (*node).parent != node {
            let parent = (*node).parent;

            // Halving: point this node at its grandparent, then step up two.
            (*node).parent = (*parent).parent;
            node = parent;
        }
    }
    node
}

/// Merge the sets containing `node1` and `node2`, by rank.
///
/// # Safety
/// Both pointers must satisfy [`uf_find`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn uf_union(node1: *mut UfNode, node2: *mut UfNode) {
    // SAFETY: the caller guarantees both chains are well-formed and live.
    unsafe {
        let root1 = uf_find(node1);
        let root2 = uf_find(node2);

        if root1 == root2 {
            return;
        }

        if (*root1).rank < (*root2).rank {
            (*root1).parent = root2;
        } else if (*root1).rank > (*root2).rank {
            (*root2).parent = root1;
        } else {
            (*root2).parent = root1;
            (*root1).rank = (*root1).rank.wrapping_add(1);
        }
    }
}
