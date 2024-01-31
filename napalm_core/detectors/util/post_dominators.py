from typing import Set, List, TYPE_CHECKING

from slither.core.cfg.node import NodeType

from slither.core.cfg.node import Node

from toolz import reduce


"""
Algorithm and implementation of post-dominators is largely based on original dominator implementation in slither.

Source: https://github.com/crytic/slither/blob/46be017fe538c04dbc5928c1134d78e8c3e70e74/slither/core/dominators/utils.py
"""

from copy import copy


def get_post_dominators(node: "Node") -> Set["Node"]:
    if hasattr(node, "post_dominators"):
        # return copy(node.post_dominators)
        return node.post_dominators
    else:
        return set()


def set_post_dominators(node: Node, nodes: List["Node"]) -> None:
    node.post_dominators = nodes


def set_immediate_post_dominator(node: Node, immediate_post_dominator: "Node") -> None:
    node.immediate_post_dominator = immediate_post_dominator


def get_immediate_post_dominator(node: Node) -> "Node":
    if hasattr(node, "immediate_post_dominator"):
        return node.immediate_post_dominator
    else:
        return None


def _intersection_successor(node: "Node") -> Set["Node"]:
    if not node.sons:
        return set()

    if not any(son.is_reachable for son in node.sons):
        return set()

    return set(reduce(set.intersection, map(get_post_dominators, node.sons)))


def _compute_post_dominators(nodes: List["Node"]) -> None:
    changed = True
    while changed:
        changed = False
        for node in nodes:
            new_set = _intersection_successor(node).union({node})
            if new_set != node.post_dominators:
                node.post_dominators = new_set
                changed = True


def _compute_immediate_post_dominators(nodes: List["Node"]) -> None:
    for node in nodes:
        idom_candidates = get_post_dominators(node) - {node}

        if len(idom_candidates) == 1:
            set_immediate_post_dominator(node, idom_candidates.pop())
            continue

        all_dominators = set()
        for d in idom_candidates:
            if d in all_dominators:
                continue
            all_dominators |= get_post_dominators(d) - {d}

        idom_candidates = all_dominators.symmetric_difference(idom_candidates)
        assert len(idom_candidates) <= 1
        if idom_candidates:
            idom = idom_candidates.pop()
            set_immediate_post_dominator(node, idom)


def compute_post_dominators(nodes: List["Node"]) -> None:
    if not nodes:
        return

    for n in nodes:
        n.post_dominators = set(nodes)

    _compute_post_dominators(nodes)

    _compute_immediate_post_dominators(nodes)

    return nodes
