import copy
from typing import Callable, TypeVar, Generic, Optional

from slither.core.cfg.node import NodeType, Function

from slither.core.cfg.node import Node

from toolz import reduce, iterate, curry


@curry
def get_taint(taint_identifier: str, node: Node):
    return node.context.get(f"TAINT_{taint_identifier}", None)


def set_taint(taint_identifier: str, node: Node, taint):
    node.context[f"TAINT_{taint_identifier}"] = taint


def _spread_taint(
    taint_identifier: str, join_taint_function, sanitize_function, node: Node
):
    node_taint_before = get_taint(taint_identifier, node)

    new_taint = reduce(
        join_taint_function,
        map(get_taint(taint_identifier), node.fathers),
        copy.copy(node_taint_before),
    )

    new_taint = sanitize_function(node, new_taint)

    set_taint(taint_identifier, node, new_taint)

    updated = new_taint != node_taint_before

    return updated


def _is_tainted(taint_identifier: str, node: Node):
    return node.context.get(f"TAINT_{taint_identifier}", None) is not None


TaintType = TypeVar("TaintType")


# this says taint analysis, but it's really just a generic fixed point algorithm
def taint_analysis(
    taint_identifier: str,
    taint_function: Callable[[Node], None],
    sanitise_function: Callable[[Node], bool],
    sink_function: Callable[[Node], bool],
    join_taint_function: Callable[
        [Optional[TaintType], Optional[TaintType]], Optional[TaintType]
    ],
    function_under_test: Function,
):
    """Perform intra procedural taint analysis on a function.

    Args:
        taint_identifier: The identifier to use for the taint.
        taint_function: A function that takes a node and taints it.
        sanitise_function: A function that takes a node and returns whether it sanitises taint.
        sink_function: A function that takes a node and returns whether it is a sink.
        join_taint_function: A function that takes two taints and joins them.
        function_under_test: The function to perform the analysis on.

    Returns:
        Whether the function is tainted.
    """
    # taint
    for node in function_under_test.nodes:
        taint_function(node)

    # spread
    changed = True
    while changed:
        changed = False
        for node in function_under_test.nodes:
            changed |= _spread_taint(
                taint_identifier, join_taint_function, sanitise_function, node
            )

    # check
    for node in function_under_test.nodes:
        if sink_function(node) and _is_tainted(taint_identifier, node):
            yield True, node, get_taint(taint_identifier, node)
