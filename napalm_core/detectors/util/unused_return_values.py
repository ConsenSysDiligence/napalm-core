from slither.core.declarations.function_contract import FunctionContract
from slither.detectors.abstract_detector import AbstractDetector
from typing import Callable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.variables import TupleVariable
from slither.slithir.operations import Condition
from slither.slithir.operations import SolidityCall
from slither.slithir.operations import Assignment
from slither.core.cfg.node import NodeType, Function, Node

from toolz.curried import pipe, map, filter, reduce, count, concat, itemmap

from napalm_core.detectors.util.taint import taint_analysis, get_taint, set_taint
from slither.analyses.data_dependency.data_dependency import (
    is_dependent_ssa,
    is_dependent,
)

from uuid import uuid4


def detect_unused_return_values(tainted_variables: Callable, function: Function):
    _taint_identifier = f"unused-return-values{uuid4()}"

    def taint_function(node: Node):
        writes = list(tainted_variables(node))
        taint = [(node, writes)] if writes else []
        taint = sanitize_function(node, taint)
        set_taint(_taint_identifier, node, taint)

    def sanitize_function(node: Node, taint):
        def clear_taint_for(variables, _taint):
            for _tainted_node, _tainted_variables in _taint:
                result = _tainted_node, [
                    tainted_variable
                    for tainted_variable in _tainted_variables
                    if not any(
                        is_dependent(read_variable, tainted_variable, node.function)
                        for read_variable in variables
                    )
                ]
                if result[1]:
                    yield result

        def sanitize_if(_taint):
            _taint = _taint[:] if _taint else []
            if node.type != NodeType.IF:
                return _taint
            return list(clear_taint_for(node.variables_read, _taint))

        def sanitize_require(_taint):
            _taint = _taint[:] if _taint else []
            try:
                is_requires_check = (
                    node.type == NodeType.EXPRESSION
                    and node.expression.called.value.full_name == "require(bool)"
                )
            except AttributeError:
                is_requires_check = False
            if not is_requires_check:
                return _taint

            return list(clear_taint_for(node.variables_read, _taint))

        def sanitize_state_variable(_taint):
            _taint = _taint[:] if _taint else []
            if not node.state_variables_written:
                return _taint
            return list(clear_taint_for(node.state_variables_written, _taint))

        sanitized = pipe(
            taint,
            sanitize_if,
            sanitize_require,
            sanitize_state_variable,
        )

        return sanitized

    def sink_function(node: Node):
        return node.type != NodeType.THROW and len(node.sons) == 0

    def join_taint_function(base, other):
        base = base or []
        # base_names = [variable.name for (node, variables) in base for variable in variables]
        other = other or []
        other = [e for e in other if e not in base]
        return base + other

    return taint_analysis(
        taint_identifier=_taint_identifier,
        taint_function=taint_function,
        sanitise_function=sanitize_function,
        sink_function=sink_function,
        join_taint_function=join_taint_function,
        function_under_test=function,
    )
