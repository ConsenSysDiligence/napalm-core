from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.call_expression import CallExpression
from toolz.curried import pipe, map, filter, reduce
from operator import add


class DoSPushArrayLoop(AbstractDetector):
    ARGUMENT = "dos-push-array-loop"
    HELP = "Potential Denial of Service when users can push to an array that's irreducible and looped over."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = (
        DetectorClassification.MEDIUM
    )  # it's impossible to determine whether a fee is actually used

    WIKI = "None"

    WIKI_TITLE = "Denial of Service on boundless loops over arrays"
    WIKI_DESCRIPTION = "Detects loops over arrays that users can push to, but that can't be popped from"
    WIKI_EXPLOIT_SCENARIO = "An attacker would push elements into the array until it becomes impossible to loop over."
    WIKI_RECOMMENDATION = (
        """Refactor the code to not loop over user controlled arrays."""
    )

    # NOTE: slither doesn't provide a post-domination tree, so we're unable to filter false positives when a pop
    # always follows each push. The following fp prompt is a remediation.
    FALSE_POSITIVE_PROMPT = """
        This is a false positive if the contract pops from the array after pushing to it
        This is a false positive if the contract resets the length of the array.
    """

    def _array_pushes_in_public_functions(self):
        return pipe(
            self.compilation_unit.functions,
            filter(lambda f: f.visibility == "public"),
            map(lambda f: f.nodes),
            reduce(add),
            filter(lambda n: n.type == NodeType.EXPRESSION),
            filter(lambda n: n.expression is not None),
            filter(lambda n: isinstance(n.expression, CallExpression)),
            filter(lambda n: isinstance(n.expression.called, MemberAccess)),
            filter(lambda n: n.expression.called.member_name == "push"),
        )

    def _array_pops_in_any_functions(self):
        # this would improve precision of the module
        pass

    def _loops_over_arrays(self):
        return pipe(
            self.compilation_unit.functions,
            map(lambda f: f.nodes),
            reduce(add),
            filter(lambda n: n.type == NodeType.IFLOOP),
        )

    def _checks(self, pushes, loops):
        tainted_storage_variables = pipe(
            pushes, map(lambda n: (n.state_variables_written, n)), list
        )

        for loop in loops:
            if loop.expression is None:
                continue
            if loop.state_variables_read is None:
                continue

            result = self.generate_result([loop, self.HELP])

            write_locations = []
            for variable in loop.state_variables_read:
                for variables, location in tainted_storage_variables:
                    if variable in variables:
                        write_locations.append(location)
                        result.add_variable(variable)
                        result.add_node(location)

            if not write_locations:
                continue

            yield result

    def _detect(self):
        pushes = list(self._array_pushes_in_public_functions())
        loops = list(self._loops_over_arrays())

        return list(self._checks(pushes, loops))
