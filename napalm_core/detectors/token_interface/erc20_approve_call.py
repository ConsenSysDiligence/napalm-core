from operator import add

from slither.core.cfg.node import NodeType
from slither.core.expressions.call_expression import CallExpression
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from toolz.curried import pipe, map, filter, reduce


class ERC20ApproveCall(AbstractDetector):
    ARGUMENT = "erc20-approve-call"
    HELP = "Potential Denial of Service when tokens don't implement approve() consistently ( e.g. USDT )."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "None"

    WIKI_TITLE = "Denial of Service on non-standard ERC20 tokens"
    WIKI_DESCRIPTION = "Detects unsafe usage of approve(), which isn't consistently implemented amongst popular tokens."
    WIKI_EXPLOIT_SCENARIO = "Undefined"
    WIKI_RECOMMENDATION = (
        """Use the safeERC20 library which handles most of the edge cases."""
    )

    @staticmethod
    def _is_erc20(contract):
        for _contract in contract.inheritance:
            if "ERC20" in _contract.name or "EIP20" in _contract.name:
                return True
        if "ERC20" in contract.name or "EIP20" in contract.name:
            return True
        return False

    def _approve_calls(self):
        return pipe(
            self.compilation_unit.functions,
            map(lambda f: f.nodes),
            reduce(add),
            filter(lambda n: n.type == NodeType.EXPRESSION),
            filter(lambda n: n.expression is not None),
            filter(lambda n: isinstance(n.expression, CallExpression)),
            filter(lambda n: n.high_level_calls is not None),
            filter(
                lambda n: filter(
                    lambda c, f: self._is_erc20(c) and f.name == "approve",
                    n.high_level_calls,
                )
            ),
        )

    def _checks(self):
        for call in self._approve_calls():
            yield self.generate_result([call, self.HELP])

    def _detect(self):
        return list(self._checks())
