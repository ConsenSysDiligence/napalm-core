from slither.core.declarations.solidity_variables import SolidityFunction
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall
from slither.slithir.operations.operation import Operation
from slither.core.cfg.node import Node

from napalm_core.detectors.util.unused_return_values import detect_unused_return_values


class UncheckedReturnCreate2(AbstractDetector):
    ARGUMENT = "unchecked-create-2"
    HELP = "Unchecked return value for CREATE2 call."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "None"

    WIKI_TITLE = "Unchecked return value create 2"
    WIKI_DESCRIPTION = "The return value of a create 2 call is not checked"

    WIKI_EXPLOIT_SCENARIO = "None"

    WIKI_RECOMMENDATION = "Ensure that the return value of CREATE2 is checked."

    @staticmethod
    def tainted_variables(node: Node):
        for ir in node.irs:
            if (
                isinstance(ir, SolidityCall)
                and isinstance(ir.function, SolidityFunction)
                and ir.function.full_name == "create2(uint256,uint256,uint256,uint256)"
            ):
                return node.variables_written
        return []

    def _scan(self):
        for function in self.compilation_unit.functions:
            result = detect_unused_return_values(self.tainted_variables, function)
            for tainted, node, variables in result:
                yield self.generate_result([node, self.HELP])

    def _detect(self):
        return list(self._scan())
