from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.slithir.operations.operation import Operation
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.expressions.binary_operation import (
    BinaryOperation,
    BinaryOperationType,
)
from slither.slithir.operations.binary import Binary, BinaryType

from napalm_core.detectors.util.unused_return_values import detect_unused_return_values


class UncheckedEquationModifierDetector(AbstractDetector):
    ARGUMENT = "unchecked-equation-modifier"
    HELP = "Potential lack of input control due to missing requires checks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = (
        DetectorClassification.HIGH
    )  # it's impossible to determine whether a fee is actually used

    WIKI = "None"

    WIKI_TITLE = "Potential lack of input control due to missing requires checks."
    WIKI_DESCRIPTION = (
        "Detects strict equations in modifiers that are not checked / used."
    )
    WIKI_EXPLOIT_SCENARIO = "Undefined"
    WIKI_RECOMMENDATION = (
        """Ensure all checks are performed, for example, using require."""
    )


    @staticmethod
    def _tainted_variables(node):
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.EQUAL:
                return node.variables_written
        return []

    def _scan(self):
        for function in self.compilation_unit.modifiers:
            for node in function.nodes:
                if (
                    isinstance(node.expression, BinaryOperation)
                    and node.expression.type == BinaryOperationType.EQUAL
                    and not node.variables_written
                ):
                    yield self.generate_result([node, self.HELP])

            result = detect_unused_return_values(self._tainted_variables, function)
            for tainted, node, variables in result:
                if variables:
                    yield self.generate_result([node, self.HELP])

    def _detect(self):
        return list(self._scan())
