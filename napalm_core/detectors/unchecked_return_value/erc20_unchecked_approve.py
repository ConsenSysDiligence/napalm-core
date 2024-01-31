from slither.core.declarations import Function
from slither.detectors.abstract_detector import DetectorClassification
from slither.detectors.operations.unused_return_values import UnusedReturnValues
from slither.slithir.operations import HighLevelCall
from slither.slithir.operations.operation import Operation


class UncheckedApprove(UnusedReturnValues):
    ARGUMENT = "unchecked-approve"
    HELP = "Unchecked token approve"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "None"

    WIKI_TITLE = "Unchecked approve"
    WIKI_DESCRIPTION = "The return value of an external approve call is not checked"

    WIKI_EXPLOIT_SCENARIO = "None"

    WIKI_RECOMMENDATION = (
        "Use `SafeERC20`, or ensure that the approve return value is checked."
    )

    def _is_instance(self, ir: Operation) -> bool:
        return (
            isinstance(ir, HighLevelCall)
            and isinstance(ir.function, Function)
            and ir.function.solidity_signature in ["approve(address,uint256)"]
        )
