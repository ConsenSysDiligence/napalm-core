from typing import List

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.type_helpers import HighLevelCallType
from toolz.curried import pipe, filter, count


class ChainlinkCircuitBreakerDetector(AbstractDetector):
    ARGUMENT = "chainlink-circuit-breaker"
    HELP = "Vulnerable to exploitation in case of a Chainlink circuit breaker event."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "None"

    WIKI_TITLE = "Chainlink Circuit Breaker"
    WIKI_DESCRIPTION = """
    Detects unsafe usage of chainlink oracles, where the contract might be vulnerable in case of a circuit breaker event.
    """

    WIKI_EXPLOIT_SCENARIO = "Undefined"
    WIKI_RECOMMENDATION = """Check the result of the chainlink oracle call to ensure it is within the expected range."""

    def _calls(self, function) -> List[HighLevelCallType]:
        for node in function.nodes:
            for high_level_call in node.high_level_calls:
                yield node, high_level_call

    def _checks(self):
        for function in self.compilation_unit.functions:
            _calls = list(self._calls(function))

            # exit(0)
            latest_round_calls = pipe(
                _calls,
                filter(
                    lambda _high_level_call: _high_level_call[1][1].name
                    == "latestRoundData"
                ),
                list,
            )
            min_value = pipe(
                _calls,
                filter(
                    lambda _high_level_call: _high_level_call[1][1].name == "minValue"
                ),
                count,
            )
            max_value = pipe(
                _calls,
                filter(
                    lambda _high_level_call: _high_level_call[1][1].name == "maxValue"
                ),
                count,
            )

            if not latest_round_calls:
                continue
            if min_value and max_value:
                # Improve: check if min_value and max_value are used
                # tbh: if both are queried then it's likely that they're used in a check
                continue

            for call in latest_round_calls:
                yield self.generate_result([call[0], self.HELP])

    def _detect(self):
        return list(self._checks())
