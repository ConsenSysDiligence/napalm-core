import re
from typing import List, Tuple

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output

PATTERN = re.compile(r"(\^|>|>=|<|<=)?([ ]+)?(\d+)\.(\d+)\.(\d+)")


class Push0SolidityVersionDetector(AbstractDetector):
    ARGUMENT = "push-0-solc-version"
    HELP = "Your solidity version uses PUSH0 which is not supported by all chains."
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.LOW
    LANGUAGE = "solidity"
    WIKI = "None"

    WIKI_TITLE = "Push0 Solidity Version Detector"

    WIKI_DESCRIPTION = (
        """Your solidity version uses PUSH0 which is not supported by all chains."""
    )
    WIKI_RECOMMENDATION = """ Deploy with a version < 0.8.20"""

    def _check_version(self, version: Tuple[str, str, str, str, str]) -> bool:
        op, _, major, minor, inter = version
        if op and op in [">", ">=", "^"]:
            return True
        elif op == "<" and int(major) >= 8 and int(inter) <= 20:
            return False
        elif op == "<=" and int(major) >= 8 and int(inter) < 20:
            return False
        else:
            return True

    def _check_pragma(self, version: str) -> bool:
        versions = PATTERN.findall(version)
        if len(versions) == 1:
            version = versions[0]
            return self._check_version(version)
        elif len(versions) == 2:
            return self._check_version(versions[0]) or self._check_version(versions[1])

    def _detect(self) -> List[Output]:
        results = []
        pragma = self.compilation_unit.pragma_directives

        for p in pragma:
            if len(p.directive) < 1 or p.directive[0] != "solidity":
                continue

            # This is version, so we test if this is disallowed.
            is_above_0_18_19 = self._check_pragma(p.version)

            if is_above_0_18_19:
                results.append(self.generate_result([p, self.HELP]))

        return results
