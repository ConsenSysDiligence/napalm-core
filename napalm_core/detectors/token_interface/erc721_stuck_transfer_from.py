from operator import add

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from toolz.curried import pipe, map, filter, reduce


class ERC721TransferFromDetector(AbstractDetector):
    ARGUMENT = "erc721-transfer-from-stuck"
    HELP = "transferFrom call on ERC721 can lead to stuck tokens"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "None"

    WIKI_TITLE = "ERC721 transferFrom Calls"
    WIKI_DESCRIPTION = "Detects calls to transferFrom on ERC721 tokens."
    WIKI_EXPLOIT_SCENARIO = "undefined"
    WIKI_RECOMMENDATION = """Use `safeTransferFrom` instead of `transferFrom` which ensures that receiving contracts
can handle receiving ERC721 tokens."""

    def _detect(self):
        results = []

        erc721_contracts = []
        for contract in self.compilation_unit.contracts_derived:
            if "ERC721" in contract.name:
                erc721_contracts.append(contract.id)
                continue
            for parent in contract.inheritance:
                if "ERC721" in parent.name:
                    erc721_contracts.append(contract.id)

        for expression, high_level_calls in pipe(
            self.compilation_unit.contracts_derived,
            map(lambda c: c.functions),  # [[functions]]
            reduce(add),
            map(lambda f: f.nodes),  # [[nodes]]
            reduce(add),
            map(lambda e: (e, e.high_level_calls)),  # [[expression, high_level_calls]]
        ):
            for contract, function in high_level_calls:
                if contract.id in erc721_contracts and function.name == "transferFrom":
                    results.append(self.generate_result([expression, self.HELP]))

        return results
