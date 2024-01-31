from operator import add

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from toolz.curried import pipe, map, filter, reduce


class ERC721MintDetector(AbstractDetector):
    ARGUMENT = "erc721-mint-stuck"
    HELP = "_mint call on ERC721 can lead to stuck tokens"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "None"

    WIKI_TITLE = "ERC721 _mint Calls"
    WIKI_DESCRIPTION = "Detects calls to _mint on ERC721 tokens."
    WIKI_EXPLOIT_SCENARIO = 'Sample'
    WIKI_RECOMMENDATION = """Use `_safeMint` instead of `_mint` which ensures that receiving contracts
can handle receiving ERC721 tokens."""

    def _scan(self):
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
                if contract.id in erc721_contracts and function.name == "_mint":
                    yield self.generate_result([expression, self.HELP])

    def _detect(self):
        return list(self._scan())
