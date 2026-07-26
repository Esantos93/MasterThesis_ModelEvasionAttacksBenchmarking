from __future__ import annotations

from dataclasses import dataclass
from typing import Any


HEADER_ONLY_STRATEGY = "header_only_strategy_v1"
PAYLOAD_ONLY_STRATEGY = "payload_only_strategy_v1"
HYBRID_STRATEGY = "hybrid_physical_header_canonical_payload_strategy_v1"


@dataclass(frozen=True)
class ModificationCapabilities:
    strategy: str
    allows_header_edits: bool
    allows_payload_edits: bool
    requires_payload_preservation: bool

    #This method returns a plain JSON-compatible record for output metadata.
    def as_metadata(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "allows_header_edits": self.allows_header_edits,
            "allows_payload_edits": self.allows_payload_edits,
            "requires_payload_preservation": self.requires_payload_preservation,
        }


SUPPORTED_MODIFICATION_STRATEGIES: dict[str, ModificationCapabilities] = {
    HEADER_ONLY_STRATEGY: ModificationCapabilities(
        strategy=HEADER_ONLY_STRATEGY,
        allows_header_edits=True,
        allows_payload_edits=False,
        requires_payload_preservation=True,
    ),
    PAYLOAD_ONLY_STRATEGY: ModificationCapabilities(
        strategy=PAYLOAD_ONLY_STRATEGY,
        allows_header_edits=False,
        allows_payload_edits=True,
        requires_payload_preservation=False,
    ),
    HYBRID_STRATEGY: ModificationCapabilities(
        strategy=HYBRID_STRATEGY,
        allows_header_edits=True,
        allows_payload_edits=True,
        requires_payload_preservation=False,
    ),
}


#This function resolves the configured modification strategy into canonical capabilities.
def resolve_modification_strategy(config: dict[str, Any]) -> ModificationCapabilities:
    strategy = config.get("pipeline", {}).get("modification_strategy")
    if not isinstance(strategy, str) or not strategy.strip():
        raise ValueError("pipeline.modification_strategy must be a non-empty string.")
    strategy = strategy.strip()
    capabilities = SUPPORTED_MODIFICATION_STRATEGIES.get(strategy)
    if capabilities is None:
        supported = ", ".join(sorted(SUPPORTED_MODIFICATION_STRATEGIES))
        raise ValueError(
            f"Unsupported pipeline.modification_strategy {strategy!r}. "
            f"Supported values: {supported}."
        )
    return capabilities
