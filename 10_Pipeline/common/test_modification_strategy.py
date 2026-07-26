import unittest

from common.modification_strategy import (
    CANONICAL_PAYLOAD_ONLY_STRATEGY,
    HEADER_ONLY_STRATEGY,
    HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY,
    SUPPORTED_MODIFICATION_STRATEGIES,
    resolve_modification_strategy,
)


def config_for(strategy: object) -> dict[str, object]:
    return {"pipeline": {"modification_strategy": strategy}}


class ModificationStrategyTests(unittest.TestCase):
    def test_supported_strategy_names_are_exactly_the_canonical_contract(self) -> None:
        self.assertEqual(
            {
                "header_only_strategy_v1",
                "canonical_payload_only_strategy_v1",
                "hybrid_header_canonical_payload_strategy_v1",
            },
            set(SUPPORTED_MODIFICATION_STRATEGIES),
        )
        self.assertEqual("header_only_strategy_v1", HEADER_ONLY_STRATEGY)
        self.assertEqual(
            "canonical_payload_only_strategy_v1",
            CANONICAL_PAYLOAD_ONLY_STRATEGY,
        )
        self.assertEqual(
            "hybrid_header_canonical_payload_strategy_v1",
            HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY,
        )

    def test_resolves_header_only_capabilities(self) -> None:
        capabilities = resolve_modification_strategy(config_for(HEADER_ONLY_STRATEGY))

        self.assertEqual(HEADER_ONLY_STRATEGY, capabilities.strategy)
        self.assertTrue(capabilities.allows_header_edits)
        self.assertFalse(capabilities.allows_payload_edits)
        self.assertTrue(capabilities.requires_payload_preservation)

    def test_resolves_canonical_payload_only_capabilities(self) -> None:
        capabilities = resolve_modification_strategy(
            config_for(CANONICAL_PAYLOAD_ONLY_STRATEGY)
        )

        self.assertEqual(CANONICAL_PAYLOAD_ONLY_STRATEGY, capabilities.strategy)
        self.assertFalse(capabilities.allows_header_edits)
        self.assertTrue(capabilities.allows_payload_edits)
        self.assertFalse(capabilities.requires_payload_preservation)

    def test_resolves_hybrid_capabilities(self) -> None:
        capabilities = resolve_modification_strategy(
            config_for(HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY)
        )

        self.assertEqual(
            HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY,
            capabilities.strategy,
        )
        self.assertTrue(capabilities.allows_header_edits)
        self.assertTrue(capabilities.allows_payload_edits)
        self.assertFalse(capabilities.requires_payload_preservation)

    def test_metadata_is_json_compatible_and_capability_based(self) -> None:
        capabilities = resolve_modification_strategy(
            config_for(HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY)
        )

        self.assertEqual(
            {
                "strategy": HYBRID_HEADER_CANONICAL_PAYLOAD_STRATEGY,
                "allows_header_edits": True,
                "allows_payload_edits": True,
                "requires_payload_preservation": False,
            },
            capabilities.as_metadata(),
        )

    def test_rejects_retired_strategy_names_without_aliases(self) -> None:
        retired_names = (
            "payload_only_strategy_v1",
            "hybrid_physical_header_canonical_payload_strategy_v1",
            "hybrid_strategy_v1",
        )

        for retired_name in retired_names:
            with self.subTest(retired_name=retired_name):
                with self.assertRaisesRegex(
                    ValueError,
                    "Unsupported pipeline.modification_strategy",
                ):
                    resolve_modification_strategy(config_for(retired_name))

    def test_rejects_missing_or_blank_strategy(self) -> None:
        invalid_configs = (
            {},
            {"pipeline": {}},
            config_for(None),
            config_for("   "),
        )

        for config in invalid_configs:
            with self.subTest(config=config):
                with self.assertRaisesRegex(
                    ValueError,
                    "pipeline.modification_strategy must be a non-empty string",
                ):
                    resolve_modification_strategy(config)

    def test_trims_canonical_strategy_value(self) -> None:
        capabilities = resolve_modification_strategy(
            config_for(f"  {CANONICAL_PAYLOAD_ONLY_STRATEGY}  ")
        )

        self.assertEqual(CANONICAL_PAYLOAD_ONLY_STRATEGY, capabilities.strategy)


if __name__ == "__main__":
    unittest.main()
