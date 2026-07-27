from __future__ import annotations

import unittest
from copy import deepcopy

from common.modification_strategy import resolve_modification_strategy
from common.payload_materialization import materialize_payload_edits


def original_packets() -> dict[str, dict]:
    return {
        "packet_000001": {
            "packet_id": "packet_000001",
            "payload_hex": "001122334455",
            "payload_length_bytes": 6,
            "packet_length_bytes": 60,
        },
        "packet_000002": {
            "packet_id": "packet_000002",
            "payload_hex": "9911223388",
            "payload_length_bytes": 5,
            "packet_length_bytes": 59,
        },
    }


def payload_edit(**overrides) -> dict:
    edit = {
        "edit_kind": "canonical_payload",
        "identity_type": "canonical_payload_region",
        "packet_id": "packet_000001",
        "representative_packet_id": "packet_000001",
        "canonical_region_id": "canonical_region_000001",
        "region_id": "canonical_region_000001",
        "region_type": "canonical_payload_region",
        "semantic_element_id": "tcp_stream_000001:bytes_000001_000003",
        "canonical_window_id": "canonical_window_000001",
        "operation": "replace_byte_range",
        "canonical_region_start_offset_bytes": 0,
        "canonical_region_length_bytes": 3,
        "authorized_canonical_start_offset_bytes": 0,
        "authorized_canonical_length_bytes": 3,
        "canonical_start_offset_bytes": 0,
        "offset_from_region_start_bytes": 0,
        "replaced_length_bytes": 2,
        "replacement_format": "hex",
        "replacement": "aabb",
        "replacement_hex": "aabb",
        "replacement_length_bytes": 2,
        "packet_aliases": [
            {
                "packet_id": "packet_000001",
                "alias_id": "packet_000001:payload@1",
                "canonical_region_id": "canonical_region_000001",
                "canonical_start_offset_bytes": 0,
                "payload_start_offset_bytes": 1,
                "length_bytes": 3,
            },
            {
                "packet_id": "packet_000002",
                "alias_id": "packet_000002:payload@1",
                "canonical_region_id": "canonical_region_000001",
                "canonical_start_offset_bytes": 0,
                "payload_start_offset_bytes": 1,
                "length_bytes": 3,
            },
        ],
        "patch_index": 1,
        "prompt_unit_id": "group_000001",
    }
    edit.update(overrides)
    return edit


class ModificationStrategyPayloadTests(unittest.TestCase):
    def test_resolves_known_strategies(self) -> None:
        header_only = resolve_modification_strategy({"pipeline": {"modification_strategy": "header_only_strategy_v1"}})
        payload_only = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "canonical_payload_only_strategy_v1"}}
        )
        hybrid = resolve_modification_strategy(
            {"pipeline": {"modification_strategy": "hybrid_header_canonical_payload_strategy_v1"}}
        )

        self.assertTrue(header_only.allows_header_edits)
        self.assertFalse(header_only.allows_payload_edits)
        self.assertTrue(header_only.requires_payload_preservation)
        self.assertFalse(payload_only.allows_header_edits)
        self.assertTrue(payload_only.allows_payload_edits)
        self.assertTrue(hybrid.allows_header_edits)
        self.assertTrue(hybrid.allows_payload_edits)

    def test_unknown_strategy_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            resolve_modification_strategy({"pipeline": {"modification_strategy": "unsupported_strategy"}})

    def test_rejects_packet_local_calling_convention(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packets()["packet_000001"], [payload_edit()])

    def test_materializes_canonical_payload_edit_to_all_aliases_without_mutating_original(self) -> None:
        originals = original_packets()
        result = materialize_payload_edits(originals, [payload_edit()])

        self.assertEqual("00aabb334455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])
        self.assertEqual("99aabb3388", result["materialized_packets_by_id"]["packet_000002"]["payload_hex"])
        self.assertEqual("001122334455", originals["packet_000001"]["payload_hex"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual(2, len(result["derived_payload_projection_changes"]))
        self.assertEqual([], result["no_effect_edits"])

    def test_materializes_canonical_payload_byte_range_without_retyping_as_full_region(self) -> None:
        result = materialize_payload_edits(
            original_packets(),
            [
                payload_edit(
                    region_id="canonical_region_000001:range_000001",
                    region_type="canonical_payload_byte_range",
                    authorized_canonical_start_offset_bytes=1,
                    authorized_canonical_length_bytes=2,
                    canonical_start_offset_bytes=2,
                    offset_from_region_start_bytes=1,
                    replaced_length_bytes=1,
                    replacement="aa",
                    replacement_hex="aa",
                    replacement_length_bytes=1,
                )
            ],
        )

        self.assertEqual("canonical_payload_byte_range", result["explicit_edits"][0]["region_type"])
        self.assertEqual("canonical_region_000001:range_000001", result["explicit_edits"][0]["region_id"])
        self.assertEqual("001122aa4455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])
        self.assertEqual("991122aa88", result["materialized_packets_by_id"]["packet_000002"]["payload_hex"])

    def test_detects_canonical_payload_no_effect(self) -> None:
        result = materialize_payload_edits(original_packets(), [payload_edit(replacement="1122", replacement_hex="1122")])

        self.assertEqual("001122334455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])
        self.assertEqual(0, len(result["applied_patches"]))
        self.assertEqual(1, len(result["no_effect_edits"]))

    def test_rejects_invalid_payload_hex(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packets(), [payload_edit(replacement="zz", replacement_hex="zz")])

    def test_rejects_invalid_replacement_format(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packets(), [payload_edit(replacement_format="base64")])

    def test_rejects_non_integer_replacement_length_bytes(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(original_packets(), [payload_edit(replacement_length_bytes="2")])

    def test_rejects_manipulated_authorized_bounds(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(
                original_packets(),
                [payload_edit(authorized_canonical_start_offset_bytes=1, canonical_start_offset_bytes=0)],
            )

    def test_rejects_payload_edit_out_of_authorized_range(self) -> None:
        with self.assertRaises(ValueError):
            materialize_payload_edits(
                original_packets(),
                [
                    payload_edit(
                        offset_from_region_start_bytes=2,
                        replaced_length_bytes=2,
                    )
                ],
            )

    def test_records_duplicate_payload_overlap(self) -> None:
        first = payload_edit(patch_index=1)
        second = payload_edit(patch_index=2)
        result = materialize_payload_edits(original_packets(), [second, first])

        self.assertEqual("duplicate", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual([], result["materialization_issues"])

    def test_duplicate_length_changing_edit_applies_once(self) -> None:
        first = payload_edit(patch_index=1, replacement="aabbcc", replacement_hex="aabbcc", replacement_length_bytes=3)
        second = payload_edit(patch_index=2, replacement="aabbcc", replacement_hex="aabbcc", replacement_length_bytes=3)
        result = materialize_payload_edits(original_packets(), [first, second])

        self.assertEqual("00aabbcc334455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])
        self.assertEqual("99aabbcc3388", result["materialized_packets_by_id"]["packet_000002"]["payload_hex"])
        self.assertEqual(7, result["materialized_packets_by_id"]["packet_000001"]["payload_length_bytes"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual(1, len(result["no_effect_edits"]))
        self.assertTrue(result["no_effect_edits"][0]["duplicate_suppressed"])

    def test_records_contradictory_payload_overlap(self) -> None:
        first = payload_edit(patch_index=1, replacement="aabb", replacement_hex="aabb")
        second = payload_edit(patch_index=2, replacement="ccdd", replacement_hex="ccdd")
        result = materialize_payload_edits(original_packets(), [second, first])

        self.assertEqual("contradictory_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("contradictory_payload_overlap", result["materialization_issues"][0]["reason"])
        self.assertEqual(original_packets(), result["materialized_packets_by_id"])

    def test_records_partial_compatible_payload_overlap(self) -> None:
        first = payload_edit(
            patch_index=1,
            replaced_length_bytes=3,
            replacement="aabbcc",
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
        )
        second = payload_edit(
            patch_index=2,
            canonical_start_offset_bytes=1,
            offset_from_region_start_bytes=1,
            replaced_length_bytes=2,
            replacement="bbcc",
            replacement_hex="bbcc",
            replacement_length_bytes=2,
        )
        result = materialize_payload_edits(original_packets(), [second, first])

        self.assertEqual("compatible_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual([], result["materialization_issues"])
        self.assertEqual("00aabbcc4455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])

    def test_records_partial_contradictory_payload_overlap(self) -> None:
        first = payload_edit(
            patch_index=1,
            replaced_length_bytes=3,
            replacement="aabbcc",
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
        )
        second = payload_edit(
            patch_index=2,
            canonical_start_offset_bytes=1,
            offset_from_region_start_bytes=1,
            replaced_length_bytes=2,
            replacement="ddee",
            replacement_hex="ddee",
            replacement_length_bytes=2,
        )
        result = materialize_payload_edits(original_packets(), [second, first])

        self.assertEqual("contradictory_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("contradictory_payload_overlap", result["materialization_issues"][0]["reason"])
        self.assertEqual(original_packets(), result["materialized_packets_by_id"])

    def test_records_length_changing_partial_overlap_as_unsupported(self) -> None:
        first = payload_edit(
            patch_index=1,
            replacement="aabbcc",
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
        )
        second = payload_edit(
            patch_index=2,
            canonical_start_offset_bytes=1,
            offset_from_region_start_bytes=1,
            replaced_length_bytes=1,
            replacement="bb",
            replacement_hex="bb",
            replacement_length_bytes=1,
        )
        result = materialize_payload_edits(original_packets(), [second, first])

        self.assertEqual("unsupported_overlap", result["explicit_edit_relationships"][0]["classification"])
        self.assertEqual("unsupported_payload_overlap", result["materialization_issues"][0]["reason"])
        self.assertEqual([], result["applied_patches"])

    def test_supports_replace_region_and_alternative_alias_offset(self) -> None:
        edit = payload_edit(
            operation="replace_region",
            replaced_length_bytes=3,
            replacement="aabbcc",
            replacement_hex="aabbcc",
            replacement_length_bytes=3,
        )
        edit["packet_aliases"][1]["payload_start_offset_bytes"] = 1
        result = materialize_payload_edits(original_packets(), [edit])

        self.assertEqual("00aabbcc4455", result["materialized_packets_by_id"]["packet_000001"]["payload_hex"])
        self.assertEqual("99aabbcc88", result["materialized_packets_by_id"]["packet_000002"]["payload_hex"])

    def test_rejects_aliases_with_inconsistent_original_bytes(self) -> None:
        originals = original_packets()
        originals["packet_000002"]["payload_hex"] = "99ffff3388"
        with self.assertRaises(ValueError):
            materialize_payload_edits(originals, [payload_edit()])

    def test_original_packet_map_is_immutable(self) -> None:
        originals = original_packets()
        before = deepcopy(originals)
        materialize_payload_edits(originals, [payload_edit()])
        self.assertEqual(before, originals)


if __name__ == "__main__":
    unittest.main()
