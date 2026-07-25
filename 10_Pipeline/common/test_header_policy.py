from __future__ import annotations

from copy import deepcopy
import unittest

from common.header_policy import (
    canonicalize_derived_header_changes,
    materialize_header_edits,
)


def packet_record() -> dict:
    # This compact packet contains the structured and flat fields affected by
    # conservative header-only materialization.
    return {
        "packet_id": "packet_000001",
        "tos": 0,
        "ttl": 64,
        "window": 8192,
        "tcp_flags": 0,
        "tcp_flags_str": "",
        "ipv4_header": {
            "tos": 0,
            "dscp": 0,
            "ecn": 0,
            "ttl": 64,
            "flags_fragment_offset": 0,
            "flags": {
                "reserved": False,
                "dont_fragment": False,
                "more_fragments": False,
            },
            "fragment_offset_units": 0,
            "fragmented": False,
            "fragment_offset_bytes": 0,
        },
        "tcp_header": {
            "window": 8192,
            "flags": {
                "raw": 0,
                "ns": False,
                "cwr": False,
                "ece": False,
                "urg": False,
                "ack": False,
                "psh": False,
                "rst": False,
                "syn": False,
                "fin": False,
            },
        },
        "payload_hex": "abcd",
        "payload_length_bytes": 2,
    }


def edit(field: str, replacement: int, patch_index: int = 1) -> dict:
    # This helper mirrors the explicit header edit shape emitted by Step 18.
    return {
        "edit_kind": "physical_header",
        "packet_id": "packet_000001",
        "field": field,
        "operation": "replace_uint",
        "replacement_format": "uint",
        "replacement": replacement,
        "patch_index": patch_index,
        "prompt_unit_id": "group_000001",
    }


class HeaderMaterializationTests(unittest.TestCase):
    def test_materializes_ttl_without_unexpected_derivatives(self) -> None:
        result = materialize_header_edits(packet_record(), [edit("ipv4.ttl", 1)])
        packet = result["materialized_packet"]
        self.assertEqual(1, packet["ttl"])
        self.assertEqual(1, packet["ipv4_header"]["ttl"])
        self.assertEqual([], result["no_effect_edits"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual([], result["derived_header_changes"])

    def test_materializes_tos_and_records_dscp_ecn_derivatives(self) -> None:
        result = materialize_header_edits(packet_record(), [edit("ipv4.tos", 7)])
        packet = result["materialized_packet"]
        self.assertEqual(7, packet["tos"])
        self.assertEqual(7, packet["ipv4_header"]["tos"])
        self.assertEqual(1, packet["ipv4_header"]["dscp"])
        self.assertEqual(3, packet["ipv4_header"]["ecn"])
        derived_fields = [
            item["derived_field"] for item in result["derived_header_changes"]
        ]
        self.assertEqual(["ipv4.dscp", "ipv4.ecn"], derived_fields)
        self.assertEqual([], result["no_effect_edits"])
        self.assertEqual(1, len(result["applied_patches"]))

    def test_no_effect_is_computed_sequentially(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [
                edit("tcp.window", 0, patch_index=1),
                edit("tcp.window", 0, patch_index=2),
            ],
        )
        packet = result["materialized_packet"]
        self.assertEqual(0, packet["window"])
        self.assertEqual(0, packet["tcp_header"]["window"])
        self.assertEqual(1, len(result["applied_patches"]))
        self.assertEqual(1, len(result["no_effect_edits"]))
        self.assertEqual(2, result["no_effect_edits"][0]["patch_index"])

    def test_contradictory_overlap_is_registered(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [
                edit("ipv4.ttl", 1, patch_index=1),
                edit("ipv4.ttl", 2, patch_index=2),
            ],
        )
        self.assertEqual(2, result["materialized_packet"]["ttl"])
        relationships = result["explicit_edit_relationships"]
        self.assertEqual("contradictory_overlap", relationships[0]["classification"])

    def test_composite_fragment_word_updates_and_traces_subfields(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [edit("ipv4.flags_fragment_offset", 0x6003)],
        )
        ipv4 = result["materialized_packet"]["ipv4_header"]
        self.assertTrue(ipv4["flags"]["dont_fragment"])
        self.assertTrue(ipv4["flags"]["more_fragments"])
        self.assertEqual(3, ipv4["fragment_offset_units"])
        derived_fields = {
            item["derived_field"] for item in result["derived_header_changes"]
        }
        self.assertIn("ipv4.flags.dont_fragment", derived_fields)
        self.assertIn("ipv4.flags.more_fragments", derived_fields)
        self.assertIn("ipv4.fragment_offset_units", derived_fields)

    def test_fragment_subfield_updates_composite_word(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [edit("ipv4.flags.dont_fragment", 1)],
        )
        self.assertIs(
            True,
            result["materialized_packet"]["ipv4_header"]["flags"]["dont_fragment"],
        )
        self.assertEqual(
            0x4000,
            result["materialized_packet"]["ipv4_header"]["flags_fragment_offset"],
        )
        self.assertIn(
            "ipv4.flags_fragment_offset",
            {item["derived_field"] for item in result["derived_header_changes"]},
        )

    def test_coupled_contradiction_and_overwrite_are_registered(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [
                edit("ipv4.flags_fragment_offset", 0x4000, patch_index=1),
                edit("ipv4.flags.dont_fragment", 0, patch_index=2),
            ],
        )
        relationship = result["explicit_edit_relationships"][0]
        self.assertEqual("contradictory_overlap", relationship["classification"])
        self.assertIn(
            "ipv4.flags.dont_fragment",
            relationship["overwritten_derived_fields"],
        )
        overwritten = [
            item
            for item in result["derived_header_changes"]
            if item["derived_field"] == "ipv4.flags.dont_fragment"
        ]
        self.assertEqual("overwritten", overwritten[0]["effect"])
        self.assertEqual(2, overwritten[0]["overwritten_by_patch_index"])
        self.assertFalse(result["explicit_edits"][1]["no_effect"])

    def test_tcp_flag_aliases_are_derived(self) -> None:
        result = materialize_header_edits(
            packet_record(),
            [edit("tcp.flags.syn", 1)],
        )
        self.assertIs(
            True,
            result["materialized_packet"]["tcp_header"]["flags"]["syn"],
        )
        derived_fields = {
            item["derived_field"] for item in result["derived_header_changes"]
        }
        self.assertTrue(
            {"tcp.flags.raw", "record.tcp_flags", "record.tcp_flags_str"}
            <= derived_fields
        )
        self.assertEqual("S", result["materialized_packet"]["tcp_flags_str"])

    def test_input_is_ordered_and_original_is_not_mutated(self) -> None:
        original = packet_record()
        snapshot = deepcopy(original)
        result = materialize_header_edits(
            original,
            [
                edit("ipv4.flags.more_fragments", 1, patch_index=2),
                edit("ipv4.flags.dont_fragment", 1, patch_index=1),
            ],
        )
        self.assertEqual(snapshot, original)
        self.assertEqual(
            [1, 2],
            [item["patch_index"] for item in result["explicit_edits"]],
        )

    def test_invalid_and_duplicate_patch_indexes_fail(self) -> None:
        invalid = edit("ipv4.ttl", 1)
        invalid["patch_index"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            materialize_header_edits(packet_record(), [invalid])

        with self.assertRaisesRegex(ValueError, "Duplicate patch_index"):
            materialize_header_edits(
                packet_record(),
                [
                    edit("ipv4.ttl", 1, patch_index=1),
                    edit("tcp.window", 1, patch_index=1),
                ],
            )

    def test_multiple_prompt_unit_owners_fail(self) -> None:
        first = edit("ipv4.ttl", 1, patch_index=1)
        second = edit("tcp.window", 0, patch_index=2)
        second["prompt_unit_id"] = "group_000002"
        with self.assertRaisesRegex(ValueError, "multiple prompt_unit_id"):
            materialize_header_edits(packet_record(), [first, second])

    def test_canonical_derived_sort_accepts_absent_or_null_overwrite_index(self) -> None:
        changes = [
            {
                "prompt_unit_id": "group_000001",
                "patch_index": 2,
                "derived_field": "ipv4.flags_fragment_offset",
                "effect": "created",
                "overwritten_by_patch_index": None,
            },
            {
                "prompt_unit_id": "group_000001",
                "patch_index": 1,
                "derived_field": "ipv4.flags.more_fragments",
                "effect": "created",
            },
        ]
        canonical = canonicalize_derived_header_changes(changes)
        self.assertEqual([1, 2], [item["patch_index"] for item in canonical])


if __name__ == "__main__":
    unittest.main()
