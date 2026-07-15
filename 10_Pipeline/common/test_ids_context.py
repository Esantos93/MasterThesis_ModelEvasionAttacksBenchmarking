from __future__ import annotations

import unittest

from common.ids_context import (
    IDS_CONTEXT_SCHEMA_VERSION,
    PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
    project_ids_context,
    validate_ids_context,
    validate_pre_snort_context_bundle,
)
from common.prompt_projection import (
    build_compact_prompt_input,
    load_prompt_input_json_data_structure,
)


def text_ids_record() -> dict:
    return {
        "detector_source": "ruleset_text",
        "gid": 1,
        "sid": 1001,
        "rev": 2,
        "message": "Example text rule",
        "rule_declaration": "alert tcp any any -> any any (msg:\"Example\"; sid:1001; rev:2;)",
        "tcp_connection_id": "tcp_connection_000001",
        "anchor_packet_ids": ["packet_000010"],
        "tcp_connection_packet_ids_in_prompt": ["packet_000010", "packet_000011"],
    }


def ids_context() -> dict:
    return {
        "schema_version": IDS_CONTEXT_SCHEMA_VERSION,
        "records": [
            text_ids_record(),
            {
                "detector_source": "ruleset_so",
                "gid": 3,
                "sid": 17775,
                "rev": 6,
                "message": "Shikata Ga Nai decoder detected",
                "so_rule_stub": "alert ip (msg:\"Shikata\"; soid:17775; gid:3; sid:17775; rev:6;)",
                "security_context": {
                    "summary": "The detector targets polymorphic shellcode decoding behavior."
                },
                "tcp_connection_id": "tcp_connection_000002",
                "anchor_packet_ids": ["packet_000020"],
                "tcp_connection_packet_ids_in_prompt": ["packet_000021"],
            },
            {
                "detector_source": "builtin_decoder_or_inspector",
                "gid": 119,
                "sid": 228,
                "rev": 1,
                "message": "server response before client request",
                "inspector": "http_inspect",
                "semantic_description": (
                    "Snort observed an HTTP response before associating a preceding client request."
                ),
                "tcp_connection_id": "tcp_connection_000003",
                "anchor_packet_ids": ["packet_000030"],
                "tcp_connection_packet_ids_in_prompt": ["packet_000030"],
            },
        ],
    }


def pre_bundle() -> dict:
    return {
        "schema_version": PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
        "metadata": {
            "snort_version": "3.11.1.0",
            "detector_policy": "security-ips",
            "snaplen": 65535,
            "builtin_rules_enabled": True,
            "ruleset_identifier": "cisco_full_set_test",
            "source_artifacts": ["alert_json.txt", "selected_traffic.pcap"],
            "source_hashes": {
                "alert_json.txt": "abc123",
                "selected_traffic.pcap": "def456",
            },
            "mapping_policy": "tcp_connection_propagation_v1",
        },
        "detector_definitions": [
            {
                "detector_source": "ruleset_text",
                "gid": 1,
                "sid": 1001,
                "rev": 2,
                "message": "Example text rule",
                "rule_declaration": "alert tcp any any -> any any (sid:1001; rev:2;)",
                "security_context": {
                    "cve_ids": ["CVE-2000-0001"],
                    "mitre_attack_ids": ["T0001"],
                    "source_urls": ["https://example.invalid/rule"],
                },
            }
        ],
        "alerts": [
            {
                "alert_id": "pre_alert_000001",
                "gid": 1,
                "sid": 1001,
                "rev": 2,
                "message": "Example text rule",
                "anchor_packet_ids": ["packet_000010"],
                "timestamp": "2026-07-16T10:00:00Z",
                "event_data": {"src_addr": "192.0.2.1"},
            }
        ],
    }


class IdsContextTest(unittest.TestCase):
    def test_accepts_all_detector_source_shapes(self) -> None:
        validate_ids_context(ids_context())

    def test_rejects_hidden_metadata_in_model_visible_context(self) -> None:
        context = ids_context()
        context["records"][0]["source_urls"] = ["https://example.invalid"]
        with self.assertRaisesRegex(ValueError, "not model-visible"):
            validate_ids_context(context)

    def test_projects_only_validated_model_visible_context(self) -> None:
        context = ids_context()
        self.assertEqual(project_ids_context(context), context)

    def test_validates_pre_bundle_and_detector_references(self) -> None:
        validate_pre_snort_context_bundle(pre_bundle())

        bundle = pre_bundle()
        bundle["alerts"][0]["sid"] = 9999
        with self.assertRaisesRegex(ValueError, "missing detector definition"):
            validate_pre_snort_context_bundle(bundle)

    def test_rejects_external_summary_for_non_so_definition(self) -> None:
        bundle = pre_bundle()
        bundle["detector_definitions"][0]["security_context"]["summary"] = "Not allowed for text rules."
        with self.assertRaisesRegex(ValueError, "allowed only for ruleset_so"):
            validate_pre_snort_context_bundle(bundle)

    def test_baseline_projection_ignores_ids_context(self) -> None:
        prompt_unit = {"schema_version": "compact_modification_unit_v2", "ids_context": ids_context()}
        baseline = load_prompt_input_json_data_structure("baseline_input_profile_v1")
        without_context = build_compact_prompt_input(
            prompt_unit={"schema_version": "compact_modification_unit_v2"},
            structure=baseline,
        )
        with_context = build_compact_prompt_input(prompt_unit=prompt_unit, structure=baseline)
        self.assertEqual(with_context, without_context)
        self.assertNotIn("ids_context", with_context)

    def test_prompt_engineering_projection_includes_ids_context(self) -> None:
        prompt_unit = {"schema_version": "compact_modification_unit_v2", "ids_context": ids_context()}
        structure = load_prompt_input_json_data_structure("prompt_engineering_input_profile_v1")
        projected = build_compact_prompt_input(prompt_unit=prompt_unit, structure=structure)
        self.assertEqual(projected["ids_context"], ids_context())


if __name__ == "__main__":
    unittest.main()
