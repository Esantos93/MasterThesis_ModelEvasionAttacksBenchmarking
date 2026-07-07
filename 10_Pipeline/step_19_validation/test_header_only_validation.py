from __future__ import annotations

import sys
import unittest
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
STEP_ROOT = Path(__file__).resolve().parent
for path in [PIPELINE_ROOT, STEP_ROOT]:
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from validate_merged_traffic import read_json, validate_merged_traffic


HEADER_POLICY = read_json(PIPELINE_ROOT / "step_15_grouping" / "01_editability_policies" / "header_v1.json")


def reference_record() -> dict:
    return {
        "packet_id": "packet_000001",
        "original_packet_number": 1,
        "reduced_packet_index": 1,
        "timestamp_epoch_pcap": 1.0,
        "eth_src": "00:11:22:33:44:55",
        "eth_dst": "66:77:88:99:aa:bb",
        "eth_type": 2048,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "proto": 6,
        "ip_version": 4,
        "transport_protocol": "TCP",
        "ttl": 64,
        "ip_id": 1234,
        "window": 8192,
        "ipv4_header": {"tos": 0, "identification": 1234, "ttl": 64},
        "tcp_header": {"window": 8192},
        "payload_hex": "",
        "payload_length_bytes": 0,
        "packet_length_bytes": 54,
    }


class HeaderOnlyValidationTests(unittest.TestCase):
    def test_accepts_authorized_header_edit(self) -> None:
        record = reference_record()
        record["ttl"] = 1
        record["ipv4_header"]["ttl"] = 1
        merged = {
            "group_outcomes": {
                "accepted_groups": [{"prompt_unit_id": "group_000001", "packet_ids": ["packet_000001"]}],
                "llm_output_failure_groups": [],
            },
            "patch_application": {
                "applied_patches": [
                    {
                        "edit_kind": "physical_header",
                        "identity_type": "physical_header_region",
                        "region_type": "header_field",
                        "packet_id": "packet_000001",
                        "field": "ipv4.ttl",
                        "operation": "replace_uint",
                        "replacement_format": "uint",
                        "original_value": 64,
                        "replacement": 1,
                        "constraints": {"min": 1, "max": 255},
                        "prompt_unit_id": "group_000001",
                    }
                ]
            },
            "traffic": [record],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id", "original_packet_number", "reduced_packet_index", "timestamp_epoch_pcap"],
            required_fields=[
                "packet_id",
                "original_packet_number",
                "reduced_packet_index",
                "timestamp_epoch_pcap",
                "eth_src",
                "eth_dst",
                "eth_type",
                "src_ip",
                "dst_ip",
                "proto",
                "ip_version",
                "transport_protocol",
                "payload_hex",
                "payload_length_bytes",
                "packet_length_bytes",
            ],
        )
        self.assertEqual(0, result["summary"]["error_count"])
        self.assertEqual(1, result["summary"]["accepted_packet_count"])

    def test_rejects_payload_edit_in_header_only_output(self) -> None:
        merged = {
            "group_outcomes": {"accepted_groups": [], "llm_output_failure_groups": []},
            "patch_application": {
                "applied_patches": [
                    {
                        "edit_kind": "canonical_payload",
                        "packet_id": "packet_000001",
                        "prompt_unit_id": "group_000001",
                    }
                ]
            },
            "traffic": [reference_record()],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference_record()},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(1, result["summary"]["error_count"])
        self.assertEqual("payload_edits_present_in_header_only_output", result["root_issues"][0]["reason"])

    def test_preserves_llm_output_failure_packet_for_reconstruction(self) -> None:
        reference = reference_record()
        merged = {
            "group_outcomes": {
                "accepted_groups": [],
                "llm_output_failure_groups": [
                    {
                        "prompt_unit_id": "group_000001",
                        "packet_ids": ["packet_000001"],
                    }
                ],
            },
            "patch_application": {"applied_patches": []},
            "traffic": [reference_record()],
        }
        result = validate_merged_traffic(
            merged_json=merged,
            reference_by_packet_id={"packet_000001": reference},
            header_policy=HEADER_POLICY,
            immutable_fields=["packet_id"],
            required_fields=["packet_id", "payload_hex", "payload_length_bytes", "packet_length_bytes"],
        )
        self.assertEqual(0, result["summary"]["accepted_packet_count"])
        self.assertEqual(1, result["summary"]["rejected_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_packet_count"])
        self.assertEqual(1, result["summary"]["llm_output_failure_preserved_packet_count"])
        self.assertEqual(1, result["summary"]["reconstruction_packet_count"])
        self.assertEqual([reference], result["reconstruction_packets"])


if __name__ == "__main__":
    unittest.main()
