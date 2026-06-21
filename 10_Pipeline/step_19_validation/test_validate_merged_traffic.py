import unittest

from step_19_validation.validate_merged_traffic import validate_merged_traffic


def packet(packet_id: str, payload_hex: str) -> dict:
    return {
        "packet_id": packet_id,
        "payload_hex": payload_hex,
        "payload_length_bytes": len(payload_hex) // 2,
    }


class UncoveredPacketClassificationTests(unittest.TestCase):
    def validate(self, merged_record: dict, reference_record: dict) -> dict:
        return validate_merged_traffic(
            merged_json={"traffic": [merged_record], "group_outcomes": {}},
            reference_by_packet_id={reference_record["packet_id"]: reference_record},
            immutable_fields=[],
            required_fields=[],
        )

    def test_unchanged_empty_payload_is_preserved_non_llm_processed(self):
        reference = packet("packet_001", "")
        result = self.validate(dict(reference), reference)

        self.assertEqual(result["summary"]["uncovered_by_step17_packet_count"], 1)
        self.assertEqual(result["summary"]["preserved_non_llm_processed_packets_count"], 1)
        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 0)
        self.assertEqual(result["summary"]["warning_count"], 0)

    def test_uncovered_packet_with_payload_is_unexpected(self):
        reference = packet("packet_002", "aa")
        result = self.validate(dict(reference), reference)

        self.assertEqual(result["summary"]["preserved_non_llm_processed_packets_count"], 0)
        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 1)
        self.assertEqual(result["root_issues"][0]["reason"], "unexpectedly_uncovered_packets")

    def test_changed_empty_payload_packet_is_unexpected(self):
        reference = packet("packet_003", "")
        merged = {**reference, "tcp_flags_str": "A"}
        result = self.validate(merged, reference)

        self.assertEqual(result["summary"]["preserved_non_llm_processed_packets_count"], 0)
        self.assertEqual(result["summary"]["unexpectedly_uncovered_packet_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 1)


if __name__ == "__main__":
    unittest.main()
