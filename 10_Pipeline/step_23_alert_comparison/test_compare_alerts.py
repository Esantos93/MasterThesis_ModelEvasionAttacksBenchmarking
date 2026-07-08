from __future__ import annotations

import unittest

from step_23_alert_comparison.compare_alerts import DEFAULT_MATCHING_POLICY, compare_alerts_by_comparable_unit


def alert(side: str, index: int, pkt_num: int, signature_key: str, tcp_connection_id: str = "tcp_conn_a") -> dict:
    gid, sid, rev = signature_key.split(":")
    return {
        "normalized_alert_id": f"{side}-{index:06d}",
        "traffic_version": side,
        "pkt_num": pkt_num,
        "packet_id": f"packet_{pkt_num:06d}",
        "reduced_packet_index": pkt_num,
        "original_packet_number": pkt_num,
        "tcp_connection_id": tcp_connection_id,
        "tcp_stream_id": f"{tcp_connection_id}_a_to_b",
        "signature_key": signature_key,
        "gid": int(gid),
        "sid": int(sid),
        "rev": int(rev),
        "detector_source": "ruleset_text",
        "msg": f"signature {signature_key}",
    }


class PacketMatchingComparisonTests(unittest.TestCase):
    def compare(self, pre_alerts: list[dict], post_alerts: list[dict]) -> dict:
        return compare_alerts_by_comparable_unit(pre_alerts, post_alerts, DEFAULT_MATCHING_POLICY)

    def test_same_packet_same_signature_is_failed_evasion(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [alert("post", 1, 10, "1:100:1")],
        )

        self.assertEqual(result["summary"]["failed_evasion_count"], 1)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "Failed Evasion")

    def test_different_signature_on_same_packet_is_alert_mutation(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [alert("post", 1, 10, "1:200:1")],
        )

        self.assertEqual(result["summary"]["alert_mutation_count"], 1)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "Alert Mutation")
        self.assertEqual(result["records"][0]["match_type"], "same_packet_same_tcp_conversation_different_signature")

    def test_same_signature_on_different_packet_same_connection_is_displaced_detection(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [alert("post", 1, 20, "1:100:1")],
        )

        self.assertEqual(result["summary"]["failed_evasion_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "TCP-Conversation Displaced Detection")

    def test_displaced_detection_cannot_reuse_consumed_packet_match(self) -> None:
        result = self.compare(
            [
                alert("pre", 1, 10, "1:100:1"),
                alert("pre", 2, 20, "1:100:1"),
            ],
            [alert("post", 1, 20, "1:100:1")],
        )

        self.assertEqual(result["summary"]["failed_evasion_count"], 1)
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual([record["classification"] for record in result["records"]], ["Failed Evasion", "Successful Evasion"])

    def test_missing_post_alert_in_packet_and_connection_is_successful_evasion(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [],
        )

        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["alert_mutation_count"], 0)
        self.assertEqual(result["summary"]["failed_evasion_count"], 0)

    def test_post_alert_without_pre_alert_is_induced_alert(self) -> None:
        result = self.compare(
            [],
            [alert("post", 1, 10, "1:200:1")],
        )

        self.assertEqual(result["summary"]["induced_alert_count"], 1)
        self.assertEqual(result["induced_alerts"][0]["classification"], "Induced Alert")

    def test_different_signatures_on_different_packets_are_not_alert_mutation(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [alert("post", 1, 20, "1:200:1")],
        )

        self.assertEqual(result["summary"]["alert_mutation_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 1)


if __name__ == "__main__":
    unittest.main()
