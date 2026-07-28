from __future__ import annotations

import unittest

from step_23_alert_comparison.compare_alerts import (
    DEFAULT_MATCHING_POLICY,
    STRICT_DELAYED_EMISSION_MATCH_TYPE,
    compare_alerts_by_comparable_unit,
)


def alert(
    side: str,
    index: int,
    pkt_num: int,
    signature_key: str,
    tcp_connection_id: str = "tcp_conn_a",
    *,
    timestamp: str = "07/06-12:00:00.000001",
    proto: str = "TCP",
    src_addr: str = "10.0.0.1",
    src_port: int = 1111,
    dst_addr: str = "10.0.0.2",
    dst_port: int = 2222,
    packet_anchor_src_addr: str | None = None,
    packet_anchor_src_port: int | None = None,
    packet_anchor_dst_addr: str | None = None,
    packet_anchor_dst_port: int | None = None,
) -> dict:
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
        "timestamp": timestamp,
        "proto": proto,
        "src_addr": src_addr,
        "src_port": src_port,
        "dst_addr": dst_addr,
        "dst_port": dst_port,
        "packet_anchor_tcp_connection_id": tcp_connection_id,
        "packet_anchor_tcp_stream_id": f"{tcp_connection_id}_a_to_b",
        "packet_anchor_proto": proto,
        "packet_anchor_src_addr": packet_anchor_src_addr if packet_anchor_src_addr is not None else src_addr,
        "packet_anchor_src_port": packet_anchor_src_port if packet_anchor_src_port is not None else src_port,
        "packet_anchor_dst_addr": packet_anchor_dst_addr if packet_anchor_dst_addr is not None else dst_addr,
        "packet_anchor_dst_port": packet_anchor_dst_port if packet_anchor_dst_port is not None else dst_port,
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

    def test_different_signature_on_same_packet_is_alert_signature_mutation(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1")],
            [alert("post", 1, 10, "1:200:1")],
        )

        self.assertEqual(result["summary"]["alert_mutation_count"], 1)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "Alert-Signature Mutation")
        self.assertEqual(result["records"][0]["match_type"], "same_packet_same_tcp_conversation_different_signature")

    def test_same_signature_on_different_packet_same_connection_is_displaced_detection(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", timestamp="07/06-12:00:00.000001")],
            [alert("post", 1, 20, "1:100:1", timestamp="07/06-12:00:00.000002")],
        )

        self.assertEqual(result["summary"]["failed_evasion_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "TCP-Conversation Displaced Detection")
        self.assertEqual(result["records"][0]["match_type"], "same_tcp_conversation_same_signature_different_packet")

    def test_strict_delayed_emission_different_packet_and_apparent_connection_is_packet_anchor_shifted(self) -> None:
        result = self.compare(
            [alert("pre", 1, 40080, "1:18757:8", "tcp_conn_pre", timestamp="07/06-17:19:02.802509", src_port=53966, dst_port=444)],
            [
                alert(
                    "post",
                    1,
                    99291,
                    "1:18757:8",
                    "tcp_conn_post",
                    timestamp="07/06-17:19:02.802509",
                    src_port=53966,
                    dst_port=444,
                    packet_anchor_src_port=1260,
                )
            ],
        )

        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["snort_event_packet_anchor_shift_count"], 1)
        self.assertEqual(result["summary"]["strict_delayed_emission_match_count"], 1)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["alert_mutation_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "Packet-Anchor shifted")
        self.assertEqual(result["records"][0]["matching_phase"], 2)
        self.assertEqual(result["records"][0]["delayed_emission_match"]["timestamp_policy"], "exact_string_equality_no_tolerance")
        self.assertFalse(result["records"][0]["delayed_emission_match"]["post_packet_anchor_matches_alert_event_tuple"])

    def test_strict_delayed_emission_same_packet_anchor_connection_remains_tcp_displaced_detection(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", "tcp_conn_a", timestamp="07/06-12:00:00.000001")],
            [alert("post", 1, 20, "1:100:1", "tcp_conn_a", timestamp="07/06-12:00:00.000001")],
        )

        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 1)
        self.assertEqual(result["summary"]["snort_event_packet_anchor_shift_count"], 0)
        self.assertEqual(result["records"][0]["classification"], "TCP-Conversation Displaced Detection")
        self.assertEqual(result["records"][0]["match_type"], STRICT_DELAYED_EMISSION_MATCH_TYPE)

    def test_five_delayed_emission_fixtures_are_consumed_one_to_one_before_mutation(self) -> None:
        pre_alerts = [
            alert("pre", 1, 40080, "1:18757:8", "tcp_conn_a", timestamp="07/06-17:19:02.802509", src_addr="192.168.10.8", src_port=53966, dst_addr="205.174.165.73", dst_port=444),
            alert("pre", 2, 40080, "1:46983:1", "tcp_conn_a", timestamp="07/06-17:19:02.802509", src_addr="192.168.10.8", src_port=53966, dst_addr="205.174.165.73", dst_port=444),
            alert("pre", 3, 40080, "1:30228:2", "tcp_conn_a", timestamp="07/06-17:19:02.556011", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=53966),
            alert("pre", 4, 98970, "1:30228:2", "tcp_conn_b", timestamp="07/06-17:28:33.276724", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=54119),
            alert("pre", 5, 99821, "1:30228:2", "tcp_conn_c", timestamp="07/06-18:04:25.659476", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=1260),
        ]
        post_alerts = [
            alert("post", 1, 99291, "1:30228:2", "tcp_conn_x", timestamp="07/06-17:19:02.556011", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=53966, packet_anchor_src_addr="192.168.10.8", packet_anchor_src_port=1260, packet_anchor_dst_addr="205.174.165.73", packet_anchor_dst_port=444),
            alert("post", 2, 99291, "1:18757:8", "tcp_conn_x", timestamp="07/06-17:19:02.802509", src_addr="192.168.10.8", src_port=53966, dst_addr="205.174.165.73", dst_port=444, packet_anchor_src_addr="192.168.10.8", packet_anchor_src_port=1260, packet_anchor_dst_addr="205.174.165.73", packet_anchor_dst_port=444),
            alert("post", 3, 99291, "1:46983:1", "tcp_conn_x", timestamp="07/06-17:19:02.802509", src_addr="192.168.10.8", src_port=53966, dst_addr="205.174.165.73", dst_port=444, packet_anchor_src_addr="192.168.10.8", packet_anchor_src_port=1260, packet_anchor_dst_addr="205.174.165.73", packet_anchor_dst_port=444),
            alert("post", 4, 99711, "1:30228:2", "tcp_conn_x", timestamp="07/06-17:28:33.276724", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=54119, packet_anchor_src_addr="205.174.165.73", packet_anchor_src_port=444, packet_anchor_dst_addr="192.168.10.8", packet_anchor_dst_port=1260),
            alert("post", 5, 99831, "1:30228:2", "tcp_conn_y", timestamp="07/06-18:04:25.659476", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=1260, packet_anchor_src_addr="172.16.0.1", packet_anchor_src_port=50964, packet_anchor_dst_addr="192.168.10.50", packet_anchor_dst_port=80),
            alert("post", 6, 98970, "116:423:1", "tcp_conn_b", timestamp="07/06-17:40:33.631536", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=54119),
            alert("post", 7, 99821, "116:423:1", "tcp_conn_c", timestamp="07/06-18:46:09.364731", src_addr="205.174.165.73", src_port=444, dst_addr="192.168.10.8", dst_port=1260),
        ]

        result = self.compare(pre_alerts, post_alerts)

        self.assertEqual(result["summary"]["tcp_conversation_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["snort_event_packet_anchor_shift_count"], 5)
        self.assertEqual(result["summary"]["strict_delayed_emission_match_count"], 5)
        self.assertEqual(result["summary"]["successful_evasion_count"], 0)
        self.assertEqual(result["summary"]["alert_mutation_count"], 0)
        self.assertEqual(result["summary"]["induced_alert_count"], 2)
        self.assertTrue(all(record["classification"] == "Packet-Anchor shifted" for record in result["records"]))

    def test_strict_delayed_emission_does_not_match_signature_only(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", "tcp_conn_pre", timestamp="07/06-12:00:00.000001")],
            [alert("post", 1, 20, "1:100:1", "tcp_conn_post", timestamp="07/06-12:00:00.000002")],
        )

        self.assertEqual(result["summary"]["strict_delayed_emission_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 1)

    def test_strict_delayed_emission_does_not_match_different_signature_same_timestamp(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", "tcp_conn_pre", timestamp="07/06-12:00:00.000001")],
            [alert("post", 1, 20, "1:200:1", "tcp_conn_post", timestamp="07/06-12:00:00.000001")],
        )

        self.assertEqual(result["summary"]["strict_delayed_emission_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 1)

    def test_strict_delayed_emission_does_not_match_incompatible_tuple(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", "tcp_conn_pre", timestamp="07/06-12:00:00.000001", dst_port=2222)],
            [alert("post", 1, 20, "1:100:1", "tcp_conn_post", timestamp="07/06-12:00:00.000001", dst_port=3333)],
        )

        self.assertEqual(result["summary"]["strict_delayed_emission_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 1)

    def test_ambiguous_delayed_emission_collision_is_not_forced(self) -> None:
        result = self.compare(
            [alert("pre", 1, 10, "1:100:1", "tcp_conn_pre", timestamp="07/06-12:00:00.000001")],
            [
                alert("post", 1, 20, "1:100:1", "tcp_conn_post_a", timestamp="07/06-12:00:00.000001"),
                alert("post", 2, 30, "1:100:1", "tcp_conn_post_b", timestamp="07/06-12:00:00.000001"),
            ],
        )

        self.assertEqual(result["summary"]["strict_delayed_emission_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["ambiguous_delayed_emission_match_count"], 1)
        self.assertEqual(result["ambiguous_delayed_emission_matches"][0]["status"], "ambiguous_unmatched")
        self.assertEqual(result["summary"]["successful_evasion_count"], 1)
        self.assertEqual(result["summary"]["induced_alert_count"], 2)

    def test_duplicate_delayed_emission_identity_is_ambiguous_even_when_cardinality_matches(self) -> None:
        result = self.compare(
            [
                alert("pre", 1, 10, "1:100:1", "tcp_conn_pre_a", timestamp="07/06-12:00:00.000001"),
                alert("pre", 2, 11, "1:100:1", "tcp_conn_pre_b", timestamp="07/06-12:00:00.000001"),
            ],
            [
                alert("post", 1, 20, "1:100:1", "tcp_conn_post_a", timestamp="07/06-12:00:00.000001"),
                alert("post", 2, 21, "1:100:1", "tcp_conn_post_b", timestamp="07/06-12:00:00.000001"),
            ],
        )

        self.assertEqual(result["summary"]["strict_delayed_emission_displaced_detection_count"], 0)
        self.assertEqual(result["summary"]["ambiguous_delayed_emission_match_count"], 1)
        self.assertEqual(result["ambiguous_delayed_emission_matches"][0]["status"], "ambiguous_unmatched")
        self.assertEqual(len(result["ambiguous_delayed_emission_matches"][0]["pre_alerts"]), 2)
        self.assertEqual(len(result["ambiguous_delayed_emission_matches"][0]["post_alerts"]), 2)
        self.assertEqual(result["summary"]["successful_evasion_count"], 2)
        self.assertEqual(result["summary"]["induced_alert_count"], 2)

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
