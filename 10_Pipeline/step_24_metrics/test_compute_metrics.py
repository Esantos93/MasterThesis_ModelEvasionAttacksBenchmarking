from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from step_24_metrics.compute_metrics import compute_metrics


class Step24MetricsTests(unittest.TestCase):
    def write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def make_fixture(
        self,
        root: Path,
        *,
        pre_count: int,
        post_count: int,
        failed: int,
        successful: int,
        mutation: int,
        induced: int = 0,
        displaced: int = 0,
        delayed: int = 0,
        weight: float = 0.0,
        detector_policy: str = "security-ips",
        signatures: list[dict] | None = None,
    ) -> Path:
        config_path = root / "config.json"
        config = {
            "experiment": {
                "experiment_id": "exp_fixture",
                "output_root": str(root),
            },
            "pipeline": {
                "experiment_config_label": "baseline_004_headers_only_fixed_size_6",
                "signature_mutation_weight": weight,
            },
            "snort": {
                "detector_policy_label": detector_policy,
                "rules_policy_path": "/rules/security.states",
                "snaplen": 65535,
            },
        }
        self.write_json(config_path, config)

        label = "baseline-004-headers-only-fixed-size-6"
        comparison_dir = root / "exp_fixture" / "13_comparison" / detector_policy
        default_signatures = [
            {
                "signature_key": "1:100:1",
                "gid": 1,
                "sid": 100,
                "rev": 1,
                "detector_source": "ruleset_text",
                "pre_count": pre_count,
                "post_count": post_count,
                "count_delta_post_minus_pre": post_count - pre_count,
                "status": "present_in_pre_and_post" if pre_count and post_count else "pre_only_disappeared",
            }
        ]
        signature_rows = signatures if signatures is not None else default_signatures
        summary = {
            "pre_alert_count": pre_count,
            "post_alert_count": post_count,
            "pre_unique_signature_count": len({row["signature_key"] for row in signature_rows if row["pre_count"] > 0}),
            "post_unique_signature_count": len({row["signature_key"] for row in signature_rows if row["post_count"] > 0}),
            "pre_detector_source_counts": {"ruleset_text": pre_count},
            "post_detector_source_counts": {"ruleset_text": post_count},
            "same_signature_matches": failed,
            "different_signature_replacements": mutation,
            "tcp_conversation_displaced_detection_count": displaced,
            "snort_event_packet_anchor_shift_count": delayed,
            "induced_alert_count": induced,
            "post_only_unmatched_count": induced,
            "classification_counts": {
                "Alert Mutation": mutation,
                "Failed Evasion": failed,
                "Induced Alert": induced,
                "Successful Evasion": successful,
                "TCP-Conversation Displaced Detection": displaced,
                "Snort Event Packet-Anchor Shift": delayed,
            },
            "successful_evasion_count": successful,
            "alert_mutation_count": mutation,
            "failed_evasion_count": failed,
        }
        metadata = {
            "schema_version": "snort_alert_comparison_v1",
            "experiment_id": "exp_fixture",
            "experiment_config_label": label,
            "detector_policy_label": detector_policy,
            "rules_policy_path": "/rules/security.states",
            "summary": summary,
        }
        self.write_json(
            comparison_dir / f"alert-comparison__experiment-config-{label}.json",
            {"metadata": metadata, "summary": summary, "comparison_records": [], "post_only_unmatched_alerts": []},
        )
        self.write_json(comparison_dir / f"comparison-metadata__experiment-config-{label}.json", metadata)
        self.write_json(
            comparison_dir / f"signature-comparison-summary__experiment-config-{label}.json",
            {"metadata": metadata, "summary": {"signature_row_count": len(signature_rows)}, "signatures": signature_rows},
        )
        return config_path

    def test_all_failed_evasion_ser_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=10, failed=10, successful=0, mutation=0)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.0)
            self.assertEqual(result["metrics"]["post_alert_retention_rate"], 1.0)

    def test_successful_evasion_increases_ser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            signatures = [
                {"signature_key": "1:1:1", "gid": 1, "detector_source": "ruleset_text", "pre_count": 6, "post_count": 6, "status": "present_in_pre_and_post"},
                {"signature_key": "1:2:1", "gid": 1, "detector_source": "ruleset_text", "pre_count": 4, "post_count": 0, "status": "pre_only_disappeared"},
            ]
            config = self.make_fixture(root, pre_count=10, post_count=6, failed=6, successful=4, mutation=0, signatures=signatures)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.4)
            self.assertEqual(result["metrics"]["disappeared_signature_count"], 1)

    def test_alert_mutation_ignored_when_weight_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=10, failed=6, successful=0, mutation=4, weight=0.0)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["alert_mutation_rate_raw"], 0.4)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.0)

    def test_alert_mutation_weight_contributes_to_ser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=10, failed=6, successful=0, mutation=4, weight=0.5)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.2)

    def test_partial_credit_weight_includes_mutation_displaced_detection_and_delayed_re_emission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(
                root,
                pre_count=10,
                post_count=10,
                failed=3,
                successful=1,
                mutation=2,
                displaced=3,
                delayed=1,
                weight=0.5,
            )
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["partial_credit_candidate_count"], 6)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.4)

    def test_induced_alert_reported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=12, failed=10, successful=0, mutation=0, induced=2)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["induced_alert_count"], 2)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.0)

    def test_tcp_conversation_displaced_detection_reported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=10, failed=8, successful=0, mutation=0, displaced=2)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["tcp_conversation_displaced_detection_count"], 2)
            self.assertEqual(result["metrics"]["tcp_conversation_displaced_detection_rate"], 0.2)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.0)

    def test_snort_event_packet_anchor_shift_reported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=10, post_count=10, failed=8, successful=0, mutation=0, delayed=2)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["snort_event_packet_anchor_shift_count"], 2)
            self.assertEqual(result["metrics"]["snort_event_packet_anchor_shift_rate"], 0.2)
            self.assertEqual(result["metrics"]["signature_evasion_rate"], 0.0)

    def test_zero_pre_alerts_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=0, post_count=0, failed=0, successful=0, mutation=0)
            with self.assertRaisesRegex(ValueError, "pre_alert_count is zero"):
                compute_metrics(config_path=config)

    def test_detector_policy_aware_default_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.make_fixture(root, pre_count=3, post_count=3, failed=3, successful=0, mutation=0, detector_policy="security-ips")
            result = compute_metrics(config_path=config)
            self.assertIn("13_comparison/security-ips", result["source_alert_comparison"].replace("\\", "/"))


if __name__ == "__main__":
    unittest.main()
