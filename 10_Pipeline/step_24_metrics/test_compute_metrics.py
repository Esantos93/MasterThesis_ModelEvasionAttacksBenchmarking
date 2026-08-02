from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from step_24_metrics.compute_metrics import compute_metrics, main


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
        anchor_shift: int = 0,
        weight: float = 0.0,
        detector_policy: str = "security-ips",
        signatures: list[dict] | None = None,
        post_run_label: str = "run-fixture",
    ) -> tuple[Path, Path]:
        config_path = root / "config.json"
        config = {
            "experiment": {
                "experiment_id": "exp_fixture",
                "output_root": str(root),
            },
            "pipeline": {
                # Historical config field kept in fixtures to prove Step 24 ignores it.
                "signature_mutation_weight": weight,
            },
            "snort": {
                "detector_policy_label": detector_policy,
                "rules_policy_path": "/rules/security.states",
                "snaplen": 65535,
            },
        }
        self.write_json(config_path, config)

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
            "snort_event_packet_anchor_shift_count": anchor_shift,
            "induced_alert_count": induced,
            "post_only_unmatched_count": induced,
            "classification_counts": {
                "Alert-Signature Mutation": mutation,
                "Failed Evasion": failed,
                "Induced Alert": induced,
                "Successful Evasion": successful,
                "TCP-Conversation Displaced Detection": displaced,
                "Packet-Anchor shifted": anchor_shift,
            },
            "successful_evasion_count": successful,
            "alert_mutation_count": mutation,
            "failed_evasion_count": failed,
        }
        metadata = {
            "schema_version": "snort_alert_comparison_v6",
            "experiment_id": "exp_fixture",
            "detector_policy_label": detector_policy,
            "rules_policy_path": "/rules/security.states",
            "post_normalization_metadata": {
                "source_post_run_label": post_run_label,
            },
            "summary": summary,
        }
        self.write_json(
            comparison_dir / "alert-comparison.json",
            {"metadata": metadata, "summary": summary, "comparison_records": [], "induced_alerts": []},
        )
        self.write_json(comparison_dir / "comparison-metadata.json", metadata)
        self.write_json(
            comparison_dir / "signature-comparison-summary.json",
            {"metadata": metadata, "summary": {"signature_row_count": len(signature_rows)}, "signatures": signature_rows},
        )
        return config_path, comparison_dir

    def test_ser_ignores_weighted_candidate_categories_from_historical_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(
                root,
                pre_count=10,
                post_count=10,
                failed=0,
                successful=1,
                mutation=2,
                displaced=3,
                anchor_shift=4,
                weight=0.9,
            )
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["ser"], 0.1)
            self.assertNotIn("weighted_successful_evasion_count", result["metrics"])
            self.assertNotIn("signature_mutation_weight", result["metrics"])

    def test_narr_positive_zero_and_negative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(root, pre_count=10, post_count=6, failed=6, successful=4, mutation=0)
            self.assertEqual(compute_metrics(config_path=config)["metrics"]["narr"], 0.4)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(root, pre_count=10, post_count=10, failed=10, successful=0, mutation=0)
            self.assertEqual(compute_metrics(config_path=config)["metrics"]["narr"], 0.0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(root, pre_count=10, post_count=12, failed=10, successful=0, mutation=0, induced=2)
            self.assertEqual(compute_metrics(config_path=config)["metrics"]["narr"], -0.2)

    def test_sir_normal_and_zero_post_unique_signature_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            signatures = [
                {"signature_key": "1:1:1", "gid": 1, "detector_source": "ruleset_text", "pre_count": 8, "post_count": 3, "status": "present_in_pre_and_post"},
                {"signature_key": "1:2:1", "gid": 1, "detector_source": "ruleset_text", "pre_count": 0, "post_count": 2, "status": "post_only_new"},
            ]
            config, _ = self.make_fixture(root, pre_count=8, post_count=5, failed=3, successful=5, mutation=0, signatures=signatures)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["new_post_unique_signature_count"], 1)
            self.assertEqual(result["metrics"]["sir"], 0.5)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            signatures = [
                {"signature_key": "1:1:1", "gid": 1, "detector_source": "ruleset_text", "pre_count": 8, "post_count": 0, "status": "pre_only_disappeared"},
            ]
            config, _ = self.make_fixture(root, pre_count=8, post_count=0, failed=0, successful=8, mutation=0, signatures=signatures)
            result = compute_metrics(config_path=config)
            self.assertEqual(result["metrics"]["unique_post_signature_count"], 0)
            self.assertEqual(result["metrics"]["sir"], 0.0)

    def test_all_six_diagnostic_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(
                root,
                pre_count=20,
                post_count=18,
                failed=5,
                successful=7,
                mutation=3,
                induced=2,
                displaced=4,
                anchor_shift=1,
            )
            diagnostics = compute_metrics(config_path=config)["diagnostic_metrics"]
            expected = {
                "induced_alert_rate": 2 / 20,
                "alert_mutation_rate": 3 / 20,
                "failed_evasion_rate": 5 / 20,
                "tcp_conversation_displaced_detection_rate": 4 / 20,
                "packet_anchor_shift_rate": 1 / 20,
                "post_alert_retention_rate": 18 / 20,
            }
            self.assertEqual(set(diagnostics), set(expected))
            for name, value in expected.items():
                self.assertEqual(diagnostics[name]["value"], value)
                self.assertEqual(diagnostics[name]["percentage"], value * 100)

    def test_clean_json_shape_identifiers_and_exact_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "isolated_metrics"
            config, _ = self.make_fixture(root, pre_count=10, post_count=10, failed=10, successful=0, mutation=0)
            result = compute_metrics(config_path=config, output_dir=output_dir)
            clean_path = output_dir / "metrics_summary-exp_fixture.json"
            detailed_path = output_dir / "metrics.json"
            report_path = output_dir / "metrics-report.md"
            csv_path = output_dir / "metrics-table.csv"

            self.assertEqual(Path(result["artifacts"]["clean_metrics_summary"]), clean_path)
            self.assertEqual(Path(result["artifacts"]["metrics"]), detailed_path)
            self.assertEqual(Path(result["artifacts"]["metrics_report"]), report_path)
            self.assertTrue(clean_path.exists())
            self.assertTrue(detailed_path.exists())
            self.assertTrue(report_path.exists())
            self.assertFalse(csv_path.exists())

            clean = json.loads(clean_path.read_text(encoding="utf-8"))
            self.assertEqual(set(clean), {"experiment_identifier", "primary_metrics", "diagnostic_metrics"})
            self.assertEqual(list(clean), ["experiment_identifier", "primary_metrics", "diagnostic_metrics"])
            clean_text = clean_path.read_text(encoding="utf-8")
            self.assertLess(clean_text.index('"experiment_identifier"'), clean_text.index('"primary_metrics"'))
            self.assertLess(clean_text.index('"primary_metrics"'), clean_text.index('"diagnostic_metrics"'))
            self.assertEqual(
                clean["experiment_identifier"],
                {
                    "experiment_id": "exp_fixture",
                    "detector_policy_label": "security-ips",
                    "post_run_label": "run-fixture",
                },
            )

    def test_terminal_output_lists_primary_and_diagnostic_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "terminal_metrics"
            log_file = root / "step24.log"
            config, _ = self.make_fixture(root, pre_count=10, post_count=12, failed=8, successful=1, mutation=1, induced=2)
            old_argv = sys.argv[:]
            sys.argv = [
                "compute_metrics.py",
                "--config",
                str(config),
                "--output-dir",
                str(output_dir),
                "--log-file",
                str(log_file),
            ]
            try:
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    main()
            finally:
                sys.argv = old_argv
            text = stdout.getvalue()
            self.assertIn("Primary metrics:", text)
            self.assertIn("  ser: numerator=1 denominator=10 value=0.100000000000 percentage=10.000000%", text)
            self.assertIn("Diagnostic metrics:", text)
            self.assertIn("  induced_alert_rate: numerator=2 denominator=10 value=0.200000000000 percentage=20.000000%", text)
            self.assertIn("Clean metrics summary:", text)

    def test_zero_pre_alerts_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(root, pre_count=0, post_count=0, failed=0, successful=0, mutation=0)
            with self.assertRaisesRegex(ValueError, "pre_alert_count is zero"):
                compute_metrics(config_path=config)

    def test_detector_policy_aware_default_path_and_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _ = self.make_fixture(root, pre_count=3, post_count=3, failed=3, successful=0, mutation=0, detector_policy="security-ips")
            first = compute_metrics(config_path=config)
            clean_path = Path(first["artifacts"]["clean_metrics_summary"])
            first_clean = json.loads(clean_path.read_text(encoding="utf-8"))
            second = compute_metrics(config_path=config)
            second_clean = json.loads(clean_path.read_text(encoding="utf-8"))
            self.assertIn("13_comparison/security-ips", first["source_alert_comparison"].replace("\\", "/"))
            self.assertEqual(first_clean, second_clean)
            self.assertEqual(first["primary_metrics"], second["primary_metrics"])
            self.assertEqual(first["diagnostic_metrics"], second["diagnostic_metrics"])


if __name__ == "__main__":
    unittest.main()
