from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from step_22_alert_normalization.normalize_alerts import normalize_alerts
from step_23_alert_comparison.compare_alerts import compare_normalized_alerts
from step_24_metrics.compute_metrics import compute_metrics


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


class AlertPipelineIdentityTests(unittest.TestCase):
    def test_steps_22_to_24_use_experiment_id_without_config_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            experiment_id = "exp_alert_flow"
            experiment_root = root / experiment_id
            detector_policy = "security-ips"
            rules_policy_path = "/rules/security.states"
            config_path = root / "config.json"
            write_json(
                config_path,
                {
                    "experiment": {
                        "experiment_id": experiment_id,
                        "output_root": str(root),
                    },
                    "pipeline": {},
                    "snort": {
                        "detector_policy_label": detector_policy,
                        "rules_policy_path": rules_policy_path,
                        "snaplen": 65535,
                    },
                },
            )
            write_json(
                experiment_root / "04_packet_json" / "selected_packet_records.json",
                {
                    "metadata": {"experiment_id": experiment_id},
                    "traffic": [
                        {
                            "packet_id": "packet_000001",
                            "original_packet_number": 42,
                            "reduced_packet_index": 1,
                            "tcp_connection_id": "tcp_connection_000001",
                            "tcp_stream_id": 1,
                            "transport_protocol": "TCP",
                            "src_ip": "10.0.0.1",
                            "dst_ip": "10.0.0.2",
                            "src_port": 12345,
                            "dst_port": 80,
                            "assigned_flow_ids": [],
                            "candidate_flow_ids": [],
                        }
                    ],
                },
            )

            for traffic_version, alerts in (
                (
                    "pre",
                    [
                        {
                            "gid": 1,
                            "sid": 100,
                            "rev": 1,
                            "msg": "fixture",
                            "pkt_num": 1,
                            "proto": "TCP",
                            "src_addr": "10.0.0.1",
                            "src_port": 12345,
                            "dst_addr": "10.0.0.2",
                            "dst_port": 80,
                        }
                    ],
                ),
                ("post", []),
            ):
                input_dir = root / f"step21_{traffic_version}"
                alert_path = input_dir / "alerts.json"
                write_json(alert_path, alerts)
                write_json(
                    input_dir / "execution_metadata.json",
                    {
                        "experiment_id": experiment_id,
                        "traffic_version": traffic_version,
                        "traffic_scope": traffic_version,
                        "detector_policy_label": detector_policy,
                        "rules_policy_path": rules_policy_path,
                        "post_run_label": "run-fixture" if traffic_version == "post" else None,
                    },
                )
                normalize_alerts(
                    config_path=config_path,
                    traffic_version=traffic_version,
                    experiment_root=experiment_root,
                    post_run_label=None,
                    input_dir=input_dir,
                    output_dir=None,
                    input_alert_json=alert_path,
                )

            comparison = compare_normalized_alerts(
                config_path=config_path,
                experiment_root=experiment_root,
                pre_normalized=None,
                post_normalized=None,
                output_dir=None,
                matching_policy="packet_tcp_conversation",
            )
            metrics = compute_metrics(
                config_path=config_path,
                experiment_root=experiment_root,
            )

            self.assertEqual(1, comparison["successful_evasion_count"])
            self.assertEqual(1.0, metrics["metrics"]["ser"])
            self.assertNotIn("experiment_config_label", metrics)
            self.assertTrue(
                (experiment_root / "13_comparison" / detector_policy / "alert-comparison.json").exists()
            )
            self.assertTrue(
                (experiment_root / "14_metrics" / detector_policy / "metrics.json").exists()
            )


if __name__ == "__main__":
    unittest.main()
