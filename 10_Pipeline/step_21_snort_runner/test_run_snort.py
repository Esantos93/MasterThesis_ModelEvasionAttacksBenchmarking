from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from step_21_snort_runner import run_snort


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class Step21SnortRunnerTests(unittest.TestCase):
    def make_config(self, root: Path) -> Path:
        config = {
            "experiment": {
                "experiment_id": "exp_fixture",
                "output_root": str(root),
            },
            "pipeline": {},
            "snort": {
                "snort_binary": "/usr/local/bin/snort",
                "config_path": "/usr/local/etc/snort/snort.lua",
                "enable_ruleset": True,
                "ruleset_path": "/usr/local/etc/snort/rules/include.rules",
                "rules_policy_path": "/usr/local/etc/snort/rules/CiscoFullSet/rulestates-max-detect-ips.states",
                "detector_policy_label": "max-detect-ips",
                "plugin_path": "/usr/local/etc/snort/so_rules",
                "daq_dir": "/usr/local/lib/daq",
                "snaplen": 65535,
                "enable_builtin_rules": True,
            },
        }
        config_path = root / "config.json"
        write_json(config_path, config)
        return config_path

    def make_experiment_inputs(self, experiment_root: Path) -> None:
        pre_pcap = experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap"
        post_pcap = experiment_root / "10_reconstructed_pcap" / "modified_traffic.pcap"
        pre_pcap.parent.mkdir(parents=True, exist_ok=True)
        post_pcap.parent.mkdir(parents=True, exist_ok=True)
        pre_pcap.write_bytes(b"pcap")
        post_pcap.write_bytes(b"pcap")

    def fake_snort_run(self, command: list[str]) -> tuple[str, str, int]:
        output_dir = Path(command[command.index("-l") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        with (output_dir / "alert_json.txt").open("a", encoding="utf-8") as alert_file:
            alert_file.write('{"gid":1,"sid":50447,"rev":1,"msg":"test alert"}\n')
        return "fake snort stdout\n", "", 0

    def test_new_pre_directory_writes_one_alert_population(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)

            with patch.object(run_snort, "run_subprocess_with_tee", side_effect=self.fake_snort_run):
                runs = run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=None,
                    output_dir=None,
                    experiment_root=None,
                    dry_run=False,
                )

            output_dir = Path(runs[0]["output_dir"])
            self.assertEqual(1, len((output_dir / "alert_json.txt").read_text(encoding="utf-8").splitlines()))
            self.assertEqual(1, runs[0]["alert_json_postprocessing"]["alert_count"])

    def test_reused_pre_directory_replaces_alert_json_instead_of_appending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)

            with patch.object(run_snort, "run_subprocess_with_tee", side_effect=self.fake_snort_run):
                run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=None,
                    output_dir=None,
                    experiment_root=None,
                    dry_run=False,
                )
                runs = run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=None,
                    output_dir=None,
                    experiment_root=None,
                    dry_run=False,
                )

            output_dir = Path(runs[0]["output_dir"])
            self.assertEqual(1, len((output_dir / "alert_json.txt").read_text(encoding="utf-8").splitlines()))
            self.assertEqual(1, runs[0]["alert_json_postprocessing"]["alert_count"])
            self.assertTrue(any(path.endswith("alert_json.txt") for path in runs[0]["cleaned_output_artifacts"]))

    def test_known_old_artifacts_are_cleaned_but_unmanaged_files_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)
            output_dir = experiment_root / "11_snort_raw" / "max-detect-ips" / "pre"
            output_dir.mkdir(parents=True, exist_ok=True)
            for filename in ["alert_json.txt", "command.json", "execution_metadata.json", "stdout.log", "stderr.log"]:
                (output_dir / filename).write_text("stale\n", encoding="utf-8")
            (output_dir / "alerts__traffic-pre__old.json").write_text("[]\n", encoding="utf-8")
            unmanaged = output_dir / "operator-note.txt"
            unmanaged.write_text("keep me\n", encoding="utf-8")

            with patch.object(run_snort, "run_subprocess_with_tee", side_effect=self.fake_snort_run):
                runs = run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=None,
                    output_dir=None,
                    experiment_root=None,
                    dry_run=False,
                )

            self.assertTrue(unmanaged.exists())
            self.assertEqual("keep me\n", unmanaged.read_text(encoding="utf-8"))
            self.assertFalse((output_dir / "alerts__traffic-pre__old.json").exists())
            self.assertGreaterEqual(len(runs[0]["cleaned_output_artifacts"]), 6)

    def test_output_directory_outside_experiment_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)
            unsafe_output = root / "outside-output"

            with self.assertRaisesRegex(ValueError, "outside experiment root"):
                run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
                    output_dir=unsafe_output,
                    experiment_root=experiment_root,
                    dry_run=True,
                )

    def test_dry_run_does_not_delete_existing_alert_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)
            output_dir = experiment_root / "11_snort_raw" / "max-detect-ips" / "pre"
            output_dir.mkdir(parents=True, exist_ok=True)
            alert_json = output_dir / "alert_json.txt"
            alert_json.write_text('{"old":true}\n', encoding="utf-8")

            runs = run_snort.run_snort(
                config_path=config_path,
                traffic_version="pre",
                input_pcap=None,
                output_dir=None,
                experiment_root=None,
                dry_run=True,
            )

            self.assertEqual('{"old":true}\n', alert_json.read_text(encoding="utf-8"))
            self.assertEqual([], runs[0]["cleaned_output_artifacts"])
            self.assertEqual("not_run", runs[0]["alert_json_postprocessing"]["status"])

    def test_pre_and_post_use_same_idempotent_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)
            pre_output = experiment_root / "11_snort_raw" / "max-detect-ips" / "pre"
            post_output = experiment_root / "11_snort_raw" / "max-detect-ips" / "post" / "manual-post"
            pre_output.mkdir(parents=True, exist_ok=True)
            post_output.mkdir(parents=True, exist_ok=True)
            (pre_output / "alert_json.txt").write_text('{"old":true}\n', encoding="utf-8")
            (post_output / "alert_json.txt").write_text('{"old":true}\n', encoding="utf-8")

            with patch.object(run_snort, "run_subprocess_with_tee", side_effect=self.fake_snort_run):
                pre_run = run_snort.run_one_snort_execution(
                    config=run_snort.load_json_config(config_path),
                    traffic_version="pre",
                    detector_policy_label="max-detect-ips",
                    post_run_label=None,
                    input_pcap_path=experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
                    output_dir=pre_output,
                    experiment_root=experiment_root,
                    dry_run=False,
                )
                post_run = run_snort.run_one_snort_execution(
                    config=run_snort.load_json_config(config_path),
                    traffic_version="post",
                    detector_policy_label="max-detect-ips",
                    post_run_label="manual-post",
                    input_pcap_path=experiment_root / "10_reconstructed_pcap" / "modified_traffic.pcap",
                    output_dir=post_output,
                    experiment_root=experiment_root,
                    dry_run=False,
                )

            self.assertEqual(1, pre_run["alert_json_postprocessing"]["alert_count"])
            self.assertEqual(1, post_run["alert_json_postprocessing"]["alert_count"])
            self.assertTrue(any(path.endswith("alert_json.txt") for path in pre_run["cleaned_output_artifacts"]))
            self.assertTrue(any(path.endswith("alert_json.txt") for path in post_run["cleaned_output_artifacts"]))

    def test_command_snaplen_ruleset_builtins_and_metadata_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self.make_config(root)
            experiment_root = root / "exp_fixture"
            self.make_experiment_inputs(experiment_root)

            with patch.object(run_snort, "run_subprocess_with_tee", side_effect=self.fake_snort_run):
                runs = run_snort.run_snort(
                    config_path=config_path,
                    traffic_version="pre",
                    input_pcap=None,
                    output_dir=None,
                    experiment_root=None,
                    dry_run=False,
                )

            output_dir = Path(runs[0]["output_dir"])
            command = json.loads((output_dir / "command.json").read_text(encoding="utf-8"))["argv"]
            metadata = json.loads((output_dir / "execution_metadata.json").read_text(encoding="utf-8"))
            lua_override = command[command.index("--lua") + 1]
            self.assertIn("--snaplen", command)
            self.assertEqual("65535", command[command.index("--snaplen") + 1])
            self.assertIn("/usr/local/etc/snort/rules/include.rules", lua_override)
            self.assertIn("enable_builtin_rules = true", lua_override)
            self.assertIn("rulestates-max-detect-ips.states", lua_override)
            self.assertEqual(65535, metadata["snaplen"])
            self.assertTrue(metadata["enable_builtin_rules"])
            self.assertTrue(metadata["enable_ruleset"])
            self.assertEqual("/usr/local/etc/snort/rules/CiscoFullSet/rulestates-max-detect-ips.states", metadata["rules_policy_path"])


if __name__ == "__main__":
    unittest.main()
