from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("run_pipeline_1.py")
PIPELINE_ROOT = Path(__file__).resolve().parents[2] / "10_Pipeline"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_pipeline_1_under_test", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load runner: {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PIPELINE_ROOT = PIPELINE_ROOT
    return module


def valid_bundle() -> dict:
    return {
        "schema_version": "pre_snort_context_bundle_v1",
        "metadata": {
            "snort_version": "3.11.1.0",
            "detector_policy": "max-detect-ips",
            "snaplen": 65535,
            "builtin_rules_enabled": True,
            "ruleset_identifier": "test_ruleset",
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
                "rev": 1,
                "message": "Example detector",
                "rule_declaration": "alert tcp any any -> any any (sid:1001; rev:1;)",
            }
        ],
        "alerts": [
            {
                "alert_id": "pre_alert_000001",
                "gid": 1,
                "sid": 1001,
                "rev": 1,
                "message": "Example detector",
                "anchor_packet_ids": ["packet_000001"],
            }
        ],
    }


def config(*, input_profile: str, instructions_profile: str) -> dict:
    return {
        "llm": {
            "prompt_input_json_data_profile": input_profile,
            "prompt_instructions_profile": instructions_profile,
        }
    }


class Pipeline1PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = load_runner()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "pre_snort_context_bundle_v1.json"
        self.source.write_text(json.dumps(valid_bundle()), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def preflight(self, config_data: dict, supplied_bundle: str | None, start_step: int = 11):
        return self.runner.preflight_pre_snort_context(
            config_data=config_data,
            experiment_root=self.root / "experiment",
            supplied_bundle=supplied_bundle,
            start_step=start_step,
        )

    def test_baseline_without_bundle_preserves_existing_behavior(self) -> None:
        result = self.preflight(
            config(
                input_profile="baseline_input_profile_v1",
                instructions_profile="baseline_instructions_profile_v1",
            ),
            None,
        )
        self.assertIsNone(result)

    def test_baseline_rejects_bundle_flag(self) -> None:
        with self.assertRaisesRegex(SystemExit, "only valid.*prompt-engineering"):
            self.preflight(
                config(
                    input_profile="baseline_input_profile_v1",
                    instructions_profile="baseline_instructions_profile_v1",
                ),
                str(self.source),
            )

    def test_prompt_engineering_input_profile_requires_flag(self) -> None:
        with self.assertRaisesRegex(SystemExit, "mandatory for this config"):
            self.preflight(
                config(
                    input_profile="prompt_engineering_input_profile_v1",
                    instructions_profile="baseline_instructions_profile_v1",
                ),
                None,
            )

    def test_prompt_engineering_instructions_profile_requires_flag(self) -> None:
        with self.assertRaisesRegex(SystemExit, "mandatory for this config"):
            self.preflight(
                config(
                    input_profile="baseline_input_profile_v1",
                    instructions_profile="prompt_engineering_instructions_profile_v1",
                ),
                None,
            )

    def test_step11_accepts_valid_bundle(self) -> None:
        result = self.preflight(
            config(
                input_profile="prompt_engineering_input_profile_v1",
                instructions_profile="prompt_engineering_instructions_profile_v1",
            ),
            str(self.source),
        )
        self.assertEqual(result, self.source.resolve())

    def test_later_restart_requires_canonical_bundle(self) -> None:
        with self.assertRaisesRegex(SystemExit, "Missing PRE Snort context bundle"):
            self.preflight(
                config(
                    input_profile="prompt_engineering_input_profile_v1",
                    instructions_profile="prompt_engineering_instructions_profile_v1",
                ),
                str(self.source),
                start_step=15,
            )

    def test_later_restart_accepts_matching_canonical_bundle(self) -> None:
        canonical = (
            self.root
            / "experiment"
            / self.runner.CANONICAL_PRE_SNORT_CONTEXT_RELATIVE_PATH
        )
        canonical.parent.mkdir(parents=True)
        canonical.write_bytes(self.source.read_bytes())
        result = self.preflight(
            config(
                input_profile="prompt_engineering_input_profile_v1",
                instructions_profile="prompt_engineering_instructions_profile_v1",
            ),
            str(self.source),
            start_step=15,
        )
        self.assertEqual(result, self.source.resolve())

    def test_later_restart_rejects_different_canonical_bundle(self) -> None:
        canonical = (
            self.root
            / "experiment"
            / self.runner.CANONICAL_PRE_SNORT_CONTEXT_RELATIVE_PATH
        )
        canonical.parent.mkdir(parents=True)
        changed = valid_bundle()
        changed["metadata"]["ruleset_identifier"] = "different_ruleset"
        canonical.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "does not match the canonical bundle"):
            self.preflight(
                config(
                    input_profile="prompt_engineering_input_profile_v1",
                    instructions_profile="prompt_engineering_instructions_profile_v1",
                ),
                str(self.source),
                start_step=12,
            )


if __name__ == "__main__":
    unittest.main()
