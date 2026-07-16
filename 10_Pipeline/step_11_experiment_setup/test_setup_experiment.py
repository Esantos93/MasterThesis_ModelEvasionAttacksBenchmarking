from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common.ids_context import PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION
from common.paths import EXPERIMENT_SUBDIRS
from common.test_ids_context import pre_bundle
from step_11_experiment_setup.setup_experiment import parse_cli_args, run_setup


def base_config(output_root: Path, *, ids_aware: bool = False, instructions_only: bool = False) -> dict:
    return {
        "experiment": {
            "experiment_id": "step11_test_experiment",
            "output_root": str(output_root),
        },
        "dataset": {
            "pcap_path": "/tmp/nonexistent.pcap",
            "flow_csv_dir": "/tmp/nonexistent_flows",
            "attack_labels": ["Infiltration"],
        },
        "snort": {
            "snort_binary": "/usr/local/bin/snort",
            "config_path": "/usr/local/etc/snort/snort.lua",
            "plugin_path": "/usr/local/etc/snort/so_rules",
            "daq_dir": "/usr/local/lib/daq",
            "enable_builtin_rules": True,
            "enable_ruleset": True,
            "ruleset_path": "/usr/local/etc/snort/rules/include.rules",
            "rules_policy_path": "/usr/local/etc/snort/rules/CiscoFullSet/rulestates-security-ips.states",
        },
        "llm": {
            "model_name": "test-model",
            "model_path": "/models/test-model",
            "prompt_version": "compact_patch_prompting_v2",
            "prompt_input_json_data_profile": (
                "prompt_engineering_input_profile_v1" if ids_aware else "baseline_input_profile_v1"
            ),
            "prompt_instructions_profile": (
                "prompt_engineering_instructions_profile_v1"
                if ids_aware or instructions_only
                else "baseline_instructions_profile_v1"
            ),
            "prompt_target_context": 4096,
            "prompt_template_overhead_tokens": 500,
            "runtime_max_model_len": 12288,
            "token_budget": {
                "policy": "compact_patch_token_budget_v2",
                "chars_per_token_estimate": 3.0,
                "output_token_estimation_safety_factor": 1.2,
            },
        },
        "pipeline": {
            "target_os": "Ubuntu",
            "experiment_config_label": "test_step11",
            "experiment_config_label_options": ["test_step11"],
            "grouping_policy": "flow_context_aware" if ids_aware else "fixed_packet_count",
            "grouping_unit": "physical_packet",
            "group_size_packets": 6,
            "traffic_selection_policy": "conservative_v1",
            "validation_policy": "reject_invalid",
        },
    }


def write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Step11ExperimentSetupTests(unittest.TestCase):
    def test_baseline_config_without_bundle_keeps_original_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root))

            metadata = run_setup(config_path, False)

            experiment_root = root / "step11_test_experiment"
            self.assertEqual(
                [str(experiment_root / subdir) for subdir in EXPERIMENT_SUBDIRS],
                metadata["created_directories"],
            )
            self.assertFalse((experiment_root / "05_groups" / "pre_snort_context_source").exists())
            self.assertNotIn("ids_context_source", metadata)

            persisted_metadata = json.loads(
                (experiment_root / "01_setup" / "experiment_metadata.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("ids_context_source", persisted_metadata)

    def test_prompt_engineering_config_requires_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root, ids_aware=True))

            with self.assertRaisesRegex(ValueError, "pre-snort-context-bundle is required"):
                run_setup(config_path, False)

    def test_prompt_engineering_instructions_only_also_require_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root, instructions_only=True))

            with self.assertRaisesRegex(ValueError, "pre-snort-context-bundle is required"):
                run_setup(config_path, False)

            bundle_path = write_json(root / "pre_bundle.json", pre_bundle())
            metadata = run_setup(config_path, False, bundle_path)
            canonical_path = (
                root
                / "step11_test_experiment"
                / "05_groups"
                / "pre_snort_context_source"
                / "pre_snort_context_bundle_v1.json"
            )
            self.assertTrue(canonical_path.is_file())
            self.assertIn("ids_context_source", metadata)

    def test_prompt_engineering_config_rejects_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root, ids_aware=True))

            with self.assertRaisesRegex(FileNotFoundError, "does not exist"):
                run_setup(config_path, False, root / "missing_bundle.json")

    def test_prompt_engineering_config_uses_shared_bundle_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root, ids_aware=True))
            invalid_bundle_path = write_json(root / "invalid_bundle.json", {"schema_version": "wrong"})

            with self.assertRaisesRegex(ValueError, "pre_snort_context_bundle.schema_version"):
                run_setup(config_path, False, invalid_bundle_path)

    def test_prompt_engineering_config_copies_valid_bundle_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root, ids_aware=True))
            bundle_path = write_json(root / "pre_bundle.json", pre_bundle())

            metadata = run_setup(config_path, False, bundle_path)

            experiment_root = root / "step11_test_experiment"
            canonical_path = experiment_root / "05_groups" / "pre_snort_context_source" / "pre_snort_context_bundle_v1.json"
            self.assertTrue(canonical_path.is_file())
            self.assertEqual(bundle_path.read_bytes(), canonical_path.read_bytes())
            self.assertEqual(sha256(bundle_path), sha256(canonical_path))

            provenance = metadata["ids_context_source"]
            self.assertEqual(str(bundle_path.resolve()), provenance["original_bundle_path"])
            self.assertEqual(str(canonical_path), provenance["canonical_bundle_path"])
            self.assertEqual(PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION, provenance["bundle_schema_version"])
            self.assertEqual(sha256(bundle_path), provenance["source_sha256"])
            self.assertEqual(sha256(canonical_path), provenance["canonical_sha256"])
            self.assertEqual("tcp_connection_propagation_v1", provenance["mapping_policy"])

            persisted_metadata = json.loads(
                (experiment_root / "01_setup" / "experiment_metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provenance, persisted_metadata["ids_context_source"])

    def test_baseline_config_rejects_explicit_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = write_json(root / "config.json", base_config(root))
            bundle_path = write_json(root / "pre_bundle.json", pre_bundle())

            with self.assertRaisesRegex(ValueError, "only valid when"):
                run_setup(config_path, False, bundle_path)

    def test_existing_cli_arguments_remain_compatible(self) -> None:
        with patch.object(sys, "argv", ["setup_experiment.py", "--config", "config.json"]):
            args = parse_cli_args()

        self.assertEqual("config.json", args.config)
        self.assertFalse(args.check_inputs)
        self.assertIsNone(args.pre_snort_context_bundle)


if __name__ == "__main__":
    unittest.main()
