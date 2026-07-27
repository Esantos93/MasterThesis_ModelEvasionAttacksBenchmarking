from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("calibrate_prompt_token_budget.py")
SPEC = importlib.util.spec_from_file_location("calibrate_prompt_token_budget", SCRIPT)
assert SPEC and SPEC.loader
calibration = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = calibration
SPEC.loader.exec_module(calibration)


class FakeTokenizer:
    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        assert add_special_tokens is False
        return list(range(max(1, len(text))))


class CalibrationTests(unittest.TestCase):
    def test_ceil_to_increment(self) -> None:
        self.assertEqual(calibration.ceil_to_increment(2.076923, 0.05), 2.1)
        self.assertEqual(calibration.ceil_to_increment(2.1, 0.05), 2.1)

    def test_json_structure_detects_string_truncation(self) -> None:
        structure = calibration.scan_json_structure(
            '{"patches":[{"replacement":"aaaa'
        )
        self.assertTrue(structure.ends_inside_string)
        self.assertEqual(structure.unclosed_container_count, 3)
        self.assertTrue(structure.structurally_incomplete)

    def test_json_structure_accepts_wrapped_complete_json(self) -> None:
        structure = calibration.scan_json_structure('```json\n{"patches":[]}\n```')
        self.assertTrue(structure.complete_top_level_value)
        self.assertFalse(structure.structurally_incomplete)
        self.assertTrue(structure.trailing_non_whitespace)

    def test_probable_truncation_requires_limit_evidence(self) -> None:
        structure = calibration.scan_json_structure('{"replacement":"aaaa')
        probable, evidence = calibration.classify_probable_truncation(
            finish_reason=None,
            remaining_tokens=2,
            structure=structure,
            failure_reason="JSONDecodeError",
            proximity=8,
        )
        self.assertTrue(probable)
        self.assertIn("raw_ends_inside_string", evidence)

    def test_analysis_and_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "prompt_units_manifest_v2.json"
            run_dir = root / "run"
            (run_dir / "raw").mkdir(parents=True)
            (run_dir / "metadata").mkdir()
            (run_dir / "failures").mkdir()
            unit_id = "flow_group_000001_fragment_0001"
            manifest = {
                "metadata": {"schema_version": "prompt_units_manifest_v2"},
                "prompt_units": [
                    {
                        "prompt_unit_id": unit_id,
                        "parent_group_id": "flow_group_000001",
                        "editable_target_presence": {
                            "editable_headers_present": False,
                            "editable_payload_present": True,
                        },
                        "token_plan": {
                            "chars_per_token_estimate": 2.0,
                            "output_token_estimation_safety_factor": 1.35,
                            "planned_output_tokens": 24,
                            "prompt_target_context": 80,
                            "runtime_max_model_len": 128,
                            "breakdown": {
                                "output_chars": 32,
                                "total_prompt_chars": 128,
                            },
                        },
                    }
                ],
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            raw = '{"patches":[{"replacement":"aaaaaaaa'
            (run_dir / "raw" / f"{unit_id}.raw.txt").write_text(
                raw, encoding="utf-8"
            )
            metadata = {
                "prompt_unit_id": unit_id,
                "status": "failed",
                "failure_reason": "JSONDecodeError",
                "max_tokens": len(raw) + 1,
                "real_input_tokens": 64,
                "runtime_max_model_len": 128,
                "token_plan": manifest["prompt_units"][0]["token_plan"],
            }
            (run_dir / "metadata" / f"{unit_id}.metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )

            records, provenance = calibration.analyze_run(
                manifest_path=manifest_path,
                run_dir=run_dir,
                tokenizer=FakeTokenizer(),
                limit_proximity_tokens=8,
            )
            self.assertEqual(provenance["metadata_files_analyzed"], 1)
            self.assertTrue(records[0]["probable_truncation"])
            recommendation = calibration.conservative_recommendation(
                records,
                calibration_margin=0.10,
                minimum_output_tokens=1,
            )
            pair = recommendation["recommended_config_pair"]
            self.assertEqual(pair["chars_per_token_estimate"], 1.8)
            self.assertGreater(
                pair["output_token_estimation_safety_factor"], 1.35
            )
            self.assertGreater(
                pair["response_expansion_output_safety_factor_raw"],
                pair["density_derived_output_safety_factor_raw"],
            )
            self.assertEqual(
                pair["output_token_estimation_safety_factor"],
                calibration.ceil_to_increment(
                    pair["selected_output_safety_factor_raw"], 0.05
                ),
            )
            self.assertEqual(pair["prompt_target_overflow_count"], 1)
            self.assertEqual(records[0]["input_chars_per_real_token"], 2.0)
            self.assertIn(
                "observed_output_expansion_factor",
                records[0],
            )
            self.assertIn("config_pair_output_tokens", records[0])
            summary = calibration.build_summary(
                records=records,
                provenance=provenance,
                recommendation=recommendation,
                manifest_path=manifest_path,
                run_dir=run_dir,
                model_path="/models/fake",
                limit_proximity_tokens=8,
            )
            report_dir = root / "report"
            calibration.write_reports(report_dir, records, summary)
            report_text = (
                report_dir / "token_budget_postflight_report.md"
            ).read_text(encoding="utf-8")
            self.assertIn("chars_per_token_estimate", report_text)
            self.assertIn("output_token_estimation_safety_factor", report_text)
            self.assertIn("Response-expansion-derived raw output factor", report_text)

    def test_embedded_config_is_complete(self) -> None:
        calibration.validate_config(calibration.CONFIG)
        required_paths = {
            "prompt_manifest",
            "model_path",
            "step17_run_dir",
            "output_dir",
        }
        self.assertTrue(required_paths.issubset(calibration.CONFIG))


if __name__ == "__main__":
    unittest.main()
