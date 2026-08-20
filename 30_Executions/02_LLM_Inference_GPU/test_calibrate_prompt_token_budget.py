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
    @staticmethod
    def payload_unit(max_hex_chars: int = 20) -> dict:
        return {
            "prompt_unit_id": "unit-1",
            "parent_group_id": "group-1",
            "input_traceability": {
                "editable_regions": [
                    {
                        "region_id": "payload-1",
                        "allowed_operations": ["replace_byte_range"],
                        "max_replacement_hex_chars": max_hex_chars,
                    }
                ]
            },
        }

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

    def test_finish_reason_length_is_censored_even_with_complete_json(self) -> None:
        structure = calibration.scan_json_structure('{"patches":[]}')
        probable, evidence = calibration.classify_probable_truncation(
            finish_reason="length",
            remaining_tokens=0,
            structure=structure,
            failure_reason=None,
            proximity=8,
        )
        self.assertTrue(probable)
        self.assertIn("finish_reason=length", evidence)

    def test_complete_stopped_json_is_not_probable_truncation(self) -> None:
        structure = calibration.scan_json_structure('{"patches":[]}')
        probable, _ = calibration.classify_probable_truncation(
            finish_reason="stop",
            remaining_tokens=100,
            structure=structure,
            failure_reason=None,
            proximity=8,
        )
        self.assertFalse(probable)

    def test_analysis_and_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "prompt_units_manifest_v2.json"
            run_dir = root / "run"
            (run_dir / "raw").mkdir(parents=True)
            (run_dir / "metadata").mkdir()
            (run_dir / "failures").mkdir()
            (run_dir / "parsed").mkdir()
            unit_id = "flow_group_000001_fragment_0001"
            manifest = {
                "metadata": {
                    "schema_version": "prompt_units_manifest_v2",
                    "calibration_sample": {
                        "payload_budget_panels": {
                            "representative": {
                                "prompt_unit_ids": [unit_id]
                            },
                            "stress": {"prompt_unit_ids": []},
                        }
                    },
                },
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
            parsed_output = {"patches": []}
            raw = json.dumps(parsed_output, separators=(",", ":"))
            (run_dir / "raw" / f"{unit_id}.raw.txt").write_text(
                raw, encoding="utf-8"
            )
            (run_dir / "parsed" / f"{unit_id}.parsed.json").write_text(
                json.dumps(parsed_output), encoding="utf-8"
            )
            metadata = {
                "prompt_unit_id": unit_id,
                "status": "accepted",
                "failure_reason": None,
                "max_tokens": 24,
                "real_input_tokens": 64,
                "runtime_max_model_len": 128,
                "token_plan": manifest["prompt_units"][0]["token_plan"],
                "generation_response_metadata": {
                    "finish_reason": "stop",
                    "generated_token_count": len(raw),
                },
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
            self.assertFalse(records[0]["probable_truncation"])
            self.assertEqual(records[0]["calibration_panel"], "representative")
            self.assertEqual(
                records[0]["truncation_class"],
                calibration.COMPLETED_VALID_RESPONSE,
            )
            self.assertTrue(records[0]["selected_json_present"])
            self.assertEqual(records[0]["reported_generated_tokens"], len(raw))
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
            self.assertEqual(
                pair["output_token_estimation_safety_factor"],
                calibration.ceil_to_increment(
                    pair["completed_output_factor_raw"], 0.05
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
            report_dir.mkdir()
            (report_dir / "token_budget_postflight_records.csv").write_text(
                "legacy output\n", encoding="utf-8"
            )
            calibration.write_reports(report_dir, records, summary)
            self.assertFalse(
                (report_dir / "token_budget_postflight_records.csv").exists()
            )
            report_text = (
                report_dir / "token_budget_postflight_report.md"
            ).read_text(encoding="utf-8")
            self.assertIn("chars_per_token_estimate", report_text)
            self.assertIn("output_token_estimation_safety_factor", report_text)
            self.assertIn("Selected-JSON-expansion-derived raw output factor", report_text)
            self.assertIn("## Calibration panels", report_text)
            self.assertEqual(
                summary["panel_summaries"]["representative"]["records"], 1
            )

    def test_panel_summaries_keep_stress_prevalence_diagnostic(self) -> None:
        records = [
            {
                "calibration_panel": "representative",
                "status": "accepted",
                "truncation_class": calibration.COMPLETED_VALID_RESPONSE,
                "probable_truncation": False,
                "observed_output_expansion_factor": 1.2,
            },
            {
                "calibration_panel": "stress",
                "status": "failed",
                "truncation_class": calibration.LEGITIMATE_TRUNCATION,
                "probable_truncation": True,
                "legitimate_truncation_factor_lower_bound": 1.5,
            },
        ]
        panels = calibration.build_panel_summaries(records)
        self.assertEqual(
            panels["representative"]["role"],
            "population_prevalence_estimation",
        )
        self.assertEqual(
            panels["stress"]["role"],
            "targeted_tail_and_failure_discovery",
        )
        self.assertEqual(panels["stress"]["legitimate_truncation_rate"], 1.0)
        self.assertIn(
            "not a representative prevalence estimate",
            panels["stress"]["prevalence_interpretation"],
        )

    def test_recommendation_excludes_probable_truncations(self) -> None:
        accepted = {
            "status": "accepted",
            "probable_truncation": False,
            "truncation_class": calibration.COMPLETED_VALID_RESPONSE,
            "valid_completed_output_for_calibration": True,
            "selected_json_tokens_tokenizer": 20,
            "selected_json_chars_per_token": 2.0,
            "planned_output_chars": 100,
            "input_chars_per_real_token": 2.0,
            "current_chars_per_token": 2.0,
            "real_input_tokens": 50,
            "runtime_max_model_len": 256,
            "prompt_target_context": 200,
        }
        censored = {
            "status": "failed",
            "probable_truncation": True,
            "truncation_class": calibration.CONFIRMED_RUNAWAY,
            "valid_completed_output_for_calibration": False,
            "selected_json_tokens_tokenizer": None,
            "selected_json_chars_per_token": None,
            "generated_tokens_tokenizer": 1000,
            "chars_per_generated_token": 1.0,
            "planned_output_chars": 100,
            "input_chars_per_real_token": 2.0,
            "current_chars_per_token": 2.0,
            "real_input_tokens": 50,
            "runtime_max_model_len": 256,
            "prompt_target_context": 200,
        }
        recommendation = calibration.conservative_recommendation(
            [accepted, censored],
            calibration_margin=0.10,
            minimum_output_tokens=1,
        )
        pair = recommendation["recommended_config_pair"]
        self.assertEqual(recommendation["eligible_output_count"], 1)
        self.assertEqual(
            recommendation["censored_probable_truncation_count"], 1
        )
        self.assertEqual(recommendation["legitimate_truncation_count"], 0)
        self.assertIsNotNone(recommendation["final_calibrated_factor"])
        self.assertNotIn("observed_output_expansion_factor", censored)
        self.assertLess(pair["output_token_estimation_safety_factor"], 2.0)

    def test_maximum_legitimate_truncation_sets_next_probe_lower_bound(self) -> None:
        completed = {
            "status": "accepted",
            "probable_truncation": False,
            "truncation_class": calibration.COMPLETED_VALID_RESPONSE,
            "valid_completed_output_for_calibration": True,
            "selected_json_tokens_tokenizer": 50,
            "selected_json_chars_per_token": 2.0,
            "planned_output_chars": 100,
            "input_chars_per_real_token": 2.0,
            "current_chars_per_token": 2.0,
            "real_input_tokens": 50,
            "runtime_max_model_len": 512,
            "prompt_target_context": 400,
        }
        truncations = []
        for generated_tokens in (60, 80):
            truncations.append(
                {
                    "status": "failed",
                    "probable_truncation": True,
                    "truncation_class": calibration.LEGITIMATE_TRUNCATION,
                    "valid_completed_output_for_calibration": False,
                    "selected_json_tokens_tokenizer": None,
                    "selected_json_chars_per_token": None,
                    "generated_tokens_tokenizer": generated_tokens,
                    "planned_output_chars": 100,
                    "input_chars_per_real_token": 2.0,
                    "current_chars_per_token": 2.0,
                    "real_input_tokens": 50,
                    "runtime_max_model_len": 512,
                    "prompt_target_context": 400,
                }
            )
        recommendation = calibration.conservative_recommendation(
            [completed, *truncations],
            calibration_margin=0.10,
            minimum_output_tokens=1,
        )
        compact_base_tokens = 56  # ceil(100 / recommended 1.8 chars/token)
        expected_lower_bound = 80 / compact_base_tokens
        expected_probe = calibration.ceil_to_increment(
            max(
                recommendation["completed_output_factor"],
                expected_lower_bound / 0.90,
            ),
            0.05,
        )
        self.assertAlmostEqual(
            recommendation["legitimate_truncation_lower_bound"],
            expected_lower_bound,
        )
        self.assertEqual(
            recommendation["recommended_next_probe_factor"], expected_probe
        )
        self.assertIsNone(recommendation["final_calibrated_factor"])
        self.assertEqual(
            recommendation["calibration_status"],
            "probe_required_legitimate_truncations_present",
        )

    def test_causal_truncation_categories(self) -> None:
        unit = self.payload_unit(max_hex_chars=20)
        nested_complete = (
            '{"patches":[{"region_id":"payload-1",'
            '"operation":"replace_byte_range","replacement":"aabb"}]}'
        )
        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=True,
            finish_reason="length",
            status="accepted",
            raw_text=nested_complete,
            unit=unit,
            selected_json_present=True,
        )
        self.assertEqual(category, calibration.COMPLETE_AT_LIMIT)

        over_limit = (
            '{"patches":[{"region_id":"payload-1",'
            '"operation":"replace_byte_range","replacement":"'
            + "aa" * 11
        )
        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=True,
            finish_reason="length",
            status="failed",
            raw_text=over_limit,
            unit=unit,
            selected_json_present=False,
        )
        self.assertEqual(category, calibration.CONFIRMED_RUNAWAY)

        within_limit = (
            '{"patches":[{"region_id":"payload-1",'
            '"operation":"replace_byte_range","replacement":"aabb'
        )
        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=True,
            finish_reason="length",
            status="failed",
            raw_text=within_limit,
            unit=unit,
            selected_json_present=False,
        )
        self.assertEqual(category, calibration.LEGITIMATE_TRUNCATION)

        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=True,
            finish_reason="length",
            status="failed",
            raw_text=nested_complete + '\n{"patches":[',
            unit=unit,
            selected_json_present=False,
        )
        self.assertEqual(category, calibration.CONFIRMED_RUNAWAY)

        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=False,
            finish_reason="stop",
            status="failed",
            raw_text="not json",
            unit=unit,
            selected_json_present=False,
        )
        self.assertEqual(category, "In_budget_Invalid_response")

        category, _, _ = calibration.classify_truncation_cause(
            probable_truncation=True,
            finish_reason="length",
            status="failed",
            raw_text='{"patches":[{"region_id":"unknown",',
            unit=unit,
            selected_json_present=False,
        )
        self.assertEqual(category, calibration.AMBIGUOUS_TRUNCATION)

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
