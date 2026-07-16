from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from common.ids_context import validate_pre_snort_context_bundle
from step_21_snort_runner.build_pre_snort_context_bundle import (
    build_pre_snort_context_bundle,
    extract_rule_declarations,
)


def write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class BundleFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.experiment_root = root / "baseline"
        self.pre_dir = self.experiment_root / "11_snort_raw" / "max-detect-ips" / "pre"
        self.post_dir = self.experiment_root / "11_snort_raw" / "max-detect-ips" / "post" / "unused"
        self.packet_json = self.experiment_root / "04_packet_json" / "selected_packet_records.json"
        self.pcap = self.experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap"
        self.rules_root = root / "snort" / "rules"
        self.plugin_root = root / "snort" / "so_rules"
        self.ruleset = self.rules_root / "include.rules"
        self.rules_policy = self.rules_root / "rulestates-max-detect-ips.states"
        self.catalog = root / "ids_detector_catalog_v1.json"
        self.output = root / "pre_snort_context_bundle_v1.json"
        self._write()

    def _write(self) -> None:
        self.pre_dir.mkdir(parents=True)
        self.post_dir.mkdir(parents=True)
        self.pcap.parent.mkdir(parents=True)
        self.pcap.write_bytes(b"pcap-pre-bytes")
        (self.post_dir / "must_not_be_read.txt").write_text("POST SENTINEL", encoding="utf-8")
        self.rules_root.mkdir(parents=True)
        self.plugin_root.mkdir(parents=True)
        self.ruleset.write_text("include text.rules\n", encoding="utf-8")
        self.rules_policy.write_text("1:1001 = enable\n", encoding="utf-8")
        (self.rules_root / "text.rules").write_text(
            'alert tcp any any -> any any (msg:"Text detector"; content:"abc"; sid:1001; rev:2;)\n',
            encoding="utf-8",
        )
        (self.plugin_root / "so.rules").write_text(
            'alert ip any any -> any any (msg:"SO detector"; soid:17775; gid:3; sid:17775; rev:6;)\n',
            encoding="utf-8",
        )
        write_json(
            self.catalog,
            {
                "schema_version": "ids_detector_catalog_v1",
                "records": [
                    {
                        "detector_source": "ruleset_so",
                        "gid": 3,
                        "sid": 17775,
                        "rev": 6,
                        "security_context": {
                            "summary": "SO summary",
                            "cve_ids": [],
                            "mitre_attack_ids": [],
                            "source_urls": ["https://example.invalid/so"],
                        },
                    },
                    {
                        "detector_source": "builtin_decoder_or_inspector",
                        "gid": 119,
                        "sid": 228,
                        "rev": 1,
                        "inspector": "http_inspect",
                        "semantic_description": "Built-in semantic description.",
                    },
                ],
            },
        )
        write_json(
            self.packet_json,
            {
                "metadata": {
                    "schema_version": "packet_json_v4",
                    "source_selected_pcap": str(self.pcap),
                },
                "traffic": [
                    {"packet_id": "packet_000001", "reduced_packet_index": 1},
                    {"packet_id": "packet_000002", "reduced_packet_index": 2},
                    {"packet_id": "packet_000003", "reduced_packet_index": 3},
                ],
            },
        )
        alerts = [
            {
                "gid": 1,
                "sid": 1001,
                "rev": 2,
                "msg": "Text detector",
                "pkt_num": 1,
                "timestamp": "07/06-12:00:00.000001",
                "src_addr": "192.0.2.1",
            },
            {
                "gid": 1,
                "sid": 1001,
                "rev": 2,
                "msg": "Text detector",
                "pkt_num": 2,
                "timestamp": "07/06-12:00:00.000002",
            },
            {
                "gid": 3,
                "sid": 17775,
                "rev": 6,
                "msg": "SO detector",
                "pkt_num": 2,
            },
            {
                "gid": 119,
                "sid": 228,
                "rev": 1,
                "msg": "Built-in detector",
                "pkt_num": 3,
            },
        ]
        converted_alerts = write_json(self.pre_dir / "alerts__pre.json", alerts)
        stdout = self.pre_dir / "stdout.log"
        stdout.write_text('o")~   Snort++ 3.11.1.0\nPacket Statistics\n', encoding="utf-8")
        write_json(
            self.pre_dir / "execution_metadata.json",
            {
                "traffic_version": "pre",
                "traffic_scope": "pre_common",
                "exit_code": 0,
                "input_pcap": str(self.pcap),
                "plugin_path": str(self.plugin_root),
                "snaplen": 65535,
                "enable_builtin_rules": True,
                "detector_policy_label": "max-detect-ips",
                "ruleset_path": str(self.ruleset),
                "rules_policy_path": str(self.rules_policy),
                "artifacts": {
                    "converted_alert_json": str(converted_alerts),
                    "stdout": str(stdout),
                },
            },
        )

    def build(self, output: Path | None = None) -> dict:
        return build_pre_snort_context_bundle(
            pre_snort_dir=self.pre_dir,
            packet_json_path=self.packet_json,
            output_path=output or self.output,
            detector_catalog_path=self.catalog,
        )


class PreSnortContextBundleBuilderTests(unittest.TestCase):
    def test_extracts_multiline_rule_declaration(self) -> None:
        declarations = extract_rule_declarations(
            'alert tcp any any -> any any (\n msg:"Example (test)";\n sid:12; rev:1;\n)\n'
        )
        self.assertEqual(len(declarations), 1)
        self.assertIn("sid:12", declarations[0])

    def test_builds_text_so_and_builtin_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            bundle = fixture.build()
            validate_pre_snort_context_bundle(bundle)

            definitions = {(item["gid"], item["sid"], item["rev"]): item for item in bundle["detector_definitions"]}
            self.assertEqual(len(definitions), 3)
            self.assertIn("rule_declaration", definitions[(1, 1001, 2)])
            self.assertEqual(definitions[(3, 17775, 6)]["security_context"]["summary"], "SO summary")
            self.assertEqual(definitions[(119, 228, 1)]["inspector"], "http_inspect")

    def test_preserves_occurrences_and_resolves_real_packet_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            bundle = fixture.build()

            self.assertEqual(len(bundle["alerts"]), 4)
            self.assertEqual(bundle["alerts"][0]["anchor_packet_ids"], ["packet_000001"])
            self.assertEqual(bundle["alerts"][1]["anchor_packet_ids"], ["packet_000002"])
            self.assertEqual(bundle["alerts"][0]["alert_id"], "pre_alert_000001")

    def test_fails_when_alert_packet_number_cannot_be_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            alerts_path = fixture.pre_dir / "alerts__pre.json"
            alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
            alerts[0]["pkt_num"] = 999
            write_json(alerts_path, alerts)

            with self.assertRaisesRegex(ValueError, "does not resolve"):
                fixture.build()

    def test_fails_when_text_rule_definition_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            (fixture.rules_root / "text.rules").write_text("", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "No text rule declaration"):
                fixture.build()

    def test_fails_when_detector_catalog_definition_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            catalog = json.loads(fixture.catalog.read_text(encoding="utf-8"))
            catalog["records"] = [
                record
                for record in catalog["records"]
                if (record["gid"], record["sid"], record["rev"]) != (119, 228, 1)
            ]
            write_json(fixture.catalog, catalog)

            with self.assertRaisesRegex(ValueError, "No curated built-in detector definition"):
                fixture.build()

    def test_fails_on_contradictory_rule_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            (fixture.rules_root / "conflicting.rules").write_text(
                'alert tcp any any -> any any (msg:"Different"; content:"xyz"; sid:1001; rev:2;)\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Contradictory rule declarations"):
                fixture.build()

    def test_output_is_deterministic_and_does_not_reference_post(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = BundleFixture(Path(temporary_directory))
            first_output = fixture.root / "first.json"
            second_output = fixture.root / "second.json"
            first = fixture.build(first_output)
            second = fixture.build(second_output)

            self.assertEqual(first, second)
            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            serialized = first_output.read_text(encoding="utf-8").lower()
            self.assertNotIn("post sentinel", serialized)
            self.assertFalse(any("\\post\\" in path.lower() or "/post/" in path.lower() for path in first["metadata"]["source_artifacts"]))
            self.assertEqual(set(first["metadata"]["source_artifacts"]), set(first["metadata"]["source_hashes"]))


if __name__ == "__main__":
    unittest.main()
