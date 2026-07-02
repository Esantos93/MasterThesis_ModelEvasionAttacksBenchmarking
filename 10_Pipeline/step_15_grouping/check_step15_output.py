from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any


HEADER_ONLY_STRATEGY = "header_only_strategy_v1"
HEADER_ONLY_MANIFEST_SCHEMA = "compact_modification_units_manifest_v2"
HEADER_ONLY_UNIT_SCHEMA = "compact_modification_unit_v2"
HYBRID_MANIFEST_SCHEMA = "compact_modification_units_manifest_v1"
HYBRID_UNIT_SCHEMA = "compact_modification_unit_v1"
PACKET_JSON_SCHEMA = "packet_json_v4"


#Read a JSON artifact from disk.
def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#Resolve an artifact path from an absolute path or the Step 15 output directory.
def resolve_existing_path(path_value: Any, base_dir: Path) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError(f"Expected non-empty path string, found {path_value!r}")
    path = Path(path_value).expanduser()
    if path.exists():
        return path
    fallback = base_dir / path.name
    if fallback.exists():
        return fallback
    raise FileNotFoundError(f"Could not resolve artifact path: {path_value}")


#Find the Step 15 manifest expected for the selected strategy.
def find_manifest(output_dir: Path, expected_strategy: str | None) -> Path:
    if expected_strategy == HEADER_ONLY_STRATEGY:
        candidate = output_dir / "compact_modification_units_manifest_v2.json"
        if candidate.exists():
            return candidate
    candidates = [
        output_dir / "compact_modification_units_manifest_v2.json",
        output_dir / "compact_modification_units_manifest_v1.json",
    ]
    existing = [path for path in candidates if path.exists()]
    if len(existing) != 1:
        raise FileNotFoundError(
            "Expected exactly one Step 15 manifest in the output directory; "
            f"found {[str(path) for path in existing]}"
        )
    return existing[0]


#Check that header classification side artifacts match the manifest metadata.
def check_header_classification_artifacts(metadata: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    manifest_path = resolve_existing_path(metadata.get("headers_full_classification_manifest"), output_dir)
    jsonl_path = resolve_existing_path(metadata.get("headers_full_classification_jsonl"), output_dir)
    header_manifest = read_json(manifest_path)
    header_metadata = header_manifest.get("metadata", {})
    if header_metadata.get("schema_version") != "headers_full_classification_manifest_v1":
        raise ValueError("Header classification manifest has the wrong schema.")
    first_record_schema = None
    line_count = 0
    with jsonl_path.open("r", encoding="utf-8") as input_file:
        for line in input_file:
            if not line.strip():
                continue
            line_count += 1
            if first_record_schema is None:
                first_record_schema = json.loads(line).get("schema_version")
    if first_record_schema != "headers_full_classification_record_v1":
        raise ValueError("Header classification JSONL has the wrong record schema.")
    expected_packet_count = int(header_metadata.get("packet_count") or 0)
    if line_count != expected_packet_count:
        raise ValueError(
            f"Header classification JSONL line count mismatch: lines={line_count}, "
            f"manifest_packet_count={expected_packet_count}"
        )
    return {
        "header_manifest": str(manifest_path),
        "header_jsonl": str(jsonl_path),
        "header_classification_records": line_count,
    }


#Validate manifest-level invariants shared by Step 15 strategies.
def check_common_manifest(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    expected_strategy: str | None,
    expected_packet_count: int | None,
    expected_group_size: int | None,
) -> dict[str, Any]:
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("Manifest lacks metadata object.")
    units = manifest.get("compact_modification_units")
    if not isinstance(units, list):
        raise ValueError("Manifest lacks compact_modification_units list.")
    if metadata.get("source_packet_json_schema_version") != PACKET_JSON_SCHEMA:
        raise ValueError(
            f"Expected source_packet_json_schema_version={PACKET_JSON_SCHEMA}, "
            f"found {metadata.get('source_packet_json_schema_version')!r}"
        )
    if metadata.get("grouping_unit") != "physical_packet":
        raise ValueError(f"Expected grouping_unit='physical_packet', found {metadata.get('grouping_unit')!r}")
    if expected_strategy and metadata.get("strategy") != expected_strategy:
        raise ValueError(f"Expected strategy={expected_strategy!r}, found {metadata.get('strategy')!r}")
    if expected_packet_count is not None and int(metadata.get("total_packet_count") or -1) != expected_packet_count:
        raise ValueError(
            f"Expected total_packet_count={expected_packet_count}, found {metadata.get('total_packet_count')!r}"
        )
    if expected_group_size is not None and int(metadata.get("group_size_packets") or -1) != expected_group_size:
        raise ValueError(
            f"Expected group_size_packets={expected_group_size}, found {metadata.get('group_size_packets')!r}"
        )
    if expected_packet_count is not None and expected_group_size:
        expected_parent_groups = math.ceil(expected_packet_count / expected_group_size)
        if int(metadata.get("parent_group_count") or -1) != expected_parent_groups:
            raise ValueError(
                f"Expected parent_group_count={expected_parent_groups}, "
                f"found {metadata.get('parent_group_count')!r}"
            )
    if int(metadata.get("modification_unit_count") or -1) != len(units):
        raise ValueError("modification_unit_count does not match compact_modification_units length.")
    return check_header_classification_artifacts(metadata, manifest_path.parent)


#Validate header-only modification units and editable header regions.
def check_header_only_units(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    metadata = manifest["metadata"]
    if metadata.get("schema_version") != HEADER_ONLY_MANIFEST_SCHEMA:
        raise ValueError(f"Header-only manifest must use {HEADER_ONLY_MANIFEST_SCHEMA}.")
    if metadata.get("compact_view_schema_version") != HEADER_ONLY_UNIT_SCHEMA:
        raise ValueError(f"Header-only units must use {HEADER_ONLY_UNIT_SCHEMA}.")
    if metadata.get("header_only") is not True:
        raise ValueError("Header-only manifest must set header_only=true.")
    if metadata.get("editable_payload_regions_enabled") is not False:
        raise ValueError("Header-only manifest must disable editable payload regions.")
    if metadata.get("editable_header_regions_enabled") is not True:
        raise ValueError("Header-only manifest must enable editable header regions.")
    expected_header_fields = {str(field) for field in metadata.get("expected_editable_header_fields", [])}
    if not expected_header_fields:
        raise ValueError("Header-only manifest must record expected_editable_header_fields.")

    coverage = metadata.get("physical_parent_group_coverage", {})
    if coverage.get("duplicate_physical_packet_count") != 0 or coverage.get("missing_physical_packet_count") != 0:
        raise ValueError(f"Physical parent-group coverage failed: {coverage}")

    unit_schema_counts: Counter[str] = Counter()
    editable_region_distribution: Counter[int] = Counter()
    region_type_counts: Counter[str] = Counter()
    field_counts: Counter[str] = Counter()
    physical_packet_ids: list[str] = []
    payload_window_count = 0
    editable_payload_region_count = 0

    for entry in manifest["compact_modification_units"]:
        unit_path = resolve_existing_path(entry.get("modification_unit_file"), manifest_path.parent)
        unit = read_json(unit_path)
        unit_schema_counts[str(unit.get("schema_version"))] += 1
        if unit.get("schema_version") != HEADER_ONLY_UNIT_SCHEMA:
            raise ValueError(f"Unit {unit_path} has wrong schema {unit.get('schema_version')!r}.")
        if unit.get("packets") != []:
            raise ValueError(f"Header-only unit {unit_path} must have packets=[].")
        if unit.get("payload_window_count") != 0:
            raise ValueError(f"Header-only unit {unit_path} contains payload windows.")
        if unit.get("editable_payload_region_count") != 0:
            raise ValueError(f"Header-only unit {unit_path} contains editable payload regions.")
        payload_window_count += int(unit.get("payload_window_count") or 0)
        editable_payload_region_count += int(unit.get("editable_payload_region_count") or 0)
        editable_region_distribution[int(unit.get("editable_region_count") or 0)] += 1

        for physical_packet in unit.get("physical_packets", []):
            packet_id = str(physical_packet.get("packet_id"))
            physical_packet_ids.append(packet_id)
            for region in physical_packet.get("header_field_classifications", []):
                if region.get("identity_type") != "physical_header_region":
                    raise ValueError(f"Unexpected region identity in {unit_path}: {region.get('identity_type')!r}")
                if region.get("region_type") != "header_field":
                    raise ValueError(f"Unexpected region_type in {unit_path}: {region.get('region_type')!r}")
                if region.get("field") not in expected_header_fields:
                    raise ValueError(f"Unexpected editable field in {unit_path}: {region.get('field')!r}")
                if region.get("operation") != "replace_uint":
                    raise ValueError(f"Unexpected operation in {unit_path}: {region.get('operation')!r}")
                if region.get("replacement_format") != "uint":
                    raise ValueError(
                        f"Unexpected replacement_format in {unit_path}: {region.get('replacement_format')!r}"
                    )
                if region.get("current_value") is None and region.get("original_value") is None:
                    raise ValueError(f"Missing original/current value in {unit_path}: {region.get('region_id')!r}")
                constraints = region.get("constraints", {})
                if not isinstance(constraints, dict) or "min" not in constraints or "max" not in constraints:
                    raise ValueError(f"Missing min/max constraints in {unit_path}: {region.get('region_id')!r}")
                region_type_counts[str(region.get("identity_type"))] += 1
                field_counts[str(region.get("field"))] += 1

    duplicate_packets = [packet_id for packet_id, count in Counter(physical_packet_ids).items() if count > 1]
    if duplicate_packets:
        raise ValueError(f"Physical packets appear in more than one header-only unit: {duplicate_packets[:10]}")

    return {
        "unit_schema_counts": dict(sorted(unit_schema_counts.items())),
        "editable_region_distribution": dict(sorted(editable_region_distribution.items())),
        "region_type_counts": dict(sorted(region_type_counts.items())),
        "field_counts": dict(sorted(field_counts.items())),
        "payload_window_count": payload_window_count,
        "editable_payload_region_count": editable_payload_region_count,
        "physical_packet_units_covered": len(physical_packet_ids),
    }


#Validate hybrid modification units and canonical payload-window counts.
def check_hybrid_units(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    metadata = manifest["metadata"]
    if metadata.get("schema_version") != HYBRID_MANIFEST_SCHEMA:
        raise ValueError(f"Hybrid manifest must use {HYBRID_MANIFEST_SCHEMA}.")
    if metadata.get("compact_view_schema_version") != HYBRID_UNIT_SCHEMA:
        raise ValueError(f"Hybrid units must use {HYBRID_UNIT_SCHEMA}.")
    unit_schema_counts: Counter[str] = Counter()
    payload_window_count = 0
    for entry in manifest["compact_modification_units"]:
        unit_path = resolve_existing_path(entry.get("modification_unit_file"), manifest_path.parent)
        unit = read_json(unit_path)
        unit_schema_counts[str(unit.get("schema_version"))] += 1
        if unit.get("schema_version") != HYBRID_UNIT_SCHEMA:
            raise ValueError(f"Unit {unit_path} has wrong schema {unit.get('schema_version')!r}.")
        payload_window_count += int(unit.get("payload_window_count") or 0)
    return {
        "unit_schema_counts": dict(sorted(unit_schema_counts.items())),
        "payload_window_count": payload_window_count,
    }


#Parse command-line arguments for the Step 15 checker.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Step 15 compact modification-unit outputs.")
    parser.add_argument("--output-dir", required=True, help="Step 15 policy output directory, e.g. 05_groups/fixed_packet_count_size_006.")
    parser.add_argument("--expected-strategy", choices=[HEADER_ONLY_STRATEGY, "hybrid"], help="Expected Step 15 strategy.")
    parser.add_argument("--expected-packet-count", type=int, help="Expected physical source packet count.")
    parser.add_argument("--expected-group-size", type=int, help="Expected fixed physical packet group size.")
    return parser.parse_args()


#Run the Step 15 output checks selected by the manifest strategy.
def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser()
    expected_strategy = None if args.expected_strategy == "hybrid" else args.expected_strategy
    manifest_path = find_manifest(output_dir, expected_strategy)
    manifest = read_json(manifest_path)
    common_summary = check_common_manifest(
        manifest=manifest,
        manifest_path=manifest_path,
        expected_strategy=expected_strategy,
        expected_packet_count=args.expected_packet_count,
        expected_group_size=args.expected_group_size,
    )
    strategy = manifest["metadata"].get("strategy")
    if strategy == HEADER_ONLY_STRATEGY:
        contract_summary = check_header_only_units(manifest, manifest_path)
    else:
        contract_summary = check_hybrid_units(manifest, manifest_path)
    metadata = manifest["metadata"]
    summary = {
        "status": "ok",
        "manifest": str(manifest_path),
        "manifest_schema": metadata.get("schema_version"),
        "unit_schema": metadata.get("compact_view_schema_version"),
        "strategy": strategy,
        "grouping_policy": metadata.get("grouping_policy"),
        "grouping_unit": metadata.get("grouping_unit"),
        "group_size_packets": metadata.get("group_size_packets"),
        "total_packet_count": metadata.get("total_packet_count"),
        "parent_group_count": metadata.get("parent_group_count"),
        "modification_unit_count": metadata.get("modification_unit_count"),
        "parent_group_size_statistics": metadata.get("parent_group_size_statistics"),
        "input_token_budget": metadata.get("input_token_budget"),
        "over_budget_summary": metadata.get("over_budget_summary"),
        "editable_header_regions_enabled": metadata.get("editable_header_regions_enabled"),
        "editable_payload_regions_enabled": metadata.get("editable_payload_regions_enabled"),
        "expected_editable_header_fields": metadata.get("expected_editable_header_fields"),
        **common_summary,
        **contract_summary,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Step 15 output check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
