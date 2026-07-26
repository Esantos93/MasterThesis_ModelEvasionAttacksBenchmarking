from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.ids_context import IDS_CONTEXT_MAPPING_POLICY, IDS_CONTEXT_SCHEMA_VERSION, validate_ids_context
from common.modification_strategy import (
    ModificationCapabilities,
    SUPPORTED_MODIFICATION_STRATEGIES,
    resolve_modification_strategy,
)
from common.token_budget import (
    TOKEN_BUDGET_POLICY,
    compute_payload_replacement_limit_bytes,
)
from step_15_grouping.ids_context_mapping import IdsContextMapping, load_ids_context_mapping
from step_15_grouping.payload_v3 import PAYLOAD_OWNERSHIP_POLICY, PAYLOAD_SEGMENTATION_POLICY


MANIFEST_SCHEMA = "compact_modification_units_manifest_v3"
UNIT_SCHEMA = "compact_modification_unit_v3"
PACKET_JSON_SCHEMA = "packet_json_v4"
PARENT_GROUP_INDEX_REPRESENTATION = "deduplicated_parent_group_index_v1"
PROMPT_ENGINEERING_INPUT_PROFILE = "prompt_engineering_input_profile_v1"
BASELINE_INPUT_PROFILE = "baseline_input_profile_v1"
IDS_MANIFEST_FIELDS = {
    "ids_context_enabled",
    "ids_context_schema_version",
    "ids_context_source_bundle",
    "ids_context_source_bundle_schema_version",
    "ids_context_mapping_policy",
    "ids_context_detector_definition_count",
    "ids_context_pre_alert_count",
    "ids_context_tcp_connection_count",
    "ids_context_detector_definition_counts_by_source",
    "ids_context_compact_units_with_records",
    "ids_context_compact_units_without_records",
    "ids_context_total_materialized_detector_record_count",
}


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def resolve_existing_path(path_value: Any, base_dir: Path) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError(f"Expected non-empty path string, found {path_value!r}")
    path = Path(path_value).expanduser()
    candidates = [
        path,
        base_dir / path.name,
        base_dir.parent / "pre_snort_context_source" / path.name,
        base_dir.parent.parent / "04_packet_json" / path.name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Could not resolve artifact path: {path_value}")


def find_manifest(output_dir: Path) -> Path:
    manifest_path = output_dir / f"{MANIFEST_SCHEMA}.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Step 15 V3 manifest not found: {manifest_path}")
    return manifest_path


def capabilities_for_strategy(strategy: Any) -> ModificationCapabilities:
    if not isinstance(strategy, str) or not strategy:
        raise ValueError(f"Step 15 manifest has an invalid strategy: {strategy!r}")
    return resolve_modification_strategy(
        {"pipeline": {"modification_strategy": strategy}}
    )


def check_header_classification_artifacts(
    metadata: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    manifest_path = resolve_existing_path(
        metadata.get("headers_full_classification_manifest"),
        output_dir,
    )
    jsonl_path = resolve_existing_path(
        metadata.get("headers_full_classification_jsonl"),
        output_dir,
    )
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
            "Header classification JSONL line count mismatch: "
            f"lines={line_count}, manifest_packet_count={expected_packet_count}"
        )
    return {
        "header_manifest": str(manifest_path),
        "header_jsonl": str(jsonl_path),
        "header_classification_records": line_count,
    }


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
    if metadata.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError(f"Step 15 manifest must use {MANIFEST_SCHEMA}.")
    if metadata.get("compact_view_schema_version") != UNIT_SCHEMA:
        raise ValueError(f"Step 15 units must use {UNIT_SCHEMA}.")
    if metadata.get("source_packet_json_schema_version") != PACKET_JSON_SCHEMA:
        raise ValueError(
            f"Expected source_packet_json_schema_version={PACKET_JSON_SCHEMA}, "
            f"found {metadata.get('source_packet_json_schema_version')!r}"
        )
    if metadata.get("grouping_unit") != "physical_packet":
        raise ValueError(
            f"Expected grouping_unit='physical_packet', found {metadata.get('grouping_unit')!r}"
        )

    capabilities = capabilities_for_strategy(metadata.get("strategy"))
    expected_capabilities = capabilities.as_metadata()
    if metadata.get("modification_strategy") != capabilities.strategy:
        raise ValueError("Manifest strategy and modification_strategy disagree.")
    if metadata.get("capabilities") != expected_capabilities:
        raise ValueError(
            "Manifest capabilities do not exactly match common.modification_strategy."
        )
    if expected_strategy and capabilities.strategy != expected_strategy:
        raise ValueError(
            f"Expected strategy={expected_strategy!r}, found {capabilities.strategy!r}"
        )
    expected_header_only = (
        capabilities.allows_header_edits and not capabilities.allows_payload_edits
    )
    expected_flags = {
        "header_only": expected_header_only,
        "editable_header_regions_enabled": capabilities.allows_header_edits,
        "editable_payload_regions_enabled": capabilities.allows_payload_edits,
    }
    for field, expected_value in expected_flags.items():
        if metadata.get(field) is not expected_value:
            raise ValueError(
                f"Manifest {field} must be {expected_value!r} for {capabilities.strategy}."
            )

    if expected_packet_count is not None:
        if int(metadata.get("total_packet_count") or -1) != expected_packet_count:
            raise ValueError(
                f"Expected total_packet_count={expected_packet_count}, "
                f"found {metadata.get('total_packet_count')!r}"
            )
    if expected_group_size is not None:
        if int(metadata.get("group_size_packets") or -1) != expected_group_size:
            raise ValueError(
                f"Expected group_size_packets={expected_group_size}, "
                f"found {metadata.get('group_size_packets')!r}"
            )
    if (
        metadata.get("grouping_policy") == "fixed_packet_count"
        and expected_packet_count is not None
        and expected_group_size
    ):
        expected_parent_groups = math.ceil(expected_packet_count / expected_group_size)
        if int(metadata.get("parent_group_count") or -1) != expected_parent_groups:
            raise ValueError(
                f"Expected parent_group_count={expected_parent_groups}, "
                f"found {metadata.get('parent_group_count')!r}"
            )
    if int(metadata.get("modification_unit_count") or -1) != len(units):
        raise ValueError(
            "modification_unit_count does not match compact_modification_units length."
        )
    if metadata.get("token_budget_policy") != TOKEN_BUDGET_POLICY:
        raise ValueError(f"Manifest must use token budget policy {TOKEN_BUDGET_POLICY}.")

    return check_header_classification_artifacts(metadata, manifest_path.parent)


def load_source_packet_json(
    metadata: dict[str, Any],
    output_dir: Path,
) -> tuple[dict[str, Any], Path]:
    source_path = resolve_existing_path(metadata.get("source_packet_json"), output_dir)
    source = read_json(source_path)
    if not isinstance(source, dict):
        raise ValueError("source_packet_json root must be an object.")
    source_metadata = source.get("metadata")
    if not isinstance(source_metadata, dict):
        raise ValueError("source_packet_json lacks metadata.")
    if source_metadata.get("schema_version") != PACKET_JSON_SCHEMA:
        raise ValueError(f"Step 15 source must use {PACKET_JSON_SCHEMA}.")
    for field in ("traffic", "canonical_tcp_regions", "tcp_physical_representations"):
        if not isinstance(source.get(field), list):
            raise ValueError(f"source_packet_json lacks top-level {field!r} list.")
    return source, source_path


def build_source_lookups(
    source: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, int],
    dict[str, dict[str, Any]],
    dict[str, list[str]],
    dict[tuple[str, str], set[str]],
    dict[str, dict[str, Any]],
]:
    packets_by_id: dict[str, dict[str, Any]] = {}
    packet_order: dict[str, int] = {}
    for capture_position, packet in enumerate(source["traffic"]):
        if not isinstance(packet, dict):
            raise ValueError("source_packet_json traffic entry is not an object.")
        packet_id = str(packet.get("packet_id", ""))
        if not packet_id or packet_id in packets_by_id:
            raise ValueError(f"Missing or duplicate source packet_id: {packet_id!r}.")
        packets_by_id[packet_id] = packet
        packet_order[packet_id] = capture_position

    canonical_by_id: dict[str, dict[str, Any]] = {}
    for record in source["canonical_tcp_regions"]:
        if not isinstance(record, dict):
            raise ValueError("source canonical_tcp_regions entry is not an object.")
        region_id = str(record.get("canonical_region_id", ""))
        if not region_id or region_id in canonical_by_id:
            raise ValueError(
                f"Missing or duplicate source canonical_region_id: {region_id!r}."
            )
        canonical_by_id[region_id] = record

    alias_ids_by_region: dict[str, set[str]] = {}
    representation_ids_by_region_packet: dict[tuple[str, str], set[str]] = {}
    representations_by_id: dict[str, dict[str, Any]] = {}
    for representation in source["tcp_physical_representations"]:
        if not isinstance(representation, dict):
            raise ValueError("source tcp_physical_representations entry is not an object.")
        region_id = str(representation.get("canonical_region_id", ""))
        packet_id = str(representation.get("packet_id", ""))
        representation_id = str(representation.get("physical_representation_id", ""))
        if region_id not in canonical_by_id or packet_id not in packets_by_id:
            raise ValueError(
                "Source physical representation references an unknown packet or canonical region."
            )
        if not representation_id or representation_id in representations_by_id:
            raise ValueError(
                "Source physical representation has a missing or duplicate "
                "physical_representation_id."
            )
        representations_by_id[representation_id] = representation
        alias_ids_by_region.setdefault(region_id, set()).add(packet_id)
        representation_ids_by_region_packet.setdefault(
            (region_id, packet_id),
            set(),
        ).add(representation_id)

    ordered_alias_ids_by_region = {
        region_id: sorted(packet_ids, key=packet_order.__getitem__)
        for region_id, packet_ids in alias_ids_by_region.items()
    }
    for region_id in canonical_by_id:
        if not ordered_alias_ids_by_region.get(region_id):
            raise ValueError(
                f"Source canonical region {region_id!r} has no physical packet aliases."
            )
    return (
        packets_by_id,
        packet_order,
        canonical_by_id,
        ordered_alias_ids_by_region,
        representation_ids_by_region_packet,
        representations_by_id,
    )


def validate_parent_group_index(
    *,
    manifest: dict[str, Any],
    packets_by_id: dict[str, dict[str, Any]],
    packet_order: dict[str, int],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    metadata = manifest["metadata"]
    if metadata.get("parent_group_index_representation") != PARENT_GROUP_INDEX_REPRESENTATION:
        raise ValueError(
            "Step 15 manifest does not declare the deduplicated Parent Group index."
        )
    entries = manifest.get("parent_groups")
    if not isinstance(entries, list):
        raise ValueError("Step 15 manifest lacks the parent_groups index.")
    if len(entries) != int(metadata.get("parent_group_count") or -1):
        raise ValueError("Parent Group index count does not match metadata.parent_group_count.")

    groups_by_id: dict[str, dict[str, Any]] = {}
    packet_owner: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Every parent_groups entry must be an object.")
        parent_group_id = str(entry.get("parent_group_id", ""))
        if not parent_group_id or parent_group_id in groups_by_id:
            raise ValueError(
                f"Duplicate or missing Parent Group id in index: {parent_group_id!r}."
            )
        if entry.get("grouping_policy") != metadata.get("grouping_policy"):
            raise ValueError(
                f"Parent Group {parent_group_id!r} has the wrong grouping_policy."
            )
        packet_ids = entry.get("physical_packet_ids")
        if not isinstance(packet_ids, list):
            raise ValueError(f"Parent Group {parent_group_id!r} lacks physical_packet_ids.")
        normalized_packet_ids = [str(packet_id) for packet_id in packet_ids]
        if len(normalized_packet_ids) != int(entry.get("physical_packet_count") or 0):
            raise ValueError(
                f"Parent Group {parent_group_id!r} packet count is inconsistent."
            )
        if len(normalized_packet_ids) != len(set(normalized_packet_ids)):
            raise ValueError(
                f"Parent Group {parent_group_id!r} contains duplicate packet ids."
            )
        unknown = [packet_id for packet_id in normalized_packet_ids if packet_id not in packets_by_id]
        if unknown:
            raise ValueError(
                f"Parent Group {parent_group_id!r} references unknown packets: {unknown[:10]}"
            )
        if normalized_packet_ids != sorted(normalized_packet_ids, key=packet_order.__getitem__):
            raise ValueError(
                f"Parent Group {parent_group_id!r} is not in deterministic capture order."
            )
        for packet_id in normalized_packet_ids:
            previous_owner = packet_owner.get(packet_id)
            if previous_owner is not None:
                raise ValueError(
                    f"Packet {packet_id!r} belongs to Parent Groups "
                    f"{previous_owner!r} and {parent_group_id!r}."
                )
            packet_owner[packet_id] = parent_group_id
        if metadata.get("grouping_policy") == "flow_context_aware":
            flow_summary = entry.get("parent_flow_summary")
            if not isinstance(flow_summary, dict):
                raise ValueError(
                    f"Flow Parent Group {parent_group_id!r} lacks parent_flow_summary."
                )
            connection_id = str(entry.get("tcp_connection_id", ""))
            if not connection_id or connection_id != str(
                flow_summary.get("tcp_connection_id", "")
            ):
                raise ValueError(
                    f"Flow Parent Group {parent_group_id!r} has inconsistent TCP identity."
                )
            for packet_id in normalized_packet_ids:
                if str(packets_by_id[packet_id].get("tcp_connection_id", "")) != connection_id:
                    raise ValueError(
                        f"Packet {packet_id!r} has the wrong TCP connection for "
                        f"Parent Group {parent_group_id!r}."
                    )
        groups_by_id[parent_group_id] = entry

    if set(packet_owner) != set(packets_by_id):
        missing = sorted(set(packets_by_id) - set(packet_owner))
        unexpected = sorted(set(packet_owner) - set(packets_by_id))
        raise ValueError(
            "Parent Group index does not cover source traffic exactly once: "
            f"missing={missing[:10]}, unexpected={unexpected[:10]}."
        )
    if len(packet_owner) != int(metadata.get("total_packet_count") or -1):
        raise ValueError("Parent Group coverage disagrees with metadata.total_packet_count.")

    coverage = metadata.get("physical_parent_group_coverage")
    expected_coverage = {
        "source_physical_packet_count": len(packets_by_id),
        "covered_physical_packet_count": len(packet_owner),
        "unique_covered_physical_packet_count": len(packet_owner),
        "duplicate_physical_packet_count": 0,
        "missing_physical_packet_count": 0,
    }
    if coverage != expected_coverage:
        raise ValueError(
            "physical_parent_group_coverage does not match the validated Parent Group index."
        )
    return groups_by_id, packet_owner


def prepare_ids_context(
    *,
    metadata: dict[str, Any],
    manifest_path: Path,
    source: dict[str, Any],
) -> tuple[bool, IdsContextMapping | None]:
    input_profile = metadata.get("token_budget_config", {}).get("prompt_input_profile")
    ids_aware = input_profile == PROMPT_ENGINEERING_INPUT_PROFILE
    if input_profile not in {
        BASELINE_INPUT_PROFILE,
        PROMPT_ENGINEERING_INPUT_PROFILE,
    }:
        raise ValueError(
            f"Unsupported or missing prompt input profile in manifest: {input_profile!r}."
        )
    if not ids_aware:
        unexpected_metadata = sorted(IDS_MANIFEST_FIELDS.intersection(metadata))
        if unexpected_metadata:
            raise ValueError(
                f"Baseline manifest contains IDS-context metadata: {unexpected_metadata}"
            )
        return False, None

    missing_metadata = sorted(IDS_MANIFEST_FIELDS - set(metadata))
    if missing_metadata:
        raise ValueError(f"IDS-aware manifest lacks metadata fields: {missing_metadata}")
    if metadata.get("ids_context_enabled") is not True:
        raise ValueError("IDS-aware manifest must set ids_context_enabled=true.")
    if metadata.get("ids_context_schema_version") != IDS_CONTEXT_SCHEMA_VERSION:
        raise ValueError("IDS-aware manifest records the wrong ids_context schema.")
    if metadata.get("ids_context_mapping_policy") != IDS_CONTEXT_MAPPING_POLICY:
        raise ValueError("IDS-aware manifest records the wrong IDS mapping policy.")
    mapping = load_ids_context_mapping(
        source_bundle_path=resolve_existing_path(
            metadata.get("ids_context_source_bundle"),
            manifest_path.parent,
        ),
        traffic=source["traffic"],
    )
    return True, mapping


def validate_group_metadata(
    *,
    unit: dict[str, Any],
    unit_path: Path,
    parent_entry: dict[str, Any],
) -> None:
    group_metadata = unit.get("group_metadata")
    if not isinstance(group_metadata, dict):
        raise ValueError(f"Unit {unit_path} lacks group_metadata.")
    if "physical_packet_ids" in group_metadata:
        raise ValueError(f"Unit {unit_path} replicates Parent Group physical_packet_ids.")
    for field in (
        "parent_group_id",
        "grouping_policy",
        "physical_packet_count",
        "first_reduced_packet_index",
        "last_reduced_packet_index",
    ):
        if group_metadata.get(field) != parent_entry.get(field):
            raise ValueError(
                f"Unit {unit_path} group_metadata.{field} does not match "
                "its Parent Group index entry."
            )


def validate_header_region(
    *,
    region: dict[str, Any],
    packet_id: str,
    expected_header_fields: set[str],
    unit_path: Path,
) -> None:
    if region.get("editable") is not True:
        raise ValueError(f"Unit {unit_path} contains a non-editable header target.")
    if region.get("identity_type") != "physical_header_region":
        raise ValueError(f"Unit {unit_path} contains non-physical header ownership.")
    if region.get("region_type") != "header_field":
        raise ValueError(f"Unit {unit_path} contains an unexpected header region_type.")
    if str(region.get("packet_id", "")) != packet_id:
        raise ValueError(f"Unit {unit_path} header target has the wrong packet_id.")
    if region.get("field") not in expected_header_fields:
        raise ValueError(
            f"Unit {unit_path} exposes unexpected editable field {region.get('field')!r}."
        )
    if region.get("operation") != "replace_uint":
        raise ValueError(f"Unit {unit_path} header operation must be replace_uint.")
    if region.get("replacement_format") != "uint":
        raise ValueError(f"Unit {unit_path} header replacement format must be uint.")
    if region.get("current_value") is None and region.get("original_value") is None:
        raise ValueError(f"Unit {unit_path} header target lacks its original value.")
    constraints = region.get("constraints")
    if not isinstance(constraints, dict) or "min" not in constraints or "max" not in constraints:
        raise ValueError(f"Unit {unit_path} header target lacks min/max constraints.")
    if region.get("min") != constraints["min"] or region.get("max") != constraints["max"]:
        raise ValueError(f"Unit {unit_path} header target duplicates inconsistent limits.")


def validate_payload_entry(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    unit_path: Path,
    canonical_by_id: dict[str, dict[str, Any]],
    ordered_alias_ids_by_region: dict[str, list[str]],
    representation_ids_by_region_packet: dict[tuple[str, str], set[str]],
    representations_by_id: dict[str, dict[str, Any]],
    payload_replacement_size_policy: dict[str, Any],
    packet_owner: dict[str, str],
    packets_by_id: dict[str, dict[str, Any]],
    intervals_by_region: dict[str, list[tuple[int, int]]],
    payload_target_ids: set[str],
) -> int:
    region_id = str(entry.get("canonical_region_id", ""))
    source_region = canonical_by_id.get(region_id)
    if source_region is None:
        raise ValueError(
            f"Unit {unit_path} references unknown canonical region {region_id!r}."
        )
    if entry.get("role") != "editable_owner" or entry.get("editable") is not True:
        raise ValueError(
            f"Unit {unit_path} canonical region {region_id!r} is not an editable owner."
        )
    source_length = int(source_region.get("length") or 0)
    if int(entry.get("payload_length_bytes") or -1) != source_length:
        raise ValueError(
            f"Unit {unit_path} canonical region {region_id!r} has the wrong payload length."
        )

    ownership = entry.get("ownership")
    if not isinstance(ownership, dict):
        raise ValueError(f"Unit {unit_path} payload entry lacks ownership.")
    if ownership.get("policy") != PAYLOAD_OWNERSHIP_POLICY:
        raise ValueError(f"Unit {unit_path} payload entry uses the wrong ownership policy.")
    parent_group_id = str(unit["parent_group_id"])
    modification_unit_id = str(unit["modification_unit_id"])
    if str(ownership.get("owner_parent_group_id", "")) != parent_group_id:
        raise ValueError(f"Unit {unit_path} emits payload outside its owner Parent Group.")
    if str(ownership.get("anchor_group_fragment_id", "")) != modification_unit_id:
        raise ValueError(f"Unit {unit_path} payload anchor does not match its Compact Unit.")

    aliases = entry.get("physical_aliases")
    if not isinstance(aliases, list) or not aliases:
        raise ValueError(f"Unit {unit_path} payload entry lacks physical_aliases.")
    alias_packet_ids: list[str] = []
    for alias in aliases:
        if not isinstance(alias, dict):
            raise ValueError(f"Unit {unit_path} physical alias is not an object.")
        alias_packet_id = str(alias.get("packet_id", ""))
        if alias_packet_id not in packets_by_id:
            raise ValueError(f"Unit {unit_path} contains an unknown physical alias.")
        if int(alias.get("reduced_packet_index") or -1) != int(
            packets_by_id[alias_packet_id]["reduced_packet_index"]
        ):
            raise ValueError(f"Unit {unit_path} physical alias has the wrong capture index.")
        representations = alias.get("representations")
        if not isinstance(representations, list) or not representations:
            raise ValueError(f"Unit {unit_path} physical alias lacks representations.")
        actual_representation_ids = {
            str(representation.get("physical_representation_id", ""))
            for representation in representations
            if isinstance(representation, dict)
        }
        expected_representation_ids = representation_ids_by_region_packet.get(
            (region_id, alias_packet_id),
            set(),
        )
        if actual_representation_ids != expected_representation_ids:
            raise ValueError(
                f"Unit {unit_path} physical alias representation set is incomplete."
            )
        for representation in representations:
            if not isinstance(representation, dict):
                raise ValueError(f"Unit {unit_path} physical representation is not an object.")
            representation_id = str(
                representation.get("physical_representation_id", "")
            )
            source_representation = representations_by_id.get(representation_id)
            if source_representation is None:
                raise ValueError(
                    f"Unit {unit_path} references an unknown physical representation."
                )
            expected_projection = {
                "physical_representation_id": representation_id,
                "stream_start": int(source_representation["stream_start"]),
                "stream_end": int(source_representation["stream_end"]),
                "packet_payload_offset_start_bytes": int(
                    source_representation["packet_payload_offset_start_bytes"]
                ),
                "packet_payload_offset_end_bytes": int(
                    source_representation["packet_payload_offset_end_bytes"]
                ),
            }
            if representation != expected_projection:
                raise ValueError(
                    f"Unit {unit_path} physical alias offsets disagree with Step 14."
                )
        alias_packet_ids.append(alias_packet_id)
    expected_alias_ids = ordered_alias_ids_by_region[region_id]
    if alias_packet_ids != expected_alias_ids:
        raise ValueError(
            f"Unit {unit_path} physical_aliases do not preserve the complete capture order."
        )
    representative_packet_id = str(ownership.get("representative_packet_id", ""))
    if representative_packet_id != expected_alias_ids[0]:
        raise ValueError(
            f"Unit {unit_path} representative_packet_id is not the first physical alias."
        )
    if packet_owner.get(representative_packet_id) != parent_group_id:
        raise ValueError(
            f"Unit {unit_path} owner_parent_group_id is not owned by the first alias."
        )

    segmentation = entry.get("semantic_segmentation")
    if not isinstance(segmentation, dict):
        raise ValueError(f"Unit {unit_path} payload entry lacks segmentation provenance.")
    if segmentation.get("policy") != PAYLOAD_SEGMENTATION_POLICY:
        raise ValueError(f"Unit {unit_path} payload entry uses the wrong segmentation policy.")

    editable_regions = entry.get("editable_regions")
    if not isinstance(editable_regions, list) or not editable_regions:
        raise ValueError(f"Unit {unit_path} payload entry lacks editable_regions.")
    source_payload_hex = str(source_region.get("payload_hex", "") or "").lower()
    if len(source_payload_hex) != source_length * 2:
        raise ValueError(f"Source canonical region {region_id!r} has invalid payload_hex.")

    entry_target_count = 0
    for target in editable_regions:
        if not isinstance(target, dict):
            raise ValueError(f"Unit {unit_path} payload target is not an object.")
        if target.get("editable") is not True:
            raise ValueError(f"Unit {unit_path} payload target is not editable.")
        if str(target.get("canonical_region_id", "")) != region_id:
            raise ValueError(f"Unit {unit_path} payload target has the wrong canonical id.")
        if target.get("coordinate_space") != "canonical_tcp_region":
            raise ValueError(f"Unit {unit_path} payload target uses the wrong coordinate space.")
        if target.get("format") != "hex":
            raise ValueError(f"Unit {unit_path} payload target must use hex format.")
        target_id = str(target.get("region_id", ""))
        if not target_id or target_id in payload_target_ids:
            raise ValueError(f"Unit {unit_path} has a missing or duplicate payload region_id.")
        payload_target_ids.add(target_id)

        required_fields = {
            "authorized_start_offset_bytes",
            "authorized_end_offset_bytes",
            "authorized_length_bytes",
            "max_replacement_bytes",
            "max_replacement_hex_chars",
        }
        if not required_fields.issubset(target):
            raise ValueError(
                f"Unit {unit_path} payload target lacks explicit authorization limits."
            )
        start = int(target["authorized_start_offset_bytes"])
        end = int(target["authorized_end_offset_bytes"])
        length = int(target["authorized_length_bytes"])
        if start < 0 or end <= start or end > source_length or length != end - start:
            raise ValueError(f"Unit {unit_path} payload target has an invalid authorized range.")
        if (
            int(target.get("start_offset_bytes", -1)) != start
            or int(target.get("end_offset_bytes", -1)) != end
            or int(target.get("length_bytes", -1)) != length
        ):
            raise ValueError(
                f"Unit {unit_path} payload target range disagrees with its authorization."
            )
        max_replacement_bytes = int(target["max_replacement_bytes"])
        max_replacement_hex_chars = int(target["max_replacement_hex_chars"])
        if max_replacement_bytes <= 0:
            raise ValueError(f"Unit {unit_path} payload replacement limit must be positive.")
        if max_replacement_hex_chars != max_replacement_bytes * 2:
            raise ValueError(
                f"Unit {unit_path} payload byte and hex replacement limits disagree."
            )
        size_limit = target.get("replacement_size_limit")
        if not isinstance(size_limit, dict):
            raise ValueError(f"Unit {unit_path} payload target lacks replacement_size_limit.")
        expected_size_limit = compute_payload_replacement_limit_bytes(
            original_size_bytes=length,
            policy=payload_replacement_size_policy,
        )
        if size_limit != expected_size_limit:
            raise ValueError(
                f"Unit {unit_path} payload replacement_size_limit does not match "
                "the manifest policy."
            )
        if target.get("replacement_size_policy") != expected_size_limit["policy"]:
            raise ValueError(
                f"Unit {unit_path} payload replacement_size_policy is inconsistent."
            )
        if (
            int(size_limit.get("effective_limit_bytes") or -1)
            != max_replacement_bytes
            or int(size_limit.get("effective_limit_hex_chars") or -1)
            != max_replacement_hex_chars
        ):
            raise ValueError(
                f"Unit {unit_path} payload replacement_size_limit is inconsistent."
            )
        expected_value = source_payload_hex[start * 2 : end * 2]
        if str(target.get("value", "")).lower() != expected_value:
            raise ValueError(
                f"Unit {unit_path} payload target value does not match canonical source bytes."
            )
        allowed_operations = target.get("allowed_operations")
        if not isinstance(allowed_operations, list) or len(allowed_operations) != 1:
            raise ValueError(f"Unit {unit_path} payload target must authorize one operation.")
        intervals_by_region.setdefault(region_id, []).append((start, end))
        entry_target_count += 1

    payload_view = entry.get("payload_view")
    if not isinstance(payload_view, dict):
        raise ValueError(f"Unit {unit_path} payload entry lacks payload_view.")
    first_target = editable_regions[0]
    if len(editable_regions) == 1 and (
        int(payload_view.get("editable_start_offset_bytes", -1))
        != int(first_target["authorized_start_offset_bytes"])
        or int(payload_view.get("editable_end_offset_bytes", -1))
        != int(first_target["authorized_end_offset_bytes"])
        or str(payload_view.get("editable_value", "")).lower()
        != str(first_target.get("value", "")).lower()
    ):
        raise ValueError(f"Unit {unit_path} payload_view disagrees with its editable target.")
    return entry_target_count


def validate_token_plan(
    *,
    unit: dict[str, Any],
    unit_path: Path,
    actual_header_count: int,
    actual_payload_count: int,
) -> int:
    token_plan = unit.get("token_plan")
    if not isinstance(token_plan, dict):
        raise ValueError(f"V3 unit {unit_path} lacks token_plan.")
    if token_plan.get("policy") != TOKEN_BUDGET_POLICY:
        raise ValueError(f"V3 unit {unit_path} uses the wrong token-budget policy.")
    estimated_input_tokens = int(token_plan.get("estimated_input_tokens") or 0)
    planned_output_tokens = int(token_plan.get("planned_output_tokens") or 0)
    total_planned_tokens = int(token_plan.get("total_planned_tokens") or 0)
    prompt_target_context = int(token_plan.get("prompt_target_context") or 0)
    overflow_tokens = int(token_plan.get("overflow_tokens") or 0)
    expected_overflow = max(0, total_planned_tokens - prompt_target_context)
    if planned_output_tokens <= 0:
        raise ValueError(f"V3 unit {unit_path} has no planned output allowance.")
    if total_planned_tokens != estimated_input_tokens + planned_output_tokens:
        raise ValueError(f"V3 unit {unit_path} has an inconsistent token total.")
    if int(token_plan.get("max_tokens") or -1) != planned_output_tokens:
        raise ValueError(f"V3 unit {unit_path} max_tokens is inconsistent.")
    if overflow_tokens != expected_overflow:
        raise ValueError(f"V3 unit {unit_path} has an inconsistent overflow count.")
    if bool(token_plan.get("fits_prompt_target_context")) != (overflow_tokens == 0):
        raise ValueError(f"V3 unit {unit_path} has an inconsistent fit flag.")
    if unit.get("token_planning_validation_status") != "validated_v3_planning_path":
        raise ValueError(f"V3 unit {unit_path} lacks V3 token-planning validation status.")
    breakdown = token_plan.get("breakdown")
    if not isinstance(breakdown, dict):
        raise ValueError(f"V3 unit {unit_path} token plan lacks breakdown.")
    if bool(breakdown.get("has_editable_headers")) != (actual_header_count > 0):
        raise ValueError(f"V3 unit {unit_path} token plan misstates header target presence.")
    if bool(breakdown.get("has_editable_payload")) != (actual_payload_count > 0):
        raise ValueError(f"V3 unit {unit_path} token plan misstates payload target presence.")
    if actual_header_count + actual_payload_count > 0 and overflow_tokens:
        raise ValueError(
            f"Routable V3 unit {unit_path} exceeds prompt_target_context by "
            f"{overflow_tokens} tokens."
        )
    return overflow_tokens


def represented_parent_packet_ids(
    *,
    unit: dict[str, Any],
    parent_group_id: str,
    packet_owner: dict[str, str],
    packet_order: dict[str, int],
) -> list[str]:
    represented: set[str] = {
        str(packet.get("packet_id", ""))
        for packet in unit.get("physical_packets", [])
        if isinstance(packet, dict)
    }
    for entry in unit.get("canonical_payload_regions", []):
        if not isinstance(entry, dict):
            continue
        for alias in entry.get("physical_aliases", []):
            if not isinstance(alias, dict):
                continue
            packet_id = str(alias.get("packet_id", ""))
            if packet_owner.get(packet_id) == parent_group_id:
                represented.add(packet_id)
    represented.discard("")
    return sorted(represented, key=packet_order.__getitem__)


def validate_flow_context(
    *,
    unit: dict[str, Any],
    unit_path: Path,
    parent_entry: dict[str, Any],
    represented_packet_ids: list[str],
) -> tuple[int, int]:
    flow_context = unit.get("fragment_flow_context")
    compact_context = unit.get("fragment_compact_unit_context")
    if not isinstance(flow_context, dict) or not isinstance(compact_context, dict):
        raise ValueError(
            f"Flow-context-aware unit {unit_path} lacks its two fragment context objects."
        )
    connection_id = str(parent_entry.get("tcp_connection_id", ""))
    if (
        str(flow_context.get("flow_id", "")) != connection_id
        or str(flow_context.get("tcp_connection_id", "")) != connection_id
    ):
        raise ValueError(f"Flow context in {unit_path} has the wrong TCP identity.")
    if compact_context.get("parent_group_id") != unit.get("parent_group_id"):
        raise ValueError(f"Compact-unit context in {unit_path} has the wrong Parent Group.")
    if compact_context.get("group_fragment_id") != unit.get("modification_unit_id"):
        raise ValueError(f"Compact-unit context in {unit_path} has the wrong fragment id.")
    if not represented_packet_ids:
        raise ValueError(f"Flow-context-aware unit {unit_path} has no physical packet anchor.")

    parent_packet_ids = [str(value) for value in parent_entry["physical_packet_ids"]]
    position_by_packet = {
        packet_id: position
        for position, packet_id in enumerate(parent_packet_ids, start=1)
    }
    positions = [position_by_packet[packet_id] for packet_id in represented_packet_ids]
    if int(flow_context.get("flow_packet_first_index") or -1) != min(positions):
        raise ValueError(f"Flow context in {unit_path} has the wrong first packet index.")
    if int(flow_context.get("flow_packet_last_packet_index") or -1) != max(positions):
        raise ValueError(f"Flow context in {unit_path} has the wrong last packet index.")
    if int(compact_context.get("fragment_physical_packet_count") or -1) != len(
        represented_packet_ids
    ):
        raise ValueError(f"Compact-unit context in {unit_path} has the wrong packet count.")
    if str(compact_context.get("fragment_first_packet_id", "")) != represented_packet_ids[0]:
        raise ValueError(f"Compact-unit context in {unit_path} has the wrong first packet.")
    if str(compact_context.get("fragment_last_packet_id", "")) != represented_packet_ids[-1]:
        raise ValueError(f"Compact-unit context in {unit_path} has the wrong last packet.")
    fragment_index = int(compact_context.get("compact_unit_index") or -1)
    fragment_count = int(compact_context.get("compact_unit_count") or -1)
    if fragment_index <= 0 or fragment_count <= 0 or fragment_index > fragment_count:
        raise ValueError(f"Compact-unit context in {unit_path} has invalid fragment indexes.")
    return fragment_index, fragment_count


def validate_canonical_coverage(
    *,
    capabilities: ModificationCapabilities,
    canonical_by_id: dict[str, dict[str, Any]],
    intervals_by_region: dict[str, list[tuple[int, int]]],
) -> dict[str, int]:
    if not capabilities.allows_payload_edits:
        if intervals_by_region:
            raise ValueError("Header-only V3 output contains editable canonical payload.")
        return {
            "canonical_region_count": len(canonical_by_id),
            "editable_canonical_region_count": 0,
            "editable_canonical_payload_byte_count": 0,
            "duplicate_editable_byte_count": 0,
            "missing_editable_byte_count": 0,
            "overlapping_editable_interval_count": 0,
        }

    editable_region_count = 0
    editable_byte_count = 0
    remaining = dict(intervals_by_region)
    for region_id, source_region in canonical_by_id.items():
        payload_length = int(source_region.get("length") or 0)
        intervals = sorted(remaining.pop(region_id, []))
        if payload_length == 0:
            if intervals:
                raise ValueError(
                    f"Empty canonical region {region_id!r} has editable payload targets."
                )
            continue
        editable_region_count += 1
        cursor = 0
        for start, end in intervals:
            if start != cursor:
                relationship = "overlap" if start < cursor else "gap"
                raise ValueError(
                    f"Canonical payload ownership {relationship} for region {region_id!r}: "
                    f"expected_start={cursor}, actual_start={start}."
                )
            if end <= start or end > payload_length:
                raise ValueError(
                    f"Canonical payload interval for region {region_id!r} is out of bounds."
                )
            editable_byte_count += end - start
            cursor = end
        if cursor != payload_length:
            raise ValueError(
                f"Canonical payload ownership gap for region {region_id!r}: "
                f"covered={cursor}, expected={payload_length}."
            )
    if remaining:
        raise ValueError(
            f"V3 payload targets reference unknown canonical regions: "
            f"{sorted(remaining)[:10]}"
        )
    return {
        "canonical_region_count": len(canonical_by_id),
        "editable_canonical_region_count": editable_region_count,
        "editable_canonical_payload_byte_count": editable_byte_count,
        "duplicate_editable_byte_count": 0,
        "missing_editable_byte_count": 0,
        "overlapping_editable_interval_count": 0,
    }


def check_v3_units(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    metadata = manifest["metadata"]
    capabilities = capabilities_for_strategy(metadata.get("strategy"))
    expected_capabilities = capabilities.as_metadata()
    source, source_path = load_source_packet_json(metadata, manifest_path.parent)
    (
        packets_by_id,
        packet_order,
        canonical_by_id,
        ordered_alias_ids_by_region,
        representation_ids_by_region_packet,
        representations_by_id,
    ) = build_source_lookups(source)
    parent_groups_by_id, packet_owner = validate_parent_group_index(
        manifest=manifest,
        packets_by_id=packets_by_id,
        packet_order=packet_order,
    )

    expected_header_fields = {
        str(field) for field in metadata.get("expected_editable_header_fields", [])
    }
    if capabilities.allows_header_edits and not expected_header_fields:
        raise ValueError(
            "Header-capable V3 manifest must record expected_editable_header_fields."
        )
    if not capabilities.allows_header_edits and (
        "expected_editable_header_fields" in metadata
    ):
        raise ValueError(
            "Payload-only V3 manifest must not declare editable header fields."
        )

    payload_contract = metadata.get("payload_contract")
    payload_replacement_size_policy: dict[str, Any] = {}
    if capabilities.allows_payload_edits:
        if not isinstance(payload_contract, dict):
            raise ValueError("Payload-capable V3 manifest lacks payload_contract.")
        expected_payload_contract_fields = {
            "ownership_policy": PAYLOAD_OWNERSHIP_POLICY,
            "segmentation_policy": PAYLOAD_SEGMENTATION_POLICY,
            "canonical_payload_container": "canonical_payload_regions",
            "editable_target_container": "editable_regions",
            "ownership_container": "ownership",
            "alias_context_container": "physical_aliases",
        }
        for field, expected_value in expected_payload_contract_fields.items():
            if payload_contract.get(field) != expected_value:
                raise ValueError(
                    f"Manifest payload_contract.{field} must be {expected_value!r}."
                )
        authorization_fields = payload_contract.get("authorization_fields")
        if not isinstance(authorization_fields, dict):
            raise ValueError("Manifest payload_contract lacks authorization_fields.")
        if authorization_fields.get("authorized_range") != [
            "authorized_start_offset_bytes",
            "authorized_end_offset_bytes",
            "authorized_length_bytes",
        ]:
            raise ValueError("Manifest payload authorized-range fields are inconsistent.")
        if authorization_fields.get("replacement_limits") != [
            "max_replacement_bytes",
            "max_replacement_hex_chars",
        ]:
            raise ValueError("Manifest payload replacement-limit fields are inconsistent.")
        payload_replacement_size_policy = payload_contract.get(
            "payload_replacement_size_policy"
        )
        if not isinstance(payload_replacement_size_policy, dict):
            raise ValueError(
                "Manifest payload_contract lacks payload_replacement_size_policy."
            )
    elif "payload_contract" in metadata:
        raise ValueError("Header-only V3 manifest must not expose payload_contract.")

    ids_aware, ids_mapping = prepare_ids_context(
        metadata=metadata,
        manifest_path=manifest_path,
        source=source,
    )

    unit_schema_counts: Counter[str] = Counter()
    target_presence_counts: Counter[str] = Counter()
    header_field_counts: Counter[str] = Counter()
    token_plan_policy_counts: Counter[str] = Counter()
    header_packet_ids: list[str] = []
    header_packet_ids_by_parent: dict[str, list[str]] = {
        parent_group_id: [] for parent_group_id in parent_groups_by_id
    }
    header_region_ids: set[str] = set()
    payload_target_ids: set[str] = set()
    intervals_by_region: dict[str, list[tuple[int, int]]] = {}
    flow_fragment_indexes: dict[str, list[tuple[int, int]]] = {}
    ids_context_units_with_records = 0
    ids_context_units_without_records = 0
    ids_context_total_records = 0
    editable_header_region_count = 0
    editable_payload_region_count = 0
    canonical_payload_entry_count = 0
    token_plan_overflow_count = 0
    modification_unit_ids: set[str] = set()

    for summary_entry in manifest["compact_modification_units"]:
        if not isinstance(summary_entry, dict):
            raise ValueError("Compact Modification Unit summary is not an object.")
        unit_path = resolve_existing_path(
            summary_entry.get("modification_unit_file"),
            manifest_path.parent,
        )
        unit = read_json(unit_path)
        if not isinstance(unit, dict):
            raise ValueError(f"Unit {unit_path} root is not an object.")
        unit_schema_counts[str(unit.get("schema_version"))] += 1
        if unit.get("schema_version") != UNIT_SCHEMA:
            raise ValueError(
                f"Unit {unit_path} has wrong schema {unit.get('schema_version')!r}."
            )
        if unit.get("strategy") != capabilities.strategy:
            raise ValueError(f"Unit {unit_path} has the wrong strategy.")
        if unit.get("modification_strategy") != capabilities.strategy:
            raise ValueError(f"Unit {unit_path} has the wrong modification_strategy.")
        if unit.get("capabilities") != expected_capabilities:
            raise ValueError(
                f"Unit {unit_path} capabilities do not exactly match "
                "common.modification_strategy."
            )
        if summary_entry.get("capabilities") != expected_capabilities:
            raise ValueError(f"Unit summary {unit_path} has the wrong capabilities.")
        expected_header_only = (
            capabilities.allows_header_edits and not capabilities.allows_payload_edits
        )
        unit_flags = {
            "header_only": expected_header_only,
            "editable_header_regions_enabled": capabilities.allows_header_edits,
            "editable_payload_regions_enabled": capabilities.allows_payload_edits,
        }
        for field, expected_value in unit_flags.items():
            if unit.get(field) is not expected_value:
                raise ValueError(
                    f"Unit {unit_path} {field} must be {expected_value!r}."
                )

        parent_group_id = str(unit.get("parent_group_id", ""))
        parent_entry = parent_groups_by_id.get(parent_group_id)
        if parent_entry is None:
            raise ValueError(
                f"Unit {unit_path} references unknown Parent Group {parent_group_id!r}."
            )
        modification_unit_id = str(unit.get("modification_unit_id", ""))
        if not modification_unit_id or modification_unit_id in modification_unit_ids:
            raise ValueError(
                f"Missing or duplicate modification_unit_id={modification_unit_id!r}."
            )
        modification_unit_ids.add(modification_unit_id)
        if summary_entry.get("parent_group_id") != parent_group_id:
            raise ValueError(f"Unit summary {unit_path} has the wrong parent_group_id.")
        if summary_entry.get("modification_unit_id") != modification_unit_id:
            raise ValueError(f"Unit summary {unit_path} has the wrong modification_unit_id.")
        validate_group_metadata(
            unit=unit,
            unit_path=unit_path,
            parent_entry=parent_entry,
        )

        physical_packets = unit.get("physical_packets", [])
        if not isinstance(physical_packets, list):
            raise ValueError(f"Unit {unit_path} physical_packets must be a list.")
        if not capabilities.allows_header_edits and "physical_packets" in unit:
            raise ValueError(
                f"Payload-only unit {unit_path} must not expose physical header owners."
            )
        unit_header_count = 0
        for physical_packet in physical_packets:
            if not isinstance(physical_packet, dict):
                raise ValueError(f"Unit {unit_path} physical packet is not an object.")
            packet_id = str(physical_packet.get("packet_id", ""))
            if packet_owner.get(packet_id) != parent_group_id:
                raise ValueError(
                    f"Unit packet {packet_id!r} does not belong to "
                    f"Parent Group {parent_group_id!r}."
                )
            header_packet_ids.append(packet_id)
            header_packet_ids_by_parent[parent_group_id].append(packet_id)
            regions = physical_packet.get("header_field_classifications")
            if not isinstance(regions, list) or not regions:
                raise ValueError(
                    f"Header owner packet {packet_id!r} has no editable header regions."
                )
            if int(physical_packet.get("editable_header_region_count") or -1) != len(
                regions
            ):
                raise ValueError(
                    f"Header owner packet {packet_id!r} has an inconsistent region count."
                )
            for region in regions:
                if not isinstance(region, dict):
                    raise ValueError(f"Unit {unit_path} header target is not an object.")
                validate_header_region(
                    region=region,
                    packet_id=packet_id,
                    expected_header_fields=expected_header_fields,
                    unit_path=unit_path,
                )
                region_id = str(region.get("region_id", ""))
                if not region_id or region_id in header_region_ids:
                    raise ValueError(
                        f"Unit {unit_path} has a missing or duplicate header region_id."
                    )
                header_region_ids.add(region_id)
                header_field_counts[str(region["field"])] += 1
                unit_header_count += 1

        payload_entries = unit.get("canonical_payload_regions", [])
        if not isinstance(payload_entries, list):
            raise ValueError(f"Unit {unit_path} canonical_payload_regions must be a list.")
        if "canonical_payload_regions" in unit and not payload_entries:
            raise ValueError(f"Unit {unit_path} contains an empty canonical payload container.")
        if not capabilities.allows_payload_edits and "canonical_payload_regions" in unit:
            raise ValueError(f"Header-only unit {unit_path} exposes canonical payload.")

        unit_payload_count = 0
        for payload_entry in payload_entries:
            if not isinstance(payload_entry, dict):
                raise ValueError(f"Unit {unit_path} canonical payload entry is not an object.")
            unit_payload_count += validate_payload_entry(
                entry=payload_entry,
                unit=unit,
                unit_path=unit_path,
                canonical_by_id=canonical_by_id,
                ordered_alias_ids_by_region=ordered_alias_ids_by_region,
                representation_ids_by_region_packet=representation_ids_by_region_packet,
                representations_by_id=representations_by_id,
                payload_replacement_size_policy=payload_replacement_size_policy,
                packet_owner=packet_owner,
                packets_by_id=packets_by_id,
                intervals_by_region=intervals_by_region,
                payload_target_ids=payload_target_ids,
            )
        canonical_payload_entry_count += len(payload_entries)
        if unit_payload_count:
            payload_authorization = unit.get("payload_authorization")
            if not isinstance(payload_authorization, dict):
                raise ValueError(f"Payload unit {unit_path} lacks payload_authorization.")
            if payload_authorization.get("ownership_policy") != PAYLOAD_OWNERSHIP_POLICY:
                raise ValueError(f"Payload unit {unit_path} has the wrong ownership policy.")
            if payload_authorization.get("segmentation_policy") != PAYLOAD_SEGMENTATION_POLICY:
                raise ValueError(f"Payload unit {unit_path} has the wrong segmentation policy.")
        elif "payload_authorization" in unit:
            raise ValueError(
                f"Unit {unit_path} exposes payload authorization without payload targets."
            )

        actual_presence = {
            "editable_headers_present": unit_header_count > 0,
            "editable_payload_present": unit_payload_count > 0,
        }
        if unit.get("editable_target_presence") != actual_presence:
            raise ValueError(
                f"Unit {unit_path} editable_target_presence disagrees with its targets."
            )
        presence_label = (
            "hybrid"
            if unit_header_count and unit_payload_count
            else "header_only"
            if unit_header_count
            else "payload_only"
            if unit_payload_count
            else "context_only"
        )
        target_presence_counts[presence_label] += 1

        expected_counts = {
            "editable_header_region_count": unit_header_count,
            "editable_payload_region_count": unit_payload_count,
            "editable_region_count": unit_header_count + unit_payload_count,
        }
        for field, expected_value in expected_counts.items():
            if int(unit.get(field) or 0) != expected_value:
                raise ValueError(f"Unit {unit_path} has an inconsistent {field}.")
            if int(summary_entry.get(field) or 0) != expected_value:
                raise ValueError(f"Unit summary {unit_path} has an inconsistent {field}.")
        if int(summary_entry.get("physical_packet_count") or 0) != len(
            physical_packets
        ):
            raise ValueError(f"Unit summary {unit_path} has the wrong physical packet count.")
        if int(summary_entry.get("canonical_payload_region_entry_count") or 0) != len(
            payload_entries
        ):
            raise ValueError(f"Unit summary {unit_path} has the wrong payload entry count.")

        overflow_tokens = validate_token_plan(
            unit=unit,
            unit_path=unit_path,
            actual_header_count=unit_header_count,
            actual_payload_count=unit_payload_count,
        )
        if overflow_tokens:
            raise ValueError(
                f"V3 unit {unit_path} exceeds prompt_target_context by "
                f"{overflow_tokens} tokens."
            )
        token_plan_policy_counts[str(unit["token_plan"]["policy"])] += 1
        token_plan_overflow_count += int(overflow_tokens > 0)
        if summary_entry.get("token_plan") != unit.get("token_plan"):
            raise ValueError(f"Unit summary {unit_path} has a different token plan.")

        represented_packet_ids = represented_parent_packet_ids(
            unit=unit,
            parent_group_id=parent_group_id,
            packet_owner=packet_owner,
            packet_order=packet_order,
        )
        if metadata.get("grouping_policy") == "flow_context_aware":
            fragment_index, fragment_count = validate_flow_context(
                unit=unit,
                unit_path=unit_path,
                parent_entry=parent_entry,
                represented_packet_ids=represented_packet_ids,
            )
            flow_fragment_indexes.setdefault(parent_group_id, []).append(
                (fragment_index, fragment_count)
            )

        if ids_aware:
            if "ids_context" not in unit:
                raise ValueError(f"IDS-aware unit {unit_path} lacks ids_context.")
            validate_ids_context(unit["ids_context"])
            assert ids_mapping is not None
            expected_context = ids_mapping.materialize(
                [packets_by_id[packet_id] for packet_id in represented_packet_ids]
            )
            if unit["ids_context"] != expected_context:
                raise ValueError(
                    f"IDS context in {unit_path} does not match conservative propagation."
                )
            record_count = len(unit["ids_context"]["records"])
            ids_context_total_records += record_count
            if record_count:
                ids_context_units_with_records += 1
            else:
                ids_context_units_without_records += 1
            if int(summary_entry.get("ids_context_record_count") or 0) != record_count:
                raise ValueError(f"IDS-context summary count mismatch for {unit_path}.")
        elif "ids_context" in unit or "ids_context_record_count" in summary_entry:
            raise ValueError(
                f"Baseline unit or summary unexpectedly exposes IDS context: {unit_path}"
            )

        editable_header_region_count += unit_header_count
        editable_payload_region_count += unit_payload_count

    if capabilities.allows_header_edits:
        expected_packet_ids = set(packets_by_id)
        header_counts = Counter(header_packet_ids)
        duplicates = sorted(
            packet_id for packet_id, count in header_counts.items() if count > 1
        )
        missing = sorted(expected_packet_ids - set(header_counts))
        unexpected = sorted(set(header_counts) - expected_packet_ids)
        if duplicates or missing or unexpected:
            raise ValueError(
                "Editable physical-header ownership is not exactly once per packet: "
                f"duplicates={duplicates[:10]}, missing={missing[:10]}, "
                f"unexpected={unexpected[:10]}."
            )
        for parent_group_id, parent_entry in parent_groups_by_id.items():
            expected_parent_packet_ids = [
                str(packet_id) for packet_id in parent_entry["physical_packet_ids"]
            ]
            if header_packet_ids_by_parent[parent_group_id] != expected_parent_packet_ids:
                raise ValueError(
                    "Editable physical-header ownership does not preserve packet order in "
                    f"Parent Group {parent_group_id!r}."
                )
    elif header_packet_ids or header_region_ids:
        raise ValueError("Payload-only V3 output contains editable physical-header ownership.")

    payload_coverage = validate_canonical_coverage(
        capabilities=capabilities,
        canonical_by_id=canonical_by_id,
        intervals_by_region=intervals_by_region,
    )
    expected_ownership_coverage = {
        "header_owner_physical_packet_count": (
            len(packets_by_id) if capabilities.allows_header_edits else 0
        ),
        "duplicate_header_owner_physical_packet_count": 0,
        **payload_coverage,
    }
    if metadata.get("editable_ownership_coverage") != expected_ownership_coverage:
        raise ValueError(
            "Manifest editable_ownership_coverage disagrees with validated V3 ownership."
        )

    if metadata.get("grouping_policy") == "flow_context_aware":
        for parent_group_id, index_records in flow_fragment_indexes.items():
            ordered = sorted(index_records)
            declared_counts = {declared_count for _, declared_count in ordered}
            if len(declared_counts) != 1:
                raise ValueError(
                    f"Flow Parent Group {parent_group_id!r} has inconsistent fragment counts."
                )
            fragment_count = declared_counts.pop()
            if [index for index, _ in ordered] != list(range(1, fragment_count + 1)):
                raise ValueError(
                    f"Flow Parent Group {parent_group_id!r} has non-contiguous fragment indexes."
                )

    if ids_aware:
        ids_expected_counts = {
            "ids_context_compact_units_with_records": ids_context_units_with_records,
            "ids_context_compact_units_without_records": ids_context_units_without_records,
            "ids_context_total_materialized_detector_record_count": ids_context_total_records,
        }
        for field, expected_value in ids_expected_counts.items():
            if int(metadata.get(field) or 0) != expected_value:
                raise ValueError(
                    f"IDS-context manifest summary {field!r} is inconsistent: "
                    f"expected {expected_value}, found {metadata.get(field)!r}."
                )

    over_budget_summary = metadata.get("over_budget_summary")
    if not isinstance(over_budget_summary, dict):
        raise ValueError("Manifest lacks over_budget_summary.")
    if int(over_budget_summary.get("over_budget_editable_count") or 0) != 0:
        raise ValueError("Manifest reports over-budget routable V3 units.")

    return {
        "source_packet_json": str(source_path),
        "unit_schema_counts": dict(sorted(unit_schema_counts.items())),
        "target_presence_counts": dict(sorted(target_presence_counts.items())),
        "header_field_counts": dict(sorted(header_field_counts.items())),
        "editable_header_region_count": editable_header_region_count,
        "editable_payload_region_count": editable_payload_region_count,
        "canonical_payload_entry_count": canonical_payload_entry_count,
        "canonical_payload_coverage": payload_coverage,
        "parent_group_index_count": len(parent_groups_by_id),
        "parent_group_index_packet_count": len(packet_owner),
        "flow_context_parent_count": len(flow_fragment_indexes),
        "flow_context_fragment_count": sum(
            len(records) for records in flow_fragment_indexes.values()
        ),
        "token_plan_policy_counts": dict(sorted(token_plan_policy_counts.items())),
        "token_plan_overflow_count": token_plan_overflow_count,
        **(
            {
                "ids_context_units_with_records": ids_context_units_with_records,
                "ids_context_units_without_records": ids_context_units_without_records,
                "ids_context_total_materialized_records": ids_context_total_records,
            }
            if ids_aware
            else {}
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate active Step 15 V3 compact modification-unit outputs."
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Step 15 grouping-policy output directory.",
    )
    parser.add_argument(
        "--expected-strategy",
        choices=sorted(SUPPORTED_MODIFICATION_STRATEGIES),
        help="Expected Step 15 modification strategy.",
    )
    parser.add_argument(
        "--expected-packet-count",
        type=int,
        help="Expected physical source packet count.",
    )
    parser.add_argument(
        "--expected-group-size",
        type=int,
        help="Expected fixed physical packet group size.",
    )
    parser.add_argument(
        "--expected-grouping-policy",
        choices=["fixed_packet_count", "flow_context_aware"],
    )
    parser.add_argument("--expected-parent-group-count", type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser()
    manifest_path = find_manifest(output_dir)
    manifest = read_json(manifest_path)
    metadata = manifest.get("metadata", {})
    if args.expected_grouping_policy and (
        metadata.get("grouping_policy") != args.expected_grouping_policy
    ):
        raise ValueError(
            f"Expected grouping_policy={args.expected_grouping_policy!r}, "
            f"found {metadata.get('grouping_policy')!r}."
        )
    if (
        args.expected_parent_group_count is not None
        and int(metadata.get("parent_group_count") or -1)
        != args.expected_parent_group_count
    ):
        raise ValueError(
            f"Expected parent_group_count={args.expected_parent_group_count}, "
            f"found {metadata.get('parent_group_count')!r}."
        )
    common_summary = check_common_manifest(
        manifest=manifest,
        manifest_path=manifest_path,
        expected_strategy=args.expected_strategy,
        expected_packet_count=args.expected_packet_count,
        expected_group_size=args.expected_group_size,
    )
    contract_summary = check_v3_units(manifest, manifest_path)
    metadata = manifest["metadata"]
    summary = {
        "status": "ok",
        "manifest": str(manifest_path),
        "manifest_schema": metadata.get("schema_version"),
        "unit_schema": metadata.get("compact_view_schema_version"),
        "strategy": metadata.get("strategy"),
        "capabilities": metadata.get("capabilities"),
        "grouping_policy": metadata.get("grouping_policy"),
        "grouping_unit": metadata.get("grouping_unit"),
        "group_size_packets": metadata.get("group_size_packets"),
        "total_packet_count": metadata.get("total_packet_count"),
        "parent_group_count": metadata.get("parent_group_count"),
        "modification_unit_count": metadata.get("modification_unit_count"),
        "parent_group_size_statistics": metadata.get("parent_group_size_statistics"),
        "token_budget_policy": metadata.get("token_budget_policy"),
        "over_budget_summary": metadata.get("over_budget_summary"),
        "editable_header_regions_enabled": metadata.get(
            "editable_header_regions_enabled"
        ),
        "editable_payload_regions_enabled": metadata.get(
            "editable_payload_regions_enabled"
        ),
        "expected_editable_header_fields": metadata.get(
            "expected_editable_header_fields"
        ),
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
