from __future__ import annotations

import argparse
import binascii
import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import editable_header_fields_from_policy, header_field_value, is_editable_header_field, load_header_editability_policy
from common.io_utils import write_json
from common.modification_strategy import ModificationCapabilities, resolve_modification_strategy
from common.payload_materialization import ETHERNET_MINIMUM_FRAME_BYTES as COMMON_ETHERNET_MINIMUM_FRAME_BYTES
from common.terminal_logging import default_step_log_path, terminal_log
from common.validation_policy import resolve_post_llm_traffic_validation_policy


REPORT_SCHEMA_VERSION = "pcap_reconstruction_report_v7"
EXPECTED_INPUT_SCHEMA_VERSION = "validated_modified_traffic_v6"
STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD = "validated_effective_payload_projection_changes"
STEP19_FULL_POST_RECONSTRUCTION_POLICY = "full_packet_universe_with_original_noop_for_invalid_and_failure_only_packets"
ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS = COMMON_ETHERNET_MINIMUM_FRAME_BYTES
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_MASK = TCP_SEQUENCE_MODULUS - 1
STEP19_V5_REQUIRED_METADATA_FIELDS = [
    "experiment_id",
    "source_merged_json",
    "validation_report",
    "accepted_packet_count",
    "reconstruction_packet_count",
    "rejected_packet_count",
    "accepted_group_count",
    "invalid_traffic_group_count",
    "llm_output_failure_group_count",
    "validated_effective_payload_projection_change_count",
    "post_reconstruction_policy",
    "post_llm_traffic_validation_policy",
]
STEP19_V5_COUNT_METADATA_FIELDS = [
    "accepted_packet_count",
    "reconstruction_packet_count",
    "rejected_packet_count",
    "accepted_group_count",
    "invalid_traffic_group_count",
    "llm_output_failure_group_count",
    "validated_effective_payload_projection_change_count",
]


#This exception carries a machine-readable reconstruction failure reason.
class TcpReconstructionError(ValueError):
    #This initializer stores the reconstruction failure context for later reports.
    def __init__(self, reason: str, message: str, **context: Any):
        super().__init__(message)
        self.detail = {
            "reason": reason,
            "message": message,
            **context,
        }


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


#This function returns the default Step 20 input and output paths for the active experiment.
#This function uses experiment_root_override when provided instead of the experiment root stored in the config.
#This is useful when the VM artifacts are under a different folder than the one currently written in the config file.
def default_paths(config: dict[str, Any], experiment_root_override: str | Path | None = None) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    return {
        "input_json": experiment_root / "09_validation" / "validated_modified_traffic.json",
        "reference_pcap": experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
        "output_dir": experiment_root / "10_reconstructed_pcap",
    }


#This function validates the minimum config keys needed by Step 20.
#This function checks the experiment identity and output root.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    resolve_modification_strategy(config)
    resolve_post_llm_traffic_validation_policy(config)


#This function resolves a path stored in Step 19 metadata and handles relocated experiment roots.
#This function prefers absolute metadata paths and uses the active input location as a fallback when artifacts were moved together.
def resolve_step19_metadata_path(metadata: dict[str, Any], field: str, input_json_path: Path) -> Path:
    value = metadata.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Step 19 V5 metadata field {field!r} must be a non-empty path string: {input_json_path}")
    recorded_path = Path(value).expanduser()
    if not recorded_path.is_absolute():
        recorded_path = input_json_path.parent / recorded_path
    if recorded_path.exists():
        return recorded_path

    if field == "validation_report":
        relocated_path = input_json_path.parent / "validation_report.json"
    elif field == "source_merged_json":
        label = input_json_path.parent.name
        experiment_root = input_json_path.parent.parent.parent
        relocated_path = experiment_root / "08_merged_outputs" / label / "merged_modified_traffic.json"
    else:
        relocated_path = recorded_path
    if relocated_path.exists():
        return relocated_path
    return recorded_path


#This function enforces the Step 19 V5 artifact contract consumed by Step 20.
#This function must not silently accept legacy validated traffic schemas.
def validate_step19_v5_input(
    validated_json: Any,
    input_json_path: Path,
    capabilities: ModificationCapabilities,
    validation_policy: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(validated_json, dict):
        raise ValueError(f"Validated traffic JSON root must be an object: {input_json_path}")
    metadata = validated_json.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Validated traffic JSON must contain metadata object: {input_json_path}")
    schema_version = metadata.get("schema_version")
    if schema_version != EXPECTED_INPUT_SCHEMA_VERSION:
        raise ValueError(
            "Step 20 V6 requires Step 19 validated traffic schema "
            f"{EXPECTED_INPUT_SCHEMA_VERSION!r}; found {schema_version!r}: {input_json_path}"
        )
    traffic = validated_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError(f"Validated traffic JSON must contain a top-level traffic list: {input_json_path}")

    missing_fields = [
        field
        for field in STEP19_V5_REQUIRED_METADATA_FIELDS
        if field not in metadata
    ]
    if missing_fields:
        raise ValueError(
            "Step 19 V5 validated traffic metadata is missing required fields "
            f"{missing_fields}: {input_json_path}"
        )
    for field in STEP19_V5_COUNT_METADATA_FIELDS:
        value = metadata.get(field)
        if not is_int_like(value) or int(value) < 0:
            raise ValueError(
                f"Step 19 V5 metadata field {field!r} must be a non-negative integer; "
                f"found {value!r}: {input_json_path}"
            )
    reconstruction_packet_count = int(metadata["reconstruction_packet_count"])
    if reconstruction_packet_count != len(traffic):
        raise ValueError(
            "Step 19 V5 reconstruction_packet_count must equal the emitted traffic list length; "
            f"metadata={reconstruction_packet_count}, traffic={len(traffic)}: {input_json_path}"
        )
    if metadata.get("post_reconstruction_policy") != STEP19_FULL_POST_RECONSTRUCTION_POLICY:
        raise ValueError(
            "Step 20 V6 requires Step 19 full POST reconstruction policy "
            f"{STEP19_FULL_POST_RECONSTRUCTION_POLICY!r}; "
            f"found {metadata.get('post_reconstruction_policy')!r}: {input_json_path}"
        )
    policy_metadata = metadata.get("post_llm_traffic_validation_policy")
    if not isinstance(policy_metadata, dict):
        raise ValueError(
            f"Step 19 V5 metadata.post_llm_traffic_validation_policy must be an object: {input_json_path}"
        )
    if policy_metadata.get("policy_id") != validation_policy.policy_id:
        raise ValueError(
            "Step 19 V5 validation policy metadata does not match the active Step 20 config; "
            f"metadata={policy_metadata.get('policy_id')!r}, config={validation_policy.policy_id!r}: {input_json_path}"
        )
    if not isinstance(metadata.get("validation_report"), str) or not metadata["validation_report"].strip():
        raise ValueError(f"Step 20 V6 reconstruction requires metadata.validation_report: {input_json_path}")
    projections = validated_json.get(STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD)
    projection_contract = validate_step19_effective_payload_projection_contract(
        projections=projections,
        projection_collection_present=STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD in validated_json,
        metadata=metadata,
        traffic=traffic,
        capabilities=capabilities,
        input_json_path=input_json_path,
    )
    return metadata, traffic, projection_contract


#This helper identifies Step 19 records that are preserved because no accepted edit survived validation for that packet.
def record_is_preserved_invalid_or_failure_only(record: dict[str, Any]) -> bool:
    if bool(record.get("invalid_traffic")) or bool(record.get("llm_output_failure")):
        return True
    evaluation_status = record.get("evaluation_status")
    return evaluation_status in {"Invalid Traffic", "LLM Output Failure"}


#This helper checks the V5 effective payload projection records that Step 19 already validated.
#This helper summarizes projection evidence before the independent packet-level replay performed during the PCAP audit.
def summarize_payload_projection_evidence(
    projections: list[Any],
    input_json_path: Path,
) -> dict[str, Any]:
    required_projection_fields = [
        "packet_id",
        "physical_representation_id",
        "canonical_region_id",
        "payload_start_offset_bytes",
        "replaced_length_bytes",
        "replacement_length_bytes",
        "payload_length_delta_bytes",
        "canonical_edit_start_offset_bytes",
        "canonical_edit_end_offset_bytes",
        "canonical_replaced_length_bytes",
        "canonical_replacement_length_bytes",
        "canonical_payload_length_delta_bytes",
        "alias_canonical_start_offset_bytes",
        "alias_canonical_end_offset_bytes",
        "projection_reaches_canonical_edit_end",
        "canonical_edit_end_packet_payload_offset_bytes",
        "original_segment_hex",
        "replacement_hex",
        "requires_pipeline_recalculation",
    ]
    projected_packet_ids = set()
    seen_identity_keys: dict[tuple[Any, ...], dict[str, Any]] = {}
    recalculation_fields: Counter[str] = Counter()
    net_delta = 0
    growth = 0
    shrinkage = 0
    length_delta_projection_count = 0
    canonical_edits: dict[tuple[str, int, str, str], dict[str, Any]] = {}
    for index, projection in enumerate(projections, start=1):
        if not isinstance(projection, dict):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} is not an object: {input_json_path}"
            )
        missing_fields = [field for field in required_projection_fields if field not in projection]
        if missing_fields:
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} is missing fields "
                f"{missing_fields}: {input_json_path}"
            )
        replaced_length = projection.get("replaced_length_bytes")
        replacement_length = projection.get("replacement_length_bytes")
        payload_delta = projection.get("payload_length_delta_bytes")
        if not is_int_like(replaced_length) or not is_int_like(replacement_length) or not is_int_like(payload_delta):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has non-integer length metadata: {input_json_path}"
            )
        replaced_length = int(replaced_length)
        replacement_length = int(replacement_length)
        payload_delta = int(payload_delta)
        if payload_delta != replacement_length - replaced_length:
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has inconsistent length delta metadata: {input_json_path}"
            )
        canonical_start = projection.get("canonical_edit_start_offset_bytes")
        canonical_end = projection.get("canonical_edit_end_offset_bytes")
        canonical_replaced_length = projection.get("canonical_replaced_length_bytes")
        canonical_replacement_length = projection.get("canonical_replacement_length_bytes")
        canonical_delta = projection.get("canonical_payload_length_delta_bytes")
        if not all(
            is_int_like(value)
            for value in [
                canonical_start,
                canonical_end,
                canonical_replaced_length,
                canonical_replacement_length,
                canonical_delta,
            ]
        ):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has invalid canonical edit lengths: {input_json_path}"
            )
        if (
            int(canonical_end) - int(canonical_start) != int(canonical_replaced_length)
            or int(canonical_replacement_length) - int(canonical_replaced_length) != int(canonical_delta)
        ):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has inconsistent canonical edit bounds: {input_json_path}"
            )
        original_segment_hex = projection.get("original_segment_hex")
        replacement_hex = projection.get("replacement_hex")
        if not isinstance(original_segment_hex, str) or not isinstance(replacement_hex, str):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has non-string payload hex evidence: {input_json_path}"
            )
        try:
            original_segment = binascii.unhexlify(original_segment_hex)
            replacement_segment = binascii.unhexlify(replacement_hex)
        except (binascii.Error, ValueError) as error:
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} contains invalid hex evidence: {error}"
            ) from error
        if len(original_segment) != replaced_length or len(replacement_segment) != replacement_length:
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has hex evidence lengths inconsistent with metadata: {input_json_path}"
            )
        recalculation = projection.get("requires_pipeline_recalculation")
        if not isinstance(recalculation, list):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has invalid requires_pipeline_recalculation: {input_json_path}"
            )
        for field in recalculation:
            recalculation_fields[str(field)] += 1
        identity_key = (
            str(projection.get("packet_id")),
            str(projection.get("physical_representation_id")),
            str(projection.get("canonical_region_id")),
            str(projection.get("prompt_unit_id")),
            str(projection.get("patch_index")),
            int(projection.get("payload_start_offset_bytes")),
        )
        previous = seen_identity_keys.get(identity_key)
        if previous is not None:
            raise ValueError(
                "Step 19 V5 effective payload projection records contain a duplicate deterministic identity key: "
                f"{identity_key}: {input_json_path}"
            )
        seen_identity_keys[identity_key] = projection
        canonical_identity = (
            str(projection.get("prompt_unit_id")),
            int(projection.get("patch_index")),
            str(projection.get("canonical_region_id")),
            str(projection.get("region_id")),
        )
        canonical_evidence = {
            "prompt_unit_id": canonical_identity[0],
            "patch_index": canonical_identity[1],
            "canonical_region_id": canonical_identity[2],
            "region_id": canonical_identity[3],
            "canonical_edit_start_offset_bytes": int(canonical_start),
            "canonical_edit_end_offset_bytes": int(canonical_end),
            "canonical_replaced_length_bytes": int(canonical_replaced_length),
            "canonical_replacement_length_bytes": int(canonical_replacement_length),
            "canonical_payload_length_delta_bytes": int(canonical_delta),
            "end_boundary_anchors": [],
        }
        previous_canonical_evidence = canonical_edits.get(canonical_identity)
        if previous_canonical_evidence is not None:
            comparable_fields = {
                key: value
                for key, value in canonical_evidence.items()
                if key != "end_boundary_anchors"
            }
            previous_comparable_fields = {
                key: value
                for key, value in previous_canonical_evidence.items()
                if key != "end_boundary_anchors"
            }
            if comparable_fields != previous_comparable_fields:
                raise ValueError(
                    "Step 19 V5 payload projections disagree about one canonical edit: "
                    f"{canonical_identity}: {input_json_path}"
                )
        else:
            canonical_edits[canonical_identity] = canonical_evidence
            previous_canonical_evidence = canonical_evidence
        reaches_end = projection.get("projection_reaches_canonical_edit_end")
        if not isinstance(reaches_end, bool):
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} has invalid end-boundary evidence: {input_json_path}"
            )
        end_packet_offset = projection.get("canonical_edit_end_packet_payload_offset_bytes")
        if reaches_end:
            if not is_int_like(end_packet_offset):
                raise ValueError(
                    f"Step 19 V5 effective payload projection record {index} reaches the canonical edit end without a packet offset: {input_json_path}"
                )
            previous_canonical_evidence["end_boundary_anchors"].append(
                {
                    "packet_id": str(projection.get("packet_id")),
                    "physical_representation_id": str(projection.get("physical_representation_id")),
                    "canonical_edit_end_packet_payload_offset_bytes": int(end_packet_offset),
                }
            )
        elif end_packet_offset is not None:
            raise ValueError(
                f"Step 19 V5 effective payload projection record {index} declares an end offset without covering the edit end: {input_json_path}"
            )
        projected_packet_ids.add(str(projection.get("packet_id")))
        net_delta += payload_delta
        if payload_delta > 0:
            growth += payload_delta
        elif payload_delta < 0:
            shrinkage += abs(payload_delta)
        length_delta_projection_count += int(payload_delta != 0)
    canonical_resize_events = []
    for canonical_evidence in canonical_edits.values():
        anchors = sorted(
            canonical_evidence["end_boundary_anchors"],
            key=lambda item: (
                item["packet_id"],
                item["physical_representation_id"],
                item["canonical_edit_end_packet_payload_offset_bytes"],
            ),
        )
        canonical_evidence["end_boundary_anchors"] = anchors
        if canonical_evidence["canonical_payload_length_delta_bytes"] != 0:
            if not anchors:
                raise ValueError(
                    "Step 19 V5 length-changing canonical payload edit has no physical representation "
                    f"covering its end boundary: {canonical_evidence}"
                )
            canonical_resize_events.append(canonical_evidence)
    canonical_resize_events.sort(
        key=lambda item: (
            item["canonical_region_id"],
            item["canonical_edit_start_offset_bytes"],
            item["prompt_unit_id"],
            item["patch_index"],
        )
    )
    return {
        "projection_change_count": len(projections),
        "projected_packet_count": len(projected_packet_ids),
        "length_delta_projection_count": length_delta_projection_count,
        "payload_growth_bytes": growth,
        "payload_shrinkage_bytes": shrinkage,
        "net_payload_delta_bytes": net_delta,
        "canonical_effective_edit_count": len(canonical_edits),
        "canonical_resize_event_count": len(canonical_resize_events),
        "canonical_stream_net_payload_delta_bytes": sum(
            event["canonical_payload_length_delta_bytes"]
            for event in canonical_resize_events
        ),
        "canonical_resize_events": canonical_resize_events,
        "requires_pipeline_recalculation_counts": dict(sorted(recalculation_fields.items())),
    }


#This function validates the Step 19 effective payload projection collection used by Step 20.
def validate_step19_effective_payload_projection_contract(
    *,
    projections: Any,
    projection_collection_present: bool,
    metadata: dict[str, Any],
    traffic: list[dict[str, Any]],
    capabilities: ModificationCapabilities,
    input_json_path: Path,
) -> dict[str, Any]:
    validation_report_path = resolve_step19_metadata_path(metadata, "validation_report", input_json_path)
    summary = {
        "schema_version": "step19_v5_effective_payload_projection_contract_v1",
        "validated_traffic_schema_version": metadata.get("schema_version"),
        "full_post_reconstruction_policy": metadata.get("post_reconstruction_policy"),
        "validation_report": str(validation_report_path),
        "payload_projection_evidence_required": capabilities.allows_payload_edits,
    }
    if not projection_collection_present:
        if capabilities.allows_payload_edits:
            raise ValueError(
                f"Step 20 V6 payload-capable reconstruction requires {STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD}: {input_json_path}"
            )
        projections = []
    elif not isinstance(projections, list):
        raise ValueError(
            f"Step 19 V5 {STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD} must be a list: {input_json_path}"
        )
    if not capabilities.allows_payload_edits and projections:
        raise ValueError(
            "Step 19 V5 header-only reconstruction must not contain effective payload projection changes: "
            f"{input_json_path}"
        )
    if not capabilities.allows_payload_edits:
        summary["payload_projection_evidence_status"] = "not_required_by_modification_strategy"
        summary.update(summarize_payload_projection_evidence([], input_json_path))
        return summary

    traffic_by_packet_id: dict[str, dict[str, Any]] = {}
    duplicate_packet_ids = set()
    for record in traffic:
        if not isinstance(record, dict):
            continue
        packet_id = record.get("packet_id")
        if packet_id is None:
            continue
        packet_id = str(packet_id)
        if packet_id in traffic_by_packet_id:
            duplicate_packet_ids.add(packet_id)
        traffic_by_packet_id[packet_id] = record
    if duplicate_packet_ids:
        raise ValueError(
            f"Step 19 V5 traffic contains duplicate packet_id values before Step 20 reconstruction: {sorted(duplicate_packet_ids)}"
        )
    projected_packet_ids = {str(projection.get("packet_id")) for projection in projections if isinstance(projection, dict)}
    unknown_packet_ids = sorted(projected_packet_ids - set(traffic_by_packet_id))
    if unknown_packet_ids:
        raise ValueError(
            "Step 19 V5 effective payload projections reference packet_id values outside the validated traffic universe: "
            f"{unknown_packet_ids}: {input_json_path}"
        )
    preserved_projected_packet_ids = sorted(
        packet_id
        for packet_id in projected_packet_ids
        if record_is_preserved_invalid_or_failure_only(traffic_by_packet_id[packet_id])
    )
    if preserved_projected_packet_ids:
        raise ValueError(
            "Step 19 V5 effective payload projections must not target Invalid Traffic or LLM Output Failure-only packets: "
            f"{preserved_projected_packet_ids}: {input_json_path}"
        )
    expected_count = metadata.get("validated_effective_payload_projection_change_count")
    if not is_int_like(expected_count) or int(expected_count) != len(projections):
        raise ValueError(
            "Step 19 V5 metadata.validated_effective_payload_projection_change_count must match "
            f"{STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD}; metadata={expected_count!r}, actual={len(projections)}: {input_json_path}"
        )
    projection_summary = summarize_payload_projection_evidence(projections, input_json_path)
    for optional_delta_field in [
        "validated_effective_payload_projection_net_payload_delta_bytes",
        "effective_payload_projection_net_payload_delta_bytes",
        "payload_projection_net_payload_delta_bytes",
    ]:
        if optional_delta_field in metadata:
            value = metadata[optional_delta_field]
            if not is_int_like(value) or int(value) != projection_summary["net_payload_delta_bytes"]:
                raise ValueError(
                    f"Step 19 V5 metadata.{optional_delta_field} must match the effective payload projection net delta; "
                    f"metadata={value!r}, computed={projection_summary['net_payload_delta_bytes']}: {input_json_path}"
                )

    return {
        **summary,
        "payload_projection_evidence_status": "loaded_from_step19_validated_effective_payload_projection_changes_v1",
        "payload_projection_source": f"Step 19 {STEP19_EFFECTIVE_PAYLOAD_PROJECTIONS_FIELD}",
        "projected_packet_ids": sorted(projected_packet_ids),
        "_projections_by_packet_id": {
            packet_id: sorted(
                [
                    projection
                    for projection in projections
                    if isinstance(projection, dict) and str(projection.get("packet_id")) == packet_id
                ],
                key=lambda projection: (
                    int(projection["payload_start_offset_bytes"]),
                    int(projection["replaced_length_bytes"]),
                    str(projection["prompt_unit_id"]),
                    int(projection["patch_index"]),
                ),
                reverse=True,
            )
            for packet_id in sorted(projected_packet_ids)
        },
        **projection_summary,
    }


#This helper independently applies Step 19 physical payload projections to one immutable Step 13 payload.
def materialize_projected_packet_payload(
    reference_payload: bytes,
    projections: list[dict[str, Any]],
) -> bytes:
    materialized = reference_payload
    for projection in projections:
        start = int(projection["payload_start_offset_bytes"])
        replaced_length = int(projection["replaced_length_bytes"])
        end = start + replaced_length
        original_segment = binascii.unhexlify(projection["original_segment_hex"])
        replacement_segment = binascii.unhexlify(projection["replacement_hex"])
        if start < 0 or end > len(reference_payload):
            raise ValueError(
                f"Payload projection range [{start}, {end}) exceeds the immutable Step 13 payload length {len(reference_payload)}."
            )
        if reference_payload[start:end] != original_segment:
            raise ValueError(
                f"Payload projection original_segment_hex does not match immutable Step 13 bytes at [{start}, {end})."
            )
        materialized = materialized[:start] + replacement_segment + materialized[end:]
    return materialized


#This function imports Scapy only when PCAP reconstruction actually runs.
#This keeps --help and syntax checks usable in environments where Scapy is not installed, such as the local Windows Codex runtime.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import Ether, ICMP, IP, IPv6, PcapReader, PcapWriter, Raw, TCP, UDP, raw
        from scapy.layers.inet import TCPOptions
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_20_json_to_pcap. Install it in the Ubuntu "
            "benchmark environment before reconstructing PCAP files."
        ) from exc
    return {
        "Ether": Ether,
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapReader": PcapReader,
        "PcapWriter": PcapWriter,
        "Raw": Raw,
        "TCP": TCP,
        "TCP_OPTION_NAMES": frozenset(TCPOptions[1]),
        "UDP": UDP,
        "raw": raw,
    }


#This helper builds a structured issue entry for the reconstruction report.
#This helper builds entries that avoid silent repair when a packet is rebuilt with warnings or cannot be rebuilt.
def issue(severity: str, reason: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "reason": reason,
        "message": message,
        **extra,
    }


#This helper checks if a value is a real integer and not a boolean.
#This helper is used before assigning JSON values to Scapy header fields.
def is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


#This function appends Ethernet minimum-frame padding after Scapy has serialized the packet.
#This keeps the padding outside the IP/TCP lengths while preserving PCAP frame-size rules.
def apply_ethernet_minimum_padding(packet: Any, scapy: dict[str, Any]) -> tuple[Any, bytes, int]:
    serialized = scapy["raw"](packet)
    padding_length = max(0, ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS - len(serialized))
    if padding_length == 0:
        return packet, serialized, 0

    timestamp = getattr(packet, "time", None)
    padded_packet = scapy["Ether"](serialized + (b"\x00" * padding_length))
    if timestamp is not None:
        padded_packet.time = timestamp
    return padded_packet, scapy["raw"](padded_packet), padding_length


#This function normalizes an address and port into the endpoint tuple used by TCP connection tracking.
def tcp_endpoint(address: str, port: int) -> tuple[str, int]:
    return address, port


#This function creates an order-independent key for a bidirectional TCP connection.
def canonical_tcp_connection_key(
    source: tuple[str, int],
    destination: tuple[str, int],
) -> tuple[tuple[str, int], tuple[str, int]]:
    return tuple(sorted((source, destination)))


#This function converts a wrapped TCP sequence number into a relative number from an anchor.
def tcp_relative_number(value: int, anchor: int) -> int:
    return (value - anchor) & TCP_SEQUENCE_MASK


#This function creates the mutable state record used while assigning packets to TCP connections.
def new_tcp_connection(
    *,
    connection_key: tuple[tuple[str, int], tuple[str, int]],
    connection_index: int,
    source: tuple[str, int],
    sequence_number: int,
    explicit_syn: bool,
) -> dict[str, Any]:
    return {
        "connection_id": (connection_key, connection_index),
        "connection_key": connection_key,
        "connection_index": connection_index,
        "initiator": source if explicit_syn else None,
        "initiator_syn_sequence": sequence_number if explicit_syn else None,
        "anchors": {source: sequence_number},
        "fin_endpoints": set(),
        "closed": False,
    }


#This function assigns one reference packet descriptor to the active TCP connection state.
def assign_tcp_connection(
    descriptor: dict[str, Any],
    current_connections: dict[tuple[tuple[str, int], tuple[str, int]], dict[str, Any]],
    connection_counts: Counter,
) -> dict[str, Any]:
    source = descriptor["source_endpoint"]
    connection_key = descriptor["connection_key"]
    flags = descriptor["flags"]
    sequence_number = descriptor["sequence_number"]
    starts_connection = bool(flags & 0x02) and not bool(flags & 0x10)
    current = current_connections.get(connection_key)

    if starts_connection:
        same_syn = (
            current is not None
            and not current["closed"]
            and current["initiator"] == source
            and current["initiator_syn_sequence"] == sequence_number
        )
        if not same_syn:
            connection_counts[connection_key] += 1
            current = new_tcp_connection(
                connection_key=connection_key,
                connection_index=connection_counts[connection_key],
                source=source,
                sequence_number=sequence_number,
                explicit_syn=True,
            )
            current_connections[connection_key] = current
    elif current is None:
        connection_counts[connection_key] += 1
        current = new_tcp_connection(
            connection_key=connection_key,
            connection_index=connection_counts[connection_key],
            source=source,
            sequence_number=sequence_number,
            explicit_syn=False,
        )
        current_connections[connection_key] = current

    current["anchors"].setdefault(source, sequence_number)
    if flags & 0x04:
        current["closed"] = True
    if flags & 0x01:
        current["fin_endpoints"].add(source)
        if len(current["fin_endpoints"]) == 2:
            current["closed"] = True

    descriptor["connection_id"] = current["connection_id"]
    return current


#This function extracts the TCP/IP fields needed to track reference-packet stream state.
def reference_tcp_descriptor(
    packet: Any,
    reduced_packet_index: int,
    scapy: dict[str, Any],
) -> dict[str, Any] | None:
    TCP = scapy["TCP"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    if TCP not in packet or (IP not in packet and IPv6 not in packet):
        return None

    ip_layer = packet[IP] if IP in packet else packet[IPv6]
    tcp_layer = packet[TCP]
    source = tcp_endpoint(str(ip_layer.src), int(tcp_layer.sport))
    destination = tcp_endpoint(str(ip_layer.dst), int(tcp_layer.dport))

    if IP in packet:
        ip_header_length = int(ip_layer.ihl or 5) * 4
        tcp_header_length = int(tcp_layer.dataofs or 5) * 4
        payload_length = max(0, int(ip_layer.len) - ip_header_length - tcp_header_length)
    else:
        tcp_header_length = int(tcp_layer.dataofs or 5) * 4
        payload_length = max(0, int(ip_layer.plen) - tcp_header_length)
    payload = bytes(tcp_layer.payload)[:payload_length]

    return {
        "reduced_packet_index": reduced_packet_index,
        "source_endpoint": source,
        "destination_endpoint": destination,
        "connection_key": canonical_tcp_connection_key(source, destination),
        "sequence_number": int(tcp_layer.seq),
        "acknowledgement_number": int(tcp_layer.ack),
        "flags": int(tcp_layer.flags),
        "tcp_options": list(tcp_layer.options or []),
        "payload": payload,
        "payload_length_bytes": len(payload),
    }


#This function loads the reference PCAP packets required by the validated Step 19 traffic.
def load_reference_pcap_context(
    *,
    reference_pcap_path: Path,
    required_indices: set[int],
    scapy: dict[str, Any],
) -> dict[str, Any]:
    if not reference_pcap_path.exists():
        raise FileNotFoundError(f"Step 13 selected reference PCAP does not exist: {reference_pcap_path}")

    current_connections = {}
    connection_counts: Counter = Counter()
    connections = {}
    packets_by_index = {}
    descriptors_by_index = {}
    packet_count = 0

    with scapy["PcapReader"](str(reference_pcap_path)) as reader:
        for reduced_packet_index, packet in enumerate(reader, start=1):
            packet_count = reduced_packet_index
            descriptor = reference_tcp_descriptor(packet, reduced_packet_index, scapy)
            if descriptor is not None:
                connection = assign_tcp_connection(
                    descriptor,
                    current_connections,
                    connection_counts,
                )
                connections[connection["connection_id"]] = connection
            if reduced_packet_index in required_indices:
                packets_by_index[reduced_packet_index] = packet.copy()
                descriptors_by_index[reduced_packet_index] = descriptor

    missing_indices = sorted(required_indices - packets_by_index.keys())
    if missing_indices:
        raise ValueError(
            "Step 19 records reference packet indexes that are absent from the Step 13 PCAP: "
            f"{missing_indices[:20]}"
        )

    return {
        "packet_count": packet_count,
        "packets_by_index": packets_by_index,
        "descriptors_by_index": descriptors_by_index,
        "connections": connections,
        "connection_count": sum(connection_counts.values()),
    }


#This function verifies that a Step 19 record still matches the immutable reference packet identity.
def validate_record_against_reference(
    record: dict[str, Any],
    descriptor: dict[str, Any] | None,
) -> None:
    if descriptor is None:
        if str(record.get("transport_protocol") or "").upper() == "TCP":
            raise ValueError(
                f"TCP record {record.get('packet_id')} does not map to a TCP frame in the Step 13 PCAP."
            )
        return

    expected = {
        "src_ip": descriptor["source_endpoint"][0],
        "src_port": descriptor["source_endpoint"][1],
        "dst_ip": descriptor["destination_endpoint"][0],
        "dst_port": descriptor["destination_endpoint"][1],
    }
    mismatches = {
        field: {"record": record.get(field), "reference": value}
        for field, value in expected.items()
        if record.get(field) != value
    }
    if mismatches:
        raise ValueError(
            f"Step 19 record {record.get('packet_id')} does not match its Step 13 frame: {mismatches}"
        )


#This function decodes payload_hex and fails closed when the JSON payload is malformed.
def decode_payload_hex_strict(record: dict[str, Any]) -> bytes:
    payload_hex = record.get("payload_hex", "")
    if not isinstance(payload_hex, str):
        raise ValueError(f"Record {record.get('packet_id')} has non-string payload_hex.")
    try:
        return binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"Record {record.get('packet_id')} has invalid payload_hex: {error}") from error


#This helper maps one original stream boundary through deterministic prefix-stable canonical resize events.
def translate_relative_stream_boundary(
    boundary: int,
    resize_events: list[dict[str, Any]],
) -> int:
    cumulative_delta = 0
    for event in resize_events:
        event_start = int(event["start"])
        event_end = int(event["end"])
        replacement_length = int(event["replacement_length_bytes"])
        if boundary <= event_start:
            return boundary + cumulative_delta
        if boundary < event_end:
            return (
                event_start
                + cumulative_delta
                + min(boundary - event_start, replacement_length)
            )
        cumulative_delta += int(event["delta"])
    return boundary + cumulative_delta


#This function verifies that overlapping physical packets represent one coherent transformed TCP stream.
def validate_overlapping_tcp_segments(
    segments: list[dict[str, Any]],
    resize_events: list[dict[str, Any]],
) -> dict[str, int]:
    projected_segments = []
    for segment in segments:
        projected_start = translate_relative_stream_boundary(segment["start"], resize_events)
        projected_end = translate_relative_stream_boundary(segment["end"], resize_events)
        if projected_end - projected_start != len(segment["new_payload"]):
            raise TcpReconstructionError(
                "canonical_projection_length_mismatch",
                "A projected TCP payload length does not match the canonical boundary transformation.",
                packet_id=segment["packet_id"],
                original_sequence_range=[segment["start"], segment["end"]],
                projected_sequence_range=[projected_start, projected_end],
                projected_payload_length_bytes=len(segment["new_payload"]),
            )
        projected_segments.append(
            {
                **segment,
                "projected_start": projected_start,
                "projected_end": projected_end,
            }
        )
    ordered = sorted(
        projected_segments,
        key=lambda item: (
            item["projected_start"],
            item["projected_end"],
            item["packet_id"],
        ),
    )
    active = []
    retransmission_count = 0
    modified_retransmission_count = 0
    overlapping_segment_pair_count = 0
    modified_overlapping_segment_pair_count = 0
    for segment in ordered:
        active = [
            candidate
            for candidate in active
            if candidate["projected_end"] > segment["projected_start"]
        ]
        for candidate in active:
            if (
                candidate["projected_start"] == segment["projected_start"]
                and candidate["projected_end"] == segment["projected_end"]
            ):
                retransmission_count += 1
                modified_retransmission_count += int(candidate["changed"] or segment["changed"])
                if candidate["new_payload"] != segment["new_payload"] and (
                    candidate["changed"] or segment["changed"]
                ):
                    raise TcpReconstructionError(
                        "inconsistent_modified_retransmission",
                        "Modified TCP retransmissions disagree for the same original sequence range.",
                        previous_packet_id=candidate["packet_id"],
                        packet_id=segment["packet_id"],
                        projected_sequence_start=segment["projected_start"],
                        projected_sequence_end=segment["projected_end"],
                    )
                continue
            overlapping_segment_pair_count += 1
            modified_overlapping_segment_pair_count += int(candidate["changed"] or segment["changed"])
            if not (candidate["changed"] or segment["changed"]):
                continue
            overlap_start = max(
                candidate["projected_start"],
                segment["projected_start"],
            )
            overlap_end = min(
                candidate["projected_end"],
                segment["projected_end"],
            )
            candidate_slice = candidate["new_payload"][
                overlap_start - candidate["projected_start"] : overlap_end - candidate["projected_start"]
            ]
            segment_slice = segment["new_payload"][
                overlap_start - segment["projected_start"] : overlap_end - segment["projected_start"]
            ]
            if candidate_slice != segment_slice:
                raise TcpReconstructionError(
                    "inconsistent_modified_tcp_overlap",
                    "Modified overlapping TCP segments contain different bytes.",
                    previous_packet_id=candidate["packet_id"],
                    packet_id=segment["packet_id"],
                    overlap_sequence_range=[overlap_start, overlap_end],
                )
        active.append(segment)
    return {
        "preserved_retransmission_count": retransmission_count,
        "preserved_modified_retransmission_count": modified_retransmission_count,
        "preserved_overlapping_segment_pair_count": overlapping_segment_pair_count,
        "preserved_modified_overlapping_segment_pair_count": modified_overlapping_segment_pair_count,
    }


#This function builds the TCP sequence/ack translation plan for one stream direction.
def build_tcp_translation(
    *,
    anchor: int,
    segments: list[dict[str, Any]],
    resize_events: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered_resize_events = sorted(
        resize_events,
        key=lambda item: (
            int(item["start"]),
            int(item["end"]),
            str(item["canonical_region_id"]),
            str(item["prompt_unit_id"]),
            int(item["patch_index"]),
        ),
    )
    previous_end = None
    for event in ordered_resize_events:
        if int(event["start"]) >= int(event["end"]):
            raise TcpReconstructionError(
                "invalid_canonical_resize_event",
                "A canonical resize event must replace a non-empty original interval.",
                canonical_resize_event=event,
            )
        if previous_end is not None and int(event["start"]) < previous_end:
            raise TcpReconstructionError(
                "overlapping_canonical_resize_events",
                "Canonical resize events overlap in original TCP sequence space.",
                canonical_resize_event=event,
            )
        previous_end = int(event["end"])
    overlap_metrics = validate_overlapping_tcp_segments(
        segments,
        ordered_resize_events,
    )
    positions = [int(event["end"]) for event in ordered_resize_events]
    cumulative_deltas = []
    cumulative = 0
    for event in ordered_resize_events:
        cumulative += int(event["delta"])
        cumulative_deltas.append(cumulative)
    return {
        "anchor": anchor,
        "positions": positions,
        "cumulative_deltas": cumulative_deltas,
        "resize_events": ordered_resize_events,
        "resized_intervals": [
            (int(event["start"]), int(event["end"]), str(event["canonical_region_id"]))
            for event in ordered_resize_events
        ],
        "total_delta_bytes": cumulative,
        "segment_count": len(segments),
        "unique_sequence_range_count": len(
            {(segment["start"], segment["end"]) for segment in segments}
        ),
        "payload_growth_bytes": sum(max(0, int(event["delta"])) for event in ordered_resize_events),
        "payload_shrinkage_bytes": sum(max(0, -int(event["delta"])) for event in ordered_resize_events),
        "adjusted_sequence_packet_count": 0,
        "adjusted_acknowledgement_packet_count": 0,
        "unresolved_sequence_reference_count": 0,
        "unresolved_ack_reference_count": 0,
        **overlap_metrics,
    }


#This function translates one TCP sequence-space value through a prepared resize plan.
def translate_tcp_number(value: int, translation: dict[str, Any] | None) -> tuple[int, int, bool]:
    if not translation or not translation["resize_events"]:
        return value, 0, False
    relative = tcp_relative_number(value, translation["anchor"])
    translated_relative = translate_relative_stream_boundary(
        relative,
        translation["resize_events"],
    )
    delta = translated_relative - relative
    return (value + delta) & TCP_SEQUENCE_MASK, delta, False


#This function renders an endpoint tuple as JSON-friendly report data.
def endpoint_report_value(endpoint: tuple[str, int]) -> dict[str, Any]:
    return {"ip": endpoint[0], "port": endpoint[1]}


#This function prepares deterministic TCP sequence, acknowledgement and SACK translation for all packets.
def prepare_tcp_sequence_translation(
    *,
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
    payload_projection_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    prepared_by_index = {}
    segments_by_direction: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)
    payload_content_changed_packet_count = 0
    payload_length_changed_packet_count = 0
    packet_stream_context: dict[str, dict[str, Any]] = {}

    for record in traffic:
        reduced_packet_index = record.get("reduced_packet_index")
        if not is_int_like(reduced_packet_index):
            raise ValueError(f"Record {record.get('packet_id')} has invalid reduced_packet_index.")
        if reduced_packet_index in prepared_by_index:
            raise ValueError(f"Duplicate reduced_packet_index in Step 19 traffic: {reduced_packet_index}")
        descriptor = reference_context["descriptors_by_index"][reduced_packet_index]
        validate_record_against_reference(record, descriptor)
        final_payload = decode_payload_hex_strict(record)
        if descriptor is not None:
            payload_content_changed_packet_count += int(descriptor["payload"] != final_payload)
            payload_length_changed_packet_count += int(len(descriptor["payload"]) != len(final_payload))
        prepared_by_index[reduced_packet_index] = {
            "record": record,
            "descriptor": descriptor,
            "final_payload": final_payload,
        }
        if descriptor is None:
            continue

        connection = reference_context["connections"][descriptor["connection_id"]]
        source = descriptor["source_endpoint"]
        anchor = connection["anchors"][source]
        sequence_relative = tcp_relative_number(descriptor["sequence_number"], anchor)
        payload_start = sequence_relative + (1 if descriptor["flags"] & 0x02 else 0)
        original_payload = descriptor["payload"]
        segment = {
            "packet_id": str(record.get("packet_id")),
            "start": payload_start,
            "end": payload_start + len(original_payload),
            "original_payload": original_payload,
            "new_payload": final_payload,
            "changed": original_payload != final_payload,
            "delta": len(final_payload) - len(original_payload),
        }
        if original_payload or final_payload:
            segments_by_direction[(descriptor["connection_id"], source)].append(segment)
        packet_stream_context[str(record.get("packet_id"))] = {
            "direction_key": (descriptor["connection_id"], source),
            "payload_sequence_start": payload_start,
            "payload_length_bytes": len(original_payload),
        }

    resize_events_by_direction: dict[
        tuple[Any, tuple[str, int]],
        list[dict[str, Any]],
    ] = defaultdict(list)
    canonical_resize_events = (
        payload_projection_contract.get("canonical_resize_events", [])
        if isinstance(payload_projection_contract, dict)
        else []
    )
    if not isinstance(canonical_resize_events, list):
        raise ValueError("Step 19 canonical_resize_events must be a list.")
    for event in canonical_resize_events:
        if not isinstance(event, dict):
            raise ValueError("Step 19 canonical resize event must be an object.")
        event_positions = []
        direction_key = None
        for anchor_evidence in event.get("end_boundary_anchors", []):
            packet_id = str(anchor_evidence.get("packet_id"))
            packet_context = packet_stream_context.get(packet_id)
            if packet_context is None:
                raise TcpReconstructionError(
                    "canonical_resize_anchor_packet_missing",
                    "A canonical resize event references a packet outside the Step 20 TCP stream context.",
                    packet_id=packet_id,
                    canonical_region_id=event.get("canonical_region_id"),
                )
            anchor_direction = packet_context["direction_key"]
            if direction_key is None:
                direction_key = anchor_direction
            elif direction_key != anchor_direction:
                raise TcpReconstructionError(
                    "canonical_resize_anchor_direction_mismatch",
                    "Physical aliases for one canonical edit resolve to different TCP directions.",
                    canonical_region_id=event.get("canonical_region_id"),
                )
            packet_payload_offset = int(
                anchor_evidence["canonical_edit_end_packet_payload_offset_bytes"]
            )
            if not 0 <= packet_payload_offset <= packet_context["payload_length_bytes"]:
                raise TcpReconstructionError(
                    "canonical_resize_anchor_offset_invalid",
                    "A canonical resize end boundary lies outside its original physical packet payload.",
                    packet_id=packet_id,
                    packet_payload_offset_bytes=packet_payload_offset,
                    packet_payload_length_bytes=packet_context["payload_length_bytes"],
                )
            event_positions.append(
                packet_context["payload_sequence_start"] + packet_payload_offset
            )
        if not event_positions or len(set(event_positions)) != 1 or direction_key is None:
            raise TcpReconstructionError(
                "canonical_resize_anchor_position_mismatch",
                "Physical aliases do not resolve one canonical resize event to a unique original TCP position.",
                canonical_region_id=event.get("canonical_region_id"),
                event_positions=event_positions,
            )
        event_end = event_positions[0]
        event_start = event_end - int(event["canonical_replaced_length_bytes"])
        resize_events_by_direction[direction_key].append(
            {
                **event,
                "start": event_start,
                "end": event_end,
                "replacement_length_bytes": int(
                    event["canonical_replacement_length_bytes"]
                ),
                "delta": int(event["canonical_payload_length_delta_bytes"]),
            }
        )

    translations = {}
    resized_segment_count = 0
    all_direction_keys = set(segments_by_direction) | set(resize_events_by_direction)
    for direction_key in all_direction_keys:
        segments = segments_by_direction.get(direction_key, [])
        connection_id, source = direction_key
        anchor = reference_context["connections"][connection_id]["anchors"][source]
        translation = build_tcp_translation(
            anchor=anchor,
            segments=segments,
            resize_events=resize_events_by_direction.get(direction_key, []),
        )
        translations[direction_key] = translation
        resized_segment_count += len(translation["resized_intervals"])

    adjusted_sequence_count = 0
    adjusted_acknowledgement_count = 0
    for reduced_packet_index, prepared in prepared_by_index.items():
        descriptor = prepared["descriptor"]
        if descriptor is None:
            prepared["tcp_translation"] = None
            continue
        own_key = (descriptor["connection_id"], descriptor["source_endpoint"])
        opposite_key = (descriptor["connection_id"], descriptor["destination_endpoint"])
        translated_sequence, sequence_delta, sequence_inside = translate_tcp_number(
            descriptor["sequence_number"], translations.get(own_key)
        )
        translated_ack = descriptor["acknowledgement_number"]
        acknowledgement_delta = 0
        acknowledgement_inside = False
        if descriptor["flags"] & 0x10:
            translated_ack, acknowledgement_delta, acknowledgement_inside = translate_tcp_number(
                descriptor["acknowledgement_number"], translations.get(opposite_key)
            )
        original_sack_options = []
        reconstructed_sack_options = []
        sack_boundary_adjustment_count = 0
        for option_name, option_value in descriptor.get("tcp_options", []):
            if option_name != "SAck":
                continue
            if not isinstance(option_value, (tuple, list)) or len(option_value) % 2 != 0:
                raise TcpReconstructionError(
                    "invalid_reference_sack_option",
                    "A Step 13 TCP SACK option does not contain an even list of sequence boundaries.",
                    packet_id=prepared["record"].get("packet_id"),
                    option_value=repr(option_value),
                )
            original_values = [int(value) for value in option_value]
            reconstructed_values = []
            for boundary in original_values:
                translated_boundary, boundary_delta, boundary_inside = translate_tcp_number(
                    boundary, translations.get(opposite_key)
                )
                if boundary_inside:
                    translations[opposite_key]["unresolved_ack_reference_count"] += 1
                    raise TcpReconstructionError(
                        "sack_reference_inside_resized_segment",
                        "A TCP SACK boundary falls inside a resized segment and cannot be translated unambiguously.",
                        packet_id=prepared["record"].get("packet_id"),
                        original_sack_boundary=boundary,
                    )
                reconstructed_values.append(translated_boundary)
                sack_boundary_adjustment_count += int(boundary_delta != 0)
            original_sack_options.append(original_values)
            reconstructed_sack_options.append(reconstructed_values)
        if sequence_inside:
            translations[own_key]["unresolved_sequence_reference_count"] += 1
            raise TcpReconstructionError(
                "sequence_reference_inside_resized_segment",
                "A TCP sequence boundary falls inside a resized segment and cannot be translated unambiguously.",
                packet_id=prepared["record"].get("packet_id"),
                original_sequence_number=descriptor["sequence_number"],
            )
        if acknowledgement_inside:
            translations[opposite_key]["unresolved_ack_reference_count"] += 1
            raise TcpReconstructionError(
                "ack_reference_inside_resized_segment",
                "A TCP acknowledgement boundary falls inside a resized segment and cannot be translated unambiguously.",
                packet_id=prepared["record"].get("packet_id"),
                original_acknowledgement_number=descriptor["acknowledgement_number"],
            )
        adjusted_sequence_count += int(sequence_delta != 0)
        adjusted_acknowledgement_count += int(acknowledgement_delta != 0)
        if sequence_delta != 0:
            translations[own_key]["adjusted_sequence_packet_count"] += 1
        if acknowledgement_delta != 0:
            translations[opposite_key]["adjusted_acknowledgement_packet_count"] += 1
        prepared["tcp_translation"] = {
            "original_sequence_number": descriptor["sequence_number"],
            "reconstructed_sequence_number": translated_sequence,
            "sequence_delta": sequence_delta,
            "original_acknowledgement_number": descriptor["acknowledgement_number"],
            "reconstructed_acknowledgement_number": translated_ack,
            "acknowledgement_delta": acknowledgement_delta,
            "original_sack_options": original_sack_options,
            "reconstructed_sack_options": reconstructed_sack_options,
            "adjusted_sack_boundary_count": sack_boundary_adjustment_count,
            "connection_index": reference_context["connections"][descriptor["connection_id"]]["connection_index"],
        }

    adjusted_connections = {
        direction_key[0]
        for direction_key, translation in translations.items()
        if translation["total_delta_bytes"] != 0
    }
    direction_results = []
    for (connection_id, source), translation in sorted(
        translations.items(),
        key=lambda item: (
            item[0][0][0],
            item[0][0][1],
            item[0][1],
        ),
    ):
        connection = reference_context["connections"][connection_id]
        endpoint_a, endpoint_b = connection["connection_key"]
        destination = endpoint_b if source == endpoint_a else endpoint_a
        direction_results.append(
            {
                "connection_index": connection["connection_index"],
                "endpoint_a": endpoint_report_value(endpoint_a),
                "endpoint_b": endpoint_report_value(endpoint_b),
                "source": endpoint_report_value(source),
                "destination": endpoint_report_value(destination),
                "sequence_anchor": translation["anchor"],
                "segment_count": translation["segment_count"],
                "unique_sequence_range_count": translation["unique_sequence_range_count"],
                "resized_segment_count": len(translation["resized_intervals"]),
                "payload_growth_bytes": translation["payload_growth_bytes"],
                "payload_shrinkage_bytes": translation["payload_shrinkage_bytes"],
                "net_payload_delta_bytes": translation["total_delta_bytes"],
                "adjusted_sequence_packet_count": translation["adjusted_sequence_packet_count"],
                "adjusted_acknowledgement_packet_count": translation["adjusted_acknowledgement_packet_count"],
                "preserved_retransmission_count": translation["preserved_retransmission_count"],
                "preserved_modified_retransmission_count": translation["preserved_modified_retransmission_count"],
                "preserved_overlapping_segment_pair_count": translation["preserved_overlapping_segment_pair_count"],
                "preserved_modified_overlapping_segment_pair_count": translation["preserved_modified_overlapping_segment_pair_count"],
                "unresolved_sequence_reference_count": translation["unresolved_sequence_reference_count"],
                "unresolved_ack_reference_count": translation["unresolved_ack_reference_count"],
                "translation_event_count": len(translation["positions"]),
            }
        )
    preserved_retransmission_count = sum(
        result["preserved_retransmission_count"] for result in direction_results
    )
    preserved_modified_retransmission_count = sum(
        result["preserved_modified_retransmission_count"] for result in direction_results
    )
    preserved_overlapping_segment_pair_count = sum(
        result["preserved_overlapping_segment_pair_count"] for result in direction_results
    )
    preserved_modified_overlapping_segment_pair_count = sum(
        result["preserved_modified_overlapping_segment_pair_count"] for result in direction_results
    )
    adjusted_sack_boundary_count = sum(
        prepared["tcp_translation"]["adjusted_sack_boundary_count"]
        for prepared in prepared_by_index.values()
        if prepared.get("tcp_translation")
    )
    sack_option_packet_count = sum(
        int(bool(prepared["tcp_translation"]["original_sack_options"]))
        for prepared in prepared_by_index.values()
        if prepared.get("tcp_translation")
    )
    return {
        "prepared_by_index": prepared_by_index,
        "translations": translations,
        "direction_results": direction_results,
        "summary": {
            "reference_pcap_packet_count": reference_context["packet_count"],
            "tcp_connection_count": reference_context["connection_count"],
            "tcp_direction_count": len(direction_results),
            "tcp_payload_content_changed_packet_count": payload_content_changed_packet_count,
            "tcp_payload_length_changed_packet_count": payload_length_changed_packet_count,
            "tcp_connections_with_payload_length_delta": len(adjusted_connections),
            "resized_tcp_segment_count": resized_segment_count,
            "tcp_translation_event_count": sum(result["translation_event_count"] for result in direction_results),
            "tcp_payload_growth_bytes": sum(result["payload_growth_bytes"] for result in direction_results),
            "tcp_payload_shrinkage_bytes": sum(result["payload_shrinkage_bytes"] for result in direction_results),
            "tcp_net_payload_delta_bytes": sum(result["net_payload_delta_bytes"] for result in direction_results),
            "adjusted_tcp_sequence_packet_count": adjusted_sequence_count,
            "adjusted_tcp_acknowledgement_packet_count": adjusted_acknowledgement_count,
            "tcp_sack_option_packet_count": sack_option_packet_count,
            "adjusted_tcp_sack_boundary_count": adjusted_sack_boundary_count,
            "preserved_tcp_retransmission_count": preserved_retransmission_count,
            "preserved_modified_tcp_retransmission_count": preserved_modified_retransmission_count,
            "preserved_tcp_overlapping_segment_pair_count": preserved_overlapping_segment_pair_count,
            "preserved_modified_tcp_overlapping_segment_pair_count": preserved_modified_overlapping_segment_pair_count,
            "unresolved_tcp_sequence_reference_count": 0,
            "unresolved_tcp_ack_reference_count": 0,
            "ambiguous_tcp_translation_count": 0,
            "tcp_reconstruction_error_count": 0,
        },
    }


#This function enforces strategy-specific reconstruction constraints before packet materialization.
def enforce_active_reconstruction_contract(capabilities: ModificationCapabilities, translation_plan: dict[str, Any]) -> None:
    if not capabilities.requires_payload_preservation:
        return

    summary = translation_plan["summary"]
    payload_counters = {
        "tcp_payload_content_changed_packet_count": summary.get("tcp_payload_content_changed_packet_count", 0),
        "tcp_payload_length_changed_packet_count": summary.get("tcp_payload_length_changed_packet_count", 0),
        "resized_tcp_segment_count": summary.get("resized_tcp_segment_count", 0),
        "tcp_payload_growth_bytes": summary.get("tcp_payload_growth_bytes", 0),
        "tcp_payload_shrinkage_bytes": summary.get("tcp_payload_shrinkage_bytes", 0),
        "tcp_net_payload_delta_bytes": summary.get("tcp_net_payload_delta_bytes", 0),
        "adjusted_tcp_sequence_packet_count": summary.get("adjusted_tcp_sequence_packet_count", 0),
        "adjusted_tcp_acknowledgement_packet_count": summary.get("adjusted_tcp_acknowledgement_packet_count", 0),
    }
    if any(payload_counters.values()):
        raise TcpReconstructionError(
            "header_only_payload_change_detected",
            "The active strategy is header-only, but Step 20 detected payload changes before reconstruction.",
            modification_strategy=capabilities.strategy,
            **payload_counters,
        )


#This function decodes the mutable payload_hex field into bytes.
#This function records an error when payload_hex is not valid hexadecimal content so the packet is not silently reconstructed.
def payload_bytes(record: dict[str, Any], packet_issues: list[dict[str, Any]]) -> bytes:
    payload_hex = record.get("payload_hex", "")
    if not isinstance(payload_hex, str):
        packet_issues.append(
            issue(
                "error",
                "payload_hex_not_string",
                "payload_hex must be a string before PCAP reconstruction.",
                field="payload_hex",
            )
        )
        return b""
    try:
        return binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        packet_issues.append(
            issue(
                "error",
                "payload_hex_invalid",
                "payload_hex could not be decoded into bytes.",
                field="payload_hex",
                failure_message=str(error),
            )
        )
        return b""


#This helper coerces integer header values before assigning them to Scapy fields.
def int_header_value(record: dict[str, Any], field: str) -> int | None:
    value = header_field_value(record, field)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


#This function materializes policy-authorized physical-header edits onto a copied reference packet.
def apply_editable_header_fields_to_packet(
    *,
    packet: Any,
    record: dict[str, Any],
    header_policy: dict[str, Any],
    scapy: dict[str, Any],
) -> None:
    editable_fields = set(editable_header_fields_from_policy(header_policy))
    IP = scapy["IP"]
    TCP = scapy["TCP"]

    if IP in packet:
        ip_layer = packet[IP]
        if "ipv4.tos" in editable_fields:
            value = int_header_value(record, "ipv4.tos")
            if value is not None:
                ip_layer.tos = value
        if "ipv4.identification" in editable_fields:
            value = int_header_value(record, "ipv4.identification")
            if value is not None:
                ip_layer.id = value
        if "ipv4.ttl" in editable_fields:
            value = int_header_value(record, "ipv4.ttl")
            if value is not None:
                ip_layer.ttl = value
        if "ipv4.flags_fragment_offset" in editable_fields:
            value = int_header_value(record, "ipv4.flags_fragment_offset")
            if value is not None:
                ip_layer.flags = (value >> 13) & 0x07
                ip_layer.frag = value & 0x1FFF
        ipv4_fragment_subfields = {
            "ipv4.flags.reserved",
            "ipv4.flags.dont_fragment",
            "ipv4.flags.more_fragments",
            "ipv4.fragment_offset_units",
        }
        if editable_fields.intersection(ipv4_fragment_subfields):
            reserved = int_header_value(record, "ipv4.flags.reserved") or 0
            dont_fragment = int_header_value(record, "ipv4.flags.dont_fragment") or 0
            more_fragments = int_header_value(record, "ipv4.flags.more_fragments") or 0
            fragment_offset = int_header_value(record, "ipv4.fragment_offset_units")
            if fragment_offset is not None:
                ip_layer.flags = ((reserved & 1) << 2) | ((dont_fragment & 1) << 1) | (more_fragments & 1)
                ip_layer.frag = fragment_offset & 0x1FFF

    if TCP in packet:
        tcp_layer = packet[TCP]
        if "tcp.window" in editable_fields:
            value = int_header_value(record, "tcp.window")
            if value is not None:
                tcp_layer.window = value
        if "tcp.urgent_pointer" in editable_fields:
            value = int_header_value(record, "tcp.urgent_pointer")
            if value is not None:
                tcp_layer.urgptr = value
        tcp_flag_fields = {
            "tcp.flags.ns": 0x100,
            "tcp.flags.cwr": 0x080,
            "tcp.flags.ece": 0x040,
            "tcp.flags.urg": 0x020,
            "tcp.flags.ack": 0x010,
            "tcp.flags.psh": 0x008,
            "tcp.flags.rst": 0x004,
            "tcp.flags.syn": 0x002,
            "tcp.flags.fin": 0x001,
        }
        if editable_fields.intersection(tcp_flag_fields):
            raw_flags = 0
            for field, bit_mask in tcp_flag_fields.items():
                value = int_header_value(record, field)
                if value:
                    raw_flags |= bit_mask
            tcp_layer.flags = raw_flags


#This function rebuilds one packet from the reference frame plus validated JSON/header changes.
def rebuild_from_reference_packet(
    *,
    reference_packet: Any,
    record: dict[str, Any],
    payload: bytes,
    tcp_translation: dict[str, Any] | None,
    scapy: dict[str, Any],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    packet_issues: list[dict[str, Any]],
) -> Any:
    packet = reference_packet.copy()
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    Raw = scapy["Raw"]
    transport_protocol = str(record.get("transport_protocol") or "").upper()

    if transport_protocol == "TCP":
        if TCP not in packet or tcp_translation is None:
            packet_issues.append(
                issue(
                    "error",
                    "reference_tcp_context_missing",
                    "The Step 13 reference frame does not provide the TCP context required for reconstruction.",
                )
            )
            return None
        transport = packet[TCP]
        transport.seq = tcp_translation["reconstructed_sequence_number"]
        transport.ack = tcp_translation["reconstructed_acknowledgement_number"]
        reconstructed_sack_options = iter(tcp_translation.get("reconstructed_sack_options", []))
        translated_options = []
        for option_name, option_value in list(transport.options or []):
            if option_name == "SAck":
                option_value = tuple(next(reconstructed_sack_options))
            translated_options.append((option_name, option_value))
        transport.options = translated_options
    elif transport_protocol == "UDP":
        if UDP not in packet:
            packet_issues.append(
                issue(
                    "error",
                    "reference_udp_context_missing",
                    "The Step 13 reference frame does not contain the expected UDP layer.",
                )
            )
            return None
        transport = packet[UDP]
    else:
        packet_issues.append(
            issue(
                "error",
                "reference_transport_protocol_unsupported",
                "Reference-PCAP reconstruction currently requires TCP or UDP transport.",
                transport_protocol=transport_protocol,
            )
        )
        return None

    transport.remove_payload()
    if payload:
        transport.add_payload(Raw(load=payload))

    if capabilities.allows_header_edits:
        apply_editable_header_fields_to_packet(
            packet=packet,
            record=record,
            header_policy=header_policy,
            scapy=scapy,
        )

    if hasattr(transport, "chksum"):
        transport.chksum = None
    if UDP in packet:
        packet[UDP].len = None
    if IP in packet:
        packet[IP].len = None
        packet[IP].chksum = None
    elif IPv6 in packet:
        packet[IPv6].plen = None
    return packet


#This function extracts group-level context from the Step 18 merge trace when it is present.
#This function stores context in packet and group results so later alert comparison can map reconstructed POST packets back to their LLM group.
def group_context_for_record(record: dict[str, Any], record_index: int) -> dict[str, Any]:
    merge_trace = record.get("_merge_trace")
    if isinstance(merge_trace, dict):
        return {
            "condition": merge_trace.get("condition"),
            "model_name": merge_trace.get("model_name"),
            "group_id": merge_trace.get("group_id"),
            "group_key": f"{merge_trace.get('condition')}::{merge_trace.get('group_id')}",
            "_merge_trace": merge_trace,
        }
    group_id = record.get("group_id")
    if group_id is not None:
        return {"condition": None, "model_name": None, "group_id": str(group_id), "group_key": f"unknown::{group_id}"}
    return {"condition": None, "model_name": None, "group_id": None, "group_key": f"unassigned_record_{record_index}"}


#This function reconstructs one packet and returns both the Scapy packet object and its report entry.
#This function withholds the Scapy packet when a packet has any error-level issue, classifying it as Invalid Traffic.
def reconstruct_one_packet(
    record: Any,
    record_index: int,
    scapy: dict[str, Any],
    reference_packet: Any,
    tcp_translation: dict[str, Any] | None,
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
) -> dict[str, Any]:
    packet_issues: list[dict[str, Any]] = []
    if not isinstance(record, dict):
        return {
            "packet": None,
            "result": {
                "record_index": record_index,
                "packet_id": None,
                "status": "failed",
                "evaluation_status": "Invalid Traffic",
                "issues": [
                    issue("error", "traffic_record_not_object", "Traffic record is not a JSON object.")
                ],
            },
        }

    context = group_context_for_record(record, record_index)
    payload = payload_bytes(record, packet_issues)
    packet = rebuild_from_reference_packet(
        reference_packet=reference_packet,
        record=record,
        payload=payload,
        tcp_translation=tcp_translation,
        scapy=scapy,
        header_policy=header_policy,
        capabilities=capabilities,
        packet_issues=packet_issues,
    )

    #This function preserves PCAP timestamps when Step 19 kept a numeric timestamp_epoch_pcap value.
    if packet is not None and isinstance(record.get("timestamp_epoch_pcap"), (int, float)):
        packet.time = float(record["timestamp_epoch_pcap"])
    elif packet is not None:
        packet_issues.append(
            issue(
                "warning",
                "timestamp_not_preserved",
                "timestamp_epoch_pcap was not numeric; Scapy will use the current write time.",
                field="timestamp_epoch_pcap",
            )
        )

    #These checks do not block reconstruction. They record differences caused by Scapy rebuilding the packet from structured fields.
    if packet is not None:
        try:
            packet, rebuilt_bytes, ethernet_padding_length = apply_ethernet_minimum_padding(packet, scapy)
            rebuilt_length = len(rebuilt_bytes)
            if ethernet_padding_length:
                packet_issues.append(
                    issue(
                        "info",
                        "ethernet_minimum_padding_added",
                        "Zero padding was added outside the IP packet to preserve the Ethernet minimum frame size.",
                        padding_bytes=ethernet_padding_length,
                        minimum_frame_bytes_without_fcs=ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS,
                    )
                )
        except Exception as error:
            packet_issues.append(
                issue(
                    "error",
                    "packet_serialization_failed",
                    "Scapy could not serialize the reconstructed packet.",
                    failure_type=type(error).__name__,
                    failure_message=str(error),
                )
            )
            packet = None
            rebuilt_length = None
        declared_packet_length = record.get("packet_length_bytes")
        if rebuilt_length is not None and is_int_like(declared_packet_length) and declared_packet_length != rebuilt_length:
            packet_issues.append(
                issue(
                    "warning",
                    "packet_length_changed_after_reconstruction",
                    "Rebuilt packet length differs from packet_length_bytes stored in JSON.",
                    expected_json_value=declared_packet_length,
                    rebuilt_packet_length_bytes=rebuilt_length,
                    policy="scapy_recalculates_lengths_from_rebuilt_layers",
                )
            )
        declared_payload_length = record.get("payload_length_bytes")
        if is_int_like(declared_payload_length) and declared_payload_length != len(payload):
            packet_issues.append(
                issue(
                    "warning",
                    "payload_length_bytes_mismatch",
                    "payload_length_bytes differs from decoded payload_hex length.",
                    expected_json_value=declared_payload_length,
                    decoded_payload_length_bytes=len(payload),
                )
            )

    has_error = any(item["severity"] == "error" for item in packet_issues)
    result = {
        "record_index": record_index,
        "packet_id": record.get("packet_id"),
        "original_packet_number": record.get("original_packet_number"),
        "reduced_packet_index": record.get("reduced_packet_index"),
        "timestamp_epoch_pcap": record.get("timestamp_epoch_pcap"),
        "group_key": context["group_key"],
        "condition": context["condition"],
        "model_name": context["model_name"],
        "group_id": context["group_id"],
        "_merge_trace": context.get("_merge_trace"),
        "tcp_sequence_translation": tcp_translation,
        "status": "failed" if has_error else "reconstructed",
        "evaluation_status": "Invalid Traffic" if has_error else "Reconstructed Traffic",
        "issues": packet_issues,
    }
    return {"packet": None if has_error else packet, "result": result}


#This function writes the reconstructed Scapy packets to a PCAP file.
#This function writes Ethernet linktype PCAPs because Step 14 exports Ethernet-layer records and Step 20 rebuilds Ether frames.
def write_packets(output_pcap_path: Path, packets: list[Any], scapy: dict[str, Any]) -> None:
    output_pcap_path.parent.mkdir(parents=True, exist_ok=True)
    PcapWriter = scapy["PcapWriter"]
    writer = PcapWriter(str(output_pcap_path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


#This function independently verifies an Internet checksum over serialized bytes.
def internet_checksum_is_valid(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


#This function parses TCP option kinds from raw option bytes for independent validation.
def tcp_option_kinds_from_bytes(option_bytes: bytes) -> tuple[list[int], str | None]:
    kinds = []
    offset = 0
    while offset < len(option_bytes):
        kind = option_bytes[offset]
        kinds.append(kind)
        if kind == 0:
            if any(option_bytes[offset + 1 :]):
                return kinds, "nonzero_bytes_after_tcp_eol"
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= len(option_bytes):
            return kinds, "tcp_option_length_missing"
        option_length = option_bytes[offset + 1]
        if option_length < 2 or offset + option_length > len(option_bytes):
            return kinds, "tcp_option_length_invalid"
        offset += option_length
    return kinds, None


#This function finds inconsistent overlaps in reassembled TCP byte intervals.
def tcp_overlap_conflicts(
    segments_by_direction: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]]
) -> set[tuple[str, str]]:
    conflicts = set()
    for segments in segments_by_direction.values():
        ordered = sorted(segments, key=lambda item: (item["start"], item["end"], item["packet_id"]))
        active = []
        for segment in ordered:
            active = [candidate for candidate in active if candidate["end"] > segment["start"]]
            for candidate in active:
                overlap_start = max(candidate["start"], segment["start"])
                overlap_end = min(candidate["end"], segment["end"])
                if overlap_start >= overlap_end:
                    continue
                candidate_slice = candidate["payload"][
                    overlap_start - candidate["start"] : overlap_end - candidate["start"]
                ]
                segment_slice = segment["payload"][
                    overlap_start - segment["start"] : overlap_end - segment["start"]
                ]
                if candidate_slice != segment_slice:
                    conflicts.add(tuple(sorted((candidate["packet_id"], segment["packet_id"]))))
            active.append(segment)
    return conflicts


#This function summarizes TCP connection handshake and closure evidence in the POST subset.
def tcp_connection_state_inventory(
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
) -> dict[str, Any]:
    packets_by_connection: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for record in traffic:
        descriptor = reference_context["descriptors_by_index"].get(record["reduced_packet_index"])
        if descriptor is not None:
            packets_by_connection[descriptor["connection_id"]].append(descriptor)

    results = []
    status_counts: Counter = Counter()
    closure_counts: Counter = Counter()
    for connection_id, descriptors in sorted(
        packets_by_connection.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        descriptors.sort(key=lambda item: item["reduced_packet_index"])
        connection = reference_context["connections"][connection_id]
        initiator = connection.get("initiator")
        syn_start_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x02 and not descriptor["flags"] & 0x10
            ),
            None,
        )
        syn_ack_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x02 and descriptor["flags"] & 0x10
                and (syn_start_position is None or index > syn_start_position)
            ),
            None,
        )
        final_ack_position = next(
            (
                index
                for index, descriptor in enumerate(descriptors)
                if descriptor["flags"] & 0x10
                and not descriptor["flags"] & 0x02
                and (syn_ack_position is None or index > syn_ack_position)
                and (initiator is None or descriptor["source_endpoint"] == initiator)
            ),
            None,
        )
        if syn_start_position is not None and syn_ack_position is not None and final_ack_position is not None:
            handshake_status = "complete_in_selected_post_subset"
        elif syn_start_position is None and syn_ack_position is None:
            handshake_status = "not_observed_in_selected_post_subset"
        else:
            handshake_status = "partial_in_selected_post_subset"

        fin_endpoints = {
            descriptor["source_endpoint"]
            for descriptor in descriptors
            if descriptor["flags"] & 0x01
        }
        rst_count = sum(bool(descriptor["flags"] & 0x04) for descriptor in descriptors)
        if rst_count:
            closure_status = "reset_observed"
        elif len(fin_endpoints) == 2:
            closure_status = "bilateral_fin_observed"
        elif len(fin_endpoints) == 1:
            closure_status = "unilateral_fin_observed"
        else:
            closure_status = "not_observed_in_selected_post_subset"
        status_counts[handshake_status] += 1
        closure_counts[closure_status] += 1
        endpoint_a, endpoint_b = connection["connection_key"]
        results.append(
            {
                "connection_index": connection["connection_index"],
                "endpoint_a": endpoint_report_value(endpoint_a),
                "endpoint_b": endpoint_report_value(endpoint_b),
                "packet_count": len(descriptors),
                "handshake_status": handshake_status,
                "closure_status": closure_status,
                "syn_start_count": sum(
                    bool(descriptor["flags"] & 0x02) and not bool(descriptor["flags"] & 0x10)
                    for descriptor in descriptors
                ),
                "syn_ack_count": sum(
                    bool(descriptor["flags"] & 0x02) and bool(descriptor["flags"] & 0x10)
                    for descriptor in descriptors
                ),
                "fin_packet_count": sum(bool(descriptor["flags"] & 0x01) for descriptor in descriptors),
                "rst_packet_count": rst_count,
            }
        )
    return {
        "summary": {
            "connection_count": len(results),
            "handshake_status_counts": dict(sorted(status_counts.items())),
            "closure_status_counts": dict(sorted(closure_counts.items())),
            "interpretation": "Handshake and closure coverage is reported for the Step 19-selected POST subset. Partial capture coverage is not itself a protocol error because excluded packets may create observational gaps.",
        },
        "connection_results": results,
    }


#This function independently audits the reconstructed PCAP against protocol and policy invariants.
def audit_reconstructed_pcap(
    *,
    output_pcap_path: Path,
    traffic: list[dict[str, Any]],
    reference_context: dict[str, Any],
    translation_plan: dict[str, Any],
    payload_projection_contract: dict[str, Any],
    header_policy: dict[str, Any],
    capabilities: ModificationCapabilities,
    scapy: dict[str, Any],
) -> dict[str, Any]:
    issues_by_record_index: dict[int, list[dict[str, Any]]] = defaultdict(list)
    issue_counts: Counter = Counter()
    observed: Counter = Counter()
    tcp_option_kind_counts: Counter = Counter()
    original_segments: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)
    reconstructed_segments: dict[tuple[Any, tuple[str, int]], list[dict[str, Any]]] = defaultdict(list)
    projected_packet_ids = set(payload_projection_contract.get("projected_packet_ids", []))
    projections_by_packet_id = payload_projection_contract.get("_projections_by_packet_id", {})
    projected_packet_comparison_count = 0
    projected_packet_aggregate_no_effect_count = 0
    realized_projected_net_payload_delta_bytes = 0

    #This function records bounded per-packet audit issues and aggregate reason counts.
    def record_issue(record_index: int, reason: str, message: str, **extra: Any) -> None:
        issue_counts[reason] += 1
        if len(issues_by_record_index[record_index]) < 20:
            issues_by_record_index[record_index].append(
                issue("error", reason, message, **extra)
            )

    output_packet_count = 0
    with scapy["PcapReader"](str(output_pcap_path)) as reader:
        for record_index, (record, packet) in enumerate(zip(traffic, reader), start=1):
            output_packet_count = record_index
            reduced_packet_index = record["reduced_packet_index"]
            reference_packet = reference_context["packets_by_index"][reduced_packet_index]
            prepared = translation_plan["prepared_by_index"][reduced_packet_index]
            descriptor = prepared["descriptor"]
            frame = bytes(packet)
            observed["frame_count"] += 1

            if len(frame) < ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS:
                record_issue(record_index, "ethernet_frame_below_minimum", "Ethernet frame is shorter than 60 bytes without FCS.", frame_length_bytes=len(frame))
            if len(frame) < 14:
                record_issue(record_index, "ethernet_header_truncated", "Ethernet header is truncated.")
                continue
            ethertype = int.from_bytes(frame[12:14], "big")
            observed[f"ethertype_0x{ethertype:04x}_count"] += 1
            if ethertype in {0x8100, 0x88A8}:
                record_issue(record_index, "unexpected_vlan_encapsulation", "VLAN encapsulation is outside the selected-dataset contract.", ethertype=ethertype)
                continue
            if ethertype != 0x0800:
                record_issue(record_index, "unexpected_ether_type", "Only Ethernet/IPv4 frames are permitted by the selected-dataset contract.", ethertype=ethertype)
                continue
            if frame[:12] != bytes(reference_packet)[:12]:
                record_issue(record_index, "ethernet_addresses_changed", "Ethernet source or destination differs from the Step 13 frame.")

            if len(frame) < 34:
                record_issue(record_index, "ipv4_header_truncated", "IPv4 header is truncated.")
                continue
            version = frame[14] >> 4
            ihl = (frame[14] & 0x0F) * 4
            total_length = int.from_bytes(frame[16:18], "big")
            protocol = frame[23]
            fragment_field = int.from_bytes(frame[20:22], "big")
            observed[f"ipv4_version_{version}_count"] += 1
            observed[f"ipv4_ihl_{ihl}_count"] += 1
            observed[f"ipv4_protocol_{protocol}_count"] += 1
            observed["ipv4_fragmented_packet_count"] += int(bool((fragment_field & 0x1FFF) or (fragment_field & 0x2000)))
            observed["ipv4_option_packet_count"] += int(ihl > 20)
            if version != 4:
                record_issue(record_index, "unexpected_ip_version", "Only IPv4 is permitted by the selected-dataset contract.", ip_version=version)
                continue
            if ihl != 20:
                record_issue(record_index, "unexpected_ipv4_ihl", "IPv4 options are absent from the selected dataset and must not be introduced.", ihl_bytes=ihl)
            if total_length < ihl + 20 or 14 + total_length > len(frame):
                record_issue(record_index, "ipv4_total_length_invalid", "IPv4 total_length is inconsistent with the serialized frame.", total_length=total_length, frame_length=len(frame))
                continue
            if not internet_checksum_is_valid(frame[14 : 14 + ihl]):
                record_issue(record_index, "ipv4_checksum_invalid", "Independent IPv4 checksum verification failed.")
            if protocol != 6:
                record_issue(record_index, "unexpected_ipv4_protocol", "Only TCP is permitted by the selected-dataset contract.", protocol=protocol)
                continue
            if (fragment_field & 0x1FFF) or (fragment_field & 0x2000):
                record_issue(record_index, "unexpected_ipv4_fragmentation", "IPv4 fragmentation is absent from the selected dataset and must not be introduced.")
            expected_frame_length = max(ETHERNET_MIN_FRAME_BYTES_WITHOUT_FCS, 14 + total_length)
            padding = frame[14 + total_length :]
            observed[f"ethernet_padding_{len(padding)}_byte_frame_count"] += 1
            if len(frame) != expected_frame_length:
                record_issue(record_index, "ethernet_padding_length_invalid", "Frame length does not equal the IPv4 datagram plus required Ethernet minimum padding.", expected_frame_length=expected_frame_length, actual_frame_length=len(frame))
            if any(padding):
                record_issue(record_index, "ethernet_padding_nonzero", "Ethernet padding outside the IPv4 datagram must contain only zero bytes.")
            declared_packet_length = record.get("packet_length_bytes")
            if not is_int_like(declared_packet_length):
                record_issue(record_index, "packet_length_bytes_metadata_invalid", "Step 19 packet_length_bytes must be an integer physical frame length.")
            elif int(declared_packet_length) != len(frame):
                record_issue(
                    record_index,
                    "packet_length_bytes_metadata_mismatch",
                    "Step 19 packet_length_bytes differs from the physical frame length written to PCAP.",
                    expected_json_value=int(declared_packet_length),
                    actual_frame_length_bytes=len(frame),
                )
            record_ipv4_header = record.get("ipv4_header")
            if isinstance(record_ipv4_header, dict):
                record_ipv4_total = record_ipv4_header.get("total_length")
                if is_int_like(record_ipv4_total) and int(record_ipv4_total) != total_length:
                    record_issue(
                        record_index,
                        "ipv4_total_length_metadata_mismatch",
                        "Step 19 ipv4_header.total_length differs from the serialized IPv4 total_length.",
                        expected_json_value=int(record_ipv4_total),
                        actual_ipv4_total_length=total_length,
                    )
                capture_relation = record_ipv4_header.get("capture_relation")
                if isinstance(capture_relation, dict):
                    trailing = capture_relation.get("trailing_bytes_after_declared_ipv4")
                    if is_int_like(trailing) and int(trailing) != len(padding):
                        record_issue(
                            record_index,
                            "ipv4_capture_relation_padding_mismatch",
                            "Step 19 IPv4 capture_relation trailing bytes differ from reconstructed Ethernet padding.",
                            expected_json_value=int(trailing),
                            actual_padding_length_bytes=len(padding),
                        )
                    status = capture_relation.get("status")
                    expected_status = "complete_with_trailing_bytes" if padding else "complete"
                    if isinstance(status, str) and status != expected_status:
                        record_issue(
                            record_index,
                            "ipv4_capture_relation_status_mismatch",
                            "Step 19 IPv4 capture_relation status differs from reconstructed Ethernet padding state.",
                            expected_status=expected_status,
                            actual_status=status,
                        )
            record_ethernet_header = record.get("ethernet_header")
            if isinstance(record_ethernet_header, dict):
                metadata_checks = {
                    "header_length_bytes": 14,
                    "effective_frame_length_bytes": 14 + total_length,
                    "captured_length_bytes": len(frame),
                    "padding_length_bytes": len(padding),
                }
                for metadata_field, actual_value in metadata_checks.items():
                    metadata_value = record_ethernet_header.get(metadata_field)
                    if is_int_like(metadata_value) and int(metadata_value) != actual_value:
                        record_issue(
                            record_index,
                            f"ethernet_{metadata_field}_metadata_mismatch",
                            "Step 19 Ethernet metadata differs from the reconstructed PCAP frame.",
                            field=metadata_field,
                            expected_json_value=int(metadata_value),
                            actual_value=actual_value,
                        )
                padding_present = record_ethernet_header.get("padding_present")
                if isinstance(padding_present, bool) and padding_present != bool(padding):
                    record_issue(
                        record_index,
                        "ethernet_padding_present_metadata_mismatch",
                        "Step 19 Ethernet padding_present differs from the reconstructed PCAP padding state.",
                        expected_json_value=padding_present,
                        actual_padding_present=bool(padding),
                    )
                padding_hex = record_ethernet_header.get("padding_hex")
                if isinstance(padding_hex, str) and padding_hex.lower() != ("00" * len(padding)):
                    record_issue(
                        record_index,
                        "ethernet_padding_hex_metadata_mismatch",
                        "Step 19 Ethernet padding_hex differs from the reconstructed PCAP padding bytes.",
                        expected_json_value=padding_hex,
                        actual_padding_hex=padding.hex(),
                    )

            tcp_offset = 14 + ihl
            tcp_length = total_length - ihl
            if tcp_length < 20 or len(frame) < tcp_offset + tcp_length:
                record_issue(record_index, "tcp_header_truncated", "TCP header or segment is truncated.")
                continue
            data_offset = (frame[tcp_offset + 12] >> 4) * 4
            flags = frame[tcp_offset + 13]
            urgent_pointer = int.from_bytes(frame[tcp_offset + 18 : tcp_offset + 20], "big")
            observed[f"tcp_data_offset_{data_offset}_count"] += 1
            observed["tcp_urg_flag_packet_count"] += int(bool(flags & 0x20))
            observed["tcp_urgent_pointer_nonzero_count"] += int(urgent_pointer != 0)
            if data_offset < 20 or data_offset > tcp_length or data_offset % 4:
                record_issue(record_index, "tcp_data_offset_invalid", "TCP data offset is inconsistent with the serialized segment.", data_offset_bytes=data_offset, tcp_length_bytes=tcp_length)
                continue
            option_kinds, option_error = tcp_option_kinds_from_bytes(frame[tcp_offset + 20 : tcp_offset + data_offset])
            tcp_option_kind_counts.update(option_kinds)
            if option_error:
                record_issue(record_index, option_error, "TCP option encoding failed independent validation.")
            pseudo_header = frame[26:30] + frame[30:34] + b"\x00\x06" + tcp_length.to_bytes(2, "big")
            if not internet_checksum_is_valid(pseudo_header + frame[tcp_offset : tcp_offset + tcp_length]):
                record_issue(record_index, "tcp_checksum_invalid", "Independent TCP checksum verification failed.")

            reference_ip = reference_packet[scapy["IP"]]
            output_ip = packet[scapy["IP"]]
            ipv4_policy_fields = {
                "src": "ipv4.source_address",
                "dst": "ipv4.destination_address",
                "id": "ipv4.identification",
                "flags": "ipv4.flags_fragment_offset",
                "frag": "ipv4.fragment_offset_units",
                "ttl": "ipv4.ttl",
                "tos": "ipv4.tos",
            }
            for field in ("src", "dst", "id", "flags", "frag", "ttl", "tos"):
                if getattr(output_ip, field) != getattr(reference_ip, field):
                    if capabilities.allows_header_edits and is_editable_header_field(header_policy, ipv4_policy_fields.get(field, "")):
                        continue
                    record_issue(record_index, "ipv4_immutable_field_changed", "An immutable IPv4 field differs from Step 13.", field=field)
            if scapy["TCP"] not in reference_packet:
                record_issue(
                    record_index,
                    "reference_tcp_layer_missing",
                    "The Step 13 reference packet does not expose the TCP layer required by the selected-dataset contract.",
                )
                continue
            if scapy["TCP"] not in packet:
                record_issue(
                    record_index,
                    "tcp_layer_missing_after_reconstruction",
                    "The reconstructed IPv4 packet no longer exposes a TCP layer; this can occur when an invalid fragmentation edit changes Scapy's protocol dissection.",
                    ipv4_fragment_field=fragment_field,
                )
                continue
            reference_tcp = reference_packet[scapy["TCP"]]
            output_tcp = packet[scapy["TCP"]]
            tcp_policy_fields = {
                "sport": "tcp.source_port",
                "dport": "tcp.destination_port",
                "flags": "tcp.flags",
                "window": "tcp.window",
                "urgptr": "tcp.urgent_pointer",
            }
            for field in ("sport", "dport", "flags", "window", "urgptr"):
                if getattr(output_tcp, field) != getattr(reference_tcp, field):
                    tcp_flags_authorized = field == "flags" and any(
                        capabilities.allows_header_edits and is_editable_header_field(header_policy, flag_field)
                        for flag_field in [
                            "tcp.flags.ns",
                            "tcp.flags.cwr",
                            "tcp.flags.ece",
                            "tcp.flags.urg",
                            "tcp.flags.ack",
                            "tcp.flags.psh",
                            "tcp.flags.rst",
                            "tcp.flags.syn",
                            "tcp.flags.fin",
                        ]
                    )
                    if tcp_flags_authorized or (
                        capabilities.allows_header_edits and is_editable_header_field(header_policy, tcp_policy_fields.get(field, ""))
                    ):
                        continue
                    record_issue(record_index, "tcp_immutable_field_changed", "An immutable TCP field differs from Step 13.", field=field)
            translation = prepared["tcp_translation"]
            if int(output_tcp.seq) != translation["reconstructed_sequence_number"]:
                record_issue(record_index, "tcp_sequence_translation_mismatch", "Serialized TCP sequence number differs from the translation plan.")
            if int(output_tcp.ack) != translation["reconstructed_acknowledgement_number"]:
                record_issue(record_index, "tcp_ack_translation_mismatch", "Serialized TCP acknowledgement number differs from the translation plan.")
            expected_options = []
            sack_values = iter(translation["reconstructed_sack_options"])
            for option_name, option_value in list(reference_tcp.options or []):
                if option_name == "SAck":
                    option_value = tuple(next(sack_values))
                expected_options.append((option_name, option_value))
            if list(output_tcp.options or []) != expected_options:
                record_issue(record_index, "tcp_options_changed_unexpectedly", "TCP options differ from Step 13 after applying only the planned SACK translation.")
            observed["tcp_window_field_preserved_count"] += int(output_tcp.window == reference_tcp.window)
            observed["tcp_option_field_preserved_count"] += int(list(output_tcp.options or []) == expected_options)

            output_payload = frame[tcp_offset + data_offset : tcp_offset + tcp_length]
            if output_payload != prepared["final_payload"]:
                record_issue(record_index, "tcp_payload_mismatch", "Serialized TCP payload differs from the Step 19 payload.")
            packet_id = str(record.get("packet_id"))
            reference_payload = descriptor["payload"] if descriptor is not None else b""
            expected_payload = prepared["final_payload"]
            has_effective_projection = packet_id in projected_packet_ids
            expected_payload_changed = expected_payload != reference_payload
            if has_effective_projection:
                projected_packet_comparison_count += 1
                realized_projected_net_payload_delta_bytes += len(output_payload) - len(reference_payload)
                try:
                    independently_projected_payload = materialize_projected_packet_payload(
                        reference_payload,
                        projections_by_packet_id.get(packet_id, []),
                    )
                except (ValueError, binascii.Error) as error:
                    independently_projected_payload = None
                    record_issue(
                        record_index,
                        "effective_payload_projection_evidence_invalid",
                        "Step 20 could not independently apply the Step 19 payload projection evidence.",
                        packet_id=packet_id,
                        error=str(error),
                    )
                if independently_projected_payload is not None and independently_projected_payload != expected_payload:
                    record_issue(
                        record_index,
                        "effective_payload_projection_aggregate_mismatch",
                        "Independent aggregation of Step 19 payload projections does not match the validated packet payload.",
                        packet_id=packet_id,
                        independently_projected_length_bytes=len(independently_projected_payload),
                        expected_length_bytes=len(expected_payload),
                    )
                if independently_projected_payload == reference_payload:
                    # Multiple individually effective canonical decisions can
                    # compose back to the original physical payload. The
                    # aggregate Step 19 packet remains authoritative.
                    projected_packet_aggregate_no_effect_count += 1
                if output_payload != expected_payload:
                    reason = (
                        "effective_payload_projection_length_mismatch"
                        if len(output_payload) != len(expected_payload)
                        else "effective_payload_projection_content_mismatch"
                    )
                    record_issue(
                        record_index,
                        reason,
                        "Serialized payload does not match the Step 19 validated payload for an effective projection packet.",
                        packet_id=packet_id,
                        expected_length_bytes=len(expected_payload),
                        realized_length_bytes=len(output_payload),
                    )
            elif expected_payload_changed:
                record_issue(
                    record_index,
                    "payload_changed_without_effective_projection",
                    "Step 19 validated packet payload differs from Step 13, but no effective payload projection authorizes that packet.",
                    packet_id=packet_id,
                )
            if descriptor is not None:
                connection = reference_context["connections"][descriptor["connection_id"]]
                source = descriptor["source_endpoint"]
                anchor = connection["anchors"][source]
                original_start = tcp_relative_number(descriptor["sequence_number"], anchor) + (1 if descriptor["flags"] & 0x02 else 0)
                output_start = tcp_relative_number(int(output_tcp.seq), anchor) + (1 if int(output_tcp.flags) & 0x02 else 0)
                direction_key = (descriptor["connection_id"], source)
                if descriptor["payload"]:
                    original_segments[direction_key].append({"packet_id": packet_id, "start": original_start, "end": original_start + len(descriptor["payload"]), "payload": descriptor["payload"]})
                if output_payload:
                    reconstructed_segments[direction_key].append({"packet_id": packet_id, "start": output_start, "end": output_start + len(output_payload), "payload": output_payload})

        if next(reader, None) is not None:
            record_issue(len(traffic) + 1, "unexpected_extra_output_packets", "Reconstructed PCAP contains more packets than Step 19 traffic.")

    if output_packet_count != len(traffic):
        record_issue(output_packet_count + 1, "output_packet_count_mismatch", "Reconstructed PCAP packet count differs from Step 19 traffic.", expected=len(traffic), actual=output_packet_count)
    if projected_packet_comparison_count != len(projected_packet_ids):
        record_issue(
            0,
            "effective_payload_projection_packet_count_mismatch",
            "Not every packet with an effective Step 19 payload projection was compared in the reconstructed PCAP audit.",
            expected=len(projected_packet_ids),
            actual=projected_packet_comparison_count,
        )
    projected_net_payload_delta = int(payload_projection_contract.get("net_payload_delta_bytes", 0))
    if realized_projected_net_payload_delta_bytes != projected_net_payload_delta:
        record_issue(
            0,
            "effective_payload_projection_net_delta_mismatch",
            "The realized payload-length delta in the reconstructed PCAP does not match Step 19 effective projection evidence.",
            expected=projected_net_payload_delta,
            actual=realized_projected_net_payload_delta_bytes,
        )

    original_conflicts = tcp_overlap_conflicts(original_segments)
    reconstructed_conflicts = tcp_overlap_conflicts(reconstructed_segments)
    introduced_conflicts = reconstructed_conflicts - original_conflicts
    for first_packet_id, second_packet_id in sorted(introduced_conflicts):
        record_issue(0, "new_tcp_reassembly_overlap_conflict", "POST reconstruction introduced overlapping TCP bytes with inconsistent content.", packet_ids=[first_packet_id, second_packet_id])

    validation_error_count = sum(issue_counts.values())
    connection_state_inventory = tcp_connection_state_inventory(traffic, reference_context)
    strategy_preservation_error_count = (
        issue_counts["ipv4_immutable_field_changed"]
        + issue_counts["tcp_immutable_field_changed"]
        + issue_counts["tcp_options_changed_unexpectedly"]
    )
    payload_projection_mismatch_reasons = {
        "effective_payload_projection_aggregate_mismatch",
        "effective_payload_projection_content_mismatch",
        "effective_payload_projection_evidence_invalid",
        "effective_payload_projection_length_mismatch",
        "effective_payload_projection_packet_count_mismatch",
        "effective_payload_projection_net_delta_mismatch",
        "payload_changed_without_effective_projection",
    }
    payload_projection_mismatch_count = sum(issue_counts[reason] for reason in payload_projection_mismatch_reasons)
    return {
        "status": "valid" if validation_error_count == 0 else "invalid",
        "contract": {
            "scope": ["Ethernet II", "IPv4", "TCP"],
            "dataset_observed_stack": "Ethernet II -> IPv4 -> TCP",
            "out_of_scope_absent_protocols": ["802.1Q VLAN", "ARP", "IPv6", "UDP", "ICMP"],
            "ipv4_options_expected": False,
            "ipv4_fragmentation_expected": False,
            "tcp_urg_expected": False,
            "application_protocol_validation": "Not performed in Step 20; reserved for Step 20B.",
            "modification_strategy": capabilities.as_metadata(),
            "pipeline_controlled_reconstruction_fields": [
                "ipv4.total_length",
                "ipv4.header_checksum",
                "tcp.checksum",
                "tcp.sequence_number",
                "tcp.acknowledgement_number",
                "tcp.sack_boundaries",
                "ethernet.minimum_frame_padding",
            ],
        },
        "summary": {
            "validated_frame_count": output_packet_count,
            "network_protocol_validation_error_count": validation_error_count,
            "independently_validated_ipv4_checksum_count": output_packet_count - issue_counts["ipv4_checksum_invalid"],
            "independently_validated_tcp_checksum_count": output_packet_count - issue_counts["tcp_checksum_invalid"],
            "payload_projection_mismatch_count": payload_projection_mismatch_count,
            "payload_projection_validated_change_count": int(payload_projection_contract.get("projection_change_count", 0)),
            "payload_projection_validated_packet_count": len(projected_packet_ids),
            "payload_projection_compared_packet_count": projected_packet_comparison_count,
            "payload_projection_aggregate_no_effect_packet_count": projected_packet_aggregate_no_effect_count,
            "projected_net_payload_delta_bytes": projected_net_payload_delta,
            "realized_net_payload_delta_bytes": realized_projected_net_payload_delta_bytes,
            "payload_changed_without_effective_projection_count": issue_counts["payload_changed_without_effective_projection"],
            "tcp_seq_ack_consistency_error_count": issue_counts["tcp_sequence_translation_mismatch"] + issue_counts["tcp_ack_translation_mismatch"],
            "tcp_retransmission_consistency_error_count": issue_counts["new_tcp_reassembly_overlap_conflict"],
            "strategy_specific_preservation_error_count": strategy_preservation_error_count,
            "preexisting_tcp_reassembly_overlap_conflict_count": len(original_conflicts),
            "post_tcp_reassembly_overlap_conflict_count": len(reconstructed_conflicts),
            "introduced_tcp_reassembly_overlap_conflict_count": len(introduced_conflicts),
            "issue_counts_by_reason": dict(sorted(issue_counts.items())),
        },
        "observed_inventory": {
            **dict(sorted(observed.items())),
            "tcp_option_kind_counts": {str(key): value for key, value in sorted(tcp_option_kind_counts.items())},
        },
        "tcp_connection_state_validation": connection_state_inventory,
        "issues_by_record_index": {
            str(record_index): issues
            for record_index, issues in sorted(issues_by_record_index.items())
            if issues
        },
    }


#This function aggregates packet-level reconstruction results into group-level results.
#This function keeps the same group validity principle used in Step 19: if any packet in a group fails, the group is marked as Invalid Traffic.
#This function does not copy full packet issue objects into the group result because those details already live in packet_results.
def summarize_groups(packet_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for result in packet_results:
        key = result["group_key"]
        if key not in groups:
            groups[key] = {
                "group_key": key,
                "condition": result.get("condition"),
                "model_name": result.get("model_name"),
                "group_id": result.get("group_id"),
                "packet_ids": [],
                "record_indexes": [],
                "reconstructed_packet_count": 0,
                "failed_packet_count": 0,
                "issue_counts_by_reason": defaultdict(int),
                "warning_count": 0,
                "error_count": 0,
            }
        group = groups[key]
        group["record_indexes"].append(result["record_index"])
        if result.get("packet_id") is not None:
            group["packet_ids"].append(result["packet_id"])
        if result["status"] == "reconstructed":
            group["reconstructed_packet_count"] += 1
        else:
            group["failed_packet_count"] += 1
        for item in result["issues"]:
            group["issue_counts_by_reason"][item["reason"]] += 1
            if item["severity"] == "warning":
                group["warning_count"] += 1
            elif item["severity"] == "error":
                group["error_count"] += 1

    group_results = []
    for group in groups.values():
        failed = group["failed_packet_count"] > 0
        issue_counts_by_reason = dict(sorted(group.pop("issue_counts_by_reason").items()))
        group_results.append(
            {
                **group,
                "status": "Invalid Traffic" if failed else "Reconstructed Traffic",
                "invalid_traffic": failed,
                "packet_count": len(group["record_indexes"]),
                "issue_counts_by_reason": issue_counts_by_reason,
            }
        )
    return sorted(group_results, key=lambda item: item["group_key"])


#This function runs the core Step 20 reconstruction logic.
#This function reads Step 19 validated traffic, reconstructs accepted POST packets, writes the PCAP, and writes a detailed reconstruction report.
def reconstruct_validated_traffic(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    reference_pcap_path: Path,
    output_pcap_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    if not input_json_path.exists():
        raise FileNotFoundError(f"Step 19 validated traffic JSON does not exist: {input_json_path}")

    capabilities = resolve_modification_strategy(config)
    validation_policy = resolve_post_llm_traffic_validation_policy(config)
    validated_json = read_json(input_json_path)
    metadata, traffic, source_validation_contract = validate_step19_v5_input(
        validated_json,
        input_json_path,
        capabilities,
        validation_policy,
    )
    public_source_validation_contract = {
        key: value
        for key, value in source_validation_contract.items()
        if not key.startswith("_")
    }

    required_indices = set()
    for record in traffic:
        if not isinstance(record, dict):
            raise ValueError("Every Step 19 traffic entry must be an object before Step 20 reconstruction.")
        reduced_packet_index = record.get("reduced_packet_index")
        if not is_int_like(reduced_packet_index) or reduced_packet_index < 1:
            raise ValueError(
                f"Record {record.get('packet_id')} has invalid reduced_packet_index={reduced_packet_index!r}."
            )
        required_indices.add(reduced_packet_index)

    #This function imports Scapy after the JSON contract is checked so path/schema errors appear before dependency errors.
    scapy = import_scapy()
    header_policy = load_header_editability_policy(config, config.get("_config_path", ""))
    try:
        reference_context = load_reference_pcap_context(
            reference_pcap_path=reference_pcap_path,
            required_indices=required_indices,
            scapy=scapy,
        )
        translation_plan = prepare_tcp_sequence_translation(
            traffic=traffic,
            reference_context=reference_context,
            payload_projection_contract=source_validation_contract,
        )
        enforce_active_reconstruction_contract(capabilities, translation_plan)
    except Exception as error:
        error_detail = (
            error.detail
            if isinstance(error, TcpReconstructionError)
            else {
                "reason": "tcp_reconstruction_planning_failed",
                "message": str(error),
                "failure_type": type(error).__name__,
            }
        )
        reason = error_detail["reason"]
        unresolved_ack_count = int(
            reason.startswith("ack_reference_") or reason.startswith("sack_reference_")
        )
        unresolved_sequence_count = int(reason.startswith("sequence_reference_"))
        ambiguous_count = int(
            reason
            in {
                "ack_reference_inside_resized_segment",
                "sack_reference_inside_resized_segment",
                "sequence_reference_inside_resized_segment",
                "inconsistent_modified_retransmission",
                "resized_overlapping_tcp_segments",
                "inconsistent_modified_tcp_overlap",
                "zero_length_tcp_insertion",
            }
        )
        failure_summary = {
            "input_packet_count": len(traffic),
            "reconstructed_packet_count": 0,
            "failed_packet_count": len(traffic),
            "group_count": 0,
            "reconstructed_group_count": 0,
            "invalid_traffic_group_count": 0,
            "warning_count": 0,
            "error_count": 1,
            "issue_counts_by_reason": {reason: 1},
            "unresolved_tcp_sequence_reference_count": unresolved_sequence_count,
            "unresolved_tcp_ack_reference_count": unresolved_ack_count,
            "ambiguous_tcp_translation_count": ambiguous_count,
            "tcp_reconstruction_error_count": 1,
        }
        tcp_failure_summary = {
            "adjusted_tcp_sequence_packet_count": 0,
            "adjusted_tcp_acknowledgement_packet_count": 0,
            "preserved_tcp_retransmission_count": 0,
            "preserved_modified_tcp_retransmission_count": 0,
            "preserved_tcp_overlapping_segment_pair_count": 0,
            "unresolved_tcp_sequence_reference_count": unresolved_sequence_count,
            "unresolved_tcp_ack_reference_count": unresolved_ack_count,
            "ambiguous_tcp_translation_count": ambiguous_count,
            "tcp_reconstruction_error_count": 1,
        }
        write_json(
            report_path,
            {
                "metadata": {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "failed_during_tcp_reconstruction_planning",
                    "experiment_id": config["experiment"]["experiment_id"],
                    "config_source": config.get("_config_path", ""),
                    "input_json": str(input_json_path),
                    "reference_pcap": str(reference_pcap_path),
                    "output_pcap": str(output_pcap_path),
                    "source_validation_schema_version": metadata.get("schema_version"),
                    "modification_strategy": capabilities.as_metadata(),
                },
                "source_validation_contract": public_source_validation_contract,
                "summary": failure_summary,
                "tcp_reconstruction_summary": tcp_failure_summary,
                "tcp_direction_results": [],
                "tcp_reconstruction_errors": [error_detail],
                "group_results": [],
                "packet_results": [],
            },
        )
        if validation_policy.step20_reconstruction_error_action == "fail_run":
            raise
        raise AssertionError(
            "Unsupported Step 20 reconstruction error action reached execution."
        )
    packets = []
    packet_results = []
    for record_index, record in enumerate(traffic, start=1):
        reduced_packet_index = record["reduced_packet_index"]
        prepared = translation_plan["prepared_by_index"][reduced_packet_index]
        reconstruction = reconstruct_one_packet(
            record,
            record_index,
            scapy,
            reference_context["packets_by_index"][reduced_packet_index],
            prepared["tcp_translation"],
            header_policy,
            capabilities,
        )
        packet_results.append(reconstruction["result"])
        if reconstruction["packet"] is not None:
            packets.append(reconstruction["packet"])

    write_packets(output_pcap_path, packets, scapy)
    if len(packets) == len(traffic):
        network_protocol_validation = audit_reconstructed_pcap(
            output_pcap_path=output_pcap_path,
            traffic=traffic,
            reference_context=reference_context,
            translation_plan=translation_plan,
            payload_projection_contract=source_validation_contract,
            header_policy=header_policy,
            capabilities=capabilities,
            scapy=scapy,
        )
        for record_index_text, validation_issues in network_protocol_validation[
            "issues_by_record_index"
        ].items():
            record_index = int(record_index_text)
            if 1 <= record_index <= len(packet_results):
                result = packet_results[record_index - 1]
                result["issues"].extend(validation_issues)
                result["status"] = "failed"
                result["evaluation_status"] = "Invalid Traffic"
    else:
        network_protocol_validation = {
            "status": "not_run",
            "contract": {},
            "summary": {
                "validated_frame_count": 0,
                "network_protocol_validation_error_count": 1,
                "issue_counts_by_reason": {
                    "pre_audit_reconstruction_failure": 1,
                },
            },
            "observed_inventory": {},
            "issues_by_record_index": {},
        }
    group_results = summarize_groups(packet_results)
    issue_counts_by_reason: dict[str, int] = defaultdict(int)
    severity_counts: Counter[str] = Counter()
    for result in packet_results:
        for item in result["issues"]:
            issue_counts_by_reason[item["reason"]] += 1
            severity_counts[item["severity"]] += 1

    tcp_packet_reconstruction_error_count = sum(
        1
        for result in packet_results
        for item in result["issues"]
        if item["severity"] == "error"
        and (
            item["reason"].startswith("tcp_")
            or item["reason"].startswith("reference_tcp_")
        )
    )
    translation_plan["summary"]["tcp_reconstruction_error_count"] += (
        tcp_packet_reconstruction_error_count
    )
    network_protocol_validation_error_count = network_protocol_validation["summary"][
        "network_protocol_validation_error_count"
    ]

    now = datetime.now(timezone.utc).isoformat()
    #This function stores both the policy and the packet results so later alert comparison can distinguish real evasion from reconstruction problems.
    report = {
        "metadata": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at_utc": now,
            "status": (
                "completed"
                if network_protocol_validation_error_count == 0
                and translation_plan["summary"]["tcp_reconstruction_error_count"] == 0
                else "failed_protocol_validation"
            ),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "input_json": str(input_json_path),
            "reference_pcap": str(reference_pcap_path),
            "source_validation_schema_version": metadata.get("schema_version"),
            "modification_strategy": capabilities.as_metadata(),
            "output_pcap": str(output_pcap_path),
            "reconstruction_policy": {
                "source_of_reconstructible_post_traffic": "Step 19 validated_modified_traffic.json",
                "immutable_header_source": "Use each reduced_packet_index to copy the corresponding Step 13 selected PCAP frame.",
                "llm_output_failure_groups_reconstructed": False,
                "invalid_traffic_groups_reconstructed": False,
                "header_edit_materialization_enabled": capabilities.allows_header_edits,
                "payload_edit_materialization_enabled": capabilities.allows_payload_edits,
                "payload_preservation_required": capabilities.requires_payload_preservation,
                "timestamp_policy": "preserve timestamp_epoch_pcap when numeric",
                "checksum_policy": "Scapy recalculates checksums from rebuilt layers; Step 20 then independently verifies serialized IPv4 and TCP checksums.",
                "length_policy": "Replace the transport payload in the Step 13 frame template, then let Scapy recalculate affected lengths.",
                "ethernet_padding_policy": "After IP/TCP serialization, append zero bytes outside the IP length until Ethernet frames reach the 60-byte minimum without FCS.",
                "automatic_repair_policy": "Do not silently repair; report omitted fields, recalculated lengths, and packet failures.",
                "tcp_options_policy": "Preserve TCP options directly from the Step 13 frame template.",
                "tcp_sequence_policy": "Translate original sequence numbers by cumulative prior payload-length deltas in the same connection direction.",
                "tcp_acknowledgement_policy": "Translate original acknowledgement numbers by cumulative payload-length deltas in the opposite connection direction.",
                "tcp_retransmission_policy": "Count identical original sequence ranges once and reject modified overlapping or retransmitted ranges that cannot form one coherent byte stream.",
                "tcp_wraparound_policy": "Perform sequence-space arithmetic modulo 2^32.",
            },
        },
        "summary": {
            "input_packet_count": len(traffic),
            "written_packet_count": len(packets),
            "reconstructed_packet_count": sum(
                1 for result in packet_results if result["status"] == "reconstructed"
            ),
            "failed_packet_count": sum(
                1 for result in packet_results if result["status"] == "failed"
            ),
            "group_count": len(group_results),
            "reconstructed_group_count": sum(1 for group in group_results if not group["invalid_traffic"]),
            "invalid_traffic_group_count": sum(1 for group in group_results if group["invalid_traffic"]),
            "warning_count": severity_counts.get("warning", 0),
            "error_count": severity_counts.get("error", 0),
            "issue_counts_by_reason": dict(sorted(issue_counts_by_reason.items())),
            "network_protocol_validation_error_count": network_protocol_validation_error_count,
            **translation_plan["summary"],
        },
        "source_validation_metadata": metadata,
        "source_validation_contract": public_source_validation_contract,
        "tcp_reconstruction_summary": translation_plan["summary"],
        "tcp_direction_results": translation_plan["direction_results"],
        "tcp_reconstruction_errors": [],
        "network_protocol_validation": network_protocol_validation,
        "group_results": group_results,
        "packet_results": packet_results,
    }
    write_json(report_path, report)
    if network_protocol_validation_error_count or translation_plan["summary"]["tcp_reconstruction_error_count"]:
        if validation_policy.step20_protocol_audit_error_action == "fail_run":
            raise RuntimeError(
                "Step 20 wrote its diagnostic report but the reconstructed PCAP failed network/transport protocol validation."
            )
        raise AssertionError(
            "Unsupported Step 20 protocol audit error action reached execution."
        )
    return {
        "input_json": str(input_json_path),
        "reference_pcap": str(reference_pcap_path),
        "output_pcap": str(output_pcap_path),
        "reconstruction_report": str(report_path),
        **report["summary"],
    }


#This function is the public Python entry point for Step 20.
#This function loads the config, resolves the active experiment paths, and delegates the actual reconstruction work.
def run_reconstruction(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    reference_pcap: str | Path | None,
    output_dir: str | Path | None,
    output_pcap: str | Path | None,
    experiment_root: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    paths = default_paths(config, experiment_root)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    reference_pcap_path = Path(reference_pcap).expanduser() if reference_pcap else paths["reference_pcap"]
    reconstruction_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    output_pcap_path = Path(output_pcap).expanduser() if output_pcap else reconstruction_output_dir / "modified_traffic.pcap"
    report_path = reconstruction_output_dir / "reconstruction_report.json"
    return reconstruct_validated_traffic(
        config=config,
        input_json_path=input_json_path,
        reference_pcap_path=reference_pcap_path,
        output_pcap_path=output_pcap_path,
        report_path=report_path,
    )


#This function resolves the terminal log path for Step 20.
#This function writes default logs under the active experiment root so Ubuntu runs keep terminal evidence next to artifacts.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()

    config = load_json_config(args.config)
    validate_config(config)
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_20_json_to_pcap",
        filename_prefix="step_20_json_to_pcap",
    )


#This function parses command-line arguments for Step 20.
#This function exposes --experiment-root because the active VM artifact folder may differ from experiment.output_root in the config.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconstruct Step 20 modified PCAP from Step 19 validated JSON.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input", dest="input_json", help="Path to Step 19 validated_modified_traffic.json.")
    add(
        "--reference-pcap",
        help="Path to the Step 13 selected_malicious_traffic.pcap used as the immutable frame and TCP sequence reference.",
    )
    add("--output-dir", help="Directory where Step 20 outputs will be written.")
    add("--output-pcap", help="Optional explicit path for modified_traffic.pcap.")
    add("--log-file", help="Optional explicit terminal log file path.")
    add(
        "--experiment-root",
        help=(
            "Optional experiment root override. Useful when the VM artifact root differs from "
            "experiment.output_root in the config."
        ),
    )
    return parser.parse_args()


#This function is the command-line entry point. It prints the reconstruction summary and output paths.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 20 terminal log"):
        try:
            result = run_reconstruction(
                config_path=args.config,
                input_json=args.input_json,
                reference_pcap=args.reference_pcap,
                output_dir=args.output_dir,
                output_pcap=args.output_pcap,
                experiment_root=args.experiment_root,
            )
        except Exception:
            print("Step 20 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Input packets: {result['input_packet_count']}")
        print(f"Reconstructed packets: {result['reconstructed_packet_count']}")
        print(f"Failed packets: {result['failed_packet_count']}")
        print(f"Reconstructed groups: {result['reconstructed_group_count']}")
        print(f"Invalid traffic groups: {result['invalid_traffic_group_count']}")
        print(f"Warnings: {result['warning_count']}")
        print(f"Errors: {result['error_count']}")
        print(f"TCP connections: {result['tcp_connection_count']}")
        print(f"TCP connections with payload length delta: {result['tcp_connections_with_payload_length_delta']}")
        print(f"Adjusted TCP sequence numbers: {result['adjusted_tcp_sequence_packet_count']}")
        print(f"Adjusted TCP acknowledgement numbers: {result['adjusted_tcp_acknowledgement_packet_count']}")
        print(f"Preserved TCP retransmissions: {result['preserved_tcp_retransmission_count']}")
        print(f"Unresolved TCP sequence references: {result['unresolved_tcp_sequence_reference_count']}")
        print(f"Unresolved TCP ACK references: {result['unresolved_tcp_ack_reference_count']}")
        print(f"Ambiguous TCP translations: {result['ambiguous_tcp_translation_count']}")
        print(f"TCP reconstruction errors: {result['tcp_reconstruction_error_count']}")
        print(f"Network protocol validation errors: {result['network_protocol_validation_error_count']}")
        print(f"Input JSON: {result['input_json']}")
        print(f"Reference PCAP: {result['reference_pcap']}")
        print(f"Modified PCAP: {result['output_pcap']}")
        print(f"Reconstruction report: {result['reconstruction_report']}")


if __name__ == "__main__":
    main()

