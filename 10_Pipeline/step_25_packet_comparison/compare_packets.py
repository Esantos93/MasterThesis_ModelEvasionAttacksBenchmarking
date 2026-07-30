from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import traceback
import uuid
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from decimal import Decimal
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable

# This allows direct execution while preserving the pipeline package imports.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.header_policy import HEADER_FIELD_ALIASES
from common.io_utils import write_json
from common.terminal_logging import default_step_log_path, terminal_log
from step_14_pcap_to_json.packet_headers_extraction import extract_physical_packet_facts
from step_25_packet_comparison.json_stream import (
    consume_selected_object_members,
    iter_json_array_at_path,
    load_json_value_at_path,
)


MANIFEST_SCHEMA_VERSION = "packet_comparisons_manifest_v1"
COMPARISON_SCHEMA_VERSION = "packet_comparison_v1"
STEP14_SCHEMA_VERSION = "packet_json_v4"
STEP18_SCHEMA_VERSION = "patch_applied_traffic_v5"
STEP18_PATCH_SCHEMA_VERSION = "patch_application_report_v5"
STEP19_SCHEMA_VERSION = "merged_traffic_validation_report_v5"
STEP20_SCHEMA_VERSION = "pcap_reconstruction_report_v6"
PACKET_CORRESPONDENCE_POLICY = "same_order_and_packet_count_v1"
CHANGE_ORIGINS = {
    "llm_explicit",
    "pipeline_derived",
    "protocol_recomputed",
}
MODIFICATION_SCOPES = {
    frozenset({"llm_explicit"}): "llm",
    frozenset({"pipeline_derived"}): "pipeline",
    frozenset({"protocol_recomputed"}): "protocol",
    frozenset({"llm_explicit", "pipeline_derived"}): "llm_pipeline",
    frozenset({"llm_explicit", "protocol_recomputed"}): "llm_protocol",
    frozenset({"pipeline_derived", "protocol_recomputed"}): "pipeline_protocol",
    frozenset(
        {"llm_explicit", "pipeline_derived", "protocol_recomputed"}
    ): "llm_pipeline_protocol",
}
PROTOCOL_RECOMPUTED_FIELDS = {
    "packet.length_bytes",
    "ethernet.padding_hex",
    "ethernet.padding_length_bytes",
    "ipv4.total_length",
    "ipv4.checksum",
    "tcp.checksum",
}
PIPELINE_TRANSLATED_FIELDS = {
    "tcp.sequence_number",
    "tcp.acknowledgement_number",
    "tcp.options_raw_hex",
}
RECORD_ALIAS_TO_LOGICAL_FIELD = {
    f"record.{alias}": logical_field
    for logical_field, alias in HEADER_FIELD_ALIASES.items()
}
MISSING = object()


# This function returns a UTC timestamp for artifact metadata.
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# This function computes SHA-256 over the exact bytes of one source artifact.
def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# This function computes SHA-256 over one complete captured packet frame.
def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


# This function imports Scapy only when PCAP comparison starts.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import RawPcapReader
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for Step 25 packet comparison. Install it in the "
            "benchmark environment before running this step."
        ) from exc
    return {"RawPcapReader": RawPcapReader}


# This function builds the configured experiment root.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function validates the minimum configuration contract owned by Step 25.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")
    label = config["pipeline"]["experiment_config_label"]
    if not isinstance(label, str) or not label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")


# This function resolves Step 25's canonical upstream and output paths.
def default_paths(
    config: dict[str, Any],
    experiment_root_override: str | Path | None = None,
) -> dict[str, Path]:
    experiment_root = (
        Path(experiment_root_override).expanduser()
        if experiment_root_override
        else build_experiment_root(config)
    )
    label = config["pipeline"]["experiment_config_label"]
    return {
        "experiment_root": experiment_root,
        "reference_json": experiment_root
        / "04_packet_json"
        / "selected_packet_records.json",
        "pre_pcap": experiment_root
        / "03_selected_traffic"
        / "selected_malicious_traffic.pcap",
        "step18_merged": experiment_root
        / "08_merged_outputs"
        / label
        / "merged_modified_traffic.json",
        "step19_report": experiment_root
        / "09_validation"
        / label
        / "validation_report.json",
        "step20_report": experiment_root
        / "10_reconstructed_pcap"
        / label
        / "reconstruction_report.json",
        "post_pcap": experiment_root
        / "10_reconstructed_pcap"
        / label
        / "modified_traffic.pcap",
        "output_dir": experiment_root / "15_packet_comparisons",
    }


# This function requires an upstream artifact to exist as a regular file.
def require_file(path: Path, description: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{description} does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"{description} must be a regular file: {path}")


# This function checks one exact metadata schema version.
def require_schema(
    metadata: Any,
    *,
    expected: str,
    description: str,
) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise ValueError(f"{description} metadata must be a JSON object.")
    actual = metadata.get("schema_version")
    if actual != expected:
        raise ValueError(
            f"{description} schema mismatch: expected {expected!r}, found {actual!r}."
        )
    return metadata


# This function verifies that one artifact belongs to the active experiment branch.
def validate_artifact_identity(
    metadata: dict[str, Any],
    *,
    experiment_id: str,
    experiment_config_label: str | None,
    description: str,
) -> None:
    if metadata.get("experiment_id") != experiment_id:
        raise ValueError(
            f"{description} experiment_id mismatch: "
            f"{metadata.get('experiment_id')!r} != {experiment_id!r}."
        )
    if (
        experiment_config_label is not None
        and metadata.get("experiment_config_label") != experiment_config_label
    ):
        raise ValueError(
            f"{description} experiment_config_label mismatch: "
            f"{metadata.get('experiment_config_label')!r} != "
            f"{experiment_config_label!r}."
        )


# This function converts a JSON value to a positive 1-based packet number.
def positive_packet_number(value: Any, field_name: str, packet_id: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(
            f"Step 14 packet {packet_id!r} has invalid {field_name}={value!r}; "
            "Step 25 requires explicit 1-based packet identity."
        )
    return value


# This function builds a complete deterministic packet structure from captured bytes.
def structured_packet(frame: bytes) -> dict[str, Any]:
    facts = extract_physical_packet_facts(frame)
    return {
        "packet_length_bytes": len(frame),
        "ethernet_header": facts["ethernet_header"],
        "ipv4_header": facts["ipv4_header"],
        "tcp_header": facts["tcp_header"],
        "payload_hex": facts["payload_hex"],
        "payload_length_bytes": facts["payload_length_bytes"],
        "captured_frame_bytes_accounted_for": facts[
            "captured_frame_bytes_accounted_for"
        ],
    }


# This function returns physical and derived values used for field-level comparison.
def comparable_field_values(packet: dict[str, Any]) -> dict[str, Any]:
    ipv4 = packet["ipv4_header"]
    tcp = packet["tcp_header"]
    ethernet = packet["ethernet_header"]
    ipv4_flags = ipv4["flags"]
    tcp_flags = tcp["flags"]
    flags_fragment_offset = (
        (int(bool(ipv4_flags["reserved"])) << 15)
        | (int(bool(ipv4_flags["dont_fragment"])) << 14)
        | (int(bool(ipv4_flags["more_fragments"])) << 13)
        | int(ipv4["fragment_offset_units"])
    )
    values = {
        "packet.length_bytes": packet["packet_length_bytes"],
        "ethernet.destination_mac": ethernet["destination_mac"],
        "ethernet.source_mac": ethernet["source_mac"],
        "ethernet.outer_ether_type": ethernet["outer_ether_type"],
        "ethernet.ether_type": ethernet["ether_type"],
        "ethernet.vlan_tags": ethernet["vlan_tags"],
        "ethernet.padding_hex": ethernet["padding_hex"],
        "ethernet.padding_length_bytes": ethernet["padding_length_bytes"],
        "ipv4.version": ipv4["version"],
        "ipv4.ihl_words": ipv4["ihl_words"],
        "ipv4.tos": ipv4["tos"],
        "ipv4.dscp": ipv4["dscp"],
        "ipv4.ecn": ipv4["ecn"],
        "ipv4.total_length": ipv4["total_length"],
        "ipv4.identification": ipv4["identification"],
        "ipv4.flags_fragment_offset": flags_fragment_offset,
        "ipv4.flags.raw": ipv4_flags["raw"],
        "ipv4.flags.reserved": ipv4_flags["reserved"],
        "ipv4.flags.dont_fragment": ipv4_flags["dont_fragment"],
        "ipv4.flags.more_fragments": ipv4_flags["more_fragments"],
        "ipv4.fragment_offset_units": ipv4["fragment_offset_units"],
        "ipv4.fragment_offset_bytes": ipv4["fragment_offset_bytes"],
        "ipv4.fragmented": ipv4["fragmented"],
        "ipv4.ttl": ipv4["ttl"],
        "ipv4.protocol": ipv4["protocol"],
        "ipv4.checksum": ipv4["checksum"],
        "ipv4.source_address": ipv4["source_address"],
        "ipv4.destination_address": ipv4["destination_address"],
        "ipv4.options_raw_hex": ipv4["options_raw_hex"],
        "tcp.source_port": tcp["source_port"],
        "tcp.destination_port": tcp["destination_port"],
        "tcp.sequence_number": tcp["sequence_number"],
        "tcp.acknowledgement_number": tcp["acknowledgement_number"],
        "tcp.data_offset_words": tcp["data_offset_words"],
        "tcp.reserved_bits": tcp["reserved_bits"],
        "tcp.flags.raw": tcp_flags["raw"],
        **{
            f"tcp.flags.{flag_name}": tcp_flags[flag_name]
            for flag_name in [
                "ns",
                "cwr",
                "ece",
                "urg",
                "ack",
                "psh",
                "rst",
                "syn",
                "fin",
            ]
        },
        "tcp.window": tcp["window"],
        "tcp.checksum": tcp["checksum"],
        "tcp.urgent_pointer": tcp["urgent_pointer"],
        "tcp.options_raw_hex": tcp["options_raw_hex"],
    }
    return values


# This function returns the immutable tuple that proves PRE/POST frame order.
def immutable_packet_identity(packet: dict[str, Any]) -> tuple[Any, ...]:
    ethernet = packet["ethernet_header"]
    ipv4 = packet["ipv4_header"]
    tcp = packet["tcp_header"]
    return (
        ethernet["destination_mac"],
        ethernet["source_mac"],
        ethernet["outer_ether_type"],
        ethernet["ether_type"],
        tuple(tag["raw_hex"] for tag in ethernet["vlan_tags"]),
        ipv4["version"],
        ipv4["ihl_words"],
        ipv4["protocol"],
        ipv4["source_address"],
        ipv4["destination_address"],
        tcp["source_port"],
        tcp["destination_port"],
        tcp["data_offset_words"],
    )


# This function verifies that the Step 13 PRE frame is the frame represented by Step 14.
def validate_pre_against_step14(
    reference_record: dict[str, Any],
    pre_packet: dict[str, Any],
    packet_index: int,
) -> None:
    for field in [
        "ethernet_header",
        "ipv4_header",
        "tcp_header",
        "payload_hex",
        "payload_length_bytes",
        "packet_length_bytes",
        "captured_frame_bytes_accounted_for",
    ]:
        if reference_record.get(field) != pre_packet.get(field):
            raise ValueError(
                f"PRE PCAP frame {packet_index} does not match Step 14 field {field!r} "
                f"for packet_id={reference_record.get('packet_id')!r}."
            )


# This function compares one PCAP timestamp with Step 14's explicit timestamp.
def validate_packet_timestamp(
    packet_metadata: Any,
    reference_timestamp: Any,
    *,
    packet_id: str,
    traffic_version: str,
) -> None:
    if isinstance(reference_timestamp, bool) or not isinstance(
        reference_timestamp, (int, float)
    ):
        raise ValueError(
            f"Step 14 packet {packet_id!r} has a non-numeric timestamp_epoch_pcap."
        )
    if hasattr(packet_metadata, "sec") and hasattr(packet_metadata, "usec"):
        packet_timestamp = Decimal(int(packet_metadata.sec)) + (
            Decimal(int(packet_metadata.usec)) / Decimal(1_000_000)
        )
    else:
        raise ValueError(
            f"{traffic_version} PCAP metadata for packet_id={packet_id!r} "
            "does not expose a classic-PCAP sec/usec timestamp."
        )
    expected = Decimal(str(reference_timestamp))
    if abs(packet_timestamp - expected) > Decimal("0.000001"):
        raise ValueError(
            f"{traffic_version} PCAP timestamp mismatch for packet_id={packet_id!r}: "
            f"{packet_timestamp} != {expected}."
        )


# This function normalizes common Step 18 record aliases to logical header names.
def normalize_logical_field(field: Any) -> str:
    text = str(field)
    return RECORD_ALIAS_TO_LOGICAL_FIELD.get(text, text)


# This function returns the final provenance record for duplicate field decisions.
def final_record(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return max(
        records,
        key=lambda item: (
            int(item.get("materialization_sequence_index", 0) or 0),
            int(item.get("patch_index", 0) or 0),
            str(item.get("prompt_unit_id", "")),
        ),
    )


# This function derives one compact packet-level scope from individual change origins.
def derive_modification_scope(changes: list[dict[str, Any]]) -> str:
    origins = frozenset(str(change.get("change_origin")) for change in changes)
    if not origins or not origins.issubset(CHANGE_ORIGINS):
        raise ValueError(f"Unsupported or empty Step 25 change-origin set: {sorted(origins)}")
    scope = MODIFICATION_SCOPES.get(origins)
    if scope is None:
        raise ValueError(f"Unsupported Step 25 modification-scope combination: {sorted(origins)}")
    return scope


# This function assigns stable change ids after deterministic sorting.
def finalize_changed_fields(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    origin_order = {
        "llm_explicit": 0,
        "pipeline_derived": 1,
        "protocol_recomputed": 2,
    }
    ordered = sorted(
        changes,
        key=lambda item: (
            origin_order[item["change_origin"]],
            str(item.get("target_type", "")),
            str(item.get("field_name", "")),
            str(item.get("canonical_region_id", "")),
            int(item.get("range_start_bytes", -1)),
            str(item.get("prompt_unit_id", "")),
            int(item.get("patch_index", 0) or 0),
        ),
    )
    return [
        {"change_id": f"change_{index:04d}", **change}
        for index, change in enumerate(ordered, start=1)
    ]


# This function loads the bounded indexes required to attribute physical changes.
def load_traceability_indexes(
    *,
    step18_merged: Path,
    step19_report: Path,
    step20_report: Path,
    experiment_id: str,
    experiment_config_label: str,
) -> dict[str, Any]:
    step18_metadata = require_schema(
        load_json_value_at_path(step18_merged, ("metadata",)),
        expected=STEP18_SCHEMA_VERSION,
        description="Step 18 merged traffic",
    )
    validate_artifact_identity(
        step18_metadata,
        experiment_id=experiment_id,
        experiment_config_label=experiment_config_label,
        description="Step 18 merged traffic",
    )
    if (
        step18_metadata.get("execution_status") != "completed"
        or step18_metadata.get("materialization_success") is not True
    ):
        raise ValueError("Step 25 requires a completed, successfully materialized Step 18 artifact.")
    explicit_headers_by_packet_field: dict[
        str, dict[str, list[dict[str, Any]]]
    ] = defaultdict(lambda: defaultdict(list))
    derived_headers_by_packet_field: dict[
        str, dict[str, list[dict[str, Any]]]
    ] = defaultdict(lambda: defaultdict(list))
    payload_edits_by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    step18_patch_schema: list[Any] = []

    def consume_effective_header_edit(edit: Any) -> None:
        if isinstance(edit, dict):
            explicit_headers_by_packet_field[str(edit.get("packet_id"))][
                normalize_logical_field(edit.get("field"))
            ].append(edit)

    def consume_derived_header_change(change: Any) -> None:
        if isinstance(change, dict):
            field = normalize_logical_field(change.get("derived_field"))
            if not field.startswith("record."):
                derived_headers_by_packet_field[str(change.get("packet_id"))][
                    field
                ].append(change)

    def consume_payload_edit(edit: Any) -> None:
        if not isinstance(edit, dict):
            return
        key = (
            str(edit.get("prompt_unit_id")),
            int(edit.get("patch_index", 0) or 0),
            str(edit.get("canonical_region_id")),
        )
        if key in payload_edits_by_key and payload_edits_by_key[key] != edit:
            raise ValueError(f"Contradictory Step 18 payload edit identity: {key}.")
        payload_edits_by_key[key] = edit

    consume_selected_object_members(
        step18_merged,
        ("patch_application",),
        value_handlers={
            "schema_version": step18_patch_schema.append,
        },
        array_item_handlers={
            "effective_header_edits": consume_effective_header_edit,
            "derived_header_changes": consume_derived_header_change,
            "payload_edits": consume_payload_edit,
        },
    )
    if step18_patch_schema != [STEP18_PATCH_SCHEMA_VERSION]:
        raise ValueError(
            f"Step 18 patch-application schema mismatch: "
            f"{step18_patch_schema[0] if step18_patch_schema else None!r}."
        )

    step19_metadata_values: list[Any] = []
    step19_summary_values: list[Any] = []
    accepted_packet_ids = set()
    payload_projections_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def consume_step19_packet_result(packet_result: Any) -> None:
        if not isinstance(packet_result, dict):
            raise ValueError("Step 19 packet_results contains a non-object value.")
        if packet_result.get("status") == "accepted":
            packet_id = packet_result.get("packet_id")
            if packet_id is None:
                raise ValueError("Accepted Step 19 packet result lacks packet_id.")
            accepted_packet_ids.add(str(packet_id))

    def consume_payload_projection(projection: Any) -> None:
        if not isinstance(projection, dict) or projection.get("packet_id") is None:
            raise ValueError(
                "Step 19 effective payload projection is not traceable to packet_id."
            )
        payload_projections_by_packet[str(projection["packet_id"])].append(projection)

    consume_selected_object_members(
        step19_report,
        (),
        value_handlers={
            "metadata": step19_metadata_values.append,
            "summary": step19_summary_values.append,
        },
        array_item_handlers={
            "packet_results": consume_step19_packet_result,
            "validated_effective_payload_projection_changes": consume_payload_projection,
        },
    )
    step19_metadata = require_schema(
        step19_metadata_values[0],
        expected=STEP19_SCHEMA_VERSION,
        description="Step 19 validation report",
    )
    validate_artifact_identity(
        step19_metadata,
        experiment_id=experiment_id,
        experiment_config_label=experiment_config_label,
        description="Step 19 validation report",
    )
    step19_summary = step19_summary_values[0]
    if not isinstance(step19_summary, dict) or int(step19_summary.get("error_count", -1)) != 0:
        raise ValueError("Step 25 requires a Step 19 report with error_count = 0.")

    step20_metadata_values: list[Any] = []
    step20_summary_values: list[Any] = []
    tcp_translation_by_packet: dict[str, dict[str, Any]] = {}

    def consume_step20_packet_result(packet_result: Any) -> None:
        if not isinstance(packet_result, dict):
            raise ValueError("Step 20 packet_results contains a non-object value.")
        if packet_result.get("status") != "reconstructed":
            raise ValueError(
                f"Step 25 cannot audit a failed Step 20 packet result: "
                f"{packet_result.get('packet_id')!r}."
            )
        translation = packet_result.get("tcp_sequence_translation")
        if not isinstance(translation, dict):
            return
        if (
            int(translation.get("sequence_delta", 0) or 0) != 0
            or int(translation.get("acknowledgement_delta", 0) or 0) != 0
            or translation.get("original_sack_options")
            != translation.get("reconstructed_sack_options")
        ):
            tcp_translation_by_packet[str(packet_result.get("packet_id"))] = translation

    consume_selected_object_members(
        step20_report,
        (),
        value_handlers={
            "metadata": step20_metadata_values.append,
            "summary": step20_summary_values.append,
        },
        array_item_handlers={
            "packet_results": consume_step20_packet_result,
        },
    )
    step20_metadata = require_schema(
        step20_metadata_values[0],
        expected=STEP20_SCHEMA_VERSION,
        description="Step 20 reconstruction report",
    )
    validate_artifact_identity(
        step20_metadata,
        experiment_id=experiment_id,
        experiment_config_label=experiment_config_label,
        description="Step 20 reconstruction report",
    )
    if step20_metadata.get("status") != "completed":
        raise ValueError("Step 25 requires a completed Step 20 reconstruction report.")
    step20_summary = step20_summary_values[0]
    if not isinstance(step20_summary, dict):
        raise ValueError("Step 20 summary must be an object.")
    if int(step20_summary.get("error_count", -1)) != 0:
        raise ValueError("Step 25 requires Step 20 summary.error_count = 0.")
    if int(step20_summary.get("network_protocol_validation_error_count", -1)) != 0:
        raise ValueError(
            "Step 25 requires Step 20 network_protocol_validation_error_count = 0."
        )

    return {
        "accepted_packet_ids": accepted_packet_ids,
        "explicit_headers_by_packet_field": explicit_headers_by_packet_field,
        "derived_headers_by_packet_field": derived_headers_by_packet_field,
        "payload_edits_by_key": payload_edits_by_key,
        "payload_projections_by_packet": payload_projections_by_packet,
        "tcp_translation_by_packet": tcp_translation_by_packet,
    }


# This function creates one field-level change record and marks its field as attributed.
def append_field_change(
    *,
    changes: list[dict[str, Any]],
    attributed_fields: set[str],
    field_name: str,
    change_origin: str,
    pre_value: Any,
    post_value: Any,
    target_type: str,
    provenance: dict[str, Any] | None = None,
) -> None:
    change = {
        "target_type": target_type,
        "field_name": field_name,
        "change_origin": change_origin,
        "pre_value": pre_value,
        "post_value": post_value,
    }
    if provenance is not None:
        if provenance.get("prompt_unit_id") is not None:
            change["prompt_unit_id"] = provenance["prompt_unit_id"]
        if provenance.get("patch_index") is not None:
            change["patch_index"] = provenance["patch_index"]
    changes.append(change)
    attributed_fields.add(field_name)


# This function attributes all physical changes observed in one PRE/POST packet pair.
def build_changed_fields(
    *,
    packet_id: str,
    pre_packet: dict[str, Any],
    post_packet: dict[str, Any],
    indexes: dict[str, Any],
) -> list[dict[str, Any]]:
    pre_values = comparable_field_values(pre_packet)
    post_values = comparable_field_values(post_packet)
    changed_physical_fields = {
        field for field in pre_values if pre_values[field] != post_values[field]
    }
    payload_changed = pre_packet["payload_hex"] != post_packet["payload_hex"]
    changes: list[dict[str, Any]] = []
    attributed_fields: set[str] = set()
    llm_materialization_accepted = packet_id in indexes["accepted_packet_ids"]

    if llm_materialization_accepted:
        for field, records in sorted(
            indexes["explicit_headers_by_packet_field"].get(packet_id, {}).items()
        ):
            if field not in changed_physical_fields:
                continue
            record = final_record(records)
            append_field_change(
                changes=changes,
                attributed_fields=attributed_fields,
                field_name=field,
                change_origin="llm_explicit",
                pre_value=pre_values[field],
                post_value=post_values[field],
                target_type="physical_header_field",
                provenance=record,
            )

        for field, records in sorted(
            indexes["derived_headers_by_packet_field"].get(packet_id, {}).items()
        ):
            if (
                field not in changed_physical_fields
                or field in attributed_fields
            ):
                continue
            record = final_record(records)
            append_field_change(
                changes=changes,
                attributed_fields=attributed_fields,
                field_name=field,
                change_origin="pipeline_derived",
                pre_value=pre_values[field],
                post_value=post_values[field],
                target_type="derived_header_field",
                provenance=record,
            )

    translation = indexes["tcp_translation_by_packet"].get(packet_id)
    if translation is not None:
        for field in sorted(PIPELINE_TRANSLATED_FIELDS & changed_physical_fields):
            append_field_change(
                changes=changes,
                attributed_fields=attributed_fields,
                field_name=field,
                change_origin="pipeline_derived",
                pre_value=pre_values[field],
                post_value=post_values[field],
                target_type="pipeline_controlled_header_field",
            )

    for field in sorted(PROTOCOL_RECOMPUTED_FIELDS & changed_physical_fields):
        append_field_change(
            changes=changes,
            attributed_fields=attributed_fields,
            field_name=field,
            change_origin="protocol_recomputed",
            pre_value=pre_values[field],
            post_value=post_values[field],
            target_type="protocol_recomputed_field",
        )

    projections = indexes["payload_projections_by_packet"].get(packet_id, [])
    if payload_changed and not projections:
        raise ValueError(
            f"Packet {packet_id!r} has a PRE/POST payload difference without a "
            "Step 19 validated effective payload projection."
        )
    if payload_changed:
        seen_logical_edits = set()
        for projection in sorted(
            projections,
            key=lambda item: (
                str(item.get("canonical_region_id", "")),
                int(item.get("canonical_edit_start_offset_bytes", -1)),
                str(item.get("prompt_unit_id", "")),
                int(item.get("patch_index", 0)),
            ),
        ):
            key = (
                str(projection.get("prompt_unit_id")),
                int(projection.get("patch_index", 0) or 0),
                str(projection.get("canonical_region_id")),
            )
            if key in seen_logical_edits:
                continue
            logical_edit = indexes["payload_edits_by_key"].get(key)
            if logical_edit is None:
                raise ValueError(
                    f"Step 19 payload projection has no matching effective Step 18 "
                    f"logical edit: packet_id={packet_id!r}, key={key!r}."
                )
            seen_logical_edits.add(key)
            start = int(logical_edit["canonical_start_offset_bytes"])
            replaced_length = int(logical_edit["replaced_length_bytes"])
            changes.append(
                {
                    "target_type": "canonical_payload_range",
                    "canonical_region_id": logical_edit["canonical_region_id"],
                    "range_start_bytes": start,
                    "range_end_bytes": start + replaced_length,
                    "change_origin": "llm_explicit",
                    "pre_value": logical_edit["original_segment_hex"],
                    "post_value": logical_edit["replacement_hex"],
                    "prompt_unit_id": logical_edit["prompt_unit_id"],
                    "patch_index": logical_edit["patch_index"],
                }
            )
    elif projections:
        # Multiple valid projections may compose back to the original packet.
        # They are not physical PRE/POST differences and are intentionally omitted.
        pass

    unattributed = sorted(changed_physical_fields - attributed_fields)
    if unattributed:
        raise ValueError(
            f"Packet {packet_id!r} contains physical field changes without Step 18-20 "
            f"provenance: {unattributed}."
        )
    if not changes:
        raise ValueError(
            f"Packet {packet_id!r} differs byte-for-byte between PRE and POST but "
            "no materialized field change was attributed."
        )
    return finalize_changed_fields(changes)


# This function writes a complete Step 25 population into a staging directory.
def build_staged_comparisons(
    *,
    config: dict[str, Any],
    reference_json: Path,
    pre_pcap: Path,
    post_pcap: Path,
    step18_merged: Path,
    step19_report: Path,
    step20_report: Path,
    staging_dir: Path,
) -> dict[str, Any]:
    experiment_id = config["experiment"]["experiment_id"]
    experiment_config_label = config["pipeline"]["experiment_config_label"]
    step14_metadata = require_schema(
        load_json_value_at_path(reference_json, ("metadata",)),
        expected=STEP14_SCHEMA_VERSION,
        description="Step 14 packet reference",
    )
    if step14_metadata.get("experiment_id") != experiment_id:
        raise ValueError(
            f"Step 14 experiment_id mismatch: "
            f"{step14_metadata.get('experiment_id')!r} != {experiment_id!r}."
        )
    indexes = load_traceability_indexes(
        step18_merged=step18_merged,
        step19_report=step19_report,
        step20_report=step20_report,
        experiment_id=experiment_id,
        experiment_config_label=experiment_config_label,
    )

    scapy = import_scapy()
    RawPcapReader = scapy["RawPcapReader"]
    individual_dir = staging_dir / "individual_comparisons"
    individual_dir.mkdir(parents=True, exist_ok=True)
    summary_entries = []
    seen_packet_ids = set()
    seen_dataset_packet_numbers = set()

    reference_records = iter_json_array_at_path(reference_json, ("traffic",))
    pending_writes: set[Future[Any]] = set()
    with ThreadPoolExecutor(max_workers=12) as json_writer_pool:
        with RawPcapReader(str(pre_pcap)) as pre_reader, RawPcapReader(
            str(post_pcap)
        ) as post_reader:
            rows = zip_longest(
                reference_records, pre_reader, post_reader, fillvalue=MISSING
            )
            for packet_index, (
                reference_record,
                pre_scapy_packet,
                post_scapy_packet,
            ) in enumerate(rows, start=1):
                missing_sources = [
                    name
                    for name, value in [
                        ("Step 14 traffic", reference_record),
                        ("PRE PCAP", pre_scapy_packet),
                        ("POST PCAP", post_scapy_packet),
                    ]
                    if value is MISSING
                ]
                if missing_sources:
                    raise ValueError(
                        "Step 25 requires equal Step 14/PRE/POST packet counts; "
                        f"first mismatch at 1-based packet {packet_index}: {missing_sources}."
                    )
                if not isinstance(reference_record, dict):
                    raise ValueError(f"Step 14 traffic record {packet_index} is not an object.")
    
                packet_id = str(reference_record.get("packet_id", ""))
                expected_packet_id = f"packet_{packet_index:06d}"
                if packet_id != expected_packet_id:
                    raise ValueError(
                        f"Step 14 packet order mismatch at {packet_index}: "
                        f"{packet_id!r} != {expected_packet_id!r}."
                    )
                reduced_packet_index = positive_packet_number(
                    reference_record.get("reduced_packet_index"),
                    "reduced_packet_index",
                    packet_id,
                )
                if reduced_packet_index != packet_index:
                    raise ValueError(
                        f"Step 14 reduced_packet_index mismatch for {packet_id!r}: "
                        f"{reduced_packet_index} != {packet_index}."
                    )
                dataset_packet_number = positive_packet_number(
                    reference_record.get("original_packet_number"),
                    "original_packet_number",
                    packet_id,
                )
                if packet_id in seen_packet_ids:
                    raise ValueError(f"Duplicate Step 14 packet_id: {packet_id!r}.")
                if dataset_packet_number in seen_dataset_packet_numbers:
                    raise ValueError(
                        "dataset_pcap_packet_number is ambiguous because Step 14 "
                        f"original_packet_number={dataset_packet_number} appears more than once."
                    )
                seen_packet_ids.add(packet_id)
                seen_dataset_packet_numbers.add(dataset_packet_number)
    
                tcp_connection_id = reference_record.get("tcp_connection_id")
                if not isinstance(tcp_connection_id, str) or not tcp_connection_id:
                    raise ValueError(
                        f"Step 14 packet {packet_id!r} lacks explicit tcp_connection_id."
                    )
    
                pre_frame, pre_packet_metadata = pre_scapy_packet
                post_frame, post_packet_metadata = post_scapy_packet
                pre_frame = bytes(pre_frame)
                post_frame = bytes(post_frame)
                pre_structured = structured_packet(pre_frame)
                post_structured = structured_packet(post_frame)
                validate_pre_against_step14(reference_record, pre_structured, packet_index)
                validate_packet_timestamp(
                    pre_packet_metadata,
                    reference_record.get("timestamp_epoch_pcap"),
                    packet_id=packet_id,
                    traffic_version="PRE",
                )
                validate_packet_timestamp(
                    post_packet_metadata,
                    reference_record.get("timestamp_epoch_pcap"),
                    packet_id=packet_id,
                    traffic_version="POST",
                )
                if immutable_packet_identity(pre_structured) != immutable_packet_identity(
                    post_structured
                ):
                    raise ValueError(
                        f"PRE/POST packet order or immutable identity changed at "
                        f"1-based packet {packet_index} ({packet_id})."
                    )
    
                if pre_frame == post_frame:
                    continue
    
                changed_fields = build_changed_fields(
                    packet_id=packet_id,
                    pre_packet=pre_structured,
                    post_packet=post_structured,
                    indexes=indexes,
                )
                comparison_id = f"packet_comparison_{len(summary_entries) + 1:06d}"
                modification_scope = derive_modification_scope(changed_fields)
                detail_relative_path = (
                    Path("individual_comparisons") / f"{comparison_id}.json"
                )
                detail = {
                    "schema_version": COMPARISON_SCHEMA_VERSION,
                    "comparison_id": comparison_id,
                    "packet_identity": {
                        "packet_id": packet_id,
                        "tcp_connection_id": tcp_connection_id,
                        "dataset_pcap_packet_number": dataset_packet_number,
                        "pre_pcap_packet_number": packet_index,
                        "post_pcap_packet_number": packet_index,
                        "pre_frame_sha256": sha256_bytes(pre_frame),
                        "post_frame_sha256": sha256_bytes(post_frame),
                    },
                    "modification_scope": modification_scope,
                    "pre_packet": {
                        "raw_packet_hex": pre_frame.hex(),
                        "structured_packet": pre_structured,
                    },
                    "post_packet": {
                        "raw_packet_hex": post_frame.hex(),
                        "structured_packet": post_structured,
                    },
                    "changed_fields": changed_fields,
                }
                pending_writes.add(
                    json_writer_pool.submit(
                        write_json,
                        staging_dir / detail_relative_path,
                        detail,
                    )
                )
                if len(pending_writes) >= 192:
                    completed, pending_writes = wait(
                        pending_writes,
                        return_when=FIRST_COMPLETED,
                    )
                    for completed_write in completed:
                        completed_write.result()
                summary_entries.append(
                    {
                        "comparison_id": comparison_id,
                        "modification_scope": modification_scope,
                        "changed_field_count": len(changed_fields),
                        "comparison_artifact": detail_relative_path.as_posix(),
                    }
                )

        for pending_write in pending_writes:
            pending_write.result()

    manifest = {
        "metadata": {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "experiment_id": experiment_id,
            "experiment_config_label": experiment_config_label,
            "generated_at_utc": utc_now(),
            "comparison_count": len(summary_entries),
            "pre_pcap_path": str(pre_pcap),
            "post_pcap_path": str(post_pcap),
            "pre_pcap_sha256": sha256_file(pre_pcap),
            "post_pcap_sha256": sha256_file(post_pcap),
            "packet_correspondence_policy": PACKET_CORRESPONDENCE_POLICY,
        },
        "packet_comparisons": summary_entries,
    }
    write_json(staging_dir / "packet_comparisons_summary.json", manifest)
    return manifest


# This function atomically promotes a complete staging directory over the final branch.
def publish_staging_directory(staging_dir: Path, output_dir: Path) -> None:
    parent = output_dir.parent
    backup_dir = parent / f".{output_dir.name}.backup-{uuid.uuid4().hex}"
    moved_existing = False
    try:
        if output_dir.exists():
            output_dir.replace(backup_dir)
            moved_existing = True
        staging_dir.replace(output_dir)
    except Exception:
        if moved_existing and not output_dir.exists() and backup_dir.exists():
            backup_dir.replace(output_dir)
        raise
    else:
        if backup_dir.exists():
            shutil.rmtree(backup_dir)


# This function is the public programmatic Step 25 entry point.
def compare_packets(
    *,
    config_path: str | Path,
    experiment_root: str | Path | None = None,
    reference_json: str | Path | None = None,
    pre_pcap: str | Path | None = None,
    post_pcap: str | Path | None = None,
    step18_merged: str | Path | None = None,
    step19_report: str | Path | None = None,
    step20_report: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    paths = default_paths(config, experiment_root)
    resolved = {
        "reference_json": Path(reference_json).expanduser()
        if reference_json
        else paths["reference_json"],
        "pre_pcap": Path(pre_pcap).expanduser() if pre_pcap else paths["pre_pcap"],
        "post_pcap": Path(post_pcap).expanduser()
        if post_pcap
        else paths["post_pcap"],
        "step18_merged": Path(step18_merged).expanduser()
        if step18_merged
        else paths["step18_merged"],
        "step19_report": Path(step19_report).expanduser()
        if step19_report
        else paths["step19_report"],
        "step20_report": Path(step20_report).expanduser()
        if step20_report
        else paths["step20_report"],
    }
    for key, path in resolved.items():
        require_file(path, key.replace("_", " "))

    final_output_dir = (
        Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    )
    final_output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = final_output_dir.parent / (
        f".{final_output_dir.name}.staging-{uuid.uuid4().hex}"
    )
    staging_dir.mkdir(parents=False, exist_ok=False)
    try:
        manifest = build_staged_comparisons(
            config=config,
            reference_json=resolved["reference_json"],
            pre_pcap=resolved["pre_pcap"],
            post_pcap=resolved["post_pcap"],
            step18_merged=resolved["step18_merged"],
            step19_report=resolved["step19_report"],
            step20_report=resolved["step20_report"],
            staging_dir=staging_dir,
        )
        publish_staging_directory(staging_dir, final_output_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        raise
    return {
        "output_dir": str(final_output_dir),
        "summary_path": str(final_output_dir / "packet_comparisons_summary.json"),
        "comparison_count": manifest["metadata"]["comparison_count"],
        "pre_pcap_sha256": manifest["metadata"]["pre_pcap_sha256"],
        "post_pcap_sha256": manifest["metadata"]["post_pcap_sha256"],
    }


# This function resolves the default Step 25 terminal-log path.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    validate_config(config)
    experiment_root = (
        Path(args.experiment_root).expanduser()
        if args.experiment_root
        else build_experiment_root(config)
    )
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_25_packet_comparison",
        branch_label=config["pipeline"]["experiment_config_label"],
        filename_prefix="step_25_packet_comparison",
    )


# This function defines the Step 25 command-line contract.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare canonical PRE/POST packet frames and serialize traceable differences."
    )
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--experiment-root", help="Optional experiment root override.")
    add("--reference-json", help="Optional Step 14 selected_packet_records.json path.")
    add("--pre-pcap", help="Optional Step 13 selected PRE PCAP path.")
    add("--post-pcap", help="Optional Step 20 reconstructed POST PCAP path.")
    add("--step18-merged", help="Optional Step 18 merged_modified_traffic.json path.")
    add("--step19-report", help="Optional Step 19 validation_report.json path.")
    add("--step20-report", help="Optional Step 20 reconstruction_report.json path.")
    add("--output-dir", help="Optional Step 25 output directory.")
    add("--log-file", help="Optional explicit terminal log file path.")
    return parser.parse_args()


# This function runs Step 25 with terminal logging and fail-closed exit status.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 25 terminal log"):
        try:
            result = compare_packets(
                config_path=args.config,
                experiment_root=args.experiment_root,
                reference_json=args.reference_json,
                pre_pcap=args.pre_pcap,
                post_pcap=args.post_pcap,
                step18_merged=args.step18_merged,
                step19_report=args.step19_report,
                step20_report=args.step20_report,
                output_dir=args.output_dir,
            )
        except Exception:
            print("Step 25 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"Packet comparisons: {result['comparison_count']}")
        print(f"PRE PCAP SHA-256: {result['pre_pcap_sha256']}")
        print(f"POST PCAP SHA-256: {result['post_pcap_sha256']}")
        print(f"Packet comparison summary: {result['summary_path']}")
        print(f"Individual comparisons: {Path(result['output_dir']) / 'individual_comparisons'}")


if __name__ == "__main__":
    main()
