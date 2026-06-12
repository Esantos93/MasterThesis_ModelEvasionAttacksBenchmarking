from __future__ import annotations

import argparse
import json
import re
import string
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


#These are the Step 15 artifact schema names produced by the current code.
PROMPT_UNIT_SCHEMA_VERSION = "compact_prompt_unit_v2"
GROUP_MANIFEST_SCHEMA_VERSION = "group_manifest_v2"
PAYLOAD_STRATEGY_VERSION = "payload_strategy_v1"

#This list records the grouping policies that the current draft knows how to execute.
#When a future grouping policy is implemented, it should be added here and in group_records_by_policy().
SUPPORTED_GROUPING_POLICIES = ["fixed_packet_count", "flow_based"]

#These defaults implement Step 15 planning heuristics from the cross-step redesign.
#Experiment-level budget values that affect the LLM contract must come from the active config.
DEFAULT_TOKEN_BUDGET_CONFIG = {
    "prompt_target_context": 4096,
    "prompt_template_overhead_tokens": 500,
    "context_reserve_tokens": 256,
    "token_budget_safety_factor": 0.85,
    "chars_per_token_estimate": 3.0,
    "small_payload_min_bytes": 64,
    "small_payload_max_bytes": 512,
    "small_full_token_budget_fraction": 0.05,
    "payload_window_left_context_bytes": 128,
    "payload_window_editable_center_bytes": 512,
    "payload_window_right_context_bytes": 128,
}
REQUIRED_TOKEN_BUDGET_CONFIG_KEYS = ["expected_output_patch_tokens"]

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
TEXT_PRINTABLE = set(string.printable)


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function estimates the size of a JSON object when stored in compact form.
def compact_json_size_bytes(data: Any) -> int:
    encoded = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return len(encoded)


#This function estimates tokens with the deterministic heuristic used by Step 15 planning.
def estimate_json_tokens(data: Any, chars_per_token_estimate: float) -> int:
    size_chars = compact_json_size_bytes(data)
    return max(1, int(size_chars / chars_per_token_estimate) + 1)


#This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


#This function returns the default input and output paths for Step 15 based on the experiment directory layout created by Step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
        "output_dir": experiment_root / "05_groups",
    }


#This function validates the minimum configuration keys required by Step 15.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["grouping_policy"], "pipeline")
    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    if grouping_policy == "fixed_packet_count":
        require_keys(config["pipeline"], ["group_size_packets"], "pipeline")
    if grouping_policy == "flow_based":
        require_keys(config["pipeline"], ["flow_slide_window_overlap_packets"], "pipeline")


#This function validates the basic shape of the packet JSON produced by Step 14.
def validate_packet_json(packet_json: Any, input_path: Path) -> dict[str, Any]:
    if not isinstance(packet_json, dict):
        raise ValueError(f"Packet JSON root must be an object: {input_path}")
    traffic = packet_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError(f"Packet JSON must contain a top-level 'traffic' list: {input_path}")
    immutable_fields = packet_json.get("immutable_fields", [])
    if not isinstance(immutable_fields, list):
        raise ValueError(f"Packet JSON 'immutable_fields' must be a list: {input_path}")
    metadata = packet_json.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"Packet JSON 'metadata' must be an object: {input_path}")
    return packet_json


#This function merges Step 15 heuristic defaults with values from the active config.
def get_token_budget_config(config: dict[str, Any]) -> dict[str, Any]:
    token_config = dict(DEFAULT_TOKEN_BUDGET_CONFIG)
    llm_config = config.get("llm", {}) if isinstance(config.get("llm"), dict) else {}
    pipeline_config = config.get("pipeline", {}) if isinstance(config.get("pipeline"), dict) else {}
    for source in [llm_config, pipeline_config]:
        for key in token_config:
            if key in source:
                token_config[key] = source[key]
    for key in REQUIRED_TOKEN_BUDGET_CONFIG_KEYS:
        if key in llm_config:
            token_config[key] = llm_config[key]
        elif key in pipeline_config:
            token_config[key] = pipeline_config[key]
        else:
            raise ValueError(
                f"Step 15 requires {key!r} in the active config under 'llm' or 'pipeline'. "
                "This experiment-level budget value has no internal default."
            )
    return token_config


#This function derives the input-token budget used by Step 15 to plan compact prompt units.
def compute_input_token_budget(token_config: dict[str, Any]) -> int:
    available = (
        int(token_config["prompt_target_context"])
        - int(token_config["prompt_template_overhead_tokens"])
        - int(token_config["expected_output_patch_tokens"])
        - int(token_config["context_reserve_tokens"])
    )
    return max(1, int(available * float(token_config["token_budget_safety_factor"])))


#This function reads the flow chunk overlap setting used by flow-based Step 15 prompt-unit planning.
def get_flow_slide_window_overlap_packets(config: dict[str, Any], grouping_policy: str) -> int:
    if grouping_policy != "flow_based":
        return 0
    overlap_packets = int(config["pipeline"]["flow_slide_window_overlap_packets"])
    if overlap_packets < 0:
        raise ValueError("pipeline.flow_slide_window_overlap_packets must be zero or a positive integer.")
    return overlap_packets


#This function implements the baseline parent grouping policy.
def group_fixed_packet_count(records: list[Any], group_size: int) -> list[dict[str, Any]]:
    if group_size <= 0:
        raise ValueError("group_size_packets must be a positive integer.")
    groups = []
    for group_index, start_index in enumerate(range(0, len(records), group_size), start=1):
        groups.append(
            {
                "parent_group_id": f"group_{group_index:06d}",
                "group_index": group_index,
                "unit_type": "fixed_packet_group",
                "records": records[start_index : start_index + group_size],
            }
        )
    return groups


#This function extracts flow context from a packet and fails clearly when flow-based grouping is selected for a JSON without flow context.
def get_packet_flow_context(packet: dict[str, Any]) -> dict[str, Any]:
    flow_context = packet.get("flow_context")
    if not isinstance(flow_context, dict):
        packet_id = packet.get("packet_id", "<unknown>")
        raise ValueError(
            "The flow_based grouping policy requires Step 14 packet records with flow_context. "
            f"Packet without flow_context: {packet_id!r}."
        )
    return flow_context


#This function chooses the deterministic flow-group key for the current flow-based implementation.
def flow_group_key(packet: dict[str, Any]) -> str:
    flow_context = get_packet_flow_context(packet)
    assigned_flow_ids = [str(flow_id) for flow_id in flow_context.get("assigned_flow_ids", [])]
    candidate_flow_ids = [str(flow_id) for flow_id in flow_context.get("candidate_flow_ids", [])]
    mapping_status = str(flow_context.get("packet_mapping_status", "unknown") or "unknown")
    if len(assigned_flow_ids) > 1:
        packet_id = packet.get("packet_id", "<unknown>")
        raise ValueError(
            "flow_based grouping expects at most one assigned_flow_id per packet. "
            f"Packet {packet_id!r} has assigned_flow_ids={assigned_flow_ids!r}."
        )
    if len(assigned_flow_ids) == 1:
        return assigned_flow_ids[0]
    if len(candidate_flow_ids) == 1:
        return candidate_flow_ids[0]
    return f"unresolved_{mapping_status}"


#This function implements an initial deterministic flow-based parent grouping policy.
def group_flow_based(records: list[Any]) -> list[dict[str, Any]]:
    groups_by_key: dict[str, list[Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("flow_based grouping expects every traffic record to be a JSON object.")
        key = flow_group_key(record)
        groups_by_key.setdefault(key, []).append(record)

    groups = []
    for group_index, key in enumerate(sorted(groups_by_key), start=1):
        safe_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", key).strip("_") or f"flow_group_{group_index:06d}"
        parent_group_id = safe_key if safe_key.startswith(("flow_", "unresolved_")) else f"flow_{safe_key}"
        unit_type = "unresolved" if parent_group_id.startswith("unresolved_") else "flow"
        groups.append(
            {
                "parent_group_id": parent_group_id,
                "group_index": group_index,
                "unit_type": unit_type,
                "records": groups_by_key[key],
            }
        )
    return groups


#This function selects the concrete grouping function based on pipeline.grouping_policy.
def group_records_by_policy(*, records: list[Any], grouping_policy: str, group_size_packets: int | None) -> list[dict[str, Any]]:
    if grouping_policy == "fixed_packet_count":
        if group_size_packets is None:
            raise ValueError("group_size_packets is required when grouping_policy is fixed_packet_count.")
        return group_fixed_packet_count(records, group_size_packets)
    if grouping_policy == "flow_based":
        return group_flow_based(records)
    raise ValueError(
        f"The selected grouping policy ({grouping_policy!r}) is not supported.\n"
        f"The supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
    )


#This function builds the output subfolder name for the selected Step 15 grouping policy.
def policy_output_subdir(grouping_policy: str, group_size_packets: int | None) -> str:
    if grouping_policy == "fixed_packet_count":
        if group_size_packets is None:
            raise ValueError("group_size_packets is required when grouping_policy is fixed_packet_count.")
        return f"fixed_packet_count_size_{group_size_packets:03d}"
    if grouping_policy == "flow_based":
        return "flow_based"
    raise ValueError(
        f"The selected grouping policy ({grouping_policy!r}) is not supported.\n"
        f"The supported policies are: {SUPPORTED_GROUPING_POLICIES!r}."
    )


#This function returns a simple percentile from an already sorted list of integers.
def percentile_from_sorted(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    index = int((len(values) * percentile) + 0.999999) - 1
    return values[max(0, min(index, len(values) - 1))]


#This function returns the median from an already sorted list of integers.
def median_from_sorted(values: list[int]) -> int | float | None:
    if not values:
        return None
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return round((values[middle - 1] + values[middle]) / 2, 4)


#This function summarizes parent-group sizes so flow-based experiments can be compared with fixed-size baselines.
def parent_group_size_statistics(parent_groups: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = sorted(len(group["records"]) for group in parent_groups)
    if not sizes:
        return {
            "group_count": 0,
            "packet_count_min": None,
            "packet_count_max": None,
            "packet_count_mean": None,
            "packet_count_median": None,
            "packet_count_mode": None,
            "packet_count_p95": None,
            "packet_count_distribution": {},
            "parent_group_unit_type_counts": {},
        }

    distribution = Counter(sizes)
    unit_type_counts = Counter(str(group.get("unit_type", "unknown")) for group in parent_groups)
    mode_size, _ = sorted(distribution.items(), key=lambda item: (-item[1], item[0]))[0]
    return {
        "group_count": len(sizes),
        "packet_count_min": sizes[0],
        "packet_count_max": sizes[-1],
        "packet_count_mean": round(sum(sizes) / len(sizes), 4),
        "packet_count_median": median_from_sorted(sizes),
        "packet_count_mode": mode_size,
        "packet_count_p95": percentile_from_sorted(sizes, 0.95),
        "packet_count_distribution": {str(size): count for size, count in sorted(distribution.items())},
        "parent_group_unit_type_counts": dict(sorted(unit_type_counts.items())),
    }


#This function converts a hexadecimal payload to bytes and fails with a useful packet id when the source JSON is invalid.
def payload_hex_to_bytes(packet: dict[str, Any]) -> bytes:
    payload_hex = str(packet.get("payload_hex", "") or "")
    try:
        return bytes.fromhex(payload_hex)
    except ValueError as exc:
        packet_id = packet.get("packet_id", "<unknown>")
        raise ValueError(f"Invalid payload_hex for packet {packet_id}: {exc}") from exc


#This function computes a deterministic text-readability report for payload bytes.
def text_readability_report(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {
            "is_text": False,
            "printable_ratio": 0.0,
            "replacement_ratio": 0.0,
            "control_ratio": 0.0,
            "decoded_text": "",
        }
    decoded = payload.decode("utf-8", errors="replace")
    replacement_count = decoded.count("\ufffd")
    printable_count = sum(1 for char in decoded if char in TEXT_PRINTABLE)
    control_count = sum(1 for char in decoded if ord(char) < 32 and char not in "\r\n\t")
    char_count = max(1, len(decoded))
    printable_ratio = printable_count / char_count
    replacement_ratio = replacement_count / char_count
    control_ratio = control_count / char_count
    return {
        "is_text": printable_ratio >= 0.75 and replacement_ratio <= 0.05 and control_ratio <= 0.05,
        "printable_ratio": round(printable_ratio, 4),
        "replacement_ratio": round(replacement_ratio, 4),
        "control_ratio": round(control_ratio, 4),
        "decoded_text": decoded,
    }


#This function identifies simple HTTP payloads from text and packet port hints.
def looks_like_http(text: str, packet: dict[str, Any]) -> bool:
    first_line = text.splitlines()[0] if text.splitlines() else ""
    first_token = first_line.split(" ", 1)[0].upper() if first_line else ""
    if first_token in HTTP_METHODS or first_line.startswith("HTTP/"):
        return True
    ports = {packet.get("src_port"), packet.get("dst_port")}
    return bool({80, 8080, 8000, 8888}.intersection(ports)) and "\r\n" in text


#This function builds basic parsed HTTP fields while preserving the raw sections as editable regions.
def build_http_payload_view(packet: dict[str, Any], payload: bytes, text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header_end = text.find("\r\n\r\n")
    separator_len = 4
    if header_end < 0:
        header_end = text.find("\n\n")
        separator_len = 2
    header_text = text if header_end < 0 else text[:header_end]
    body_text = "" if header_end < 0 else text[header_end + separator_len :]
    lines = header_text.splitlines()
    start_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    view = {
        "mode": "parsed_http",
        "representation": "text",
        "payload_length_bytes": len(payload),
        "http_parsed_fields": {
            "start_line": start_line,
            "headers": headers,
            "body_preview": body_text[:256],
            "body_length_chars": len(body_text),
        },
    }
    regions = []
    if start_line:
        regions.append(
            build_region(
                packet=packet,
                region_id="http_start_line",
                region_type="http_start_line",
                offset=0,
                length=len(start_line.encode("utf-8")),
                replacement_format="text",
                value=start_line,
            )
        )
    if body_text:
        body_offset = len(text[: header_end + separator_len].encode("utf-8")) if header_end >= 0 else 0
        regions.append(
            build_region(
                packet=packet,
                region_id="http_body",
                region_type="http_body",
                offset=body_offset,
                length=len(body_text.encode("utf-8")),
                replacement_format="text",
                value=body_text[:512],
            )
        )
    return view, regions


#This function chooses the patch operations allowed for each editable region type.
def allowed_operations_for_region(region_type: str) -> list[str]:
    if region_type == "payload_byte_range":
        return ["replace_byte_range"]
    return ["replace_region"]


#This function creates a stable editable region object for one packet payload area.
def build_region(
    *,
    packet: dict[str, Any],
    region_id: str,
    region_type: str,
    offset: int,
    length: int,
    replacement_format: str,
    value: str,
) -> dict[str, Any]:
    region = {
        "packet_id": packet.get("packet_id"),
        "region_id": region_id,
        "region_type": region_type,
        "start_offset_bytes": offset,
        "end_offset_bytes": offset + length,
        "length_bytes": length,
        "format": replacement_format,
        "allowed_operations": allowed_operations_for_region(region_type),
        "editable": True,
        "value": value,
    }
    return region


#This function builds summary text for payloads that are too large to include fully in the compact view.
def payload_summary(mode: str, payload: bytes, text: str, readability: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "mode": mode,
        "payload_length_bytes": len(payload),
        "printable_ratio": readability["printable_ratio"],
        "replacement_ratio": readability["replacement_ratio"],
        "control_ratio": readability["control_ratio"],
    }
    if mode == "large_text_summary":
        summary["representation"] = "text"
        summary["text_prefix"] = text[:160]
        summary["text_suffix"] = text[-160:] if len(text) > 160 else text
    else:
        summary["representation"] = "hex"
        payload_hex = payload.hex()
        summary["hex_prefix"] = payload_hex[:160]
        summary["hex_suffix"] = payload_hex[-160:] if len(payload_hex) > 160 else payload_hex
    return summary


#This function decides whether a full payload can be included as a small editable region.
def payload_fits_small_full(candidate_view: dict[str, Any], payload_length: int, token_config: dict[str, Any], input_token_budget: int) -> bool:
    min_bytes = int(token_config["small_payload_min_bytes"])
    max_bytes = int(token_config["small_payload_max_bytes"])
    small_payload_limit = max(min_bytes, min(payload_length, max_bytes))
    small_full_token_limit = max(1, int(input_token_budget * float(token_config["small_full_token_budget_fraction"])))
    estimated_tokens = estimate_json_tokens(candidate_view, float(token_config["chars_per_token_estimate"]))
    return payload_length <= small_payload_limit and estimated_tokens <= small_full_token_limit


#This function creates fixed-size byte windows that cover every byte of a large payload exactly once in the editable center.
def build_payload_windows(packet: dict[str, Any], payload: bytes, readability: dict[str, Any], token_config: dict[str, Any]) -> list[dict[str, Any]]:
    left_context = int(token_config["payload_window_left_context_bytes"])
    center_size = int(token_config["payload_window_editable_center_bytes"])
    right_context = int(token_config["payload_window_right_context_bytes"])
    windows = []
    packet_id = str(packet.get("packet_id"))
    text = readability["decoded_text"]
    is_text = bool(readability["is_text"])
    for window_index, center_start in enumerate(range(0, len(payload), center_size), start=1):
        center_end = min(center_start + center_size, len(payload))
        window_start = max(0, center_start - left_context)
        window_end = min(len(payload), center_end + right_context)
        center_bytes = payload[center_start:center_end]
        window_bytes = payload[window_start:window_end]
        if is_text:
            center_value = center_bytes.decode("utf-8", errors="replace")
            window_value = window_bytes.decode("utf-8", errors="replace")
            replacement_format = "text"
        else:
            center_value = center_bytes.hex()
            window_value = window_bytes.hex()
            replacement_format = "hex"
        region_id = f"payload_window_{window_index:04d}_center"
        windows.append(
            {
                "packet_id": packet_id,
                "window_id": f"{packet_id}_window_{window_index:04d}",
                "window_index": window_index,
                "payload_view": {
                    "mode": "payload_window",
                    "representation": replacement_format,
                    "payload_length_bytes": len(payload),
                    "window_offset": window_start,
                    "window_length": window_end - window_start,
                    "center_offset": center_start,
                    "center_length": center_end - center_start,
                    "left_context_bytes": center_start - window_start,
                    "right_context_bytes": window_end - center_end,
                    "value": window_value,
                },
                "editable_region": build_region(
                    packet=packet,
                    region_id=region_id,
                    region_type="payload_byte_range",
                    offset=center_start,
                    length=center_end - center_start,
                    replacement_format=replacement_format,
                    value=center_value,
                ),
            }
        )
    return windows


#This function creates the compact payload view for a packet and any extra payload-window units required for large payloads.
def build_payload_plan(packet: dict[str, Any], token_config: dict[str, Any], input_token_budget: int) -> dict[str, Any]:
    payload = payload_hex_to_bytes(packet)
    payload_length = len(payload)
    if payload_length == 0:
        return {
            "payload_view": {"mode": "empty", "payload_length_bytes": 0},
            "editable_regions": [],
            "payload_windows": [],
        }

    readability = text_readability_report(payload)
    is_text = bool(readability["is_text"])
    text = readability["decoded_text"]
    if is_text and looks_like_http(text, packet):
        view, regions = build_http_payload_view(packet, payload, text)
        return {"payload_view": view, "editable_regions": regions, "payload_windows": []}

    if is_text:
        candidate_view = {
            "mode": "small_full",
            "representation": "text",
            "payload_length_bytes": payload_length,
            "value": text,
        }
        replacement_format = "text"
        value = text
    else:
        candidate_view = {
            "mode": "small_full",
            "representation": "hex",
            "payload_length_bytes": payload_length,
            "value": payload.hex(),
        }
        replacement_format = "hex"
        value = payload.hex()

    if payload_fits_small_full(candidate_view, payload_length, token_config, input_token_budget):
        return {
            "payload_view": candidate_view,
            "editable_regions": [
                build_region(
                    packet=packet,
                    region_id="payload_full",
                    region_type="payload_full",
                    offset=0,
                    length=payload_length,
                    replacement_format=replacement_format,
                    value=value,
                )
            ],
            "payload_windows": [],
        }

    summary_mode = "large_text_summary" if is_text else "large_unstructured_summary"
    return {
        "payload_view": payload_summary(summary_mode, payload, text, readability),
        "editable_regions": [],
        "payload_windows": build_payload_windows(packet, payload, readability, token_config),
    }


#This function keeps packet metadata needed by the LLM while removing the full payload_hex reference field.
def build_compact_packet(packet: dict[str, Any], payload_plan: dict[str, Any], editable: bool) -> dict[str, Any]:
    compact_packet = {
        "packet_id": packet.get("packet_id"),
        "role": "editable" if editable else "context",
        "editable": editable,
        "original_packet_number": packet.get("original_packet_number"),
        "reduced_packet_index": packet.get("reduced_packet_index"),
        "timestamp_epoch_pcap": packet.get("timestamp_epoch_pcap"),
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "transport_protocol": packet.get("transport_protocol"),
        "src_port": packet.get("src_port"),
        "dst_port": packet.get("dst_port"),
        "tcp_flags_str": packet.get("tcp_flags_str"),
        "packet_length_bytes": packet.get("packet_length_bytes"),
        "payload_length_bytes": packet.get("payload_length_bytes"),
        "payload_view": payload_plan["payload_view"],
        "editable_regions": payload_plan["editable_regions"] if editable else [],
    }
    if "flow_context" in packet:
        compact_packet["flow_context"] = packet["flow_context"]
    return compact_packet


#This function builds common group metadata shared by all prompt units from the same parent group.
def build_group_metadata(
    parent_group_id: str,
    group_index: int,
    records: list[dict[str, Any]],
    grouping_policy: str,
    group_size_packets: int | None,
    unit_type: str,
    parent_group: dict[str, Any],
) -> dict[str, Any]:
    timestamps = [record.get("timestamp_epoch_pcap") for record in records if record.get("timestamp_epoch_pcap") is not None]
    protocols = Counter(str(record.get("transport_protocol") or "OTHER") for record in records)
    metadata = {
        "parent_group_id": parent_group_id,
        "group_index": group_index,
        "unit_type": unit_type,
        "grouping_policy": grouping_policy,
        "group_size_packets": group_size_packets,
        "packet_count": len(records),
        "first_timestamp_epoch_pcap": timestamps[0] if timestamps else None,
        "last_timestamp_epoch_pcap": timestamps[-1] if timestamps else None,
        "protocol_counts": dict(sorted(protocols.items())),
    }
    if grouping_policy == "flow_based":
        metadata["packet_mapping_status_counts"] = dict(
            sorted(
                Counter(
                    str(get_packet_flow_context(record).get("packet_mapping_status", "unknown") or "unknown")
                    for record in records
                ).items()
            )
        )
    return metadata


#This function builds one compact prompt unit artifact.
def build_prompt_unit(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    prompt_unit_id: str,
    unit_type: str,
    packets: list[dict[str, Any]],
    token_config: dict[str, Any],
    input_token_budget: int,
    context_truncation: dict[str, Any] | None,
) -> dict[str, Any]:
    prompt_unit = {
        "schema_version": PROMPT_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "prompt_unit_id": prompt_unit_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
        "group_metadata": group_metadata,
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "input_token_budget": input_token_budget,
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
        },
        "packet_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "packets": packets,
        "context_truncation": context_truncation,
    }
    refresh_prompt_unit_counts(prompt_unit, token_config)
    if (
        prompt_unit["estimated_input_tokens"] > input_token_budget
        and prompt_unit["context_packet_ids"]
        and prompt_unit["editable_packet_ids"]
    ):
        original_context_packet_ids = list(prompt_unit["context_packet_ids"])
        prompt_unit["packets"] = [packet for packet in prompt_unit["packets"] if packet.get("editable")]
        prompt_unit["context_truncation"] = {
            "applied": True,
            "reason": "estimated_input_tokens_exceeded_budget",
            "policy": "drop_context_packets_keep_editable_packets",
            "original_context_packet_ids": original_context_packet_ids,
        }
        refresh_prompt_unit_counts(prompt_unit, token_config)
    return prompt_unit


#This function refreshes packet ids, region counts, window counts, and token estimates after any prompt-unit planning change.
def refresh_prompt_unit_counts(prompt_unit: dict[str, Any], token_config: dict[str, Any]) -> None:
    packets = prompt_unit["packets"]
    prompt_unit["packet_ids"] = [str(packet["packet_id"]) for packet in packets]
    prompt_unit["editable_packet_ids"] = [str(packet["packet_id"]) for packet in packets if packet.get("editable")]
    prompt_unit["context_packet_ids"] = [str(packet["packet_id"]) for packet in packets if not packet.get("editable")]
    prompt_unit["editable_region_count"] = sum(len(packet.get("editable_regions", [])) for packet in packets)
    prompt_unit["payload_window_count"] = sum(1 for packet in packets if packet.get("payload_view", {}).get("mode") == "payload_window")
    prompt_unit["estimated_input_tokens"] = estimate_json_tokens(prompt_unit, float(token_config["chars_per_token_estimate"]))


#This function copies a compact packet as context so overlapped flow windows do not edit the same packet twice.
def as_context_packet(packet: dict[str, Any]) -> dict[str, Any]:
    context_packet = dict(packet)
    context_packet["role"] = "context"
    context_packet["editable"] = False
    context_packet["editable_regions"] = []
    return context_packet


#This function splits compact packets into deterministic prompt-unit chunks that fit the estimated input-token budget when possible.
def build_token_aware_packet_chunks(
    *,
    packets: list[dict[str, Any]],
    prompt_unit_context: dict[str, Any],
    token_config: dict[str, Any],
    input_token_budget: int,
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    current_chunk: list[dict[str, Any]] = []

    for packet in packets:
        candidate_chunk = current_chunk + [packet]
        candidate_unit = dict(prompt_unit_context)
        candidate_unit["packets"] = candidate_chunk
        candidate_unit["context_truncation"] = None
        refresh_prompt_unit_counts(candidate_unit, token_config)
        if current_chunk and candidate_unit["estimated_input_tokens"] > input_token_budget:
            chunks.append({"core_packets": current_chunk})
            current_chunk = [packet]
        else:
            current_chunk = candidate_chunk

    if current_chunk:
        chunks.append({"core_packets": current_chunk})
    return chunks


#This function adds previous-packet context overlap to token-aware flow chunks.
def add_flow_chunk_context_overlap(
    *,
    chunks: list[dict[str, Any]],
    overlap_packets: int,
) -> list[dict[str, Any]]:
    if overlap_packets <= 0:
        for chunk in chunks:
            chunk["packets"] = chunk["core_packets"]
            chunk["overlap_context_packet_ids"] = []
        return chunks

    for chunk_index, chunk in enumerate(chunks):
        previous_core = [
            packet
            for previous_chunk in chunks[:chunk_index]
            for packet in previous_chunk["core_packets"]
        ]
        overlap_context = [as_context_packet(packet) for packet in previous_core[-overlap_packets:]]
        chunk["packets"] = overlap_context + chunk["core_packets"]
        chunk["overlap_context_packet_ids"] = [str(packet["packet_id"]) for packet in overlap_context]
    return chunks


#This function creates base prompt units from compact packets, splitting large flows into packet windows when needed.
def build_base_prompt_units(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    group_metadata: dict[str, Any],
    parent_group_id: str,
    unit_type: str,
    base_packets: list[dict[str, Any]],
    grouping_policy: str,
    flow_slide_window_overlap_packets: int,
    token_config: dict[str, Any],
    input_token_budget: int,
) -> list[dict[str, Any]]:
    prompt_unit_context = {
        "schema_version": PROMPT_UNIT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "parent_group_id": group_metadata["parent_group_id"],
        "prompt_unit_id": parent_group_id,
        "unit_type": unit_type,
        "source_packet_json": str(source_packet_json),
        "source_packet_json_schema_version": source_packet_json_schema_version,
        "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
        "group_metadata": group_metadata,
        "token_budget": {
            "prompt_target_context": int(token_config["prompt_target_context"]),
            "input_token_budget": input_token_budget,
            "chars_per_token_estimate": float(token_config["chars_per_token_estimate"]),
        },
        "packet_ids": [],
        "editable_packet_ids": [],
        "context_packet_ids": [],
        "packets": [],
        "context_truncation": None,
    }
    chunks = build_token_aware_packet_chunks(
        packets=base_packets,
        prompt_unit_context=prompt_unit_context,
        token_config=token_config,
        input_token_budget=input_token_budget,
    )
    if grouping_policy == "flow_based":
        chunks = add_flow_chunk_context_overlap(
            chunks=chunks,
            overlap_packets=flow_slide_window_overlap_packets,
        )
    else:
        chunks = add_flow_chunk_context_overlap(chunks=chunks, overlap_packets=0)

    prompt_units = []
    for chunk_index, chunk in enumerate(chunks, start=1):
        chunk_count = len(chunks)
        prompt_unit_id = parent_group_id if chunk_count == 1 else f"{parent_group_id}_chunk_{chunk_index:04d}"
        chunk_metadata = dict(group_metadata)
        if chunk_count > 1:
            chunk_metadata["flow_packet_window"] = {
                "chunk_index": chunk_index,
                "chunk_count": chunk_count,
                "policy": "token_aware_packet_window",
                "core_packet_ids": [str(packet["packet_id"]) for packet in chunk["core_packets"]],
                "overlap_context_packet_ids": chunk["overlap_context_packet_ids"],
                "flow_slide_window_overlap_packets": flow_slide_window_overlap_packets,
            }
        prompt_units.append(
            build_prompt_unit(
                experiment_id=experiment_id,
                source_packet_json=source_packet_json,
                source_packet_json_schema_version=source_packet_json_schema_version,
                group_metadata=chunk_metadata,
                prompt_unit_id=prompt_unit_id,
                unit_type=unit_type if chunk_count == 1 else f"{unit_type}_packet_window",
                packets=chunk["packets"],
                token_config=token_config,
                input_token_budget=input_token_budget,
                context_truncation=None,
            )
        )
    return prompt_units


#This function creates all compact prompt units for one fixed-size parent group.
def build_prompt_units_for_group(
    *,
    experiment_id: str,
    source_packet_json: Path,
    source_packet_json_schema_version: str,
    parent_group_id: str,
    group_index: int,
    unit_type: str,
    records: list[dict[str, Any]],
    grouping_policy: str,
    group_size_packets: int | None,
    parent_group: dict[str, Any],
    flow_slide_window_overlap_packets: int,
    token_config: dict[str, Any],
    input_token_budget: int,
    heartbeat: Any | None,
) -> list[dict[str, Any]]:
    payload_plans = []
    for record_index, record in enumerate(records, start=1):
        payload_plans.append(build_payload_plan(record, token_config, input_token_budget))
        if heartbeat:
            heartbeat(
                f"planning_parent_group={parent_group_id}, "
                f"planned_packets={record_index}/{len(records)}"
            )
    group_metadata = build_group_metadata(parent_group_id, group_index, records, grouping_policy, group_size_packets, unit_type, parent_group)
    base_packets = [
        build_compact_packet(record, payload_plan, editable=bool(payload_plan["editable_regions"]))
        for record, payload_plan in zip(records, payload_plans)
    ]
    prompt_units = build_base_prompt_units(
        experiment_id=experiment_id,
        source_packet_json=source_packet_json,
        source_packet_json_schema_version=source_packet_json_schema_version,
        group_metadata=group_metadata,
        parent_group_id=parent_group_id,
        unit_type=unit_type,
        base_packets=base_packets,
        grouping_policy=grouping_policy,
        flow_slide_window_overlap_packets=flow_slide_window_overlap_packets,
        token_config=token_config,
        input_token_budget=input_token_budget,
    )

    window_counter = 0
    for record_index, (record, payload_plan) in enumerate(zip(records, payload_plans), start=1):
        for payload_window in payload_plan["payload_windows"]:
            window_counter += 1
            window_packet_plan = {
                "payload_view": payload_window["payload_view"],
                "editable_regions": [payload_window["editable_region"]],
            }
            window_packets = []
            for context_record, context_plan in zip(records, payload_plans):
                if context_record.get("packet_id") == record.get("packet_id"):
                    window_packets.append(build_compact_packet(context_record, window_packet_plan, editable=True))
                else:
                    summary_plan = {"payload_view": context_plan["payload_view"], "editable_regions": []}
                    window_packets.append(build_compact_packet(context_record, summary_plan, editable=False))
            prompt_units.append(
                build_prompt_unit(
                    experiment_id=experiment_id,
                    source_packet_json=source_packet_json,
                    source_packet_json_schema_version=source_packet_json_schema_version,
                    group_metadata=group_metadata,
                    prompt_unit_id=f"{parent_group_id}_window_{window_counter:04d}",
                    unit_type="payload_window",
                    packets=window_packets,
                    token_config=token_config,
                    input_token_budget=input_token_budget,
                    context_truncation=None,
                )
            )
        if heartbeat:
            heartbeat(
                f"building_parent_group={parent_group_id}, "
                f"payload_window_source_packets={record_index}/{len(records)}, "
                f"payload_window_units={window_counter}"
            )
    return prompt_units


#This function builds the manifest entry for one compact prompt unit.
def summarize_prompt_unit(prompt_unit: dict[str, Any], prompt_unit_path: Path) -> dict[str, Any]:
    group_metadata = prompt_unit.get("group_metadata", {})
    summary = {
        "parent_group_id": prompt_unit["parent_group_id"],
        "prompt_unit_id": prompt_unit["prompt_unit_id"],
        "unit_type": prompt_unit["unit_type"],
        "prompt_unit_file": str(prompt_unit_path),
        "packet_ids": prompt_unit["packet_ids"],
        "editable_packet_ids": prompt_unit["editable_packet_ids"],
        "context_packet_ids": prompt_unit["context_packet_ids"],
        "estimated_input_tokens": prompt_unit["estimated_input_tokens"],
        "payload_window_count": prompt_unit["payload_window_count"],
        "editable_region_count": prompt_unit["editable_region_count"],
        "context_truncation": prompt_unit["context_truncation"],
        "prompt_unit_file_size_bytes_pretty": prompt_unit_path.stat().st_size,
    }
    for key in ["packet_mapping_status_counts", "flow_packet_window"]:
        if key in group_metadata:
            summary[key] = group_metadata[key]
    return summary


#This function builds the top-level group_manifest.json artifact for compact prompt units.
def build_manifest(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_dir: Path,
    packet_json: dict[str, Any],
    grouping_policy: str,
    group_size_packets: int | None,
    flow_slide_window_overlap_packets: int,
    token_config: dict[str, Any],
    input_token_budget: int,
    parent_group_count: int,
    parent_group_stats: dict[str, Any],
    prompt_unit_summaries: list[dict[str, Any]],
    payload_mode_counts: Counter[str],
) -> dict[str, Any]:
    return {
        "metadata": {
            "schema_version": GROUP_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "source_packet_json": str(input_json_path),
            "source_packet_json_schema_version": packet_json.get("metadata", {}).get("schema_version"),
            "output_dir": str(output_dir),
            "grouping_policy": grouping_policy,
            "group_size_packets": group_size_packets,
            "flow_slide_window_overlap_packets": flow_slide_window_overlap_packets,
            "parent_group_count": parent_group_count,
            "parent_group_size_statistics": parent_group_stats,
            "prompt_unit_count": len(prompt_unit_summaries),
            "total_packet_count": len(packet_json["traffic"]),
            "compact_view_schema_version": PROMPT_UNIT_SCHEMA_VERSION,
            "payload_strategy_version": PAYLOAD_STRATEGY_VERSION,
            "token_budget_config": token_config,
            "input_token_budget": input_token_budget,
            "payload_mode_counts": dict(sorted(payload_mode_counts.items())),
            "immutable_fields": packet_json.get("immutable_fields", []),
        },
        "prompt_units": prompt_unit_summaries,
    }


#This function removes previous Step 15 output JSON files from the output directory.
def clear_previous_output_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("group_*.json"):
        path.unlink()
    manifest_path = output_dir / "group_manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()


#This function orchestrates Step 15.
def run_grouping(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    output_dir: str | Path | None,
    group_size_packets: int | None,
    heartbeat_seconds: int,
) -> dict[str, Any]:
    if heartbeat_seconds < 0:
        raise ValueError("--heartbeat-seconds must be zero or a positive integer.")

    config = load_json_config(config_path)
    validate_config(config)

    grouping_policy = str(config["pipeline"]["grouping_policy"]).strip()
    paths = default_paths(config)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    if grouping_policy == "fixed_packet_count":
        effective_group_size = group_size_packets or int(config["pipeline"]["group_size_packets"])
    else:
        effective_group_size = group_size_packets if group_size_packets is not None else config["pipeline"].get("group_size_packets")
        effective_group_size = int(effective_group_size) if effective_group_size is not None else None
    output_root_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    output_group_dir = output_root_dir / policy_output_subdir(grouping_policy, effective_group_size)
    token_config = get_token_budget_config(config)
    input_token_budget = compute_input_token_budget(token_config)
    flow_slide_window_overlap_packets = get_flow_slide_window_overlap_packets(config, grouping_policy)

    packet_json = validate_packet_json(read_json(input_json_path), input_json_path)
    traffic = packet_json["traffic"]
    parent_groups = group_records_by_policy(
        records=traffic,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
    )
    parent_group_stats = parent_group_size_statistics(parent_groups)
    start_time = time.monotonic()
    last_heartbeat_time = [start_time]

    def heartbeat(message: str, force: bool = False) -> None:
        if heartbeat_seconds <= 0:
            return
        current_time = time.monotonic()
        if force or current_time - last_heartbeat_time[0] >= heartbeat_seconds:
            elapsed_seconds = round(current_time - start_time, 1)
            print(f"Step 15 heartbeat: {message}, elapsed_seconds={elapsed_seconds}", flush=True)
            last_heartbeat_time[0] = current_time

    heartbeat(
        f"parent_groups_ready={len(parent_groups)}, "
        f"traffic_packets={len(traffic)}, "
        f"grouping_policy={grouping_policy}, "
        f"output_dir={output_group_dir}",
        force=True,
    )

    clear_previous_output_files(output_group_dir)
    prompt_unit_summaries = []
    payload_mode_counts: Counter[str] = Counter()
    experiment_id = config["experiment"]["experiment_id"]
    source_schema = str(packet_json.get("metadata", {}).get("schema_version", ""))

    for processed_parent_groups, parent_group in enumerate(parent_groups, start=1):
        records = parent_group["records"]
        heartbeat(
            f"processing_parent_group={parent_group['parent_group_id']}, "
            f"parent_group_index={processed_parent_groups}/{len(parent_groups)}, "
            f"parent_group_packets={len(records)}, "
            f"prompt_units_written={len(prompt_unit_summaries)}"
        )
        prompt_units = build_prompt_units_for_group(
            experiment_id=experiment_id,
            source_packet_json=input_json_path,
            source_packet_json_schema_version=source_schema,
            parent_group_id=parent_group["parent_group_id"],
            group_index=parent_group["group_index"],
            unit_type=parent_group["unit_type"],
            records=records,
            grouping_policy=grouping_policy,
            group_size_packets=effective_group_size,
            parent_group=parent_group,
            flow_slide_window_overlap_packets=flow_slide_window_overlap_packets,
            token_config=token_config,
            input_token_budget=input_token_budget,
            heartbeat=heartbeat,
        )
        for prompt_unit in prompt_units:
            for packet in prompt_unit["packets"]:
                payload_mode_counts[str(packet.get("payload_view", {}).get("mode", "unknown"))] += 1
            prompt_unit_path = output_group_dir / f"{prompt_unit['prompt_unit_id']}.json"
            write_json(prompt_unit_path, prompt_unit)
            prompt_unit_summaries.append(summarize_prompt_unit(prompt_unit, prompt_unit_path))
        heartbeat(
            f"processed_parent_groups={processed_parent_groups}/{len(parent_groups)}, "
            f"prompt_units_written={len(prompt_unit_summaries)}"
        )

    manifest = build_manifest(
        config=config,
        input_json_path=input_json_path,
        output_dir=output_group_dir,
        packet_json=packet_json,
        grouping_policy=grouping_policy,
        group_size_packets=effective_group_size,
        flow_slide_window_overlap_packets=flow_slide_window_overlap_packets,
        token_config=token_config,
        input_token_budget=input_token_budget,
        parent_group_count=len(parent_groups),
        parent_group_stats=parent_group_stats,
        prompt_unit_summaries=prompt_unit_summaries,
        payload_mode_counts=payload_mode_counts,
    )
    manifest_path = output_group_dir / "group_manifest.json"
    write_json(manifest_path, manifest)

    return {
        "manifest_path": str(manifest_path),
        "output_dir": str(output_group_dir),
        "parent_group_count": len(parent_groups),
        "prompt_unit_count": len(prompt_unit_summaries),
        "packet_count": len(traffic),
        "group_size_packets": effective_group_size,
        "flow_slide_window_overlap_packets": flow_slide_window_overlap_packets,
        "parent_group_size_statistics": parent_group_stats,
        "input_token_budget": input_token_budget,
    }


#This function defines the command-line arguments accepted by Step 15.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build compact LLM-facing prompt units from packet JSON records.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--input-json", help="Path to selected_packet_records.json.")
    parser.add_argument("--output-dir", help="Root directory for Step 15 outputs. The script creates a policy-specific subfolder inside it.")
    parser.add_argument("--group-size-packets", type=int, help="Override pipeline.group_size_packets.")
    parser.add_argument("--heartbeat-seconds", type=int, default=30, help="Print progress heartbeat every N seconds. Use 0 to disable.")
    return parser.parse_args()


#This is the command-line entry point. It runs the grouping/planning step and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    result = run_grouping(
        config_path=args.config,
        input_json=args.input_json,
        output_dir=args.output_dir,
        group_size_packets=args.group_size_packets,
        heartbeat_seconds=args.heartbeat_seconds,
    )
    print(f"Grouped packets: {result['packet_count']}")
    print(f"Parent group count: {result['parent_group_count']}")
    print(f"Prompt unit count: {result['prompt_unit_count']}")
    print(f"Group size packets: {result['group_size_packets']}")
    print(f"Input token budget: {result['input_token_budget']}")
    print(f"Output directory: {result['output_dir']}")
    print(f"Group manifest written to: {result['manifest_path']}")


if __name__ == "__main__":
    main()
