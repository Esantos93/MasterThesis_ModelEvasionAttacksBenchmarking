from __future__ import annotations

import math
from typing import Any

from common.token_budget import compute_payload_replacement_limit_bytes


PAYLOAD_OWNERSHIP_POLICY = "first_physical_alias_capture_order_v1"
PAYLOAD_SEGMENTATION_POLICY = "semantic_first_adaptive_fallback_v1"
APPLICATION_SEMANTIC_ELEMENTS_FIELD = "application_semantic_elements"


def payload_bytes(record: dict[str, Any]) -> bytes:
    payload_hex = str(record.get("payload_hex", "") or "")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise ValueError(
            f"Canonical region {record.get('canonical_region_id')!r} contains invalid payload_hex."
        ) from exc
    expected_length = int(record.get("payload_length_bytes", record.get("length", 0)) or 0)
    if len(payload) != expected_length:
        raise ValueError(
            f"Canonical region {record.get('canonical_region_id')!r} payload length mismatch: "
            f"declared={expected_length}, decoded={len(payload)}."
        )
    return payload


def _semantic_element(record: dict[str, Any], raw: dict[str, Any], index: int) -> dict[str, Any]:
    region_id = str(record["canonical_region_id"])
    element_id = str(raw.get("semantic_element_id", "")).strip()
    semantic_type = str(raw.get("semantic_type", "")).strip()
    if not element_id or not semantic_type:
        raise ValueError(
            f"Canonical region {region_id!r} application semantic element {index} "
            "requires semantic_element_id and semantic_type."
        )
    start = int(raw.get("start_offset_bytes", -1))
    end = int(raw.get("end_offset_bytes", -1))
    if start < 0 or end <= start:
        raise ValueError(
            f"Canonical region {region_id!r} semantic element {element_id!r} has invalid byte bounds."
        )
    return {
        "kind": "semantic_element",
        "semantic_element_id": element_id,
        "semantic_type": semantic_type,
        "start_offset_bytes": start,
        "end_offset_bytes": end,
    }


def build_semantic_partitions(record: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload_length = int(record.get("payload_length_bytes", record.get("length", 0)) or 0)
    raw_elements = record.get(APPLICATION_SEMANTIC_ELEMENTS_FIELD)
    if raw_elements is None:
        return (
            [
                {
                    "kind": "fallback",
                    "start_offset_bytes": 0,
                    "end_offset_bytes": payload_length,
                    "fallback_reason": "source_semantics_unavailable",
                }
            ]
            if payload_length
            else [],
            {
                "policy": PAYLOAD_SEGMENTATION_POLICY,
                "semantic_segmentation_status": "source_semantics_unavailable",
                "semantic_source_field": APPLICATION_SEMANTIC_ELEMENTS_FIELD,
            },
        )
    if not isinstance(raw_elements, list) or not raw_elements:
        raise ValueError(
            f"Canonical region {record.get('canonical_region_id')!r} has an invalid "
            f"{APPLICATION_SEMANTIC_ELEMENTS_FIELD} value."
        )

    elements = sorted(
        (
            _semantic_element(record, raw, index)
            for index, raw in enumerate(raw_elements, start=1)
            if isinstance(raw, dict)
        ),
        key=lambda item: (
            int(item["start_offset_bytes"]),
            int(item["end_offset_bytes"]),
            str(item["semantic_element_id"]),
        ),
    )
    if len(elements) != len(raw_elements):
        raise ValueError(
            f"Canonical region {record.get('canonical_region_id')!r} contains a non-object semantic element."
        )

    partitions: list[dict[str, Any]] = []
    cursor = 0
    for element in elements:
        start = int(element["start_offset_bytes"])
        end = int(element["end_offset_bytes"])
        if end > payload_length:
            raise ValueError(
                f"Canonical region {record.get('canonical_region_id')!r} semantic element "
                f"{element['semantic_element_id']!r} exceeds the canonical payload."
            )
        if start < cursor:
            raise ValueError(
                f"Canonical region {record.get('canonical_region_id')!r} has overlapping semantic elements."
            )
        if start > cursor:
            partitions.append(
                {
                    "kind": "fallback",
                    "start_offset_bytes": cursor,
                    "end_offset_bytes": start,
                    "fallback_reason": "semantic_coverage_gap",
                }
            )
        partitions.append(element)
        cursor = end
    if cursor < payload_length:
        partitions.append(
            {
                "kind": "fallback",
                "start_offset_bytes": cursor,
                "end_offset_bytes": payload_length,
                "fallback_reason": "semantic_coverage_gap",
            }
        )
    return partitions, {
        "policy": PAYLOAD_SEGMENTATION_POLICY,
        "semantic_segmentation_status": "explicit_source_semantics",
        "semantic_source_field": APPLICATION_SEMANTIC_ELEMENTS_FIELD,
        "semantic_element_count": len(elements),
    }


def balanced_contiguous_ranges(
    *,
    start_offset_bytes: int,
    end_offset_bytes: int,
    maximum_bytes_available_per_window: int,
) -> list[tuple[int, int]]:
    total_editable_bytes = end_offset_bytes - start_offset_bytes
    if total_editable_bytes < 0:
        raise ValueError("Adaptive payload range end must not precede its start.")
    if total_editable_bytes == 0:
        return []
    if maximum_bytes_available_per_window <= 0:
        raise ValueError("maximum_bytes_available_per_window must be positive.")

    window_count = math.ceil(total_editable_bytes / maximum_bytes_available_per_window)
    base_size, remainder = divmod(total_editable_bytes, window_count)
    ranges: list[tuple[int, int]] = []
    cursor = start_offset_bytes
    for window_index in range(window_count):
        size = base_size + (1 if window_index < remainder else 0)
        ranges.append((cursor, cursor + size))
        cursor += size
    if cursor != end_offset_bytes:
        raise AssertionError("Adaptive payload ranges do not cover the requested interval.")
    return ranges


def build_payload_entry(
    *,
    record: dict[str, Any],
    start_offset_bytes: int,
    end_offset_bytes: int,
    mode: str,
    provenance: dict[str, Any],
    range_index: int,
    range_count: int,
    left_context_bytes: int,
    right_context_bytes: int,
    payload_replacement_size_policy: dict[str, Any],
    anchor_group_fragment_id: str,
) -> dict[str, Any]:
    payload = payload_bytes(record)
    payload_length = len(payload)
    if start_offset_bytes < 0 or end_offset_bytes <= start_offset_bytes or end_offset_bytes > payload_length:
        raise ValueError(
            f"Canonical region {record.get('canonical_region_id')!r} has invalid editable bounds "
            f"[{start_offset_bytes}, {end_offset_bytes})."
        )

    canonical_region_id = str(record["canonical_region_id"])
    editable_bytes = payload[start_offset_bytes:end_offset_bytes]
    context_start = max(0, start_offset_bytes - left_context_bytes)
    context_end = min(payload_length, end_offset_bytes + right_context_bytes)
    region_type = (
        "canonical_payload_region"
        if start_offset_bytes == 0 and end_offset_bytes == payload_length
        else "canonical_payload_semantic_element"
        if mode == "semantic_element"
        else "canonical_payload_byte_range"
    )
    operation = "replace_region" if region_type == "canonical_payload_region" else "replace_byte_range"
    region_id = f"{canonical_region_id}:bytes_{start_offset_bytes:08d}_{end_offset_bytes:08d}"
    replacement_limit = compute_payload_replacement_limit_bytes(
        original_size_bytes=len(editable_bytes),
        policy=payload_replacement_size_policy,
    )

    payload_view: dict[str, Any] = {
        "mode": mode,
        "representation": "hex",
        "payload_length_bytes": payload_length,
        "editable_start_offset_bytes": start_offset_bytes,
        "editable_end_offset_bytes": end_offset_bytes,
        "editable_value": editable_bytes.hex(),
    }
    if context_start < start_offset_bytes:
        payload_view["left_context"] = {
            "start_offset_bytes": context_start,
            "end_offset_bytes": start_offset_bytes,
            "value": payload[context_start:start_offset_bytes].hex(),
        }
    if end_offset_bytes < context_end:
        payload_view["right_context"] = {
            "start_offset_bytes": end_offset_bytes,
            "end_offset_bytes": context_end,
            "value": payload[end_offset_bytes:context_end].hex(),
        }

    physical_aliases = record.get("physical_aliases", [])
    if not isinstance(physical_aliases, list) or not physical_aliases:
        raise ValueError(f"Canonical region {canonical_region_id!r} has no physical alias context.")

    segmentation = {
        "policy": PAYLOAD_SEGMENTATION_POLICY,
        "mode": mode,
        "range_index": range_index,
        "range_count": range_count,
        **provenance,
    }
    ownership = {
        "policy": PAYLOAD_OWNERSHIP_POLICY,
        "representative_packet_id": str(record["representative_packet_id"]),
        "owner_parent_group_id": str(record["owner_parent_group_id"]),
        "anchor_group_fragment_id": anchor_group_fragment_id,
    }
    return {
        "canonical_region_id": canonical_region_id,
        "role": "editable_owner",
        "editable": True,
        "payload_length_bytes": payload_length,
        "tcp_connection_id": record.get("tcp_connection_id"),
        "tcp_stream_id": record.get("tcp_stream_id"),
        "stream_start": int(record.get("stream_start") or 0),
        "stream_end": int(record.get("stream_end") or 0),
        "ownership": ownership,
        "semantic_segmentation": segmentation,
        "physical_aliases": physical_aliases,
        "global_region_summary": {
            "payload_length_bytes": payload_length,
            "canonical_stream_start": int(record.get("stream_start") or 0),
            "canonical_stream_end": int(record.get("stream_end") or 0),
            "physical_alias_count": len(physical_aliases),
        },
        "payload_view": payload_view,
        "editable_regions": [
            {
                "canonical_region_id": canonical_region_id,
                "region_id": region_id,
                "region_type": region_type,
                "coordinate_space": "canonical_tcp_region",
                "start_offset_bytes": start_offset_bytes,
                "end_offset_bytes": end_offset_bytes,
                "length_bytes": len(editable_bytes),
                "format": "hex",
                "allowed_operations": [operation],
                "editable": True,
                "value": editable_bytes.hex(),
                "authorized_start_offset_bytes": start_offset_bytes,
                "authorized_end_offset_bytes": end_offset_bytes,
                "authorized_length_bytes": len(editable_bytes),
                "max_replacement_bytes": int(replacement_limit["effective_limit_bytes"]),
                "max_replacement_hex_chars": int(replacement_limit["effective_limit_hex_chars"]),
                "replacement_size_policy": str(replacement_limit["policy"]),
                "replacement_size_limit": replacement_limit,
            }
        ],
    }


def payload_entry_interval(entry: dict[str, Any]) -> tuple[str, int, int]:
    editable_regions = entry.get("editable_regions", [])
    if not isinstance(editable_regions, list) or len(editable_regions) != 1:
        raise ValueError("Each V3 canonical payload entry must contain exactly one editable region.")
    region = editable_regions[0]
    return (
        str(entry["canonical_region_id"]),
        int(region["start_offset_bytes"]),
        int(region["end_offset_bytes"]),
    )


def validate_canonical_payload_coverage(
    *,
    entries: list[dict[str, Any]],
    canonical_records: list[dict[str, Any]],
) -> dict[str, Any]:
    intervals_by_region: dict[str, list[tuple[int, int]]] = {}
    for entry in entries:
        region_id, start, end = payload_entry_interval(entry)
        intervals_by_region.setdefault(region_id, []).append((start, end))

    editable_byte_count = 0
    for record in canonical_records:
        region_id = str(record["canonical_region_id"])
        payload_length = int(record.get("payload_length_bytes", record.get("length", 0)) or 0)
        intervals = sorted(intervals_by_region.pop(region_id, []))
        if payload_length == 0:
            if intervals:
                raise ValueError(f"Empty canonical region {region_id!r} unexpectedly has editable intervals.")
            continue
        cursor = 0
        for start, end in intervals:
            if start != cursor:
                relationship = "overlap" if start < cursor else "gap"
                raise ValueError(
                    f"Canonical payload ownership {relationship} for region {region_id!r}: "
                    f"expected_start={cursor}, actual_start={start}."
                )
            if end <= start or end > payload_length:
                raise ValueError(f"Canonical payload interval for region {region_id!r} is out of bounds.")
            editable_byte_count += end - start
            cursor = end
        if cursor != payload_length:
            raise ValueError(
                f"Canonical payload ownership gap for region {region_id!r}: "
                f"covered={cursor}, expected={payload_length}."
            )
    if intervals_by_region:
        raise ValueError(
            f"V3 payload entries reference unknown canonical regions: {sorted(intervals_by_region)[:10]}"
        )
    return {
        "canonical_region_count": len(canonical_records),
        "editable_canonical_region_count": sum(
            int(record.get("payload_length_bytes", record.get("length", 0)) or 0) > 0
            for record in canonical_records
        ),
        "editable_canonical_payload_byte_count": editable_byte_count,
        "duplicate_editable_byte_count": 0,
        "missing_editable_byte_count": 0,
        "overlapping_editable_interval_count": 0,
    }
