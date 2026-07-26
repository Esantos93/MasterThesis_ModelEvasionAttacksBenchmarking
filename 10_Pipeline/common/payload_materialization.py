from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


PAYLOAD_MATERIALIZATION_SCHEMA_VERSION = "canonical_payload_materialization_result_v1"
SUPPORTED_REPLACEMENT_FORMATS = {"hex", "text"}
SUPPORTED_PAYLOAD_OPERATIONS = {"replace_region", "replace_byte_range"}


#This function checks whether a value is valid even-length hexadecimal content.
def is_valid_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value) is not None


#This helper converts optional integer fields into deterministic sort values.
def sort_int(value: Any, default: int = -1) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


#This helper returns a stable list of unique string identifiers.
def stable_unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values))


#This helper extracts and validates a required integer field.
def require_int(container: dict[str, Any], field: str, *, minimum: int = 0, context: str = "payload edit") -> int:
    value = container.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{context}.{field} must be an integer >= {minimum}.")
    return value


#This helper extracts the normalized payload_hex and length for one packet.
def packet_payload(packet: dict[str, Any], packet_id: str) -> tuple[str, int]:
    payload_hex = packet.get("payload_hex", "")
    if not is_valid_hex(payload_hex):
        raise ValueError(f"payload_hex for packet {packet_id!r} is invalid.")
    normalized = str(payload_hex).lower()
    return normalized, len(normalized) // 2


#This helper rejects the old packet-local calling convention.
def normalize_original_packets(original_packets_by_id: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not isinstance(original_packets_by_id, dict):
        raise ValueError("original_packets_by_id must be a mapping from packet_id to original_packet.")
    if "packet_id" in original_packets_by_id and "payload_hex" in original_packets_by_id:
        raise ValueError(
            "materialize_payload_edits now requires a packet map; canonical payload edits must not be materialized packet-local."
        )
    normalized = {}
    for packet_id, packet in original_packets_by_id.items():
        if not isinstance(packet, dict):
            raise ValueError(f"original_packets_by_id[{packet_id!r}] must be a JSON object.")
        actual_packet_id = packet.get("packet_id")
        if actual_packet_id is None:
            raise ValueError(f"original packet {packet_id!r} is missing packet_id.")
        normalized[str(actual_packet_id)] = packet
    return normalized


#This helper returns an ordered copy of explicit canonical payload edits.
def ordered_payload_edits(explicit_payload_edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (deepcopy(edit) for edit in explicit_payload_edits),
        key=lambda edit: (
            str(edit.get("canonical_region_id", edit.get("region_id", ""))),
            sort_int(edit.get("canonical_start_offset_bytes")),
            str(edit.get("prompt_unit_id", "")),
            sort_int(edit.get("patch_index")),
        ),
    )


#This helper classifies two canonical payload edits in canonical-region coordinates.
def classify_payload_edit_relationship(previous_edit: dict[str, Any], current_edit: dict[str, Any]) -> dict[str, Any]:
    previous_region = previous_edit.get("canonical_region_id") or previous_edit.get("region_id")
    current_region = current_edit.get("canonical_region_id") or current_edit.get("region_id")
    if previous_region != current_region:
        return {"classification": "disjoint", "overlap_start_offset_bytes": None, "overlap_length_bytes": 0}

    previous_start = int(previous_edit["canonical_start_offset_bytes"])
    previous_end = previous_start + int(previous_edit["replaced_length_bytes"])
    current_start = int(current_edit["canonical_start_offset_bytes"])
    current_end = current_start + int(current_edit["replaced_length_bytes"])
    overlap_start = max(previous_start, current_start)
    overlap_end = min(previous_end, current_end)
    if overlap_start >= overlap_end:
        return {"classification": "disjoint", "overlap_start_offset_bytes": None, "overlap_length_bytes": 0}
    if (
        previous_start == current_start
        and previous_end == current_end
        and previous_edit.get("replacement_hex", "").lower() == current_edit.get("replacement_hex", "").lower()
    ):
        classification = "duplicate"
    elif (
        int(previous_edit.get("replacement_length_bytes", -1)) != int(previous_edit["replaced_length_bytes"])
        or int(current_edit.get("replacement_length_bytes", -1)) != int(current_edit["replaced_length_bytes"])
    ):
        classification = "unsupported_overlap"
    else:
        previous_relative_start = overlap_start - previous_start
        previous_relative_end = overlap_end - previous_start
        current_relative_start = overlap_start - current_start
        current_relative_end = overlap_end - current_start
        previous_overlap_hex = previous_edit.get("replacement_hex", "").lower()[
            previous_relative_start * 2 : previous_relative_end * 2
        ]
        current_overlap_hex = current_edit.get("replacement_hex", "").lower()[
            current_relative_start * 2 : current_relative_end * 2
        ]
        classification = "compatible_overlap" if previous_overlap_hex == current_overlap_hex else "contradictory_overlap"
    return {
        "classification": classification,
        "overlap_start_offset_bytes": overlap_start,
        "overlap_length_bytes": overlap_end - overlap_start,
    }


#This helper normalizes the physical packet aliases for one canonical payload region.
def normalize_packet_aliases(edit: dict[str, Any], original_packets_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    aliases = edit.get("packet_aliases")
    if not isinstance(aliases, list) or not aliases:
        raise ValueError("canonical payload edit must include a non-empty packet_aliases list.")

    normalized_aliases = []
    seen_alias_keys: set[tuple[str, int, int, int]] = set()
    for alias_index, alias in enumerate(aliases, start=1):
        if not isinstance(alias, dict):
            raise ValueError(f"packet_aliases[{alias_index}] must be a JSON object.")
        packet_id = alias.get("packet_id")
        if packet_id is None:
            raise ValueError(f"packet_aliases[{alias_index}].packet_id is required.")
        packet_id_text = str(packet_id)
        original_packet = original_packets_by_id.get(packet_id_text)
        if original_packet is None:
            raise ValueError(f"packet_aliases[{alias_index}] references packet_id {packet_id_text!r} outside Step 14.")
        canonical_start = require_int(alias, "canonical_start_offset_bytes", context=f"packet_aliases[{alias_index}]")
        payload_start = require_int(alias, "payload_start_offset_bytes", context=f"packet_aliases[{alias_index}]")
        length = require_int(alias, "length_bytes", context=f"packet_aliases[{alias_index}]")
        _payload_hex, payload_length = packet_payload(original_packet, packet_id_text)
        if payload_start + length > payload_length:
            raise ValueError(f"packet_aliases[{alias_index}] exceeds payload length for packet {packet_id_text!r}.")
        alias_key = (packet_id_text, canonical_start, payload_start, length)
        if alias_key in seen_alias_keys:
            continue
        seen_alias_keys.add(alias_key)
        normalized_alias = {
            "packet_id": packet_id_text,
            "alias_id": str(alias.get("alias_id", f"{packet_id_text}:payload@{payload_start}")),
            "canonical_region_id": str(alias.get("canonical_region_id", edit.get("canonical_region_id"))),
            "canonical_start_offset_bytes": canonical_start,
            "payload_start_offset_bytes": payload_start,
            "length_bytes": length,
        }
        for provenance_field in [
            "physical_representation_id",
            "stream_start",
            "stream_end",
            "packet_payload_offset_start_bytes",
            "packet_payload_offset_end_bytes",
        ]:
            if provenance_field in alias:
                normalized_alias[provenance_field] = deepcopy(alias[provenance_field])
        normalized_aliases.append(normalized_alias)
    return sorted(
        normalized_aliases,
        key=lambda item: (
            item["packet_id"],
            item["canonical_start_offset_bytes"],
            item["payload_start_offset_bytes"],
            item["length_bytes"],
        ),
    )


#This helper validates a normalized canonical edit against its authorized canonical bounds and aliases.
def validate_payload_edit(
    edit: dict[str, Any],
    edit_position: int,
    original_packets_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    prompt_unit_id = edit.get("prompt_unit_id")
    if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
        raise ValueError(f"explicit_payload_edits[{edit_position}].prompt_unit_id must be a non-empty string.")
    patch_index = require_int(edit, "patch_index", minimum=1, context=f"explicit_payload_edits[{edit_position}]")
    canonical_region_id = edit.get("canonical_region_id") or edit.get("region_id")
    if not isinstance(canonical_region_id, str) or not canonical_region_id:
        raise ValueError(f"explicit_payload_edits[{edit_position}].canonical_region_id must be a non-empty string.")
    representative_packet_id = edit.get("representative_packet_id") or edit.get("packet_id")
    if representative_packet_id is None:
        raise ValueError(f"explicit_payload_edits[{edit_position}].representative_packet_id is required.")
    representative_packet_id = str(representative_packet_id)
    if representative_packet_id not in original_packets_by_id:
        raise ValueError(f"representative_packet_id {representative_packet_id!r} is outside Step 14.")
    if edit.get("edit_kind") != "canonical_payload":
        raise ValueError(f"explicit_payload_edits[{edit_position}].edit_kind must be canonical_payload.")
    if edit.get("identity_type") != "canonical_payload_region":
        raise ValueError(f"explicit_payload_edits[{edit_position}].identity_type must be canonical_payload_region.")
    if edit.get("region_type") != "canonical_payload_region":
        raise ValueError(f"explicit_payload_edits[{edit_position}].region_type must be canonical_payload_region.")
    operation = edit.get("operation")
    if operation not in SUPPORTED_PAYLOAD_OPERATIONS:
        raise ValueError(f"Unsupported payload operation {operation!r}.")
    replacement_format = edit.get("replacement_format")
    if replacement_format not in SUPPORTED_REPLACEMENT_FORMATS:
        raise ValueError(f"Payload edit {patch_index} replacement_format is unsupported: {replacement_format!r}.")
    if not is_valid_hex(edit.get("replacement_hex")):
        raise ValueError(f"Payload edit {patch_index} replacement_hex is invalid.")
    replacement_hex = str(edit["replacement_hex"]).lower()
    replacement = edit.get("replacement")
    if replacement_format == "hex" and replacement is not None:
        if not is_valid_hex(replacement) or str(replacement).lower() != replacement_hex:
            raise ValueError(f"Payload edit {patch_index} replacement_hex is not coherent with hex replacement.")
    if replacement_format == "text":
        replacement_text = edit.get("replacement_text", replacement)
        if replacement_text is not None and str(replacement_text).encode("utf-8").hex() != replacement_hex:
            raise ValueError(f"Payload edit {patch_index} replacement_hex is not coherent with text replacement.")

    authorized_start = require_int(edit, "authorized_canonical_start_offset_bytes", context=f"explicit_payload_edits[{edit_position}]")
    authorized_length = require_int(edit, "authorized_canonical_length_bytes", context=f"explicit_payload_edits[{edit_position}]")
    region_start = require_int(edit, "canonical_region_start_offset_bytes", context=f"explicit_payload_edits[{edit_position}]")
    region_length = require_int(edit, "canonical_region_length_bytes", context=f"explicit_payload_edits[{edit_position}]")
    if authorized_start < region_start or authorized_start + authorized_length > region_start + region_length:
        raise ValueError(f"Payload edit {patch_index} authorized bounds exceed the canonical region.")

    if operation == "replace_region":
        canonical_start = authorized_start
        replaced_length = authorized_length
        local_offset = 0
    else:
        local_offset = require_int(edit, "offset_from_region_start_bytes", context=f"explicit_payload_edits[{edit_position}]")
        replaced_length = require_int(edit, "replaced_length_bytes", context=f"explicit_payload_edits[{edit_position}]")
        if local_offset + replaced_length > authorized_length:
            raise ValueError(f"Payload edit {patch_index} exceeds authorized canonical bounds.")
        canonical_start = authorized_start + local_offset

    declared_canonical_start = edit.get("canonical_start_offset_bytes")
    if declared_canonical_start is not None and declared_canonical_start != canonical_start:
        raise ValueError(f"Payload edit {patch_index} canonical_start_offset_bytes does not match authorized bounds.")
    declared_replaced_length = edit.get("replaced_length_bytes")
    if declared_replaced_length is not None and declared_replaced_length != replaced_length:
        raise ValueError(f"Payload edit {patch_index} replaced_length_bytes does not match operation bounds.")
    replacement_length = edit.get("replacement_length_bytes")
    if replacement_length is not None and (not isinstance(replacement_length, int) or isinstance(replacement_length, bool)):
        raise ValueError(f"Payload edit {patch_index} replacement_length_bytes must be an integer when present.")
    if isinstance(replacement_length, int) and not isinstance(replacement_length, bool) and replacement_length != len(replacement_hex) // 2:
        raise ValueError(f"Payload edit {patch_index} replacement_length_bytes does not match replacement_hex.")

    aliases = normalize_packet_aliases(edit, original_packets_by_id)
    target_end = canonical_start + replaced_length
    alias_original_segments = []
    for alias in aliases:
        alias_start = alias["canonical_start_offset_bytes"]
        alias_end = alias_start + alias["length_bytes"]
        if canonical_start < alias_start or target_end > alias_end:
            raise ValueError(
                f"Payload edit {patch_index} target range is not fully covered by alias {alias['alias_id']!r}."
            )
        original_packet = original_packets_by_id[alias["packet_id"]]
        payload_hex, _payload_length = packet_payload(original_packet, alias["packet_id"])
        relative_start = canonical_start - alias_start
        payload_start = alias["payload_start_offset_bytes"] + relative_start
        original_segment_hex = payload_hex[payload_start * 2 : (payload_start + replaced_length) * 2]
        alias_original_segments.append(original_segment_hex)
    if len(set(alias_original_segments)) > 1:
        raise ValueError(f"Payload edit {patch_index} aliases do not expose the same original canonical bytes.")

    original_segment_hex = alias_original_segments[0] if alias_original_segments else ""
    normalized_edit = deepcopy(edit)
    normalized_edit.update(
        {
            "edit_kind": "canonical_payload",
            "identity_type": "canonical_payload_region",
            "region_type": "canonical_payload_region",
            "packet_id": representative_packet_id,
            "representative_packet_id": representative_packet_id,
            "canonical_region_id": canonical_region_id,
            "region_id": str(edit.get("region_id", canonical_region_id)),
            "operation": operation,
            "replacement_format": replacement_format,
            "replacement_hex": replacement_hex,
            "replacement_length_bytes": len(replacement_hex) // 2,
            "canonical_region_start_offset_bytes": region_start,
            "canonical_region_length_bytes": region_length,
            "authorized_canonical_start_offset_bytes": authorized_start,
            "authorized_canonical_length_bytes": authorized_length,
            "canonical_start_offset_bytes": canonical_start,
            "replaced_length_bytes": replaced_length,
            "offset_from_region_start_bytes": local_offset,
            "packet_aliases": aliases,
            "patch_index": patch_index,
            "prompt_unit_id": prompt_unit_id,
            "materialization_sequence_index": edit_position,
            "original_segment_hex": original_segment_hex,
            "no_effect": original_segment_hex == replacement_hex,
        }
    )
    if replacement_format == "text" and "replacement_text" not in normalized_edit and replacement is not None:
        normalized_edit["replacement_text"] = str(replacement)
    return normalized_edit


#This helper builds one physical projection record for a canonical payload edit.
def build_projection_change(
    *,
    edit: dict[str, Any],
    alias: dict[str, Any],
    original_packet: dict[str, Any],
) -> dict[str, Any]:
    canonical_start = int(edit["canonical_start_offset_bytes"])
    alias_start = int(alias["canonical_start_offset_bytes"])
    relative_start = canonical_start - alias_start
    payload_start = int(alias["payload_start_offset_bytes"]) + relative_start
    replaced_length = int(edit["replaced_length_bytes"])
    payload_hex, _payload_length = packet_payload(original_packet, alias["packet_id"])
    original_segment_hex = payload_hex[payload_start * 2 : (payload_start + replaced_length) * 2]
    replacement_length = int(edit["replacement_length_bytes"])
    return {
        "edit_kind": "canonical_payload_projection",
        "packet_id": alias["packet_id"],
        "alias_id": alias["alias_id"],
        "physical_representation_id": alias.get("physical_representation_id"),
        "canonical_region_id": edit["canonical_region_id"],
        "region_id": edit["region_id"],
        "semantic_element_id": edit.get("semantic_element_id"),
        "canonical_window_id": edit.get("canonical_window_id"),
        "representative_packet_id": edit["representative_packet_id"],
        "prompt_unit_id": edit["prompt_unit_id"],
        "parent_group_id": edit.get("parent_group_id"),
        "patch_index": edit["patch_index"],
        "canonical_start_offset_bytes": canonical_start,
        "stream_start": alias.get("stream_start"),
        "stream_end": alias.get("stream_end"),
        "replaced_length_bytes": replaced_length,
        "replacement_length_bytes": replacement_length,
        "payload_start_offset_bytes": payload_start,
        "packet_payload_offset_start_bytes": alias.get("packet_payload_offset_start_bytes"),
        "packet_payload_offset_end_bytes": alias.get("packet_payload_offset_end_bytes"),
        "payload_length_delta_bytes": replacement_length - replaced_length,
        "original_segment_hex": original_segment_hex,
        "replacement_hex": edit["replacement_hex"],
        "requires_pipeline_recalculation": [
            "ipv4.total_length",
            "ipv4.checksum",
            "tcp.checksum",
            "tcp.seq_ack_length_projection",
        ],
    }


#This function materializes canonical payload edits once and projects them to every authorized physical alias.
def materialize_payload_edits(
    original_packets_by_id: dict[str, dict[str, Any]],
    explicit_payload_edits: list[dict[str, Any]],
) -> dict[str, Any]:
    original_packets = normalize_original_packets(original_packets_by_id)
    if not isinstance(explicit_payload_edits, list):
        raise ValueError("explicit_payload_edits must be a list.")

    output_packets_by_id = {packet_id: deepcopy(packet) for packet_id, packet in original_packets.items()}
    ordered_edits = ordered_payload_edits(explicit_payload_edits)
    validated_edits = [
        validate_payload_edit(edit, edit_position, original_packets)
        for edit_position, edit in enumerate(ordered_edits, start=1)
    ]

    materialization_issues: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for current_position, current_edit in enumerate(validated_edits):
        for previous_edit in validated_edits[:current_position]:
            classified = classify_payload_edit_relationship(previous_edit, current_edit)
            if classified["classification"] == "disjoint":
                continue
            relationship = {
                "canonical_region_id": current_edit["canonical_region_id"],
                "previous_prompt_unit_id": previous_edit["prompt_unit_id"],
                "prompt_unit_id": current_edit["prompt_unit_id"],
                "previous_patch_index": previous_edit["patch_index"],
                "patch_index": current_edit["patch_index"],
                "previous_region_id": previous_edit.get("region_id"),
                "region_id": current_edit.get("region_id"),
                "classification": classified["classification"],
                "overlap_start_offset_bytes": classified["overlap_start_offset_bytes"],
                "overlap_length_bytes": classified["overlap_length_bytes"],
            }
            relationships.append(relationship)
            if classified["classification"] in {"contradictory_overlap", "unsupported_overlap"}:
                reason = (
                    "unsupported_payload_overlap"
                    if classified["classification"] == "unsupported_overlap"
                    else "contradictory_payload_overlap"
                )
                materialization_issues.append(
                    {
                        "severity": "error",
                        "reason": reason,
                        **relationship,
                    }
                )

    blocking_overlap = any(issue.get("severity") == "error" for issue in materialization_issues)
    applied_signatures: set[tuple[str, int, int, str]] = set()
    effective_edits: list[dict[str, Any]] = []
    no_effect_edits: list[dict[str, Any]] = []
    projection_changes: list[dict[str, Any]] = []

    if not blocking_overlap:
        materialization_edits = []
        for edit in validated_edits:
            signature = (
                edit["canonical_region_id"],
                int(edit["canonical_start_offset_bytes"]),
                int(edit["replaced_length_bytes"]),
                str(edit["replacement_hex"]),
            )
            if signature in applied_signatures:
                duplicate_edit = deepcopy(edit)
                duplicate_edit["duplicate_suppressed"] = True
                duplicate_edit["no_effect"] = True
                duplicate_edit["no_effect_reason"] = "duplicate_canonical_payload_edit_suppressed"
                no_effect_edits.append(duplicate_edit)
                continue
            applied_signatures.add(signature)
            if edit["no_effect"]:
                no_effect_edits.append(deepcopy(edit))
            else:
                effective_edits.append(deepcopy(edit))
                materialization_edits.append(edit)

        packet_projection_edits: dict[str, list[dict[str, Any]]] = {}
        for edit in materialization_edits:
            for alias in edit["packet_aliases"]:
                projection = build_projection_change(
                    edit=edit,
                    alias=alias,
                    original_packet=original_packets[alias["packet_id"]],
                )
                packet_projection_edits.setdefault(alias["packet_id"], []).append(projection)
                projection_changes.append(projection)

        for packet_id, projections in packet_projection_edits.items():
            payload_hex, old_payload_length = packet_payload(output_packets_by_id[packet_id], packet_id)
            for projection in sorted(
                projections,
                key=lambda item: (
                    int(item["payload_start_offset_bytes"]),
                    int(item["replaced_length_bytes"]),
                    str(item["prompt_unit_id"]),
                    int(item["patch_index"]),
                ),
                reverse=True,
            ):
                start_hex = int(projection["payload_start_offset_bytes"]) * 2
                end_hex = start_hex + int(projection["replaced_length_bytes"]) * 2
                payload_hex = payload_hex[:start_hex] + projection["replacement_hex"] + payload_hex[end_hex:]
            new_payload_length = len(payload_hex) // 2
            delta = new_payload_length - old_payload_length
            output_packets_by_id[packet_id]["payload_hex"] = payload_hex
            output_packets_by_id[packet_id]["payload_length_bytes"] = new_payload_length
            if isinstance(output_packets_by_id[packet_id].get("packet_length_bytes"), int):
                output_packets_by_id[packet_id]["packet_length_bytes"] = int(output_packets_by_id[packet_id]["packet_length_bytes"]) + delta

    else:
        no_effect_edits = [deepcopy(edit) for edit in validated_edits if edit["no_effect"]]

    return {
        "schema_version": PAYLOAD_MATERIALIZATION_SCHEMA_VERSION,
        "materialized_packets_by_id": output_packets_by_id,
        "explicit_edits": validated_edits,
        "applied_patches": effective_edits,
        "no_effect_edits": no_effect_edits,
        "derived_payload_projection_changes": sorted(
            projection_changes,
            key=lambda item: (
                item["packet_id"],
                item["payload_start_offset_bytes"],
                item["canonical_region_id"],
                item["prompt_unit_id"],
                item["patch_index"],
            ),
        ),
        "explicit_edit_relationships": sorted(
            relationships,
            key=lambda item: (
                item["canonical_region_id"],
                item["previous_patch_index"],
                item["patch_index"],
                item["classification"],
            ),
        ),
        "materialization_issues": sorted(
            materialization_issues,
            key=lambda item: (
                item.get("canonical_region_id", ""),
                item.get("previous_patch_index", -1),
                item.get("patch_index", -1),
                item.get("reason", ""),
            ),
        ),
    }
