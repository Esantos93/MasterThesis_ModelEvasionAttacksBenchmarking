from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


PAYLOAD_MATERIALIZATION_SCHEMA_VERSION = "payload_materialization_result_v1"


#This function checks whether a string is valid even-length hexadecimal content.
def is_valid_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value) is not None


#This helper converts optional integer fields into deterministic sort values.
def sort_int(value: Any, default: int = -1) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


#This helper returns an ordered copy of explicit payload edits.
def ordered_payload_edits(explicit_payload_edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (deepcopy(edit) for edit in explicit_payload_edits),
        key=lambda edit: (
            str(edit.get("prompt_unit_id", "")),
            sort_int(edit.get("patch_index")),
            sort_int(edit.get("absolute_start_offset_bytes")),
            str(edit.get("region_id", "")),
        ),
    )


#This helper classifies two payload edits that touch the same original packet bytes.
def classify_payload_edit_relationship(previous_edit: dict[str, Any], current_edit: dict[str, Any]) -> dict[str, Any]:
    previous_start = int(previous_edit["absolute_start_offset_bytes"])
    previous_end = previous_start + int(previous_edit["replaced_length_bytes"])
    current_start = int(current_edit["absolute_start_offset_bytes"])
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
        classification = (
            "compatible_overlap"
            if previous_overlap_hex == current_overlap_hex
            else "contradictory_overlap"
        )
    return {
        "classification": classification,
        "overlap_start_offset_bytes": overlap_start,
        "overlap_length_bytes": overlap_end - overlap_start,
    }


#This function validates and materializes canonical payload edits over a copied original packet.
def materialize_payload_edits(original_packet: dict[str, Any], explicit_payload_edits: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(original_packet, dict):
        raise ValueError("original_packet must be a JSON object.")
    if not isinstance(explicit_payload_edits, list):
        raise ValueError("explicit_payload_edits must be a list.")
    packet_id = original_packet.get("packet_id")
    if packet_id is None:
        raise ValueError("original_packet.packet_id is required.")
    packet_id_text = str(packet_id)
    original_payload_hex = original_packet.get("payload_hex", "")
    if not is_valid_hex(original_payload_hex):
        raise ValueError(f"Original payload_hex for packet {packet_id_text!r} is invalid.")
    original_payload_hex = str(original_payload_hex).lower()
    original_payload_length = len(original_payload_hex) // 2

    ordered_edits = ordered_payload_edits(explicit_payload_edits)
    seen_patch_keys: set[tuple[str, int]] = set()
    validated_edits: list[dict[str, Any]] = []
    materialization_issues: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    for edit_position, edit in enumerate(ordered_edits, start=1):
        patch_index = edit.get("patch_index")
        if not isinstance(patch_index, int) or isinstance(patch_index, bool) or patch_index <= 0:
            raise ValueError(f"explicit_payload_edits[{edit_position}].patch_index must be a positive integer.")

        edit_packet_id = edit.get("packet_id")
        if edit_packet_id is not None and str(edit_packet_id) != packet_id_text:
            raise ValueError(f"Payload edit packet_id {edit_packet_id!r} does not match original packet {packet_id_text!r}.")
        prompt_unit_id = edit.get("prompt_unit_id")
        if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
            raise ValueError(f"explicit_payload_edits[{edit_position}].prompt_unit_id must be a non-empty string.")
        patch_key = (prompt_unit_id, patch_index)
        if patch_key in seen_patch_keys:
            raise ValueError(f"Duplicate patch key {patch_key!r} for packet {packet_id_text!r}.")
        seen_patch_keys.add(patch_key)
        if edit.get("edit_kind") != "canonical_payload":
            raise ValueError(f"explicit_payload_edits[{edit_position}].edit_kind must be canonical_payload.")
        if edit.get("operation") not in {"replace_region", "replace_byte_range"}:
            raise ValueError(f"Unsupported payload operation {edit.get('operation')!r}.")
        replacement_format = edit.get("replacement_format")
        if replacement_format not in {"hex", "text"}:
            raise ValueError(f"Payload edit {patch_index} replacement_format is unsupported: {replacement_format!r}.")
        if not is_valid_hex(edit.get("replacement_hex")):
            raise ValueError(f"Payload edit {patch_index} replacement_hex is invalid.")
        start = edit.get("absolute_start_offset_bytes")
        replaced_length = edit.get("replaced_length_bytes")
        if not isinstance(start, int) or isinstance(start, bool) or start < 0:
            raise ValueError(f"Payload edit {patch_index} absolute_start_offset_bytes is invalid.")
        if not isinstance(replaced_length, int) or isinstance(replaced_length, bool) or replaced_length < 0:
            raise ValueError(f"Payload edit {patch_index} replaced_length_bytes is invalid.")
        if start + replaced_length > original_payload_length:
            raise ValueError(f"Payload edit {patch_index} exceeds original payload length.")
        region_start = edit.get("authorized_region_start_offset_bytes")
        region_length = edit.get("authorized_region_length_bytes")
        if not isinstance(region_start, int) or isinstance(region_start, bool) or region_start < 0:
            raise ValueError(f"Payload edit {patch_index} authorized_region_start_offset_bytes is invalid.")
        if not isinstance(region_length, int) or isinstance(region_length, bool) or region_length < 0:
            raise ValueError(f"Payload edit {patch_index} authorized_region_length_bytes is invalid.")
        if region_start + region_length > original_payload_length:
            raise ValueError(f"Payload edit {patch_index} authorized region exceeds original payload length.")
        if edit.get("operation") == "replace_region":
            if start != region_start or replaced_length != region_length:
                raise ValueError(f"Payload edit {patch_index} replace_region does not match authorized region bounds.")
        else:
            local_offset = edit.get("offset_from_region_start_bytes")
            if not isinstance(local_offset, int) or isinstance(local_offset, bool) or local_offset < 0:
                raise ValueError(f"Payload edit {patch_index} offset_from_region_start_bytes is invalid.")
            if start != region_start + local_offset:
                raise ValueError(f"Payload edit {patch_index} absolute offset does not match authorized local offset.")
            if local_offset + replaced_length > region_length:
                raise ValueError(f"Payload edit {patch_index} exceeds authorized region bounds.")
        replacement_hex = str(edit["replacement_hex"]).lower()
        replacement_length = edit.get("replacement_length_bytes")
        if replacement_length is not None and (not isinstance(replacement_length, int) or isinstance(replacement_length, bool)):
            raise ValueError(f"Payload edit {patch_index} replacement_length_bytes must be an integer when present.")
        if isinstance(replacement_length, int) and not isinstance(replacement_length, bool) and replacement_length != len(replacement_hex) // 2:
            raise ValueError(f"Payload edit {patch_index} replacement_length_bytes does not match replacement_hex.")
        edit_record = deepcopy(edit)
        edit_record["packet_id"] = packet_id_text
        edit_record["replacement_hex"] = replacement_hex
        edit_record["replacement_length_bytes"] = len(replacement_hex) // 2
        edit_record["materialization_sequence_index"] = len(validated_edits) + 1
        edit_record["original_segment_hex"] = original_payload_hex[start * 2 : (start + replaced_length) * 2]
        edit_record["no_effect"] = edit_record["original_segment_hex"] == replacement_hex
        validated_edits.append(edit_record)

    blocking_overlap = False
    for current_position, current_edit in enumerate(validated_edits):
        for previous_edit in validated_edits[:current_position]:
            classified = classify_payload_edit_relationship(previous_edit, current_edit)
            if classified["classification"] == "disjoint":
                continue
            relationship = {
                "packet_id": packet_id_text,
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
                blocking_overlap = True
                issue_reason = (
                    "unsupported_payload_overlap"
                    if classified["classification"] == "unsupported_overlap"
                    else "contradictory_payload_overlap"
                )
                materialization_issues.append(
                    {
                        "severity": "error",
                        "reason": issue_reason,
                        **relationship,
                    }
                )

    materialized_packet = deepcopy(original_packet)
    applied_signatures: set[tuple[int, int, str]] = set()
    if not blocking_overlap:
        payload_hex = original_payload_hex
        materialization_edits = []
        for edit in validated_edits:
            signature = (
                int(edit["absolute_start_offset_bytes"]),
                int(edit["replaced_length_bytes"]),
                str(edit["replacement_hex"]),
            )
            if signature in applied_signatures:
                edit["duplicate_suppressed"] = True
                edit["no_effect"] = True
                edit["no_effect_reason"] = "duplicate_payload_edit_suppressed"
                continue
            applied_signatures.add(signature)
            materialization_edits.append(edit)
        for edit in sorted(materialization_edits, key=lambda item: int(item["absolute_start_offset_bytes"]), reverse=True):
            start_hex = int(edit["absolute_start_offset_bytes"]) * 2
            end_hex = start_hex + int(edit["replaced_length_bytes"]) * 2
            payload_hex = payload_hex[:start_hex] + edit["replacement_hex"] + payload_hex[end_hex:]
        old_payload_length = original_payload_length
        new_payload_length = len(payload_hex) // 2
        delta = new_payload_length - old_payload_length
        materialized_packet["payload_hex"] = payload_hex
        materialized_packet["payload_length_bytes"] = new_payload_length
        if isinstance(materialized_packet.get("packet_length_bytes"), int):
            materialized_packet["packet_length_bytes"] = int(materialized_packet["packet_length_bytes"]) + delta

    applied_patches = [] if blocking_overlap else [deepcopy(edit) for edit in validated_edits if not edit["no_effect"]]
    no_effect_edits = [deepcopy(edit) for edit in validated_edits if edit["no_effect"]]
    return {
        "schema_version": PAYLOAD_MATERIALIZATION_SCHEMA_VERSION,
        "materialized_packet": materialized_packet,
        "explicit_edits": validated_edits,
        "applied_patches": applied_patches,
        "no_effect_edits": no_effect_edits,
        "explicit_edit_relationships": sorted(
            relationships,
            key=lambda item: (item["packet_id"], item["previous_patch_index"], item["patch_index"], item["classification"]),
        ),
        "materialization_issues": sorted(
            materialization_issues,
            key=lambda item: (item["packet_id"], item["previous_patch_index"], item["patch_index"], item["reason"]),
        ),
    }
