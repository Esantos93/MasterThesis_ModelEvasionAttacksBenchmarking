from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


PAYLOAD_MATERIALIZATION_SCHEMA_VERSION = "canonical_payload_materialization_result_v2"
SUPPORTED_REPLACEMENT_FORMATS = {"hex", "text"}
SUPPORTED_PAYLOAD_OPERATIONS = {"replace_region", "replace_byte_range"}
SUPPORTED_PAYLOAD_REGION_TYPES = {"canonical_payload_region", "canonical_payload_byte_range"}
ETHERNET_MINIMUM_FRAME_BYTES = 60


#This exception preserves the exact canonical edit and physical alias that caused materialization to fail.
class PayloadMaterializationError(ValueError):
    def __init__(self, message: str, **detail: Any):
        super().__init__(message)
        self.detail = detail


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


#This helper returns a nested dictionary or None when the packet has no structured metadata for that layer.
def nested_dict(packet: dict[str, Any], field: str) -> dict[str, Any] | None:
    value = packet.get(field)
    return value if isinstance(value, dict) else None


#This helper updates Ethernet/IPv4 length and padding metadata after a payload length change.
def update_physical_payload_metadata(
    *,
    original_packet: dict[str, Any],
    materialized_packet: dict[str, Any],
    packet_id: str,
    old_payload_length: int,
    new_payload_length: int,
) -> None:
    delta = new_payload_length - old_payload_length
    materialized_packet["payload_length_bytes"] = new_payload_length
    original_packet_length = original_packet.get("packet_length_bytes")
    materialized_packet_length = materialized_packet.get("packet_length_bytes")
    original_ipv4 = nested_dict(original_packet, "ipv4_header")
    materialized_ipv4 = nested_dict(materialized_packet, "ipv4_header")
    original_ethernet = nested_dict(original_packet, "ethernet_header")
    materialized_ethernet = nested_dict(materialized_packet, "ethernet_header")

    if delta == 0:
        if isinstance(materialized_packet_length, int) and not isinstance(materialized_packet_length, bool):
            materialized_packet["packet_length_bytes"] = materialized_packet_length
        return

    if not isinstance(original_packet_length, int) or isinstance(original_packet_length, bool):
        if isinstance(materialized_packet_length, int) and not isinstance(materialized_packet_length, bool):
            materialized_packet["packet_length_bytes"] = materialized_packet_length + delta
        return
    if original_ipv4 is None or materialized_ipv4 is None or original_ethernet is None or materialized_ethernet is None:
        materialized_packet["packet_length_bytes"] = original_packet_length + delta
        return

    if original_ethernet.get("encapsulation") not in {None, "ethernet_ii"}:
        raise ValueError(f"packet {packet_id!r} uses unsupported Ethernet encapsulation for payload resizing.")
    if original_ethernet.get("vlan_present") not in {None, False}:
        raise ValueError(f"packet {packet_id!r} uses VLAN metadata; payload resizing has no validated VLAN/FCS contract.")
    header_length = original_ethernet.get("header_length_bytes")
    old_ipv4_total = original_ipv4.get("total_length", original_packet.get("ip_len"))
    old_padding = original_ethernet.get("padding_length_bytes", 0)
    if not isinstance(header_length, int) or isinstance(header_length, bool) or header_length < 0:
        raise ValueError(f"packet {packet_id!r} ethernet_header.header_length_bytes is invalid.")
    if not isinstance(old_ipv4_total, int) or isinstance(old_ipv4_total, bool) or old_ipv4_total < 0:
        raise ValueError(f"packet {packet_id!r} ipv4 total length is invalid.")
    if not isinstance(old_padding, int) or isinstance(old_padding, bool) or old_padding < 0:
        raise ValueError(f"packet {packet_id!r} ethernet_header.padding_length_bytes is invalid.")
    old_effective_frame_length = header_length + old_ipv4_total
    recorded_effective = original_ethernet.get("effective_frame_length_bytes")
    if isinstance(recorded_effective, int) and not isinstance(recorded_effective, bool) and recorded_effective != old_effective_frame_length:
        raise ValueError(f"packet {packet_id!r} ethernet effective frame length contradicts IPv4 total length.")
    if old_effective_frame_length + old_padding != original_packet_length:
        raise ValueError(f"packet {packet_id!r} packet_length_bytes contradicts Ethernet padding metadata.")
    capture_relation = original_ipv4.get("capture_relation")
    if isinstance(capture_relation, dict):
        trailing = capture_relation.get("trailing_bytes_after_declared_ipv4")
        status = capture_relation.get("status")
        if isinstance(trailing, int) and not isinstance(trailing, bool) and trailing != old_padding:
            raise ValueError(f"packet {packet_id!r} IPv4 trailing bytes disagree with Ethernet padding.")
        if old_padding and status not in {"complete_with_trailing_bytes", None}:
            raise ValueError(f"packet {packet_id!r} has trailing bytes not classified as Ethernet padding.")
    padding_hex = original_ethernet.get("padding_hex", "")
    if old_padding:
        if not is_valid_hex(padding_hex) or len(str(padding_hex)) // 2 != old_padding:
            raise ValueError(f"packet {packet_id!r} Ethernet padding_hex is inconsistent with padding length.")
    if old_padding and original_ethernet.get("padding_present") not in {True, None}:
        raise ValueError(f"packet {packet_id!r} has padding length but padding_present is false.")

    new_ipv4_total = old_ipv4_total + delta
    if new_ipv4_total < 0:
        raise ValueError(f"packet {packet_id!r} payload resize makes IPv4 total length negative.")
    new_effective_frame_length = header_length + new_ipv4_total
    new_padding = max(0, ETHERNET_MINIMUM_FRAME_BYTES - new_effective_frame_length)
    new_packet_length = new_effective_frame_length + new_padding

    materialized_packet["packet_length_bytes"] = new_packet_length
    if "ip_len" in materialized_packet:
        materialized_packet["ip_len"] = new_ipv4_total
    materialized_ipv4["total_length"] = new_ipv4_total
    materialized_tcp = nested_dict(materialized_packet, "tcp_header")
    if materialized_tcp is not None:
        for tcp_payload_length_field in ["captured_payload_length_bytes", "declared_payload_length_bytes"]:
            if tcp_payload_length_field in materialized_tcp:
                materialized_tcp[tcp_payload_length_field] = new_payload_length
    if isinstance(materialized_ipv4.get("capture_relation"), dict):
        relation = materialized_ipv4["capture_relation"]
        relation["captured_bytes_from_ipv4_start"] = new_packet_length - header_length
        relation["captured_declared_ipv4_bytes"] = new_ipv4_total
        relation["declared_total_length_bytes"] = new_ipv4_total
        relation["trailing_bytes_after_declared_ipv4"] = new_padding
        relation["status"] = "complete_with_trailing_bytes" if new_padding else "complete"
    materialized_ethernet["effective_frame_length_bytes"] = new_effective_frame_length
    materialized_ethernet["captured_length_bytes"] = new_packet_length
    materialized_ethernet["padding_length_bytes"] = new_padding
    materialized_ethernet["padding_hex"] = "00" * new_padding
    materialized_ethernet["padding_present"] = new_padding > 0
    materialized_ethernet["padding_offset_start"] = new_effective_frame_length if new_padding else None
    materialized_ethernet["padding_offset_end"] = new_packet_length if new_padding else None


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
    region_type = edit.get("region_type")
    if region_type not in SUPPORTED_PAYLOAD_REGION_TYPES:
        raise ValueError(
            f"explicit_payload_edits[{edit_position}].region_type must be one of {sorted(SUPPORTED_PAYLOAD_REGION_TYPES)}."
        )
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
    canonical_original_bytes: list[int | None] = [None] * replaced_length
    overlapping_alias_count = 0
    for alias in aliases:
        alias_start = alias["canonical_start_offset_bytes"]
        alias_end = alias_start + alias["length_bytes"]
        overlap_start = max(canonical_start, alias_start)
        overlap_end = min(target_end, alias_end)
        if overlap_start >= overlap_end:
            continue
        overlapping_alias_count += 1
        original_packet = original_packets_by_id[alias["packet_id"]]
        payload_hex, _payload_length = packet_payload(original_packet, alias["packet_id"])
        relative_start = overlap_start - alias_start
        payload_start = alias["payload_start_offset_bytes"] + relative_start
        overlap_length = overlap_end - overlap_start
        original_segment = bytes.fromhex(
            payload_hex[payload_start * 2 : (payload_start + overlap_length) * 2]
        )
        canonical_offset = overlap_start - canonical_start
        for byte_offset, byte_value in enumerate(original_segment):
            target_offset = canonical_offset + byte_offset
            previous_value = canonical_original_bytes[target_offset]
            if previous_value is not None and previous_value != byte_value:
                raise PayloadMaterializationError(
                    f"Payload edit {patch_index} aliases disagree on original canonical bytes.",
                    reason="canonical_alias_original_bytes_mismatch",
                    prompt_unit_id=prompt_unit_id,
                    patch_index=patch_index,
                    canonical_region_id=canonical_region_id,
                    region_id=edit.get("region_id", canonical_region_id),
                    alias_id=alias["alias_id"],
                    canonical_offset_bytes=canonical_start + target_offset,
                )
            canonical_original_bytes[target_offset] = byte_value
    missing_offsets = [
        canonical_start + offset
        for offset, byte_value in enumerate(canonical_original_bytes)
        if byte_value is None
    ]
    if missing_offsets:
        raise PayloadMaterializationError(
            f"Payload edit {patch_index} target range is not jointly covered by its physical aliases.",
            reason="canonical_target_not_jointly_covered",
            prompt_unit_id=prompt_unit_id,
            patch_index=patch_index,
            canonical_region_id=canonical_region_id,
            region_id=edit.get("region_id", canonical_region_id),
            first_missing_canonical_offset_bytes=missing_offsets[0],
            missing_canonical_byte_count=len(missing_offsets),
        )

    original_segment_hex = bytes(int(value) for value in canonical_original_bytes).hex()
    normalized_edit = deepcopy(edit)
    normalized_edit.update(
        {
            "edit_kind": "canonical_payload",
            "identity_type": "canonical_payload_region",
            "region_type": region_type,
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
            "overlapping_physical_alias_count": overlapping_alias_count,
            "no_effect": original_segment_hex == replacement_hex,
        }
    )
    if replacement_format == "text" and "replacement_text" not in normalized_edit and replacement is not None:
        normalized_edit["replacement_text"] = str(replacement)
    return normalized_edit


#This helper maps an original canonical boundary through one prefix-stable replacement.
def transform_canonical_boundary(
    boundary: int,
    *,
    canonical_start: int,
    replaced_length: int,
    replacement_length: int,
) -> int:
    canonical_end = canonical_start + replaced_length
    if boundary <= canonical_start:
        return boundary
    if boundary >= canonical_end:
        return boundary + replacement_length - replaced_length
    return canonical_start + min(boundary - canonical_start, replacement_length)


#This helper removes unchanged prefix and suffix bytes from one physical projection.
def trim_unchanged_projection(
    original_segment: bytes,
    replacement_segment: bytes,
) -> tuple[int, bytes, bytes]:
    common_prefix = 0
    common_limit = min(len(original_segment), len(replacement_segment))
    while (
        common_prefix < common_limit
        and original_segment[common_prefix] == replacement_segment[common_prefix]
    ):
        common_prefix += 1
    common_suffix = 0
    suffix_limit = min(
        len(original_segment) - common_prefix,
        len(replacement_segment) - common_prefix,
    )
    while (
        common_suffix < suffix_limit
        and original_segment[len(original_segment) - common_suffix - 1]
        == replacement_segment[len(replacement_segment) - common_suffix - 1]
    ):
        common_suffix += 1
    original_end = len(original_segment) - common_suffix if common_suffix else len(original_segment)
    replacement_end = (
        len(replacement_segment) - common_suffix
        if common_suffix
        else len(replacement_segment)
    )
    return (
        common_prefix,
        original_segment[common_prefix:original_end],
        replacement_segment[common_prefix:replacement_end],
    )


#This helper builds one physical projection record for a canonical payload edit.
def build_projection_change(
    *,
    edit: dict[str, Any],
    alias: dict[str, Any],
    original_packet: dict[str, Any],
) -> dict[str, Any] | None:
    canonical_start = int(edit["canonical_start_offset_bytes"])
    canonical_end = canonical_start + int(edit["replaced_length_bytes"])
    replacement = bytes.fromhex(str(edit["replacement_hex"]))
    replacement_length = len(replacement)
    alias_start = int(alias["canonical_start_offset_bytes"])
    alias_end = alias_start + int(alias["length_bytes"])
    transformed_alias_start = transform_canonical_boundary(
        alias_start,
        canonical_start=canonical_start,
        replaced_length=int(edit["replaced_length_bytes"]),
        replacement_length=replacement_length,
    )
    transformed_alias_end = transform_canonical_boundary(
        alias_end,
        canonical_start=canonical_start,
        replaced_length=int(edit["replaced_length_bytes"]),
        replacement_length=replacement_length,
    )
    payload_start = int(alias["payload_start_offset_bytes"])
    payload_hex, _payload_length = packet_payload(original_packet, alias["packet_id"])
    alias_length = int(alias["length_bytes"])
    original_alias_segment = bytes.fromhex(
        payload_hex[payload_start * 2 : (payload_start + alias_length) * 2]
    )

    prefix_end = min(alias_end, canonical_start)
    prefix_length = max(0, prefix_end - alias_start)
    suffix_start = max(alias_start, canonical_end)
    suffix_offset = max(0, suffix_start - alias_start)
    replacement_slice_start = max(transformed_alias_start, canonical_start) - canonical_start
    replacement_slice_end = min(
        transformed_alias_end,
        canonical_start + replacement_length,
    ) - canonical_start
    replacement_slice_start = max(0, min(replacement_length, replacement_slice_start))
    replacement_slice_end = max(
        replacement_slice_start,
        min(replacement_length, replacement_slice_end),
    )
    transformed_alias_segment = (
        original_alias_segment[:prefix_length]
        + replacement[replacement_slice_start:replacement_slice_end]
        + original_alias_segment[suffix_offset:]
    )
    projection_prefix, original_projection, replacement_projection = trim_unchanged_projection(
        original_alias_segment,
        transformed_alias_segment,
    )
    if original_projection == replacement_projection:
        return None
    projection_payload_start = payload_start + projection_prefix
    reaches_canonical_end = alias_start <= canonical_end <= alias_end
    canonical_end_payload_offset = (
        payload_start + canonical_end - alias_start
        if reaches_canonical_end
        else None
    )
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
        "canonical_edit_start_offset_bytes": canonical_start,
        "canonical_edit_end_offset_bytes": canonical_end,
        "canonical_replaced_length_bytes": int(edit["replaced_length_bytes"]),
        "canonical_replacement_length_bytes": replacement_length,
        "canonical_payload_length_delta_bytes": (
            replacement_length - int(edit["replaced_length_bytes"])
        ),
        "alias_canonical_start_offset_bytes": alias_start,
        "alias_canonical_end_offset_bytes": alias_end,
        "transformed_alias_canonical_start_offset_bytes": transformed_alias_start,
        "transformed_alias_canonical_end_offset_bytes": transformed_alias_end,
        "projection_reaches_canonical_edit_end": reaches_canonical_end,
        "canonical_edit_end_packet_payload_offset_bytes": canonical_end_payload_offset,
        "stream_start": alias.get("stream_start"),
        "stream_end": alias.get("stream_end"),
        "replaced_length_bytes": len(original_projection),
        "replacement_length_bytes": len(replacement_projection),
        "payload_start_offset_bytes": projection_payload_start,
        "packet_payload_offset_start_bytes": alias.get("packet_payload_offset_start_bytes"),
        "packet_payload_offset_end_bytes": alias.get("packet_payload_offset_end_bytes"),
        "payload_length_delta_bytes": len(replacement_projection) - len(original_projection),
        "original_segment_hex": original_projection.hex(),
        "replacement_hex": replacement_projection.hex(),
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
    edits_by_canonical_region: dict[str, list[dict[str, Any]]] = {}
    for edit in validated_edits:
        edits_by_canonical_region.setdefault(str(edit["canonical_region_id"]), []).append(edit)

    # Only edits owned by the same canonical region can overlap. Grouping first
    # keeps the relationship audit proportional to edits per region instead of
    # comparing every payload decision in a full experiment with every other one.
    for region_edits in edits_by_canonical_region.values():
        for current_position, current_edit in enumerate(region_edits):
            for previous_edit in region_edits[:current_position]:
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
                if projection is None:
                    continue
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
            output_packets_by_id[packet_id]["payload_hex"] = payload_hex
            update_physical_payload_metadata(
                original_packet=original_packets[packet_id],
                materialized_packet=output_packets_by_id[packet_id],
                packet_id=packet_id,
                old_payload_length=old_payload_length,
                new_payload_length=new_payload_length,
            )

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
