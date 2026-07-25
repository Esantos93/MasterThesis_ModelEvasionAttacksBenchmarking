from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


PIPELINE_ROOT = Path(__file__).resolve().parents[1]
HEADER_POLICY_SCHEMA_VERSION = "header_editability_policy_v1"
KNOWN_HEADER_PROTOCOLS = {"ethernet", "ipv4", "tcp"}
HEADER_FIELD_ALIASES = {
    "ipv4.tos": "tos",
    "ipv4.ttl": "ttl",
    "ipv4.identification": "ip_id",
    "tcp.window": "window",
}
HEADER_MATERIALIZATION_SCHEMA_VERSION = "header_materialization_result_v1"
TCP_FLAG_BITS = {
    "ns": 0x100,
    "cwr": 0x080,
    "ece": 0x040,
    "urg": 0x020,
    "ack": 0x010,
    "psh": 0x008,
    "rst": 0x004,
    "syn": 0x002,
    "fin": 0x001,
}
IPV4_FRAGMENT_WORD_FIELDS = {
    "ipv4.flags_fragment_offset": (0xFFFF, 0),
    "ipv4.flags.reserved": (0x8000, 15),
    "ipv4.flags.dont_fragment": (0x4000, 14),
    "ipv4.flags.more_fragments": (0x2000, 13),
    "ipv4.fragment_offset_units": (0x1FFF, 0),
}


#This helper coerces boolean-like bit values into integer bits.
def bit_value(value: Any) -> int:
    return 1 if bool(value) else 0


#This helper keeps IPv4 fragmentation composite and subfields consistent after edits.
def sync_ipv4_fragment_fields(header: dict[str, Any]) -> None:
    flags = header.get("flags")
    if not isinstance(flags, dict):
        return
    combined = (
        (bit_value(flags.get("reserved")) << 15)
        | (bit_value(flags.get("dont_fragment")) << 14)
        | (bit_value(flags.get("more_fragments")) << 13)
        | (int(header.get("fragment_offset_units") or 0) & 0x1FFF)
    )
    header["flags_fragment_offset"] = combined
    header["fragmented"] = bool((combined & 0x2000) or (combined & 0x1FFF))
    header["fragment_offset_bytes"] = (combined & 0x1FFF) * 8


#This helper keeps TCP flag raw value and top-level aliases consistent after subflag edits.
def sync_tcp_flag_fields(record: dict[str, Any]) -> None:
    header = record.get("tcp_header")
    if not isinstance(header, dict):
        return
    flags = header.get("flags")
    if not isinstance(flags, dict):
        return
    raw = 0
    for flag_name, bit_mask in TCP_FLAG_BITS.items():
        if bit_value(flags.get(flag_name)):
            raw |= bit_mask
    flags["raw"] = raw
    record["tcp_flags"] = raw
    flag_letters = [
        ("fin", "F"),
        ("syn", "S"),
        ("rst", "R"),
        ("psh", "P"),
        ("ack", "A"),
        ("urg", "U"),
        ("ece", "E"),
        ("cwr", "C"),
        ("ns", "N"),
    ]
    record["tcp_flags_str"] = "".join(letter for flag_name, letter in flag_letters if bit_value(flags.get(flag_name)))


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function resolves the header editability policy selected by the active config.
def resolve_header_policy_path(config: dict[str, Any], config_path: str | Path) -> Path:
    policy_value = config.get("pipeline", {}).get("header_editability_policy_path")
    if not policy_value:
        raise ValueError("pipeline.header_editability_policy_path is required for header editability.")
    policy_path = Path(str(policy_value)).expanduser()
    if policy_path.is_absolute():
        return policy_path
    config_relative = Path(config_path).expanduser().parent / policy_path
    if config_relative.exists():
        return config_relative
    return PIPELINE_ROOT / policy_path


#This function expands the policy rules into a field->rule lookup.
def header_policy_rule_lookup(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Header editability policy rules must be JSON objects.")
        expanded_fields: list[str] = []
        if "protocol" in rule and "field" in rule:
            expanded_fields.append(f"{rule['protocol']}.{rule['field']}")
        for field in rule.get("fields", []):
            field_text = str(field)
            field_protocol, _, _field_remainder = field_text.partition(".")
            if "." in field_text and field_protocol in KNOWN_HEADER_PROTOCOLS:
                expanded_fields.append(field_text)
            elif "protocol" in rule:
                expanded_fields.append(f"{rule['protocol']}.{field_text}")
            else:
                for protocol in rule.get("protocols", []):
                    expanded_fields.append(f"{protocol}.{field_text}")
        for field_key in expanded_fields:
            if field_key in lookup:
                raise ValueError(f"Header editability policy defines multiple rules for {field_key!r}.")
            lookup[field_key] = rule
    return lookup


#This function loads the global header editability policy used by pipeline steps.
def load_header_editability_policy(config: dict[str, Any], config_path: str | Path) -> dict[str, Any]:
    policy_path = resolve_header_policy_path(config, config_path)
    policy = read_json(policy_path)
    if not isinstance(policy, dict):
        raise ValueError(f"Header editability policy must be a JSON object: {policy_path}")
    if policy.get("schema_version") != HEADER_POLICY_SCHEMA_VERSION:
        raise ValueError(
            f"Header policy schema must be {HEADER_POLICY_SCHEMA_VERSION!r}; "
            f"found {policy.get('schema_version')!r}: {policy_path}"
        )
    if not isinstance(policy.get("rules"), list):
        raise ValueError(f"Header editability policy must contain a rules list: {policy_path}")
    policy["_policy_path"] = str(policy_path)
    policy["_rule_lookup"] = header_policy_rule_lookup(policy)
    return policy


#This helper returns one stable ordered list without duplicating values.
def unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values))


#This function extracts policy fields that match a classification and optional editability flag.
def header_fields_by_classification(
    policy: dict[str, Any],
    classification: str,
    *,
    editable: bool | None = None,
) -> list[str]:
    fields = []
    for field_key, rule in (policy.get("_rule_lookup") or header_policy_rule_lookup(policy)).items():
        if rule.get("classification") != classification:
            continue
        if editable is not None and bool(rule.get("editable")) != editable:
            continue
        fields.append(field_key)
    return sorted(unique_strings(fields))


#This function extracts the model-visible editable header fields from the active policy.
def editable_header_fields_from_policy(policy: dict[str, Any]) -> list[str]:
    return header_fields_by_classification(policy, "llm_editable_headers_region", editable=True)


#This function returns true when a field is authorized as LLM-editable by the active policy.
def is_editable_header_field(policy: dict[str, Any], field: str) -> bool:
    rule = (policy.get("_rule_lookup") or header_policy_rule_lookup(policy)).get(field)
    return bool(
        rule
        and rule.get("editable")
        and rule.get("classification") == "llm_editable_headers_region"
    )


#This helper returns a nested value from a structured packet header.
def nested_header_value(header: dict[str, Any], field_name: str) -> Any:
    if field_name == "flags_fragment_offset" and "flags_fragment_offset" not in header:
        flags = header.get("flags")
        if isinstance(flags, dict):
            return (
                (bit_value(flags.get("reserved")) << 15)
                | (bit_value(flags.get("dont_fragment")) << 14)
                | (bit_value(flags.get("more_fragments")) << 13)
                | (int(header.get("fragment_offset_units") or 0) & 0x1FFF)
            )
    current: Any = header
    for part in field_name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


#This helper sets a nested value inside a structured packet header.
def set_nested_header_value(header: dict[str, Any], field_name: str, value: Any) -> bool:
    current: Any = header
    parts = field_name.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        return False
    current[parts[-1]] = value
    return True


#This helper extracts stable scalar header paths before and after materialization.
def scalar_header_paths(record: dict[str, Any]) -> dict[str, Any]:
    paths: dict[str, Any] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key in sorted(value):
                walk(f"{prefix}.{key}" if prefix else str(key), value[key])
            return
        if isinstance(value, (str, int, float, bool)) or value is None:
            paths[prefix] = value

    for header_name in ["ethernet_header", "ipv4_header", "tcp_header"]:
        header = record.get(header_name)
        if isinstance(header, dict):
            walk(header_name, header)
    for field_name in sorted(set(HEADER_FIELD_ALIASES.values()) | {"tcp_flags", "tcp_flags_str", "ip_flags"}):
        if field_name in record and (isinstance(record[field_name], (str, int, float, bool)) or record[field_name] is None):
            paths[field_name] = record[field_name]
    return paths


#This helper returns the packet paths directly represented by one logical header field.
def explicit_header_paths_for_field(field: str) -> set[str]:
    paths = set()
    protocol, _, field_name = field.partition(".")
    if protocol and field_name:
        paths.add(f"{protocol}_header.{field_name}")
    alias = HEADER_FIELD_ALIASES.get(field)
    if alias is not None:
        paths.add(alias)
    return paths


#This helper converts one packet path into the canonical logical header-field name used in provenance.
def logical_header_field_from_path(path: str) -> str:
    for header_name, protocol in [
        ("ethernet_header.", "ethernet."),
        ("ipv4_header.", "ipv4."),
        ("tcp_header.", "tcp."),
    ]:
        if path.startswith(header_name):
            return protocol + path[len(header_name) :]
    return f"record.{path}"


#This helper stores one deterministic before/after change record.
def header_change_record(
    *,
    packet_id: Any,
    path: str,
    before: Any,
    after: Any,
    field: str,
    patch_index: int,
    prompt_unit_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": "derived_header_change_v1",
        "packet_id": packet_id,
        "prompt_unit_id": prompt_unit_id,
        "patch_index": patch_index,
        "explicit_field": field,
        "derived_field": logical_header_field_from_path(path),
        "previous_value": deepcopy(before),
        "final_value": deepcopy(after),
        "effect": "created",
    }


#This helper converts an explicit edit into the constraint it imposes on physical header bits.
def header_edit_physical_constraint(edit: dict[str, Any]) -> dict[str, Any]:
    field = edit.get("field")
    replacement = edit.get("replacement")
    if not isinstance(field, str) or not field:
        raise ValueError("Explicit header edit field must be a non-empty string.")
    if not isinstance(replacement, int) or isinstance(replacement, bool):
        raise ValueError(f"Explicit header edit replacement for {field!r} must be an integer.")
    fragment_constraint = IPV4_FRAGMENT_WORD_FIELDS.get(field)
    if fragment_constraint is not None:
        mask, shift = fragment_constraint
        return {
            "physical_group": "ipv4.flags_fragment_offset_word",
            "mask": mask,
            "bits": (replacement << shift) & mask,
        }
    return {
        "physical_group": f"field::{field}",
        "mask": None,
        "bits": replacement,
    }


#This helper classifies whether two explicit edits constrain shared physical bits consistently.
def classify_header_edit_relationship(
    previous_edit: dict[str, Any],
    current_edit: dict[str, Any],
) -> dict[str, Any]:
    previous = header_edit_physical_constraint(previous_edit)
    current = header_edit_physical_constraint(current_edit)
    if previous["physical_group"] != current["physical_group"]:
        return {"classification": "disjoint", "physical_group": None, "overlap_mask": 0}

    previous_mask = previous["mask"]
    current_mask = current["mask"]
    if previous_mask is None or current_mask is None:
        classification = (
            "duplicate"
            if previous["bits"] == current["bits"]
            else "contradictory_overlap"
        )
        return {
            "classification": classification,
            "physical_group": previous["physical_group"],
            "overlap_mask": None,
        }

    overlap_mask = int(previous_mask) & int(current_mask)
    if overlap_mask == 0:
        classification = "disjoint"
    elif (int(previous["bits"]) & overlap_mask) != (int(current["bits"]) & overlap_mask):
        classification = "contradictory_overlap"
    elif previous_mask == current_mask and previous["bits"] == current["bits"]:
        classification = "duplicate"
    else:
        classification = "compatible_overlap"
    return {
        "classification": classification,
        "physical_group": previous["physical_group"],
        "overlap_mask": overlap_mask,
    }


#This helper normalizes optional integer fields used in deterministic provenance sorting.
def canonical_sort_integer(value: Any, default: int = -1) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


#This helper returns a canonical deterministic representation of derived changes.
def canonicalize_derived_header_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (deepcopy(change) for change in changes),
        key=lambda change: (
            str(change.get("prompt_unit_id", "")),
            canonical_sort_integer(change.get("patch_index")),
            str(change.get("derived_field", "")),
            str(change.get("explicit_field", "")),
            str(change.get("effect", "")),
            canonical_sort_integer(change.get("overwritten_by_patch_index")),
        ),
    )


#This helper returns a canonical deterministic representation of explicit-edit relationships.
def canonicalize_explicit_edit_relationships(
    relationships: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        (deepcopy(relationship) for relationship in relationships),
        key=lambda relationship: (
            str(relationship.get("prompt_unit_id", "")),
            canonical_sort_integer(relationship.get("patch_index")),
            canonical_sort_integer(relationship.get("previous_patch_index")),
            str(relationship.get("classification", "")),
            str(relationship.get("previous_field", "")),
            str(relationship.get("field", "")),
        ),
    )


#This function returns the value of one physical header field from a packet record.
def header_field_value(record: dict[str, Any], field: str) -> Any:
    protocol, _, field_name = field.partition(".")
    if not protocol or not field_name:
        return None
    header = record.get(f"{protocol}_header", {})
    if isinstance(header, dict):
        value = nested_header_value(header, field_name)
        if value is not None:
            return value
    alias = HEADER_FIELD_ALIASES.get(field)
    if alias is not None:
        return record.get(alias)
    return record.get(field_name)


#This function applies one physical header replacement to a copied Step 14 packet record.
def set_header_value(record: dict[str, Any], field: str, value: int) -> None:
    protocol, _, field_name = field.partition(".")
    header = record.get(f"{protocol}_header", {})
    if isinstance(header, dict):
        structured_value: Any = value
        if field.startswith("ipv4.flags.") or field.startswith("tcp.flags."):
            structured_value = bool(value)
        set_nested_header_value(header, field_name, structured_value)
        if field == "ipv4.tos":
            header["dscp"] = value >> 2
            header["ecn"] = value & 0x03
        if field == "ipv4.dscp":
            ecn = int(header.get("ecn") or 0) & 0x03
            header["tos"] = ((value & 0x3F) << 2) | ecn
            value = header["tos"]
        if field == "ipv4.ecn":
            dscp = int(header.get("dscp") or 0) & 0x3F
            header["tos"] = (dscp << 2) | (value & 0x03)
            value = header["tos"]
        if field.startswith("ipv4.flags.") or field == "ipv4.fragment_offset_units":
            sync_ipv4_fragment_fields(header)
        if field == "ipv4.flags_fragment_offset":
            flags = header.get("flags")
            if isinstance(flags, dict):
                flags["reserved"] = bool(value & 0x8000)
                flags["dont_fragment"] = bool(value & 0x4000)
                flags["more_fragments"] = bool(value & 0x2000)
            header["fragment_offset_units"] = value & 0x1FFF
            sync_ipv4_fragment_fields(header)
        if field.startswith("tcp.flags."):
            sync_tcp_flag_fields(record)
    alias = HEADER_FIELD_ALIASES.get(field)
    if alias is not None:
        record[alias] = value
    if field in {"ipv4.dscp", "ipv4.ecn"} and isinstance(header, dict):
        record["tos"] = header.get("tos")


#This function validates one unsigned integer replacement against policy or region constraints.
def validate_uint_replacement(
    *,
    replacement: Any,
    constraints: dict[str, Any],
) -> str | None:
    if not isinstance(replacement, int) or isinstance(replacement, bool):
        return "header_replacement_not_integer"
    min_value = constraints.get("min")
    max_value = constraints.get("max")
    if isinstance(min_value, int) and replacement < min_value:
        return "header_replacement_below_min"
    if isinstance(max_value, int) and replacement > max_value:
        return "header_replacement_above_max"
    return None


#This function materializes explicit physical-header edits over a copied original packet.
def materialize_header_edits(original_packet: dict[str, Any], explicit_edits: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(original_packet, dict):
        raise ValueError("original_packet must be a JSON object.")
    if not isinstance(explicit_edits, list):
        raise ValueError("explicit_edits must be a list.")
    packet_id = original_packet.get("packet_id")
    if packet_id is None:
        raise ValueError("original_packet.packet_id is required.")
    packet_id_text = str(packet_id)

    ordered_edits = []
    seen_patch_indexes: set[int] = set()
    prompt_unit_ids: set[str] = set()
    for edit_position, edit in enumerate(explicit_edits, start=1):
        if not isinstance(edit, dict):
            raise ValueError(f"explicit_edits[{edit_position}] must be a JSON object.")
        patch_index = edit.get("patch_index")
        if not isinstance(patch_index, int) or isinstance(patch_index, bool) or patch_index <= 0:
            raise ValueError(
                f"explicit_edits[{edit_position}].patch_index must be a positive integer."
            )
        if patch_index in seen_patch_indexes:
            raise ValueError(f"Duplicate patch_index {patch_index} for packet {packet_id_text!r}.")
        seen_patch_indexes.add(patch_index)

        prompt_unit_id = edit.get("prompt_unit_id")
        if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
            raise ValueError(
                f"explicit_edits[{edit_position}].prompt_unit_id must be a non-empty string."
            )
        prompt_unit_ids.add(prompt_unit_id)
        edit_packet_id = edit.get("packet_id")
        if edit_packet_id is not None and str(edit_packet_id) != packet_id_text:
            raise ValueError(
                f"Header edit packet_id {edit_packet_id!r} does not match original packet "
                f"{packet_id_text!r}."
            )
        field = edit.get("field")
        if not isinstance(field, str) or not field:
            raise ValueError(f"explicit_edits[{edit_position}].field must be a non-empty string.")
        replacement = edit.get("replacement")
        if not isinstance(replacement, int) or isinstance(replacement, bool):
            raise ValueError(
                f"explicit_edits[{edit_position}].replacement must be an integer."
            )
        ordered_edits.append(deepcopy(edit))

    if len(prompt_unit_ids) > 1:
        raise ValueError(
            f"Packet {packet_id_text!r} has explicit edits from multiple prompt_unit_id values: "
            f"{sorted(prompt_unit_ids)!r}."
        )
    ordered_edits.sort(key=lambda item: int(item["patch_index"]))

    materialized_packet = deepcopy(original_packet)
    explicit_header_edits: list[dict[str, Any]] = []
    applied_patches: list[dict[str, Any]] = []
    no_effect_edits: list[dict[str, Any]] = []
    derived_header_changes: list[dict[str, Any]] = []
    active_derived_by_path: dict[str, dict[str, Any]] = {}

    for sequence_index, edit in enumerate(ordered_edits, start=1):
        field = str(edit["field"])
        replacement = int(edit["replacement"])
        patch_index = int(edit["patch_index"])
        prompt_unit_id = str(edit["prompt_unit_id"])
        current_value = header_field_value(materialized_packet, field)
        if current_value is None:
            raise ValueError(
                f"Header field {field!r} is absent from original packet {packet_id_text!r}."
            )

        before_paths = scalar_header_paths(materialized_packet)
        set_header_value(materialized_packet, field, replacement)
        final_value = header_field_value(materialized_packet, field)
        if final_value != replacement:
            raise ValueError(
                f"set_header_value() did not materialize {field!r}={replacement!r} "
                f"for packet {packet_id_text!r}; observed {final_value!r}."
            )
        after_paths = scalar_header_paths(materialized_packet)

        edit_record = deepcopy(edit)
        edit_record["packet_id"] = packet_id_text
        edit_record["materialization_sequence_index"] = sequence_index
        edit_record["sequential_original_value"] = deepcopy(current_value)
        edit_record["materialization_previous_value"] = deepcopy(current_value)
        edit_record["materialization_final_value"] = deepcopy(final_value)
        edit_record["no_effect"] = current_value == final_value
        explicit_header_edits.append(edit_record)
        if edit_record["no_effect"]:
            no_effect_edits.append(edit_record)
        else:
            applied_patches.append(edit_record)

        explicit_paths = explicit_header_paths_for_field(field)
        changed_paths = sorted(
            path
            for path in set(before_paths) | set(after_paths)
            if before_paths.get(path) != after_paths.get(path)
        )
        for path in changed_paths:
            previous_derived = active_derived_by_path.pop(path, None)
            if previous_derived is not None:
                previous_derived["effect"] = "overwritten"
                previous_derived["overwritten_by_prompt_unit_id"] = prompt_unit_id
                previous_derived["overwritten_by_patch_index"] = patch_index
                previous_derived["overwritten_by_explicit_field"] = field

            if path in explicit_paths:
                continue
            change = header_change_record(
                packet_id=packet_id_text,
                path=path,
                before=before_paths.get(path),
                after=after_paths.get(path),
                field=field,
                patch_index=patch_index,
                prompt_unit_id=prompt_unit_id,
            )
            derived_header_changes.append(change)
            active_derived_by_path[path] = change

    explicit_edit_relationships: list[dict[str, Any]] = []
    relationship_by_pair: dict[tuple[int, int], dict[str, Any]] = {}
    for current_position, current_edit in enumerate(explicit_header_edits):
        for previous_edit in explicit_header_edits[:current_position]:
            classified = classify_header_edit_relationship(previous_edit, current_edit)
            if classified["classification"] == "disjoint":
                continue
            relationship = {
                "packet_id": packet_id_text,
                "previous_prompt_unit_id": previous_edit["prompt_unit_id"],
                "prompt_unit_id": current_edit["prompt_unit_id"],
                "previous_patch_index": previous_edit["patch_index"],
                "patch_index": current_edit["patch_index"],
                "previous_field": previous_edit["field"],
                "field": current_edit["field"],
                "previous_replacement": previous_edit["replacement"],
                "replacement": current_edit["replacement"],
                "classification": classified["classification"],
                "physical_group": classified["physical_group"],
                "overlap_mask": classified["overlap_mask"],
                "overwritten_derived_fields": [],
            }
            explicit_edit_relationships.append(relationship)
            relationship_by_pair[
                (int(previous_edit["patch_index"]), int(current_edit["patch_index"]))
            ] = relationship

    for change in derived_header_changes:
        overwritten_by = change.get("overwritten_by_patch_index")
        if change.get("effect") != "overwritten" or not isinstance(overwritten_by, int):
            continue
        pair = (int(change["patch_index"]), overwritten_by)
        relationship = relationship_by_pair.get(pair)
        if relationship is None:
            previous_edit = next(
                item for item in explicit_header_edits if int(item["patch_index"]) == pair[0]
            )
            current_edit = next(
                item for item in explicit_header_edits if int(item["patch_index"]) == pair[1]
            )
            relationship = {
                "packet_id": packet_id_text,
                "previous_prompt_unit_id": previous_edit["prompt_unit_id"],
                "prompt_unit_id": current_edit["prompt_unit_id"],
                "previous_patch_index": previous_edit["patch_index"],
                "patch_index": current_edit["patch_index"],
                "previous_field": previous_edit["field"],
                "field": current_edit["field"],
                "previous_replacement": previous_edit["replacement"],
                "replacement": current_edit["replacement"],
                "classification": "disjoint",
                "physical_group": None,
                "overlap_mask": 0,
                "overwritten_derived_fields": [],
            }
            explicit_edit_relationships.append(relationship)
            relationship_by_pair[pair] = relationship
        relationship["overwritten_derived_fields"].append(change["derived_field"])

    for relationship in explicit_edit_relationships:
        relationship["overwritten_derived_fields"] = sorted(
            set(relationship["overwritten_derived_fields"])
        )

    canonical_changes = canonicalize_derived_header_changes(derived_header_changes)
    canonical_relationships = canonicalize_explicit_edit_relationships(
        explicit_edit_relationships
    )
    return {
        "schema_version": HEADER_MATERIALIZATION_SCHEMA_VERSION,
        "materialized_packet": materialized_packet,
        "explicit_edits": explicit_header_edits,
        "applied_patches": applied_patches,
        "no_effect_edits": no_effect_edits,
        "derived_header_changes": canonical_changes,
        "explicit_edit_relationships": canonical_relationships,
        "materialization_issues": [],
    }
