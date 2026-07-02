from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PIPELINE_ROOT = Path(__file__).resolve().parents[1]
HEADER_POLICY_SCHEMA_VERSION = "header_editability_policy_v1"
HEADER_FIELD_ALIASES = {
    "ipv4.tos": "tos",
    "ipv4.ttl": "ttl",
    "ipv4.identification": "ip_id",
    "tcp.window": "window",
}


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
            if "." in field_text:
                expanded_fields.append(field_text)
            else:
                for protocol in rule.get("protocols", []):
                    expanded_fields.append(f"{protocol}.{field_text}")
                if "protocol" in rule:
                    expanded_fields.append(f"{rule['protocol']}.{field_text}")
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
        set_nested_header_value(header, field_name, value)
        if field == "ipv4.tos":
            header["dscp"] = value >> 2
            header["ecn"] = value & 0x03
    alias = HEADER_FIELD_ALIASES.get(field)
    if alias is not None:
        record[alias] = value


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
