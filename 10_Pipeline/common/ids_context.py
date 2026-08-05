from __future__ import annotations

from typing import Any


PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION = "pre_snort_context_bundle_v1"
IDS_CONTEXT_SCHEMA_VERSION = "ids_context_v1"
IDS_CONTEXT_MAPPING_POLICY = "tcp_connection_propagation_v1"

DETECTOR_SOURCES = {
    "ruleset_text",
    "ruleset_so",
    "builtin_decoder_or_inspector",
}

_IDS_COMMON_FIELDS = {
    "detector_source",
    "gid",
    "sid",
    "rev",
    "message",
    "tcp_connection_id",
    "anchor_packet_ids",
    "tcp_connection_packet_ids_in_prompt",
}
_IDS_SOURCE_FIELDS = {
    "ruleset_text": {"rule_declaration"},
    "ruleset_so": {"so_rule_stub", "security_context"},
    "builtin_decoder_or_inspector": {"inspector", "semantic_description"},
}
_NON_MODEL_VISIBLE_SNORT_RULE_OPTIONS = {"metadata", "reference"}


#This function removes Snort provenance options that are retained for audit but intentionally hidden from the model.
def strip_non_model_visible_snort_rule_options(rule_declaration: str) -> str:
    """Remove provenance-only Snort options without changing detection logic."""
    rule = _require_nonempty_string(rule_declaration, "rule_declaration")
    opening_parenthesis = rule.find("(")
    closing_parenthesis = rule.rfind(")")
    if opening_parenthesis < 0 or closing_parenthesis <= opening_parenthesis:
        raise ValueError("Snort rule declaration must contain a parenthesized option block.")

    option_block = rule[opening_parenthesis + 1 : closing_parenthesis]
    kept_segments: list[str] = []
    segment_start = 0
    inside_quotes = False
    escaped = False

    for index, character in enumerate(option_block):
        if escaped:
            escaped = False
            continue
        if character == "\\" and inside_quotes:
            escaped = True
            continue
        if character == '"':
            inside_quotes = not inside_quotes
            continue
        if character != ";" or inside_quotes:
            continue

        segment = option_block[segment_start : index + 1]
        option_name = segment.lstrip().split(":", 1)[0].strip().lower()
        if option_name not in _NON_MODEL_VISIBLE_SNORT_RULE_OPTIONS:
            kept_segments.append(segment)
        segment_start = index + 1

    trailing_segment = option_block[segment_start:]
    if trailing_segment.strip():
        option_name = trailing_segment.lstrip().split(":", 1)[0].strip().lower()
        if option_name not in _NON_MODEL_VISIBLE_SNORT_RULE_OPTIONS:
            kept_segments.append(trailing_segment)

    return rule[: opening_parenthesis + 1] + "".join(kept_segments) + rule[closing_parenthesis:]


#This function validates that a contract field is a JSON object and returns its typed value.
def _require_dict(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object.")
    return value


#This function validates that a contract field is a JSON array.
def _require_list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON array.")
    return value


#This function rejects absent or blank identifiers and model-visible text fields.
def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")
    return value


#This function validates non-negative integer fields while excluding booleans.
def _require_nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer.")
    return value


#This function validates ordered identifier collections and prevents duplicate traceability entries.
def _require_unique_strings(value: Any, field_name: str, *, allow_empty: bool = False) -> list[str]:
    values = _require_list(value, field_name)
    if not allow_empty and not values:
        raise ValueError(f"{field_name} must not be empty.")
    normalized = [_require_nonempty_string(item, f"{field_name}[]") for item in values]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field_name} must not contain duplicates.")
    return normalized


#This function returns the canonical Snort detector identity used for deduplication and joins.
def detector_identity(record: dict[str, Any]) -> tuple[int, int, int]:
    return int(record["gid"]), int(record["sid"]), int(record["rev"])


#This function limits model-visible SO-rule context to the approved compact summary.
def _validate_security_context(value: Any, field_name: str) -> None:
    security_context = _require_dict(value, field_name)
    unexpected = set(security_context) - {"summary"}
    if unexpected:
        raise ValueError(
            f"{field_name} contains model-visible fields that are not allowed: {sorted(unexpected)}"
        )
    _require_nonempty_string(security_context.get("summary"), f"{field_name}.summary")


#This function validates one model-visible IDS record according to its detector source.
def validate_ids_context_record(record: Any, *, field_name: str = "ids_context.records[]") -> None:
    detector = _require_dict(record, field_name)
    source = _require_nonempty_string(detector.get("detector_source"), f"{field_name}.detector_source")
    if source not in DETECTOR_SOURCES:
        raise ValueError(f"{field_name}.detector_source is unsupported: {source!r}.")

    allowed_fields = _IDS_COMMON_FIELDS | _IDS_SOURCE_FIELDS[source]
    unexpected = set(detector) - allowed_fields
    if unexpected:
        raise ValueError(
            f"{field_name} contains fields that are not model-visible: {sorted(unexpected)}"
        )

    _require_nonnegative_int(detector.get("gid"), f"{field_name}.gid")
    _require_nonnegative_int(detector.get("sid"), f"{field_name}.sid")
    _require_nonnegative_int(detector.get("rev"), f"{field_name}.rev")
    _require_nonempty_string(detector.get("message"), f"{field_name}.message")
    _require_nonempty_string(detector.get("tcp_connection_id"), f"{field_name}.tcp_connection_id")
    _require_unique_strings(detector.get("anchor_packet_ids"), f"{field_name}.anchor_packet_ids")
    _require_unique_strings(
        detector.get("tcp_connection_packet_ids_in_prompt"),
        f"{field_name}.tcp_connection_packet_ids_in_prompt",
    )

    if source == "ruleset_text":
        rule_declaration = _require_nonempty_string(
            detector.get("rule_declaration"),
            f"{field_name}.rule_declaration",
        )
        if strip_non_model_visible_snort_rule_options(rule_declaration) != rule_declaration:
            raise ValueError(
                f"{field_name}.rule_declaration contains non-model-visible reference or metadata options."
            )
    elif source == "ruleset_so":
        so_rule_stub = _require_nonempty_string(detector.get("so_rule_stub"), f"{field_name}.so_rule_stub")
        if strip_non_model_visible_snort_rule_options(so_rule_stub) != so_rule_stub:
            raise ValueError(
                f"{field_name}.so_rule_stub contains non-model-visible reference or metadata options."
            )
        if "security_context" in detector:
            _validate_security_context(detector["security_context"], f"{field_name}.security_context")
    else:
        _require_nonempty_string(detector.get("inspector"), f"{field_name}.inspector")
        _require_nonempty_string(
            detector.get("semantic_description"),
            f"{field_name}.semantic_description",
        )


#This function validates the complete model-visible IDS context and its per-connection uniqueness invariant.
def validate_ids_context(ids_context: Any) -> None:
    context = _require_dict(ids_context, "ids_context")
    unexpected = set(context) - {"schema_version", "records"}
    if unexpected:
        raise ValueError(f"ids_context contains unsupported model-visible fields: {sorted(unexpected)}")
    if context.get("schema_version") != IDS_CONTEXT_SCHEMA_VERSION:
        raise ValueError(
            f"ids_context.schema_version must be {IDS_CONTEXT_SCHEMA_VERSION!r}; "
            f"found {context.get('schema_version')!r}."
        )
    records = _require_list(context.get("records"), "ids_context.records")
    seen: set[tuple[tuple[int, int, int], str]] = set()
    for index, record in enumerate(records):
        field_name = f"ids_context.records[{index}]"
        validate_ids_context_record(record, field_name=field_name)
        detector = _require_dict(record, field_name)
        key = (detector_identity(detector), str(detector["tcp_connection_id"]))
        if key in seen:
            raise ValueError(
                "ids_context must contain at most one record for each detector identity and TCP connection."
            )
        seen.add(key)


#This function creates the exact IDS projection allowed in a prompt after validating the source object.
def project_ids_context(ids_context: Any) -> dict[str, Any]:
    validate_ids_context(ids_context)
    context = _require_dict(ids_context, "ids_context")
    records: list[dict[str, Any]] = []
    for source_record in context["records"]:
        source = str(source_record["detector_source"])
        allowed_fields = _IDS_COMMON_FIELDS | _IDS_SOURCE_FIELDS[source]
        records.append({key: source_record[key] for key in source_record if key in allowed_fields})
    return {
        "schema_version": IDS_CONTEXT_SCHEMA_VERSION,
        "records": records,
    }


#This function validates auditable external references stored in a PRE bundle but not necessarily shown to the model.
def _validate_external_security_context(value: Any, field_name: str) -> None:
    context = _require_dict(value, field_name)
    allowed = {"summary", "cve_ids", "mitre_attack_ids", "source_urls"}
    unexpected = set(context) - allowed
    if unexpected:
        raise ValueError(f"{field_name} contains unsupported fields: {sorted(unexpected)}")
    if "summary" in context:
        _require_nonempty_string(context["summary"], f"{field_name}.summary")
    for key in ("cve_ids", "mitre_attack_ids", "source_urls"):
        if key in context:
            _require_unique_strings(context[key], f"{field_name}.{key}", allow_empty=True)


#This function validates a canonical detector definition and its source-specific evidence.
def _validate_detector_definition(value: Any, field_name: str) -> None:
    detector = _require_dict(value, field_name)
    source = _require_nonempty_string(detector.get("detector_source"), f"{field_name}.detector_source")
    if source not in DETECTOR_SOURCES:
        raise ValueError(f"{field_name}.detector_source is unsupported: {source!r}.")
    _require_nonnegative_int(detector.get("gid"), f"{field_name}.gid")
    _require_nonnegative_int(detector.get("sid"), f"{field_name}.sid")
    _require_nonnegative_int(detector.get("rev"), f"{field_name}.rev")
    _require_nonempty_string(detector.get("message"), f"{field_name}.message")

    common = {"detector_source", "gid", "sid", "rev", "message", "security_context"}
    if source == "ruleset_text":
        allowed = common | {"rule_declaration"}
        _require_nonempty_string(detector.get("rule_declaration"), f"{field_name}.rule_declaration")
    elif source == "ruleset_so":
        allowed = common | {"so_rule_stub"}
        _require_nonempty_string(detector.get("so_rule_stub"), f"{field_name}.so_rule_stub")
    else:
        allowed = common | {"inspector", "semantic_description"}
        _require_nonempty_string(detector.get("inspector"), f"{field_name}.inspector")
        _require_nonempty_string(detector.get("semantic_description"), f"{field_name}.semantic_description")
    unexpected = set(detector) - allowed
    if unexpected:
        raise ValueError(f"{field_name} contains unsupported fields: {sorted(unexpected)}")
    if "security_context" in detector:
        _validate_external_security_context(detector["security_context"], f"{field_name}.security_context")
        if source != "ruleset_so" and "summary" in detector["security_context"]:
            raise ValueError(f"{field_name}.security_context.summary is allowed only for ruleset_so.")


#This function validates one PRE alert and its unambiguous packet anchors.
def _validate_pre_alert(value: Any, field_name: str) -> None:
    alert = _require_dict(value, field_name)
    allowed = {
        "alert_id",
        "gid",
        "sid",
        "rev",
        "message",
        "anchor_packet_ids",
        "timestamp",
        "event_data",
    }
    unexpected = set(alert) - allowed
    if unexpected:
        raise ValueError(f"{field_name} contains unsupported fields: {sorted(unexpected)}")
    _require_nonempty_string(alert.get("alert_id"), f"{field_name}.alert_id")
    _require_nonnegative_int(alert.get("gid"), f"{field_name}.gid")
    _require_nonnegative_int(alert.get("sid"), f"{field_name}.sid")
    _require_nonnegative_int(alert.get("rev"), f"{field_name}.rev")
    _require_nonempty_string(alert.get("message"), f"{field_name}.message")
    _require_unique_strings(alert.get("anchor_packet_ids"), f"{field_name}.anchor_packet_ids")
    if "timestamp" in alert:
        _require_nonempty_string(alert["timestamp"], f"{field_name}.timestamp")
    if "event_data" in alert:
        _require_dict(alert["event_data"], f"{field_name}.event_data")


#This function validates the complete PRE Snort bundle consumed by IDS-aware grouping.
def validate_pre_snort_context_bundle(bundle: Any) -> None:
    source_bundle = _require_dict(bundle, "pre_snort_context_bundle")
    unexpected = set(source_bundle) - {"schema_version", "metadata", "detector_definitions", "alerts"}
    if unexpected:
        raise ValueError(f"pre_snort_context_bundle contains unsupported fields: {sorted(unexpected)}")
    if source_bundle.get("schema_version") != PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION:
        raise ValueError(
            f"pre_snort_context_bundle.schema_version must be {PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION!r}; "
            f"found {source_bundle.get('schema_version')!r}."
        )

    metadata = _require_dict(source_bundle.get("metadata"), "pre_snort_context_bundle.metadata")
    required_metadata = {
        "snort_version",
        "detector_policy",
        "snaplen",
        "builtin_rules_enabled",
        "ruleset_identifier",
        "source_artifacts",
        "source_hashes",
        "mapping_policy",
    }
    missing_metadata = required_metadata - set(metadata)
    if missing_metadata:
        raise ValueError(f"pre_snort_context_bundle.metadata is missing fields: {sorted(missing_metadata)}")
    unexpected_metadata = set(metadata) - required_metadata
    if unexpected_metadata:
        raise ValueError(
            f"pre_snort_context_bundle.metadata contains unsupported fields: {sorted(unexpected_metadata)}"
        )
    _require_nonempty_string(metadata["snort_version"], "pre_snort_context_bundle.metadata.snort_version")
    _require_nonempty_string(metadata["detector_policy"], "pre_snort_context_bundle.metadata.detector_policy")
    if isinstance(metadata["snaplen"], bool) or not isinstance(metadata["snaplen"], int) or metadata["snaplen"] <= 0:
        raise ValueError("pre_snort_context_bundle.metadata.snaplen must be a positive integer.")
    if not isinstance(metadata["builtin_rules_enabled"], bool):
        raise ValueError("pre_snort_context_bundle.metadata.builtin_rules_enabled must be a boolean.")
    _require_nonempty_string(
        metadata["ruleset_identifier"],
        "pre_snort_context_bundle.metadata.ruleset_identifier",
    )
    _require_unique_strings(
        metadata["source_artifacts"],
        "pre_snort_context_bundle.metadata.source_artifacts",
    )
    source_hashes = _require_dict(metadata["source_hashes"], "pre_snort_context_bundle.metadata.source_hashes")
    if not source_hashes:
        raise ValueError("pre_snort_context_bundle.metadata.source_hashes must not be empty.")
    for artifact_name, digest in source_hashes.items():
        _require_nonempty_string(artifact_name, "pre_snort_context_bundle.metadata.source_hashes key")
        _require_nonempty_string(digest, f"pre_snort_context_bundle.metadata.source_hashes.{artifact_name}")
    if metadata["mapping_policy"] != IDS_CONTEXT_MAPPING_POLICY:
        raise ValueError(
            f"pre_snort_context_bundle.metadata.mapping_policy must be {IDS_CONTEXT_MAPPING_POLICY!r}."
        )

    definitions = _require_list(
        source_bundle.get("detector_definitions"),
        "pre_snort_context_bundle.detector_definitions",
    )
    definition_ids: set[tuple[int, int, int]] = set()
    for index, definition in enumerate(definitions):
        field_name = f"pre_snort_context_bundle.detector_definitions[{index}]"
        _validate_detector_definition(definition, field_name)
        identity = detector_identity(_require_dict(definition, field_name))
        if identity in definition_ids:
            raise ValueError(f"Duplicate detector definition for gid/sid/rev={identity}.")
        definition_ids.add(identity)

    alerts = _require_list(source_bundle.get("alerts"), "pre_snort_context_bundle.alerts")
    alert_ids: set[str] = set()
    for index, alert in enumerate(alerts):
        field_name = f"pre_snort_context_bundle.alerts[{index}]"
        _validate_pre_alert(alert, field_name)
        alert_record = _require_dict(alert, field_name)
        alert_id = str(alert_record["alert_id"])
        if alert_id in alert_ids:
            raise ValueError(f"Duplicate pre_snort_context_bundle alert_id={alert_id!r}.")
        alert_ids.add(alert_id)
        identity = detector_identity(alert_record)
        if identity not in definition_ids:
            raise ValueError(f"Alert {alert_id!r} references missing detector definition {identity}.")
