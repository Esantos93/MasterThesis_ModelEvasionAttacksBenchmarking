from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.ids_context import (
    IDS_CONTEXT_MAPPING_POLICY,
    IDS_CONTEXT_SCHEMA_VERSION,
    PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
    detector_identity,
    strip_non_model_visible_snort_rule_options,
    validate_ids_context,
    validate_pre_snort_context_bundle,
)


#This function reads one IDS mapping source artifact from disk.
def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function projects only approved detector evidence into IDS-aware Compact Units.
def _model_visible_detector_fields(definition: dict[str, Any]) -> dict[str, Any]:
    source = str(definition["detector_source"])
    record = {
        "detector_source": source,
        "gid": int(definition["gid"]),
        "sid": int(definition["sid"]),
        "rev": int(definition["rev"]),
        "message": str(definition["message"]),
    }
    if source == "ruleset_text":
        record["rule_declaration"] = strip_non_model_visible_snort_rule_options(
            definition["rule_declaration"]
        )
    elif source == "ruleset_so":
        record["so_rule_stub"] = strip_non_model_visible_snort_rule_options(
            definition["so_rule_stub"]
        )
        security_context = definition.get("security_context")
        if isinstance(security_context, dict) and security_context.get("summary"):
            record["security_context"] = {"summary": security_context["summary"]}
    elif source == "builtin_decoder_or_inspector":
        record["inspector"] = definition["inspector"]
        record["semantic_description"] = definition["semantic_description"]
    else:
        raise ValueError(f"Unsupported PRE detector_source={source!r}.")
    return record


@dataclass(frozen=True)
class IdsContextMapping:
    source_bundle_path: Path
    packet_connection_by_id: dict[str, str]
    records_by_connection: dict[str, tuple[dict[str, Any], ...]]
    detector_definition_count: int
    pre_alert_count: int
    detector_definition_counts_by_source: dict[str, int]

    @property
    #This property reports how many TCP conversations have propagated detector evidence.
    def tcp_connections_with_ids_context(self) -> int:
        return len(self.records_by_connection)

    #This method materializes connection-propagated IDS records for the packets visible in one Compact Unit.
    def materialize(self, physical_packets: list[dict[str, Any]]) -> dict[str, Any]:
        packet_ids_by_connection: dict[str, list[str]] = {}
        for packet in physical_packets:
            packet_id_value = packet.get("packet_id")
            connection_id_value = packet.get("tcp_connection_id")
            packet_id = str(packet_id_value).strip() if packet_id_value is not None else ""
            connection_id = str(connection_id_value).strip() if connection_id_value is not None else ""
            if not packet_id or not connection_id:
                raise ValueError(
                    "IDS-aware Compact Units require packet_id and tcp_connection_id on every physical packet."
                )
            expected_connection = self.packet_connection_by_id.get(packet_id)
            if expected_connection != connection_id:
                raise ValueError(
                    f"Compact packet {packet_id!r} has tcp_connection_id={connection_id!r}, "
                    f"but Step 14 traffic maps it to {expected_connection!r}."
                )
            packet_ids_by_connection.setdefault(connection_id, []).append(packet_id)

        records: list[dict[str, Any]] = []
        for connection_id in packet_ids_by_connection:
            prompt_packet_ids = packet_ids_by_connection[connection_id]
            for base_record in self.records_by_connection.get(connection_id, ()):
                records.append(
                    {
                        **base_record,
                        "tcp_connection_packet_ids_in_prompt": list(prompt_packet_ids),
                    }
                )
        context = {"schema_version": IDS_CONTEXT_SCHEMA_VERSION, "records": records}
        validate_ids_context(context)
        return context

    #This method serializes IDS source and population counts for manifest-level audit.
    def manifest_metadata(self) -> dict[str, Any]:
        return {
            "ids_context_enabled": True,
            "ids_context_schema_version": IDS_CONTEXT_SCHEMA_VERSION,
            "ids_context_source_bundle": str(self.source_bundle_path),
            "ids_context_source_bundle_schema_version": PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
            "ids_context_mapping_policy": IDS_CONTEXT_MAPPING_POLICY,
            "ids_context_detector_definition_count": self.detector_definition_count,
            "ids_context_pre_alert_count": self.pre_alert_count,
            "ids_context_tcp_connection_count": self.tcp_connections_with_ids_context,
            "ids_context_detector_definition_counts_by_source": self.detector_definition_counts_by_source,
        }


#This function joins validated PRE alerts, detector definitions, packets, and TCP connections for Step 15.
def load_ids_context_mapping(
    *,
    source_bundle_path: Path,
    traffic: list[dict[str, Any]],
) -> IdsContextMapping:
    if not source_bundle_path.is_file():
        raise FileNotFoundError(
            "Prompt-engineering IDS context is enabled, but the canonical PRE Snort bundle is missing: "
            f"{source_bundle_path}"
        )
    bundle = _read_json(source_bundle_path)
    validate_pre_snort_context_bundle(bundle)

    packet_connection_by_id: dict[str, str] = {}
    packet_order: dict[str, tuple[int, int]] = {}
    for capture_position, packet in enumerate(traffic):
        packet_id_value = packet.get("packet_id")
        packet_id = str(packet_id_value).strip() if packet_id_value is not None else ""
        if not packet_id:
            raise ValueError("Step 14 traffic contains a packet without packet_id.")
        if packet_id in packet_connection_by_id:
            raise ValueError(f"Step 14 traffic contains duplicate packet_id={packet_id!r}.")
        connection_id_value = packet.get("tcp_connection_id")
        connection_id = str(connection_id_value).strip() if connection_id_value is not None else ""
        packet_connection_by_id[packet_id] = connection_id
        reduced_index = packet.get("reduced_packet_index")
        packet_order[packet_id] = (
            int(reduced_index) if reduced_index is not None else capture_position,
            capture_position,
        )

    definitions = bundle["detector_definitions"]
    definitions_by_identity = {detector_identity(definition): definition for definition in definitions}
    anchors_by_record: dict[tuple[int, int, int, str], set[str]] = {}
    record_order: list[tuple[int, int, int, str]] = []
    for alert in bundle["alerts"]:
        identity = detector_identity(alert)
        if identity not in definitions_by_identity:
            raise ValueError(f"PRE alert references missing detector definition {identity}.")
        anchors_by_connection: dict[str, list[str]] = {}
        for packet_id_value in alert["anchor_packet_ids"]:
            packet_id = str(packet_id_value)
            if packet_id not in packet_connection_by_id:
                raise ValueError(
                    f"PRE alert {alert['alert_id']!r} references unknown anchor packet {packet_id!r}."
                )
            connection_id = packet_connection_by_id[packet_id]
            if not connection_id:
                raise ValueError(
                    f"PRE alert {alert['alert_id']!r} anchor packet {packet_id!r} lacks tcp_connection_id."
                )
            anchors_by_connection.setdefault(connection_id, []).append(packet_id)
        for connection_id, anchor_ids in anchors_by_connection.items():
            key = (*identity, connection_id)
            if key not in anchors_by_record:
                anchors_by_record[key] = set()
                record_order.append(key)
            anchors_by_record[key].update(anchor_ids)

    records_by_connection: dict[str, list[dict[str, Any]]] = {}
    for gid, sid, rev, connection_id in record_order:
        identity = (gid, sid, rev)
        definition = definitions_by_identity[identity]
        ordered_anchor_ids = sorted(anchors_by_record[(gid, sid, rev, connection_id)], key=packet_order.__getitem__)
        record = {
            **_model_visible_detector_fields(definition),
            "tcp_connection_id": connection_id,
            "anchor_packet_ids": ordered_anchor_ids,
        }
        records_by_connection.setdefault(connection_id, []).append(record)

    detector_counts = Counter(str(definition["detector_source"]) for definition in definitions)
    return IdsContextMapping(
        source_bundle_path=source_bundle_path,
        packet_connection_by_id=packet_connection_by_id,
        records_by_connection={key: tuple(value) for key, value in records_by_connection.items()},
        detector_definition_count=len(definitions),
        pre_alert_count=len(bundle["alerts"]),
        detector_definition_counts_by_source=dict(sorted(detector_counts.items())),
    )
