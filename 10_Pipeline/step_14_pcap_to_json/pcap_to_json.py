from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from step_14_pcap_to_json.packet_headers_extraction import (
    DERIVED_HEADER_FACTS,
    HEADER_FIELD_DEFINITIONS,
    bytes_to_hex,
    extract_physical_packet_facts,
)
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records


SCHEMA_VERSION = "packet_json_v4"
GROUPING_UNIT = "physical_packet"


# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function reads a JSONL file and returns one dictionary per non-empty line.
def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records = []
    with Path(path).open("r", encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if not isinstance(record, dict):
                raise ValueError(f"JSONL record at line {line_number} is not an object: {path}")
            records.append(record)
    return records


# This function imports Scapy only when the conversion actually runs. This keeps --help usable before Scapy is installed.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import PcapReader
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_14_pcap_to_json. Install it in the Ubuntu "
            "benchmark environment before running this step."
        ) from exc
    return {"PcapReader": PcapReader}


# This function derives the reduced packet index from the stable step 13 packet_id format.
def reduced_index_from_packet_id(packet_id: Any) -> int:
    text = str(packet_id).strip()
    if not text.startswith("packet_"):
        raise ValueError(f"Invalid packet_id in packet index: {packet_id}")
    return int(text.removeprefix("packet_"))


# This function resolves artifact paths stored in the compact step 13 manifest.
def resolve_artifact_path(manifest_path: Path, artifact_value: Any) -> Path:
    artifact_path = Path(str(artifact_value)).expanduser()
    if artifact_path.is_absolute():
        return artifact_path
    return manifest_path.parent / artifact_path


# This function returns the default input and output paths derived from the experiment directory created in step 11.
def default_paths(config: dict[str, Any]) -> dict[str, Path]:
    experiment_root = build_experiment_root(config)
    return {
        "input_pcap": experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap",
        "packet_manifest": experiment_root / "03_selected_traffic" / "selected_packet_manifest.json",
        "output_json": experiment_root / "04_packet_json" / "selected_packet_records.json",
    }


# This function loads the definitive compact_v1 artifacts produced by step 13.
def load_step13_context(packet_manifest_path: str | Path) -> dict[int, dict[str, Any]]:
    manifest_path = Path(packet_manifest_path)
    manifest = read_json(manifest_path)
    if manifest.get("metadata", {}).get("artifact_format") != "compact_v1":
        raise ValueError("Step 14 expects the final step 13 compact_v1 manifest.")

    artifacts = manifest.get("artifacts", {})
    packet_index_path = resolve_artifact_path(manifest_path, artifacts.get("packet_index", ""))
    packet_records = read_jsonl(packet_index_path)
    context_by_index = {}
    for record in packet_records:
        reduced_index = reduced_index_from_packet_id(record.get("packet_id", ""))
        context_by_index[reduced_index] = {
            **record,
            "reduced_packet_index": reduced_index,
        }

    return context_by_index


# This function estimates JSON size with compact separators without changing the record itself.
def compact_record_size(record: dict[str, Any]) -> int:
    return len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))


# This function builds one JSON packet record by combining Scapy packet facts with step 13 packet identity.
def build_json_record(
    packet: Any,
    reduced_packet_index: int,
    packet_context: dict[str, Any],
    include_frame_hex: bool,
) -> dict[str, Any]:
    packet_bytes = bytes(packet)
    packet_id = str(packet_context["packet_id"])
    facts = extract_physical_packet_facts(packet_bytes)
    ethernet = facts["ethernet_header"]
    ipv4 = facts["ipv4_header"]
    tcp = facts["tcp_header"]
    tcp_flag_letters = "".join(
        letter
        for key, letter in [
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
        if tcp["flags"][key]
    )
    record = {
        "packet_id": packet_id,
        "original_packet_number": packet_context.get("original_packet_number", ""),
        "reduced_packet_index": reduced_packet_index,
        "timestamp_epoch_pcap": packet_context.get("timestamp_epoch_pcap", 0.0),
        "eth_src": ethernet["source_mac"],
        "eth_dst": ethernet["destination_mac"],
        "eth_type": ethernet["ether_type"],
        "src_ip": ipv4["source_address"],
        "dst_ip": ipv4["destination_address"],
        "proto": ipv4["protocol"],
        "ip_version": ipv4["version"],
        "ttl": ipv4["ttl"],
        "ip_id": ipv4["identification"],
        "ip_flags": "".join(
            name
            for enabled, name in [
                (ipv4["flags"]["dont_fragment"], "DF"),
                (ipv4["flags"]["more_fragments"], "MF"),
            ]
            if enabled
        ),
        "ip_len": ipv4["total_length"],
        "transport_protocol": "TCP",
        "src_port": tcp["source_port"],
        "dst_port": tcp["destination_port"],
        "tcp_flags": tcp["flags"]["raw"],
        "tcp_flags_str": tcp_flag_letters,
        "tcp_seq": tcp["sequence_number"],
        "tcp_ack": tcp["acknowledgement_number"],
        "window": tcp["window"],
        "ethernet_header": ethernet,
        "ipv4_header": ipv4,
        "tcp_header": tcp,
        "payload_hex": facts["payload_hex"],
        "payload_length_bytes": facts["payload_length_bytes"],
        "captured_frame_bytes_accounted_for": facts["captured_frame_bytes_accounted_for"],
        "packet_length_bytes": len(packet_bytes),
    }
    if include_frame_hex:
        record["packet_bytes_hex"] = bytes_to_hex(packet_bytes)
    return record


# This function verifies packet order, stable identity and complete structured headers before the artifact is written.
def validate_physical_packet_contract(
    records: list[dict[str, Any]],
    context_by_index: dict[int, dict[str, Any]],
    max_packets: int | None,
) -> None:
    expected_count = min(len(context_by_index), max_packets) if max_packets is not None else len(context_by_index)
    if len(records) != expected_count:
        raise ValueError(f"Step 14 produced {len(records)} records but expected {expected_count}.")
    for expected_index, record in enumerate(records, start=1):
        context = context_by_index.get(expected_index)
        if context is None:
            raise ValueError(f"Missing Step 13 identity context for reduced_packet_index={expected_index}.")
        for field in ["packet_id", "original_packet_number", "timestamp_epoch_pcap"]:
            if record.get(field) != context.get(field):
                raise ValueError(f"Step 14 changed {field} for reduced_packet_index={expected_index}.")
        if int(record.get("reduced_packet_index") or 0) != expected_index:
            raise ValueError(f"Step 14 packet order changed at reduced_packet_index={expected_index}.")
        ethernet = record.get("ethernet_header", {})
        ipv4 = record.get("ipv4_header", {})
        tcp = record.get("tcp_header", {})
        if ethernet.get("encapsulation") != "ethernet_ii":
            raise ValueError(f"Packet {record.get('packet_id')} is not Ethernet II.")
        if ipv4.get("version") != 4 or ipv4.get("capture_relation", {}).get("status") == "truncated":
            raise ValueError(f"Packet {record.get('packet_id')} lacks a complete IPv4 datagram.")
        if record.get("transport_protocol") != "TCP" or tcp.get("payload_capture_status") == "truncated":
            raise ValueError(f"Packet {record.get('packet_id')} lacks a complete TCP segment.")
        if not record.get("captured_frame_bytes_accounted_for"):
            raise ValueError(f"Packet {record.get('packet_id')} has unaccounted captured bytes.")


# This function summarizes observed physical-header facts without classifying any field as editable.
def summarize_physical_headers(records: list[dict[str, Any]]) -> dict[str, Any]:
    tcp_option_counts: Counter[str] = Counter()
    for record in records:
        tcp_option_counts.update(option["name"] for option in record["tcp_header"]["options"])
    return {
        "ethernet_ii_packet_count": sum(
            record["ethernet_header"]["encapsulation"] == "ethernet_ii" for record in records
        ),
        "vlan_packet_count": sum(record["ethernet_header"]["vlan_present"] for record in records),
        "ipv4_packet_count": sum(record["ipv4_header"]["version"] == 4 for record in records),
        "fragmented_ipv4_packet_count": sum(record["ipv4_header"]["fragmented"] for record in records),
        "tcp_packet_count": sum(record["transport_protocol"] == "TCP" for record in records),
        "ethernet_padding_packet_count": sum(record["ethernet_header"]["padding_present"] for record in records),
        "ipv4_options_packet_count": sum(bool(record["ipv4_header"]["options_raw_hex"]) for record in records),
        "tcp_options_packet_count": sum(bool(record["tcp_header"]["options_raw_hex"]) for record in records),
        "tcp_option_counts": dict(sorted(tcp_option_counts.items())),
        "all_captured_frame_bytes_accounted_for": all(
            record["captured_frame_bytes_accounted_for"] for record in records
        ),
    }


# This function prevents contradictory original stream bytes from reaching downstream ownership or editability logic.
def reject_canonical_conflicts(tcp_summary: dict[str, Any]) -> None:
    conflict_count = int(tcp_summary.get("conflict_count") or 0)
    if conflict_count:
        raise ValueError(
            "Step 14 found contradictory TCP payload bytes and refuses to produce a downstream reference artifact: "
            f"conflicts={conflict_count}."
        )


# This function reads the selected PCAP and converts each selected packet into a traceable JSON record.
def convert_pcap_to_json_records(
    config: dict[str, Any],
    input_pcap: str | Path,
    packet_manifest_path: str | Path,
    include_frame_hex: bool,
    max_packets: int | None,
) -> dict[str, Any]:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id"], "experiment")
    require_keys(config["pipeline"], ["grouping_unit"], "pipeline")
    if str(config["pipeline"]["grouping_unit"]).strip() != GROUPING_UNIT:
        raise ValueError(f"Step 14 requires pipeline.grouping_unit={GROUPING_UNIT!r}.")

    scapy = import_scapy()
    PcapReader = scapy["PcapReader"]
    input_pcap_path = Path(input_pcap).expanduser()
    if not input_pcap_path.exists():
        raise FileNotFoundError(f"Selected PCAP does not exist: {input_pcap_path}")

    context_by_index = load_step13_context(packet_manifest_path)
    records = []
    protocol_counts: Counter[str] = Counter()

    with PcapReader(str(input_pcap_path)) as reader:
        for reduced_packet_index, packet in enumerate(reader, start=1):
            if max_packets is not None and reduced_packet_index > max_packets:
                break
            packet_context = context_by_index.get(reduced_packet_index)
            if packet_context is None:
                raise ValueError(f"Step 13 packet index has no record for reduced_packet_index={reduced_packet_index}.")
            record = build_json_record(
                packet=packet,
                reduced_packet_index=reduced_packet_index,
                packet_context=packet_context,
                include_frame_hex=include_frame_hex,
            )
            records.append(record)
            protocol_counts[str(record.get("transport_protocol") or "OTHER")] += 1

    expected_count = len(context_by_index)
    if max_packets is None and len(records) != expected_count:
        raise ValueError(
            f"Selected PCAP packet count ({len(records)}) does not match step 13 packet index count ({expected_count})."
        )
    validate_physical_packet_contract(records, context_by_index, max_packets)
    physical_header_summary = summarize_physical_headers(records)

    # TCP canonicalization is independent of the later grouping policy and always runs before Step 15.
    tcp_canonicalization = canonicalize_tcp_records(records)
    tcp_summary = tcp_canonicalization["summary"]
    if tcp_summary["tcp_packet_count"] != protocol_counts.get("TCP", 0):
        raise ValueError("TCP canonicalization did not account for every TCP packet record.")
    tcp_packets_without_connection = [
        record.get("packet_id")
        for record in records
        if record.get("transport_protocol") == "TCP" and not record.get("tcp_connection_id")
    ]
    if tcp_packets_without_connection:
        raise ValueError(f"TCP packets without canonical connection identity: {tcp_packets_without_connection[:10]}")
    reject_canonical_conflicts(tcp_summary)

    record_sizes = [compact_record_size(record) for record in records]
    output = {
        "metadata": {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "schema_version": SCHEMA_VERSION,
            "grouping_policy": config.get("pipeline", {}).get("grouping_policy", ""),
            "grouping_unit": GROUPING_UNIT,
            "source_selected_pcap": str(input_pcap_path),
            "packet_manifest_path": str(packet_manifest_path),
            "packet_count": len(records),
            "step13_packet_index_count": expected_count,
            "max_packets": max_packets,
            "include_frame_hex": include_frame_hex,
            "packet_record_size_bytes_compact": {
                "average": round(sum(record_sizes) / len(record_sizes), 2) if record_sizes else 0,
                "min": min(record_sizes) if record_sizes else 0,
                "max": max(record_sizes) if record_sizes else 0,
            },
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "physical_header_summary": physical_header_summary,
            "tcp_canonicalization": tcp_summary,
        },
        "identity_fields": [
            "packet_id",
            "original_packet_number",
            "reduced_packet_index",
            "timestamp_epoch_pcap",
        ],
        "header_field_definitions": HEADER_FIELD_DEFINITIONS,
        "derived_header_fact_definitions": DERIVED_HEADER_FACTS,
        "traffic": records,
        "tcp_connections": tcp_canonicalization["tcp_connections"],
        "tcp_streams": tcp_canonicalization["tcp_streams"],
        "canonical_tcp_regions": tcp_canonicalization["canonical_tcp_regions"],
        "tcp_physical_representations": tcp_canonicalization["tcp_physical_representations"],
        "tcp_representation_sets": tcp_canonicalization["tcp_representation_sets"],
        "tcp_canonicalization_conflicts": tcp_canonicalization["tcp_canonicalization_conflicts"],
    }
    return output


# This function runs the full conversion and writes the output JSON artifact.
def run_conversion(
    config_path: str | Path,
    input_pcap: str | Path | None,
    packet_manifest_path: str | Path | None,
    output_json: str | Path | None,
    include_frame_hex: bool,
    max_packets: int | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    paths = default_paths(config)
    input_pcap_file = Path(input_pcap) if input_pcap else paths["input_pcap"]
    packet_manifest_file = Path(packet_manifest_path) if packet_manifest_path else paths["packet_manifest"]
    output_json_file = Path(output_json) if output_json else paths["output_json"]

    packet_json = convert_pcap_to_json_records(
        config=config,
        input_pcap=input_pcap_file,
        packet_manifest_path=packet_manifest_file,
        include_frame_hex=include_frame_hex,
        max_packets=max_packets,
    )
    write_json(output_json_file, packet_json)
    output_size = output_json_file.stat().st_size
    packet_json["metadata"]["output_json_size_bytes_pretty"] = output_size
    write_json(output_json_file, packet_json)

    return {
        "output_json": str(output_json_file),
        "packet_count": packet_json["metadata"]["packet_count"],
        "output_json_size_bytes": output_json_file.stat().st_size,
        "average_record_size_bytes": packet_json["metadata"]["packet_record_size_bytes_compact"]["average"],
        "tcp_canonicalization": packet_json["metadata"]["tcp_canonicalization"],
    }


# This function defines the CLI arguments used for full runs and smoke tests.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert selected PCAP packets to traceable JSON records.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input-pcap", help="Path to selected_malicious_traffic.pcap.")
    add("--packet-manifest", help="Path to the compact step 13 selected_packet_manifest.json.")
    add("--output", help="Path for selected_packet_records.json.")
    add("--include-frame-hex", action="store_true", help="Embed full packet bytes in each JSON record.")
    add("--max-packets", type=int, help="Optional cap for smoke tests.")
    return parser.parse_args()


# This is the command-line entry point. It prints the packet-level conversion summary.
def main() -> None:
    args = parse_cli_args()
    result = run_conversion(
        config_path=args.config,
        input_pcap=args.input_pcap,
        packet_manifest_path=args.packet_manifest,
        output_json=args.output,
        include_frame_hex=args.include_frame_hex,
        max_packets=args.max_packets,
    )
    print(f"Packet JSON records: {result['packet_count']}")
    print(f"Average compact record size: {result['average_record_size_bytes']} bytes")
    tcp_summary = result["tcp_canonicalization"]
    print(
        "TCP canonicalization: "
        f"connections={tcp_summary['tcp_connection_count']}, "
        f"streams={tcp_summary['tcp_stream_count']}, "
        f"regions={tcp_summary['canonical_region_count']}, "
        f"conflicts={tcp_summary['conflict_count']}, "
        f"oversized_frames={tcp_summary['oversized_frame_count']}"
    )
    print(f"Packet JSON written to: {result['output_json']}")


if __name__ == "__main__":
    main()
