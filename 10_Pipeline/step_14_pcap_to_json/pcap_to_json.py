from __future__ import annotations

import argparse
import binascii
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
from step_14_pcap_to_json.tcp_canonicalization import canonicalize_tcp_records


SCHEMA_VERSION = "packet_json_v3"
GROUPING_UNIT = "canonical_tcp_region"


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
        from scapy.all import ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_14_pcap_to_json. Install it in the Ubuntu "
            "benchmark environment before running this step."
        ) from exc
    return {
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapReader": PcapReader,
        "Raw": Raw,
        "TCP": TCP,
        "UDP": UDP,
    }


# This helper converts bytes to lowercase hexadecimal strings for JSON storage.
def bytes_to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


# This helper converts values that should be integers while preserving None for missing fields.
def integer_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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


# This function decides whether step 14 should export flow metadata and per-packet flow context for the selected experiment.
def should_include_flow_context(config: dict[str, Any]) -> bool:
    grouping_policy = str(config.get("pipeline", {}).get("grouping_policy", "")).strip()
    return grouping_policy != "fixed_packet_count"


# This function converts the step 13 flow table into a lookup keyed by flow_id.
def flow_table_by_id(flow_table: dict[str, Any]) -> dict[str, dict[str, Any]]:
    flows = flow_table.get("flows")
    if not isinstance(flows, list):
        raise ValueError("Step 13 flow table must contain a 'flows' list.")
    return {str(flow["flow_id"]): flow for flow in flows if flow.get("flow_id")}


# This function loads the definitive compact_v1 artifacts produced by step 13.
def load_step13_context(
    packet_manifest_path: str | Path,
    include_flow_context: bool,
) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest_path = Path(packet_manifest_path)
    manifest = read_json(manifest_path)
    if manifest.get("metadata", {}).get("artifact_format") != "compact_v1":
        raise ValueError("Step 14 expects the final step 13 compact_v1 manifest.")

    artifacts = manifest.get("artifacts", {})
    packet_index_path = resolve_artifact_path(manifest_path, artifacts.get("packet_index", ""))
    packet_records = read_jsonl(packet_index_path)
    flow_lookup = {}
    if include_flow_context:
        flow_table_path = resolve_artifact_path(manifest_path, artifacts.get("flow_table", ""))
        flow_lookup = flow_table_by_id(read_json(flow_table_path))

    context_by_index = {}
    for record in packet_records:
        reduced_index = reduced_index_from_packet_id(record.get("packet_id", ""))
        context_by_index[reduced_index] = {
            **record,
            "reduced_packet_index": reduced_index,
        }

    return context_by_index, flow_lookup


# This function extracts Ethernet fields using the same direct style as the original 90_Testing prototype.
def extract_ethernet(packet: Any) -> dict[str, Any]:
    return {
        "eth_src": getattr(packet, "src", "00:00:00:00:00:00"),
        "eth_dst": getattr(packet, "dst", "00:00:00:00:00:00"),
        "eth_type": integer_or_none(getattr(packet, "type", None)),
    }


# This function extracts IPv4 or IPv6 fields. Non-IP packets keep empty IP fields but still remain traceable.
def extract_ip(packet: Any, scapy: dict[str, Any]) -> dict[str, Any]:
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    if IP in packet:
        layer = packet[IP]
        return {
            "src_ip": layer.src,
            "dst_ip": layer.dst,
            "proto": integer_or_none(layer.proto),
            "ip_version": 4,
            "ttl": integer_or_none(layer.ttl),
            "ip_id": integer_or_none(layer.id),
            "ip_flags": str(layer.flags),
            "ip_len": integer_or_none(layer.len),
        }
    if IPv6 in packet:
        layer = packet[IPv6]
        return {
            "src_ip": layer.src,
            "dst_ip": layer.dst,
            "proto": integer_or_none(layer.nh),
            "ip_version": 6,
            "ttl": integer_or_none(layer.hlim),
            "ip_id": None,
            "ip_flags": "",
            "ip_len": integer_or_none(layer.plen),
        }
    return {
        "src_ip": "",
        "dst_ip": "",
        "proto": None,
        "ip_version": None,
        "ttl": None,
        "ip_id": None,
        "ip_flags": "",
        "ip_len": None,
    }


# This function extracts transport fields used by the old prototype, plus minimal UDP/ICMP support.
def extract_transport(packet: Any, scapy: dict[str, Any]) -> dict[str, Any]:
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    ICMP = scapy["ICMP"]
    if TCP in packet:
        layer = packet[TCP]
        return {
            "transport_protocol": "TCP",
            "src_port": integer_or_none(layer.sport),
            "dst_port": integer_or_none(layer.dport),
            "tcp_flags": int(layer.flags),
            "tcp_flags_str": str(layer.flags),
            "tcp_seq": int(layer.seq),
            "tcp_ack": int(layer.ack),
            "window": integer_or_none(layer.window),
            "options": str(layer.options),
        }
    if UDP in packet:
        layer = packet[UDP]
        return {
            "transport_protocol": "UDP",
            "src_port": integer_or_none(layer.sport),
            "dst_port": integer_or_none(layer.dport),
            "udp_len": integer_or_none(layer.len),
        }
    if ICMP in packet:
        layer = packet[ICMP]
        return {
            "transport_protocol": "ICMP",
            "icmp_type": integer_or_none(layer.type),
            "icmp_code": integer_or_none(layer.code),
        }
    return {"transport_protocol": "", "src_port": None, "dst_port": None}


# This function extracts the mutable application payload. This is safer for LLM edits than exposing full IP or TCP bytes as mutable data.
def extract_payload_hex(packet: Any, scapy: dict[str, Any]) -> str:
    Raw = scapy["Raw"]
    if Raw in packet:
        return bytes_to_hex(bytes(packet[Raw].load))
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    if IP in packet or IPv6 in packet:
        return ""
    payload = getattr(packet, "payload", None)
    if payload is None:
        return ""
    return bytes_to_hex(bytes(payload))


# This function estimates JSON size with compact separators without changing the record itself.
def compact_record_size(record: dict[str, Any]) -> int:
    return len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))


# This function builds one JSON packet record by combining Scapy packet fields with step 13 identity and flow context.
def build_json_record(
    packet: Any,
    reduced_packet_index: int,
    packet_context: dict[str, Any],
    include_frame_hex: bool,
    include_flow_context: bool,
    scapy: dict[str, Any],
) -> dict[str, Any]:
    packet_bytes = bytes(packet)
    packet_id = str(packet_context["packet_id"])
    payload_hex = extract_payload_hex(packet, scapy)
    record = {
        "packet_id": packet_id,
        "original_packet_number": packet_context.get("original_packet_number", ""),
        "reduced_packet_index": reduced_packet_index,
        "timestamp_epoch_pcap": packet_context.get("timestamp_epoch_pcap", 0.0),
        **extract_ethernet(packet),
        **extract_ip(packet, scapy),
        **extract_transport(packet, scapy),
        "payload_hex": payload_hex,
        "payload_length_bytes": len(payload_hex) // 2,
        "packet_length_bytes": len(packet_bytes),
    }
    if include_flow_context:
        record["flow_context"] = {
            "candidate_flow_ids": packet_context.get("candidate_flow_ids", []),
            "assigned_flow_ids": packet_context.get("assigned_flow_ids", []),
            "packet_mapping_status": packet_context.get("packet_mapping_status", ""),
        }
    if include_frame_hex:
        record["packet_bytes_hex"] = bytes_to_hex(packet_bytes)
    return record


# This helper returns the sorted flow IDs referenced by the exported packet records.
def referenced_flow_ids(records: list[dict[str, Any]]) -> list[str]:
    flow_ids = set()
    for record in records:
        context = record.get("flow_context", {})
        flow_ids.update(str(flow_id) for flow_id in context.get("candidate_flow_ids", []))
        flow_ids.update(str(flow_id) for flow_id in context.get("assigned_flow_ids", []))
    return sorted(flow_ids)


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
    include_flow_context = should_include_flow_context(config)
    input_pcap_path = Path(input_pcap).expanduser()
    if not input_pcap_path.exists():
        raise FileNotFoundError(f"Selected PCAP does not exist: {input_pcap_path}")

    context_by_index, flow_lookup = load_step13_context(packet_manifest_path, include_flow_context)
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
                include_flow_context=include_flow_context,
                scapy=scapy,
            )
            records.append(record)
            protocol_counts[str(record.get("transport_protocol") or "OTHER")] += 1

    expected_count = len(context_by_index)
    if max_packets is None and len(records) != expected_count:
        raise ValueError(
            f"Selected PCAP packet count ({len(records)}) does not match step 13 packet index count ({expected_count})."
        )

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

    record_sizes = [compact_record_size(record) for record in records]
    output = {
        "metadata": {
            "experiment_id": config["experiment"]["experiment_id"],
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "config_source": config.get("_config_path", ""),
            "schema_version": SCHEMA_VERSION,
            "grouping_policy": config.get("pipeline", {}).get("grouping_policy", ""),
            "grouping_unit": GROUPING_UNIT,
            "include_flow_context": include_flow_context,
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
            "tcp_canonicalization": tcp_summary,
        },
        "immutable_fields": [
            "packet_id",
            "original_packet_number",
            "reduced_packet_index",
            "timestamp_epoch_pcap",
        ],
        "traffic": records,
        "tcp_connections": tcp_canonicalization["tcp_connections"],
        "tcp_streams": tcp_canonicalization["tcp_streams"],
        "canonical_tcp_regions": tcp_canonicalization["canonical_tcp_regions"],
        "tcp_physical_representations": tcp_canonicalization["tcp_physical_representations"],
        "tcp_representation_sets": tcp_canonicalization["tcp_representation_sets"],
        "tcp_canonicalization_conflicts": tcp_canonicalization["tcp_canonicalization_conflicts"],
    }
    if include_flow_context:
        flow_ids = referenced_flow_ids(records)
        output["flow_context_fields"] = [
            "candidate_flow_ids",
            "assigned_flow_ids",
            "packet_mapping_status",
        ]
        output["flows"] = [flow_lookup[flow_id] for flow_id in flow_ids if flow_id in flow_lookup]
        output["metadata"]["flow_count"] = len(output["flows"])
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
