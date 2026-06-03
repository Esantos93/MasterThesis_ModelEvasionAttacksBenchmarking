from __future__ import annotations

import argparse
import binascii
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


REPORT_SCHEMA_VERSION = "pcap_reconstruction_report_v1"
DEFAULT_INPUT_SCHEMA_VERSION = "validated_modified_traffic_v1"


# This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function builds the root directory for the experiment based on the output_root and experiment_id specified in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function returns the default Step 20 input and output paths for the active experiment configuration.
# If experiment_root_override is provided, it is used instead of the experiment root stored in the config.
# This is useful when the VM artifacts are under a different folder than the one currently written in the config file.
def default_paths(config: dict[str, Any], experiment_config_label: str, experiment_root_override: str | Path | None = None) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    return {
        "input_json": experiment_root / "09_validation" / experiment_config_label / "validated_modified_traffic.json",
        "output_dir": experiment_root / "10_reconstructed_pcap" / experiment_config_label,
    }


# This function validates the minimum config keys needed by Step 20.
# Step 20 needs the experiment identity, output root, and pipeline.experiment_config_label because each config maps to one POST branch.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")

    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")


# This function returns the single pipeline.experiment_config_label configured for this run.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


# This function imports Scapy only when PCAP reconstruction actually runs.
# This keeps --help and syntax checks usable in environments where Scapy is not installed, such as the local Windows Codex runtime.
def import_scapy() -> dict[str, Any]:
    try:
        from scapy.all import Ether, ICMP, IP, IPv6, PcapWriter, Raw, TCP, UDP, raw
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for step_20_json_to_pcap. Install it in the Ubuntu "
            "benchmark environment before reconstructing PCAP files."
        ) from exc
    return {
        "Ether": Ether,
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "PcapWriter": PcapWriter,
        "Raw": Raw,
        "TCP": TCP,
        "UDP": UDP,
        "raw": raw,
    }


# This helper builds a structured issue entry for the reconstruction report.
# The report uses these entries to avoid silent repair when a packet is rebuilt with warnings or cannot be rebuilt.
def issue(severity: str, reason: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "reason": reason,
        "message": message,
        **extra,
    }


# This helper checks if a value is a real integer and not a boolean.
# It is used before assigning JSON values to Scapy header fields.
def is_int_like(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# This helper returns an integer value when the JSON field is valid, otherwise it returns the provided default.
def int_or_default(value: Any, default: int | None) -> int | None:
    if is_int_like(value):
        return value
    return default


# This function decodes the mutable payload_hex field into bytes.
# If the payload is not valid hexadecimal content, it records an error so the packet is not silently reconstructed.
def payload_bytes(record: dict[str, Any], packet_issues: list[dict[str, Any]]) -> bytes:
    payload_hex = record.get("payload_hex", "")
    if not isinstance(payload_hex, str):
        packet_issues.append(
            issue(
                "error",
                "payload_hex_not_string",
                "payload_hex must be a string before PCAP reconstruction.",
                field="payload_hex",
            )
        )
        return b""
    try:
        return binascii.unhexlify(payload_hex)
    except (binascii.Error, ValueError) as error:
        packet_issues.append(
            issue(
                "error",
                "payload_hex_invalid",
                "payload_hex could not be decoded into bytes.",
                field="payload_hex",
                failure_message=str(error),
            )
        )
        return b""


# This function rebuilds the Ethernet layer from the JSON record.
# Ethernet source, destination, and type are taken from Step 14 / Step 19 fields.
def build_ethernet(record: dict[str, Any], scapy: dict[str, Any], packet_issues: list[dict[str, Any]]) -> Any:
    Ether = scapy["Ether"]
    eth_src = record.get("eth_src")
    eth_dst = record.get("eth_dst")
    eth_type = int_or_default(record.get("eth_type"), None)
    if not isinstance(eth_src, str) or not isinstance(eth_dst, str):
        packet_issues.append(
            issue(
                "error",
                "ethernet_address_missing",
                "eth_src and eth_dst must be strings before PCAP reconstruction.",
            )
        )
        return None
    kwargs = {"src": eth_src, "dst": eth_dst}
    if eth_type is not None:
        kwargs["type"] = eth_type
    return Ether(**kwargs)


# This function rebuilds either an IPv4 or IPv6 layer from the JSON record.
# It preserves IP addresses, protocol number, TTL or hop limit, IPv4 ID, and IPv4 flags when those values are available.
def build_ip_layer(record: dict[str, Any], scapy: dict[str, Any], packet_issues: list[dict[str, Any]]) -> Any:
    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    ip_version = record.get("ip_version")
    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    if not isinstance(src_ip, str) or not src_ip or not isinstance(dst_ip, str) or not dst_ip:
        packet_issues.append(issue("error", "ip_address_missing", "src_ip and dst_ip are required for IP packets."))
        return None

    proto = int_or_default(record.get("proto"), None)
    ttl = int_or_default(record.get("ttl"), None)
    if ip_version == 4:
        kwargs = {"src": src_ip, "dst": dst_ip}
        if proto is not None:
            kwargs["proto"] = proto
        if ttl is not None:
            kwargs["ttl"] = ttl
        ip_id = int_or_default(record.get("ip_id"), None)
        if ip_id is not None:
            kwargs["id"] = ip_id
        ip_flags = record.get("ip_flags")
        if isinstance(ip_flags, str) and ip_flags:
            kwargs["flags"] = ip_flags
        return IP(**kwargs)
    if ip_version == 6:
        kwargs = {"src": src_ip, "dst": dst_ip}
        if proto is not None:
            kwargs["nh"] = proto
        if ttl is not None:
            kwargs["hlim"] = ttl
        return IPv6(**kwargs)

    packet_issues.append(
        issue(
            "error",
            "unsupported_ip_version",
            "Only IPv4 and IPv6 records can be reconstructed as IP packets.",
            ip_version=ip_version,
        )
    )
    return None


# This function rebuilds the supported transport layer from the JSON record.
# TCP, UDP, and ICMP are reconstructed explicitly. Unsupported transport protocols are reported and the payload is attached after the IP layer.
def build_transport_layer(record: dict[str, Any], scapy: dict[str, Any], packet_issues: list[dict[str, Any]]) -> Any:
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]
    ICMP = scapy["ICMP"]
    transport_protocol = str(record.get("transport_protocol") or "").upper()

    if transport_protocol == "TCP":
        src_port = int_or_default(record.get("src_port"), None)
        dst_port = int_or_default(record.get("dst_port"), None)
        if src_port is None or dst_port is None:
            packet_issues.append(issue("error", "tcp_ports_missing", "TCP records require src_port and dst_port."))
            return None
        kwargs = {
            "sport": src_port,
            "dport": dst_port,
            "flags": int_or_default(record.get("tcp_flags"), 0),
        }
        window = int_or_default(record.get("window"), None)
        if window is not None:
            kwargs["window"] = window
        options = record.get("options")
        if options not in (None, "", "[]"):
            # Step 14 stores TCP options as a display string, not as a safe structured object for Scapy reconstruction.
            packet_issues.append(
                issue(
                    "warning",
                    "tcp_options_not_reconstructed",
                    "TCP options are stored as a display string and are not reconstructed by Step 20.",
                    field="options",
                    policy="omit_non_structured_tcp_options",
                )
            )
        return TCP(**kwargs)

    if transport_protocol == "UDP":
        src_port = int_or_default(record.get("src_port"), None)
        dst_port = int_or_default(record.get("dst_port"), None)
        if src_port is None or dst_port is None:
            packet_issues.append(issue("error", "udp_ports_missing", "UDP records require src_port and dst_port."))
            return None
        return UDP(sport=src_port, dport=dst_port)

    if transport_protocol == "ICMP":
        kwargs = {
            "type": int_or_default(record.get("icmp_type"), 8),
            "code": int_or_default(record.get("icmp_code"), 0),
        }
        return ICMP(**kwargs)

    if transport_protocol:
        packet_issues.append(
            issue(
                "warning",
                "transport_protocol_not_reconstructed",
                "Unsupported transport protocol; payload is attached directly after the IP layer.",
                transport_protocol=transport_protocol,
            )
        )
    return None


# This function extracts group-level context from the Step 18 merge trace when it is present.
# The context is stored in packet and group results so later alert comparison can map reconstructed POST packets back to their LLM group.
def group_context_for_record(record: dict[str, Any], record_index: int) -> dict[str, Any]:
    merge_trace = record.get("_merge_trace")
    if isinstance(merge_trace, dict):
        return {
            "condition": merge_trace.get("condition"),
            "model_name": merge_trace.get("model_name"),
            "group_id": merge_trace.get("group_id"),
            "group_key": f"{merge_trace.get('condition')}::{merge_trace.get('group_id')}",
            "_merge_trace": merge_trace,
        }
    group_id = record.get("group_id")
    if group_id is not None:
        return {"condition": None, "model_name": None, "group_id": str(group_id), "group_key": f"unknown::{group_id}"}
    return {"condition": None, "model_name": None, "group_id": None, "group_key": f"unassigned_record_{record_index}"}


# This function reconstructs one packet and returns both the Scapy packet object and its report entry.
# If a packet has any error-level issue, the Scapy packet is not returned and the packet is classified as Invalid Traffic.
def reconstruct_one_packet(record: Any, record_index: int, scapy: dict[str, Any]) -> dict[str, Any]:
    packet_issues: list[dict[str, Any]] = []
    if not isinstance(record, dict):
        return {
            "packet": None,
            "result": {
                "record_index": record_index,
                "packet_id": None,
                "status": "failed",
                "evaluation_status": "Invalid Traffic",
                "issues": [
                    issue("error", "traffic_record_not_object", "Traffic record is not a JSON object.")
                ],
            },
        }

    context = group_context_for_record(record, record_index)
    payload = payload_bytes(record, packet_issues)
    ether = build_ethernet(record, scapy, packet_issues)
    ip_layer = build_ip_layer(record, scapy, packet_issues)
    transport = build_transport_layer(record, scapy, packet_issues)

    # The packet is assembled layer by layer so Scapy can recalculate lengths and checksums from the final structure.
    packet = None
    if ether is not None and ip_layer is not None:
        packet = ether / ip_layer
        if transport is not None:
            packet = packet / transport
        if payload:
            packet = packet / scapy["Raw"](load=payload)

    # PCAP timestamps are preserved when Step 19 kept a numeric timestamp_epoch_pcap value.
    if packet is not None and isinstance(record.get("timestamp_epoch_pcap"), (int, float)):
        packet.time = float(record["timestamp_epoch_pcap"])
    elif packet is not None:
        packet_issues.append(
            issue(
                "warning",
                "timestamp_not_preserved",
                "timestamp_epoch_pcap was not numeric; Scapy will use the current write time.",
                field="timestamp_epoch_pcap",
            )
        )

    # These checks do not block reconstruction. They record differences caused by Scapy rebuilding the packet from structured fields.
    if packet is not None:
        rebuilt_length = len(scapy["raw"](packet))
        declared_packet_length = record.get("packet_length_bytes")
        if is_int_like(declared_packet_length) and declared_packet_length != rebuilt_length:
            packet_issues.append(
                issue(
                    "warning",
                    "packet_length_changed_after_reconstruction",
                    "Rebuilt packet length differs from packet_length_bytes stored in JSON.",
                    expected_json_value=declared_packet_length,
                    rebuilt_packet_length_bytes=rebuilt_length,
                    policy="scapy_recalculates_lengths_from_rebuilt_layers",
                )
            )
        declared_payload_length = record.get("payload_length_bytes")
        if is_int_like(declared_payload_length) and declared_payload_length != len(payload):
            packet_issues.append(
                issue(
                    "warning",
                    "payload_length_bytes_mismatch",
                    "payload_length_bytes differs from decoded payload_hex length.",
                    expected_json_value=declared_payload_length,
                    decoded_payload_length_bytes=len(payload),
                )
            )

    has_error = any(item["severity"] == "error" for item in packet_issues)
    result = {
        "record_index": record_index,
        "packet_id": record.get("packet_id"),
        "original_packet_number": record.get("original_packet_number"),
        "reduced_packet_index": record.get("reduced_packet_index"),
        "timestamp_epoch_pcap": record.get("timestamp_epoch_pcap"),
        "group_key": context["group_key"],
        "condition": context["condition"],
        "model_name": context["model_name"],
        "group_id": context["group_id"],
        "_merge_trace": context.get("_merge_trace"),
        "status": "failed" if has_error else "reconstructed",
        "evaluation_status": "Invalid Traffic" if has_error else "Reconstructed Traffic",
        "issues": packet_issues,
    }
    return {"packet": None if has_error else packet, "result": result}


# This function writes the reconstructed Scapy packets to a PCAP file.
# The linktype is Ethernet because Step 14 exports Ethernet-layer records and Step 20 rebuilds Ether frames.
def write_packets(output_pcap_path: Path, packets: list[Any], scapy: dict[str, Any]) -> None:
    output_pcap_path.parent.mkdir(parents=True, exist_ok=True)
    PcapWriter = scapy["PcapWriter"]
    writer = PcapWriter(str(output_pcap_path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


# This function aggregates packet-level reconstruction results into group-level results.
# It keeps the same group validity principle used in Step 19: if any packet in a group fails, the group is marked as Invalid Traffic.
# It does not copy the full packet issue objects into the group result, because those details already live in packet_results.
def summarize_groups(packet_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for result in packet_results:
        key = result["group_key"]
        if key not in groups:
            groups[key] = {
                "group_key": key,
                "condition": result.get("condition"),
                "model_name": result.get("model_name"),
                "group_id": result.get("group_id"),
                "packet_ids": [],
                "record_indexes": [],
                "reconstructed_packet_count": 0,
                "failed_packet_count": 0,
                "issue_counts_by_reason": defaultdict(int),
                "warning_count": 0,
                "error_count": 0,
            }
        group = groups[key]
        group["record_indexes"].append(result["record_index"])
        if result.get("packet_id") is not None:
            group["packet_ids"].append(result["packet_id"])
        if result["status"] == "reconstructed":
            group["reconstructed_packet_count"] += 1
        else:
            group["failed_packet_count"] += 1
        for item in result["issues"]:
            group["issue_counts_by_reason"][item["reason"]] += 1
            if item["severity"] == "warning":
                group["warning_count"] += 1
            elif item["severity"] == "error":
                group["error_count"] += 1

    group_results = []
    for group in groups.values():
        failed = group["failed_packet_count"] > 0
        issue_counts_by_reason = dict(sorted(group.pop("issue_counts_by_reason").items()))
        group_results.append(
            {
                **group,
                "status": "Invalid Traffic" if failed else "Reconstructed Traffic",
                "invalid_traffic": failed,
                "packet_count": len(group["record_indexes"]),
                "issue_counts_by_reason": issue_counts_by_reason,
            }
        )
    return sorted(group_results, key=lambda item: item["group_key"])


# This function runs the core Step 20 reconstruction logic.
# It reads Step 19 validated traffic, reconstructs accepted POST packets, writes the PCAP, and writes a detailed reconstruction report.
def reconstruct_validated_traffic(
    *,
    config: dict[str, Any],
    input_json_path: Path,
    output_pcap_path: Path,
    report_path: Path,
    experiment_config_label: str,
) -> dict[str, Any]:
    if not input_json_path.exists():
        raise FileNotFoundError(f"Step 19 validated traffic JSON does not exist: {input_json_path}")

    validated_json = read_json(input_json_path)
    metadata = validated_json.get("metadata", {}) if isinstance(validated_json, dict) else {}
    traffic = validated_json.get("traffic") if isinstance(validated_json, dict) else None
    if not isinstance(traffic, list):
        raise ValueError(f"Validated traffic JSON must contain a top-level traffic list: {input_json_path}")

    # Scapy is imported after the input JSON exists and has the expected root shape, so path/schema errors appear before dependency errors.
    scapy = import_scapy()
    packets = []
    packet_results = []
    for record_index, record in enumerate(traffic, start=1):
        reconstruction = reconstruct_one_packet(record, record_index, scapy)
        packet_results.append(reconstruction["result"])
        if reconstruction["packet"] is not None:
            packets.append(reconstruction["packet"])

    write_packets(output_pcap_path, packets, scapy)
    group_results = summarize_groups(packet_results)
    issue_counts_by_reason: dict[str, int] = defaultdict(int)
    severity_counts: Counter[str] = Counter()
    for result in packet_results:
        for item in result["issues"]:
            issue_counts_by_reason[item["reason"]] += 1
            severity_counts[item["severity"]] += 1

    now = datetime.now(timezone.utc).isoformat()
    # The report stores both the policy and the packet results so later alert comparison can distinguish real evasion from reconstruction problems.
    report = {
        "metadata": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at_utc": now,
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "experiment_config_label": experiment_config_label,
            "input_json": str(input_json_path),
            "source_validation_schema_version": metadata.get("schema_version", DEFAULT_INPUT_SCHEMA_VERSION),
            "output_pcap": str(output_pcap_path),
            "reconstruction_policy": {
                "source_of_reconstructible_post_traffic": "Step 19 validated_modified_traffic.json",
                "failed_modification_groups_reconstructed": False,
                "invalid_traffic_groups_reconstructed": False,
                "timestamp_policy": "preserve timestamp_epoch_pcap when numeric",
                "checksum_policy": "Scapy recalculates checksums from rebuilt layers at write time",
                "length_policy": "Scapy recalculates IP, TCP, UDP, and frame lengths from rebuilt layers",
                "automatic_repair_policy": "Do not silently repair; report omitted fields, recalculated lengths, and packet failures.",
                "tcp_options_policy": "Step 14 stores TCP options as display strings, so Step 20 omits non-empty options and reports a warning.",
            },
        },
        "summary": {
            "input_packet_count": len(traffic),
            "reconstructed_packet_count": len(packets),
            "failed_packet_count": len(traffic) - len(packets),
            "group_count": len(group_results),
            "reconstructed_group_count": sum(1 for group in group_results if not group["invalid_traffic"]),
            "invalid_traffic_group_count": sum(1 for group in group_results if group["invalid_traffic"]),
            "warning_count": severity_counts.get("warning", 0),
            "error_count": severity_counts.get("error", 0),
            "issue_counts_by_reason": dict(sorted(issue_counts_by_reason.items())),
        },
        "source_validation_metadata": metadata,
        "group_results": group_results,
        "packet_results": packet_results,
    }
    write_json(report_path, report)
    return {
        "input_json": str(input_json_path),
        "output_pcap": str(output_pcap_path),
        "reconstruction_report": str(report_path),
        **report["summary"],
    }


# This function is the public Python entry point for Step 20.
# It loads the config, resolves the active experiment_config_label paths, and delegates the actual reconstruction work.
def run_reconstruction(
    *,
    config_path: str | Path,
    input_json: str | Path | None,
    output_dir: str | Path | None,
    output_pcap: str | Path | None,
    experiment_root: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    paths = default_paths(config, experiment_config_label, experiment_root)
    input_json_path = Path(input_json).expanduser() if input_json else paths["input_json"]
    reconstruction_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    output_pcap_path = Path(output_pcap).expanduser() if output_pcap else reconstruction_output_dir / "modified_traffic.pcap"
    report_path = reconstruction_output_dir / "reconstruction_report.json"
    return reconstruct_validated_traffic(
        config=config,
        input_json_path=input_json_path,
        output_pcap_path=output_pcap_path,
        report_path=report_path,
        experiment_config_label=experiment_config_label,
    )


# This function parses command-line arguments for Step 20.
# The --experiment-root override is available because the active VM artifact folder may differ from experiment.output_root in the config.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconstruct Step 20 modified PCAP from Step 19 validated JSON.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--input", dest="input_json", help="Path to Step 19 validated_modified_traffic.json.")
    add("--output-dir", help="Directory where Step 20 outputs will be written.")
    add("--output-pcap", help="Optional explicit path for modified_traffic.pcap.")
    add(
        "--experiment-root",
        help=(
            "Optional experiment root override. Useful when the VM artifact root differs from "
            "experiment.output_root in the config."
        ),
    )
    return parser.parse_args()


# This function is the command-line entry point. It prints the reconstruction summary and output paths.
def main() -> None:
    args = parse_cli_args()
    result = run_reconstruction(
        config_path=args.config,
        input_json=args.input_json,
        output_dir=args.output_dir,
        output_pcap=args.output_pcap,
        experiment_root=args.experiment_root,
    )
    print(f"Input packets: {result['input_packet_count']}")
    print(f"Reconstructed packets: {result['reconstructed_packet_count']}")
    print(f"Failed packets: {result['failed_packet_count']}")
    print(f"Reconstructed groups: {result['reconstructed_group_count']}")
    print(f"Invalid traffic groups: {result['invalid_traffic_group_count']}")
    print(f"Warnings: {result['warning_count']}")
    print(f"Errors: {result['error_count']}")
    print(f"Input JSON: {result['input_json']}")
    print(f"Modified PCAP: {result['output_pcap']}")
    print(f"Reconstruction report: {result['reconstruction_report']}")


if __name__ == "__main__":
    main()
