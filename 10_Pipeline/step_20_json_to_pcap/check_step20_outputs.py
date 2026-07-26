from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.naming import sanitize_name_component


REPORT_SCHEMA_VERSION = "pcap_reconstruction_report_v4"
EXPECTED_SOURCE_VALIDATION_SCHEMA_VERSION = "validated_modified_traffic_v4"
DEFAULT_EXPERIMENT_ROOT = Path("/home/santos/Experiments/exp_cicids2017_baseline_004")
DEFAULT_EXPERIMENT_CONFIG_LABEL = "baseline-004-headers-only-fixed-size-6"
DEFAULT_EXPECTED_PACKET_COUNT = 99831

HEADER_ONLY_ZERO_FIELDS = [
    "tcp_payload_content_changed_packet_count",
    "tcp_payload_length_changed_packet_count",
    "resized_tcp_segment_count",
    "tcp_payload_growth_bytes",
    "tcp_payload_shrinkage_bytes",
    "tcp_net_payload_delta_bytes",
    "tcp_connections_with_payload_length_delta",
    "adjusted_tcp_sequence_packet_count",
    "adjusted_tcp_acknowledgement_packet_count",
]


def read_json(path: Path) -> dict[str, Any]:
    """Carga un fichero JSON y exige que la raiz sea un objeto."""
    with path.open("r", encoding="utf-8") as input_file:
        data = json.load(input_file)
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def file_size_mb(path: Path) -> float:
    """Devuelve el tamano del fichero en MB."""
    return path.stat().st_size / (1024 * 1024)


def format_json(value: Any) -> str:
    """Serializa un valor como JSON legible y ordenado."""
    return json.dumps(value, indent=2, sort_keys=True)


def nested_get(data: dict[str, Any], path: list[str], default: Any = None) -> Any:
    """Lee una ruta anidada de diccionarios y devuelve un valor por defecto si falta."""
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def add_equal_check(failures: list[str], label: str, actual: Any, expected: Any) -> None:
    """Anade un fallo si el valor actual no coincide con el esperado."""
    if actual != expected:
        failures.append(f"{label}: expected {expected!r}, got {actual!r}")


def add_zero_check(failures: list[str], label: str, actual: Any) -> None:
    """Anade un fallo si el contador no es cero ni nulo."""
    if actual not in (0, None):
        failures.append(f"{label}: expected 0, got {actual!r}")


def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de linea de comandos del comprobador."""
    parser = argparse.ArgumentParser(
        description=(
            "Check Step 20 reconstructed PCAP outputs and reconstruction_report.json "
            "for the selected experiment branch."
        )
    )
    parser.add_argument(
        "--experiment-root",
        default=str(DEFAULT_EXPERIMENT_ROOT),
        help="Experiment root containing 10_reconstructed_pcap/.",
    )
    parser.add_argument(
        "--experiment-config-label",
        default=DEFAULT_EXPERIMENT_CONFIG_LABEL,
        help="Step 20 output branch under 10_reconstructed_pcap/. The value is normalized like config labels.",
    )
    parser.add_argument(
        "--expected-packets",
        type=int,
        default=DEFAULT_EXPECTED_PACKET_COUNT,
        help="Expected reconstructed packet count. Use 0 to skip this check.",
    )
    parser.add_argument(
        "--allow-payload-changes",
        action="store_true",
        help="Do not enforce header-only zero payload/sequence-delta counters.",
    )
    parser.add_argument(
        "--show-first-packet-results",
        type=int,
        default=3,
        help="Print the first N non-reconstructed packet results when present.",
    )
    return parser.parse_args()


def main() -> None:
    """Ejecuta las comprobaciones principales del Step 20."""
    args = parse_args()
    experiment_root = Path(args.experiment_root).expanduser()
    experiment_config_label = sanitize_name_component(args.experiment_config_label)
    output_dir = experiment_root / "10_reconstructed_pcap" / experiment_config_label
    pcap_path = output_dir / "modified_traffic.pcap"
    report_path = output_dir / "reconstruction_report.json"
    failures: list[str] = []

    print(f"Experiment root: {experiment_root}")
    print(f"Experiment config label: {experiment_config_label}")
    print(f"Modified PCAP: {pcap_path}")
    print(f"Reconstruction report: {report_path}")

    if not report_path.exists():
        raise SystemExit(f"Missing reconstruction report: {report_path}")
    if not pcap_path.exists():
        failures.append(f"Missing modified PCAP: {pcap_path}")
    elif pcap_path.stat().st_size <= 0:
        failures.append(f"Modified PCAP is empty: {pcap_path}")
    else:
        print(f"Modified PCAP size MB: {file_size_mb(pcap_path):.2f}")

    report = read_json(report_path)
    metadata = report.get("metadata", {})
    summary = report.get("summary", {})
    source_validation_contract = report.get("source_validation_contract", {})
    tcp_summary = report.get("tcp_reconstruction_summary", {})
    protocol_summary = nested_get(report, ["network_protocol_validation", "summary"], {})
    issue_counts = protocol_summary.get("issue_counts_by_reason", {}) if isinstance(protocol_summary, dict) else {}

    print("\nMetadata:")
    print(format_json(metadata))
    print("\nSummary:")
    print(format_json(summary))
    print("\nSource validation contract:")
    print(format_json(source_validation_contract))
    print("\nTCP reconstruction summary:")
    print(format_json(tcp_summary))
    print("\nNetwork protocol validation summary:")
    print(format_json(protocol_summary))
    print("\nNetwork issue counts:")
    print(format_json(issue_counts))

    add_equal_check(failures, "metadata.schema_version", metadata.get("schema_version"), REPORT_SCHEMA_VERSION)
    add_equal_check(
        failures,
        "metadata.source_validation_schema_version",
        metadata.get("source_validation_schema_version"),
        EXPECTED_SOURCE_VALIDATION_SCHEMA_VERSION,
    )
    add_equal_check(failures, "metadata.status", metadata.get("status"), "completed")
    add_equal_check(
        failures,
        "source_validation_contract.validated_traffic_schema_version",
        source_validation_contract.get("validated_traffic_schema_version") if isinstance(source_validation_contract, dict) else None,
        EXPECTED_SOURCE_VALIDATION_SCHEMA_VERSION,
    )
    add_equal_check(
        failures,
        "metadata.experiment_config_label",
        metadata.get("experiment_config_label"),
        experiment_config_label,
    )

    input_packet_count = summary.get("input_packet_count")
    if args.expected_packets:
        add_equal_check(failures, "summary.input_packet_count", input_packet_count, args.expected_packets)
    add_equal_check(failures, "summary.written_packet_count", summary.get("written_packet_count"), input_packet_count)
    add_equal_check(
        failures,
        "summary.reconstructed_packet_count",
        summary.get("reconstructed_packet_count"),
        input_packet_count,
    )
    add_zero_check(failures, "summary.failed_packet_count", summary.get("failed_packet_count"))
    add_zero_check(failures, "summary.error_count", summary.get("error_count"))
    add_zero_check(
        failures,
        "summary.network_protocol_validation_error_count",
        summary.get("network_protocol_validation_error_count"),
    )
    add_zero_check(
        failures,
        "summary.tcp_reconstruction_error_count",
        summary.get("tcp_reconstruction_error_count"),
    )
    add_zero_check(
        failures,
        "network_protocol_validation.summary.network_protocol_validation_error_count",
        protocol_summary.get("network_protocol_validation_error_count") if isinstance(protocol_summary, dict) else None,
    )

    if not args.allow_payload_changes:
        for field in HEADER_ONLY_ZERO_FIELDS:
            add_zero_check(failures, f"tcp_reconstruction_summary.{field}", tcp_summary.get(field))

    failed_packets = [
        result
        for result in report.get("packet_results", [])
        if isinstance(result, dict) and result.get("status") != "reconstructed"
    ]
    if failed_packets:
        failures.append(f"Non-reconstructed packet results: {len(failed_packets)}")
        print("\nFirst non-reconstructed packet results:")
        print(format_json(failed_packets[: args.show_first_packet_results]))

    if failures:
        print("\nCHECK FAILED")
        for failure in failures:
            print(f"- {failure}")
        raise SystemExit(1)

    print("\nCHECK PASSED")


if __name__ == "__main__":
    main()
