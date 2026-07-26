import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    """Carga un fichero JSON y devuelve su contenido como diccionario."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def file_size_mb(path: Path) -> str:
    """Devuelve el tamano del fichero en MB, o una cadena vacia si no existe."""
    if not path.exists():
        return ""
    return f"{path.stat().st_size / (1024 * 1024):.2f} MB"


def print_json(title: str, data: Any, limit: int | None = None) -> None:
    """Imprime una seccion JSON, recortandola si se define un limite."""
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if limit is not None:
        text = text[:limit]
    print(f"\n{title}")
    print(text)


def print_expected_files(step19_dir: Path) -> tuple[Path, Path]:
    """Muestra y devuelve los ficheros esperados del Step 19."""
    validated = step19_dir / "validated_modified_traffic.json"
    validation_report = step19_dir / "validation_report.json"

    print("STEP 19 FILES")
    for path in [validated, validation_report]:
        print(f"{path}: exists={path.exists()} {file_size_mb(path)}")

    missing = [path for path in [validated, validation_report] if not path.exists()]
    if missing:
        missing_text = "\n".join(str(path) for path in missing)
        raise SystemExit(f"\nMissing expected Step 19 output files:\n{missing_text}")

    return validated, validation_report


def summarize_step19(validated: Path, validation_report: Path, sample_size: int) -> None:
    """Resume metadata, contadores y muestras relevantes del Step 19."""
    validated_data = load_json(validated)
    report_data = load_json(validation_report)

    print_json("STEP 19 METADATA", validated_data.get("metadata", {}), limit=4000)
    print_json("STEP 19 SUMMARY", report_data.get("summary", {}))
    print_json("STEP 19 ROOT ISSUES", report_data.get("root_issues", []), limit=5000)

    print("\nSTEP 19 INVALID TRAFFIC GROUPS COUNT")
    print(len(report_data.get("invalid_traffic_groups", [])))

    print("\nSTEP 19 LLM OUTPUT FAILURE GROUPS COUNT")
    print(len(report_data.get("llm_output_failure_groups", [])))

    packet_results = report_data.get("packet_results", [])
    status_counts = Counter(packet.get("status", "<missing>") for packet in packet_results)
    evaluation_counts = Counter(packet.get("evaluation_status", "<missing>") for packet in packet_results)
    authorization_counts = Counter(packet.get("authorization_materialization_status", "<missing>") for packet in packet_results)
    semantic_counts = Counter(packet.get("semantic_protocol_status", "<missing>") for packet in packet_results)
    payload_functional_counts = Counter(packet.get("payload_functional_coherence_status", "<missing>") for packet in packet_results)

    print("\nSTEP 19 PACKET RESULT COUNTS")
    print("status:", json.dumps(dict(sorted(status_counts.items())), indent=2, ensure_ascii=False))
    print("evaluation_status:", json.dumps(dict(sorted(evaluation_counts.items())), indent=2, ensure_ascii=False))
    print("authorization_materialization_status:", json.dumps(dict(sorted(authorization_counts.items())), indent=2, ensure_ascii=False))
    print("semantic_protocol_status:", json.dumps(dict(sorted(semantic_counts.items())), indent=2, ensure_ascii=False))
    print("payload_functional_coherence_status:", json.dumps(dict(sorted(payload_functional_counts.items())), indent=2, ensure_ascii=False))

    rejected = [packet for packet in packet_results if packet.get("status") == "rejected"]
    print_json("FIRST REJECTED PACKET RESULTS", rejected[:sample_size], limit=5000)

    traffic = validated_data.get("traffic", [])
    print("\nVALIDATED TRAFFIC COUNT")
    print(len(traffic))

    print_json("FIRST VALIDATED PACKET", (traffic or [{}])[0], limit=3000)


def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de linea de comandos del comprobador."""
    parser = argparse.ArgumentParser(description="Inspect Step 19 validation output and report.")
    parser.add_argument(
        "--experiment-root",
        required=True,
        help="Experiment root folder.",
    )
    parser.add_argument(
        "--experiment-config-label",
        required=True,
        help="Experiment config label used under 09_validation.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=5,
        help="Number of example records to print for each sampled section.",
    )
    return parser.parse_args()


def main() -> None:
    """Ejecuta la comprobacion de outputs del Step 19."""
    args = parse_args()
    step19_dir = Path(args.experiment_root) / "09_validation" / args.experiment_config_label
    validated, validation_report = print_expected_files(step19_dir)
    summarize_step19(validated=validated, validation_report=validation_report, sample_size=args.sample_size)


if __name__ == "__main__":
    main()
