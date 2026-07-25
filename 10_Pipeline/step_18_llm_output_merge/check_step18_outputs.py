import argparse
import json
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


def print_expected_files(step18_dir: Path) -> tuple[Path, Path]:
    """Muestra y devuelve los ficheros esperados del Step 18."""
    merged = step18_dir / "merged_modified_traffic.json"
    merge_report = step18_dir / "merge_report.json"

    print("STEP 18 FILES")
    for path in [merged, merge_report]:
        print(f"{path}: exists={path.exists()} {file_size_mb(path)}")

    missing = [path for path in [merged, merge_report] if not path.exists()]
    if missing:
        missing_text = "\n".join(str(path) for path in missing)
        raise SystemExit(f"\nMissing expected Step 18 output files:\n{missing_text}")

    return merged, merge_report


def summarize_step18(merged: Path, merge_report: Path, sample_size: int) -> None:
    """Resume metadata, contadores y muestras relevantes del Step 18."""
    merged_data = load_json(merged)
    report_data = load_json(merge_report)

    summary = report_data.get("summary", {})
    group_outcomes = report_data.get("group_outcomes", {})
    patch_application = report_data.get("patch_application", {})

    print_json("STEP 18 METADATA", merged_data.get("metadata", {}), limit=4000)
    print_json("STEP 18 SUMMARY", summary)

    print("\nSTEP 18 PATCH APPLICATION COUNTS")
    print("explicit_header_edits:", len(patch_application.get("explicit_header_edits", [])))
    print("applied_patches:", len(patch_application.get("applied_patches", [])))
    print("effective_header_edits:", len(patch_application.get("effective_header_edits", [])))
    print("no_effect_edits:", len(patch_application.get("no_effect_edits", [])))
    print("derived_header_changes:", len(patch_application.get("derived_header_changes", [])))
    print("explicit_edit_relationships:", len(patch_application.get("explicit_edit_relationships", [])))
    print("header_materialization_issues:", len(patch_application.get("header_materialization_issues", [])))
    print("payload_edits:", len(patch_application.get("payload_edits", [])))
    print("modified_packet_ids:", len(patch_application.get("modified_packet_ids", [])))
    print("errors:", len(patch_application.get("errors", [])))

    group_counts = {
        "accepted_group_count": summary.get("accepted_group_count", 0),
        "llm_output_failure_group_count": summary.get("llm_output_failure_group_count", 0),
        "accepted_groups_in_group_outcomes": len(group_outcomes.get("accepted_groups", [])),
        "llm_output_failure_groups_in_group_outcomes": len(group_outcomes.get("llm_output_failure_groups", [])),
    }
    print_json("STEP 18 GROUP COUNTS", group_counts)

    payload_edits = patch_application.get("payload_edits", [])
    if payload_edits:
        print_json(
            "WARNING: PAYLOAD EDITS FOUND. HEADER-ONLY RUNS EXPECT ZERO.",
            payload_edits[:sample_size],
            limit=5000,
        )

    errors = patch_application.get("errors", [])
    if errors:
        print_json("FIRST STEP 18 PATCH ERRORS", errors[:sample_size], limit=5000)

    materialization_issues = patch_application.get("header_materialization_issues", [])
    if materialization_issues:
        print_json("FIRST STEP 18 HEADER MATERIALIZATION ISSUES", materialization_issues[:sample_size], limit=5000)

    relationships = patch_application.get("explicit_edit_relationships", [])
    if relationships:
        print_json("FIRST EXPLICIT EDIT RELATIONSHIPS", relationships[:sample_size], limit=5000)

    print_json(
        "FIRST EXPLICIT HEADER EDITS",
        patch_application.get("explicit_header_edits", [])[:sample_size],
        limit=8000,
    )
    print_json(
        "FIRST EFFECTIVE HEADER EDITS",
        patch_application.get("effective_header_edits", [])[:sample_size],
        limit=8000,
    )
    print_json(
        "FIRST NO-EFFECT EDITS",
        patch_application.get("no_effect_edits", [])[:sample_size],
        limit=8000,
    )
    print_json(
        "FIRST DERIVED HEADER CHANGES",
        patch_application.get("derived_header_changes", [])[:sample_size],
        limit=8000,
    )


def parse_args() -> argparse.Namespace:
    """Parsea los argumentos de linea de comandos del comprobador."""
    parser = argparse.ArgumentParser(description="Inspect Step 18 merged output and merge report.")
    parser.add_argument(
        "--experiment-root",
        required=True,
        help="Experiment root folder.",
    )
    parser.add_argument(
        "--experiment-config-label",
        required=True,
        help="Experiment config label used under 08_merged_outputs.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=5,
        help="Number of example records to print for each sampled section.",
    )
    return parser.parse_args()


def main() -> None:
    """Ejecuta la comprobacion de outputs del Step 18."""
    args = parse_args()
    step18_dir = Path(args.experiment_root) / "08_merged_outputs" / args.experiment_config_label
    merged, merge_report = print_expected_files(step18_dir)
    summarize_step18(merged=merged, merge_report=merge_report, sample_size=args.sample_size)


if __name__ == "__main__":
    main()
