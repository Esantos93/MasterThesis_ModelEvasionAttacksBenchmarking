from __future__ import annotations

import argparse
import csv
import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# This allows the script to import shared helpers from common/ when it is executed directly.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from common.naming import sanitize_name_component
from common.terminal_logging import default_step_log_path, terminal_log


METRICS_SCHEMA_VERSION = "snort_metrics_summary_v1"


# This function reads a JSON file and returns the parsed Python value.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function returns the current UTC timestamp in ISO 8601 format for metric metadata.
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# This function builds the experiment root directory from the experiment output_root and experiment_id fields.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function validates the minimum config shape required by Step 24.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline", "snort"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")
    require_keys(config["snort"], ["detector_policy_label"], "snort")
    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")
    detector_policy_label = config["snort"]["detector_policy_label"]
    if not isinstance(detector_policy_label, str) or not sanitize_name_component(detector_policy_label):
        raise ValueError("snort.detector_policy_label must be a non-empty string.")


def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


def detector_policy_label_from_config(config: dict[str, Any], override: str | None = None) -> str:
    raw_label = override if override is not None else config["snort"]["detector_policy_label"]
    label = sanitize_name_component(raw_label)
    if not label:
        raise ValueError("detector policy label must be a non-empty string.")
    return label


def rules_policy_path_from_config(config: dict[str, Any]) -> str:
    return str(config.get("snort", {}).get("rules_policy_path", "")).strip()


def signature_mutation_weight_from_config(config: dict[str, Any]) -> float:
    value = config.get("pipeline", {}).get("signature_mutation_weight", 0.0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("pipeline.signature_mutation_weight must be a number.")
    if value < 0:
        raise ValueError("pipeline.signature_mutation_weight must be non-negative.")
    return float(value)


# This function resolves the default Step 23 input directory and Step 24 output directory.
def default_paths(
    config: dict[str, Any],
    detector_policy_label: str,
    experiment_root_override: str | Path | None = None,
) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    return {
        "comparison_dir": experiment_root / "13_comparison" / detector_policy_label,
        "output_dir": experiment_root / "14_metrics" / detector_policy_label,
    }


def default_step23_artifact_paths(comparison_dir: Path, experiment_config_label: str) -> dict[str, Path]:
    return {
        "alert_comparison": comparison_dir / f"alert-comparison__experiment-config-{experiment_config_label}.json",
        "comparison_metadata": comparison_dir / f"comparison-metadata__experiment-config-{experiment_config_label}.json",
        "signature_summary": comparison_dir / f"signature-comparison-summary__experiment-config-{experiment_config_label}.json",
    }


def require_json_object(value: Any, path: Path, artifact_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{artifact_name} must be a JSON object: {path}")
    return value


def require_int(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Step 23 summary field must be an integer: {key}")
    if value < 0:
        raise ValueError(f"Step 23 summary field must be non-negative: {key}")
    return value


def safe_rate(numerator: int | float, denominator: int) -> float:
    if denominator == 0:
        raise ValueError(
            "pre_alert_count is zero. Step 24 does not define SER for experiments with no PRE detections."
        )
    return float(numerator) / float(denominator)


def validate_step23_metadata(
    *,
    artifact: dict[str, Any],
    artifact_path: Path,
    expected_experiment_id: str,
    expected_experiment_config_label: str,
    expected_detector_policy_label: str,
) -> None:
    metadata = artifact.get("metadata", artifact)
    if not isinstance(metadata, dict):
        raise ValueError(f"Step 23 artifact has invalid metadata: {artifact_path}")
    if metadata.get("experiment_id") != expected_experiment_id:
        raise ValueError(
            f"Step 23 artifact experiment_id mismatch in {artifact_path}: "
            f"{metadata.get('experiment_id')!r} != {expected_experiment_id!r}"
        )
    if metadata.get("experiment_config_label") != expected_experiment_config_label:
        raise ValueError(
            f"Step 23 artifact experiment_config_label mismatch in {artifact_path}: "
            f"{metadata.get('experiment_config_label')!r} != {expected_experiment_config_label!r}"
        )
    if metadata.get("detector_policy_label") != expected_detector_policy_label:
        raise ValueError(
            f"Step 23 artifact detector_policy_label mismatch in {artifact_path}: "
            f"{metadata.get('detector_policy_label')!r} != {expected_detector_policy_label!r}"
        )


def summarize_signature_rows(signature_artifact: dict[str, Any]) -> dict[str, Any]:
    signatures = signature_artifact.get("signatures")
    if not isinstance(signatures, list):
        raise ValueError("Step 23 signature summary must contain a signatures list.")

    status_counts = Counter()
    detector_source_rows = Counter()
    detector_source_pre_alerts = Counter()
    detector_source_post_alerts = Counter()
    gid_rows = Counter()
    disappeared_signature_count = 0
    new_post_signature_count = 0
    unchanged_signature_count = 0

    for index, row in enumerate(signatures, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"Signature summary row {index} is not a JSON object.")
        pre_count = row.get("pre_count")
        post_count = row.get("post_count")
        if isinstance(pre_count, bool) or not isinstance(pre_count, int) or pre_count < 0:
            raise ValueError(f"Signature summary row {index} has invalid pre_count.")
        if isinstance(post_count, bool) or not isinstance(post_count, int) or post_count < 0:
            raise ValueError(f"Signature summary row {index} has invalid post_count.")
        status = str(row.get("status", "unknown"))
        detector_source = str(row.get("detector_source", "unknown"))
        gid = str(row.get("gid", "unknown"))
        status_counts[status] += 1
        detector_source_rows[detector_source] += 1
        detector_source_pre_alerts[detector_source] += pre_count
        detector_source_post_alerts[detector_source] += post_count
        gid_rows[gid] += 1
        if pre_count > 0 and post_count == 0:
            disappeared_signature_count += 1
        if pre_count == 0 and post_count > 0:
            new_post_signature_count += 1
        if pre_count > 0 and post_count > 0 and pre_count == post_count:
            unchanged_signature_count += 1

    return {
        "signature_row_count": len(signatures),
        "signature_status_counts": dict(sorted(status_counts.items())),
        "disappeared_signature_count": disappeared_signature_count,
        "new_post_signature_count": new_post_signature_count,
        "unchanged_signature_count": unchanged_signature_count,
        "detector_source_signature_rows": dict(sorted(detector_source_rows.items())),
        "detector_source_pre_alert_counts_from_signatures": dict(sorted(detector_source_pre_alerts.items())),
        "detector_source_post_alert_counts_from_signatures": dict(sorted(detector_source_post_alerts.items())),
        "gid_signature_rows": dict(sorted(gid_rows.items())),
    }


def build_metrics(
    *,
    config: dict[str, Any],
    detector_policy_label: str,
    alert_comparison: dict[str, Any],
    comparison_metadata: dict[str, Any],
    signature_summary: dict[str, Any],
) -> dict[str, Any]:
    comparison_summary = alert_comparison.get("summary")
    if not isinstance(comparison_summary, dict):
        raise ValueError("Step 23 alert comparison must contain a summary object.")
    metadata_summary = comparison_metadata.get("summary")
    if isinstance(metadata_summary, dict) and metadata_summary != comparison_summary:
        raise ValueError("Step 23 comparison metadata summary does not match alert comparison summary.")

    pre_alert_count = require_int(comparison_summary, "pre_alert_count")
    post_alert_count = require_int(comparison_summary, "post_alert_count")
    failed_evasion_count = require_int(comparison_summary, "failed_evasion_count")
    successful_evasion_count = require_int(comparison_summary, "successful_evasion_count")
    alert_mutation_count = require_int(comparison_summary, "alert_mutation_count")
    tcp_conversation_displaced_detection_count = int(comparison_summary.get("tcp_conversation_displaced_detection_count", 0) or 0)
    induced_alert_count = int(
        comparison_summary.get("induced_alert_count", comparison_summary.get("post_only_unmatched_count", 0)) or 0
    )
    post_only_unmatched_count = induced_alert_count
    same_signature_match_count = require_int(comparison_summary, "same_signature_matches")
    different_signature_replacements = require_int(comparison_summary, "different_signature_replacements")
    pre_unique_signature_count = require_int(comparison_summary, "pre_unique_signature_count")
    post_unique_signature_count = require_int(comparison_summary, "post_unique_signature_count")

    # This explicit zero-denominator policy keeps no-PRE-alert experiments from being mistaken for zero evasion.
    if pre_alert_count == 0:
        raise ValueError(
            "pre_alert_count is zero. Step 24 requires PRE detections because SER is defined over detected PRE alerts."
        )

    signature_mutation_weight = signature_mutation_weight_from_config(config)
    partial_credit_candidate_count = alert_mutation_count + tcp_conversation_displaced_detection_count
    weighted_success = successful_evasion_count + (signature_mutation_weight * partial_credit_candidate_count)
    signature_breakdowns = summarize_signature_rows(signature_summary)
    return {
        "pre_alert_count": pre_alert_count,
        "post_alert_count": post_alert_count,
        "failed_evasion_count": failed_evasion_count,
        "successful_evasion_count": successful_evasion_count,
        "alert_mutation_count": alert_mutation_count,
        "tcp_conversation_displaced_detection_count": tcp_conversation_displaced_detection_count,
        "induced_alert_count": induced_alert_count,
        "post_only_unmatched_count": post_only_unmatched_count,
        "same_signature_match_count": same_signature_match_count,
        "different_signature_replacements": different_signature_replacements,
        "partial_credit_candidate_count": partial_credit_candidate_count,
        "signature_mutation_weight": signature_mutation_weight,
        "weighted_successful_evasion_count": weighted_success,
        "signature_evasion_rate": safe_rate(weighted_success, pre_alert_count),
        "successful_evasion_rate_raw": safe_rate(successful_evasion_count, pre_alert_count),
        "failed_evasion_rate": safe_rate(failed_evasion_count, pre_alert_count),
        "alert_mutation_rate_raw": safe_rate(alert_mutation_count, pre_alert_count),
        "tcp_conversation_displaced_detection_rate": safe_rate(tcp_conversation_displaced_detection_count, pre_alert_count),
        "post_alert_retention_rate": safe_rate(post_alert_count, pre_alert_count),
        "induced_alert_rate_vs_pre": safe_rate(induced_alert_count, pre_alert_count),
        "post_only_unmatched_rate_vs_pre": safe_rate(induced_alert_count, pre_alert_count),
        "unique_pre_signature_count": pre_unique_signature_count,
        "unique_post_signature_count": post_unique_signature_count,
        **signature_breakdowns,
        "pre_detector_source_counts": comparison_summary.get("pre_detector_source_counts", {}),
        "post_detector_source_counts": comparison_summary.get("post_detector_source_counts", {}),
        "classification_counts": comparison_summary.get("classification_counts", {}),
        "detector_policy_label": detector_policy_label,
    }


def write_metrics_csv(path: Path, metrics: dict[str, Any]) -> None:
    scalar_keys = [
        "pre_alert_count",
        "post_alert_count",
        "failed_evasion_count",
        "successful_evasion_count",
        "alert_mutation_count",
        "tcp_conversation_displaced_detection_count",
        "induced_alert_count",
        "post_only_unmatched_count",
        "same_signature_match_count",
        "different_signature_replacements",
        "partial_credit_candidate_count",
        "signature_mutation_weight",
        "weighted_successful_evasion_count",
        "signature_evasion_rate",
        "successful_evasion_rate_raw",
        "failed_evasion_rate",
        "alert_mutation_rate_raw",
        "tcp_conversation_displaced_detection_rate",
        "post_alert_retention_rate",
        "induced_alert_rate_vs_pre",
        "post_only_unmatched_rate_vs_pre",
        "unique_pre_signature_count",
        "unique_post_signature_count",
        "disappeared_signature_count",
        "new_post_signature_count",
        "unchanged_signature_count",
        "signature_row_count",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["metric", "value"])
        writer.writeheader()
        for key in scalar_keys:
            writer.writerow({"metric": key, "value": metrics.get(key)})


def percentage(value: float) -> str:
    return f"{value * 100:.6f}%"


def write_metrics_report(path: Path, artifact: dict[str, Any]) -> None:
    metrics = artifact["metrics"]
    policy = artifact["metric_policy"]
    lines = [
        "# Step 24 Metrics Report",
        "",
        f"- Experiment ID: `{artifact['experiment_id']}`",
        f"- Experiment config label: `{artifact['experiment_config_label']}`",
        f"- Detector policy label: `{artifact['detector_policy_label']}`",
        f"- Rules policy path: `{artifact.get('rules_policy_path') or 'none'}`",
        f"- Snaplen: `{artifact.get('snaplen', 'not configured')}`",
        "",
        "## Core Metric",
        "",
        f"- SER formula: `{policy['signature_evasion_rate_formula']}`",
        f"- Signature mutation weight: `{metrics['signature_mutation_weight']}`",
        f"- Signature Evasion Rate: `{metrics['signature_evasion_rate']:.12f}` ({percentage(metrics['signature_evasion_rate'])})",
        "",
        "## Alert Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| PRE alerts | {metrics['pre_alert_count']} |",
        f"| POST alerts | {metrics['post_alert_count']} |",
        f"| Failed Evasion | {metrics['failed_evasion_count']} |",
        f"| Successful Evasion | {metrics['successful_evasion_count']} |",
        f"| Alert Mutation | {metrics['alert_mutation_count']} |",
        f"| TCP-Conversation Displaced Detection | {metrics['tcp_conversation_displaced_detection_count']} |",
        f"| Induced Alert | {metrics['induced_alert_count']} |",
        "",
        "## Supporting Rates",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Successful evasion rate raw | {percentage(metrics['successful_evasion_rate_raw'])} |",
        f"| Failed evasion rate | {percentage(metrics['failed_evasion_rate'])} |",
        f"| Alert mutation rate raw | {percentage(metrics['alert_mutation_rate_raw'])} |",
        f"| TCP-conversation displaced detection rate | {percentage(metrics['tcp_conversation_displaced_detection_rate'])} |",
        f"| Induced alert rate vs PRE | {percentage(metrics['induced_alert_rate_vs_pre'])} |",
        f"| POST alert retention rate | {percentage(metrics['post_alert_retention_rate'])} |",
        "",
        "## Signature Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| PRE unique signatures | {metrics['unique_pre_signature_count']} |",
        f"| POST unique signatures | {metrics['unique_post_signature_count']} |",
        f"| Disappeared signatures | {metrics['disappeared_signature_count']} |",
        f"| New POST signatures | {metrics['new_post_signature_count']} |",
        f"| Unchanged signature counts | {metrics['unchanged_signature_count']} |",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def compute_metrics(
    *,
    config_path: str | Path,
    experiment_root: str | Path | None = None,
    comparison_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    detector_policy_label: str | None = None,
    alert_comparison: str | Path | None = None,
    comparison_metadata: str | Path | None = None,
    signature_summary: str | Path | None = None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_id = config["experiment"]["experiment_id"]
    experiment_config_label = experiment_config_label_from_config(config)
    resolved_detector_policy_label = detector_policy_label_from_config(config, detector_policy_label)
    paths = default_paths(config, resolved_detector_policy_label, experiment_root)
    resolved_comparison_dir = Path(comparison_dir).expanduser() if comparison_dir else paths["comparison_dir"]
    resolved_output_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    step23_paths = default_step23_artifact_paths(resolved_comparison_dir, experiment_config_label)
    alert_comparison_path = Path(alert_comparison).expanduser() if alert_comparison else step23_paths["alert_comparison"]
    comparison_metadata_path = Path(comparison_metadata).expanduser() if comparison_metadata else step23_paths["comparison_metadata"]
    signature_summary_path = Path(signature_summary).expanduser() if signature_summary else step23_paths["signature_summary"]

    for path in [alert_comparison_path, comparison_metadata_path, signature_summary_path]:
        if not path.exists():
            raise FileNotFoundError(f"Required Step 23 artifact does not exist: {path}")

    alert_comparison_artifact = require_json_object(read_json(alert_comparison_path), alert_comparison_path, "Step 23 alert comparison")
    comparison_metadata_artifact = require_json_object(read_json(comparison_metadata_path), comparison_metadata_path, "Step 23 comparison metadata")
    signature_summary_artifact = require_json_object(read_json(signature_summary_path), signature_summary_path, "Step 23 signature summary")

    for artifact, path in [
        (alert_comparison_artifact, alert_comparison_path),
        (comparison_metadata_artifact, comparison_metadata_path),
        (signature_summary_artifact, signature_summary_path),
    ]:
        validate_step23_metadata(
            artifact=artifact,
            artifact_path=path,
            expected_experiment_id=experiment_id,
            expected_experiment_config_label=experiment_config_label,
            expected_detector_policy_label=resolved_detector_policy_label,
        )

    metrics = build_metrics(
        config=config,
        detector_policy_label=resolved_detector_policy_label,
        alert_comparison=alert_comparison_artifact,
        comparison_metadata=comparison_metadata_artifact,
        signature_summary=signature_summary_artifact,
    )
    base_name = (
        f"experiment-config-{experiment_config_label}__"
        f"detector-policy-{resolved_detector_policy_label}"
    )
    summary_path = resolved_output_dir / f"metrics-summary__{base_name}.json"
    report_path = resolved_output_dir / f"metrics-report__{base_name}.md"
    table_path = resolved_output_dir / f"metrics-table__{base_name}.csv"
    artifact = {
        "schema_version": METRICS_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "experiment_id": experiment_id,
        "experiment_config_label": experiment_config_label,
        "detector_policy_label": resolved_detector_policy_label,
        "rules_policy_path": rules_policy_path_from_config(config),
        "snaplen": config.get("snort", {}).get("snaplen"),
        "config_source": config.get("_config_path", ""),
        "source_step_23_comparison_metadata": str(comparison_metadata_path),
        "source_alert_comparison": str(alert_comparison_path),
        "source_signature_summary": str(signature_summary_path),
        "metric_policy": {
            "signature_evasion_rate_formula": "(successful_evasion_count + signature_mutation_weight * (alert_mutation_count + tcp_conversation_displaced_detection_count)) / pre_alert_count",
            "current_policy": "With signature_mutation_weight = 0, only successful_evasion_count contributes to SER.",
            "partial_credit_candidate_policy": "If partial credit is enabled later, Alert Mutation and TCP-Conversation Displaced Detection are the weighted candidate categories.",
            "signature_mutation_weight_source": "pipeline.signature_mutation_weight",
            "zero_pre_alert_policy": "fail clearly because SER is undefined without PRE detections.",
            "tcp_conversation_displaced_detection_policy": "reported separately and not counted as evasion.",
            "induced_alert_policy": "reported separately and not counted as evasion.",
            "post_only_unmatched_policy": "legacy alias for induced_alert_count.",
        },
        "metrics": metrics,
        "artifacts": {
            "metrics_summary": str(summary_path),
            "metrics_report": str(report_path),
            "metrics_table": str(table_path),
        },
    }
    write_json(summary_path, artifact)
    write_metrics_csv(table_path, metrics)
    write_metrics_report(report_path, artifact)
    return artifact


def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    validate_config(config)
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    detector_policy_label = detector_policy_label_from_config(config, args.detector_policy_label)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_24_metrics",
        branch_label=detector_policy_label,
        filename_prefix="step_24_metrics",
    )


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute Step 24 thesis metrics from Step 23 alert comparison artifacts.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--experiment-root", help="Optional experiment root override.")
    add("--comparison-dir", help="Optional Step 23 comparison directory. Defaults to 13_comparison/<detector_policy_label>.")
    add("--output-dir", help="Optional Step 24 output directory. Defaults to 14_metrics/<detector_policy_label>.")
    add("--detector-policy-label", help="Optional detector policy label override.")
    add("--alert-comparison", help="Explicit Step 23 alert-comparison artifact.")
    add("--comparison-metadata", help="Explicit Step 23 comparison-metadata artifact.")
    add("--signature-summary", help="Explicit Step 23 signature-comparison-summary artifact.")
    add("--log-file", help="Optional explicit terminal log file path.")
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 24 terminal log"):
        try:
            result = compute_metrics(
                config_path=args.config,
                experiment_root=args.experiment_root,
                comparison_dir=args.comparison_dir,
                output_dir=args.output_dir,
                detector_policy_label=args.detector_policy_label,
                alert_comparison=args.alert_comparison,
                comparison_metadata=args.comparison_metadata,
                signature_summary=args.signature_summary,
            )
        except Exception:
            print("Step 24 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        metrics = result["metrics"]
        print(f"Experiment: {result['experiment_id']}")
        print(f"Experiment config: {result['experiment_config_label']}")
        print(f"Detector policy: {result['detector_policy_label']}")
        print(f"Rules policy path: {result['rules_policy_path'] or 'none'}")
        print(f"Snaplen: {result.get('snaplen', 'not configured')}")
        print(f"PRE alerts: {metrics['pre_alert_count']}")
        print(f"POST alerts: {metrics['post_alert_count']}")
        print(f"Successful evasion: {metrics['successful_evasion_count']}")
        print(f"Alert mutation: {metrics['alert_mutation_count']}")
        print(f"TCP-conversation displaced detection: {metrics['tcp_conversation_displaced_detection_count']}")
        print(f"Failed evasion: {metrics['failed_evasion_count']}")
        print(f"Induced alert: {metrics['induced_alert_count']}")
        print(f"Signature mutation weight: {metrics['signature_mutation_weight']}")
        print(f"Signature Evasion Rate: {metrics['signature_evasion_rate']:.12f}")
        print(f"POST alert retention rate: {metrics['post_alert_retention_rate']:.12f}")
        print(f"Metrics summary: {result['artifacts']['metrics_summary']}")
        print(f"Metrics report: {result['artifacts']['metrics_report']}")
        print(f"Metrics table: {result['artifacts']['metrics_table']}")


if __name__ == "__main__":
    main()
