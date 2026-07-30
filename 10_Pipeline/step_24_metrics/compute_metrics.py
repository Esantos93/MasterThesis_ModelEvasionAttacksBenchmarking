from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
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


METRICS_SCHEMA_VERSION = "snort_metrics_v2"


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


def optional_int(summary: dict[str, Any], key: str, default: int = 0) -> int:
    if key not in summary:
        return default
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


def zeroable_rate(numerator: int | float, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def metric_value(value: float, numerator: int | float, denominator: int) -> dict[str, int | float]:
    return {
        "value": value,
        "percentage": value * 100.0,
        "numerator": numerator,
        "denominator": denominator,
    }


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


def post_run_label_from_metadata(comparison_metadata: dict[str, Any]) -> str | None:
    post_metadata = comparison_metadata.get("post_normalization_metadata")
    if isinstance(post_metadata, dict):
        value = post_metadata.get("source_post_run_label")
        if isinstance(value, str) and value.strip():
            return value
    value = comparison_metadata.get("source_post_run_label")
    if isinstance(value, str) and value.strip():
        return value
    return None


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
    tcp_conversation_displaced_detection_count = optional_int(comparison_summary, "tcp_conversation_displaced_detection_count")
    snort_event_packet_anchor_shift_count = optional_int(
        comparison_summary,
        "snort_event_packet_anchor_shift_count",
        optional_int(comparison_summary, "delayed_snort_event_re_emission_count"),
    )
    induced_alert_count = optional_int(
        comparison_summary,
        "induced_alert_count",
        optional_int(comparison_summary, "post_only_unmatched_count"),
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

    signature_breakdowns = summarize_signature_rows(signature_summary)
    new_post_unique_signature_count = signature_breakdowns["new_post_signature_count"]
    signature_evasion_rate = safe_rate(successful_evasion_count, pre_alert_count)
    net_alert_reduction_rate = safe_rate(pre_alert_count - post_alert_count, pre_alert_count)
    signature_introduction_rate = zeroable_rate(new_post_unique_signature_count, post_unique_signature_count)
    return {
        "pre_alert_count": pre_alert_count,
        "post_alert_count": post_alert_count,
        "failed_evasion_count": failed_evasion_count,
        "successful_evasion_count": successful_evasion_count,
        "alert_mutation_count": alert_mutation_count,
        "tcp_conversation_displaced_detection_count": tcp_conversation_displaced_detection_count,
        "snort_event_packet_anchor_shift_count": snort_event_packet_anchor_shift_count,
        "delayed_snort_event_re_emission_count": snort_event_packet_anchor_shift_count,
        "induced_alert_count": induced_alert_count,
        "post_only_unmatched_count": post_only_unmatched_count,
        "same_signature_match_count": same_signature_match_count,
        "different_signature_replacements": different_signature_replacements,
        "signature_evasion_rate": signature_evasion_rate,
        "ser": signature_evasion_rate,
        "net_alert_reduction_rate": net_alert_reduction_rate,
        "narr": net_alert_reduction_rate,
        "signature_introduction_rate": signature_introduction_rate,
        "sir": signature_introduction_rate,
        "successful_evasion_rate_raw": signature_evasion_rate,
        "failed_evasion_rate": safe_rate(failed_evasion_count, pre_alert_count),
        "alert_mutation_rate": safe_rate(alert_mutation_count, pre_alert_count),
        "alert_mutation_rate_raw": safe_rate(alert_mutation_count, pre_alert_count),
        "tcp_conversation_displaced_detection_rate": safe_rate(tcp_conversation_displaced_detection_count, pre_alert_count),
        "packet_anchor_shift_rate": safe_rate(snort_event_packet_anchor_shift_count, pre_alert_count),
        "snort_event_packet_anchor_shift_rate": safe_rate(snort_event_packet_anchor_shift_count, pre_alert_count),
        "post_alert_retention_rate": safe_rate(post_alert_count, pre_alert_count),
        "induced_alert_rate": safe_rate(induced_alert_count, pre_alert_count),
        "induced_alert_rate_vs_pre": safe_rate(induced_alert_count, pre_alert_count),
        "unique_pre_signature_count": pre_unique_signature_count,
        "unique_post_signature_count": post_unique_signature_count,
        **signature_breakdowns,
        "new_post_unique_signature_count": new_post_unique_signature_count,
        "pre_detector_source_counts": comparison_summary.get("pre_detector_source_counts", {}),
        "post_detector_source_counts": comparison_summary.get("post_detector_source_counts", {}),
        "classification_counts": comparison_summary.get("classification_counts", {}),
        "detector_policy_label": detector_policy_label,
    }


def percentage(value: float) -> str:
    return f"{value * 100:.6f}%"


def build_metric_groups(metrics: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    primary_metrics = {
        "ser": metric_value(metrics["ser"], metrics["successful_evasion_count"], metrics["pre_alert_count"]),
        "narr": metric_value(metrics["narr"], metrics["pre_alert_count"] - metrics["post_alert_count"], metrics["pre_alert_count"]),
        "sir": metric_value(metrics["sir"], metrics["new_post_unique_signature_count"], metrics["unique_post_signature_count"]),
    }
    diagnostic_metrics = {
        "induced_alert_rate": metric_value(metrics["induced_alert_rate"], metrics["induced_alert_count"], metrics["pre_alert_count"]),
        "alert_mutation_rate": metric_value(metrics["alert_mutation_rate"], metrics["alert_mutation_count"], metrics["pre_alert_count"]),
        "failed_evasion_rate": metric_value(metrics["failed_evasion_rate"], metrics["failed_evasion_count"], metrics["pre_alert_count"]),
        "tcp_conversation_displaced_detection_rate": metric_value(
            metrics["tcp_conversation_displaced_detection_rate"],
            metrics["tcp_conversation_displaced_detection_count"],
            metrics["pre_alert_count"],
        ),
        "packet_anchor_shift_rate": metric_value(
            metrics["packet_anchor_shift_rate"],
            metrics["snort_event_packet_anchor_shift_count"],
            metrics["pre_alert_count"],
        ),
        "post_alert_retention_rate": metric_value(metrics["post_alert_retention_rate"], metrics["post_alert_count"], metrics["pre_alert_count"]),
    }
    return primary_metrics, diagnostic_metrics


def build_clean_summary(artifact: dict[str, Any]) -> dict[str, Any]:
    primary_metrics, diagnostic_metrics = build_metric_groups(artifact["metrics"])
    return {
        "experiment_identifier": {
            "experiment_id": artifact["experiment_id"],
            "experiment_config_label": artifact["experiment_config_label"],
            "detector_policy_label": artifact["detector_policy_label"],
            "post_run_label": artifact.get("post_run_label"),
        },
        "primary_metrics": primary_metrics,
        "diagnostic_metrics": diagnostic_metrics,
    }


def write_clean_summary_json(path: Path, clean_summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(clean_summary, output_file, indent=2)
        output_file.write("\n")


def write_metrics_report(path: Path, artifact: dict[str, Any]) -> None:
    metrics = artifact["metrics"]
    policy = artifact["metric_policy"]
    primary_metrics, diagnostic_metrics = build_metric_groups(metrics)
    lines = [
        "# Step 24 Metrics Report",
        "",
        f"- Experiment ID: `{artifact['experiment_id']}`",
        f"- Experiment config label: `{artifact['experiment_config_label']}`",
        f"- Detector policy label: `{artifact['detector_policy_label']}`",
        f"- Rules policy path: `{artifact.get('rules_policy_path') or 'none'}`",
        f"- Snaplen: `{artifact.get('snaplen', 'not configured')}`",
        f"- POST run label: `{artifact.get('post_run_label') or 'unknown'}`",
        "",
        "## Primary Metrics",
        "",
        f"- SER formula: `{policy['ser_formula']}`",
        f"- NARR formula: `{policy['narr_formula']}`",
        f"- SIR formula: `{policy['sir_formula']}`",
        "",
        "| Metric | Numerator | Denominator | Value | Percentage |",
        "| --- | ---: | ---: | ---: | ---: |",
        *[
            f"| {name.upper()} | {entry['numerator']} | {entry['denominator']} | {entry['value']:.12f} | {entry['percentage']:.6f}% |"
            for name, entry in primary_metrics.items()
        ],
        "",
        "## Alert Counts",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| PRE alerts | {metrics['pre_alert_count']} |",
        f"| POST alerts | {metrics['post_alert_count']} |",
        f"| Failed Evasion | {metrics['failed_evasion_count']} |",
        f"| Successful Evasion | {metrics['successful_evasion_count']} |",
        f"| Alert-Signature Mutation | {metrics['alert_mutation_count']} |",
        f"| TCP-Conversation Displaced Detection | {metrics['tcp_conversation_displaced_detection_count']} |",
        f"| Packet-Anchor shifted | {metrics['snort_event_packet_anchor_shift_count']} |",
        f"| Induced Alert | {metrics['induced_alert_count']} |",
        "",
        "## Diagnostic Metrics",
        "",
        "| Metric | Numerator | Denominator | Value | Percentage |",
        "| --- | ---: | ---: | ---: | ---: |",
        *[
            f"| {name} | {entry['numerator']} | {entry['denominator']} | {entry['value']:.12f} | {entry['percentage']:.6f}% |"
            for name, entry in diagnostic_metrics.items()
        ],
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
    metrics_path = resolved_output_dir / f"metrics__{base_name}.json"
    report_path = resolved_output_dir / f"metrics-report__{base_name}.md"
    clean_summary_path = resolved_output_dir / f"metrics_summary-{experiment_id}.json"
    post_run_label = post_run_label_from_metadata(comparison_metadata_artifact)
    primary_metrics, diagnostic_metrics = build_metric_groups(metrics)
    artifact = {
        "schema_version": METRICS_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "experiment_id": experiment_id,
        "experiment_config_label": experiment_config_label,
        "detector_policy_label": resolved_detector_policy_label,
        "rules_policy_path": rules_policy_path_from_config(config),
        "snaplen": config.get("snort", {}).get("snaplen"),
        "post_run_label": post_run_label,
        "config_source": config.get("_config_path", ""),
        "source_step_23_comparison_metadata": str(comparison_metadata_path),
        "source_alert_comparison": str(alert_comparison_path),
        "source_signature_summary": str(signature_summary_path),
        "metric_policy": {
            "ser_formula": "successful_evasion_count / pre_alert_count",
            "narr_formula": "(pre_alert_count - post_alert_count) / pre_alert_count",
            "sir_formula": "new_post_unique_signature_count / post_unique_signature_count; returns 0.0 when post_unique_signature_count is zero.",
            "current_policy": "SER is strict disappearance of PRE detections. No weighted credit is applied to Alert-Signature Mutation, TCP-Conversation Displaced Detection, or Packet-Anchor shifted.",
            "zero_pre_alert_policy": "fail clearly because SER is undefined without PRE detections.",
            "tcp_conversation_displaced_detection_policy": "reported separately and not counted as evasion.",
            "snort_event_packet_anchor_shift_policy": "reported separately and not counted as evasion.",
            "delayed_snort_event_re_emission_policy": "legacy alias for snort_event_packet_anchor_shift_count.",
            "induced_alert_policy": "reported separately and not counted as evasion.",
            "post_only_unmatched_policy": "legacy alias for induced_alert_count.",
        },
        "primary_metrics": primary_metrics,
        "diagnostic_metrics": diagnostic_metrics,
        "metrics": metrics,
        "artifacts": {
            "metrics": str(metrics_path),
            "clean_metrics_summary": str(clean_summary_path),
            "metrics_report": str(report_path),
        },
    }
    clean_summary = build_clean_summary(artifact)
    write_json(metrics_path, artifact)
    write_clean_summary_json(clean_summary_path, clean_summary)
    write_metrics_report(report_path, artifact)
    return artifact


def print_metric_group(title: str, metric_group: dict[str, Any]) -> None:
    print(title)
    for name, entry in metric_group.items():
        print(
            f"  {name}: numerator={entry['numerator']} denominator={entry['denominator']} "
            f"value={entry['value']:.12f} percentage={entry['percentage']:.6f}%"
        )


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
        print(f"Alert-signature mutation: {metrics['alert_mutation_count']}")
        print(f"TCP-conversation displaced detection: {metrics['tcp_conversation_displaced_detection_count']}")
        print(f"Packet-anchor shifted: {metrics['snort_event_packet_anchor_shift_count']}")
        print(f"Failed evasion: {metrics['failed_evasion_count']}")
        print(f"Induced alert: {metrics['induced_alert_count']}")
        print_metric_group("Primary metrics:", result["primary_metrics"])
        print_metric_group("Diagnostic metrics:", result["diagnostic_metrics"])
        print(f"Metrics JSON: {result['artifacts']['metrics']}")
        print(f"Clean metrics summary: {result['artifacts']['clean_metrics_summary']}")
        print(f"Metrics report: {result['artifacts']['metrics_report']}")


if __name__ == "__main__":
    main()
