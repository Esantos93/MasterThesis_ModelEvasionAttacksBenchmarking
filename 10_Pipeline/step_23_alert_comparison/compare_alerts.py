from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# This allows the script to import shared helpers from common/ when it is executed directly.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json
from common.terminal_logging import default_step_log_path, terminal_log


COMPARISON_SCHEMA_VERSION = "snort_alert_comparison_v1"


# This function reads a JSON file and returns the parsed Python value.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function returns the current UTC timestamp in ISO 8601 format for comparison metadata.
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# This function builds the experiment root directory from the experiment output_root and experiment_id fields.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function validates the minimum config shape required by Step 23.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")
    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")


# This function returns the experiment configuration label fixed in the Step 11 config.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


# This function resolves default Step 22 normalized alert paths and default Step 23 output paths.
def default_paths(
    config: dict[str, Any],
    experiment_config_label: str,
    experiment_root_override: str | Path | None = None,
) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    pre_dir = experiment_root / "12_alerts_processed" / "pre"
    post_dir = experiment_root / "12_alerts_processed" / "post" / experiment_config_label
    comparison_dir = experiment_root / "13_comparison" / experiment_config_label
    return {
        "pre_normalized": pre_dir / "normalized-alerts__traffic-pre.json",
        "post_normalized": post_dir / f"normalized-alerts__traffic-post__experiment-config-{experiment_config_label}.json",
        "comparison_dir": comparison_dir,
    }


# This function validates and extracts the normalized alert list from a Step 22 artifact.
def load_normalized_alerts(path: Path, expected_traffic_version: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    artifact = read_json(path)
    if not isinstance(artifact, dict):
        raise ValueError(f"Normalized alert artifact must be a JSON object: {path}")
    alerts = artifact.get("alerts")
    if not isinstance(alerts, list):
        raise ValueError(f"Normalized alert artifact must contain an alerts list: {path}")
    for index, alert in enumerate(alerts, start=1):
        if not isinstance(alert, dict):
            raise ValueError(f"Normalized alert {index} is not a JSON object in: {path}")
        if alert.get("traffic_version") != expected_traffic_version:
            raise ValueError(f"Normalized alert {index} has unexpected traffic_version in: {path}")
        if not isinstance(alert.get("signature_key"), str):
            raise ValueError(f"Normalized alert {index} has no string signature_key in: {path}")
    return artifact, alerts


# This helper returns a compact alert reference for comparison records.
def alert_ref(alert: dict[str, Any] | None) -> dict[str, Any] | None:
    if alert is None:
        return None
    return {
        "normalized_alert_id": alert.get("normalized_alert_id"),
        "signature_key": alert.get("signature_key"),
        "gid": alert.get("gid"),
        "sid": alert.get("sid"),
        "rev": alert.get("rev"),
        "detector_source": alert.get("detector_source"),
        "msg": alert.get("msg"),
        "class": alert.get("class"),
        "action": alert.get("action"),
        "proto": alert.get("proto"),
        "pkt_num": alert.get("pkt_num"),
        "timestamp": alert.get("timestamp"),
        "src_addr": alert.get("src_addr"),
        "src_port": alert.get("src_port"),
        "dst_addr": alert.get("dst_addr"),
        "dst_port": alert.get("dst_port"),
    }


# This function compares PRE and POST alerts as multisets of Snort signatures.
# Exact same-signature POST alerts are consumed first and classified as Failed Evasion.
# Disappeared PRE alerts can then consume remaining different POST alerts as Alert Mutation.
# If no replacement POST alert remains, the PRE alert is classified as Successful Evasion.
def compare_alert_multisets(pre_alerts: list[dict[str, Any]], post_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    post_by_signature: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    for alert in post_alerts:
        post_by_signature[alert["signature_key"]].append(alert)

    comparison_records = []
    same_signature_matches = 0
    for pre_alert in pre_alerts:
        key = pre_alert["signature_key"]
        matching_post = post_by_signature[key].popleft() if post_by_signature[key] else None
        if matching_post is not None:
            same_signature_matches += 1
            comparison_records.append(
                {
                    "comparison_id": f"cmp-{len(comparison_records) + 1:06d}",
                    "classification": "Failed Evasion",
                    "match_type": "same_signature",
                    "pre_alert": alert_ref(pre_alert),
                    "post_alert": alert_ref(matching_post),
                    "reason": "The original PRE Snort signature is still present in POST alerts.",
                }
            )
        else:
            comparison_records.append(
                {
                    "comparison_id": f"cmp-{len(comparison_records) + 1:06d}",
                    "classification": "pending_disappeared_pre",
                    "match_type": "none_yet",
                    "pre_alert": alert_ref(pre_alert),
                    "post_alert": None,
                    "reason": "No same-signature POST alert was available for this PRE alert.",
                }
            )

    remaining_post_alerts = []
    for key in sorted(post_by_signature):
        remaining_post_alerts.extend(post_by_signature[key])
    remaining_post_queue = deque(remaining_post_alerts)

    mutation_matches = 0
    successful_evasions = 0
    for record in comparison_records:
        if record["classification"] != "pending_disappeared_pre":
            continue
        replacement_post = remaining_post_queue.popleft() if remaining_post_queue else None
        if replacement_post is not None:
            mutation_matches += 1
            record["classification"] = "Alert Mutation"
            record["match_type"] = "different_signature_replacement"
            record["post_alert"] = alert_ref(replacement_post)
            record["reason"] = "The original PRE signature disappeared and a different POST alert remained available."
        else:
            successful_evasions += 1
            record["classification"] = "Successful Evasion"
            record["match_type"] = "no_replacement_alert"
            record["reason"] = "The original PRE signature disappeared and no POST replacement alert remained available."

    post_only_records = []
    for post_alert in remaining_post_queue:
        post_only_records.append(
            {
                "post_alert": alert_ref(post_alert),
                "status": "post_only_unmatched",
                "reason": "This POST alert was not needed to explain a disappeared PRE alert; no standalone Induced Alert category is used.",
            }
        )

    classification_counts = Counter(record["classification"] for record in comparison_records)
    pre_signature_counts = Counter(alert["signature_key"] for alert in pre_alerts)
    post_signature_counts = Counter(alert["signature_key"] for alert in post_alerts)
    pre_detector_source_counts = Counter(str(alert.get("detector_source")) for alert in pre_alerts)
    post_detector_source_counts = Counter(str(alert.get("detector_source")) for alert in post_alerts)
    return {
        "records": comparison_records,
        "post_only_unmatched_alerts": post_only_records,
        "summary": {
            "pre_alert_count": len(pre_alerts),
            "post_alert_count": len(post_alerts),
            "pre_unique_signature_count": len(pre_signature_counts),
            "post_unique_signature_count": len(post_signature_counts),
            "pre_detector_source_counts": dict(sorted(pre_detector_source_counts.items())),
            "post_detector_source_counts": dict(sorted(post_detector_source_counts.items())),
            "same_signature_matches": same_signature_matches,
            "different_signature_replacements": mutation_matches,
            "post_only_unmatched_count": len(post_only_records),
            "classification_counts": dict(sorted(classification_counts.items())),
            "successful_evasion_count": successful_evasions,
            "alert_mutation_count": mutation_matches,
            "failed_evasion_count": same_signature_matches,
        },
    }


# This function builds a per-signature summary for thesis inspection and Step 24 metrics.
def summarize_by_signature(pre_alerts: list[dict[str, Any]], post_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pre_counts = Counter(alert["signature_key"] for alert in pre_alerts)
    post_counts = Counter(alert["signature_key"] for alert in post_alerts)
    all_keys = sorted(set(pre_counts) | set(post_counts))
    rows = []
    for key in all_keys:
        pre_count = pre_counts.get(key, 0)
        post_count = post_counts.get(key, 0)
        if pre_count and post_count:
            status = "present_in_pre_and_post"
        elif pre_count:
            status = "pre_only_disappeared"
        else:
            status = "post_only_new"
        example = next((alert for alert in pre_alerts if alert["signature_key"] == key), None)
        if example is None:
            example = next((alert for alert in post_alerts if alert["signature_key"] == key), None)
        rows.append(
            {
                "signature_key": key,
                "gid": example.get("gid") if example else None,
                "sid": example.get("sid") if example else None,
                "rev": example.get("rev") if example else None,
                "detector_source": example.get("detector_source") if example else None,
                "msg": example.get("msg") if example else None,
                "class": example.get("class") if example else None,
                "pre_count": pre_count,
                "post_count": post_count,
                "count_delta_post_minus_pre": post_count - pre_count,
                "status": status,
            }
        )
    return rows


# This function runs the Step 23 comparison and writes all comparison artifacts.
def compare_normalized_alerts(
    *,
    config_path: str | Path,
    experiment_root: str | Path | None,
    pre_normalized: str | Path | None,
    post_normalized: str | Path | None,
    output_dir: str | Path | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    paths = default_paths(config, experiment_config_label, experiment_root)
    pre_path = Path(pre_normalized).expanduser() if pre_normalized else paths["pre_normalized"]
    post_path = Path(post_normalized).expanduser() if post_normalized else paths["post_normalized"]
    comparison_dir = Path(output_dir).expanduser() if output_dir else paths["comparison_dir"]

    pre_artifact, pre_alerts = load_normalized_alerts(pre_path, "pre")
    post_artifact, post_alerts = load_normalized_alerts(post_path, "post")
    comparison = compare_alert_multisets(pre_alerts, post_alerts)
    per_signature_summary = summarize_by_signature(pre_alerts, post_alerts)
    comparison_dir.mkdir(parents=True, exist_ok=True)

    comparison_path = comparison_dir / f"alert-comparison__experiment-config-{experiment_config_label}.json"
    signature_summary_path = comparison_dir / f"signature-comparison-summary__experiment-config-{experiment_config_label}.json"
    metadata_path = comparison_dir / f"comparison-metadata__experiment-config-{experiment_config_label}.json"
    metadata = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "experiment_id": config["experiment"]["experiment_id"],
        "config_source": config.get("_config_path", ""),
        "experiment_config_label": experiment_config_label,
        "source_pre_normalized_alerts": str(pre_path),
        "source_post_normalized_alerts": str(post_path),
        "comparison_policy": {
            "matching_basis": "Snort signature multiset using normalized signature_key gid:sid:rev.",
            "detection_evidence": "Any normalized alert record counts as detection evidence, regardless of action value.",
            "classification_labels": ["Successful Evasion", "Alert Mutation", "Failed Evasion"],
            "new_post_alert_policy": "No standalone Induced Alert category. Unmatched POST-only alerts are reported as post_only_unmatched.",
            "invalid_or_llm_output_failure_policy": "Invalid Traffic and LLM Output Failure come from previous pipeline stages, not from Snort comparison alone.",
        },
        "pre_normalization_metadata": pre_artifact.get("metadata", {}),
        "post_normalization_metadata": post_artifact.get("metadata", {}),
        "summary": comparison["summary"],
        "artifacts": {
            "alert_comparison": str(comparison_path),
            "signature_comparison_summary": str(signature_summary_path),
            "comparison_metadata": str(metadata_path),
        },
    }
    comparison_artifact = {
        "metadata": metadata,
        "summary": comparison["summary"],
        "comparison_records": comparison["records"],
        "post_only_unmatched_alerts": comparison["post_only_unmatched_alerts"],
    }
    signature_artifact = {
        "metadata": metadata,
        "summary": {
            "signature_row_count": len(per_signature_summary),
            "pre_unique_signature_count": len({alert["signature_key"] for alert in pre_alerts}),
            "post_unique_signature_count": len({alert["signature_key"] for alert in post_alerts}),
        },
        "signatures": per_signature_summary,
    }
    write_json(comparison_path, comparison_artifact)
    write_json(signature_summary_path, signature_artifact)
    write_json(metadata_path, metadata)
    return {
        "pre_alert_count": comparison["summary"]["pre_alert_count"],
        "post_alert_count": comparison["summary"]["post_alert_count"],
        "pre_unique_signature_count": comparison["summary"]["pre_unique_signature_count"],
        "post_unique_signature_count": comparison["summary"]["post_unique_signature_count"],
        "pre_detector_source_counts": comparison["summary"]["pre_detector_source_counts"],
        "post_detector_source_counts": comparison["summary"]["post_detector_source_counts"],
        "classification_counts": comparison["summary"]["classification_counts"],
        "successful_evasion_count": comparison["summary"]["successful_evasion_count"],
        "alert_mutation_count": comparison["summary"]["alert_mutation_count"],
        "failed_evasion_count": comparison["summary"]["failed_evasion_count"],
        "post_only_unmatched_count": comparison["summary"]["post_only_unmatched_count"],
        "alert_comparison": str(comparison_path),
        "signature_comparison_summary": str(signature_summary_path),
        "comparison_metadata": str(metadata_path),
    }


# This function resolves the terminal log path for Step 23.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()
    config = load_json_config(args.config)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_23_alert_comparison",
        branch_label=experiment_config_label,
        filename_prefix="step_23_alert_comparison",
    )


# This function parses Step 23 command-line arguments.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Step 22 normalized PRE and POST Snort alerts.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--experiment-root", help="Optional experiment root override.")
    add("--pre-normalized", help="Explicit normalized PRE alert artifact.")
    add("--post-normalized", help="Explicit normalized POST alert artifact.")
    add("--output-dir", help="Explicit Step 23 output directory.")
    add("--log-file", help="Optional explicit terminal log file path.")
    return parser.parse_args()


# This function is the command-line entry point.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 23 terminal log"):
        try:
            result = compare_normalized_alerts(
                config_path=args.config,
                experiment_root=args.experiment_root,
                pre_normalized=args.pre_normalized,
                post_normalized=args.post_normalized,
                output_dir=args.output_dir,
            )
        except Exception:
            print("Step 23 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"PRE alerts: {result['pre_alert_count']}")
        print(f"POST alerts: {result['post_alert_count']}")
        print(f"PRE unique signatures: {result['pre_unique_signature_count']}")
        print(f"POST unique signatures: {result['post_unique_signature_count']}")
        print(f"PRE detector sources: {result['pre_detector_source_counts']}")
        print(f"POST detector sources: {result['post_detector_source_counts']}")
        print(f"Classifications: {result['classification_counts']}")
        print(f"Successful evasion: {result['successful_evasion_count']}")
        print(f"Alert mutation: {result['alert_mutation_count']}")
        print(f"Failed evasion: {result['failed_evasion_count']}")
        print(f"POST-only unmatched: {result['post_only_unmatched_count']}")
        print(f"Alert comparison: {result['alert_comparison']}")
        print(f"Signature summary: {result['signature_comparison_summary']}")


if __name__ == "__main__":
    main()

