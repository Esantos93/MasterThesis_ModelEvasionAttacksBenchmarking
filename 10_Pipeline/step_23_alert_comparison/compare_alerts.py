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


COMPARISON_SCHEMA_VERSION = "snort_alert_comparison_v4"
DEFAULT_MATCHING_POLICY = "packet_tcp_conversation"
SUPPORTED_MATCHING_POLICIES = {"packet", "packet_tcp_conversation"}


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


# This function returns the experiment configuration label fixed in the Step 11 config.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


def detector_policy_label_from_config(config: dict[str, Any]) -> str:
    return sanitize_name_component(config["snort"]["detector_policy_label"])


def rules_policy_path_from_config(config: dict[str, Any]) -> str:
    return str(config.get("snort", {}).get("rules_policy_path", "")).strip()


# This function resolves default Step 22 normalized alert paths and default Step 23 output paths.
def default_paths(
    config: dict[str, Any],
    detector_policy_label: str,
    experiment_config_label: str,
    experiment_root_override: str | Path | None = None,
) -> dict[str, Path]:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    processed_root = experiment_root / "12_alerts_processed" / detector_policy_label
    pre_dir = processed_root / "pre"
    post_dir = processed_root / "post" / experiment_config_label
    comparison_dir = experiment_root / "13_comparison" / detector_policy_label
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


def validate_normalization_metadata(
    artifact: dict[str, Any],
    *,
    artifact_path: Path,
    expected_detector_policy_label: str,
) -> None:
    metadata = artifact.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"Normalized alert artifact has invalid metadata: {artifact_path}")
    source_detector_policy_label = metadata.get("source_detector_policy_label")
    configured_detector_policy_label = metadata.get("configured_detector_policy_label")
    if configured_detector_policy_label != expected_detector_policy_label:
        raise ValueError(
            "Normalized artifact configured_detector_policy_label does not match active config: "
            f"{configured_detector_policy_label!r} != {expected_detector_policy_label!r} in {artifact_path}"
        )
    if source_detector_policy_label != expected_detector_policy_label:
        raise ValueError(
            "Normalized artifact source_detector_policy_label does not match active config: "
            f"{source_detector_policy_label!r} != {expected_detector_policy_label!r} in {artifact_path}"
        )


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
        "packet_id": alert.get("packet_id"),
        "original_packet_number": alert.get("original_packet_number"),
        "reduced_packet_index": alert.get("reduced_packet_index"),
        "tcp_connection_id": alert.get("tcp_connection_id"),
        "tcp_stream_id": alert.get("tcp_stream_id"),
        "timestamp": alert.get("timestamp"),
        "src_addr": alert.get("src_addr"),
        "src_port": alert.get("src_port"),
        "dst_addr": alert.get("dst_addr"),
        "dst_port": alert.get("dst_port"),
    }


def comparable_unit_key(alert: dict[str, Any], traffic_side: str, matching_policy: str) -> str:
    if matching_policy in {"packet", "packet_tcp_conversation"}:
        packet_id = alert.get("packet_id")
        if isinstance(packet_id, str) and packet_id.strip():
            return f"packet_id:{packet_id}"
        pkt_num = alert.get("pkt_num")
        if isinstance(pkt_num, int):
            return f"pkt_num:{pkt_num}"
        alert_id = alert.get("normalized_alert_id") or "unknown-alert"
        return f"{traffic_side}:missing-pkt-num:{alert_id}"
    raise ValueError(f"Unsupported matching policy: {matching_policy}")


def comparable_unit_type(matching_policy: str) -> str:
    if matching_policy in {"packet", "packet_tcp_conversation"}:
        return "packet"
    raise ValueError(f"Unsupported matching policy: {matching_policy}")


def comparable_unit_field(matching_policy: str) -> str:
    if matching_policy == "packet":
        return "packet_id_or_pkt_num"
    if matching_policy == "packet_tcp_conversation":
        return "packet_id_or_pkt_num + tcp_connection_id"
    raise ValueError(f"Unsupported matching policy: {matching_policy}")


def packet_anchor(alert: dict[str, Any]) -> str | None:
    packet_id = alert.get("packet_id")
    if isinstance(packet_id, str) and packet_id.strip():
        return packet_id
    pkt_num = alert.get("pkt_num")
    if isinstance(pkt_num, int):
        return f"pkt_num:{pkt_num}"
    return None


def tcp_conversation_anchor(alert: dict[str, Any]) -> str | None:
    connection_id = alert.get("tcp_connection_id")
    if isinstance(connection_id, str) and connection_id.strip():
        return connection_id
    return None


def alert_sort_key(alert: dict[str, Any]) -> tuple[Any, ...]:
    return (
        packet_anchor(alert) or "",
        tcp_conversation_anchor(alert) or "",
        str(alert.get("signature_key") or ""),
        int(alert.get("alert_index") or 0),
        str(alert.get("normalized_alert_id") or ""),
    )


def conversation_compatible(pre_alert: dict[str, Any], post_alert: dict[str, Any], matching_policy: str) -> bool:
    if matching_policy == "packet":
        return True
    pre_connection = tcp_conversation_anchor(pre_alert)
    post_connection = tcp_conversation_anchor(post_alert)
    if pre_connection is None or post_connection is None:
        return True
    return pre_connection == post_connection


def same_packet(pre_alert: dict[str, Any], post_alert: dict[str, Any], matching_policy: str) -> bool:
    return packet_anchor(pre_alert) == packet_anchor(post_alert) and conversation_compatible(pre_alert, post_alert, matching_policy)


def same_tcp_conversation(pre_alert: dict[str, Any], post_alert: dict[str, Any]) -> bool:
    pre_connection = tcp_conversation_anchor(pre_alert)
    post_connection = tcp_conversation_anchor(post_alert)
    return pre_connection is not None and pre_connection == post_connection


def pop_first_matching(
    candidates: list[dict[str, Any]],
    predicate: Any,
) -> dict[str, Any] | None:
    for index, candidate in enumerate(candidates):
        if predicate(candidate):
            return candidates.pop(index)
    return None


def make_comparison_record(
    *,
    comparison_index: int,
    classification: str,
    match_type: str,
    matching_phase: int,
    matching_policy: str,
    pre_alert: dict[str, Any],
    post_alert: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    return {
        "comparison_id": f"cmp-{comparison_index:06d}",
        "classification": classification,
        "match_type": match_type,
        "matching_phase": matching_phase,
        "matching_policy": matching_policy,
        "comparable_unit_key": comparable_unit_key(pre_alert, "pre", matching_policy),
        "comparable_unit_type": comparable_unit_type(matching_policy),
        "packet_anchor": packet_anchor(pre_alert),
        "tcp_conversation_anchor": tcp_conversation_anchor(pre_alert),
        "pre_alert": alert_ref(pre_alert),
        "post_alert": alert_ref(post_alert),
        "reason": reason,
    }


# This function compares PRE and POST through the packet -> alert -> signature/rule chain.
# The primary unit is packet identity, with tcp_connection_id used to catch displaced detections.
def compare_alerts_by_comparable_unit(
    pre_alerts: list[dict[str, Any]],
    post_alerts: list[dict[str, Any]],
    matching_policy: str,
) -> dict[str, Any]:
    if matching_policy not in SUPPORTED_MATCHING_POLICIES:
        raise ValueError(f"Unsupported matching policy: {matching_policy}")

    comparison_records = []
    induced_alerts = []
    remaining_pre = sorted(pre_alerts, key=alert_sort_key)
    remaining_post = sorted(post_alerts, key=alert_sort_key)

    def append_record(classification: str, match_type: str, phase: int, pre_alert: dict[str, Any], post_alert: dict[str, Any] | None, reason: str) -> None:
        comparison_records.append(
            make_comparison_record(
                comparison_index=len(comparison_records) + 1,
                classification=classification,
                match_type=match_type,
                matching_phase=phase,
                matching_policy=matching_policy,
                pre_alert=pre_alert,
                post_alert=post_alert,
                reason=reason,
            )
        )

    next_remaining_pre = []
    for pre_alert in remaining_pre:
        matching_post = pop_first_matching(
            remaining_post,
            lambda post_alert, pre_alert=pre_alert: (
                same_packet(pre_alert, post_alert, matching_policy)
                and post_alert["signature_key"] == pre_alert["signature_key"]
            ),
        )
        if matching_post is None:
            next_remaining_pre.append(pre_alert)
            continue
        append_record(
            "Failed Evasion",
            "same_packet_same_tcp_conversation_same_signature",
            1,
            pre_alert,
            matching_post,
            "The same packet anchor still generated the same Snort signature in POST.",
        )
    remaining_pre = next_remaining_pre

    next_remaining_pre = []
    for pre_alert in remaining_pre:
        matching_post = pop_first_matching(
            remaining_post,
            lambda post_alert, pre_alert=pre_alert: (
                same_packet(pre_alert, post_alert, matching_policy)
                and post_alert["signature_key"] != pre_alert["signature_key"]
            ),
        )
        if matching_post is None:
            next_remaining_pre.append(pre_alert)
            continue
        append_record(
            "Alert Mutation",
            "same_packet_same_tcp_conversation_different_signature",
            2,
            pre_alert,
            matching_post,
            "The same packet anchor no longer generated the PRE signature, but it generated a different POST alert.",
        )
    remaining_pre = next_remaining_pre

    next_remaining_pre = []
    for pre_alert in remaining_pre:
        matching_post = pop_first_matching(
            remaining_post,
            lambda post_alert, pre_alert=pre_alert: (
                same_tcp_conversation(pre_alert, post_alert)
                and packet_anchor(pre_alert) != packet_anchor(post_alert)
                and post_alert["signature_key"] == pre_alert["signature_key"]
            ),
        )
        if matching_post is None:
            next_remaining_pre.append(pre_alert)
            continue
        append_record(
            "TCP-Conversation Displaced Detection",
            "same_tcp_conversation_same_signature_different_packet",
            3,
            pre_alert,
            matching_post,
            "The same signature remained inside the same TCP conversation, but the alert emission anchor moved to a different packet.",
        )
    remaining_pre = next_remaining_pre

    for pre_alert in remaining_pre:
        append_record(
            "Successful Evasion",
            "no_unconsumed_post_alert_in_packet_or_tcp_conversation",
            4,
            pre_alert,
            None,
            "No unconsumed POST alert matched the same packet, and the same signature did not remain in the same TCP conversation.",
        )

    for post_alert in remaining_post:
        induced_alerts.append(
            {
                "matching_policy": matching_policy,
                "matching_phase": 5,
                "comparable_unit_key": comparable_unit_key(post_alert, "post", matching_policy),
                "comparable_unit_type": comparable_unit_type(matching_policy),
                "packet_anchor": packet_anchor(post_alert),
                "tcp_conversation_anchor": tcp_conversation_anchor(post_alert),
                "post_alert": alert_ref(post_alert),
                "classification": "Induced Alert",
                "status": "induced_alert",
                "reason": "This POST alert was not consumed by any stronger PRE/POST match.",
            }
        )

    classification_counts = Counter(record["classification"] for record in comparison_records)
    if induced_alerts:
        classification_counts["Induced Alert"] = len(induced_alerts)
    pre_signature_counts = Counter(alert["signature_key"] for alert in pre_alerts)
    post_signature_counts = Counter(alert["signature_key"] for alert in post_alerts)
    pre_detector_source_counts = Counter(str(alert.get("detector_source")) for alert in pre_alerts)
    post_detector_source_counts = Counter(str(alert.get("detector_source")) for alert in post_alerts)
    pre_unit_keys = {comparable_unit_key(alert, "pre", matching_policy) for alert in pre_alerts}
    post_unit_keys = {comparable_unit_key(alert, "post", matching_policy) for alert in post_alerts}
    tcp_displaced_count = sum(record["classification"] == "TCP-Conversation Displaced Detection" for record in comparison_records)
    alert_mutation_count = sum(record["classification"] == "Alert Mutation" for record in comparison_records)
    failed_evasion_count = sum(record["classification"] == "Failed Evasion" for record in comparison_records)
    successful_evasion_count = sum(record["classification"] == "Successful Evasion" for record in comparison_records)
    return {
        "records": comparison_records,
        "induced_alerts": induced_alerts,
        "summary": {
            "matching_policy": matching_policy,
            "comparable_unit_type": comparable_unit_type(matching_policy),
            "comparable_unit_field": comparable_unit_field(matching_policy),
            "pre_alert_count": len(pre_alerts),
            "post_alert_count": len(post_alerts),
            "pre_unique_signature_count": len(pre_signature_counts),
            "post_unique_signature_count": len(post_signature_counts),
            "pre_comparable_unit_count": len(pre_unit_keys),
            "post_comparable_unit_count": len(post_unit_keys),
            "compared_comparable_unit_count": len(set(pre_unit_keys) | set(post_unit_keys)),
            "pre_detector_source_counts": dict(sorted(pre_detector_source_counts.items())),
            "post_detector_source_counts": dict(sorted(post_detector_source_counts.items())),
            "same_signature_matches": failed_evasion_count,
            "different_signature_replacements": alert_mutation_count,
            "tcp_conversation_displaced_detection_count": tcp_displaced_count,
            "induced_alert_count": len(induced_alerts),
            "post_only_unmatched_count": len(induced_alerts),
            "classification_counts": dict(sorted(classification_counts.items())),
            "successful_evasion_count": successful_evasion_count,
            "alert_mutation_count": alert_mutation_count,
            "failed_evasion_count": failed_evasion_count,
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
    matching_policy: str,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_config_label = experiment_config_label_from_config(config)
    detector_policy_label = detector_policy_label_from_config(config)
    rules_policy_path = rules_policy_path_from_config(config)
    paths = default_paths(config, detector_policy_label, experiment_config_label, experiment_root)
    pre_path = Path(pre_normalized).expanduser() if pre_normalized else paths["pre_normalized"]
    post_path = Path(post_normalized).expanduser() if post_normalized else paths["post_normalized"]
    comparison_dir = Path(output_dir).expanduser() if output_dir else paths["comparison_dir"]

    pre_artifact, pre_alerts = load_normalized_alerts(pre_path, "pre")
    post_artifact, post_alerts = load_normalized_alerts(post_path, "post")
    validate_normalization_metadata(
        pre_artifact,
        artifact_path=pre_path,
        expected_detector_policy_label=detector_policy_label,
    )
    validate_normalization_metadata(
        post_artifact,
        artifact_path=post_path,
        expected_detector_policy_label=detector_policy_label,
    )
    comparison = compare_alerts_by_comparable_unit(pre_alerts, post_alerts, matching_policy)
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
        "detector_policy_label": detector_policy_label,
        "rules_policy_path": rules_policy_path,
        "experiment_config_label": experiment_config_label,
        "source_pre_normalized_alerts": str(pre_path),
        "source_post_normalized_alerts": str(post_path),
        "comparison_policy": {
            "matching_basis": "Packet -> alert -> signature/rule, with tcp_connection_id used for TCP-conversation displaced detections.",
            "causal_chain": "packet_id/pkt_num -> normalized alert -> signature_key (gid:sid:rev)",
            "tcp_conversation_anchor": "tcp_connection_id",
            "matching_policy": matching_policy,
            "comparable_unit_type": comparable_unit_type(matching_policy),
            "comparable_unit_field": comparable_unit_field(matching_policy),
            "detection_evidence": "Any normalized alert record counts as detection evidence, regardless of action value.",
            "classification_labels": [
                "Failed Evasion",
                "Alert Mutation",
                "TCP-Conversation Displaced Detection",
                "Successful Evasion",
                "Induced Alert",
            ],
            "phase_order": [
                "Phase 1: same packet + same TCP conversation + same signature -> Failed Evasion",
                "Phase 2: same packet + same TCP conversation + different signature -> Alert Mutation",
                "Phase 3: same tcp_connection_id + same signature + different packet -> TCP-Conversation Displaced Detection",
                "Phase 4: unconsumed PRE alerts -> Successful Evasion",
                "Phase 5: unconsumed POST alerts -> Induced Alert",
            ],
            "new_post_alert_policy": "Unconsumed POST alerts after phased matching are reported as Induced Alert.",
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
        "induced_alerts": comparison["induced_alerts"],
        "post_only_unmatched_alerts": comparison["induced_alerts"],
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
        "matching_policy": comparison["summary"]["matching_policy"],
        "comparable_unit_type": comparison["summary"]["comparable_unit_type"],
        "comparable_unit_field": comparison["summary"]["comparable_unit_field"],
        "pre_comparable_unit_count": comparison["summary"]["pre_comparable_unit_count"],
        "post_comparable_unit_count": comparison["summary"]["post_comparable_unit_count"],
        "compared_comparable_unit_count": comparison["summary"]["compared_comparable_unit_count"],
        "pre_detector_source_counts": comparison["summary"]["pre_detector_source_counts"],
        "post_detector_source_counts": comparison["summary"]["post_detector_source_counts"],
        "detector_policy_label": detector_policy_label,
        "rules_policy_path": rules_policy_path,
        "classification_counts": comparison["summary"]["classification_counts"],
        "successful_evasion_count": comparison["summary"]["successful_evasion_count"],
        "alert_mutation_count": comparison["summary"]["alert_mutation_count"],
        "failed_evasion_count": comparison["summary"]["failed_evasion_count"],
        "tcp_conversation_displaced_detection_count": comparison["summary"]["tcp_conversation_displaced_detection_count"],
        "induced_alert_count": comparison["summary"]["induced_alert_count"],
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
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    detector_policy_label = detector_policy_label_from_config(config)
    return default_step_log_path(
        experiment_root=experiment_root,
        step_name="step_23_alert_comparison",
        branch_label=detector_policy_label,
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
    add(
        "--matching-policy",
        choices=sorted(SUPPORTED_MATCHING_POLICIES),
        default=DEFAULT_MATCHING_POLICY,
        help="Comparable-unit matching policy used before classifying alert outcomes.",
    )
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
                matching_policy=args.matching_policy,
            )
        except Exception:
            print("Step 23 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        print(f"PRE alerts: {result['pre_alert_count']}")
        print(f"POST alerts: {result['post_alert_count']}")
        print(f"Detector policy: {result['detector_policy_label']}")
        print(f"Rules policy path: {result['rules_policy_path'] or 'none'}")
        print(
            f"Matching policy: {result['matching_policy']} "
            f"({result['comparable_unit_type']} via {result['comparable_unit_field']})"
        )
        print(f"PRE comparable units: {result['pre_comparable_unit_count']}")
        print(f"POST comparable units: {result['post_comparable_unit_count']}")
        print(f"Compared comparable units: {result['compared_comparable_unit_count']}")
        print(f"PRE unique signatures: {result['pre_unique_signature_count']}")
        print(f"POST unique signatures: {result['post_unique_signature_count']}")
        print(f"PRE detector sources: {result['pre_detector_source_counts']}")
        print(f"POST detector sources: {result['post_detector_source_counts']}")
        print(f"Classifications: {result['classification_counts']}")
        print(f"Successful evasion: {result['successful_evasion_count']}")
        print(f"Alert mutation: {result['alert_mutation_count']}")
        print(f"TCP-conversation displaced detection: {result['tcp_conversation_displaced_detection_count']}")
        print(f"Failed evasion: {result['failed_evasion_count']}")
        print(f"Induced alert: {result['induced_alert_count']}")
        print(f"Alert comparison: {result['alert_comparison']}")
        print(f"Signature summary: {result['signature_comparison_summary']}")


if __name__ == "__main__":
    main()

