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
from common.terminal_logging import terminal_log


NORMALIZED_SCHEMA_VERSION = "snort_normalized_alerts_v4"


# This function reads a JSON file and returns the parsed Python value.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


# This function returns the current UTC timestamp in ISO 8601 format for processing metadata.
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# This function returns a compact UTC timestamp for terminal log filenames.
def utc_timestamp_for_log_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# This function builds the experiment root directory from the experiment output_root and experiment_id fields.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function validates the minimum config shape required by Step 22.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "pipeline", "snort"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["snort"], ["detector_policy_label"], "snort")
    detector_policy_label = config["snort"]["detector_policy_label"]
    if not isinstance(detector_policy_label, str) or not sanitize_name_component(detector_policy_label):
        raise ValueError("snort.detector_policy_label must be a non-empty string.")


#This function resolves the detector-policy branch used to locate and label Snort artifacts.
def detector_policy_label_from_config(config: dict[str, Any]) -> str:
    return sanitize_name_component(config["snort"]["detector_policy_label"])


#This function preserves the Snort rules-policy selector in normalization provenance.
def rules_policy_path_from_config(config: dict[str, Any]) -> str:
    return str(config.get("snort", {}).get("rules_policy_path", "")).strip()


# This function resolves the default Step 21 input directory for PRE or POST alert artifacts.
def default_snort_input_dir(
    config: dict[str, Any],
    traffic_version: str,
    detector_policy_label: str,
    post_run_label: str | None = None,
    experiment_root_override: str | Path | None = None,
) -> Path:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    detector_root = experiment_root / "11_snort_raw" / detector_policy_label
    if traffic_version == "pre":
        return detector_root / "pre"
    if not post_run_label:
        raise ValueError("POST normalization requires --post-run-label unless --input-dir is provided explicitly.")
    return detector_root / "post" / post_run_label


# This function resolves the default Step 22 output directory for PRE or POST normalized alerts.
def default_normalized_output_dir(
    config: dict[str, Any],
    traffic_version: str,
    detector_policy_label: str,
    experiment_root_override: str | Path | None = None,
) -> Path:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    detector_root = experiment_root / "12_alerts_processed" / detector_policy_label
    if traffic_version == "pre":
        return detector_root / "pre"
    return detector_root / "post"


#This function resolves the Step 14 packet trace used to map Snort packet numbers to stable packet IDs.
def default_packet_trace_path(config: dict[str, Any], experiment_root_override: str | Path | None = None) -> Path:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    return experiment_root / "04_packet_json" / "selected_packet_records.json"


#This function builds a unique reduced-index lookup and rejects ambiguous packet provenance.
def packet_trace_by_reduced_index(packet_json_path: Path) -> dict[int, dict[str, Any]]:
    packet_json = read_json(packet_json_path)
    if not isinstance(packet_json, dict):
        raise ValueError(f"Step 14 packet JSON must be an object: {packet_json_path}")
    traffic = packet_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError(f"Step 14 packet JSON must contain a traffic list: {packet_json_path}")
    trace_by_index: dict[int, dict[str, Any]] = {}
    for packet in traffic:
        if not isinstance(packet, dict):
            continue
        reduced_index = optional_int(packet.get("reduced_packet_index"))
        if reduced_index is None:
            continue
        trace_by_index[reduced_index] = {
            "packet_id": packet.get("packet_id"),
            "original_packet_number": packet.get("original_packet_number"),
            "reduced_packet_index": reduced_index,
            "tcp_connection_id": packet.get("tcp_connection_id"),
            "tcp_stream_id": packet.get("tcp_stream_id"),
            "packet_anchor_proto": packet.get("transport_protocol") or packet.get("proto"),
            "packet_anchor_src_addr": packet.get("src_ip"),
            "packet_anchor_src_port": optional_int(packet.get("src_port")),
            "packet_anchor_dst_addr": packet.get("dst_ip"),
            "packet_anchor_dst_port": optional_int(packet.get("dst_port")),
            "assigned_flow_ids": (packet.get("flow_context") or {}).get("assigned_flow_ids", []),
            "candidate_flow_ids": (packet.get("flow_context") or {}).get("candidate_flow_ids", []),
            "packet_mapping_status": (packet.get("flow_context") or {}).get("packet_mapping_status"),
        }
    return trace_by_index


# This function finds the converted Step 21 alert JSON file in a Snort raw output directory.
# execution_metadata.json is preferred because it records the exact converted file chosen by Step 21.
def resolve_converted_alert_json(input_dir: Path, execution_metadata: dict[str, Any]) -> Path:
    artifact_path = execution_metadata.get("artifacts", {}).get("converted_alert_json")
    if isinstance(artifact_path, str) and artifact_path.strip():
        candidate = Path(artifact_path)
        if candidate.exists():
            return candidate
        local_candidate = input_dir / candidate.name
        if local_candidate.exists():
            return local_candidate

    matches = sorted(input_dir.glob("alerts__*.json"))
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(f"No converted Step 21 alerts__*.json file found in: {input_dir}")
    raise ValueError(f"Multiple converted alert JSON files found in {input_dir}; pass --input-alert-json explicitly.")


# This function normalizes a value that should be an integer while keeping None for missing fields.
def optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


# This function creates the stable Snort signature key used by Step 23 comparison.
def signature_key(gid: int | None, sid: int | None, rev: int | None) -> str:
    gid_part = str(gid) if gid is not None else "unknown"
    sid_part = str(sid) if sid is not None else "unknown"
    rev_part = str(rev) if rev is not None else "unknown"
    return f"{gid_part}:{sid_part}:{rev_part}"


# This function infers the broad detector source from Snort's generator ID.
# Snort alert_json does not include an explicit source field, so Step 22 records this practical and traceable classification.
def detector_source_from_gid(gid: int | None) -> str:
    if gid == 1:
        return "ruleset_text"
    if gid == 3:
        return "ruleset_so"
    if gid in {116, 119, 129}:
        return "builtin_decoder_or_inspector"
    return "unknown"


# This function normalizes one Snort alert_json record while preserving the full raw object for provenance.
def normalize_one_alert(
    raw_alert: dict[str, Any],
    alert_index: int,
    traffic_version: str,
    experiment_id: str,
    packet_trace: dict[str, Any] | None,
) -> dict[str, Any]:
    gid = optional_int(raw_alert.get("gid"))
    sid = optional_int(raw_alert.get("sid"))
    rev = optional_int(raw_alert.get("rev"))
    key = signature_key(gid, sid, rev)
    detector_source = detector_source_from_gid(gid)
    pkt_num = optional_int(raw_alert.get("pkt_num"))
    trace = packet_trace or {}
    return {
        "normalized_alert_id": f"{traffic_version}-{alert_index:06d}",
        "alert_index": alert_index,
        "traffic_version": traffic_version,
        "experiment_id": experiment_id,
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "signature_key": key,
        "detector_source": detector_source,
        "msg": raw_alert.get("msg"),
        "class": raw_alert.get("class"),
        "action": raw_alert.get("action"),
        "proto": raw_alert.get("proto"),
        "src_addr": raw_alert.get("src_addr"),
        "src_port": optional_int(raw_alert.get("src_port")),
        "dst_addr": raw_alert.get("dst_addr"),
        "dst_port": optional_int(raw_alert.get("dst_port")),
        "pkt_num": pkt_num,
        "packet_id": trace.get("packet_id"),
        "original_packet_number": trace.get("original_packet_number"),
        "reduced_packet_index": trace.get("reduced_packet_index"),
        "tcp_connection_id": trace.get("tcp_connection_id"),
        "tcp_stream_id": trace.get("tcp_stream_id"),
        "packet_anchor_tcp_connection_id": trace.get("tcp_connection_id"),
        "packet_anchor_tcp_stream_id": trace.get("tcp_stream_id"),
        "packet_anchor_proto": trace.get("packet_anchor_proto"),
        "packet_anchor_src_addr": trace.get("packet_anchor_src_addr"),
        "packet_anchor_src_port": trace.get("packet_anchor_src_port"),
        "packet_anchor_dst_addr": trace.get("packet_anchor_dst_addr"),
        "packet_anchor_dst_port": trace.get("packet_anchor_dst_port"),
        "assigned_flow_ids": trace.get("assigned_flow_ids", []),
        "candidate_flow_ids": trace.get("candidate_flow_ids", []),
        "packet_mapping_status": trace.get("packet_mapping_status"),
        "packet_trace_status": "matched_step14_packet" if packet_trace else "missing_step14_packet_trace",
        "timestamp": raw_alert.get("timestamp"),
        "pkt_len": optional_int(raw_alert.get("pkt_len")),
        "raw_alert": raw_alert,
    }


# This function aggregates normalized alerts by signature for inspection and later comparison.
def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    signature_counts = Counter(alert["signature_key"] for alert in alerts)
    gid_counts = Counter(str(alert.get("gid")) for alert in alerts)
    detector_source_counts = Counter(str(alert.get("detector_source")) for alert in alerts)
    action_counts = Counter(str(alert.get("action")) for alert in alerts)
    proto_counts = Counter(str(alert.get("proto")) for alert in alerts)
    packet_trace_status_counts = Counter(str(alert.get("packet_trace_status")) for alert in alerts)
    tcp_connection_count = len({alert.get("tcp_connection_id") for alert in alerts if alert.get("tcp_connection_id")})
    signatures = []
    for key, count in sorted(signature_counts.items()):
        first = next(alert for alert in alerts if alert["signature_key"] == key)
        signatures.append(
            {
                "signature_key": key,
                "count": count,
                "gid": first["gid"],
                "sid": first["sid"],
                "rev": first["rev"],
                "detector_source": first["detector_source"],
                "msg": first.get("msg"),
                "class": first.get("class"),
            }
        )
    return {
        "alert_count": len(alerts),
        "unique_signature_count": len(signature_counts),
        "signature_counts": dict(sorted(signature_counts.items())),
        "gid_counts": dict(sorted(gid_counts.items())),
        "detector_source_counts": dict(sorted(detector_source_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
        "proto_counts": dict(sorted(proto_counts.items())),
        "packet_trace_status_counts": dict(sorted(packet_trace_status_counts.items())),
        "tcp_connection_count": tcp_connection_count,
        "signatures": signatures,
    }


# This function runs Step 22 for one traffic version.
def normalize_one_traffic_version(
    *,
    config: dict[str, Any],
    traffic_version: str,
    configured_detector_policy_label: str,
    configured_rules_policy_path: str,
    configured_experiment_id: str,
    input_dir: Path,
    output_dir: Path,
    input_alert_json: Path | None,
    packet_trace_index: dict[int, dict[str, Any]],
    packet_trace_path: Path,
) -> dict[str, Any]:
    metadata_path = input_dir / "execution_metadata.json"
    if not metadata_path.exists():
        raise FileNotFoundError(f"Step 21 execution metadata does not exist: {metadata_path}")
    execution_metadata = read_json(metadata_path)
    source_traffic_version = execution_metadata.get("traffic_version")
    source_detector_policy_label = execution_metadata.get("detector_policy_label")
    source_rules_policy_path = execution_metadata.get("rules_policy_path")
    source_experiment_id = execution_metadata.get("experiment_id")
    source_traffic_scope = execution_metadata.get("traffic_scope")
    source_post_run_label = execution_metadata.get("post_run_label")
    if source_traffic_version != traffic_version:
        raise ValueError(
            "Step 21 execution metadata traffic_version does not match the requested normalization side: "
            f"{source_traffic_version!r} != {traffic_version!r}"
        )
    if source_detector_policy_label != configured_detector_policy_label:
        raise ValueError(
            "Step 21 execution metadata detector_policy_label does not match the active config: "
            f"{source_detector_policy_label!r} != {configured_detector_policy_label!r}"
        )
    if source_experiment_id != configured_experiment_id:
        raise ValueError(
            "Step 21 metadata experiment_id does not match the active config: "
            f"{source_experiment_id!r} != {configured_experiment_id!r}"
        )

    alert_json_path = input_alert_json if input_alert_json else resolve_converted_alert_json(input_dir, execution_metadata)
    raw_alerts = read_json(alert_json_path)
    if not isinstance(raw_alerts, list):
        raise ValueError(f"Converted Step 21 alert JSON must contain a JSON array: {alert_json_path}")

    normalized_alerts = []
    for alert_index, raw_alert in enumerate(raw_alerts, start=1):
        if not isinstance(raw_alert, dict):
            raise ValueError(f"Alert record {alert_index} is not a JSON object in: {alert_json_path}")
        pkt_num = optional_int(raw_alert.get("pkt_num"))
        packet_trace = packet_trace_index.get(pkt_num) if pkt_num is not None else None
        normalized_alerts.append(
            normalize_one_alert(
                raw_alert,
                alert_index,
                traffic_version,
                configured_experiment_id,
                packet_trace,
            )
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / f"normalized-alerts__traffic-{traffic_version}.json"
    metadata_output_path = output_dir / f"normalization-metadata__traffic-{traffic_version}.json"
    summary = summarize_alerts(normalized_alerts)
    normalized_artifact = {
        "metadata": {
            "schema_version": NORMALIZED_SCHEMA_VERSION,
            "generated_at_utc": utc_now(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "traffic_version": traffic_version,
            "source_traffic_version": source_traffic_version,
            "configured_detector_policy_label": configured_detector_policy_label,
            "source_detector_policy_label": source_detector_policy_label,
            "configured_rules_policy_path": configured_rules_policy_path,
            "source_rules_policy_path": source_rules_policy_path,
            "source_experiment_id": source_experiment_id,
            "traffic_scope": source_traffic_scope,
            "source_post_run_label": source_post_run_label,
            "source_snort_raw_dir": str(input_dir),
            "source_execution_metadata": str(metadata_path),
            "source_alert_json": str(alert_json_path),
            "normalization_policy": {
                "detection_evidence": "Any Snort alert_json record counts as detection evidence, regardless of action value.",
                "signature_key": "gid:sid:rev",
                "packet_traceability": {
                    "source_step_14_packet_json": str(packet_trace_path),
                    "mapping": "Snort pkt_num is mapped to Step 14 reduced_packet_index.",
                    "packet_anchor": "packet_id",
                    "tcp_conversation_anchor": "tcp_connection_id",
                    "tcp_stream_anchor": "tcp_stream_id",
                    "packet_anchor_tuple_fields": [
                        "packet_anchor_proto",
                        "packet_anchor_src_addr",
                        "packet_anchor_src_port",
                        "packet_anchor_dst_addr",
                        "packet_anchor_dst_port",
                    ],
                    "packet_anchor_tuple_basis": "Physical Step 14 packet tuple for the packet referenced by Snort pkt_num, not the alert tuple reported by Snort.",
                },
                "detector_source": {
                    "basis": "Inferred from Snort gid because alert_json has no explicit source field.",
                    "gid_1": "ruleset_text",
                    "gid_3": "ruleset_so",
                    "gid_116": "builtin_decoder_or_inspector",
                    "gid_119": "builtin_decoder_or_inspector",
                    "gid_129": "builtin_decoder_or_inspector",
                    "fallback": "unknown",
                },
                "raw_alert_preservation": "Each normalized alert stores the original Snort alert object in raw_alert.",
            },
        },
        "summary": summary,
        "alerts": normalized_alerts,
    }
    processing_metadata = {
        "schema_version": "snort_alert_normalization_metadata_v2",
        "generated_at_utc": utc_now(),
        "traffic_version": traffic_version,
        "source_traffic_version": source_traffic_version,
        "configured_detector_policy_label": configured_detector_policy_label,
        "source_detector_policy_label": source_detector_policy_label,
        "configured_rules_policy_path": configured_rules_policy_path,
        "source_rules_policy_path": source_rules_policy_path,
        "experiment_id": configured_experiment_id,
        "source_experiment_id": source_experiment_id,
        "traffic_scope": source_traffic_scope,
        "source_post_run_label": source_post_run_label,
        "source_alert_json": str(alert_json_path),
        "source_execution_metadata": str(metadata_path),
        "source_step_21_metadata": execution_metadata,
        "source_step_14_packet_json": str(packet_trace_path),
        "output_normalized_alerts": str(normalized_path),
        "summary": summary,
    }
    write_json(normalized_path, normalized_artifact)
    write_json(metadata_output_path, processing_metadata)
    return {
        "traffic_version": traffic_version,
        "detector_policy_label": configured_detector_policy_label,
        "rules_policy_path": configured_rules_policy_path,
        "alert_count": summary["alert_count"],
        "unique_signature_count": summary["unique_signature_count"],
        "detector_source_counts": summary["detector_source_counts"],
        "packet_trace_status_counts": summary["packet_trace_status_counts"],
        "normalized_alerts": str(normalized_path),
        "normalization_metadata": str(metadata_output_path),
    }


# This function is the public Python entry point for Step 22.
def normalize_alerts(
    *,
    config_path: str | Path,
    traffic_version: str,
    experiment_root: str | Path | None,
    post_run_label: str | None,
    input_dir: str | Path | None,
    output_dir: str | Path | None,
    input_alert_json: str | Path | None,
) -> list[dict[str, Any]]:
    config = load_json_config(config_path)
    validate_config(config)
    experiment_id = config["experiment"]["experiment_id"]
    detector_policy_label = detector_policy_label_from_config(config)
    rules_policy_path = rules_policy_path_from_config(config)
    packet_trace_path = default_packet_trace_path(config, experiment_root)
    packet_trace_index = packet_trace_by_reduced_index(packet_trace_path)
    selected_versions = ["pre", "post"] if traffic_version == "both" else [traffic_version]
    if (input_dir or output_dir or input_alert_json) and len(selected_versions) != 1:
        raise ValueError("--input-dir, --output-dir, and --input-alert-json overrides are only valid for one traffic version.")
    if post_run_label and input_dir:
        raise ValueError("--post-run-label cannot be combined with --input-dir.")
    if "post" in selected_versions and not post_run_label and not input_dir:
        raise ValueError("POST normalization requires --post-run-label unless --input-dir is provided explicitly.")

    results = []
    for selected_version in selected_versions:
        resolved_input_dir = (
            Path(input_dir).expanduser()
            if input_dir
            else default_snort_input_dir(
                config,
                selected_version,
                detector_policy_label,
                post_run_label if selected_version == "post" else None,
                experiment_root,
            )
        )
        resolved_output_dir = (
            Path(output_dir).expanduser()
            if output_dir
            else default_normalized_output_dir(config, selected_version, detector_policy_label, experiment_root)
        )
        resolved_input_alert_json = Path(input_alert_json).expanduser() if input_alert_json else None
        results.append(
            normalize_one_traffic_version(
                config=config,
                traffic_version=selected_version,
                configured_detector_policy_label=detector_policy_label,
                configured_rules_policy_path=rules_policy_path,
                configured_experiment_id=experiment_id,
                input_dir=resolved_input_dir,
                output_dir=resolved_output_dir,
                input_alert_json=resolved_input_alert_json,
                packet_trace_index=packet_trace_index,
                packet_trace_path=packet_trace_path,
            )
        )
    return results


# This function resolves the terminal log path for Step 22.
# POST logs include the Step 21 run label in the directory path because POST Snort runs are stored by run timestamp.
def resolve_log_path(args: argparse.Namespace) -> Path:
    if args.log_file:
        return Path(args.log_file).expanduser()

    config = load_json_config(args.config)
    validate_config(config)
    experiment_root = Path(args.experiment_root).expanduser() if args.experiment_root else build_experiment_root(config)
    detector_policy_label = detector_policy_label_from_config(config)
    log_root = experiment_root / "logs" / "step_22_alert_normalization" / detector_policy_label
    if args.traffic_version == "pre":
        log_dir = log_root / "pre"
        label_for_filename = "pre"
    elif args.traffic_version == "post":
        if not args.post_run_label and not args.input_dir:
            raise ValueError("POST terminal logging requires --post-run-label unless --input-dir is provided explicitly.")
        post_branch_label = args.post_run_label or "manual-input-dir"
        log_dir = log_root / "post" / post_branch_label
        label_for_filename = f"post_{post_branch_label}"
    else:
        if not args.post_run_label:
            raise ValueError("Combined PRE/POST terminal logging requires --post-run-label.")
        log_dir = log_root / "both" / args.post_run_label
        label_for_filename = f"both_{args.post_run_label}"
    return log_dir / f"step_22_alert_normalization_{label_for_filename}_{utc_timestamp_for_log_filename()}.log"


# This function parses Step 22 command-line arguments.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize Step 21 Snort alert JSON artifacts for comparison.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--traffic-version", choices=["pre", "post", "both"], default="both", help="Traffic side to normalize.")
    add("--experiment-root", help="Optional experiment root override.")
    add("--post-run-label", help="Required for POST default input resolution. Step 21 POST run label under 11_snort_raw/<detector_policy_label>/post/.")
    add("--input-dir", help="Explicit Step 21 input directory. Only valid for one traffic version.")
    add("--input-alert-json", help="Explicit converted Step 21 alerts__*.json path. Only valid for one traffic version.")
    add("--output-dir", help="Explicit Step 22 output directory. Only valid for one traffic version.")
    add("--log-file", help="Optional explicit terminal log file path.")
    return parser.parse_args()


# This function is the command-line entry point.
def main() -> None:
    args = parse_cli_args()
    log_path = resolve_log_path(args)
    with terminal_log(log_path, banner="Step 22 terminal log"):
        try:
            results = normalize_alerts(
                config_path=args.config,
                traffic_version=args.traffic_version,
                experiment_root=args.experiment_root,
                post_run_label=args.post_run_label,
                input_dir=args.input_dir,
                output_dir=args.output_dir,
                input_alert_json=args.input_alert_json,
            )
        except Exception:
            print("Step 22 failed. Traceback follows:", file=sys.stderr)
            traceback.print_exc()
            raise SystemExit(1)

        for result in results:
            print(
                f"{result['traffic_version']} {result['detector_policy_label']}: alerts={result['alert_count']} "
                f"unique_signatures={result['unique_signature_count']} output={result['normalized_alerts']}"
            )
            print(f"{result['traffic_version']} {result['detector_policy_label']}: rules_policy_path={result['rules_policy_path'] or 'none'}")
            print(f"{result['traffic_version']} {result['detector_policy_label']}: detector_sources={result['detector_source_counts']}")
            print(f"{result['traffic_version']} {result['detector_policy_label']}: packet_trace={result['packet_trace_status_counts']}")


if __name__ == "__main__":
    main()
