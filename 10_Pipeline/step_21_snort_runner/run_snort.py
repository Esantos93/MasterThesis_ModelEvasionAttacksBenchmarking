from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# This allows the script to import shared pipeline helpers from common/ even when it is executed from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


# This schema version identifies the raw Snort execution metadata written by Step 21.
RUN_SCHEMA_VERSION = "snort_raw_run_v1"


# This function returns the current UTC timestamp in ISO 8601 format for reproducible execution metadata.
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# This function builds the experiment root directory from the experiment output_root and experiment_id fields in the config.
def build_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config["experiment"]
    return Path(experiment["output_root"]).expanduser() / experiment["experiment_id"]


# This function validates the minimum config shape required by Step 21.
# It checks the experiment paths, Snort execution settings, detector rule toggles, and the pipeline experiment_config_label.
# The rules_policy_path is optional, but when present it must be a string so it can be injected safely into the Snort Lua override.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "snort", "pipeline"], "config")
    require_keys(config["experiment"], ["experiment_id", "output_root"], "experiment")
    require_keys(config["snort"], ["snort_binary", "config_path", "enable_builtin_rules", "enable_ruleset", "ruleset_path"], "snort")
    require_keys(config["pipeline"], ["experiment_config_label"], "pipeline")

    snort = config["snort"]
    if not isinstance(snort["enable_builtin_rules"], bool):
        raise ValueError("snort.enable_builtin_rules must be true or false.")
    if not isinstance(snort["enable_ruleset"], bool):
        raise ValueError("snort.enable_ruleset must be true or false.")
    if snort["enable_ruleset"] and not str(snort.get("ruleset_path", "")).strip():
        raise ValueError("snort.ruleset_path must be set when snort.enable_ruleset is true.")
    if not isinstance(snort.get("rules_policy_path", ""), str):
        raise ValueError("snort.rules_policy_path must be a string when provided.")

    experiment_config_label = config["pipeline"]["experiment_config_label"]
    if not isinstance(experiment_config_label, str) or not experiment_config_label.strip():
        raise ValueError("pipeline.experiment_config_label must be a non-empty string.")
    label_options = config["pipeline"].get("experiment_config_label_options")
    if label_options is not None:
        if not isinstance(label_options, list) or not all(isinstance(item, str) for item in label_options):
            raise ValueError("pipeline.experiment_config_label_options must be a list of strings when provided.")
        if experiment_config_label not in label_options:
            raise ValueError("pipeline.experiment_config_label must be one of pipeline.experiment_config_label_options.")


# This function returns the experiment configuration label that is fixed for the current pipeline run.
# Step 21 uses this label to locate POST PCAP artifacts and to keep POST Snort outputs separated by experiment configuration.
def experiment_config_label_from_config(config: dict[str, Any]) -> str:
    return config["pipeline"]["experiment_config_label"]


# This function returns the default input PCAP for either PRE or POST traffic.
# PRE traffic is common to every experiment configuration, while POST traffic is resolved through experiment_config_label.
def default_input_pcap(
    config: dict[str, Any],
    traffic_version: str,
    experiment_config_label: str | None,
    experiment_root_override: str | Path | None = None,
) -> Path:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    if traffic_version == "pre":
        return experiment_root / "03_selected_traffic" / "selected_malicious_traffic.pcap"
    return experiment_root / "10_reconstructed_pcap" / experiment_config_label / "modified_traffic.pcap"


# This function returns the default Step 21 output directory for a Snort run.
# PRE artifacts are stored in a single common directory, while POST artifacts are separated by experiment_config_label.
def default_output_dir(
    config: dict[str, Any],
    traffic_version: str,
    experiment_config_label: str | None,
    experiment_root_override: str | Path | None = None,
) -> Path:
    experiment_root = Path(experiment_root_override).expanduser() if experiment_root_override else build_experiment_root(config)
    if traffic_version == "pre":
        return experiment_root / "11_snort_raw" / "pre"
    return experiment_root / "11_snort_raw" / "post" / experiment_config_label


# This function builds the inline Lua ips table passed to Snort through --lua.
# It keeps the base snort.lua file stable while letting the pipeline config control built-in rules, the external ruleset include, and the optional Cisco policy states file.
def build_lua_ips_config(snort_config: dict[str, Any]) -> str:
    parts = [
        "variables = default_variables",
        f"enable_builtin_rules = {str(snort_config['enable_builtin_rules']).lower()}",
    ]
    if snort_config["enable_ruleset"]:
        ruleset_path = expand_config_path(snort_config["ruleset_path"])
        parts.append(f"include = '{ruleset_path}'")
        rules_policy_path = str(snort_config.get("rules_policy_path", "")).strip()
        if rules_policy_path:
            parts.append(f"states = '{expand_config_path(rules_policy_path)}'")
    return "ips = { " + ", ".join(parts) + " }"


# This function expands user-home references without converting Ubuntu-style absolute paths into Windows-style paths.
# The pipeline config is intended for the Ubuntu VM, so paths such as /usr/local/bin/snort must be preserved when inspected from Windows.
def expand_config_path(raw_path: str) -> str:
    return os.path.expanduser(str(raw_path))


# This function constructs the Snort command as an argv list.
# The command runs Snort over one PCAP, writes logs under output_dir, disables checksum validation with -k none, and injects the detector configuration through --lua.
def build_snort_command(
    *,
    snort_config: dict[str, Any],
    input_pcap_path: Path,
    output_dir: Path,
) -> list[str]:
    command = [
        expand_config_path(snort_config["snort_binary"]),
        "-c",
        expand_config_path(snort_config["config_path"]),
    ]
    if snort_config.get("plugin_path"):
        command.extend(["--plugin-path", expand_config_path(snort_config["plugin_path"])])
    if snort_config.get("daq_dir"):
        command.extend(["--daq-dir", expand_config_path(snort_config["daq_dir"])])
    command.extend(
        [
            "-l",
            str(output_dir),
            "-k",
            "none",
            "-r",
            str(input_pcap_path),
            "--lua",
            build_lua_ips_config(snort_config),
        ]
    )
    return command


# This function writes a UTF-8 text artifact and creates its parent directory if needed.
def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# This function normalises one filename component.
# It uses dashes inside a component and leaves double underscores available as the separator between complete filename fields.
def safe_filename_part(value: str) -> str:
    cleaned = value.strip().replace("_", "-")
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", cleaned)
    cleaned = cleaned.strip("-_.")
    return cleaned or "unknown"


# This function returns the ruleset value used in the converted alert JSON filename.
# If the ruleset is disabled, the filename records that explicitly; otherwise it records the configured ruleset file stem.
def ruleset_label(snort_config: dict[str, Any]) -> str:
    if not snort_config["enable_ruleset"]:
        return "off"
    ruleset_path = expand_config_path(snort_config["ruleset_path"])
    return safe_filename_part(Path(ruleset_path).stem)


# This function returns the policy value used in the converted alert JSON filename.
# Cisco policy state files are named rulestates-*.states, so the prefix is removed to keep filenames shorter.
def rules_policy_label(snort_config: dict[str, Any]) -> str:
    rules_policy_path = str(snort_config.get("rules_policy_path", "")).strip()
    if not snort_config["enable_ruleset"] or not rules_policy_path:
        return "none"
    policy_stem = Path(expand_config_path(rules_policy_path)).stem
    policy_stem = policy_stem.removeprefix("rulestates-")
    return safe_filename_part(policy_stem)


# This function returns whether Snort built-in inspector rules were enabled for the run.
def builtin_label(snort_config: dict[str, Any]) -> str:
    return "on" if snort_config["enable_builtin_rules"] else "off"


# This function formats one filename field as name-value.
# Complete fields are later separated with double underscores to avoid ambiguity when values contain dashes.
def filename_field(name: str, value: str) -> str:
    return f"{safe_filename_part(name)}-{safe_filename_part(value)}"


# This function builds the human-readable converted alert JSON filename.
# The filename records traffic side, experiment configuration, PCAP stem, ruleset, policy, and built-in rule state.
def converted_alert_json_name(
    *,
    traffic_version: str,
    experiment_config_label: str | None,
    input_pcap_path: Path,
    snort_config: dict[str, Any],
) -> str:
    parts = [
        "alerts",
        filename_field("traffic", traffic_version),
    ]
    if experiment_config_label:
        parts.append(filename_field("experiment-config", experiment_config_label))
    parts.extend(
        [
            filename_field("pcap", input_pcap_path.stem),
            filename_field("ruleset", ruleset_label(snort_config)),
            filename_field("policy", rules_policy_label(snort_config)),
            filename_field("builtin", builtin_label(snort_config)),
        ]
    )
    return "__".join(parts) + ".json"


# This function converts Snort alert_json.txt content from JSONL into a JSON array.
# The raw alert_json.txt file is left untouched, and parse errors are reported in metadata instead of silently dropping lines.
def convert_alert_jsonl_to_json_array(source_path: Path, output_path: Path) -> dict[str, Any]:
    alerts = []
    errors = []
    with source_path.open("r", encoding="utf-8") as source_file:
        for line_number, line in enumerate(source_file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                alerts.append(json.loads(stripped))
            except json.JSONDecodeError as error:
                errors.append(
                    {
                        "line_number": line_number,
                        "error": str(error),
                    }
                )

    if errors:
        return {
            "source": str(source_path),
            "converted": None,
            "alert_count": len(alerts),
            "status": "failed",
            "errors": errors,
        }

    write_json(output_path, alerts)
    return {
        "source": str(source_path),
        "converted": str(output_path),
        "alert_count": len(alerts),
        "status": "converted",
        "errors": [],
    }


# This function post-processes Snort's alert_json.txt output when it exists.
# It preserves the raw JSONL file and creates a separate JSON array file for easier human inspection.
def postprocess_snort_alert_json(
    *,
    output_dir: Path,
    traffic_version: str,
    experiment_config_label: str | None,
    input_pcap_path: Path,
    snort_config: dict[str, Any],
) -> dict[str, Any]:
    raw_alert_path = output_dir / "alert_json.txt"
    if not raw_alert_path.exists():
        return {
            "source": str(raw_alert_path),
            "converted": None,
            "alert_count": 0,
            "status": "source_not_found",
            "errors": [],
        }

    converted_path = output_dir / converted_alert_json_name(
        traffic_version=traffic_version,
        experiment_config_label=experiment_config_label,
        input_pcap_path=input_pcap_path,
        snort_config=snort_config,
    )
    return convert_alert_jsonl_to_json_array(raw_alert_path, converted_path)


# This function executes one Snort run or prepares one dry-run.
# It stores command evidence, stdout/stderr logs, converted alert JSON artifacts, and structured execution metadata even if Snort exits with a non-zero code.
def run_one_snort_execution(
    *,
    config: dict[str, Any],
    traffic_version: str,
    experiment_config_label: str | None,
    input_pcap_path: Path,
    output_dir: Path,
    dry_run: bool,
) -> dict[str, Any]:
    if not input_pcap_path.exists():
        raise FileNotFoundError(f"Input PCAP does not exist: {input_pcap_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    snort_config = config["snort"]
    command = build_snort_command(snort_config=snort_config, input_pcap_path=input_pcap_path, output_dir=output_dir)

    started_at = utc_now()
    completed_at = started_at
    stdout = ""
    stderr = ""
    exit_code: int | None = None

    if not dry_run:
        completed_process = subprocess.run(command, capture_output=True, text=True, check=False)
        completed_at = utc_now()
        stdout = completed_process.stdout
        stderr = completed_process.stderr
        exit_code = completed_process.returncode

    command_json = {
        "argv": command,
        "shell_escaped_hint": " ".join(json.dumps(part) for part in command),
    }
    write_json(output_dir / "command.json", command_json)
    write_text(output_dir / "stdout.log", stdout)
    write_text(output_dir / "stderr.log", stderr)
    alert_postprocessing = postprocess_snort_alert_json(
        output_dir=output_dir,
        traffic_version=traffic_version,
        experiment_config_label=experiment_config_label,
        input_pcap_path=input_pcap_path,
        snort_config=snort_config,
    )

    metadata = {
        "schema_version": RUN_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "dry_run": dry_run,
        "exit_code": exit_code,
        "experiment_id": config["experiment"]["experiment_id"],
        "config_source": config.get("_config_path", ""),
        "traffic_version": traffic_version,
        "traffic_scope": "pre_common" if traffic_version == "pre" else "post_experiment_config",
        "experiment_config_label": experiment_config_label,
        "input_pcap": str(input_pcap_path),
        "output_dir": str(output_dir),
        "snort_binary": expand_config_path(snort_config["snort_binary"]),
        "snort_config_path": expand_config_path(snort_config["config_path"]),
        "plugin_path": expand_config_path(snort_config["plugin_path"]) if snort_config.get("plugin_path") else None,
        "daq_dir": expand_config_path(snort_config["daq_dir"]) if snort_config.get("daq_dir") else None,
        "enable_builtin_rules": snort_config["enable_builtin_rules"],
        "enable_ruleset": snort_config["enable_ruleset"],
        "ruleset_path": expand_config_path(snort_config["ruleset_path"]) if snort_config["enable_ruleset"] else "",
        "rules_policy_path": (
            expand_config_path(snort_config.get("rules_policy_path", ""))
            if snort_config["enable_ruleset"] and str(snort_config.get("rules_policy_path", "")).strip()
            else ""
        ),
        "alert_output_mode": "alert_json",
        "alert_output_source": "snort_lua_config",
        "alert_json_postprocessing": alert_postprocessing,
        "artifacts": {
            "command": str(output_dir / "command.json"),
            "stdout": str(output_dir / "stdout.log"),
            "stderr": str(output_dir / "stderr.log"),
            "metadata": str(output_dir / "execution_metadata.json"),
            "raw_alert_jsonl": alert_postprocessing["source"],
            "converted_alert_json": alert_postprocessing["converted"],
        },
    }
    write_json(output_dir / "execution_metadata.json", metadata)
    return metadata


# This function is the public Python entry point for Step 21.
# It loads and validates the config, resolves PRE/POST paths, and runs Snort once or twice depending on the requested traffic version.
def run_snort(
    *,
    config_path: str | Path,
    traffic_version: str,
    input_pcap: str | Path | None,
    output_dir: str | Path | None,
    experiment_root: str | Path | None,
    dry_run: bool,
) -> list[dict[str, Any]]:
    config = load_json_config(config_path)
    validate_config(config)

    experiment_config_label = experiment_config_label_from_config(config)
    runs: list[dict[str, Any]] = []
    selected_versions = ["pre", "post"] if traffic_version == "both" else [traffic_version]
    for selected_version in selected_versions:
        run_experiment_config_label = None if selected_version == "pre" else experiment_config_label
        resolved_input = (
            Path(input_pcap).expanduser()
            if input_pcap and len(selected_versions) == 1
            else default_input_pcap(config, selected_version, run_experiment_config_label, experiment_root)
        )
        resolved_output_dir = (
            Path(output_dir).expanduser()
            if output_dir and len(selected_versions) == 1
            else default_output_dir(config, selected_version, run_experiment_config_label, experiment_root)
        )
        runs.append(
            run_one_snort_execution(
                config=config,
                traffic_version=selected_version,
                experiment_config_label=run_experiment_config_label,
                input_pcap_path=resolved_input,
                output_dir=resolved_output_dir,
                dry_run=dry_run,
            )
        )
    return runs


# This function parses command-line arguments for Step 21.
# The experiment_config_label, ruleset, policy, and built-in rule settings are intentionally read from the config rather than from CLI flags.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Snort 3 over Step 21 PRE and POST PCAP artifacts.")
    add = parser.add_argument
    add("--config", required=True, help="Path to the experiment JSON config.")
    add("--traffic-version", choices=["pre", "post", "both"], default="both", help="Traffic side to run.")
    add("--input-pcap", help="Explicit PCAP path. Only valid for a single resolved run.")
    add("--output-dir", help="Explicit output directory. Only valid for a single resolved run.")
    add(
        "--experiment-root",
        help=(
            "Optional experiment root override. Useful when the VM artifact root differs from "
            "experiment.output_root in the config."
        ),
    )
    add("--dry-run", action="store_true", help="Write command and metadata without executing Snort.")
    return parser.parse_args()


# This function is the command-line entry point.
# It rejects input/output overrides for traffic-version both because one override cannot safely represent both PRE and POST runs.
def main() -> None:
    args = parse_cli_args()
    if (args.input_pcap or args.output_dir) and args.traffic_version == "both":
        raise ValueError("--input-pcap and --output-dir overrides are only valid for one resolved run.")

    runs = run_snort(
        config_path=args.config,
        traffic_version=args.traffic_version,
        input_pcap=args.input_pcap,
        output_dir=args.output_dir,
        experiment_root=args.experiment_root,
        dry_run=args.dry_run,
    )
    for run in runs:
        label = run["experiment_config_label"] or run["traffic_scope"]
        print(f"{run['traffic_version']} {label}: exit_code={run['exit_code']} output_dir={run['output_dir']}")


if __name__ == "__main__":
    main()
