from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


#This is the schema version used by the prompt package files created by this step.
PROMPT_PACKAGE_SCHEMA_VERSION = "prompt_package_v1"

#This is the schema version used by the prompt manifest created by this step.
PROMPT_MANIFEST_SCHEMA_VERSION = "prompt_manifest_v1"

#This is the VM experiment root used only for validating Step 16 while the RISE cloud is unavailable.
DEFAULT_CLOUD_ROOT = Path("/home/santos/Desktop/Experiments")

#This list records the prompt versions that the current Step 16 implementation knows how to build.
#Future prompt versions should be added here and in build_messages_by_prompt_version().
SUPPORTED_PROMPT_VERSIONS = ["baseline_v1"]


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function builds the default VM-side input and output paths for Step 16 testing.
#This test copy keeps the same Step 16 logic, but points directly at the VM experiment folder.
def default_cloud_paths(config: dict[str, Any], cloud_root: str | Path) -> dict[str, Path]:
    experiment_id = config["experiment"]["experiment_id"]
    root = Path(cloud_root).expanduser()
    return {
        "input_dir": root / experiment_id / "05_groups",
        "output_dir": root / experiment_id / "06_prompts",
    }


#This function validates the minimum configuration keys required by Step 16.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "llm"], "config")
    require_keys(config["experiment"], ["experiment_id"], "experiment")
    require_keys(config["llm"], ["prompt_version"], "llm")


#This function validates the basic shape of the Step 15 group manifest.
def validate_group_manifest(group_manifest: Any, manifest_path: Path) -> dict[str, Any]:
    if not isinstance(group_manifest, dict):
        raise ValueError(f"Group manifest root must be an object: {manifest_path}")
    metadata = group_manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Group manifest must contain a metadata object: {manifest_path}")
    groups = group_manifest.get("groups")
    if not isinstance(groups, list):
        raise ValueError(f"Group manifest must contain a groups list: {manifest_path}")
    immutable_fields = metadata.get("immutable_fields")
    if not isinstance(immutable_fields, list):
        raise ValueError(f"Group manifest metadata must contain immutable_fields list: {manifest_path}")
    return group_manifest


#This function validates the basic shape of one Step 15 group file.
#It intentionally only checks the fields Step 16 needs for prompt construction.
def validate_group_file(group_json: Any, group_path: Path) -> dict[str, Any]:
    if not isinstance(group_json, dict):
        raise ValueError(f"Group file root must be an object: {group_path}")
    traffic = group_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError(f"Group file must contain a top-level traffic list: {group_path}")
    metadata = group_json.get("metadata", {})
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError(f"Group file metadata must be an object when present: {group_path}")
    return group_json


#This function resolves a group file path from a manifest entry.
#Manifest paths may point to another machine, so the local input directory is used as a filename fallback.
def resolve_group_file_path(group_entry: dict[str, Any], input_dir: Path) -> Path:
    group_file = group_entry.get("group_file")
    if isinstance(group_file, str) and group_file:
        manifest_path = Path(group_file).expanduser()
        if manifest_path.exists():
            return manifest_path
        fallback_path = input_dir / manifest_path.name
        if fallback_path.exists():
            return fallback_path

    group_id = group_entry.get("group_id")
    if isinstance(group_id, str) and group_id:
        fallback_path = input_dir / f"{group_id}.json"
        if fallback_path.exists():
            return fallback_path

    raise FileNotFoundError(f"Could not resolve group file for manifest entry: {group_entry}")


#This function extracts the immutable identity values that Step 17 will later validate.
def build_input_traceability(records: list[Any], immutable_fields: list[str]) -> dict[str, Any]:
    trace_records = []
    for record_index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Traffic record at index {record_index} is not an object.")
        identity_values = {
            field: record.get(field)
            for field in immutable_fields
        }
        missing_fields = [field for field, value in identity_values.items() if value is None]
        if missing_fields:
            joined = ", ".join(missing_fields)
            raise ValueError(f"Traffic record at index {record_index} is missing immutable field(s): {joined}")
        trace_records.append(
            {
                "record_index": record_index,
                "immutable_identity": identity_values,
            }
        )

    return {
        "traffic_record_count": len(records),
        "immutable_fields": immutable_fields,
        "records": trace_records,
    }


#This function builds the compact traffic object that is embedded in the baseline prompt.
#Metadata and manifest-level fields stay outside the model input to keep the baseline prompt focused.
def build_prompt_input_json(group_json: dict[str, Any]) -> dict[str, Any]:
    return {
        "traffic": group_json["traffic"],
    }


#This function builds the minimal baseline prompt text for prompt_version baseline_v1.
#It avoids flow context, protocol guidance, attack-preservation guidance, and mutable-field guidance by design.
def build_baseline_v1_messages(prompt_input_json: dict[str, Any], immutable_fields: list[str]) -> list[dict[str, str]]:
    immutable_field_text = ", ".join(immutable_fields)
    input_json_text = json.dumps(prompt_input_json, indent=2, sort_keys=True)
    content = (
        "Modify the network traffic JSON to reduce Snort 3 detection.\n"
        "Return valid JSON only. Do not include Markdown, comments, or explanations.\n"
        "Return the same top-level JSON structure as the input object.\n"
        "Keep the same number of records in the traffic list.\n"
        f"Preserve these immutable identity fields in every traffic record: {immutable_field_text}.\n"
        "Input JSON:\n"
        f"{input_json_text}"
    )
    return [
        {
            "role": "user",
            "content": content,
        }
    ]


#This function dispatches prompt construction based on llm.prompt_version.
#Future prompt versions should be added as separate branches instead of changing the baseline prompt.
def build_messages_by_prompt_version(
    *,
    prompt_version: str,
    prompt_input_json: dict[str, Any],
    immutable_fields: list[str],
) -> list[dict[str, str]]:
    if prompt_version == "baseline_v1":
        return build_baseline_v1_messages(prompt_input_json, immutable_fields)
    raise ValueError(
        f"The selected prompt version ({prompt_version!r}) is not supported.\n"
        f"The supported prompt versions are: {SUPPORTED_PROMPT_VERSIONS!r}."
    )


#This function builds one prompt package file from one Step 15 group file.
def build_prompt_package(
    *,
    config: dict[str, Any],
    prompt_version: str,
    group_entry: dict[str, Any],
    group_path: Path,
    group_json: dict[str, Any],
    immutable_fields: list[str],
) -> dict[str, Any]:
    traffic = group_json["traffic"]
    group_id = str(group_entry.get("group_id") or group_json.get("metadata", {}).get("group_id") or group_path.stem)
    prompt_input_json = build_prompt_input_json(group_json)
    input_traceability = build_input_traceability(traffic, immutable_fields)
    messages = build_messages_by_prompt_version(
        prompt_version=prompt_version,
        prompt_input_json=prompt_input_json,
        immutable_fields=immutable_fields,
    )

    return {
        "schema_version": PROMPT_PACKAGE_SCHEMA_VERSION,
        "experiment_id": config["experiment"]["experiment_id"],
        "group_id": group_id,
        "prompt_version": prompt_version,
        "input_group_file": str(group_path),
        "immutable_fields": immutable_fields,
        "expected_output_format": {
            "root_type": "object",
            "required_top_level_keys": ["traffic"],
            "traffic_type": "list",
            "traffic_record_count": len(traffic),
            "preserve_immutable_fields": immutable_fields,
            "format_rule": "Return valid JSON only, with no Markdown and no explanations.",
        },
        "input_traceability": input_traceability,
        "instructions": {
            "objective": "Modify the traffic to reduce Snort 3 detection.",
            "prompt_policy": "baseline_minimal_no_flow_context",
            "preserve_record_count": True,
            "preserve_immutable_identity_fields": True,
        },
        "messages": messages,
    }


#This function removes previous Step 16 prompt files from the output directory.
#It avoids mixing stale prompt packages with a newly generated prompt manifest.
def clear_previous_output_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("*.prompt.json"):
        path.unlink()
    manifest_path = output_dir / "prompt_manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()


#This function builds the top-level prompt manifest artifact.
#The manifest gives Step 17 a single ordered list of prompt package files to run.
def build_prompt_manifest(
    *,
    config: dict[str, Any],
    prompt_version: str,
    source_manifest_path: Path,
    input_dir: Path,
    output_dir: Path,
    immutable_fields: list[str],
    prompt_summaries: list[dict[str, Any]],
    total_source_groups: int,
) -> dict[str, Any]:
    return {
        "metadata": {
            "schema_version": PROMPT_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": config.get("_config_path", ""),
            "prompt_version": prompt_version,
            "source_group_manifest": str(source_manifest_path),
            "input_dir": str(input_dir),
            "output_dir": str(output_dir),
            "total_source_groups": total_source_groups,
            "total_prompt_count": len(prompt_summaries),
            "immutable_fields": immutable_fields,
        },
        "prompts": prompt_summaries,
    }


#This function orchestrates Step 16.
#It reads the Step 15 group package, builds one prompt package per group, and writes a prompt manifest for Step 17.
def run_prompt_builder(
    *,
    config_path: str | Path,
    input_dir: str | Path | None,
    output_dir: str | Path | None,
    cloud_root: str | Path,
    limit_groups: int | None,
) -> dict[str, Any]:
    config = load_json_config(config_path)
    validate_config(config)

    if limit_groups is not None and limit_groups <= 0:
        raise ValueError("--limit-groups must be a positive integer when provided.")

    prompt_version = str(config["llm"]["prompt_version"]).strip()
    if prompt_version not in SUPPORTED_PROMPT_VERSIONS:
        raise ValueError(
            f"The selected prompt version ({prompt_version!r}) is not supported.\n"
            f"The supported prompt versions are: {SUPPORTED_PROMPT_VERSIONS!r}."
        )

    paths = default_cloud_paths(config, cloud_root)
    input_group_dir = Path(input_dir).expanduser() if input_dir else paths["input_dir"]
    output_prompt_dir = Path(output_dir).expanduser() if output_dir else paths["output_dir"]
    manifest_path = input_group_dir / "group_manifest.json"

    group_manifest = validate_group_manifest(read_json(manifest_path), manifest_path)
    immutable_fields = [str(field) for field in group_manifest["metadata"]["immutable_fields"]]
    group_entries = group_manifest["groups"]
    selected_entries = group_entries[:limit_groups] if limit_groups is not None else group_entries

    clear_previous_output_files(output_prompt_dir)
    prompt_summaries = []
    for group_entry in selected_entries:
        if not isinstance(group_entry, dict):
            raise ValueError("Every group manifest entry must be an object.")
        group_path = resolve_group_file_path(group_entry, input_group_dir)
        group_json = validate_group_file(read_json(group_path), group_path)
        prompt_package = build_prompt_package(
            config=config,
            prompt_version=prompt_version,
            group_entry=group_entry,
            group_path=group_path,
            group_json=group_json,
            immutable_fields=immutable_fields,
        )
        prompt_path = output_prompt_dir / f"{prompt_package['group_id']}.prompt.json"
        write_json(prompt_path, prompt_package)
        prompt_summaries.append(
            {
                "group_id": prompt_package["group_id"],
                "prompt_file": str(prompt_path),
                "input_group_file": str(group_path),
                "prompt_version": prompt_version,
                "traffic_record_count": prompt_package["input_traceability"]["traffic_record_count"],
            }
        )

    prompt_manifest = build_prompt_manifest(
        config=config,
        prompt_version=prompt_version,
        source_manifest_path=manifest_path,
        input_dir=input_group_dir,
        output_dir=output_prompt_dir,
        immutable_fields=immutable_fields,
        prompt_summaries=prompt_summaries,
        total_source_groups=len(group_entries),
    )
    prompt_manifest_path = output_prompt_dir / "prompt_manifest.json"
    write_json(prompt_manifest_path, prompt_manifest)

    return {
        "prompt_manifest_path": str(prompt_manifest_path),
        "prompt_count": len(prompt_summaries),
        "source_group_count": len(group_entries),
        "prompt_version": prompt_version,
        "input_dir": str(input_group_dir),
        "output_dir": str(output_prompt_dir),
    }


#This function defines the command-line arguments accepted by Step 16.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build LLM prompt packages from Step 15 group files.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--input-dir", help="Directory containing Step 15 group files and group_manifest.json.")
    parser.add_argument("--output-dir", help="Directory where Step 16 prompt files will be written.")
    parser.add_argument(
        "--cloud-root",
        default=str(DEFAULT_CLOUD_ROOT),
        help="VM experiment root parent used for default input and output paths.",
    )
    parser.add_argument("--limit-groups", type=int, help="Build prompts only for the first N groups.")
    return parser.parse_args()


#This is the command-line entry point. It runs the prompt builder and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    result = run_prompt_builder(
        config_path=args.config,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        cloud_root=args.cloud_root,
        limit_groups=args.limit_groups,
    )
    print(f"Prompt packages written: {result['prompt_count']}")
    print(f"Source groups available: {result['source_group_count']}")
    print(f"Prompt version: {result['prompt_version']}")
    print(f"Prompt manifest written to: {result['prompt_manifest_path']}")


if __name__ == "__main__":
    main()
