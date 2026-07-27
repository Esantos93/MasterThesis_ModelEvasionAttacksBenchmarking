from __future__ import annotations

import argparse
from copy import deepcopy
import csv
import hashlib
import importlib
import io
import json
from pathlib import Path
import shutil
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
CODE_ROOT = SCRIPT_DIR.parents[1]


def locate_pipeline_layout() -> tuple[Path, Path, Path]:
    base_candidates = [
        CODE_ROOT / "10_Pipeline",
        SCRIPT_DIR,
        SCRIPT_DIR.parent,
        Path("/tf/thesis_Santos/04_Steps"),
    ]
    step16_names = ("step_16_prompt_builder", "Step16")
    step17_names = ("step_17_llm_batch_runner", "Step17")
    for base in base_candidates:
        if not (base / "common" / "token_budget.py").is_file():
            continue
        step16_dir = next(
            (
                base / name
                for name in step16_names
                if (base / name / "build_prompts.py").is_file()
            ),
            None,
        )
        step17_dir = next(
            (
                base / name
                for name in step17_names
                if (base / name / "run_llm_batch.py").is_file()
            ),
            None,
        )
        if step16_dir is not None and step17_dir is not None:
            return base.resolve(), step16_dir.resolve(), step17_dir.resolve()
    rendered = ", ".join(str(candidate) for candidate in base_candidates)
    raise RuntimeError(
        "Could not locate the shared pipeline modules required by the "
        f"diagnostic builder. Checked: {rendered}"
    )


PIPELINE_ROOT, STEP16_DIR, STEP17_DIR = locate_pipeline_layout()
for module_dir in (
    PIPELINE_ROOT,
    STEP16_DIR,
    STEP17_DIR,
):
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))

from common import prompt_projection  # noqa: E402
from common.config import load_json_config  # noqa: E402
from common.modification_strategy import resolve_modification_strategy  # noqa: E402
from common.token_budget import (  # noqa: E402
    TOKEN_BUDGET_POLICY,
    build_compact_patch_token_plan,
    compute_payload_replacement_limit_bytes,
)
if STEP16_DIR.name == "step_16_prompt_builder":
    step16 = importlib.import_module(  # noqa: E402
        "step_16_prompt_builder.build_prompts"
    )
else:
    step16 = importlib.import_module("build_prompts")  # noqa: E402

if STEP17_DIR.name == "step_17_llm_batch_runner":
    step17 = importlib.import_module(  # noqa: E402
        "step_17_llm_batch_runner.run_llm_batch"
    )
else:
    step17 = importlib.import_module("run_llm_batch")  # noqa: E402


DIAGNOSTIC_SCHEMA_VERSION = "payload_limit_sensitivity_smoke_v1"
EXPECTED_FAILURE_REASON = "JSONDecodeError"
EXPECTED_FAILURE_COUNT = 31
PROMPT_MARKER = "Compact prompt unit:\n"
DIAGNOSTIC_EXPERIMENT_ID = (
    "20_diag_payload_limit_3x_baseline_flow_context_gemma-4-26B-A4B-it"
)
DIAGNOSTIC_CONFIG_FILENAME = (
    "config_exp20_payload_limit_sensitivity_3x_gemma-4-26B-A4B-it.json"
)
EXPERIMENTAL_PAYLOAD_POLICY = {
    "policy": "tiered_relative_to_original_v1",
    "tiers": [{"max_original_bytes": None, "factor": 3.0}],
    "absolute_max_replacement_bytes": None,
}
LIMIT_FIELDS = {
    "max_replacement_bytes",
    "max_replacement_hex_chars",
    "replacement_size_policy",
    "replacement_size_limit",
}


DEFAULT_STEP17_ROOT = Path(
    r"C:\TFM_Data\resultados\inferencia"
    r"\step17_llm_outputs_run_20260727_040117_baseline_hybrid_flow_context_aware_gemma26_smoke"
)
DEFAULT_STEP16_ROOT = Path(
    r"C:\TFM_Data\resultados\inferencia"
    r"\step16_prompts_run_20260727_034703_baseline_hybrid_flow_context_aware_gemma26_full"
)
DEFAULT_SAMPLE_MANIFEST = Path(
    r"C:\TFM_Data\resultados\inferencia\payload_budget_sample_512.json"
)
DEFAULT_SAMPLE_REPORT = Path(
    r"C:\TFM_Data\resultados\inferencia\payload_budget_sample_512.sample_report.json"
)
OFFICIAL_CONFIG_FILENAME = (
    "config_LLM_payload_involved_flow_context_aware_gemma-4-26B-A4B-it.json"
)
_official_config_candidates = [
    PIPELINE_ROOT / "setups" / OFFICIAL_CONFIG_FILENAME,
    PIPELINE_ROOT
    / "step_11_experiment_setup"
    / "07_ExpPayloadInvolved_FlowContextAware"
    / OFFICIAL_CONFIG_FILENAME,
    SCRIPT_DIR / "setups" / OFFICIAL_CONFIG_FILENAME,
]
DEFAULT_OFFICIAL_CONFIG = next(
    (
        candidate
        for candidate in _official_config_candidates
        if candidate.is_file()
    ),
    _official_config_candidates[0],
)
DEFAULT_COMPACT_UNITS_DIR = Path(
    r"C:\TFM_Data\resultados"
    r"\20_exp_payload_baseline_flow_context_gemma-4-26B-A4B-it"
    r"\05_groups\flow_context_aware"
)


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def write_json(path: str | Path, value: Any) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as output_file:
        json.dump(value, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def write_text(path: str | Path, value: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as output_file:
        output_file.write(value)
        if not value.endswith("\n"):
            output_file.write("\n")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_single_directory(
    root: str | Path,
    *,
    required_children: tuple[str, ...],
    description: str,
) -> Path:
    candidate_root = Path(root).expanduser().resolve()
    candidates: list[Path] = []
    if candidate_root.is_dir() and all(
        (candidate_root / child).exists() for child in required_children
    ):
        candidates.append(candidate_root)
    if candidate_root.is_dir():
        first_child = required_children[0]
        for match in candidate_root.rglob(first_child):
            parent = match.parent
            if parent == candidate_root:
                continue
            if all((parent / child).exists() for child in required_children):
                candidates.append(parent)
    unique = sorted(set(candidates))
    if len(unique) != 1:
        rendered = ", ".join(str(path) for path in unique) or "none"
        raise ValueError(
            f"Expected exactly one {description} under {candidate_root}; found "
            f"{len(unique)}: {rendered}"
        )
    return unique[0]


def resolve_step17_run_root(root: str | Path) -> Path:
    return resolve_single_directory(
        root,
        required_children=("metadata", "raw", "failures"),
        description="Step 17 model run directory",
    )


def resolve_step16_prompt_root(root: str | Path) -> Path:
    candidate_root = Path(root).expanduser().resolve()
    manifests = []
    direct = candidate_root / "prompt_units_manifest_v2.json"
    if direct.is_file():
        manifests.append(direct)
    if candidate_root.is_dir():
        manifests.extend(
            path
            for path in candidate_root.rglob("prompt_units_manifest_v2.json")
            if path != direct
        )
    unique = sorted(set(manifests))
    if len(unique) != 1:
        rendered = ", ".join(str(path) for path in unique) or "none"
        raise ValueError(
            f"Expected exactly one Step 16 prompt manifest under {candidate_root}; "
            f"found {len(unique)}: {rendered}"
        )
    return unique[0].parent


def select_jsondecode_metadata(
    step17_run_root: str | Path,
    *,
    expected_count: int = EXPECTED_FAILURE_COUNT,
) -> list[tuple[Path, dict[str, Any]]]:
    metadata_dir = Path(step17_run_root) / "metadata"
    selected: list[tuple[Path, dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for metadata_path in sorted(metadata_dir.glob("*.metadata.json")):
        metadata = read_json(metadata_path)
        if metadata.get("failure_reason") != EXPECTED_FAILURE_REASON:
            continue
        prompt_unit_id = metadata.get("prompt_unit_id")
        if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
            raise ValueError(
                f"Selected metadata lacks prompt_unit_id: {metadata_path}"
            )
        if prompt_unit_id in seen_ids:
            raise ValueError(
                f"Duplicate JSONDecodeError prompt_unit_id={prompt_unit_id}"
            )
        seen_ids.add(prompt_unit_id)
        selected.append((metadata_path, metadata))
    if len(selected) != expected_count:
        raise AssertionError(
            f"Expected exactly {expected_count} {EXPECTED_FAILURE_REASON} units; "
            f"found {len(selected)}."
        )
    return selected


def index_sample_manifest(
    sample_manifest_path: str | Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    sample_manifest = read_json(sample_manifest_path)
    prompt_units = sample_manifest.get("prompt_units")
    if not isinstance(prompt_units, list):
        raise ValueError("Sample manifest must contain a prompt_units list.")
    index: dict[str, dict[str, Any]] = {}
    for entry in prompt_units:
        if not isinstance(entry, dict):
            raise ValueError("Every sample manifest entry must be an object.")
        prompt_unit_id = entry.get("prompt_unit_id")
        if not isinstance(prompt_unit_id, str) or not prompt_unit_id:
            raise ValueError("Sample manifest entry lacks prompt_unit_id.")
        if prompt_unit_id in index:
            raise ValueError(f"Duplicate sample prompt_unit_id={prompt_unit_id}")
        index[prompt_unit_id] = entry
    return sample_manifest, index


def index_sample_panels(sample_report_path: str | Path) -> dict[str, str]:
    sample_report = read_json(sample_report_path)
    panels = sample_report.get("panels")
    if not isinstance(panels, dict):
        raise ValueError("Sample sidecar must contain a panels object.")
    panel_by_prompt: dict[str, str] = {}
    for panel_name, panel in panels.items():
        if not isinstance(panel, dict):
            continue
        prompt_unit_ids = panel.get("prompt_unit_ids")
        if not isinstance(prompt_unit_ids, list):
            raise ValueError(f"Panel {panel_name!r} lacks prompt_unit_ids.")
        for prompt_unit_id in prompt_unit_ids:
            prompt_unit_id_text = str(prompt_unit_id)
            if prompt_unit_id_text in panel_by_prompt:
                raise ValueError(
                    f"Prompt {prompt_unit_id_text} occurs in multiple panels."
                )
            panel_by_prompt[prompt_unit_id_text] = str(panel_name)
    return panel_by_prompt


def parse_model_visible_input(
    prompt_package: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    messages = prompt_package.get("messages")
    if (
        not isinstance(messages, list)
        or len(messages) != 1
        or not isinstance(messages[0], dict)
        or not isinstance(messages[0].get("content"), str)
    ):
        raise ValueError(
            f"Expected one textual user message for {prompt_package.get('prompt_unit_id')}"
        )
    content = messages[0]["content"]
    fixed_prompt_text, marker, json_text = content.partition(PROMPT_MARKER)
    if marker != PROMPT_MARKER or not json_text:
        raise ValueError(
            f"Prompt marker not found for {prompt_package.get('prompt_unit_id')}"
        )
    prompt_input = json.loads(json_text)
    if not isinstance(prompt_input, dict):
        raise ValueError("Model-visible compact prompt unit must be an object.")
    return fixed_prompt_text + marker, prompt_input


def reconstruct_source_unit_from_prompt(
    prompt_package: dict[str, Any],
    prompt_input: dict[str, Any],
    *,
    region_container_name: str,
) -> dict[str, Any]:
    canonical_regions = prompt_input.get(region_container_name)
    if not isinstance(canonical_regions, list) or not canonical_regions:
        raise ValueError(
            f"Selected unit {prompt_package.get('prompt_unit_id')} lacks payload regions."
        )
    target_presence = prompt_package.get("editable_target_presence")
    if target_presence != {
        "editable_headers_present": False,
        "editable_payload_present": True,
    }:
        raise ValueError(
            "The paired sensitivity builder currently requires the 31 selected "
            "JSONDecodeError units to be payload-only."
        )
    prompt_unit_id = str(prompt_package["prompt_unit_id"])
    canonical_payload_regions = deepcopy(canonical_regions)
    for canonical_region in canonical_payload_regions:
        if not isinstance(canonical_region, dict):
            continue
        for editable_region in canonical_region.get("editable_regions", []):
            if isinstance(editable_region, dict):
                # The model-visible projection includes only editable targets
                # and therefore omits the internal Step 15 boolean.
                editable_region["editable"] = True
    source_unit = {
        key: deepcopy(value)
        for key, value in prompt_input.items()
        if key != region_container_name
    }
    source_unit.update(
        {
            "schema_version": step16.SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION,
            "experiment_id": prompt_package["experiment_id"],
            "parent_group_id": prompt_package["parent_group_id"],
            "modification_unit_id": prompt_unit_id,
            "prompt_unit_id": prompt_unit_id,
            "strategy": prompt_package["modification_strategy"],
            "modification_strategy": prompt_package["modification_strategy"],
            "capabilities": deepcopy(prompt_package["capabilities"]),
            "editable_target_presence": deepcopy(target_presence),
            "canonical_payload_regions": canonical_payload_regions,
            "physical_packets": [],
            "source_packet_json": prompt_package.get("source_packet_json"),
            "source_packet_json_schema_version": prompt_package.get(
                "source_packet_json_schema_version"
            ),
            "payload_strategy_version": prompt_package.get(
                "payload_strategy_version"
            ),
        }
    )
    source_unit.pop(region_container_name, None)
    return source_unit


def rebuild_prompt_content(
    config: dict[str, Any],
    source_unit: dict[str, Any],
) -> str:
    structure = prompt_projection.load_prompt_input_json_data_structure_from_config(
        config
    )
    _, instruction_lines = (
        prompt_projection.load_prompt_instructions_profile_from_config(config)
    )
    return prompt_projection.build_compact_patch_prompt_parts(
        prompt_unit=source_unit,
        prompt_input_structure=structure,
        instruction_lines=instruction_lines,
    )["content"]


def resolve_exact_source_unit(
    *,
    original_prompt: dict[str, Any],
    original_config: dict[str, Any],
    compact_units_dir: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt_unit_id = str(original_prompt["prompt_unit_id"])
    original_content = str(original_prompt["messages"][0]["content"])
    local_candidate_path = (
        compact_units_dir / f"{prompt_unit_id}.json"
        if compact_units_dir is not None
        else None
    )
    candidate_status = "not_configured"
    if local_candidate_path is not None:
        if local_candidate_path.is_file():
            candidate = read_json(local_candidate_path)
            try:
                candidate_content = rebuild_prompt_content(
                    original_config, candidate
                )
            except Exception as error:
                candidate_status = f"unusable:{type(error).__name__}"
            else:
                if candidate_content == original_content:
                    return deepcopy(candidate), {
                        "source_resolution": "exact_local_compact_modification_unit",
                        "local_candidate": str(local_candidate_path),
                        "local_candidate_status": "exact_round_trip",
                    }
                candidate_status = "present_but_prompt_round_trip_mismatch"
        else:
            candidate_status = "missing"

    _, visible_input = parse_model_visible_input(original_prompt)
    structure = prompt_projection.load_prompt_input_json_data_structure_from_config(
        original_config
    )
    region_container_name = str(
        structure.get("region_container_name", "canonical_regions")
    )
    reconstructed = reconstruct_source_unit_from_prompt(
        original_prompt,
        visible_input,
        region_container_name=region_container_name,
    )
    reconstructed_content = rebuild_prompt_content(
        original_config, reconstructed
    )
    if reconstructed_content != original_content:
        raise AssertionError(
            f"Prompt-visible reconstruction does not round-trip exactly: "
            f"{prompt_unit_id}"
        )
    return reconstructed, {
        "source_resolution": "prompt_visible_structured_round_trip",
        "local_candidate": (
            str(local_candidate_path) if local_candidate_path is not None else None
        ),
        "local_candidate_status": candidate_status,
    }


def make_experimental_config(
    official_config: dict[str, Any],
) -> dict[str, Any]:
    config = deepcopy(official_config)
    config.pop("_config_path", None)
    config["experiment"]["experiment_id"] = DIAGNOSTIC_EXPERIMENT_ID
    config["experiment"]["description"] = (
        "Diagnostic paired payload replacement-limit sensitivity smoke at 3.0x "
        "for the 31 Experiment 20 Gemma JSONDecodeError Prompt Units."
    )
    config["experiment"]["output_root"] = (
        "/tf/thesis_Santos/02_OutputFiles_Diagnostics"
    )
    llm = config["llm"]
    llm["prompt_target_context"] = 12288
    llm["runtime_max_model_len"] = 12288
    token_budget = llm["token_budget"]
    token_budget["chars_per_token_estimate"] = 1.5
    token_budget["output_token_estimation_safety_factor"] = 2.0
    token_budget["payload_replacement_size_policy"] = deepcopy(
        EXPERIMENTAL_PAYLOAD_POLICY
    )
    config["pipeline"]["experiment_config_label"] = (
        "diag_payload_limit_sensitivity_3x_flow_context_aware_gemma-4-26B-A4B-it"
    )
    config["pipeline"]["experiment_config_label_options"] = [
        config["pipeline"]["experiment_config_label"]
    ]
    config["diagnostic"] = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "paired_control_experiment_id": official_config["experiment"][
            "experiment_id"
        ],
        "selected_failure_reason": EXPECTED_FAILURE_REASON,
        "expected_prompt_count": EXPECTED_FAILURE_COUNT,
        "payload_growth_factor": 3.0,
        "absolute_max_replacement_bytes": None,
        "official_pipeline_config": False,
    }
    return config


def apply_three_x_payload_limits(
    source_unit: dict[str, Any],
    *,
    policy: dict[str, Any] = EXPERIMENTAL_PAYLOAD_POLICY,
) -> list[dict[str, Any]]:
    observed_limits: list[dict[str, Any]] = []
    canonical_regions = source_unit.get("canonical_payload_regions")
    if not isinstance(canonical_regions, list):
        raise ValueError("Source unit lacks canonical_payload_regions.")
    for canonical_region in canonical_regions:
        if not isinstance(canonical_region, dict):
            continue
        editable_regions = canonical_region.get("editable_regions")
        if not isinstance(editable_regions, list):
            continue
        for region in editable_regions:
            if not isinstance(region, dict) or not region.get("editable", True):
                continue
            original_size = region.get("length_bytes")
            if (
                isinstance(original_size, bool)
                or not isinstance(original_size, int)
                or original_size < 0
            ):
                raise ValueError(
                    f"Invalid length_bytes for region {region.get('region_id')}"
                )
            limit = compute_payload_replacement_limit_bytes(
                original_size_bytes=original_size,
                policy=policy,
            )
            expected_bytes = original_size * 3
            if limit["effective_limit_bytes"] != expected_bytes:
                raise AssertionError(
                    f"3.0x limit was capped for {region.get('region_id')}: "
                    f"expected={expected_bytes}, actual={limit['effective_limit_bytes']}"
                )
            if limit["absolute_max_replacement_bytes"] is not None:
                raise AssertionError("Experimental absolute cap must remain null.")
            region["max_replacement_bytes"] = int(limit["effective_limit_bytes"])
            region["max_replacement_hex_chars"] = int(
                limit["effective_limit_hex_chars"]
            )
            region["replacement_size_policy"] = str(limit["policy"])
            region["replacement_size_limit"] = deepcopy(limit)
            observed_limits.append(
                {
                    "canonical_region_id": canonical_region.get(
                        "canonical_region_id"
                    ),
                    "region_id": region.get("region_id"),
                    **deepcopy(limit),
                }
            )
    if not observed_limits:
        raise ValueError(
            f"No editable payload region found in {source_unit.get('modification_unit_id')}"
        )
    source_unit["payload_authorization"] = {
        "ownership_policy": (
            canonical_regions[0].get("ownership", {}).get("policy")
            if isinstance(canonical_regions[0], dict)
            else None
        ),
        "replacement_size_policy": deepcopy(policy),
        "segmentation_policy": (
            canonical_regions[0].get("semantic_segmentation", {}).get("policy")
            if isinstance(canonical_regions[0], dict)
            else None
        ),
    }
    return observed_limits


def normalize_visible_input_for_pairing(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize_visible_input_for_pairing(item) for item in value]
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            if key in LIMIT_FIELDS or key == "experiment_id":
                continue
            normalized[key] = normalize_visible_input_for_pairing(item)
        return normalized
    return value


def physical_packet_ids(prompt_input: dict[str, Any]) -> list[str]:
    packet_ids: set[str] = set()
    for canonical_region in prompt_input.get("canonical_regions", []):
        if not isinstance(canonical_region, dict):
            continue
        for alias in canonical_region.get("physical_aliases", []):
            if isinstance(alias, dict) and alias.get("packet_id") is not None:
                packet_ids.add(str(alias["packet_id"]))
    return sorted(packet_ids)


def payload_region_identity(prompt_input: dict[str, Any]) -> list[dict[str, Any]]:
    identities = []
    for canonical_region in prompt_input.get("canonical_regions", []):
        if not isinstance(canonical_region, dict):
            continue
        for region in canonical_region.get("editable_regions", []):
            if not isinstance(region, dict):
                continue
            identities.append(
                {
                    key: deepcopy(region.get(key))
                    for key in (
                        "canonical_region_id",
                        "region_id",
                        "region_type",
                        "coordinate_space",
                        "start_offset_bytes",
                        "end_offset_bytes",
                        "length_bytes",
                        "allowed_operations",
                        "value",
                        "authorized_start_offset_bytes",
                        "authorized_end_offset_bytes",
                        "authorized_length_bytes",
                    )
                }
            )
    return identities


def summarize_original_limits(prompt_input: dict[str, Any]) -> list[dict[str, Any]]:
    limits = []
    for canonical_region in prompt_input.get("canonical_regions", []):
        if not isinstance(canonical_region, dict):
            continue
        for region in canonical_region.get("editable_regions", []):
            if not isinstance(region, dict):
                continue
            limits.append(
                {
                    "canonical_region_id": region.get("canonical_region_id"),
                    "region_id": region.get("region_id"),
                    "length_bytes": region.get("length_bytes"),
                    "max_replacement_bytes": region.get(
                        "max_replacement_bytes"
                    ),
                    "max_replacement_hex_chars": region.get(
                        "max_replacement_hex_chars"
                    ),
                    "replacement_size_policy": region.get(
                        "replacement_size_policy"
                    ),
                    "replacement_size_limit": deepcopy(
                        region.get("replacement_size_limit")
                    ),
                }
            )
    return limits


def build_prompt_summary(prompt_package: dict[str, Any]) -> dict[str, Any]:
    return {
        "parent_group_id": prompt_package["parent_group_id"],
        "prompt_unit_id": prompt_package["prompt_unit_id"],
        "group_id": prompt_package["group_id"],
        "prompt_file": f"{prompt_package['prompt_unit_id']}.prompt.json",
        "source_modification_unit_id": prompt_package[
            "source_modification_unit_id"
        ],
        "source_modification_unit_file": prompt_package[
            "source_modification_unit_file"
        ],
        "prompt_version": prompt_package["prompt_version"],
        "prompt_contract": prompt_package["prompt_contract"],
        "modification_strategy": prompt_package["modification_strategy"],
        "capabilities": prompt_package["capabilities"],
        "editable_target_presence": prompt_package[
            "editable_target_presence"
        ],
        "source_modification_unit_schema_version": prompt_package[
            "source_modification_unit_schema_version"
        ],
        "prompt_input_json_data_profile": prompt_package["prompt_template"][
            "prompt_input_json_data_profile"
        ],
        "prompt_instructions_profile": prompt_package["prompt_template"][
            "prompt_instructions_profile"
        ],
        "editable_region_count": len(
            prompt_package["input_traceability"]["editable_regions"]
        ),
        "estimated_input_tokens": prompt_package["estimated_input_tokens"],
        "token_plan": prompt_package["token_plan"],
        "token_estimation": prompt_package["token_estimation"],
    }


def copy_control_file(
    *,
    source: Path,
    destination: Path,
) -> dict[str, Any]:
    if not source.is_file():
        raise FileNotFoundError(f"Required control artifact not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    source_hash = sha256_file(source)
    copied_hash = sha256_file(destination)
    if source_hash != copied_hash:
        raise AssertionError(f"Control copy hash mismatch: {source}")
    return {
        "source_path": str(source),
        "copied_path": destination.as_posix(),
        "sha256": source_hash,
        "size_bytes": source.stat().st_size,
    }


def render_summary_csv(unit_reports: list[dict[str, Any]]) -> str:
    columns = [
        "prompt_unit_id",
        "parent_group_id",
        "sample_panel",
        "source_resolution",
        "local_candidate_status",
        "status",
        "payload_region_count",
        "original_min_max_replacement_bytes",
        "original_max_max_replacement_bytes",
        "variant_min_max_replacement_bytes",
        "variant_max_max_replacement_bytes",
        "original_planned_output_tokens",
        "variant_planned_output_tokens",
        "variant_max_tokens",
        "variant_estimated_input_tokens",
        "variant_total_planned_tokens",
        "overflow_tokens",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for unit in unit_reports:
        original_limits = unit["original"]["payload_limits"]
        variant_limits = unit["variant"]["payload_limits"]
        writer.writerow(
            {
                "prompt_unit_id": unit["prompt_unit_id"],
                "parent_group_id": unit["parent_group_id"],
                "sample_panel": unit["sample_panel"],
                "source_resolution": unit["source_resolution"],
                "local_candidate_status": unit["local_candidate_status"],
                "status": unit["status"],
                "payload_region_count": len(variant_limits),
                "original_min_max_replacement_bytes": min(
                    item["max_replacement_bytes"] for item in original_limits
                ),
                "original_max_max_replacement_bytes": max(
                    item["max_replacement_bytes"] for item in original_limits
                ),
                "variant_min_max_replacement_bytes": min(
                    item["effective_limit_bytes"] for item in variant_limits
                ),
                "variant_max_max_replacement_bytes": max(
                    item["effective_limit_bytes"] for item in variant_limits
                ),
                "original_planned_output_tokens": unit["original"][
                    "token_plan"
                ]["planned_output_tokens"],
                "variant_planned_output_tokens": unit["variant"][
                    "token_plan"
                ]["planned_output_tokens"],
                "variant_max_tokens": unit["variant"]["token_plan"][
                    "max_tokens"
                ],
                "variant_estimated_input_tokens": unit["variant"][
                    "token_plan"
                ]["estimated_input_tokens"],
                "variant_total_planned_tokens": unit["variant"]["token_plan"][
                    "total_planned_tokens"
                ],
                "overflow_tokens": unit["variant"]["token_plan"][
                    "overflow_tokens"
                ],
            }
        )
    return output.getvalue()


def render_mapping_csv(unit_reports: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    columns = [
        "prompt_unit_id",
        "control_prompt",
        "variant_prompt",
        "control_metadata",
        "control_raw",
        "control_failure",
        "status",
    ]
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for unit in unit_reports:
        writer.writerow(
            {
                "prompt_unit_id": unit["prompt_unit_id"],
                "control_prompt": unit["control"]["prompt"]["copied_path"],
                "variant_prompt": unit["variant"].get("prompt_file"),
                "control_metadata": unit["control"]["metadata"][
                    "copied_path"
                ],
                "control_raw": unit["control"]["raw"]["copied_path"],
                "control_failure": unit["control"]["failure"][
                    "copied_path"
                ],
                "status": unit["status"],
            }
        )
    return output.getvalue()


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Experiment 20 Payload-Limit Sensitivity Smoke",
        "",
        "This package is diagnostic and is not an official Experiment 20 run.",
        "",
        "## Summary",
        "",
        f"- Selected failure reason: `{EXPECTED_FAILURE_REASON}`",
        f"- Paired control units: {summary['selected_prompt_count']}",
        f"- Runnable under 12,288: {summary['runnable_prompt_count']}",
        f"- Not runnable under 12,288: {summary['not_runnable_prompt_count']}",
        "- Payload replacement policy: exactly 3.0x with no absolute cap",
        "- Token planning: official compact_patch_token_budget_v2 at 1.5/2.0",
        f"- New max replacement bytes: {summary['max_replacement_bytes_range'][0]}"
        f"-{summary['max_replacement_bytes_range'][1]}",
        f"- Planned output/max tokens: {summary['planned_output_tokens_range'][0]}"
        f"-{summary['planned_output_tokens_range'][1]}",
        f"- Maximum total planned tokens: {summary['maximum_total_planned_tokens']}",
        "",
        "## Units",
        "",
        "| Prompt Unit | Panel | Status | New max bytes | Planned output | Total planned |",
        "|---|---|---|---:|---:|---:|",
    ]
    for unit in report["units"]:
        limits = unit["variant"]["payload_limits"]
        token_plan = unit["variant"]["token_plan"]
        limit_text = (
            str(limits[0]["effective_limit_bytes"])
            if len(limits) == 1
            else f"{min(item['effective_limit_bytes'] for item in limits)}-"
            f"{max(item['effective_limit_bytes'] for item in limits)}"
        )
        lines.append(
            f"| `{unit['prompt_unit_id']}` | {unit['sample_panel']} | "
            f"`{unit['status']}` | {limit_text} | "
            f"{token_plan['planned_output_tokens']} | "
            f"{token_plan['total_planned_tokens']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation Boundary",
            "",
            "This builder changes only the declared payload replacement limit and "
            "the mechanically derived prompt/token plan. It does not run Step 17 "
            "and does not modify Steps 15-20 or any official config/artifact.",
        ]
    )
    return "\n".join(lines)


def stable_source_manifest(
    *,
    config: dict[str, Any],
    source_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    capabilities = resolve_modification_strategy(config)
    return {
        "metadata": {
            "schema_version": step16.SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION,
            "compact_view_schema_version": step16.SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION,
            "experiment_id": config["experiment"]["experiment_id"],
            "strategy": capabilities.strategy,
            "modification_strategy": capabilities.strategy,
            "capabilities": capabilities.as_metadata(),
            "token_budget_policy": TOKEN_BUDGET_POLICY,
            "diagnostic_schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        },
        "compact_modification_units": source_entries,
    }


def stable_prompt_manifest(
    *,
    config: dict[str, Any],
    prompt_summaries: list[dict[str, Any]],
    total_source_units: int,
) -> dict[str, Any]:
    capabilities = resolve_modification_strategy(config)
    planned_values = [
        int(entry["token_plan"]["planned_output_tokens"])
        for entry in prompt_summaries
    ]
    counts: dict[str, int] = {}
    for value in planned_values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return {
        "metadata": {
            "schema_version": step16.PROMPT_UNITS_MANIFEST_SCHEMA_VERSION,
            "generated_at_utc": "deterministic_diagnostic_build",
            "experiment_id": config["experiment"]["experiment_id"],
            "config_source": DIAGNOSTIC_CONFIG_FILENAME,
            "prompt_version": config["llm"]["prompt_version"],
            "modification_strategy": capabilities.strategy,
            "capabilities": capabilities.as_metadata(),
            "prompt_input_json_data_profile": config["llm"][
                "prompt_input_json_data_profile"
            ],
            "prompt_instructions_profile": config["llm"][
                "prompt_instructions_profile"
            ],
            "source_compact_modification_units_manifest": (
                "source_units/compact_modification_units_manifest_v3.json"
            ),
            "source_compact_modification_units_manifest_schema_version": (
                step16.SOURCE_MODIFICATION_UNITS_MANIFEST_SCHEMA_VERSION
            ),
            "source_compact_view_schema_version": (
                step16.SOURCE_MODIFICATION_UNIT_SCHEMA_VERSION
            ),
            "input_dir": "source_units",
            "output_dir": "prompts",
            "total_source_modification_units": total_source_units,
            "total_prompt_count": len(prompt_summaries),
            "token_budget_policy": TOKEN_BUDGET_POLICY,
            "max_tokens_source": "token_plan.planned_output_tokens",
            "planned_output_tokens_distribution": {
                "count": len(planned_values),
                "min": min(planned_values) if planned_values else None,
                "max": max(planned_values) if planned_values else None,
                "value_counts": dict(
                    sorted(counts.items(), key=lambda item: int(item[0]))
                ),
            },
            "diagnostic_schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        },
        "prompt_units": prompt_summaries,
    }


def validate_step17_consumability(
    *,
    config: dict[str, Any],
    manifest_path: Path,
    prompt_dir: Path,
) -> None:
    capabilities = resolve_modification_strategy(config)
    manifest = step17.validate_prompt_manifest(
        read_json(manifest_path),
        manifest_path,
        expected_capabilities=capabilities,
    )
    for entry in manifest["prompt_units"]:
        prompt_path = step17.resolve_prompt_file_path(entry, prompt_dir)
        prompt_package = step17.validate_prompt_package(
            read_json(prompt_path), prompt_path
        )
        if (
            prompt_package["token_plan"]["max_tokens"]
            != prompt_package["token_plan"]["planned_output_tokens"]
        ):
            raise AssertionError(
                f"Step 17 max_tokens mismatch in {prompt_path}"
            )


def build_diagnostic_package(
    *,
    step17_root: str | Path,
    step16_root: str | Path,
    sample_manifest_path: str | Path,
    sample_report_path: str | Path,
    official_config_path: str | Path,
    output_dir: str | Path,
    compact_units_dir: str | Path | None = None,
    expected_failure_count: int = EXPECTED_FAILURE_COUNT,
) -> dict[str, Any]:
    output_root = Path(output_dir).expanduser().resolve()
    if output_root.exists() and any(output_root.iterdir()):
        raise FileExistsError(
            f"Diagnostic output directory must not already contain files: {output_root}"
        )
    output_root.mkdir(parents=True, exist_ok=True)

    resolved_step17_root = resolve_step17_run_root(step17_root)
    resolved_step16_root = resolve_step16_prompt_root(step16_root)
    sample_manifest_path = Path(sample_manifest_path).expanduser().resolve()
    sample_report_path = Path(sample_report_path).expanduser().resolve()
    official_config_path = Path(official_config_path).expanduser().resolve()
    resolved_compact_units_dir = (
        Path(compact_units_dir).expanduser().resolve()
        if compact_units_dir is not None and Path(compact_units_dir).exists()
        else None
    )

    official_config = load_json_config(official_config_path)
    experimental_config = make_experimental_config(official_config)
    capabilities = resolve_modification_strategy(experimental_config)
    structure = prompt_projection.load_prompt_input_json_data_structure_from_config(
        experimental_config
    )
    _, instruction_lines = (
        prompt_projection.load_prompt_instructions_profile_from_config(
            experimental_config
        )
    )
    token_budget_config = experimental_config["llm"]["token_budget"]

    selected = select_jsondecode_metadata(
        resolved_step17_root, expected_count=expected_failure_count
    )
    sample_manifest, sample_index = index_sample_manifest(sample_manifest_path)
    panel_by_prompt = index_sample_panels(sample_report_path)
    selected_ids = [str(metadata["prompt_unit_id"]) for _, metadata in selected]
    if len(selected_ids) != len(set(selected_ids)):
        raise AssertionError("Selected JSONDecodeError ids are not unique.")
    missing_from_sample = [
        prompt_unit_id
        for prompt_unit_id in selected_ids
        if prompt_unit_id not in sample_index
    ]
    missing_from_panels = [
        prompt_unit_id
        for prompt_unit_id in selected_ids
        if prompt_unit_id not in panel_by_prompt
    ]
    if missing_from_sample or missing_from_panels:
        raise AssertionError(
            f"Selected units missing from sample artifacts: "
            f"manifest={missing_from_sample}, panels={missing_from_panels}"
        )

    immutable_paths: set[Path] = {
        official_config_path,
        sample_manifest_path,
        sample_report_path,
        resolved_step16_root / "prompt_units_manifest_v2.json",
    }
    before_hashes = {
        str(path): sha256_file(path) for path in sorted(immutable_paths)
    }
    unit_reports: list[dict[str, Any]] = []
    source_entries: list[dict[str, Any]] = []
    prompt_summaries: list[dict[str, Any]] = []
    runnable_ids: list[str] = []
    not_runnable_ids: list[str] = []

    for metadata_path, metadata in selected:
        prompt_unit_id = str(metadata["prompt_unit_id"])
        prompt_path = resolved_step16_root / f"{prompt_unit_id}.prompt.json"
        raw_path = resolved_step17_root / "raw" / f"{prompt_unit_id}.raw.txt"
        failure_path = (
            resolved_step17_root
            / "failures"
            / f"{prompt_unit_id}.failure.json"
        )
        for required_path in (
            prompt_path,
            metadata_path,
            raw_path,
            failure_path,
        ):
            if not required_path.is_file():
                raise FileNotFoundError(
                    f"Required paired control artifact is missing: {required_path}"
                )
            immutable_paths.add(required_path)
            before_hashes.setdefault(
                str(required_path), sha256_file(required_path)
            )

        local_candidate_path = (
            resolved_compact_units_dir / f"{prompt_unit_id}.json"
            if resolved_compact_units_dir is not None
            else None
        )
        if (
            local_candidate_path is not None
            and local_candidate_path.is_file()
        ):
            immutable_paths.add(local_candidate_path)
            before_hashes.setdefault(
                str(local_candidate_path), sha256_file(local_candidate_path)
            )

        original_prompt = read_json(prompt_path)
        if original_prompt.get("prompt_unit_id") != prompt_unit_id:
            raise AssertionError(f"Prompt id mismatch in {prompt_path}")
        original_fixed, original_visible = parse_model_visible_input(
            original_prompt
        )
        source_unit, source_resolution = resolve_exact_source_unit(
            original_prompt=original_prompt,
            original_config=official_config,
            compact_units_dir=resolved_compact_units_dir,
        )
        local_candidate = source_resolution.get("local_candidate")
        if (
            isinstance(local_candidate, str)
            and Path(local_candidate).is_file()
        ):
            immutable_paths.add(Path(local_candidate))
            before_hashes.setdefault(
                str(Path(local_candidate)), sha256_file(local_candidate)
            )

        source_unit = deepcopy(source_unit)
        source_unit["experiment_id"] = experimental_config["experiment"][
            "experiment_id"
        ]
        source_unit["token_budget"] = {
            "active_policy": TOKEN_BUDGET_POLICY,
            "chars_per_token_estimate": 1.5,
            "output_token_estimation_safety_factor": 2.0,
            "prompt_target_context": 12288,
            "runtime_max_model_len": 12288,
            "payload_replacement_size_policy": deepcopy(
                EXPERIMENTAL_PAYLOAD_POLICY
            ),
        }
        variant_limits = apply_three_x_payload_limits(source_unit)
        token_plan = build_compact_patch_token_plan(
            prompt_unit=source_unit,
            prompt_input_structure=structure,
            instruction_lines=instruction_lines,
            prompt_target_context=12288,
            runtime_max_model_len=12288,
            chars_per_token_estimate=float(
                token_budget_config["chars_per_token_estimate"]
            ),
            output_token_estimation_safety_factor=float(
                token_budget_config[
                    "output_token_estimation_safety_factor"
                ]
            ),
            payload_replacement_size_policy=EXPERIMENTAL_PAYLOAD_POLICY,
        )
        source_unit["token_plan"] = deepcopy(token_plan)
        source_unit["estimated_input_tokens"] = int(
            token_plan["estimated_input_tokens"]
        )
        source_unit["token_planning_validation_status"] = (
            "runnable"
            if token_plan["fits_prompt_target_context"]
            else "not_runnable_under_12288"
        )

        logical_source_path = Path("source_units") / f"{prompt_unit_id}.json"
        source_output_path = output_root / logical_source_path
        write_json(source_output_path, source_unit)
        source_entries.append(
            {
                "modification_unit_id": prompt_unit_id,
                "parent_group_id": source_unit["parent_group_id"],
                "modification_unit_file": logical_source_path.as_posix(),
                "token_plan": deepcopy(token_plan),
                "runnable": bool(token_plan["fits_prompt_target_context"]),
            }
        )

        variant_prompt: dict[str, Any] | None = None
        variant_visible: dict[str, Any]
        variant_fixed: str
        if token_plan["fits_prompt_target_context"]:
            variant_prompt = step16.build_prompt_unit(
                config=experimental_config,
                prompt_version=experimental_config["llm"]["prompt_version"],
                modification_unit_entry=source_entries[-1],
                modification_unit_path=logical_source_path,
                prompt_unit=step16.prepare_prompt_source_unit(source_unit),
                expected_capabilities=capabilities,
            )
            variant_fixed, variant_visible = parse_model_visible_input(
                variant_prompt
            )
            if original_fixed != variant_fixed:
                raise AssertionError(
                    f"Instructions/skeleton changed for {prompt_unit_id}"
                )
            if normalize_visible_input_for_pairing(
                original_visible
            ) != normalize_visible_input_for_pairing(variant_visible):
                raise AssertionError(
                    f"Non-limit model-visible content changed for {prompt_unit_id}"
                )
            if physical_packet_ids(original_visible) != physical_packet_ids(
                variant_visible
            ):
                raise AssertionError(
                    f"Physical packet aliases changed for {prompt_unit_id}"
                )
            if payload_region_identity(
                original_visible
            ) != payload_region_identity(variant_visible):
                raise AssertionError(
                    f"Payload target identity changed for {prompt_unit_id}"
                )
            variant_prompt_path = (
                output_root / "prompts" / f"{prompt_unit_id}.prompt.json"
            )
            write_json(variant_prompt_path, variant_prompt)
            prompt_summaries.append(build_prompt_summary(variant_prompt))
            runnable_ids.append(prompt_unit_id)
            status = "runnable"
            variant_prompt_relative = (
                Path("prompts") / variant_prompt_path.name
            ).as_posix()
        else:
            parts = prompt_projection.build_compact_patch_prompt_parts(
                prompt_unit=source_unit,
                prompt_input_structure=structure,
                instruction_lines=instruction_lines,
            )
            variant_fixed = parts["fixed_prompt_text"]
            variant_visible = parts["json_prompt_input"]
            if original_fixed != variant_fixed:
                raise AssertionError(
                    f"Instructions/skeleton changed for {prompt_unit_id}"
                )
            if normalize_visible_input_for_pairing(
                original_visible
            ) != normalize_visible_input_for_pairing(variant_visible):
                raise AssertionError(
                    f"Non-limit model-visible content changed for {prompt_unit_id}"
                )
            not_runnable_ids.append(prompt_unit_id)
            status = "not_runnable_under_12288"
            variant_prompt_relative = None

        control = {
            "prompt": copy_control_file(
                source=prompt_path,
                destination=(
                    output_root
                    / "control"
                    / "prompts"
                    / prompt_path.name
                ),
            ),
            "metadata": copy_control_file(
                source=metadata_path,
                destination=(
                    output_root
                    / "control"
                    / "metadata"
                    / metadata_path.name
                ),
            ),
            "raw": copy_control_file(
                source=raw_path,
                destination=(
                    output_root / "control" / "raw" / raw_path.name
                ),
            ),
            "failure": copy_control_file(
                source=failure_path,
                destination=(
                    output_root
                    / "control"
                    / "failures"
                    / failure_path.name
                ),
            ),
        }
        for control_artifact in control.values():
            control_artifact["copied_path"] = (
                Path(control_artifact["copied_path"])
                .relative_to(output_root)
                .as_posix()
            )
        original_limits = summarize_original_limits(original_visible)
        if not original_limits:
            raise AssertionError(
                f"Original prompt has no payload limits: {prompt_unit_id}"
            )
        unit_reports.append(
            {
                "prompt_unit_id": prompt_unit_id,
                "parent_group_id": original_prompt["parent_group_id"],
                "sample_panel": panel_by_prompt[prompt_unit_id],
                "sample_manifest_entry": deepcopy(sample_index[prompt_unit_id]),
                "status": status,
                **source_resolution,
                "control": control,
                "original": {
                    "failure_reason": metadata["failure_reason"],
                    "payload_limits": original_limits,
                    "physical_packet_ids": physical_packet_ids(
                        original_visible
                    ),
                    "payload_region_identity": payload_region_identity(
                        original_visible
                    ),
                    "token_plan": deepcopy(original_prompt["token_plan"]),
                },
                "variant": {
                    "prompt_file": variant_prompt_relative,
                    "source_unit_file": logical_source_path.as_posix(),
                    "payload_limits": deepcopy(variant_limits),
                    "physical_packet_ids": physical_packet_ids(
                        variant_visible
                    ),
                    "payload_region_identity": payload_region_identity(
                        variant_visible
                    ),
                    "token_plan": deepcopy(token_plan),
                    "max_tokens_source": "token_plan.planned_output_tokens",
                },
                "coherence_checks": {
                    "original_prompt_round_trip_exact": True,
                    "same_fixed_instructions_and_output_skeleton": True,
                    "same_non_limit_model_visible_content": True,
                    "same_physical_packet_aliases": True,
                    "same_payload_region_identity": True,
                    "exact_three_x_limit": True,
                    "absolute_cap_is_null": True,
                    "hex_chars_equal_two_times_bytes": all(
                        item["effective_limit_hex_chars"]
                        == 2 * item["effective_limit_bytes"]
                        for item in variant_limits
                    ),
                    "max_tokens_derived_from_planned_output_tokens": (
                        token_plan["max_tokens"]
                        == token_plan["planned_output_tokens"]
                    ),
                    "total_is_input_plus_output": (
                        token_plan["total_planned_tokens"]
                        == token_plan["estimated_input_tokens"]
                        + token_plan["planned_output_tokens"]
                    ),
                },
            }
        )

    source_manifest = stable_source_manifest(
        config=experimental_config,
        source_entries=source_entries,
    )
    write_json(
        output_root
        / "source_units"
        / step16.SOURCE_MANIFEST_FILENAME,
        source_manifest,
    )
    prompt_manifest = stable_prompt_manifest(
        config=experimental_config,
        prompt_summaries=prompt_summaries,
        total_source_units=len(source_entries),
    )
    prompt_manifest_path = (
        output_root / "prompts" / "prompt_units_manifest_v2.json"
    )
    write_json(prompt_manifest_path, prompt_manifest)
    write_json(
        output_root / DIAGNOSTIC_CONFIG_FILENAME,
        experimental_config,
    )
    write_text(
        output_root / "runnable_prompt_unit_ids.txt",
        "\n".join(runnable_ids),
    )
    write_text(
        output_root / "not_runnable_under_12288_prompt_unit_ids.txt",
        "\n".join(not_runnable_ids),
    )

    all_limits = [
        item
        for unit in unit_reports
        for item in unit["variant"]["payload_limits"]
    ]
    all_plans = [unit["variant"]["token_plan"] for unit in unit_reports]
    report = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "objective": (
            "Paired sensitivity test of a finite 3.0x payload replacement "
            "growth limit for the 31 Experiment 20 Gemma JSONDecodeError units."
        ),
        "inputs": {
            "step17_run_root": str(resolved_step17_root),
            "step16_prompt_root": str(resolved_step16_root),
            "sample_manifest": str(sample_manifest_path),
            "sample_report": str(sample_report_path),
            "official_config": str(official_config_path),
            "compact_units_dir": (
                str(resolved_compact_units_dir)
                if resolved_compact_units_dir is not None
                else None
            ),
            "sample_manifest_method": sample_manifest.get("metadata", {})
            .get("calibration_sample", {})
            .get("method"),
        },
        "experimental_contract": {
            "payload_replacement_size_policy": deepcopy(
                EXPERIMENTAL_PAYLOAD_POLICY
            ),
            "chars_per_token_estimate": 1.5,
            "output_token_estimation_safety_factor": 2.0,
            "prompt_target_context": 12288,
            "runtime_max_model_len": 12288,
            "max_tokens_source": "token_plan.planned_output_tokens",
        },
        "summary": {
            "selected_prompt_count": len(unit_reports),
            "runnable_prompt_count": len(runnable_ids),
            "not_runnable_prompt_count": len(not_runnable_ids),
            "max_replacement_bytes_range": [
                min(item["effective_limit_bytes"] for item in all_limits),
                max(item["effective_limit_bytes"] for item in all_limits),
            ],
            "planned_output_tokens_range": [
                min(plan["planned_output_tokens"] for plan in all_plans),
                max(plan["planned_output_tokens"] for plan in all_plans),
            ],
            "max_tokens_range": [
                min(plan["max_tokens"] for plan in all_plans),
                max(plan["max_tokens"] for plan in all_plans),
            ],
            "estimated_input_tokens_range": [
                min(plan["estimated_input_tokens"] for plan in all_plans),
                max(plan["estimated_input_tokens"] for plan in all_plans),
            ],
            "maximum_total_planned_tokens": max(
                plan["total_planned_tokens"] for plan in all_plans
            ),
            "maximum_overflow_tokens": max(
                plan["overflow_tokens"] for plan in all_plans
            ),
            "source_resolution_counts": {
                mode: sum(
                    1
                    for unit in unit_reports
                    if unit["source_resolution"] == mode
                )
                for mode in sorted(
                    {unit["source_resolution"] for unit in unit_reports}
                )
            },
        },
        "units": unit_reports,
        "global_coherence_checks": {
            "selected_exactly_expected_jsondecode_count": (
                len(unit_reports) == expected_failure_count
            ),
            "all_selected_units_in_sample_manifest": True,
            "all_selected_units_in_sample_sidecar_panels": True,
            "all_limits_exactly_three_x": all(
                item["effective_limit_bytes"]
                == item["original_size_bytes"] * 3
                for item in all_limits
            ),
            "no_absolute_cap_applied": all(
                item["absolute_max_replacement_bytes"] is None
                for item in all_limits
            ),
            "all_hex_limits_coherent": all(
                item["effective_limit_hex_chars"]
                == 2 * item["effective_limit_bytes"]
                for item in all_limits
            ),
            "all_max_tokens_derived": all(
                plan["max_tokens"] == plan["planned_output_tokens"]
                for plan in all_plans
            ),
            "manifest_contains_only_runnable_units": (
                len(prompt_summaries) == len(runnable_ids)
            ),
        },
        "input_hashes_before_build": before_hashes,
    }
    write_json(output_root / "payload_limit_sensitivity_report.json", report)
    write_text(
        output_root / "payload_limit_sensitivity_summary.csv",
        render_summary_csv(unit_reports),
    )
    write_text(
        output_root / "original_to_variant_mapping.csv",
        render_mapping_csv(unit_reports),
    )
    write_text(
        output_root / "payload_limit_sensitivity_report.md",
        render_markdown(report),
    )

    validate_step17_consumability(
        config=experimental_config,
        manifest_path=prompt_manifest_path,
        prompt_dir=output_root / "prompts",
    )

    after_hashes = {
        str(path): sha256_file(path) for path in sorted(immutable_paths)
    }
    if before_hashes != after_hashes:
        changed = [
            path
            for path in before_hashes
            if before_hashes[path] != after_hashes.get(path)
        ]
        raise AssertionError(
            f"Original input artifacts changed during build: {changed}"
        )
    report["input_hashes_after_build"] = after_hashes
    report["global_coherence_checks"]["no_original_file_modified"] = True
    report["global_coherence_checks"][
        "step17_manifest_and_prompts_consumable"
    ] = True
    write_json(output_root / "payload_limit_sensitivity_report.json", report)
    return report


def hash_output_tree(root: str | Path) -> dict[str, str]:
    root_path = Path(root)
    return {
        path.relative_to(root_path).as_posix(): sha256_file(path)
        for path in sorted(root_path.rglob("*"))
        if path.is_file()
    }


def verify_deterministic_build(
    *,
    first_output_dir: Path,
    build_kwargs: dict[str, Any],
) -> None:
    second_output_dir = first_output_dir.parent / (
        first_output_dir.name + "__determinism_check"
    )
    if second_output_dir.exists():
        raise FileExistsError(
            f"Determinism-check directory already exists: {second_output_dir}"
        )
    build_diagnostic_package(
        **build_kwargs,
        output_dir=second_output_dir,
    )
    try:
        first_hashes = hash_output_tree(first_output_dir)
        second_hashes = hash_output_tree(second_output_dir)
        if first_hashes != second_hashes:
            differing = sorted(
                set(first_hashes) ^ set(second_hashes)
                | {
                    path
                    for path in set(first_hashes) & set(second_hashes)
                    if first_hashes[path] != second_hashes[path]
                }
            )
            raise AssertionError(
                f"Diagnostic builder is not deterministic: {differing}"
            )
    finally:
        resolved_second = second_output_dir.resolve()
        resolved_parent = first_output_dir.parent.resolve()
        if (
            resolved_second.parent != resolved_parent
            or not resolved_second.name.endswith("__determinism_check")
        ):
            raise RuntimeError(
                f"Refusing unsafe determinism cleanup: {resolved_second}"
            )
        shutil.rmtree(resolved_second)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a paired Experiment 20 diagnostic Step 17 smoke with an "
            "exact 3.0x payload replacement-size policy."
        )
    )
    parser.add_argument("--step17-root", default=str(DEFAULT_STEP17_ROOT))
    parser.add_argument("--step16-root", default=str(DEFAULT_STEP16_ROOT))
    parser.add_argument(
        "--sample-manifest", default=str(DEFAULT_SAMPLE_MANIFEST)
    )
    parser.add_argument(
        "--sample-report", default=str(DEFAULT_SAMPLE_REPORT)
    )
    parser.add_argument(
        "--official-config", default=str(DEFAULT_OFFICIAL_CONFIG)
    )
    parser.add_argument(
        "--compact-units-dir",
        default=(
            str(DEFAULT_COMPACT_UNITS_DIR)
            if DEFAULT_COMPACT_UNITS_DIR.exists()
            else None
        ),
        help=(
            "Optional Step 15 directory. A local unit is used only if the "
            "official builder reproduces the original prompt byte-for-byte."
        ),
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="New, empty directory for the diagnostic package.",
    )
    parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Build a second temporary package, compare every file hash, then remove it.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    build_kwargs = {
        "step17_root": args.step17_root,
        "step16_root": args.step16_root,
        "sample_manifest_path": args.sample_manifest,
        "sample_report_path": args.sample_report,
        "official_config_path": args.official_config,
        "compact_units_dir": args.compact_units_dir,
        "expected_failure_count": EXPECTED_FAILURE_COUNT,
    }
    output_dir = Path(args.output_dir).expanduser().resolve()
    report = build_diagnostic_package(
        **build_kwargs,
        output_dir=output_dir,
    )
    if args.verify_determinism:
        verify_deterministic_build(
            first_output_dir=output_dir,
            build_kwargs=build_kwargs,
        )
    summary = report["summary"]
    print("Payload-limit sensitivity smoke builder completed.")
    print(f"Selected JSONDecodeError units: {summary['selected_prompt_count']}")
    print(f"Runnable under 12288: {summary['runnable_prompt_count']}")
    print(
        "Not runnable under 12288: "
        f"{summary['not_runnable_prompt_count']}"
    )
    print(
        "New max_replacement_bytes range: "
        f"{summary['max_replacement_bytes_range']}"
    )
    print(
        "planned_output_tokens/max_tokens range: "
        f"{summary['planned_output_tokens_range']}"
    )
    print(
        "Maximum total_planned_tokens: "
        f"{summary['maximum_total_planned_tokens']}"
    )
    print(f"Output directory: {output_dir}")
    if args.verify_determinism:
        print("Determinism check: passed")


if __name__ == "__main__":
    main()
