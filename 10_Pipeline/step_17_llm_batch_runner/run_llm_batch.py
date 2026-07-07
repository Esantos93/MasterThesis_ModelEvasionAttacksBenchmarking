from __future__ import annotations

import argparse
import json
import math
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#This allows the script to find the folder common/ with shared code, even if the script is run from a different working directory.
PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.config import load_json_config, require_keys
from common.io_utils import write_json


#This is the fixed RISE cloud root agreed for the LLM-side pipeline steps.
DEFAULT_CLOUD_ROOT = Path("/home/ubuntu/thesis_Santos")

#These are the output folders written for each model.
MODEL_OUTPUT_SUBDIRS = ["raw", "parsed", "metadata", "failures"]

#These are the Step 16/17 schema names for the compact patch-based contract.
PROMPT_UNIT_SCHEMA_VERSION = "prompt_unit_v1"
PROMPT_UNITS_MANIFEST_SCHEMA_VERSION = "prompt_units_manifest_v1"
PATCH_OUTPUT_SCHEMA_VERSION = "patch_output_v1"
PATCH_PROMPT_CONTRACT = "patch_output"
FIELD_ALIASES = {
    "region_type": ["region_type", "type"],
    "operation": ["operation", "op"],
}


#This function reads a JSON file and returns the parsed Python object.
def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function writes plain text to a file, creating the parent folder when needed.
def write_text(path: str | Path, text: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        output_file.write(text)
        output_file.write("\n")


#This function validates the minimum configuration keys required by Step 17.
def validate_config(config: dict[str, Any]) -> None:
    require_keys(config, ["experiment", "llm"], "config")
    require_keys(config["experiment"], ["experiment_id"], "experiment")


#This function builds the default cloud-side paths for Step 17.
def default_cloud_paths(config: dict[str, Any], cloud_root: str | Path) -> dict[str, Path]:
    experiment_id = config["experiment"]["experiment_id"]
    root = Path(cloud_root).expanduser()
    return {
        "prompt_manifest": root / "02_OutputFiles" / experiment_id / "06_prompts" / "prompt_units_manifest_v1.json",
        "prompt_dir": root / "02_OutputFiles" / experiment_id / "06_prompts",
        "output_root": root / "02_OutputFiles" / experiment_id / "07_llm_outputs",
        "model_dir": root / "03_Models",
    }


#This function validates the basic shape of a Step 16 prompt manifest.
def validate_prompt_manifest(prompt_manifest: Any, manifest_path: Path) -> dict[str, Any]:
    if not isinstance(prompt_manifest, dict):
        raise ValueError(f"Prompt manifest root must be an object: {manifest_path}")
    metadata = prompt_manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Prompt manifest must contain a metadata object: {manifest_path}")
    schema_version = metadata.get("schema_version")
    if schema_version != PROMPT_UNITS_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"Prompt manifest must use schema_version={PROMPT_UNITS_MANIFEST_SCHEMA_VERSION}: {manifest_path}"
        )
    prompt_units = prompt_manifest.get("prompt_units")
    if not isinstance(prompt_units, list):
        raise ValueError(f"Prompt manifest must contain a prompt_units list: {manifest_path}")
    return prompt_manifest


#This function validates the basic shape of one Step 16 prompt unit.
def validate_prompt_package(prompt_package: Any, prompt_path: Path) -> dict[str, Any]:
    if not isinstance(prompt_package, dict):
        raise ValueError(f"Prompt unit root must be an object: {prompt_path}")
    if prompt_package.get("schema_version") != PROMPT_UNIT_SCHEMA_VERSION:
        raise ValueError(
            f"Prompt unit must use schema_version={PROMPT_UNIT_SCHEMA_VERSION}: {prompt_path}"
        )
    if prompt_package.get("prompt_contract") != PATCH_PROMPT_CONTRACT:
        raise ValueError(
            f"Step 17 currently expects prompt_contract={PATCH_PROMPT_CONTRACT}: {prompt_path}"
        )
    messages = prompt_package.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError(f"Prompt unit must contain a non-empty messages list: {prompt_path}")
    traceability = prompt_package.get("input_traceability")
    if not isinstance(traceability, dict):
        raise ValueError(f"Prompt unit must contain input_traceability object: {prompt_path}")
    if not isinstance(traceability.get("editable_regions"), list):
        raise ValueError(f"Prompt unit input_traceability must contain editable_regions list: {prompt_path}")
    return prompt_package


#This function resolves a prompt unit path from a prompt manifest entry.
#If a manifest path was generated on another machine, the local prompt directory is used as a filename fallback.
def resolve_prompt_file_path(prompt_entry: dict[str, Any], prompt_dir: Path) -> Path:
    prompt_file = prompt_entry.get("prompt_file")
    if isinstance(prompt_file, str) and prompt_file:
        manifest_path = Path(prompt_file).expanduser()
        if manifest_path.exists():
            return manifest_path
        fallback_path = prompt_dir / manifest_path.name
        if fallback_path.exists():
            return fallback_path

    prompt_id = prompt_entry.get("prompt_unit_id") or prompt_entry.get("group_id")
    if isinstance(prompt_id, str) and prompt_id:
        fallback_path = prompt_dir / f"{prompt_id}.prompt.json"
        if fallback_path.exists():
            return fallback_path

    raise FileNotFoundError(f"Could not resolve prompt file for manifest entry: {prompt_entry}")


#This function reads the prompt manifest and returns the ordered prompt paths selected for this run.
def collect_prompt_paths(
    *,
    prompt_manifest_path: Path,
    prompt_dir: Path,
    limit_prompts_s17: int | None,
) -> list[Path]:
    prompt_manifest = validate_prompt_manifest(read_json(prompt_manifest_path), prompt_manifest_path)
    prompt_entries = prompt_manifest["prompt_units"]
    selected_entries = prompt_entries[:limit_prompts_s17] if limit_prompts_s17 is not None else prompt_entries

    prompt_paths = []
    for prompt_entry in selected_entries:
        if not isinstance(prompt_entry, dict):
            raise ValueError("Every prompt manifest entry must be an object.")
        prompt_paths.append(resolve_prompt_file_path(prompt_entry, prompt_dir))
    return prompt_paths


#This function resolves the prompt files selected for this run.
#A direct prompt file is useful for a one-group smoke test, while the manifest is the normal batch mode.
def resolve_selected_prompt_paths(args: argparse.Namespace, paths: dict[str, Path]) -> list[Path]:
    if args.prompt_file and args.prompt_manifest:
        raise ValueError("Use either --prompt-file or --prompt-manifest, not both.")
    if args.prompt_file and args.limit_prompts_s17 is not None:
        raise ValueError("--limit-prompts-s17 is only valid with prompt manifest mode.")

    if args.prompt_file:
        prompt_path = Path(args.prompt_file).expanduser()
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file does not exist: {prompt_path}")
        return [prompt_path]

    prompt_manifest_path = Path(args.prompt_manifest).expanduser() if args.prompt_manifest else paths["prompt_manifest"]
    prompt_dir = Path(args.prompt_dir).expanduser() if args.prompt_dir else paths["prompt_dir"]
    return collect_prompt_paths(
        prompt_manifest_path=prompt_manifest_path,
        prompt_dir=prompt_dir,
        limit_prompts_s17=args.limit_prompts_s17,
    )


#This function normalises a model name so it is safe to use as a folder name.
def safe_model_name(model_path: Path) -> str:
    name = model_path.name if model_path.is_dir() or not model_path.suffix else model_path.stem
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    return name.strip("_") or "model"


#This function builds a stable run id when the caller does not provide one.
def build_default_run_id(run_label: str | None) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if run_label:
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", run_label).strip("_")
        if safe_label:
            return f"run_{timestamp}_{safe_label}"
    return f"run_{timestamp}"


#This function resolves the model paths selected for this run.
def collect_model_paths(
    *,
    model_dir: Path,
    explicit_model_paths: list[str] | None,
    model_filters: list[str] | None,
) -> list[Path]:
    raise RuntimeError("Step 17 no longer supports direct model discovery in run_llm_batch.py. Use run_llm_batch_vllm.py.")


#This function loads the selected model backend. The vLLM runner replaces this function before execution.
def load_model(model_path: Path, generation_params: dict[str, Any]) -> Any:
    raise RuntimeError("Step 17 no longer supports direct model loading in run_llm_batch.py. Use run_llm_batch_vllm.py.")


#This function creates the output folders for a model and run.
def prepare_model_output_dirs(output_root: Path, model_name: str, run_id: str) -> dict[str, Path]:
    model_root = output_root / model_name / run_id
    paths = {subdir: model_root / subdir for subdir in MODEL_OUTPUT_SUBDIRS}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


#This function returns the generation parameters used by the active Step 17 backend.
def build_generation_params(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    llm_config = config.get("llm", {})
    runtime_max_model_len = (
        args.runtime_max_model_len
        if args.runtime_max_model_len is not None
        else int(llm_config.get("runtime_max_model_len", llm_config.get("max_n_ctx", 32768)))
    )
    return {
        "temperature": args.temperature if args.temperature is not None else float(llm_config.get("temperature", 0.0)),
        "top_p": args.top_p if args.top_p is not None else float(llm_config.get("top_p", 0.95)),
        "output_token_margin_percent": (
            args.output_token_margin_percent
            if args.output_token_margin_percent is not None
            else float(llm_config.get("output_token_margin_percent", 20.0))
        ),
        "context_reserve_tokens": (
            args.context_reserve_tokens
            if args.context_reserve_tokens is not None
            else int(llm_config.get("context_reserve_tokens", 256))
        ),
        "prompt_target_context": int(llm_config.get("prompt_target_context", 4096)),
        "runtime_max_model_len": runtime_max_model_len,
        "expected_output_patch_tokens": (
            args.expected_output_patch_tokens
            if args.expected_output_patch_tokens is not None
            else int(llm_config.get("expected_output_patch_tokens", 1536))
        ),
        "n_ctx": args.n_ctx if args.n_ctx is not None else runtime_max_model_len,
        "n_ctx_mode": "fixed_cli" if args.n_ctx is not None else "runtime_max_model_len",
        "min_n_ctx": args.min_n_ctx if args.min_n_ctx is not None else int(llm_config.get("min_n_ctx", 2048)),
        "max_n_ctx": args.max_n_ctx if args.max_n_ctx is not None else int(llm_config.get("max_n_ctx", 32768)),
        "chars_per_token_estimate": (
            args.chars_per_token_estimate
            if args.chars_per_token_estimate is not None
            else float(llm_config.get("chars_per_token_estimate", 3.0))
        ),
    }


#This function converts chat messages into a stable text representation for input-token estimation.
#The actual chat template can add a few extra tokens, so Step 17 also keeps a context reserve.
def messages_to_estimation_text(messages: list[dict[str, Any]]) -> str:
    parts = []
    for message in messages:
        role = str(message.get("role", "user"))
        content = str(message.get("content", ""))
        parts.append(f"{role}:\n{content}")
    return "\n\n".join(parts)


#This function estimates token count from text length before the model is loaded.
#It is only used for context preflight before the vLLM model is loaded.
def estimate_tokens_from_char_count(text: str, chars_per_token_estimate: float) -> int:
    if chars_per_token_estimate <= 0:
        raise ValueError("--chars-per-token-estimate must be greater than zero.")
    return max(1, math.ceil(len(text) / chars_per_token_estimate))


#This function returns the next power of two greater than or equal to a positive integer.
def next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 2 ** math.ceil(math.log2(value))


#This function estimates the context window required by all selected prompts before model loading.
#A single model context length is selected for the whole run before the backend is loaded.
def estimate_dynamic_n_ctx(prompt_paths: list[Path], generation_params: dict[str, Any]) -> dict[str, Any]:
    if generation_params["n_ctx"] is not None:
        return {
            "mode": generation_params.get("n_ctx_mode", "fixed_cli"),
            "n_ctx": generation_params["n_ctx"],
            "largest_required_context_tokens": None,
            "largest_prompt_file": None,
            "was_capped_by_max_n_ctx": False,
        }

    largest_required_context_tokens = 0
    largest_prompt_file = None
    largest_input_tokens_estimate = 0
    largest_output_tokens_estimate = 0

    for prompt_path in prompt_paths:
        prompt_package = validate_prompt_package(read_json(prompt_path), prompt_path)
        message_text = messages_to_estimation_text(prompt_package["messages"])
        input_tokens_estimate = estimate_tokens_from_char_count(
            message_text,
            generation_params["chars_per_token_estimate"],
        )
        output_tokens_estimate = int(generation_params["expected_output_patch_tokens"])
        required_context_tokens = (
            input_tokens_estimate
            + output_tokens_estimate
            + int(generation_params["context_reserve_tokens"])
        )

        if required_context_tokens > largest_required_context_tokens:
            largest_required_context_tokens = required_context_tokens
            largest_prompt_file = str(prompt_path)
            largest_input_tokens_estimate = input_tokens_estimate
            largest_output_tokens_estimate = output_tokens_estimate

    desired_n_ctx = next_power_of_two(largest_required_context_tokens)
    desired_n_ctx = max(int(generation_params["min_n_ctx"]), desired_n_ctx)
    selected_n_ctx = min(desired_n_ctx, int(generation_params["max_n_ctx"]))
    return {
        "mode": "dynamic_prompt_preflight",
        "n_ctx": selected_n_ctx,
        "desired_n_ctx": desired_n_ctx,
        "min_n_ctx": generation_params["min_n_ctx"],
        "max_n_ctx": generation_params["max_n_ctx"],
        "chars_per_token_estimate": generation_params["chars_per_token_estimate"],
        "largest_required_context_tokens": largest_required_context_tokens,
        "largest_input_tokens_estimate": largest_input_tokens_estimate,
        "largest_output_tokens_estimate": largest_output_tokens_estimate,
        "largest_prompt_file": largest_prompt_file,
        "was_capped_by_max_n_ctx": selected_n_ctx < desired_n_ctx,
    }


#This function measures how many tokens the current prompt messages occupy for the loaded model.
def measure_input_tokens(llm: Any, messages: list[dict[str, Any]]) -> int:
    estimation_text = messages_to_estimation_text(messages)
    try:
        tokens = llm.tokenize(estimation_text.encode("utf-8"), add_bos=True)
    except TypeError:
        tokens = llm.tokenize(estimation_text.encode("utf-8"))
    return len(tokens)


OUTPUT_BUDGET_POLICY_NAME = "hybrid_output_token_budget_v1"
HEADER_ONLY_OUTPUT_BUDGET = 1536
MIXED_HEADER_OUTPUT_BUDGET_FLOOR = 1536
PAYLOAD_OUTPUT_BUDGET_BY_EDITABLE_BYTES = [
    (64, 768),
    (256, 1024),
    (512, 1280),
]
PAYLOAD_OUTPUT_BUDGET_ABOVE_MAX_BYTES = 1536


#This function counts editable regions declared by a Step 16 prompt unit.
def get_editable_region_count(prompt_package: dict[str, Any]) -> int:
    traceability = prompt_package.get("input_traceability", {})
    editable_regions = traceability.get("editable_regions", [])
    if isinstance(editable_regions, list):
        return sum(1 for editable_region in editable_regions if isinstance(editable_region, dict))
    return 0


#This function summarizes editable payload/header regions for dynamic output-token budgeting.
def summarize_editable_regions_for_output_budget(prompt_package: dict[str, Any]) -> dict[str, Any]:
    traceability = prompt_package.get("input_traceability", {})
    editable_regions = traceability.get("editable_regions", [])
    summary = {
        "editable_region_count": 0,
        "payload_editable_region_count": 0,
        "header_editable_region_count": 0,
        "payload_editable_bytes": 0,
        "prompt_class": None,
    }
    if not isinstance(editable_regions, list):
        return summary

    for editable_region in editable_regions:
        if not isinstance(editable_region, dict):
            continue
        summary["editable_region_count"] += 1
        if editable_region.get("identity_type") == "physical_header_region":
            summary["header_editable_region_count"] += 1
            continue
        summary["payload_editable_region_count"] += 1
        length_bytes = editable_region.get("length_bytes")
        if isinstance(length_bytes, int) and length_bytes > 0:
            summary["payload_editable_bytes"] += length_bytes

    if summary["payload_editable_region_count"] > 0:
        summary["prompt_class"] = "payload_involved"
    elif summary["header_editable_region_count"] > 0:
        summary["prompt_class"] = "header_only"
    return summary


#This function maps editable payload bytes to the configured output-token tier.
def estimate_payload_output_budget(payload_editable_bytes: int) -> tuple[int, str]:
    for max_payload_bytes, output_tokens in PAYLOAD_OUTPUT_BUDGET_BY_EDITABLE_BYTES:
        if payload_editable_bytes <= max_payload_bytes:
            return output_tokens, f"payload_bytes_le_{max_payload_bytes}"
    return PAYLOAD_OUTPUT_BUDGET_ABOVE_MAX_BYTES, "payload_bytes_above_512"


#This function estimates the desired output-token budget for one prompt unit.
def estimate_desired_output_tokens(
    *,
    prompt_package: dict[str, Any],
    output_token_cap: int,
) -> tuple[int, dict[str, Any]]:
    region_summary = summarize_editable_regions_for_output_budget(prompt_package)
    prompt_class = region_summary["prompt_class"]
    if prompt_class is None:
        raise ValueError("Step 17 supports only header_only or payload_involved prompt units.")
    if prompt_class == "header_only":
        estimated_output_tokens = HEADER_ONLY_OUTPUT_BUDGET
        budget_tier = "header_only"
    else:
        estimated_output_tokens, budget_tier = estimate_payload_output_budget(
            int(region_summary["payload_editable_bytes"])
        )
        if region_summary["header_editable_region_count"] > 0 and estimated_output_tokens < MIXED_HEADER_OUTPUT_BUDGET_FLOOR:
            estimated_output_tokens = MIXED_HEADER_OUTPUT_BUDGET_FLOOR
            budget_tier = f"{budget_tier}_mixed_header_floor"

    desired_output_tokens = min(estimated_output_tokens, output_token_cap)
    policy_details = {
        "policy": OUTPUT_BUDGET_POLICY_NAME,
        "editable_region_count": region_summary["editable_region_count"],
        "payload_editable_region_count": region_summary["payload_editable_region_count"],
        "header_editable_region_count": region_summary["header_editable_region_count"],
        "payload_editable_bytes": region_summary["payload_editable_bytes"],
        "prompt_class": prompt_class,
        "budget_tier": budget_tier,
        "estimated_output_tokens": estimated_output_tokens,
        "output_token_cap": output_token_cap,
        "was_capped_by_output_token_cap": desired_output_tokens < estimated_output_tokens,
    }
    return desired_output_tokens, policy_details


#This function calculates max_tokens for one compact patch prompt.
def build_prompt_generation_params(
    *,
    llm: Any,
    prompt_package: dict[str, Any],
    base_generation_params: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt_generation_params = dict(base_generation_params)
    real_input_tokens = measure_input_tokens(llm, prompt_package["messages"])
    estimated_input_tokens = prompt_package.get("estimated_input_tokens")
    if isinstance(estimated_input_tokens, (int, float)) and estimated_input_tokens > 0:
        estimation_error_ratio = real_input_tokens / float(estimated_input_tokens)
    else:
        estimation_error_ratio = None

    output_token_cap = int(base_generation_params["expected_output_patch_tokens"])
    desired_max_tokens, output_budget_policy = estimate_desired_output_tokens(
        prompt_package=prompt_package,
        output_token_cap=output_token_cap,
    )
    available_context_tokens = (
        int(base_generation_params["n_ctx"])
        - real_input_tokens
        - int(base_generation_params["context_reserve_tokens"])
    )
    if available_context_tokens <= 0:
        raise ValueError(
            "Prompt does not fit in the configured context window after reserve tokens. "
            f"real_input_tokens={real_input_tokens}, "
            f"n_ctx={base_generation_params['n_ctx']}, "
            f"context_reserve_tokens={base_generation_params['context_reserve_tokens']}"
        )

    max_tokens = min(desired_max_tokens, available_context_tokens)
    prompt_generation_params["max_tokens"] = max_tokens
    token_plan = {
        "mode": "compact_patch_dynamic_output_budget_v1",
        "estimated_input_tokens": estimated_input_tokens,
        "real_input_tokens": real_input_tokens,
        "estimation_error_ratio": estimation_error_ratio,
        "prompt_target_context": base_generation_params["prompt_target_context"],
        "runtime_max_model_len": base_generation_params["runtime_max_model_len"],
        "desired_max_tokens": desired_max_tokens,
        "max_tokens": max_tokens,
        "expected_output_patch_tokens": base_generation_params["expected_output_patch_tokens"],
        "output_token_cap": output_token_cap,
        "dynamic_output_budget_policy": output_budget_policy,
        "editable_region_count": output_budget_policy["editable_region_count"],
        "payload_editable_region_count": output_budget_policy["payload_editable_region_count"],
        "header_editable_region_count": output_budget_policy["header_editable_region_count"],
        "payload_editable_bytes": output_budget_policy["payload_editable_bytes"],
        "prompt_class": output_budget_policy["prompt_class"],
        "context_reserve_tokens": base_generation_params["context_reserve_tokens"],
        "available_context_tokens": available_context_tokens,
        "was_capped_by_context": max_tokens < desired_max_tokens,
    }
    return prompt_generation_params, token_plan


#This function extracts the text response from the model chat completion response.
def extract_response_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("Model response did not contain choices.")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise ValueError("Model response first choice is not an object.")
    message = first_choice.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    if isinstance(first_choice.get("text"), str):
        return first_choice["text"]
    raise ValueError("Model response did not contain message content.")


#This function extracts generated text from one streamed model chunk.
def extract_stream_chunk_text(chunk: dict[str, Any]) -> str:
    choices = chunk.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""
    delta = first_choice.get("delta")
    if isinstance(delta, dict) and isinstance(delta.get("content"), str):
        return delta["content"]
    if isinstance(first_choice.get("text"), str):
        return first_choice["text"]
    return ""


#This function reads the packet ids expected in the output from the Step 16 traceability block (heartbeat).
def expected_packet_ids_from_traceability(prompt_package: dict[str, Any]) -> list[str]:
    traceability = prompt_package.get("input_traceability", {})
    packet_ids = traceability.get("packet_ids")
    if isinstance(packet_ids, list):
        return [str(packet_id) for packet_id in packet_ids]
    return []


#This function estimates packet-level output progress by counting expected packet ids already visible in generated text.
def count_visible_packet_ids(generated_text: str, expected_packet_ids: list[str]) -> int:
    return sum(1 for packet_id in expected_packet_ids if packet_id in generated_text)


#This function starts a small heartbeat thread while a blocking model generation call is running.
#It gives terminal feedback even when one prompt takes a long time to finish.
def start_generation_heartbeat(
    *,
    model_name: str,
    group_id: str,
    prompt_index: int,
    total_prompts: int,
    heartbeat_seconds: int,
    progress_state: dict[str, Any],
) -> tuple[threading.Event, threading.Thread | None]:
    stop_event = threading.Event()
    if heartbeat_seconds <= 0:
        return stop_event, None

    #This function prints periodic progress while one blocking generation call is running.
    def heartbeat_loop() -> None:
        while not stop_event.wait(heartbeat_seconds):
            packet_text = ""
            visible_packet_count = progress_state.get("visible_packet_count")
            total_packet_count = progress_state.get("total_packet_count")
            if isinstance(visible_packet_count, int) and isinstance(total_packet_count, int) and total_packet_count > 0:
                packet_text = f". Observed packet IDs in streamed output: {visible_packet_count}/{total_packet_count}"
            print(
                f"[{datetime.now().isoformat(timespec='seconds')}] "
                f"{model_name}: still generating response for prompt/group {prompt_index}/{total_prompts} "
                f"({group_id}){packet_text}"
            )

    thread = threading.Thread(target=heartbeat_loop, daemon=True)
    thread.start()
    return stop_event, thread


#This function parses the model response as strict JSON.
#Text before or after the JSON object is rejected by json.loads.
def parse_strict_json(raw_text: str) -> Any:
    return json.loads(raw_text)


#This function builds a lookup for editable regions declared by Step 16.
def build_editable_region_lookup(prompt_package: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    lookup: dict[tuple[str, str], dict[str, Any]] = {}
    traceability = prompt_package.get("input_traceability", {})
    for region in traceability.get("editable_regions", []):
        if not isinstance(region, dict):
            continue
        packet_id = region.get("packet_id")
        region_id = region.get("region_id")
        if packet_id is None or not isinstance(region_id, str):
            continue
        lookup[(str(packet_id), region_id)] = region
    return lookup


#This function finds a unique editable header region by header region id.
def find_unique_header_region_by_region_id(
    editable_lookup: dict[tuple[str, str], dict[str, Any]],
    region_id: str,
) -> tuple[str, dict[str, Any]] | None:
    matches = [
        (packet_id, region)
        for (packet_id, candidate_region_id), region in editable_lookup.items()
        if candidate_region_id == region_id and region.get("identity_type") == "physical_header_region"
    ]
    if len(matches) != 1:
        return None
    return matches[0]


#This function normalizes payload patch identity aliases to the canonical-region contract.
def normalize_payload_patch_target_identity(patch: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    packet_id = patch.get("packet_id")
    canonical_region_id = patch.get("canonical_region_id")
    if packet_id is None and canonical_region_id is None:
        return None, {"accepted": False, "reason": "patch_missing_packet_or_canonical_region"}

    if packet_id is None:
        packet_id = canonical_region_id
        patch["packet_id"] = packet_id
    elif canonical_region_id is None:
        canonical_region_id = packet_id
        patch["canonical_region_id"] = canonical_region_id
    elif str(packet_id) != str(canonical_region_id):
        return None, {
            "accepted": False,
            "reason": "packet_id_canonical_region_id_mismatch",
            "packet_id": str(packet_id),
            "canonical_region_id": str(canonical_region_id),
        }

    return str(packet_id), None


#This function normalizes header patch identity aliases to the physical-packet contract.
def normalize_header_patch_target_identity(patch: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    packet_id = patch.get("packet_id")
    canonical_region_id = patch.get("canonical_region_id")
    if packet_id is None:
        return None, {"accepted": False, "reason": "header_patch_missing_packet_id"}
    if canonical_region_id is not None and str(canonical_region_id) != str(packet_id):
        return None, {
            "accepted": False,
            "reason": "header_patch_unexpected_canonical_region_id",
            "packet_id": str(packet_id),
            "canonical_region_id": str(canonical_region_id),
        }
    return str(packet_id), None


#This function reads a canonical field name while accepting known model-output aliases.
def get_field_with_aliases(obj: dict[str, Any], canonical_name: str) -> Any:
    for field_name in FIELD_ALIASES.get(canonical_name, [canonical_name]):
        if field_name in obj:
            return obj[field_name]
    return None


#This function validates whether a string contains even-length hexadecimal bytes.
def validate_hex_string(value: str) -> bool:
    cleaned = value.strip()
    return len(cleaned) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", cleaned) is not None


#This function validates a replacement value against the target region format.
def validate_replacement_format(
    *,
    patch: dict[str, Any],
    region: dict[str, Any],
    patch_index: int,
) -> dict[str, Any] | None:
    replacement_format = patch.get("replacement_format")
    if replacement_format not in {"text", "hex"}:
        return {
            "accepted": False,
            "reason": "invalid_replacement_format",
            "patch_index": patch_index,
            "replacement_format": replacement_format,
        }

    expected_format = region.get("format")
    if expected_format in {"text", "hex"} and replacement_format != expected_format:
        return {
            "accepted": False,
            "reason": "replacement_format_mismatch",
            "patch_index": patch_index,
            "expected_format": expected_format,
            "actual_format": replacement_format,
        }

    replacement = patch.get("replacement")
    if not isinstance(replacement, str):
        return {
            "accepted": False,
            "reason": "replacement_not_string",
            "patch_index": patch_index,
        }
    if replacement_format == "hex" and not validate_hex_string(replacement):
        return {
            "accepted": False,
            "reason": "replacement_hex_invalid",
            "patch_index": patch_index,
        }
    return None


#This function validates integer header replacements against field constraints.
def validate_uint_replacement(
    *,
    patch: dict[str, Any],
    region: dict[str, Any],
    patch_index: int,
) -> dict[str, Any] | None:
    if patch.get("replacement_format") != "uint":
        return {
            "accepted": False,
            "reason": "invalid_uint_replacement_format",
            "patch_index": patch_index,
            "replacement_format": patch.get("replacement_format"),
        }
    replacement = patch.get("replacement")
    if isinstance(replacement, bool) or not isinstance(replacement, int):
        return {
            "accepted": False,
            "reason": "replacement_uint_not_integer",
            "patch_index": patch_index,
        }
    constraints = region.get("constraints", {})
    if not isinstance(constraints, dict):
        constraints = {}
    min_value = constraints.get("min")
    max_value = constraints.get("max")
    if isinstance(min_value, int) and replacement < min_value:
        return {
            "accepted": False,
            "reason": "replacement_uint_below_min",
            "patch_index": patch_index,
            "replacement": replacement,
            "min": min_value,
        }
    if isinstance(max_value, int) and replacement > max_value:
        return {
            "accepted": False,
            "reason": "replacement_uint_above_max",
            "patch_index": patch_index,
            "replacement": replacement,
            "max": max_value,
        }
    return None


#This function expands compact header_edits into normal replace_uint patches before validation.
def expand_compact_header_edits(parsed_output: dict[str, Any], prompt_package: dict[str, Any]) -> dict[str, Any] | None:
    header_edits = parsed_output.get("header_edits")
    if header_edits is None:
        return None
    if not isinstance(header_edits, list):
        return {"accepted": False, "reason": "header_edits_not_list"}

    editable_lookup = build_editable_region_lookup(prompt_package)
    patches = parsed_output.get("patches")
    if patches is None:
        patches = []
        parsed_output["patches"] = patches
    if not isinstance(patches, list):
        return {"accepted": False, "reason": "patches_not_list"}
    parsed_output["patches"] = [
        patch
        for patch in patches
        if not (
            isinstance(patch, dict)
            and set(patch) <= {"packet_id", "field", "replacement_uint"}
            and {"packet_id", "field", "replacement_uint"} <= set(patch)
        )
    ]
    patches = parsed_output["patches"]

    for edit_index, header_edit in enumerate(header_edits, start=1):
        if not isinstance(header_edit, list) or len(header_edit) != 3:
            return {
                "accepted": False,
                "reason": "header_edit_invalid_shape",
                "header_edit_index": edit_index,
            }
        packet_id, field, replacement = header_edit
        if not isinstance(packet_id, str):
            return {
                "accepted": False,
                "reason": "header_edit_packet_id_not_string",
                "header_edit_index": edit_index,
            }
        if not isinstance(field, str):
            return {
                "accepted": False,
                "reason": "header_edit_field_not_string",
                "header_edit_index": edit_index,
            }
        packet_id_text = str(packet_id)
        matching_regions = [
            region
            for (lookup_packet_id, _lookup_region_id), region in editable_lookup.items()
            if lookup_packet_id == packet_id_text
            and region.get("identity_type") == "physical_header_region"
            and region.get("field") == field
        ]
        if len(matching_regions) != 1:
            return {
                "accepted": False,
                "reason": "header_edit_references_unknown_or_non_editable_region",
                "header_edit_index": edit_index,
                "packet_id": packet_id_text,
                "field": field,
            }
        region = matching_regions[0]
        region_id = str(region["region_id"])
        patches.append(
            {
                "packet_id": packet_id_text,
                "region_id": region_id,
                "region_type": "header_field",
                "operation": "replace_uint",
                "replacement_format": "uint",
                "replacement": replacement,
            }
        )
    return None


#This function validates the patch_output_v1 contract using the Step 16 editable-region index.
def validate_patch_output(parsed_output: Any, prompt_package: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parsed_output, dict):
        return {"accepted": False, "reason": "parsed_output_root_not_object"}

    if parsed_output.get("schema_version") != PATCH_OUTPUT_SCHEMA_VERSION:
        return {
            "accepted": False,
            "reason": "invalid_patch_schema_version",
            "expected_schema_version": PATCH_OUTPUT_SCHEMA_VERSION,
            "actual_schema_version": parsed_output.get("schema_version"),
        }

    if parsed_output.get("parent_group_id") != prompt_package.get("parent_group_id"):
        return {
            "accepted": False,
            "reason": "parent_group_id_changed",
            "expected_parent_group_id": prompt_package.get("parent_group_id"),
            "actual_parent_group_id": parsed_output.get("parent_group_id"),
        }

    if parsed_output.get("prompt_unit_id") != prompt_package.get("prompt_unit_id"):
        return {
            "accepted": False,
            "reason": "prompt_unit_id_changed",
            "expected_prompt_unit_id": prompt_package.get("prompt_unit_id"),
            "actual_prompt_unit_id": parsed_output.get("prompt_unit_id"),
        }

    compact_header_edit_error = expand_compact_header_edits(parsed_output, prompt_package)
    if compact_header_edit_error:
        return compact_header_edit_error

    patches = parsed_output.get("patches")
    if not isinstance(patches, list):
        return {"accepted": False, "reason": "patches_not_list"}

    editable_lookup = build_editable_region_lookup(prompt_package)
    editable_packet_ids = set(str(packet_id) for packet_id in prompt_package["input_traceability"].get("editable_packet_ids", []))
    for patch_index, patch in enumerate(patches, start=1):
        if not isinstance(patch, dict):
            return {"accepted": False, "reason": "patch_not_object", "patch_index": patch_index}

        region_id = patch.get("region_id")
        if not isinstance(region_id, str):
            return {"accepted": False, "reason": "patch_missing_packet_or_region", "patch_index": patch_index}

        explicit_packet_id = patch.get("packet_id")
        raw_packet_id = explicit_packet_id or patch.get("canonical_region_id")
        region = None
        if raw_packet_id is None:
            inferred_header_region = find_unique_header_region_by_region_id(editable_lookup, region_id)
            if inferred_header_region is None:
                return {"accepted": False, "reason": "patch_missing_packet_or_canonical_region", "patch_index": patch_index}
            packet_id_text, region = inferred_header_region
            patch["packet_id"] = packet_id_text
        else:
            packet_id_text = str(raw_packet_id)
            if explicit_packet_id is None and packet_id_text not in editable_packet_ids:
                inferred_header_region = find_unique_header_region_by_region_id(editable_lookup, region_id)
                if inferred_header_region is not None:
                    packet_id_text, region = inferred_header_region
                    patch["packet_id"] = packet_id_text
                    patch.pop("canonical_region_id", None)
        if packet_id_text not in editable_packet_ids:
            return {
                "accepted": False,
                "reason": "patch_references_non_editable_packet",
                "patch_index": patch_index,
                "packet_id": packet_id_text,
            }

        if region is None:
            region = editable_lookup.get((packet_id_text, region_id))
        if region is None:
            return {
                "accepted": False,
                "reason": "patch_references_unknown_or_non_editable_region",
                "patch_index": patch_index,
                "packet_id": packet_id_text,
                "region_id": region_id,
            }
        region_identity_type = region.get("identity_type", "canonical_payload_region")
        if region_identity_type == "physical_header_region":
            packet_id_text, identity_error = normalize_header_patch_target_identity(patch)
        else:
            packet_id_text, identity_error = normalize_payload_patch_target_identity(patch)
        if identity_error:
            identity_error["patch_index"] = patch_index
            return identity_error
        if packet_id_text is None:
            return {"accepted": False, "reason": "patch_missing_packet_or_region", "patch_index": patch_index}

        region_canonical_region_id = region.get("canonical_region_id")
        if region_identity_type != "physical_header_region" and region_canonical_region_id is not None and str(patch.get("canonical_region_id")) != str(region_canonical_region_id):
            return {
                "accepted": False,
                "reason": "patch_canonical_region_id_mismatch",
                "patch_index": patch_index,
                "packet_id": packet_id_text,
                "region_id": region_id,
                "expected_canonical_region_id": str(region_canonical_region_id),
                "actual_canonical_region_id": str(patch.get("canonical_region_id")),
            }

        operation = get_field_with_aliases(patch, "operation")
        allowed_operations = region.get("allowed_operations") or ["replace_region"]
        if not isinstance(allowed_operations, list):
            return {
                "accepted": False,
                "reason": "invalid_region_allowed_operations",
                "patch_index": patch_index,
                "region_id": region_id,
            }
        if operation not in allowed_operations:
            return {
                "accepted": False,
                "reason": "operation_not_allowed_for_region",
                "patch_index": patch_index,
                "operation": operation,
                "allowed_operations": allowed_operations,
            }

        expected_region_type = region.get("region_type")
        actual_region_type = get_field_with_aliases(patch, "region_type")
        if (
            region_identity_type == "physical_header_region"
            and actual_region_type == region.get("field")
            and expected_region_type == "header_field"
        ):
            patch["region_type"] = "header_field"
            actual_region_type = "header_field"
        if actual_region_type != expected_region_type:
            return {
                "accepted": False,
                "reason": "region_type_mismatch",
                "patch_index": patch_index,
                "expected_region_type": expected_region_type,
                "actual_region_type": actual_region_type,
            }

        if operation == "replace_uint":
            replacement_error = validate_uint_replacement(patch=patch, region=region, patch_index=patch_index)
            if replacement_error:
                return replacement_error
            continue

        replacement_error = validate_replacement_format(patch=patch, region=region, patch_index=patch_index)
        if replacement_error:
            return replacement_error

        if operation == "replace_byte_range":
            offset = patch.get("offset_from_region_start_bytes")
            length_bytes = patch.get("length_bytes")
            if not isinstance(offset, int) or offset < 0:
                return {
                    "accepted": False,
                    "reason": "invalid_replace_byte_range_offset",
                    "patch_index": patch_index,
                }
            if not isinstance(length_bytes, int) or length_bytes < 0:
                return {
                    "accepted": False,
                    "reason": "invalid_replace_byte_range_length",
                    "patch_index": patch_index,
                }
            region_length = region.get("length_bytes")
            if not isinstance(region_length, int) or region_length < 0:
                return {
                    "accepted": False,
                    "reason": "editable_region_missing_length_bytes",
                    "patch_index": patch_index,
                    "region_id": region_id,
                }
            if offset + length_bytes > region_length:
                return {
                    "accepted": False,
                    "reason": "replace_byte_range_exceeds_region",
                    "patch_index": patch_index,
                    "offset_from_region_start_bytes": offset,
                    "length_bytes": length_bytes,
                    "region_length_bytes": region_length,
                }
        elif operation != "replace_region":
            return {
                "accepted": False,
                "reason": "unsupported_patch_operation",
                "patch_index": patch_index,
                "operation": operation,
            }

    return {
        "accepted": True,
        "reason": "accepted",
        "patch_count": len(patches),
    }


#This function builds the metadata object written for every attempted model/prompt run.
def build_run_metadata(
    *,
    status: str,
    failure_reason: str | None,
    prompt_package: dict[str, Any],
    prompt_path: Path,
    model_path: Path,
    model_name: str,
    generation_params: dict[str, Any],
    token_plan: dict[str, Any] | None,
    started_at_utc: str,
    finished_at_utc: str,
    runtime_seconds: float,
    output_paths: dict[str, str],
    validation_result: dict[str, Any] | None,
    generation_response_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "status": status,
        "failure_reason": failure_reason,
        "experiment_id": prompt_package.get("experiment_id"),
        "group_id": prompt_package.get("group_id"),
        "parent_group_id": prompt_package.get("parent_group_id"),
        "prompt_unit_id": prompt_package.get("prompt_unit_id"),
        "prompt_version": prompt_package.get("prompt_version"),
        "prompt_contract": prompt_package.get("prompt_contract"),
        "prompt_file": str(prompt_path),
        "source_modification_unit_file": prompt_package.get("source_modification_unit_file"),
        "source_modification_unit_schema_version": prompt_package.get("source_modification_unit_schema_version"),
        "model_name": model_name,
        "model_path": str(model_path),
        "generation_params": generation_params,
        "token_plan": token_plan,
        "real_input_tokens": token_plan.get("real_input_tokens") if token_plan else None,
        "max_tokens": token_plan.get("max_tokens") if token_plan else None,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "runtime_seconds": runtime_seconds,
        "output_paths": output_paths,
        "validation_result": validation_result,
        "generation_response_metadata": generation_response_metadata,
    }


#This function writes one failure report and optional rejected JSON for a run.
def write_failure_outputs(
    *,
    output_dirs: dict[str, Path],
    output_stem: str,
    failure_report: dict[str, Any],
    rejected_json: Any | None,
) -> dict[str, str]:
    failure_path = output_dirs["failures"] / f"{output_stem}.failure.json"
    write_json(failure_path, failure_report)
    output_paths = {"failure": str(failure_path)}
    if rejected_json is not None:
        rejected_path = output_dirs["failures"] / f"{output_stem}.rejected.json"
        write_json(rejected_path, rejected_json)
        output_paths["rejected_json"] = str(rejected_path)
    return output_paths


#This function runs one prompt through one already-loaded model.
#Each call uses only the messages from the current prompt unit, so no previous prompt context is carried forward.
def run_single_prompt(
    *,
    llm: Any,
    prompt_path: Path,
    model_path: Path,
    model_name: str,
    output_dirs: dict[str, Path],
    generation_params: dict[str, Any],
    heartbeat_seconds: int,
    prompt_index: int,
    total_prompts: int,
) -> dict[str, Any]:
    prompt_package = validate_prompt_package(read_json(prompt_path), prompt_path)
    prompt_unit_id = str(prompt_package.get("prompt_unit_id") or prompt_package.get("group_id") or prompt_path.stem.replace(".prompt", ""))
    parent_group_id = str(prompt_package.get("parent_group_id") or "")
    output_stem = prompt_unit_id
    raw_path = output_dirs["raw"] / f"{output_stem}.raw.txt"
    parsed_path = output_dirs["parsed"] / f"{output_stem}.parsed.json"
    metadata_path = output_dirs["metadata"] / f"{output_stem}.metadata.json"

    started_at_utc = datetime.now(timezone.utc).isoformat()
    start_time = time.perf_counter()
    status = "failed"
    failure_reason = None
    validation_result = None
    raw_text = ""
    parsed_output = None
    generation_response_metadata = None
    token_plan = None
    output_paths: dict[str, str] = {}

    traceability = prompt_package["input_traceability"]
    editable_packet_ids = traceability.get("editable_packet_ids", [])
    editable_packet_count = len(editable_packet_ids) if isinstance(editable_packet_ids, list) else 0
    editable_region_count = get_editable_region_count(prompt_package)

    if editable_region_count == 0:
        parsed_output = {
            "schema_version": PATCH_OUTPUT_SCHEMA_VERSION,
            "parent_group_id": prompt_package.get("parent_group_id"),
            "prompt_unit_id": prompt_package.get("prompt_unit_id"),
            "patches": [],
        }
        failure_reason = "no_editable_regions_not_supported"
        validation_result = {"accepted": False, "reason": failure_reason, "patch_count": 0}
        token_plan = {
            "mode": "invalid_no_editable_regions",
            "estimated_input_tokens": prompt_package.get("estimated_input_tokens"),
            "real_input_tokens": 0,
            "runtime_max_model_len": generation_params["runtime_max_model_len"],
            "desired_max_tokens": 0,
            "max_tokens": 0,
            "expected_output_patch_tokens": generation_params["expected_output_patch_tokens"],
            "output_token_cap": generation_params["expected_output_patch_tokens"],
            "dynamic_output_budget_policy": {
                "policy": OUTPUT_BUDGET_POLICY_NAME,
                "editable_region_count": editable_region_count,
                "editable_packet_count": editable_packet_count,
                "budget_tier": "invalid_no_editable_regions",
                "estimated_output_tokens": 0,
                "output_token_cap": generation_params["expected_output_patch_tokens"],
                "was_capped_by_output_token_cap": False,
            },
            "editable_region_count": editable_region_count,
            "editable_packet_count": editable_packet_count,
            "context_reserve_tokens": generation_params["context_reserve_tokens"],
            "available_context_tokens": generation_params["runtime_max_model_len"],
            "was_capped_by_context": False,
        }
        write_json(parsed_path, parsed_output)
        output_paths["parsed"] = str(parsed_path)
        output_paths["metadata"] = str(metadata_path)
        metadata = build_run_metadata(
            status="failed",
            failure_reason=failure_reason,
            prompt_package=prompt_package,
            prompt_path=prompt_path,
            model_path=model_path,
            model_name=model_name,
            generation_params=generation_params,
            started_at_utc=started_at_utc,
            finished_at_utc=started_at_utc,
            runtime_seconds=0.0,
            output_paths=output_paths,
            validation_result=validation_result,
            token_plan=token_plan,
            generation_response_metadata=None,
        )
        write_json(metadata_path, metadata)
        return metadata

    try:
        prompt_generation_params, token_plan = build_prompt_generation_params(
            llm=llm,
            prompt_package=prompt_package,
            base_generation_params=generation_params,
        )
        expected_packet_ids = expected_packet_ids_from_traceability(prompt_package)
        progress_state = {
            "visible_packet_count": 0,
            "total_packet_count": len(expected_packet_ids),
        }
        heartbeat_stop, heartbeat_thread = start_generation_heartbeat(
            model_name=model_name,
            group_id=prompt_unit_id,
            prompt_index=prompt_index,
            total_prompts=total_prompts,
            heartbeat_seconds=heartbeat_seconds,
            progress_state=progress_state,
        )
        try:
            response_chunks = llm.create_chat_completion(
                messages=prompt_package["messages"],
                temperature=prompt_generation_params["temperature"],
                top_p=prompt_generation_params["top_p"],
                max_tokens=prompt_generation_params["max_tokens"],
                stream=True,
            )
            raw_parts = []
            for chunk in response_chunks:
                chunk_text = extract_stream_chunk_text(chunk)
                if chunk_text:
                    raw_parts.append(chunk_text)
                    if expected_packet_ids:
                        raw_text_so_far = "".join(raw_parts)
                        progress_state["visible_packet_count"] = count_visible_packet_ids(
                            raw_text_so_far,
                            expected_packet_ids,
                        )
            raw_text = "".join(raw_parts)
        finally:
            heartbeat_stop.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=1)

        write_text(raw_path, raw_text)
        output_paths["raw"] = str(raw_path)
        generation_response_metadata = {
            "stream": True,
            "stream_visible_packet_ids": progress_state["visible_packet_count"],
            "stream_expected_packet_ids": progress_state["total_packet_count"],
        }

        parsed_output = parse_strict_json(raw_text)
        validation_result = validate_patch_output(parsed_output, prompt_package)
        if validation_result["accepted"]:
            write_json(parsed_path, parsed_output)
            output_paths["parsed"] = str(parsed_path)
            status = "accepted"
        else:
            failure_reason = validation_result["reason"]
            failure_report = {
                "failure_reason": failure_reason,
                "parent_group_id": parent_group_id,
                "prompt_unit_id": prompt_unit_id,
                "prompt_file": str(prompt_path),
                "model_name": model_name,
                "validation_result": validation_result,
            }
            output_paths.update(
                write_failure_outputs(
                    output_dirs=output_dirs,
                    output_stem=output_stem,
                    failure_report=failure_report,
                    rejected_json=parsed_output,
                )
            )

    except Exception as error:
        failure_reason = type(error).__name__
        failure_report = {
            "failure_reason": failure_reason,
            "failure_message": str(error),
            "parent_group_id": parent_group_id,
            "prompt_unit_id": prompt_unit_id,
            "prompt_file": str(prompt_path),
            "model_name": model_name,
        }
        output_paths.update(
            write_failure_outputs(
                output_dirs=output_dirs,
                output_stem=output_stem,
                failure_report=failure_report,
                rejected_json=parsed_output,
            )
        )
        if raw_text and "raw" not in output_paths:
            write_text(raw_path, raw_text)
            output_paths["raw"] = str(raw_path)

    finished_at_utc = datetime.now(timezone.utc).isoformat()
    runtime_seconds = time.perf_counter() - start_time
    output_paths["metadata"] = str(metadata_path)
    metadata = build_run_metadata(
        status=status,
        failure_reason=failure_reason,
        prompt_package=prompt_package,
        prompt_path=prompt_path,
        model_path=model_path,
        model_name=model_name,
        generation_params=generation_params,
        started_at_utc=started_at_utc,
        finished_at_utc=finished_at_utc,
        runtime_seconds=runtime_seconds,
        output_paths=output_paths,
        validation_result=validation_result,
        token_plan=token_plan,
        generation_response_metadata=generation_response_metadata,
    )
    write_json(metadata_path, metadata)
    return metadata


#This function builds reusable output paths and prompt identity fields for one generated response.
def build_prompt_output_context(
    *,
    prompt_package: dict[str, Any],
    prompt_path: Path,
    model_name: str,
    output_dirs: dict[str, Path],
) -> dict[str, Any]:
    prompt_unit_id = str(prompt_package.get("prompt_unit_id") or prompt_package.get("group_id") or prompt_path.stem.replace(".prompt", ""))
    output_stem = prompt_unit_id
    return {
        "prompt_unit_id": prompt_unit_id,
        "parent_group_id": str(prompt_package.get("parent_group_id") or ""),
        "output_stem": output_stem,
        "raw_path": output_dirs["raw"] / f"{output_stem}.raw.txt",
        "parsed_path": output_dirs["parsed"] / f"{output_stem}.parsed.json",
        "metadata_path": output_dirs["metadata"] / f"{output_stem}.metadata.json",
        "expected_packet_ids": expected_packet_ids_from_traceability(prompt_package),
        "model_name": model_name,
    }


#This function parses, validates, and writes outputs for one generated batch response.
def write_generated_prompt_outputs(
    *,
    prompt_package: dict[str, Any],
    prompt_path: Path,
    model_path: Path,
    model_name: str,
    output_dirs: dict[str, Path],
    generation_params: dict[str, Any],
    token_plan: dict[str, Any],
    raw_text: str,
    started_at_utc: str,
    start_time: float,
    batch_index: int,
    batch_size: int,
    batch_limit: int,
    batch_runtime_seconds: float,
) -> dict[str, Any]:
    context = build_prompt_output_context(
        prompt_package=prompt_package,
        prompt_path=prompt_path,
        model_name=model_name,
        output_dirs=output_dirs,
    )
    status = "failed"
    failure_reason = None
    validation_result = None
    parsed_output = None
    output_paths: dict[str, str] = {}

    try:
        write_text(context["raw_path"], raw_text)
        output_paths["raw"] = str(context["raw_path"])
        parsed_output = parse_strict_json(raw_text)
        validation_result = validate_patch_output(parsed_output, prompt_package)
        if validation_result["accepted"]:
            write_json(context["parsed_path"], parsed_output)
            output_paths["parsed"] = str(context["parsed_path"])
            status = "accepted"
        else:
            failure_reason = validation_result["reason"]
            failure_report = {
                "failure_reason": failure_reason,
                "parent_group_id": context["parent_group_id"],
                "prompt_unit_id": context["prompt_unit_id"],
                "prompt_file": str(prompt_path),
                "model_name": model_name,
                "validation_result": validation_result,
            }
            output_paths.update(
                write_failure_outputs(
                    output_dirs=output_dirs,
                    output_stem=context["output_stem"],
                    failure_report=failure_report,
                    rejected_json=parsed_output,
                )
            )
    except Exception as error:
        failure_reason = type(error).__name__
        failure_report = {
            "failure_reason": failure_reason,
            "failure_message": str(error),
            "parent_group_id": context["parent_group_id"],
            "prompt_unit_id": context["prompt_unit_id"],
            "prompt_file": str(prompt_path),
            "model_name": model_name,
        }
        output_paths.update(
            write_failure_outputs(
                output_dirs=output_dirs,
                output_stem=context["output_stem"],
                failure_report=failure_report,
                rejected_json=parsed_output,
            )
        )

    finished_at_utc = datetime.now(timezone.utc).isoformat()
    output_paths["metadata"] = str(context["metadata_path"])
    generation_response_metadata = {
        "stream": False,
        "batch_index": batch_index,
        "batch_size": batch_size,
        "batch_limit": batch_limit,
        "batch_runtime_seconds": batch_runtime_seconds,
        "stream_visible_packet_ids": count_visible_packet_ids(raw_text, context["expected_packet_ids"]),
        "stream_expected_packet_ids": len(context["expected_packet_ids"]),
    }
    metadata = build_run_metadata(
        status=status,
        failure_reason=failure_reason,
        prompt_package=prompt_package,
        prompt_path=prompt_path,
        model_path=model_path,
        model_name=model_name,
        generation_params=generation_params,
        started_at_utc=started_at_utc,
        finished_at_utc=finished_at_utc,
        runtime_seconds=time.perf_counter() - start_time,
        output_paths=output_paths,
        validation_result=validation_result,
        token_plan=token_plan,
        generation_response_metadata=generation_response_metadata,
    )
    write_json(context["metadata_path"], metadata)
    return metadata


#This function sends one batch of prompt messages to the loaded model backend.
def run_prompt_generation_batch(
    *,
    llm: Any,
    model_path: Path,
    model_name: str,
    output_dirs: dict[str, Path],
    generation_params: dict[str, Any],
    batch_items: list[dict[str, Any]],
    batch_index: int,
    batch_limit: int,
) -> list[dict[str, Any]]:
    messages_batch = [item["prompt_package"]["messages"] for item in batch_items]
    generation_params_batch = [item["prompt_generation_params"] for item in batch_items]
    batch_started = time.perf_counter()
    if hasattr(llm, "create_chat_completions_batch"):
        raw_texts = llm.create_chat_completions_batch(
            messages_batch=messages_batch,
            generation_params_batch=generation_params_batch,
        )
    else:
        raw_texts = []
        for item in batch_items:
            response_chunks = llm.create_chat_completion(
                messages=item["prompt_package"]["messages"],
                temperature=item["prompt_generation_params"]["temperature"],
                top_p=item["prompt_generation_params"]["top_p"],
                max_tokens=item["prompt_generation_params"]["max_tokens"],
                stream=True,
            )
            raw_texts.append("".join(extract_stream_chunk_text(chunk) for chunk in response_chunks))
    batch_runtime_seconds = time.perf_counter() - batch_started

    metadata_rows = []
    batch_size = len(batch_items)
    for item, raw_text in zip(batch_items, raw_texts):
        metadata_rows.append(
            write_generated_prompt_outputs(
                prompt_package=item["prompt_package"],
                prompt_path=item["prompt_path"],
                model_path=model_path,
                model_name=model_name,
                output_dirs=output_dirs,
                generation_params=generation_params,
                token_plan=item["token_plan"],
                raw_text=raw_text,
                started_at_utc=item["started_at_utc"],
                start_time=item["start_time"],
                batch_index=batch_index,
                batch_size=batch_size,
                batch_limit=batch_limit,
                batch_runtime_seconds=batch_runtime_seconds,
            )
        )
    return metadata_rows


#This function runs all selected prompts for one selected model.
def run_model_batch(
    *,
    model_path: Path,
    prompt_paths: list[Path],
    output_root: Path,
    run_id: str,
    generation_params: dict[str, Any],
    progress_every: int,
    heartbeat_seconds: int,
    llm_batch_size: int,
) -> dict[str, Any]:
    model_name = safe_model_name(model_path)
    output_dirs = prepare_model_output_dirs(output_root, model_name, run_id)
    print(f"[{datetime.now().isoformat(timespec='seconds')}] Loading model: {model_name}")
    llm = load_model(model_path, generation_params)

    accepted_count = 0
    failed_count = 0
    unsupported_no_editable_count = 0
    total_prompts = len(prompt_paths)
    model_start = time.perf_counter()
    pending_batch: list[dict[str, Any]] = []
    generation_batch_index = 0

    #This function updates per-model status counters from one prompt metadata record.
    def record_metadata(metadata: dict[str, Any]) -> None:
        nonlocal accepted_count
        nonlocal failed_count
        nonlocal unsupported_no_editable_count
        if metadata["status"] == "accepted":
            accepted_count += 1
        elif metadata.get("failure_reason") == "no_editable_regions_not_supported":
            unsupported_no_editable_count += 1
            failed_count += 1
        else:
            failed_count += 1

    #This function sends and records the currently accumulated generation batch.
    def flush_pending_batch(prompt_index: int) -> None:
        nonlocal generation_batch_index
        if not pending_batch:
            return
        generation_batch_index += 1
        batch_started = time.perf_counter()
        metadata_rows = run_prompt_generation_batch(
            llm=llm,
            model_path=model_path,
            model_name=model_name,
            output_dirs=output_dirs,
            generation_params=generation_params,
            batch_items=list(pending_batch),
            batch_index=generation_batch_index,
            batch_limit=llm_batch_size,
        )
        pending_batch.clear()
        for metadata in metadata_rows:
            record_metadata(metadata)
        print(
            f"[{datetime.now().isoformat(timespec='seconds')}] "
            f"{model_name}: generation batch {generation_batch_index} finished "
            f"(items={len(metadata_rows)}, last_batch={time.perf_counter() - batch_started:.1f}s, "
            f"processed={prompt_index}/{total_prompts}, accepted={accepted_count}, "
            f"failed={failed_count}, unsupported_no_editable={unsupported_no_editable_count})"
        )

    for prompt_index, prompt_path in enumerate(prompt_paths, start=1):
        prompt_started = time.perf_counter()
        if llm_batch_size <= 1:
            metadata = run_single_prompt(
                llm=llm,
                prompt_path=prompt_path,
                model_path=model_path,
                model_name=model_name,
                output_dirs=output_dirs,
                generation_params=generation_params,
                heartbeat_seconds=heartbeat_seconds,
                prompt_index=prompt_index,
                total_prompts=total_prompts,
            )
            record_metadata(metadata)
        else:
            prompt_package = validate_prompt_package(read_json(prompt_path), prompt_path)
            editable_region_count = get_editable_region_count(prompt_package)
            if editable_region_count == 0:
                metadata = run_single_prompt(
                    llm=llm,
                    prompt_path=prompt_path,
                    model_path=model_path,
                    model_name=model_name,
                    output_dirs=output_dirs,
                    generation_params=generation_params,
                    heartbeat_seconds=heartbeat_seconds,
                    prompt_index=prompt_index,
                    total_prompts=total_prompts,
                )
                record_metadata(metadata)
            else:
                prompt_generation_params, token_plan = build_prompt_generation_params(
                    llm=llm,
                    prompt_package=prompt_package,
                    base_generation_params=generation_params,
                )
                pending_batch.append(
                    {
                        "prompt_path": prompt_path,
                        "prompt_package": prompt_package,
                        "prompt_generation_params": prompt_generation_params,
                        "token_plan": token_plan,
                        "started_at_utc": datetime.now(timezone.utc).isoformat(),
                        "start_time": time.perf_counter(),
                    }
                )
                if len(pending_batch) >= llm_batch_size:
                    flush_pending_batch(prompt_index)

        should_print = (
            prompt_index == 1
            or prompt_index == total_prompts
            or (progress_every > 0 and prompt_index % progress_every == 0)
        )
        if should_print:
            elapsed = time.perf_counter() - model_start
            last_runtime = time.perf_counter() - prompt_started
            print(
                f"[{datetime.now().isoformat(timespec='seconds')}] "
                f"{model_name}: {prompt_index}/{total_prompts} prompts processed "
                f"(accepted={accepted_count}, failed={failed_count}, "
                f"unsupported_no_editable={unsupported_no_editable_count}, "
                f"last={last_runtime:.1f}s, elapsed={elapsed:.1f}s)"
            )

    flush_pending_batch(total_prompts)

    return {
        "model_name": model_name,
        "model_path": str(model_path),
        "run_id": run_id,
        "prompt_count": total_prompts,
        "accepted_count": accepted_count,
        "failed_count": failed_count,
        "unsupported_no_editable_count": unsupported_no_editable_count,
        "llm_batch_size": llm_batch_size,
        "runtime_seconds": time.perf_counter() - model_start,
    }


#This function orchestrates Step 17.
#It loads the prompt manifest, selects models, and runs each prompt independently for each model.
def run_llm_batch(args: argparse.Namespace) -> dict[str, Any]:
    config = load_json_config(args.config)
    validate_config(config)

    if args.limit_prompts_s17 is not None and args.limit_prompts_s17 <= 0:
        raise ValueError("--limit-prompts-s17 must be a positive integer when provided.")
    if args.progress_every < 0:
        raise ValueError("--progress-every must be zero or a positive integer.")
    if args.heartbeat_seconds < 0:
        raise ValueError("--heartbeat-seconds must be zero or a positive integer.")
    if args.llm_batch_size <= 0:
        raise ValueError("--llm-batch-size must be a positive integer.")
    if args.expected_output_patch_tokens is not None and args.expected_output_patch_tokens <= 0:
        raise ValueError("--expected-output-patch-tokens must be a positive integer.")
    run_id = args.run_id or build_default_run_id(args.run_label)
    paths = default_cloud_paths(config, args.cloud_root)
    output_root = Path(args.output_root).expanduser() if args.output_root else paths["output_root"]
    model_dir = Path(args.model_dir).expanduser() if args.model_dir else paths["model_dir"]

    prompt_paths = resolve_selected_prompt_paths(args, paths)
    model_paths = collect_model_paths(
        model_dir=model_dir,
        explicit_model_paths=args.model_path,
        model_filters=args.model_filter,
    )
    generation_params = build_generation_params(config, args)
    if generation_params["output_token_margin_percent"] < 0:
        raise ValueError("llm.output_token_margin_percent or --output-token-margin-percent must be zero or positive.")
    if generation_params["context_reserve_tokens"] < 0:
        raise ValueError("llm.context_reserve_tokens or --context-reserve-tokens must be zero or positive.")
    if generation_params["prompt_target_context"] <= 0:
        raise ValueError("llm.prompt_target_context must be a positive integer.")
    if generation_params["runtime_max_model_len"] <= 0:
        raise ValueError("llm.runtime_max_model_len or --runtime-max-model-len must be a positive integer.")
    if generation_params["expected_output_patch_tokens"] <= 0:
        raise ValueError("llm.expected_output_patch_tokens or --expected-output-patch-tokens must be positive.")
    if generation_params["min_n_ctx"] <= 0:
        raise ValueError("llm.min_n_ctx or --min-n-ctx must be a positive integer.")
    if generation_params["max_n_ctx"] <= 0:
        raise ValueError("llm.max_n_ctx or --max-n-ctx must be a positive integer.")
    if generation_params["min_n_ctx"] > generation_params["max_n_ctx"]:
        raise ValueError("llm.min_n_ctx cannot be larger than llm.max_n_ctx.")
    if generation_params["chars_per_token_estimate"] <= 0:
        raise ValueError("llm.chars_per_token_estimate or --chars-per-token-estimate must be greater than zero.")
    n_ctx_plan = estimate_dynamic_n_ctx(prompt_paths, generation_params)
    generation_params["n_ctx"] = n_ctx_plan["n_ctx"]
    generation_params["n_ctx_plan"] = n_ctx_plan

    print(f"Prompt source: {args.prompt_file or args.prompt_manifest or paths['prompt_manifest']}")
    print(f"Prompt files selected: {len(prompt_paths)}")
    print(f"Models selected: {len(model_paths)}")
    for model_path in model_paths:
        print(f"  - {model_path}")
    print(f"Output root: {output_root}")
    print(f"Run id: {run_id}")
    print(f"n_ctx plan: {n_ctx_plan}")
    print(f"Generation params: {generation_params}")

    summaries = []
    batch_start = time.perf_counter()
    for model_path in model_paths:
        summaries.append(
            run_model_batch(
                model_path=model_path,
                prompt_paths=prompt_paths,
                output_root=output_root,
                run_id=run_id,
                generation_params=generation_params,
                progress_every=args.progress_every,
                heartbeat_seconds=args.heartbeat_seconds,
                llm_batch_size=args.llm_batch_size,
            )
        )

    return {
        "prompt_source": str(args.prompt_file or args.prompt_manifest or paths["prompt_manifest"]),
        "prompt_count": len(prompt_paths),
        "model_count": len(model_paths),
        "model_summaries": summaries,
        "run_id": run_id,
        "n_ctx_plan": n_ctx_plan,
        "runtime_seconds": time.perf_counter() - batch_start,
        "output_root": str(output_root),
    }


#This function defines the command-line arguments accepted by Step 17.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run LLM models over Step 16 compact patch prompt units.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--prompt-file", help="Path to one Step 16 prompt_unit.prompt.json file.")
    parser.add_argument("--prompt-manifest", help="Path to Step 16 prompt_units_manifest_v1.json.")
    parser.add_argument("--prompt-dir", help="Directory containing Step 16 prompt_unit.prompt.json files.")
    parser.add_argument("--output-root", help="Directory where Step 17 model outputs will be written.")
    parser.add_argument("--cloud-root", default=str(DEFAULT_CLOUD_ROOT), help="RISE cloud root for default paths.")
    parser.add_argument("--model-dir", help="Directory containing vLLM-loadable local model directories.")
    parser.add_argument("--model-path", action="append", help="Specific vLLM-loadable model path to run. Can be repeated.")
    parser.add_argument(
        "--model-filter",
        action="append",
        help="Run only discovered/selected model paths containing this text. Can be repeated.",
    )
    parser.add_argument("--limit-prompts-s17", type=int, help="Run only the first N Step 16 prompt units for smoke tests.")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print progress every N prompts per model. Use 0 to print only first and last prompt.",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=int,
        default=60,
        help="Print a heartbeat every N seconds during each blocking model generation. Use 0 to disable.",
    )
    parser.add_argument("--run-id", help="Explicit run id under 07_llm_outputs/<model>/<run_id>.")
    parser.add_argument("--run-label", help="Optional label appended to an automatically generated run id.")
    parser.add_argument("--temperature", type=float, help="Override llm.temperature from config.")
    parser.add_argument("--top-p", type=float, help="Override llm.top_p from config.")
    parser.add_argument(
        "--output-token-margin-percent",
        type=float,
        help="Legacy override kept for old metadata; compact patch prompts use expected_output_patch_tokens.",
    )
    parser.add_argument(
        "--context-reserve-tokens",
        type=int,
        help="Override llm.context_reserve_tokens for context-window budgeting.",
    )
    parser.add_argument(
        "--n-ctx",
        type=int,
        help="Fixed backend context window size. Overrides runtime_max_model_len.",
    )
    parser.add_argument(
        "--runtime-max-model-len",
        type=int,
        help="Hard backend context cap used by vLLM max_model_len.",
    )
    parser.add_argument(
        "--expected-output-patch-tokens",
        type=int,
        help="Expected maximum patch-output token budget for compact patch prompting.",
    )
    parser.add_argument(
        "--min-n-ctx",
        type=int,
        help="Override llm.min_n_ctx for dynamic prompt preflight.",
    )
    parser.add_argument(
        "--max-n-ctx",
        type=int,
        help="Override llm.max_n_ctx for dynamic prompt preflight.",
    )
    parser.add_argument(
        "--chars-per-token-estimate",
        type=float,
        help="Override llm.chars_per_token_estimate for dynamic n_ctx preflight before model loading.",
    )
    parser.add_argument("--llm-batch-size", type=int, default=1, help="Maximum number of real LLM prompt units per generation batch.")
    return parser.parse_args()


#This is the command-line entry point. It runs the batch and prints a short execution summary.
def main() -> None:
    args = parse_cli_args()
    summary = run_llm_batch(args)
    print("Step 17 batch finished.")
    print(f"Prompt files processed per model: {summary['prompt_count']}")
    print(f"Models processed: {summary['model_count']}")
    print(f"Total runtime seconds: {summary['runtime_seconds']:.1f}")
    print(f"Output root: {summary['output_root']}")


if __name__ == "__main__":
    main()
