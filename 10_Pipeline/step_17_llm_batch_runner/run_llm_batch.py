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
        "prompt_manifest": root / "02_OutputFiles" / experiment_id / "06_prompts" / "prompt_manifest.json",
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
    prompts = prompt_manifest.get("prompts")
    if not isinstance(prompts, list):
        raise ValueError(f"Prompt manifest must contain a prompts list: {manifest_path}")
    return prompt_manifest


#This function validates the basic shape of one Step 16 prompt package.
def validate_prompt_package(prompt_package: Any, prompt_path: Path) -> dict[str, Any]:
    if not isinstance(prompt_package, dict):
        raise ValueError(f"Prompt package root must be an object: {prompt_path}")
    messages = prompt_package.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError(f"Prompt package must contain a non-empty messages list: {prompt_path}")
    traceability = prompt_package.get("input_traceability")
    if not isinstance(traceability, dict):
        raise ValueError(f"Prompt package must contain input_traceability object: {prompt_path}")
    return prompt_package


#This function resolves a prompt package path from a prompt manifest entry.
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

    group_id = prompt_entry.get("group_id")
    if isinstance(group_id, str) and group_id:
        fallback_path = prompt_dir / f"{group_id}.prompt.json"
        if fallback_path.exists():
            return fallback_path

    raise FileNotFoundError(f"Could not resolve prompt file for manifest entry: {prompt_entry}")


#This function reads the prompt manifest and returns the ordered prompt paths selected for this run.
def collect_prompt_paths(
    *,
    prompt_manifest_path: Path,
    prompt_dir: Path,
    limit_prompts: int | None,
) -> list[Path]:
    prompt_manifest = validate_prompt_manifest(read_json(prompt_manifest_path), prompt_manifest_path)
    prompt_entries = prompt_manifest["prompts"]
    selected_entries = prompt_entries[:limit_prompts] if limit_prompts is not None else prompt_entries

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
    if args.prompt_file and args.limit_prompts is not None:
        raise ValueError("--limit-prompts is only valid with prompt manifest mode.")

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
        limit_prompts=args.limit_prompts,
    )


#This function normalises a model name so it is safe to use as a folder name.
def safe_model_name(model_path: Path) -> str:
    name = model_path.stem
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    return name.strip("_") or "model"


#This function discovers GGUF models in the configured model directory.
def discover_model_paths(model_dir: Path) -> list[Path]:
    if not model_dir.exists():
        raise FileNotFoundError(f"Model directory does not exist: {model_dir}")
    model_paths = sorted(model_dir.glob("*.gguf"))
    if not model_paths:
        raise FileNotFoundError(f"No .gguf models found in model directory: {model_dir}")
    return model_paths


#This function resolves the model paths selected for this run.
#By default it runs all GGUF models found in the model directory, which should be the two benchmark models.
def collect_model_paths(
    *,
    model_dir: Path,
    explicit_model_paths: list[str] | None,
    model_filters: list[str] | None,
) -> list[Path]:
    if explicit_model_paths:
        model_paths = [Path(path).expanduser() for path in explicit_model_paths]
    else:
        model_paths = discover_model_paths(model_dir)

    if model_filters:
        lowered_filters = [model_filter.lower() for model_filter in model_filters]
        model_paths = [
            model_path
            for model_path in model_paths
            if any(model_filter in str(model_path).lower() for model_filter in lowered_filters)
        ]

    missing_paths = [str(model_path) for model_path in model_paths if not model_path.exists()]
    if missing_paths:
        joined = "\n".join(missing_paths)
        raise FileNotFoundError(f"Selected model path(s) do not exist:\n{joined}")
    if not model_paths:
        raise ValueError("No models selected. Check --model-path, --model-dir, or --model-filter.")
    return model_paths


#This function creates the output folders for a model.
def prepare_model_output_dirs(output_root: Path, model_name: str) -> dict[str, Path]:
    model_root = output_root / model_name
    paths = {subdir: model_root / subdir for subdir in MODEL_OUTPUT_SUBDIRS}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


#This function returns the generation parameters used by llama-cpp-python.
def build_generation_params(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    llm_config = config.get("llm", {})
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
            else int(llm_config.get("context_reserve_tokens", 128))
        ),
        "n_ctx": args.n_ctx,
        "n_ctx_mode": "fixed_cli" if args.n_ctx is not None else "dynamic_prompt_preflight",
        "min_n_ctx": args.min_n_ctx if args.min_n_ctx is not None else int(llm_config.get("min_n_ctx", 2048)),
        "max_n_ctx": args.max_n_ctx if args.max_n_ctx is not None else int(llm_config.get("max_n_ctx", 32768)),
        "chars_per_token_estimate": (
            args.chars_per_token_estimate
            if args.chars_per_token_estimate is not None
            else float(llm_config.get("chars_per_token_estimate", 3.0))
        ),
        "n_gpu_layers": args.n_gpu_layers,
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
#It mirrors the old Ping Mallory prototype and is only used for choosing an initial n_ctx.
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
#A single n_ctx is selected for the whole run because llama-cpp-python fixes n_ctx when the model is loaded.
def estimate_dynamic_n_ctx(prompt_paths: list[Path], generation_params: dict[str, Any]) -> dict[str, Any]:
    if generation_params["n_ctx"] is not None:
        return {
            "mode": "fixed_cli",
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
        output_tokens_estimate = max(
            1,
            math.ceil(
                input_tokens_estimate
                * (1.0 + float(generation_params["output_token_margin_percent"]) / 100.0)
            ),
        )
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


#This function estimates how many tokens the current prompt messages occupy for the loaded model.
def estimate_input_tokens(llm: Any, messages: list[dict[str, Any]]) -> int:
    estimation_text = messages_to_estimation_text(messages)
    try:
        tokens = llm.tokenize(estimation_text.encode("utf-8"), add_bos=True)
    except TypeError:
        tokens = llm.tokenize(estimation_text.encode("utf-8"))
    return len(tokens)


#This function calculates max_tokens for one prompt from estimated input tokens and a configurable margin.
def build_prompt_generation_params(
    *,
    llm: Any,
    prompt_package: dict[str, Any],
    base_generation_params: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt_generation_params = dict(base_generation_params)
    input_tokens_estimate = estimate_input_tokens(llm, prompt_package["messages"])

    margin_percent = float(base_generation_params["output_token_margin_percent"])
    desired_max_tokens = max(1, math.ceil(input_tokens_estimate * (1.0 + margin_percent / 100.0)))
    available_context_tokens = (
        int(base_generation_params["n_ctx"])
        - input_tokens_estimate
        - int(base_generation_params["context_reserve_tokens"])
    )
    if available_context_tokens <= 0:
        raise ValueError(
            "Prompt does not fit in the configured context window after reserve tokens. "
            f"input_tokens_estimate={input_tokens_estimate}, "
            f"n_ctx={base_generation_params['n_ctx']}, "
            f"context_reserve_tokens={base_generation_params['context_reserve_tokens']}"
        )

    max_tokens = min(desired_max_tokens, available_context_tokens)
    prompt_generation_params["max_tokens"] = max_tokens
    token_plan = {
        "mode": "dynamic_input_tokens_plus_margin",
        "input_tokens_estimate": input_tokens_estimate,
        "desired_max_tokens": desired_max_tokens,
        "max_tokens": max_tokens,
        "output_token_margin_percent": margin_percent,
        "context_reserve_tokens": base_generation_params["context_reserve_tokens"],
        "available_context_tokens": available_context_tokens,
        "was_capped_by_context": max_tokens < desired_max_tokens,
    }
    return prompt_generation_params, token_plan


#This function extracts the text response from the llama-cpp-python chat completion response.
def extract_response_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("llama-cpp-python response did not contain choices.")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise ValueError("llama-cpp-python first choice is not an object.")
    message = first_choice.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    if isinstance(first_choice.get("text"), str):
        return first_choice["text"]
    raise ValueError("llama-cpp-python response did not contain message content.")


#This function starts a small heartbeat thread while a blocking model generation call is running.
#It gives terminal feedback even when one prompt takes a long time to finish.
def start_generation_heartbeat(
    *,
    model_name: str,
    group_id: str,
    heartbeat_seconds: int,
) -> tuple[threading.Event, threading.Thread | None]:
    stop_event = threading.Event()
    if heartbeat_seconds <= 0:
        return stop_event, None

    def heartbeat_loop() -> None:
        while not stop_event.wait(heartbeat_seconds):
            print(
                f"[{datetime.now().isoformat(timespec='seconds')}] "
                f"{model_name}: still generating response for {group_id}"
            )

    thread = threading.Thread(target=heartbeat_loop, daemon=True)
    thread.start()
    return stop_event, thread


#This function parses the model response as strict JSON.
#Text before or after the JSON object is rejected by json.loads.
def parse_strict_json(raw_text: str) -> Any:
    return json.loads(raw_text)


#This function validates basic traceability using the Step 16 input_traceability block.
def validate_traceability(parsed_output: Any, prompt_package: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parsed_output, dict):
        return {"accepted": False, "reason": "parsed_output_root_not_object"}

    traffic = parsed_output.get("traffic")
    if not isinstance(traffic, list):
        return {"accepted": False, "reason": "missing_or_invalid_traffic_list"}

    traceability = prompt_package["input_traceability"]
    expected_count = traceability.get("traffic_record_count")
    if len(traffic) != expected_count:
        return {
            "accepted": False,
            "reason": "traffic_record_count_changed",
            "expected_count": expected_count,
            "actual_count": len(traffic),
        }

    immutable_fields = traceability.get("immutable_fields", [])
    trace_records = traceability.get("records", [])
    if not isinstance(immutable_fields, list) or not isinstance(trace_records, list):
        return {"accepted": False, "reason": "invalid_input_traceability_shape"}

    for record_index, expected_record in enumerate(trace_records):
        if record_index >= len(traffic) or not isinstance(traffic[record_index], dict):
            return {"accepted": False, "reason": "traffic_record_not_object", "record_index": record_index + 1}
        expected_identity = expected_record.get("immutable_identity", {})
        actual_record = traffic[record_index]
        for field in immutable_fields:
            expected_value = expected_identity.get(field)
            actual_value = actual_record.get(field)
            if actual_value != expected_value:
                return {
                    "accepted": False,
                    "reason": "immutable_field_changed",
                    "record_index": record_index + 1,
                    "field": field,
                    "expected_value": expected_value,
                    "actual_value": actual_value,
                }

    return {"accepted": True, "reason": "accepted"}


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
    llama_response_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "status": status,
        "failure_reason": failure_reason,
        "experiment_id": prompt_package.get("experiment_id"),
        "group_id": prompt_package.get("group_id"),
        "prompt_version": prompt_package.get("prompt_version"),
        "prompt_file": str(prompt_path),
        "input_group_file": prompt_package.get("input_group_file"),
        "model_name": model_name,
        "model_path": str(model_path),
        "generation_params": generation_params,
        "token_plan": token_plan,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "runtime_seconds": runtime_seconds,
        "output_paths": output_paths,
        "validation_result": validation_result,
        "llama_response_metadata": llama_response_metadata,
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
#Each call uses only the messages from the current prompt package, so no previous prompt context is carried forward.
def run_single_prompt(
    *,
    llm: Any,
    prompt_path: Path,
    model_path: Path,
    model_name: str,
    output_dirs: dict[str, Path],
    generation_params: dict[str, Any],
    heartbeat_seconds: int,
) -> dict[str, Any]:
    prompt_package = validate_prompt_package(read_json(prompt_path), prompt_path)
    group_id = str(prompt_package.get("group_id") or prompt_path.stem.replace(".prompt", ""))
    output_stem = group_id
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
    llama_response_metadata = None
    token_plan = None
    output_paths: dict[str, str] = {}

    try:
        prompt_generation_params, token_plan = build_prompt_generation_params(
            llm=llm,
            prompt_package=prompt_package,
            base_generation_params=generation_params,
        )
        heartbeat_stop, heartbeat_thread = start_generation_heartbeat(
            model_name=model_name,
            group_id=group_id,
            heartbeat_seconds=heartbeat_seconds,
        )
        try:
            response = llm.create_chat_completion(
                messages=prompt_package["messages"],
                temperature=prompt_generation_params["temperature"],
                top_p=prompt_generation_params["top_p"],
                max_tokens=prompt_generation_params["max_tokens"],
            )
        finally:
            heartbeat_stop.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=1)

        raw_text = extract_response_text(response)
        write_text(raw_path, raw_text)
        output_paths["raw"] = str(raw_path)
        llama_response_metadata = {
            key: value
            for key, value in response.items()
            if key != "choices"
        }

        parsed_output = parse_strict_json(raw_text)
        validation_result = validate_traceability(parsed_output, prompt_package)
        if validation_result["accepted"]:
            write_json(parsed_path, parsed_output)
            output_paths["parsed"] = str(parsed_path)
            status = "accepted"
        else:
            failure_reason = validation_result["reason"]
            failure_report = {
                "failure_reason": failure_reason,
                "group_id": group_id,
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
            "group_id": group_id,
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
        llama_response_metadata=llama_response_metadata,
    )
    write_json(metadata_path, metadata)
    return metadata


#This function loads one GGUF model through llama-cpp-python.
def load_llama_model(model_path: Path, generation_params: dict[str, Any]) -> Any:
    from llama_cpp import Llama

    return Llama(
        model_path=str(model_path),
        n_ctx=generation_params["n_ctx"],
        n_gpu_layers=generation_params["n_gpu_layers"],
        verbose=False,
    )


#This function runs all selected prompts for one selected model.
def run_model_batch(
    *,
    model_path: Path,
    prompt_paths: list[Path],
    output_root: Path,
    generation_params: dict[str, Any],
    progress_every: int,
    heartbeat_seconds: int,
) -> dict[str, Any]:
    model_name = safe_model_name(model_path)
    output_dirs = prepare_model_output_dirs(output_root, model_name)
    print(f"[{datetime.now().isoformat(timespec='seconds')}] Loading model: {model_name}")
    llm = load_llama_model(model_path, generation_params)

    accepted_count = 0
    failed_count = 0
    total_prompts = len(prompt_paths)
    model_start = time.perf_counter()

    for prompt_index, prompt_path in enumerate(prompt_paths, start=1):
        prompt_started = time.perf_counter()
        metadata = run_single_prompt(
            llm=llm,
            prompt_path=prompt_path,
            model_path=model_path,
            model_name=model_name,
            output_dirs=output_dirs,
            generation_params=generation_params,
            heartbeat_seconds=heartbeat_seconds,
        )
        if metadata["status"] == "accepted":
            accepted_count += 1
        else:
            failed_count += 1

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
                f"last={last_runtime:.1f}s, elapsed={elapsed:.1f}s)"
            )

    return {
        "model_name": model_name,
        "model_path": str(model_path),
        "prompt_count": total_prompts,
        "accepted_count": accepted_count,
        "failed_count": failed_count,
        "runtime_seconds": time.perf_counter() - model_start,
    }


#This function orchestrates Step 17.
#It loads the prompt manifest, selects models, and runs each prompt independently for each model.
def run_llm_batch(args: argparse.Namespace) -> dict[str, Any]:
    config = load_json_config(args.config)
    validate_config(config)

    if args.limit_prompts is not None and args.limit_prompts <= 0:
        raise ValueError("--limit-prompts must be a positive integer when provided.")
    if args.progress_every < 0:
        raise ValueError("--progress-every must be zero or a positive integer.")
    if args.heartbeat_seconds < 0:
        raise ValueError("--heartbeat-seconds must be zero or a positive integer.")
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
                generation_params=generation_params,
                progress_every=args.progress_every,
                heartbeat_seconds=args.heartbeat_seconds,
            )
        )

    return {
        "prompt_source": str(args.prompt_file or args.prompt_manifest or paths["prompt_manifest"]),
        "prompt_count": len(prompt_paths),
        "model_count": len(model_paths),
        "model_summaries": summaries,
        "n_ctx_plan": n_ctx_plan,
        "runtime_seconds": time.perf_counter() - batch_start,
        "output_root": str(output_root),
    }


#This function defines the command-line arguments accepted by Step 17.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run GGUF LLM models over Step 16 prompt packages.")
    parser.add_argument("--config", required=True, help="Path to the experiment JSON config.")
    parser.add_argument("--prompt-file", help="Path to one Step 16 group_XXXXXX.prompt.json file.")
    parser.add_argument("--prompt-manifest", help="Path to Step 16 prompt_manifest.json.")
    parser.add_argument("--prompt-dir", help="Directory containing Step 16 group_XXXXXX.prompt.json files.")
    parser.add_argument("--output-root", help="Directory where Step 17 model outputs will be written.")
    parser.add_argument("--cloud-root", default=str(DEFAULT_CLOUD_ROOT), help="RISE cloud root for default paths.")
    parser.add_argument("--model-dir", help="Directory containing GGUF model files.")
    parser.add_argument("--model-path", action="append", help="Specific GGUF model path to run. Can be repeated.")
    parser.add_argument(
        "--model-filter",
        action="append",
        help="Run only discovered/selected model paths containing this text. Can be repeated.",
    )
    parser.add_argument("--limit-prompts", type=int, help="Run only the first N prompt files for smoke tests.")
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
    parser.add_argument("--temperature", type=float, help="Override llm.temperature from config.")
    parser.add_argument("--top-p", type=float, help="Override llm.top_p from config.")
    parser.add_argument(
        "--output-token-margin-percent",
        type=float,
        help="Override llm.output_token_margin_percent for dynamic max_tokens.",
    )
    parser.add_argument(
        "--context-reserve-tokens",
        type=int,
        help="Override llm.context_reserve_tokens for context-window budgeting.",
    )
    parser.add_argument(
        "--n-ctx",
        type=int,
        help="Fixed llama-cpp-python context window size. If omitted, Step 17 estimates n_ctx from selected prompts.",
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
    parser.add_argument("--n-gpu-layers", type=int, default=-1, help="llama-cpp-python GPU layer count.")
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
