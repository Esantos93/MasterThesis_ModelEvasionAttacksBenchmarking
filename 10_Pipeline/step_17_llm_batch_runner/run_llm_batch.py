from __future__ import annotations

# Adapted from 90_Testing/94_llama_cpp_python/Test_Models_PingMallory.py.

import argparse
import json
import math
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from llama_cpp import ChatCompletionRequestMessage, Llama
except ImportError:  # pragma: no cover - handled at runtime on the VM
    ChatCompletionRequestMessage = dict  # type: ignore[misc,assignment]
    Llama = None  # type: ignore[assignment]


PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.io_utils import write_json


DEFAULT_IDENTITY_FIELDS = [
    "packet_id",
    "record_id",
    "original_packet_number",
    "flow_id",
    "group_id",
]


def get_dynamic_n_ctx(input_path: Path, max_tokens_response: int) -> int:
    char_count = input_path.stat().st_size
    estimated_tokens = (char_count // 3) + max_tokens_response
    if estimated_tokens <= 2048:
        return 2048

    power = math.ceil(math.log2(estimated_tokens))
    dynamic_ctx = int(2**power)
    return min(dynamic_ctx, 32768)


def sanitize_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return sanitized.strip("_") or "model"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8") as input_file:
        return input_file.read()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        output_file.write(text)
        if not text.endswith("\n"):
            output_file.write("\n")


def resolve_experiment_root(config: dict[str, Any]) -> Path:
    experiment = config.get("experiment", {})
    output_root = Path(experiment["output_root"]).expanduser()
    experiment_id = experiment["experiment_id"]
    return output_root / experiment_id


def load_config(config_path: Path | None) -> dict[str, Any]:
    if config_path is None:
        return {}
    config = read_json(config_path)
    if not isinstance(config, dict):
        raise ValueError(f"Config root must be a JSON object: {config_path}")
    return config


def build_messages_from_input_json(
    input_json_path: Path,
    prompt_version: str,
    identity_fields: list[str],
) -> list[ChatCompletionRequestMessage]:
    original_json_data = read_text(input_json_path)
    identity_fields_text = ", ".join(identity_fields)
    user_content = (
        "Read the following network traffic JSON and modify the traffic to reduce "
        "Snort 3 detection while preserving the original traffic structure. "
        f"Prompt version: {prompt_version}. "
        f"Do not modify these identity fields when present: {identity_fields_text}. "
        "Return only one valid JSON object. Do not include explanations, Markdown, "
        "or text outside the JSON object.\n\n"
        f"{original_json_data}"
    )
    return [
        {
            "role": "user",
            "content": user_content,
        }
    ]


def load_messages_from_prompt_file(prompt_file: Path) -> tuple[list[ChatCompletionRequestMessage], dict[str, Any]]:
    prompt_package = read_json(prompt_file)
    if not isinstance(prompt_package, dict):
        raise ValueError(f"Prompt file root must be a JSON object: {prompt_file}")
    messages = prompt_package.get("messages")
    if not isinstance(messages, list):
        raise ValueError(f"Prompt file must contain a messages list: {prompt_file}")
    return messages, prompt_package


def parse_model_response(text_response: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(text_response), None
    except json.JSONDecodeError as exc:
        return None, f"{exc.msg} at line {exc.lineno}, column {exc.colno}"


def extract_text_response(completion: dict[str, Any]) -> str:
    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("Model response does not contain choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("Model response choice does not contain a message object")
    content = message.get("content")
    if not isinstance(content, str):
        raise ValueError("Model response message content is not a string")
    return content


def build_output_paths(output_root: Path, model_name: str, run_id: str) -> dict[str, Path]:
    model_dir = output_root / sanitize_name(model_name)
    return {
        "raw": model_dir / "raw" / f"{run_id}.txt",
        "parsed": model_dir / "parsed" / f"{run_id}.json",
        "metadata": model_dir / "metadata" / f"{run_id}.json",
        "failure": model_dir / "failures" / f"{run_id}.json",
    }


def run_one_prompt(
    *,
    messages: list[ChatCompletionRequestMessage],
    output_root: Path,
    model_path: Path,
    model_name: str,
    run_id: str,
    n_ctx: int,
    max_tokens: int,
    temperature: float,
    top_p: float,
    n_gpu_layers: int,
    source_info: dict[str, Any],
) -> dict[str, Any]:
    if Llama is None:
        raise RuntimeError("llama-cpp-python is not installed in this Python environment")

    output_paths = build_output_paths(output_root, model_name, run_id)
    metadata: dict[str, Any] = {
        "run_id": run_id,
        "started_at": utc_now(),
        "model_name": model_name,
        "model_path": str(model_path),
        "n_ctx": n_ctx,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "n_gpu_layers": n_gpu_layers,
        "source": source_info,
        "outputs": {key: str(path) for key, path in output_paths.items()},
    }

    llm = Llama(
        model_path=str(model_path),
        n_gpu_layers=n_gpu_layers,
        n_ctx=n_ctx,
        add_bos=False,
        verbose=False,
    )

    try:
        generation_start = time.time()
        completion = llm.create_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            stream=False,
            response_format={"type": "json_object"},
        )
        duration_seconds = time.time() - generation_start
    finally:
        del llm

    if not isinstance(completion, dict):
        raise ValueError("llama-cpp-python returned a non-dictionary response")

    text_response = extract_text_response(completion)
    write_text(output_paths["raw"], text_response)

    parsed_json, parse_error = parse_model_response(text_response)
    metadata["finished_at"] = utc_now()
    metadata["duration_seconds"] = round(duration_seconds, 3)
    metadata["raw_response_chars"] = len(text_response)
    metadata["llama_cpp_response_metadata"] = {
        key: value for key, value in completion.items() if key != "choices"
    }

    if parse_error is None:
        write_json(output_paths["parsed"], parsed_json)
        metadata["status"] = "parsed"
    else:
        failure = {
            "run_id": run_id,
            "failure_type": "json_parse_error",
            "failure_reason": parse_error,
            "raw_output_path": str(output_paths["raw"]),
            "recorded_at": utc_now(),
        }
        write_json(output_paths["failure"], failure)
        metadata["status"] = "failed"
        metadata["failure_path"] = str(output_paths["failure"])
        metadata["failure_reason"] = parse_error

    write_json(output_paths["metadata"], metadata)
    return metadata


def make_run_id(source_path: Path, model_name: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{source_path.stem}_{sanitize_name(model_name)}_{timestamp}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one traffic-modification prompt through a local GGUF model with llama-cpp-python."
    )
    parser.add_argument("--config", type=Path, help="Pipeline JSON config with experiment and llm sections.")
    parser.add_argument("--prompt-file", type=Path, help="Prompt package JSON produced by step_16.")
    parser.add_argument("--input-json", type=Path, help="Manual traffic JSON input used to build a baseline prompt.")
    parser.add_argument("--output-root", type=Path, help="Override output root. Defaults to <experiment>/07_llm_outputs.")
    parser.add_argument("--model-path", type=Path, help="Override GGUF model path.")
    parser.add_argument("--model-name", help="Override model name.")
    parser.add_argument("--prompt-version", default="baseline_v1")
    parser.add_argument("--max-tokens", type=int, help="Override max output tokens.")
    parser.add_argument("--temperature", type=float, help="Override sampling temperature.")
    parser.add_argument("--top-p", type=float, help="Override top_p.")
    parser.add_argument("--n-ctx", type=int, help="Override context window.")
    parser.add_argument("--n-gpu-layers", type=int, default=-1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if bool(args.prompt_file) == bool(args.input_json):
        raise SystemExit("Provide exactly one of --prompt-file or --input-json.")

    config = load_config(args.config)
    llm_config = config.get("llm", {}) if isinstance(config.get("llm", {}), dict) else {}

    model_path = args.model_path or Path(llm_config.get("model_path", ""))
    model_name = args.model_name or llm_config.get("model_name") or model_path.stem
    max_tokens = args.max_tokens or int(llm_config.get("max_tokens", 3000))
    temperature = args.temperature if args.temperature is not None else float(llm_config.get("temperature", 0.0))
    top_p = args.top_p if args.top_p is not None else float(llm_config.get("top_p", 0.95))
    prompt_version = args.prompt_version or llm_config.get("prompt_version", "baseline_v1")

    if not str(model_path):
        raise SystemExit("A model path is required through --model-path or config llm.model_path.")
    if not model_path.expanduser().exists():
        raise SystemExit(f"Model path does not exist: {model_path}")

    if args.output_root:
        output_root = args.output_root
    elif config:
        output_root = resolve_experiment_root(config) / "07_llm_outputs"
    else:
        output_root = Path("07_llm_outputs")

    if args.prompt_file:
        source_path = args.prompt_file
        messages, prompt_package = load_messages_from_prompt_file(args.prompt_file)
        source_info = {
            "mode": "prompt_file",
            "prompt_file": str(args.prompt_file),
            "experiment_id": prompt_package.get("experiment_id"),
            "group_id": prompt_package.get("group_id"),
            "prompt_version": prompt_package.get("prompt_version", prompt_version),
        }
    else:
        source_path = args.input_json
        identity_fields = list(llm_config.get("identity_fields", DEFAULT_IDENTITY_FIELDS))
        messages = build_messages_from_input_json(args.input_json, prompt_version, identity_fields)
        source_info = {
            "mode": "input_json",
            "input_json": str(args.input_json),
            "prompt_version": prompt_version,
            "identity_fields": identity_fields,
        }

    n_ctx = args.n_ctx or get_dynamic_n_ctx(source_path, max_tokens)
    run_id = make_run_id(source_path, model_name)
    metadata = run_one_prompt(
        messages=messages,
        output_root=output_root,
        model_path=model_path.expanduser(),
        model_name=model_name,
        run_id=run_id,
        n_ctx=n_ctx,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        n_gpu_layers=args.n_gpu_layers,
        source_info=source_info,
    )

    print(f"LLM run finished with status: {metadata['status']}")
    print(f"Metadata written to: {metadata['outputs']['metadata']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
