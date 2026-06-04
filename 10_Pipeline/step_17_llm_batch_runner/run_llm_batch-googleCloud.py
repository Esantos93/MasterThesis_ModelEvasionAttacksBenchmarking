from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


#This Google Cloud runner keeps the original Step 17 validation/output logic, but replaces llama-cpp-python with vLLM.
#It is meant for modern GPU instances such as NVIDIA L4/A100 where Hugging Face models are preferable to GGUF files.

STEP17_DIR = Path(__file__).resolve().parent
if str(STEP17_DIR) not in sys.path:
    sys.path.insert(0, str(STEP17_DIR))

import run_llm_batch as base_step17  # noqa: E402


VLLM_MODEL_IDS: list[str] | None = None
VLLM_DTYPE: str = "auto"
VLLM_QUANTIZATION: str | None = None
VLLM_GPU_MEMORY_UTILIZATION: float = 0.90
VLLM_MAX_MODEL_LEN: int | None = None
VLLM_TRUST_REMOTE_CODE: bool = False


class VllmChatCompletionAdapter:
    def __init__(self, model_id: str) -> None:
        from vllm import LLM

        kwargs: dict[str, Any] = {
            "model": model_id,
            "dtype": VLLM_DTYPE,
            "gpu_memory_utilization": VLLM_GPU_MEMORY_UTILIZATION,
            "trust_remote_code": VLLM_TRUST_REMOTE_CODE,
        }
        if VLLM_QUANTIZATION:
            kwargs["quantization"] = VLLM_QUANTIZATION
        if VLLM_MAX_MODEL_LEN:
            kwargs["max_model_len"] = VLLM_MAX_MODEL_LEN
        self.model_id = model_id
        self.llm = LLM(**kwargs)

    def create_chat_completion(
        self,
        *,
        messages: list[dict[str, str]],
        temperature: float,
        top_p: float,
        max_tokens: int,
        stream: bool,
    ) -> Any:
        from vllm import SamplingParams

        sampling_params = SamplingParams(
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
        )
        outputs = self.llm.chat(messages=messages, sampling_params=sampling_params, use_tqdm=False)
        text = outputs[0].outputs[0].text if outputs and outputs[0].outputs else ""
        if not stream:
            return {"choices": [{"message": {"content": text}}]}
        return iter([{"choices": [{"delta": {"content": text}}]}])


def collect_vllm_model_paths(
    *,
    model_dir: Path,
    explicit_model_paths: list[str] | None,
    model_filters: list[str] | None,
) -> list[Path]:
    if VLLM_MODEL_IDS:
        selected = [Path(model_id) for model_id in VLLM_MODEL_IDS]
    elif explicit_model_paths:
        selected = [Path(path).expanduser() for path in explicit_model_paths]
    else:
        if not model_dir.exists():
            raise FileNotFoundError(f"Model directory does not exist: {model_dir}")
        selected = sorted(path for path in model_dir.iterdir() if path.is_dir())

    if model_filters:
        lowered_filters = [model_filter.lower() for model_filter in model_filters]
        selected = [
            model_path
            for model_path in selected
            if any(model_filter in str(model_path).lower() for model_filter in lowered_filters)
        ]
    if not selected:
        raise ValueError("No vLLM models selected. Use --hf-model-id, --model-path, --model-dir, or --model-filter.")
    return selected


def load_vllm_model(model_path: Path, generation_params: dict[str, Any]) -> VllmChatCompletionAdapter:
    return VllmChatCompletionAdapter(str(model_path))


def parse_google_cloud_args() -> argparse.Namespace:
    extra_parser = argparse.ArgumentParser(add_help=False)
    extra_parser.add_argument("--hf-model-id", action="append", help="Hugging Face model id to load with vLLM. Can be repeated.")
    extra_parser.add_argument("--vllm-dtype", default="auto", help="vLLM dtype, for example auto, half, bfloat16, or float16.")
    extra_parser.add_argument("--vllm-quantization", help="vLLM quantization method, for example awq, gptq, or bitsandbytes.")
    extra_parser.add_argument("--vllm-gpu-memory-utilization", type=float, default=0.90)
    extra_parser.add_argument("--vllm-max-model-len", type=int)
    extra_parser.add_argument("--trust-remote-code", action="store_true")
    extra_args, remaining_argv = extra_parser.parse_known_args()

    original_argv = sys.argv
    try:
        sys.argv = [sys.argv[0], *remaining_argv]
        args = base_step17.parse_cli_args()
    finally:
        sys.argv = original_argv

    for key, value in vars(extra_args).items():
        setattr(args, key, value)
    return args


def main() -> None:
    global VLLM_MODEL_IDS
    global VLLM_DTYPE
    global VLLM_QUANTIZATION
    global VLLM_GPU_MEMORY_UTILIZATION
    global VLLM_MAX_MODEL_LEN
    global VLLM_TRUST_REMOTE_CODE

    args = parse_google_cloud_args()
    VLLM_MODEL_IDS = args.hf_model_id
    VLLM_DTYPE = args.vllm_dtype
    VLLM_QUANTIZATION = args.vllm_quantization
    VLLM_GPU_MEMORY_UTILIZATION = args.vllm_gpu_memory_utilization
    VLLM_MAX_MODEL_LEN = args.vllm_max_model_len
    VLLM_TRUST_REMOTE_CODE = args.trust_remote_code

    base_step17.collect_model_paths = collect_vllm_model_paths
    base_step17.load_llama_model = load_vllm_model

    summary = base_step17.run_llm_batch(args)
    print("Step 17 vLLM batch finished.")
    print(f"Prompt files processed per model: {summary['prompt_count']}")
    print(f"Models processed: {summary['model_count']}")
    print(f"Total runtime seconds: {summary['runtime_seconds']:.1f}")
    print(f"Output root: {summary['output_root']}")


if __name__ == "__main__":
    main()
