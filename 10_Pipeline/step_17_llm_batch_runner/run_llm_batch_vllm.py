from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


#This vLLM runner keeps the original Step 17 validation/output logic, but replaces llama-cpp-python with vLLM.
#It is meant for modern GPU instances such as NVIDIA L4/H100 where Hugging Face models are preferable to GGUF files.

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
VLLM_KV_CACHE_DTYPE: str = "auto"


#This function checks whether a local directory looks like a vLLM-loadable model directory.
def is_local_vllm_model_dir(path: Path) -> bool:
    return path.is_dir() and not path.name.startswith(".") and (
        (path / "config.json").is_file() or (path / "params.json").is_file()
    )


#This class adapts vLLM's chat API to the Step 17 llama-cpp-style interface.
class VllmChatCompletionAdapter:
    #This method loads one Hugging Face/vLLM model with the configured runtime options.
    def __init__(self, model_id: str, max_model_len: int | None) -> None:
        from vllm import LLM

        kwargs: dict[str, Any] = {
            "model": model_id,
            "dtype": VLLM_DTYPE,
            "gpu_memory_utilization": VLLM_GPU_MEMORY_UTILIZATION,
            "trust_remote_code": VLLM_TRUST_REMOTE_CODE,
            "kv_cache_dtype": VLLM_KV_CACHE_DTYPE,
        }
        if VLLM_QUANTIZATION:
            kwargs["quantization"] = VLLM_QUANTIZATION
        if max_model_len:
            kwargs["max_model_len"] = max_model_len
        self.model_id = model_id
        self.llm = LLM(**kwargs)

    #This method exposes tokenization in the shape expected by the shared Step 17 code.
    def tokenize(self, text: bytes | str, add_bos: bool = False) -> list[int]:
        tokenizer = self.llm.get_tokenizer()
        decoded_text = text.decode("utf-8") if isinstance(text, bytes) else text
        return tokenizer.encode(decoded_text, add_special_tokens=add_bos)

    #This method runs one chat completion and returns a llama-cpp-compatible response object.
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

    #This method runs a batch of chat completions with per-prompt generation parameters.
    def create_chat_completions_batch(
        self,
        *,
        messages_batch: list[list[dict[str, str]]],
        generation_params_batch: list[dict[str, Any]],
    ) -> list[str]:
        from vllm import SamplingParams

        sampling_params_batch = [
            SamplingParams(
                temperature=generation_params["temperature"],
                top_p=generation_params["top_p"],
                max_tokens=generation_params["max_tokens"],
            )
            for generation_params in generation_params_batch
        ]
        outputs = self.llm.chat(
            messages=messages_batch,
            sampling_params=sampling_params_batch,
            use_tqdm=False,
        )
        return [output.outputs[0].text if output.outputs else "" for output in outputs]


#This function selects vLLM model paths or Hugging Face model ids for the current run.
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
        selected = sorted(path for path in model_dir.iterdir() if is_local_vllm_model_dir(path))

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


#This function loads one selected vLLM model through the adapter.
def load_vllm_model(model_path: Path, generation_params: dict[str, Any]) -> VllmChatCompletionAdapter:
    max_model_len = VLLM_MAX_MODEL_LEN or int(generation_params["n_ctx"])
    return VllmChatCompletionAdapter(str(model_path), max_model_len=max_model_len)


#This function runs a small diagnostic proving vLLM accepts per-request SamplingParams.
def run_vllm_per_request_sampling_probe(args: argparse.Namespace) -> None:
    from vllm import SamplingParams

    model_dir = Path(args.model_dir).expanduser() if args.model_dir else Path(args.cloud_root).expanduser() / "03_Models"
    model_paths = collect_vllm_model_paths(
        model_dir=model_dir,
        explicit_model_paths=args.model_path,
        model_filters=args.model_filter,
    )
    model_path = model_paths[0]
    max_model_len = VLLM_MAX_MODEL_LEN or args.vllm_max_model_len or args.runtime_max_model_len or 2048
    adapter = VllmChatCompletionAdapter(str(model_path), max_model_len=max_model_len)
    messages_batch = [
        [{"role": "user", "content": "Reply with exactly one token: A"}],
        [{"role": "user", "content": "Reply with a short five word sentence."}],
    ]
    sampling_params_batch = [
        SamplingParams(temperature=0.0, top_p=1.0, max_tokens=1),
        SamplingParams(temperature=0.0, top_p=1.0, max_tokens=8),
    ]
    print("Running vLLM per-request SamplingParams probe.")
    print(f"Probe model: {model_path}")
    print(f"Probe max_model_len: {max_model_len}")
    print("Probe request max_tokens: [1, 8]")
    outputs = adapter.llm.chat(
        messages=messages_batch,
        sampling_params=sampling_params_batch,
        use_tqdm=False,
    )
    print(f"Probe outputs returned: {len(outputs)}")
    for index, output in enumerate(outputs):
        text = output.outputs[0].text if output.outputs else ""
        token_ids = output.outputs[0].token_ids if output.outputs else []
        print(
            f"Probe output {index}: generated_tokens={len(token_ids)}, "
            f"text={text!r}"
        )
    print("VLLM_PER_REQUEST_SAMPLING_PROBE_OK")


#This function parses vLLM-specific arguments and then delegates shared Step 17 arguments to the base parser.
def parse_rise_cloud_args() -> argparse.Namespace:
    extra_parser = argparse.ArgumentParser(add_help=False)
    extra_parser.add_argument("--hf-model-id", action="append", help="Hugging Face model id to load with vLLM. Can be repeated.")
    extra_parser.add_argument("--vllm-dtype", default="auto", help="vLLM dtype, for example auto, half, bfloat16, or float16.")
    extra_parser.add_argument("--vllm-quantization", help="vLLM quantization method, for example awq, gptq, or bitsandbytes.")
    extra_parser.add_argument("--vllm-gpu-memory-utilization", type=float, default=0.90)
    extra_parser.add_argument("--vllm-max-model-len", type=int)
    extra_parser.add_argument("--trust-remote-code", action="store_true")
    extra_parser.add_argument("--kv-cache-dtype", default="auto", help="vLLM KV Cache storage precision (auto or fp8).")
    extra_parser.add_argument(
        "--probe-vllm-per-request-sampling",
        action="store_true",
        help="Load vLLM and verify whether LLM.chat accepts one SamplingParams object per request.",
    )
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


#This is the command-line entry point for the vLLM-backed Step 17 runner.
def main() -> None:
    global VLLM_MODEL_IDS
    global VLLM_DTYPE
    global VLLM_QUANTIZATION
    global VLLM_GPU_MEMORY_UTILIZATION
    global VLLM_MAX_MODEL_LEN
    global VLLM_TRUST_REMOTE_CODE
    global VLLM_KV_CACHE_DTYPE

    args = parse_rise_cloud_args()
    VLLM_MODEL_IDS = args.hf_model_id
    VLLM_DTYPE = args.vllm_dtype
    VLLM_QUANTIZATION = args.vllm_quantization
    VLLM_GPU_MEMORY_UTILIZATION = args.vllm_gpu_memory_utilization
    VLLM_MAX_MODEL_LEN = args.vllm_max_model_len
    VLLM_TRUST_REMOTE_CODE = args.trust_remote_code
    VLLM_KV_CACHE_DTYPE = args.kv_cache_dtype
    if args.probe_vllm_per_request_sampling:
        run_vllm_per_request_sampling_probe(args)
        return

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
