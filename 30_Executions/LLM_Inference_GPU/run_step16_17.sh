#!/usr/bin/env bash
set -Eeuo pipefail

# Run Steps 16 and 17 on the active RISE GPU container/host.
# This script intentionally does not use Docker, Google Cloud, GCS, SSH, or
# bucket transfers. Upload/download of artifacts is handled outside the script.
#
# Expected layout:
#   ${CLOUD_ROOT}/
#     01_InputFiles/<experiment_id>/05_groups/<grouping_label>/
#     02_OutputFiles/<experiment_id>/06_prompts/<grouping_label>/<run_id>/
#     02_OutputFiles/<experiment_id>/07_llm_outputs/<grouping_label>/<model>/<run_id>/
#     03_Models/<huggingface_model_dir>/
#     04_Steps/
#       Step16/build_prompts.py
#       Step17/run_llm_batch.py
#       Step17/run_llm_batch_vllm.py
#       Step17/summarize_llm_runtime.py
#       common/
#       setups/*.json

CLOUD_ROOT="${CLOUD_ROOT:-/tf/thesis_Santos}"
VLLM_VENV="${VLLM_VENV:-${CLOUD_ROOT}/.venv-vllm}"
EXPERIMENT_ID="${EXPERIMENT_ID:-exp_cicids2017_thursday_baseline_002}"
GROUPING_LABEL="${GROUPING_LABEL:-fixed_packet_count_size_006}"
RUN_ID="${RUN_ID:-run_$(date -u +%Y%m%d_%H%M%S)_rise_h100_step16_17_smoke}"

CONFIG_PATH="${CONFIG_PATH:-${CLOUD_ROOT}/04_Steps/setups/config_LLM_baseline_002.json}"
GROUP_DIR="${GROUP_DIR:-${CLOUD_ROOT}/01_InputFiles/${EXPERIMENT_ID}/05_groups/${GROUPING_LABEL}}"
PROMPT_DIR="${PROMPT_DIR:-${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/06_prompts/${GROUPING_LABEL}/${RUN_ID}}"
STEP17_OUTPUT_ROOT="${STEP17_OUTPUT_ROOT:-${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/07_llm_outputs/${GROUPING_LABEL}}"
MODEL_DIR="${MODEL_DIR:-${CLOUD_ROOT}/03_Models}"
HF_MODEL_ID="${HF_MODEL_ID:-}"
MODEL_PATH="${MODEL_PATH:-}"
MODEL_FILTER="${MODEL_FILTER:-}"
STEP17_BACKEND="${STEP17_BACKEND:-vllm}"

BATCH_SIZE="${BATCH_SIZE:-190}"
LIMIT_PROMPTS_S16="${LIMIT_PROMPTS_S16:-}"
LIMIT_PROMPTS_S17="${LIMIT_PROMPTS_S17:-500}"
RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN:-12288}"
EXPECTED_OUTPUT_PATCH_TOKENS="${EXPECTED_OUTPUT_PATCH_TOKENS:-1536}"
PROGRESS_EVERY="${PROGRESS_EVERY:-25}"
HEARTBEAT_SECONDS="${HEARTBEAT_SECONDS:-30}"
VLLM_DTYPE="${VLLM_DTYPE:-auto}"
VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION:-0.90}"
VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-${RUNTIME_MAX_MODEL_LEN}}"
VLLM_QUANTIZATION="${VLLM_QUANTIZATION:-}"
TRUST_REMOTE_CODE="${TRUST_REMOTE_CODE:-0}"

SKIP_STEP16="${SKIP_STEP16:-0}"
SKIP_STEP17="${SKIP_STEP17:-0}"
SKIP_RUNTIME_SUMMARY="${SKIP_RUNTIME_SUMMARY:-0}"
ALLOW_EXISTING_RUN="${ALLOW_EXISTING_RUN:-0}"

if [[ "${STEP17_BACKEND}" == "vllm" && "${SKIP_STEP17}" != "1" ]]; then
  if [[ ! -f "${VLLM_VENV}/bin/activate" ]]; then
    echo "vLLM virtual environment not found: ${VLLM_VENV}"
    echo "Create it before running the pipeline or override VLLM_VENV."
    exit 1
  fi
  # shellcheck disable=SC1091
  source "${VLLM_VENV}/bin/activate"
fi

STEP16_DIR="${CLOUD_ROOT}/04_Steps/Step16"
STEP17_DIR="${CLOUD_ROOT}/04_Steps/Step17"
LOG_DIR="${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/logs/${RUN_ID}"
LOG_FILE="${LOG_DIR}/step16_17_${RUN_ID}.log"
STATUS_FILE="${LOG_DIR}/status.txt"
LOCK_FILE="/tmp/${EXPERIMENT_ID}_${RUN_ID}.lock"

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

started_at="$(date --iso-8601=seconds)"
current_stage="preflight"

write_status() {
  local status="$1"
  {
    printf 'status=%s\n' "${status}"
    printf 'stage=%s\n' "${current_stage}"
    printf 'started_at=%s\n' "${started_at}"
    printf 'updated_at=%s\n' "$(date --iso-8601=seconds)"
    printf 'experiment_id=%s\n' "${EXPERIMENT_ID}"
    printf 'grouping_label=%s\n' "${GROUPING_LABEL}"
    printf 'run_id=%s\n' "${RUN_ID}"
    printf 'batch_size=%s\n' "${BATCH_SIZE}"
    printf 'limit_prompts_s16=%s\n' "${LIMIT_PROMPTS_S16}"
    printf 'limit_prompts_s17=%s\n' "${LIMIT_PROMPTS_S17}"
  } > "${STATUS_FILE}"
}

on_exit() {
  local exit_code=$?
  if [[ ${exit_code} -eq 0 ]]; then
    write_status "completed"
    echo "Run completed successfully at $(date --iso-8601=seconds)."
  else
    write_status "failed"
    echo "Run failed in stage '${current_stage}' with exit code ${exit_code} at $(date --iso-8601=seconds)."
  fi
  exit "${exit_code}"
}
trap on_exit EXIT

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Required file not found: $1"
    exit 1
  fi
}

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "Required directory not found: $1"
    exit 1
  fi
}

write_status "running"

if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    echo "Another process already holds ${LOCK_FILE}."
    exit 1
  fi
else
  echo "Warning: flock is not available; run locking is disabled."
fi

echo "=== Host information ==="
uname -a || true
if [[ -f /etc/os-release ]]; then
  cat /etc/os-release
fi
python3 --version
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi
else
  echo "Warning: nvidia-smi is not available."
fi

require_file "${CONFIG_PATH}"
require_file "${STEP16_DIR}/build_prompts.py"
require_file "${STEP17_DIR}/run_llm_batch.py"
if [[ "${STEP17_BACKEND}" == "vllm" ]]; then
  STEP17_RUNNER="${STEP17_DIR}/run_llm_batch_vllm.py"
  require_file "${STEP17_RUNNER}"
elif [[ "${STEP17_BACKEND}" == "llama-cpp" ]]; then
  STEP17_RUNNER="${STEP17_DIR}/run_llm_batch.py"
else
  echo "Unsupported STEP17_BACKEND=${STEP17_BACKEND}. Use vllm or llama-cpp."
  exit 1
fi
require_file "${STEP17_DIR}/summarize_llm_runtime.py"
require_dir "${GROUP_DIR}"
require_dir "${MODEL_DIR}"

if [[ "${SKIP_STEP17}" != "1" ]]; then
  if [[ "${STEP17_BACKEND}" == "vllm" ]]; then
    python3 - <<'PY'
import importlib.util
import sys

if importlib.util.find_spec("vllm") is None:
    sys.exit("Required Python package not found: vllm")
print("vllm import check: OK")
PY
  else
    python3 - <<'PY'
import importlib.util
import sys

if importlib.util.find_spec("llama_cpp") is None:
    sys.exit("Required Python package not found: llama_cpp")
print("llama_cpp import check: OK")
PY
  fi
fi

if [[ "${ALLOW_EXISTING_RUN}" != "1" ]]; then
  if [[ "${SKIP_STEP16}" != "1" && -e "${PROMPT_DIR}" ]]; then
    echo "Prompt run directory already exists: ${PROMPT_DIR}"
    exit 1
  fi
  if [[ "${SKIP_STEP17}" != "1" ]] && find "${STEP17_OUTPUT_ROOT}" -mindepth 2 -maxdepth 2 -type d -name "${RUN_ID}" -print -quit 2>/dev/null | grep -q .; then
    echo "A Step 17 output directory already exists for run ${RUN_ID}."
    exit 1
  fi
fi

echo "=== Run configuration ==="
echo "Cloud root: ${CLOUD_ROOT}"
echo "Experiment: ${EXPERIMENT_ID}"
echo "Grouping label: ${GROUPING_LABEL}"
echo "Run ID: ${RUN_ID}"
echo "Config: ${CONFIG_PATH}"
echo "Group dir: ${GROUP_DIR}"
echo "Prompt dir: ${PROMPT_DIR}"
echo "Step 17 output root: ${STEP17_OUTPUT_ROOT}"
echo "Model dir: ${MODEL_DIR}"
echo "HF model id override: ${HF_MODEL_ID:-<none>}"
echo "Model path override: ${MODEL_PATH:-<none>}"
echo "Model filter: ${MODEL_FILTER:-<none>}"
echo "Step 17 backend: ${STEP17_BACKEND}"
echo "vLLM virtual environment: ${VLLM_VENV}"
echo "Step 17 runner: ${STEP17_RUNNER:-<skipped>}"
echo "Batch size: ${BATCH_SIZE}"
echo "Limit Step 16: ${LIMIT_PROMPTS_S16:-<none>}"
echo "Limit Step 17: ${LIMIT_PROMPTS_S17:-<none>}"
echo "Terminal log: ${LOG_FILE}"

if [[ "${SKIP_STEP16}" != "1" ]]; then
  current_stage="step16"
  write_status "running"
  echo "Starting Step 16 at $(date --iso-8601=seconds)."

  step16_args=(
    "${STEP16_DIR}/build_prompts.py"
    --config "${CONFIG_PATH}"
    --input-dir "${GROUP_DIR}"
    --output-dir "${PROMPT_DIR}"
  )
  if [[ -n "${LIMIT_PROMPTS_S16}" ]]; then
    step16_args+=(--limit-prompts-s16 "${LIMIT_PROMPTS_S16}")
  fi
  python3 "${step16_args[@]}"
  echo "Step 16 completed at $(date --iso-8601=seconds)."
else
  echo "Skipping Step 16 because SKIP_STEP16=1."
fi

require_file "${PROMPT_DIR}/prompt_manifest.json"

if [[ "${SKIP_STEP17}" != "1" ]]; then
  current_stage="step17"
  write_status "running"
  echo "Starting Step 17 at $(date --iso-8601=seconds)."

  step17_args=(
    "${STEP17_RUNNER}"
    --config "${CONFIG_PATH}"
    --cloud-root "${CLOUD_ROOT}"
    --model-dir "${MODEL_DIR}"
    --progress-every "${PROGRESS_EVERY}"
    --heartbeat-seconds "${HEARTBEAT_SECONDS}"
    --llm-batch-size "${BATCH_SIZE}"
    --prompt-manifest "${PROMPT_DIR}/prompt_manifest.json"
    --prompt-dir "${PROMPT_DIR}"
    --output-root "${STEP17_OUTPUT_ROOT}"
    --run-id "${RUN_ID}"
    --runtime-max-model-len "${RUNTIME_MAX_MODEL_LEN}"
    --expected-output-patch-tokens "${EXPECTED_OUTPUT_PATCH_TOKENS}"
  )
  if [[ "${STEP17_BACKEND}" == "vllm" ]]; then
    step17_args+=(--vllm-dtype "${VLLM_DTYPE}")
    step17_args+=(--vllm-gpu-memory-utilization "${VLLM_GPU_MEMORY_UTILIZATION}")
    step17_args+=(--vllm-max-model-len "${VLLM_MAX_MODEL_LEN}")
    if [[ -n "${VLLM_QUANTIZATION}" ]]; then
      step17_args+=(--vllm-quantization "${VLLM_QUANTIZATION}")
    fi
    if [[ "${TRUST_REMOTE_CODE}" == "1" ]]; then
      step17_args+=(--trust-remote-code)
    fi
  fi
  if [[ -n "${LIMIT_PROMPTS_S17}" ]]; then
    step17_args+=(--limit-prompts-s17 "${LIMIT_PROMPTS_S17}")
  fi
  if [[ -n "${HF_MODEL_ID}" ]]; then
    step17_args+=(--hf-model-id "${HF_MODEL_ID}")
  fi
  if [[ -n "${MODEL_PATH}" ]]; then
    step17_args+=(--model-path "${MODEL_PATH}")
  fi
  if [[ -n "${MODEL_FILTER}" ]]; then
    step17_args+=(--model-filter "${MODEL_FILTER}")
  fi

  python3 "${step17_args[@]}"
  echo "Step 17 completed at $(date --iso-8601=seconds)."
else
  echo "Skipping Step 17 because SKIP_STEP17=1."
fi

if [[ "${SKIP_STEP17}" != "1" && "${SKIP_RUNTIME_SUMMARY}" != "1" ]]; then
  current_stage="runtime_summary"
  write_status "running"
  mapfile -t model_run_dirs < <(
    find "${STEP17_OUTPUT_ROOT}" -mindepth 2 -maxdepth 2 -type d -name "${RUN_ID}" | sort
  )
  if [[ ${#model_run_dirs[@]} -eq 0 ]]; then
    echo "No Step 17 model run directories were produced."
    exit 1
  fi

  for model_run_dir in "${model_run_dirs[@]}"; do
    python3 "${STEP17_DIR}/summarize_llm_runtime.py" \
      --run-dir "${model_run_dir}" \
      --prompt-dir "${PROMPT_DIR}"
  done
fi

current_stage="complete"
write_status "running"
