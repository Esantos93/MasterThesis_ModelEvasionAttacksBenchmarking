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
EXPERIMENT_ID="${EXPERIMENT_ID:-}"
GROUPING_LABEL="${GROUPING_LABEL:-}"
RUN_ID="${RUN_ID:-run_$(date -u +%Y%m%d_%H%M%S)_step16_17_smoke}"

CONFIG_PATH="${CONFIG_PATH:-}"
if [[ -z "${EXPERIMENT_ID}" || -z "${GROUPING_LABEL}" || -z "${CONFIG_PATH}" ]]; then
  echo "EXPERIMENT_ID, GROUPING_LABEL and CONFIG_PATH are required for the active V3 contract."
  exit 2
fi
GROUP_DIR="${GROUP_DIR:-${CLOUD_ROOT}/01_InputFiles/${EXPERIMENT_ID}/05_groups/${GROUPING_LABEL}}"
PROMPT_DIR="${PROMPT_DIR:-${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/06_prompts/${GROUPING_LABEL}/${RUN_ID}}"
PROMPT_MANIFEST="${PROMPT_MANIFEST:-${PROMPT_DIR}/prompt_units_manifest_v2.json}"
STEP17_OUTPUT_ROOT="${STEP17_OUTPUT_ROOT:-${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/07_llm_outputs/${GROUPING_LABEL}}"
MODEL_DIR="${MODEL_DIR:-${CLOUD_ROOT}/03_Models}"
HF_MODEL_ID="${HF_MODEL_ID:-}"
MODEL_PATH="${MODEL_PATH:-}"
MODEL_FILTER="${MODEL_FILTER:-}"
STEP17_BACKEND="${STEP17_BACKEND:-vllm}"

BATCH_SIZE="${BATCH_SIZE:-168}"
LIMIT_PROMPTS_S16="${LIMIT_PROMPTS_S16:-}"
LIMIT_PROMPTS_S17="${LIMIT_PROMPTS_S17:-}"
if [[ -z "${RUNTIME_MAX_MODEL_LEN:-}" ]]; then
  RUNTIME_MAX_MODEL_LEN="$(python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
value = config.get("llm", {}).get("runtime_max_model_len")
if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
    raise SystemExit("llm.runtime_max_model_len must be a positive integer")
print(value)
' "${CONFIG_PATH}")"
fi
if [[ -n "${EXPECTED_OUTPUT_PATCH_TOKENS:-}" ]]; then
  echo "EXPECTED_OUTPUT_PATCH_TOKENS is obsolete. Step 17 uses each prompt unit's token_plan.planned_output_tokens."
  exit 1
fi
PROGRESS_EVERY="${PROGRESS_EVERY:-25}"
HEARTBEAT_SECONDS="${HEARTBEAT_SECONDS:-30}"
VLLM_DTYPE="${VLLM_DTYPE:-auto}"
VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION:-0.90}"
TRUST_REMOTE_CODE="${TRUST_REMOTE_CODE:-0}"
DISABLE_THINKING="${DISABLE_THINKING:-0}"

SKIP_STEP16="${SKIP_STEP16:-0}"
SKIP_STEP17="${SKIP_STEP17:-0}"
SKIP_RUNTIME_SUMMARY="${SKIP_RUNTIME_SUMMARY:-0}"
ALLOW_EXISTING_RUN="${ALLOW_EXISTING_RUN:-0}"
COMPRESS_STEP16="${COMPRESS_STEP16:-1}"
COMPRESS_STEP17="${COMPRESS_STEP17:-1}"

if [[ "${STEP17_BACKEND}" == "vllm" && "${SKIP_STEP17}" != "1" ]]; then
  if [[ ! -f "${VLLM_VENV}/bin/activate" ]]; then
    echo "vLLM virtual environment not found: ${VLLM_VENV}"
    echo "Create it before running the pipeline or override VLLM_VENV."
    exit 1
  fi
  # shellcheck disable=SC1091
  source "${VLLM_VENV}/bin/activate"

  mapfile -t vllm_nvidia_lib_dirs < <(
    find "${VLLM_VENV}/lib" -type d -path '*/site-packages/nvidia/*/lib' 2>/dev/null | sort
  )
  if [[ ${#vllm_nvidia_lib_dirs[@]} -gt 0 ]]; then
    vllm_nvidia_library_path="$(IFS=:; printf '%s' "${vllm_nvidia_lib_dirs[*]}")"
    export LD_LIBRARY_PATH="${vllm_nvidia_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  fi

  mapfile -t vllm_nvidia_include_dirs < <(
    find "${VLLM_VENV}/lib" -type d -path '*/site-packages/nvidia/curand/include' 2>/dev/null | sort
  )
  if [[ ${#vllm_nvidia_include_dirs[@]} -gt 0 ]]; then
    vllm_nvidia_include_path="$(IFS=:; printf '%s' "${vllm_nvidia_include_dirs[*]}")"
    export CPATH="${vllm_nvidia_include_path}${CPATH:+:${CPATH}}"
    export CPLUS_INCLUDE_PATH="${vllm_nvidia_include_path}${CPLUS_INCLUDE_PATH:+:${CPLUS_INCLUDE_PATH}}"
  fi
fi

STEP16_DIR="${CLOUD_ROOT}/04_Steps/Step16"
STEP17_DIR="${CLOUD_ROOT}/04_Steps/Step17"
EXECUTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPERIMENT_OUTPUT_DIR="${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}"
STEP16_COMPRESSION_SCRIPT="${EXECUTION_DIR}/compression/compression_step_16.sh"
STEP17_COMPRESSION_SCRIPT="${EXECUTION_DIR}/compression/compression_step_17.sh"
STEP16_ARCHIVE="${STEP16_ARCHIVE:-${EXPERIMENT_OUTPUT_DIR}/step16_prompts_${RUN_ID}.tar.gz}"
STEP17_ARCHIVE="${STEP17_ARCHIVE:-${EXPERIMENT_OUTPUT_DIR}/step17_llm_outputs_${RUN_ID}.tar.gz}"
LOG_DIR="${CLOUD_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/logs/${RUN_ID}"
LOG_FILE="${LOG_DIR}/step16_17_${RUN_ID}.log"
STATUS_FILE="${LOG_DIR}/status.txt"
LOCK_FILE="/tmp/${EXPERIMENT_ID}_${RUN_ID}.lock"

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

started_at="$(date --iso-8601=seconds)"
started_epoch="$(date +%s)"
finished_at=""
duration_seconds=""
duration_human=""
current_stage="preflight"

format_duration() {
  local total_seconds="$1"
  local days=$((total_seconds / 86400))
  local hours=$(((total_seconds % 86400) / 3600))
  local minutes=$(((total_seconds % 3600) / 60))
  local seconds=$((total_seconds % 60))

  if ((days > 0)); then
    printf '%dd %02dh %02dm %02ds' "${days}" "${hours}" "${minutes}" "${seconds}"
  elif ((hours > 0)); then
    printf '%dh %02dm %02ds' "${hours}" "${minutes}" "${seconds}"
  elif ((minutes > 0)); then
    printf '%dm %02ds' "${minutes}" "${seconds}"
  else
    printf '%ds' "${seconds}"
  fi
}

write_status() {
  local status="$1"
  {
    printf 'status=%s\n' "${status}"
    printf 'stage=%s\n' "${current_stage}"
    printf 'started_at=%s\n' "${started_at}"
    printf 'updated_at=%s\n' "$(date --iso-8601=seconds)"
    if [[ -n "${finished_at}" ]]; then
      printf 'finished_at=%s\n' "${finished_at}"
      printf 'duration_seconds=%s\n' "${duration_seconds}"
      printf 'duration_human=%s\n' "${duration_human}"
    fi
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
  local finished_epoch

  finished_at="$(date --iso-8601=seconds)"
  finished_epoch="$(date +%s)"
  duration_seconds=$((finished_epoch - started_epoch))
  duration_human="$(format_duration "${duration_seconds}")"

  if [[ ${exit_code} -eq 0 ]]; then
    write_status "completed"
    echo "Run completed successfully at ${finished_at}."
  else
    write_status "failed"
    echo "Run failed in stage '${current_stage}' with exit code ${exit_code} at ${finished_at}."
  fi
  echo "Run duration: ${duration_human} (${duration_seconds} seconds)."
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
if [[ "${STEP17_BACKEND}" != "vllm" ]]; then
  echo "Unsupported STEP17_BACKEND=${STEP17_BACKEND}. Step 17 now supports vllm only."
  exit 1
fi
require_file "${STEP17_DIR}/run_llm_batch.py"
STEP17_RUNNER="${STEP17_DIR}/run_llm_batch_vllm.py"
require_file "${STEP17_RUNNER}"
require_file "${STEP17_DIR}/summarize_llm_runtime.py"
if [[ "${SKIP_STEP16}" != "1" && "${COMPRESS_STEP16}" == "1" ]]; then
  require_file "${STEP16_COMPRESSION_SCRIPT}"
fi
if [[ "${SKIP_STEP17}" != "1" && "${COMPRESS_STEP17}" == "1" ]]; then
  require_file "${STEP17_COMPRESSION_SCRIPT}"
fi
require_dir "${GROUP_DIR}"
require_dir "${MODEL_DIR}"

if [[ "${SKIP_STEP17}" != "1" ]]; then
  python3 - <<'PY'
import torch
from vllm import LLM

if not torch.cuda.is_available():
    raise SystemExit("PyTorch cannot access CUDA.")
print(f"vLLM runtime import check: OK; GPU={torch.cuda.get_device_name(0)}")
PY
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
echo "Prompt manifest: ${PROMPT_MANIFEST}"
echo "Step 17 output root: ${STEP17_OUTPUT_ROOT}"
echo "Model dir: ${MODEL_DIR}"
echo "HF model id override: ${HF_MODEL_ID:-<none>}"
echo "Model path override: ${MODEL_PATH:-<none>}"
echo "Model filter: ${MODEL_FILTER:-<none>}"
echo "Step 17 backend: ${STEP17_BACKEND}"
echo "vLLM virtual environment: ${VLLM_VENV}"
echo "Step 17 runner: ${STEP17_RUNNER:-<skipped>}"
echo "Batch size: ${BATCH_SIZE}"
echo "Runtime max model len: ${RUNTIME_MAX_MODEL_LEN}"
echo "Output token budget source: prompt_unit.token_plan.planned_output_tokens"
echo "Disable thinking: ${DISABLE_THINKING}"
echo "Limit Step 16: ${LIMIT_PROMPTS_S16:-<none>}"
echo "Limit Step 17: ${LIMIT_PROMPTS_S17:-<none>}"
echo "Compress Step 16: ${COMPRESS_STEP16}"
echo "Compress Step 17: ${COMPRESS_STEP17}"
echo "Step 16 archive: ${STEP16_ARCHIVE}"
echo "Step 17 archive: ${STEP17_ARCHIVE}"
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

require_file "${PROMPT_MANIFEST}"

python3 - "${PROMPT_MANIFEST}" <<'PY'
import collections
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
metadata = manifest.get("metadata") or {}
prompt_units = manifest.get("prompt_units")
if not isinstance(prompt_units, list):
    raise SystemExit(f"Prompt manifest has no prompt_units list: {manifest_path}")
if metadata.get("schema_version") != "prompt_units_manifest_v2":
    raise SystemExit(f"Expected prompt_units_manifest_v2: {manifest_path}")
if metadata.get("source_compact_view_schema_version") != "compact_modification_unit_v3":
    raise SystemExit(f"Expected compact_modification_unit_v3 source traceability: {manifest_path}")
editable_counts = collections.Counter(
    unit.get("editable_region_count")
    for unit in prompt_units
    if isinstance(unit, dict)
)
target_presence_counts = collections.Counter(
    (
        bool((unit.get("editable_target_presence") or {}).get("editable_headers_present")),
        bool((unit.get("editable_target_presence") or {}).get("editable_payload_present")),
    )
    for unit in prompt_units
    if isinstance(unit, dict)
)
print("=== Prompt manifest preflight ===")
print(f"Manifest: {manifest_path}")
print(f"Schema: {metadata.get('schema_version')}")
print(f"Prompt units: {len(prompt_units)}")
print(f"Total prompt count metadata: {metadata.get('total_prompt_count')}")
print(f"Source modification units metadata: {metadata.get('total_source_modification_units')}")
print(f"Source unit schema: {metadata.get('source_compact_view_schema_version')}")
print(f"Modification strategy: {metadata.get('modification_strategy')}")
print(f"Capabilities: {metadata.get('capabilities')}")
print(f"Editable-target-presence distribution: {dict(sorted(target_presence_counts.items()))}")
print(f"Editable-region count distribution: {dict(sorted(editable_counts.items(), key=lambda item: str(item[0])))}")
print(f"Prompt input profile: {metadata.get('prompt_input_json_data_profile')}")
print(f"Prompt instructions profile: {metadata.get('prompt_instructions_profile')}")
print(f"Token budget policy: {metadata.get('token_budget_policy')}")
print(f"Max tokens source: {metadata.get('max_tokens_source')}")
print(f"Planned output tokens distribution: {metadata.get('planned_output_tokens_distribution')}")
PY

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
    --prompt-manifest "${PROMPT_MANIFEST}"
    --prompt-dir "${PROMPT_DIR}"
    --output-root "${STEP17_OUTPUT_ROOT}"
    --run-id "${RUN_ID}"
    --runtime-max-model-len "${RUNTIME_MAX_MODEL_LEN}"
  )
  if [[ "${STEP17_BACKEND}" == "vllm" ]]; then
    step17_args+=(--vllm-dtype "${VLLM_DTYPE}")
    step17_args+=(--vllm-gpu-memory-utilization "${VLLM_GPU_MEMORY_UTILIZATION}")
    if [[ "${TRUST_REMOTE_CODE}" == "1" ]]; then
      step17_args+=(--trust-remote-code)
    fi
    if [[ "${DISABLE_THINKING}" == "1" ]]; then
      step17_args+=(--disable-thinking)
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

if [[ "${SKIP_STEP16}" != "1" && "${COMPRESS_STEP16}" == "1" ]]; then
  current_stage="compress_step16"
  write_status "running"
  bash "${STEP16_COMPRESSION_SCRIPT}" \
    "${EXPERIMENT_OUTPUT_DIR}" \
    "${PROMPT_DIR}" \
    "${STEP16_ARCHIVE}"
elif [[ "${SKIP_STEP16}" != "1" ]]; then
  echo "Skipping Step 16 compression because COMPRESS_STEP16=${COMPRESS_STEP16}."
fi

if [[ "${SKIP_STEP17}" != "1" && "${COMPRESS_STEP17}" == "1" ]]; then
  current_stage="compress_step17"
  write_status "running"
  bash "${STEP17_COMPRESSION_SCRIPT}" \
    "${EXPERIMENT_OUTPUT_DIR}" \
    "${STEP17_OUTPUT_ROOT}" \
    "${RUN_ID}" \
    "${STEP17_ARCHIVE}"
elif [[ "${SKIP_STEP17}" != "1" ]]; then
  echo "Skipping Step 17 compression because COMPRESS_STEP17=${COMPRESS_STEP17}."
fi

current_stage="complete"
write_status "running"
