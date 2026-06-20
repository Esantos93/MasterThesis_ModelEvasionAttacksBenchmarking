#!/usr/bin/env bash
set -Eeuo pipefail

# Run Steps 16 and 17 entirely on the Google Cloud GPU VM. All settings can be
# overridden with environment variables before launching the script.
REMOTE_ROOT="${REMOTE_ROOT:-/home/dornas93/thesis_Santos}"
EXPERIMENT_ID="${EXPERIMENT_ID:-exp_cicids2017_thursday_baseline_002}"
GROUPING_LABEL="${GROUPING_LABEL:-baseline-002-fixed-size-6}"
RUN_ID="${RUN_ID:-run_20260620_baseline002_fixed006_full_batch190}"
BATCH_SIZE="${BATCH_SIZE:-190}"

DOCKER_IMAGE="${DOCKER_IMAGE:-thesis-step16-17-vllm:latest}"
CONFIG_PATH="${CONFIG_PATH:-${REMOTE_ROOT}/04_Steps/setups/config_LLM_baseline.json}"
GROUP_DIR="${GROUP_DIR:-${REMOTE_ROOT}/01_InputFiles/${EXPERIMENT_ID}/05_groups/groups}"
PROMPT_DIR="${PROMPT_DIR:-${REMOTE_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/06_prompts/${GROUPING_LABEL}/${RUN_ID}}"
STEP17_OUTPUT_ROOT="${STEP17_OUTPUT_ROOT:-${REMOTE_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/07_llm_outputs/${GROUPING_LABEL}}"
GCS_RUN_ROOT="${GCS_RUN_ROOT:-gs://thesis-santos-llm-artifacts/${EXPERIMENT_ID}/runs/${RUN_ID}}"

VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-12288}"
RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN:-12288}"
EXPECTED_OUTPUT_PATCH_TOKENS="${EXPECTED_OUTPUT_PATCH_TOKENS:-1536}"
VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION:-0.90}"
PROGRESS_EVERY="${PROGRESS_EVERY:-100}"
HEARTBEAT_SECONDS="${HEARTBEAT_SECONDS:-30}"
UPLOAD_TO_GCS="${UPLOAD_TO_GCS:-1}"
ALLOW_EXISTING_RUN="${ALLOW_EXISTING_RUN:-0}"

STEP16_DIR="${REMOTE_ROOT}/04_Steps/Step16"
STEP17_DIR="${REMOTE_ROOT}/04_Steps/Step17"
LOG_DIR="${REMOTE_ROOT}/02_OutputFiles/${EXPERIMENT_ID}/logs/direct_step16_17/${RUN_ID}"
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
    printf 'run_id=%s\n' "${RUN_ID}"
    printf 'batch_size=%s\n' "${BATCH_SIZE}"
  } > "${STATUS_FILE}"
}

upload_log_best_effort() {
  if [[ "${UPLOAD_TO_GCS}" == "1" ]] && command -v gcloud >/dev/null 2>&1; then
    gcloud storage cp "${LOG_FILE}" "${GCS_RUN_ROOT}/logs/$(basename "${LOG_FILE}")" || true
    gcloud storage cp "${STATUS_FILE}" "${GCS_RUN_ROOT}/logs/status.txt" || true
  fi
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
  upload_log_best_effort
  exit "${exit_code}"
}
trap on_exit EXIT

write_status "running"

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "Another process already holds ${LOCK_FILE}."
  exit 1
fi

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

require_file "${CONFIG_PATH}"
require_file "${STEP16_DIR}/build_prompts-googleCloud.py"
require_file "${STEP17_DIR}/run_llm_batch-googleCloud.py"
require_file "${STEP17_DIR}/summarize_llm_runtime.py"
require_dir "${GROUP_DIR}"
command -v gcloud >/dev/null 2>&1 || { echo "gcloud is not available."; exit 1; }
command -v flock >/dev/null 2>&1 || { echo "flock is not available."; exit 1; }
sudo -n true || { echo "Passwordless sudo is required for detached Docker execution."; exit 1; }
sudo docker image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1 || {
  echo "Docker image not found: ${DOCKER_IMAGE}"
  exit 1
}

if [[ "${ALLOW_EXISTING_RUN}" != "1" ]]; then
  if [[ -e "${PROMPT_DIR}" ]]; then
    echo "Prompt run directory already exists: ${PROMPT_DIR}"
    exit 1
  fi
  if find "${STEP17_OUTPUT_ROOT}" -mindepth 2 -maxdepth 2 -type d -name "${RUN_ID}" -print -quit 2>/dev/null | grep -q .; then
    echo "A Step 17 output directory already exists for run ${RUN_ID}."
    exit 1
  fi
fi

if nvidia-smi --query-compute-apps=pid --format=csv,noheader | grep -q '[0-9]'; then
  echo "The GPU is already in use. Refusing to start another inference run."
  exit 1
fi

echo "Experiment: ${EXPERIMENT_ID}"
echo "Run ID: ${RUN_ID}"
echo "Batch size: ${BATCH_SIZE}"
echo "Prompt directory: ${PROMPT_DIR}"
echo "Step 17 output root: ${STEP17_OUTPUT_ROOT}"
echo "GCS run root: ${GCS_RUN_ROOT}"
echo "Terminal log: ${LOG_FILE}"

current_stage="step16"
write_status "running"
echo "Starting Step 16 at $(date --iso-8601=seconds)."
sudo docker run --rm --gpus all \
  -e "HF_TOKEN=${HF_TOKEN:-}" \
  -e HF_HUB_ENABLE_HF_TRANSFER=1 \
  -v "${REMOTE_ROOT}:${REMOTE_ROOT}" \
  -w "${STEP16_DIR}" \
  --entrypoint python3 \
  "${DOCKER_IMAGE}" \
  build_prompts-googleCloud.py \
  --config "${CONFIG_PATH}" \
  --cloud-root "${REMOTE_ROOT}" \
  --output-dir "${PROMPT_DIR}" \
  --input-dir "${GROUP_DIR}"

require_file "${PROMPT_DIR}/prompt_manifest.json"
echo "Step 16 completed at $(date --iso-8601=seconds)."

current_stage="step17"
write_status "running"
echo "Starting Step 17 at $(date --iso-8601=seconds)."
sudo docker run --rm --gpus all \
  -e "HF_TOKEN=${HF_TOKEN:-}" \
  -e HF_HUB_ENABLE_HF_TRANSFER=1 \
  -v "${REMOTE_ROOT}:${REMOTE_ROOT}" \
  -w "${STEP17_DIR}" \
  --entrypoint python3 \
  "${DOCKER_IMAGE}" \
  run_llm_batch-googleCloud.py \
  --config "${CONFIG_PATH}" \
  --cloud-root "${REMOTE_ROOT}" \
  --n-gpu-layers -1 \
  --progress-every "${PROGRESS_EVERY}" \
  --heartbeat-seconds "${HEARTBEAT_SECONDS}" \
  --llm-batch-size "${BATCH_SIZE}" \
  --prompt-manifest "${PROMPT_DIR}/prompt_manifest.json" \
  --prompt-dir "${PROMPT_DIR}" \
  --output-root "${STEP17_OUTPUT_ROOT}" \
  --run-id "${RUN_ID}" \
  --vllm-dtype auto \
  --vllm-gpu-memory-utilization "${VLLM_GPU_MEMORY_UTILIZATION}" \
  --vllm-max-model-len "${VLLM_MAX_MODEL_LEN}" \
  --runtime-max-model-len "${RUNTIME_MAX_MODEL_LEN}" \
  --expected-output-patch-tokens "${EXPECTED_OUTPUT_PATCH_TOKENS}"
echo "Step 17 completed at $(date --iso-8601=seconds)."

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
  sudo docker run --rm --gpus all \
    -e "HF_TOKEN=${HF_TOKEN:-}" \
    -v "${REMOTE_ROOT}:${REMOTE_ROOT}" \
    -w "${STEP17_DIR}" \
    --entrypoint python3 \
    "${DOCKER_IMAGE}" \
    summarize_llm_runtime.py \
    --run-dir "${model_run_dir}" \
    --prompt-dir "${PROMPT_DIR}"
done

if [[ "${UPLOAD_TO_GCS}" == "1" ]]; then
  current_stage="gcs_upload"
  write_status "running"
  echo "Uploading run artifacts to ${GCS_RUN_ROOT}."
  gcloud storage rsync -r "${PROMPT_DIR}" "${GCS_RUN_ROOT}/06_prompts"
  for model_run_dir in "${model_run_dirs[@]}"; do
    model_name="$(basename "$(dirname "${model_run_dir}")")"
    gcloud storage rsync -r "${model_run_dir}" "${GCS_RUN_ROOT}/07_llm_outputs/${model_name}"
  done
fi

current_stage="complete"
write_status "running"
