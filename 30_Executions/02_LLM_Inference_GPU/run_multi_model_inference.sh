#!/usr/bin/env bash
set -Eeuo pipefail

# Run the existing Step 16/17 RISE launcher sequentially for a selected model
# matrix. Execute this script inside tmux; it deliberately does not create or
# manage tmux sessions.

# =============================================================================
# CONFIGURATION - edit these values before starting an experiment
# =============================================================================

CLOUD_ROOT="/tf/thesis_Santos"
GROUPING_LABEL="flow_context_aware"

# Allowed values: smoke, full. Smoke is the safe default.
RUN_MODE="smoke"
RUN_LABEL="baseline_flow_context_aware"

# Select the models to execute: 1 = enabled, 0 = disabled.
ENABLE_LLAMA31=0
ENABLE_GEMMA12=1
ENABLE_GEMMA26=1
ENABLE_QWEN32=0

# Smoke limits are applied equally to Steps 16 and 17. The Gemma default
# exercises one complete batch of 224 plus a 32-prompt tail. Qwen uses eight
# complete batches of 8 because its throughput differs materially.
SMOKE_PROMPTS_DEFAULT=256
SMOKE_PROMPTS_QWEN32=64

# Continue with later enabled models when one run fails.
CONTINUE_ON_ERROR=1

# Shared runtime controls.
STEP17_BACKEND="vllm"
VLLM_DTYPE="auto"
VLLM_GPU_MEMORY_UTILIZATION="0.9"
RUNTIME_MAX_MODEL_LEN=12288
TRUST_REMOTE_CODE=0
COMPRESS_STEP16=1
COMPRESS_STEP17=1

# Llama 3.1 8B
LLAMA31_EXPERIMENT_ID="exp_cicids2017_baseline_flow_context_aware_Llama31_8B"
LLAMA31_CONFIG="config_LLM_baseline_flow_context_aware_Llama31_8B.json"
LLAMA31_MODEL_PATH="/models_root/Llama-3.1-8B-Instruct/"
LLAMA31_BATCH_SIZE=192
LLAMA31_DISABLE_THINKING=0

# Gemma 4 12B
GEMMA12_EXPERIMENT_ID="exp_cicids2017_baseline_flow_context_aware_gemma-4-12B-it"
GEMMA12_CONFIG="config_LLM_baseline_flow_context_aware_gemma-4-12B-it.json"
GEMMA12_MODEL_PATH="/models_root/gemma-4-12B-it/"
GEMMA12_BATCH_SIZE=192
GEMMA12_DISABLE_THINKING=0

# Gemma 4 26B-A4B
GEMMA26_EXPERIMENT_ID="exp_cicids2017_baseline_flow_context_aware_gemma-4-26B-A4B-it"
GEMMA26_CONFIG="config_LLM_baseline_flow_context_aware_gemma-4-26B-A4B-it.json"
GEMMA26_MODEL_PATH="/models_root/gemma-4-26B-A4B-it/"
GEMMA26_BATCH_SIZE=192
GEMMA26_DISABLE_THINKING=0

# Qwen3 32B. The path matches the completed fixed-group experiment.
QWEN32_EXPERIMENT_ID="exp_cicids2017_baseline_flow_context_aware_Qwen3_32B"
QWEN32_CONFIG="config_LLM_baseline_flow_context_aware_Qwen3-32B.json"
QWEN32_MODEL_PATH="/models_root/Qwen/Qwen3-32B/"
QWEN32_BATCH_SIZE=8
QWEN32_DISABLE_THINKING=1

# =============================================================================
# END CONFIGURATION
# =============================================================================

RUNNER="${CLOUD_ROOT}/04_Steps/run_step16_17.sh"
CONFIG_ROOT="${CLOUD_ROOT}/04_Steps/setups"
QUEUE_ID="queue_$(date -u +%Y%m%d_%H%M%S)_${RUN_LABEL}_${RUN_MODE}"
QUEUE_LOG_DIR="${CLOUD_ROOT}/02_OutputFiles/multi_model_logs/${QUEUE_ID}"
QUEUE_LOG="${QUEUE_LOG_DIR}/multi_model_inference.log"
QUEUE_STATUS="${QUEUE_LOG_DIR}/status.txt"
QUEUE_STARTED_AT="$(date --iso-8601=seconds)"
QUEUE_STARTED_EPOCH="$(date +%s)"

declare -a ENABLED_MODELS=()
declare -a COMPLETED_MODELS=()
declare -a FAILED_MODELS=()

[[ "${ENABLE_LLAMA31}" == "1" ]] && ENABLED_MODELS+=("llama31")
[[ "${ENABLE_GEMMA12}" == "1" ]] && ENABLED_MODELS+=("gemma12")
[[ "${ENABLE_GEMMA26}" == "1" ]] && ENABLED_MODELS+=("gemma26")
[[ "${ENABLE_QWEN32}" == "1" ]] && ENABLED_MODELS+=("qwen32")

if [[ "${RUN_MODE}" != "smoke" && "${RUN_MODE}" != "full" ]]; then
  echo "RUN_MODE must be either 'smoke' or 'full'; received: ${RUN_MODE}"
  exit 1
fi
if [[ ${#ENABLED_MODELS[@]} -eq 0 ]]; then
  echo "No models are enabled. Set at least one ENABLE_* value to 1."
  exit 1
fi
if [[ "${CONTINUE_ON_ERROR}" != "0" && "${CONTINUE_ON_ERROR}" != "1" ]]; then
  echo "CONTINUE_ON_ERROR must be 0 or 1."
  exit 1
fi

mkdir -p "${QUEUE_LOG_DIR}"
exec > >(tee -a "${QUEUE_LOG}") 2>&1

format_duration() {
  local total_seconds="$1"
  printf '%02dh %02dm %02ds' \
    "$((total_seconds / 3600))" \
    "$(((total_seconds % 3600) / 60))" \
    "$((total_seconds % 60))"
}

model_value() {
  local model_key="$1"
  local field="$2"
  case "${model_key}:${field}" in
    llama31:label) echo "Llama-3.1-8B-Instruct" ;;
    llama31:experiment_id) echo "${LLAMA31_EXPERIMENT_ID}" ;;
    llama31:config) echo "${LLAMA31_CONFIG}" ;;
    llama31:model_path) echo "${LLAMA31_MODEL_PATH}" ;;
    llama31:batch_size) echo "${LLAMA31_BATCH_SIZE}" ;;
    llama31:disable_thinking) echo "${LLAMA31_DISABLE_THINKING}" ;;
    llama31:smoke_limit) echo "${SMOKE_PROMPTS_DEFAULT}" ;;
    gemma12:label) echo "gemma-4-12B-it" ;;
    gemma12:experiment_id) echo "${GEMMA12_EXPERIMENT_ID}" ;;
    gemma12:config) echo "${GEMMA12_CONFIG}" ;;
    gemma12:model_path) echo "${GEMMA12_MODEL_PATH}" ;;
    gemma12:batch_size) echo "${GEMMA12_BATCH_SIZE}" ;;
    gemma12:disable_thinking) echo "${GEMMA12_DISABLE_THINKING}" ;;
    gemma12:smoke_limit) echo "${SMOKE_PROMPTS_DEFAULT}" ;;
    gemma26:label) echo "gemma-4-26B-A4B-it" ;;
    gemma26:experiment_id) echo "${GEMMA26_EXPERIMENT_ID}" ;;
    gemma26:config) echo "${GEMMA26_CONFIG}" ;;
    gemma26:model_path) echo "${GEMMA26_MODEL_PATH}" ;;
    gemma26:batch_size) echo "${GEMMA26_BATCH_SIZE}" ;;
    gemma26:disable_thinking) echo "${GEMMA26_DISABLE_THINKING}" ;;
    gemma26:smoke_limit) echo "${SMOKE_PROMPTS_DEFAULT}" ;;
    qwen32:label) echo "Qwen3-32B" ;;
    qwen32:experiment_id) echo "${QWEN32_EXPERIMENT_ID}" ;;
    qwen32:config) echo "${QWEN32_CONFIG}" ;;
    qwen32:model_path) echo "${QWEN32_MODEL_PATH}" ;;
    qwen32:batch_size) echo "${QWEN32_BATCH_SIZE}" ;;
    qwen32:disable_thinking) echo "${QWEN32_DISABLE_THINKING}" ;;
    qwen32:smoke_limit) echo "${SMOKE_PROMPTS_QWEN32}" ;;
    *) echo "Unknown model field: ${model_key}:${field}" >&2; return 1 ;;
  esac
}

write_queue_status() {
  local status="$1"
  local finished_at="${2:-}"
  local duration_seconds="${3:-}"
  {
    printf 'status=%s\n' "${status}"
    printf 'queue_id=%s\n' "${QUEUE_ID}"
    printf 'run_mode=%s\n' "${RUN_MODE}"
    printf 'started_at=%s\n' "${QUEUE_STARTED_AT}"
    printf 'updated_at=%s\n' "$(date --iso-8601=seconds)"
    [[ -n "${finished_at}" ]] && printf 'finished_at=%s\n' "${finished_at}"
    [[ -n "${duration_seconds}" ]] && printf 'duration_seconds=%s\n' "${duration_seconds}"
    printf 'enabled_models=%s\n' "${ENABLED_MODELS[*]}"
    printf 'completed_models=%s\n' "${COMPLETED_MODELS[*]:-}"
    printf 'failed_models=%s\n' "${FAILED_MODELS[*]:-}"
  } > "${QUEUE_STATUS}"
}

preflight_model() {
  local model_key="$1"
  local experiment_id config_name model_path config_path group_dir
  experiment_id="$(model_value "${model_key}" experiment_id)"
  config_name="$(model_value "${model_key}" config)"
  model_path="$(model_value "${model_key}" model_path)"
  config_path="${CONFIG_ROOT}/${config_name}"
  group_dir="${CLOUD_ROOT}/01_InputFiles/${experiment_id}/05_groups/${GROUPING_LABEL}"

  [[ -f "${config_path}" ]] || { echo "Missing config: ${config_path}"; return 1; }
  [[ -d "${group_dir}" ]] || { echo "Missing Step 15 group directory: ${group_dir}"; return 1; }
  [[ -d "${model_path}" ]] || { echo "Missing model directory: ${model_path}"; return 1; }
}

run_model() {
  local model_key="$1"
  local label experiment_id config_name model_path batch_size disable_thinking
  local config_path group_dir run_id prompt_dir prompt_limit exit_code

  label="$(model_value "${model_key}" label)"
  experiment_id="$(model_value "${model_key}" experiment_id)"
  config_name="$(model_value "${model_key}" config)"
  model_path="$(model_value "${model_key}" model_path)"
  batch_size="$(model_value "${model_key}" batch_size)"
  disable_thinking="$(model_value "${model_key}" disable_thinking)"
  config_path="${CONFIG_ROOT}/${config_name}"
  group_dir="${CLOUD_ROOT}/01_InputFiles/${experiment_id}/05_groups/${GROUPING_LABEL}"
  run_id="run_$(date -u +%Y%m%d_%H%M%S)_${RUN_LABEL}_${model_key}_${RUN_MODE}"
  prompt_dir="${CLOUD_ROOT}/02_OutputFiles/${experiment_id}/06_prompts/${GROUPING_LABEL}/${run_id}"

  if [[ "${RUN_MODE}" == "smoke" ]]; then
    prompt_limit="$(model_value "${model_key}" smoke_limit)"
  else
    prompt_limit=""
  fi

  echo
  echo "================================================================"
  echo "Starting model: ${label}"
  echo "Run ID: ${run_id}"
  echo "Mode: ${RUN_MODE}"
  echo "Prompt limit: ${prompt_limit:-<full population>}"
  echo "Batch size: ${batch_size}"
  echo "Started at: $(date --iso-8601=seconds)"
  echo "================================================================"

  set +e
  CLOUD_ROOT="${CLOUD_ROOT}" \
  EXPERIMENT_ID="${experiment_id}" \
  GROUPING_LABEL="${GROUPING_LABEL}" \
  RUN_ID="${run_id}" \
  CONFIG_PATH="${config_path}" \
  GROUP_DIR="${group_dir}" \
  MODEL_PATH="${model_path}" \
  PROMPT_DIR="${prompt_dir}" \
  STEP17_BACKEND="${STEP17_BACKEND}" \
  BATCH_SIZE="${batch_size}" \
  LIMIT_PROMPTS_S16="${prompt_limit}" \
  LIMIT_PROMPTS_S17="${prompt_limit}" \
  VLLM_DTYPE="${VLLM_DTYPE}" \
  VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION}" \
  RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN}" \
  TRUST_REMOTE_CODE="${TRUST_REMOTE_CODE}" \
  DISABLE_THINKING="${disable_thinking}" \
  COMPRESS_STEP16="${COMPRESS_STEP16}" \
  COMPRESS_STEP17="${COMPRESS_STEP17}" \
  PYTHONUNBUFFERED=1 \
  bash "${RUNNER}"
  exit_code=$?
  set -e

  if [[ ${exit_code} -eq 0 ]]; then
    COMPLETED_MODELS+=("${model_key}")
    echo "Completed model: ${label}"
  else
    FAILED_MODELS+=("${model_key}")
    echo "Failed model: ${label}; exit code=${exit_code}"
  fi
  write_queue_status "running"
  return "${exit_code}"
}

echo "=== Multi-model inference preflight ==="
echo "Queue ID: ${QUEUE_ID}"
echo "Run mode: ${RUN_MODE}"
echo "Enabled models: ${ENABLED_MODELS[*]}"
echo "Runner: ${RUNNER}"
echo "Master log: ${QUEUE_LOG}"

[[ -f "${RUNNER}" ]] || { echo "Missing runner: ${RUNNER}"; exit 1; }

preflight_failed=0
for model_key in "${ENABLED_MODELS[@]}"; do
  if ! preflight_model "${model_key}"; then
    preflight_failed=1
  fi
done
if [[ ${preflight_failed} -ne 0 ]]; then
  echo "Preflight failed. No model runs were started."
  write_queue_status "preflight_failed"
  exit 1
fi

echo "Preflight completed successfully for all enabled models."
write_queue_status "running"

for model_key in "${ENABLED_MODELS[@]}"; do
  if ! run_model "${model_key}"; then
    if [[ "${CONTINUE_ON_ERROR}" != "1" ]]; then
      echo "Stopping queue because CONTINUE_ON_ERROR=0."
      break
    fi
    echo "Continuing with the next enabled model."
  fi
done

finished_at="$(date --iso-8601=seconds)"
duration_seconds=$(($(date +%s) - QUEUE_STARTED_EPOCH))

echo
echo "================================================================"
echo "Multi-model inference queue finished."
echo "Completed models: ${COMPLETED_MODELS[*]:-<none>}"
echo "Failed models: ${FAILED_MODELS[*]:-<none>}"
echo "Finished at: ${finished_at}"
echo "Duration: $(format_duration "${duration_seconds}")"
echo "Master log: ${QUEUE_LOG}"
echo "================================================================"

if [[ ${#FAILED_MODELS[@]} -eq 0 && ${#COMPLETED_MODELS[@]} -eq ${#ENABLED_MODELS[@]} ]]; then
  write_queue_status "completed" "${finished_at}" "${duration_seconds}"
  exit 0
fi

write_queue_status "completed_with_failures" "${finished_at}" "${duration_seconds}"
exit 1
