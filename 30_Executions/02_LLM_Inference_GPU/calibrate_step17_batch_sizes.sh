#!/usr/bin/env bash
set -Eeuo pipefail

CLOUD_ROOT="${CLOUD_ROOT:-/tf/thesis_Santos}"
EXPERIMENT_ID="${EXPERIMENT_ID:-exp_cicids2017_thursday_baseline_003}"
GROUPING_LABEL="${GROUPING_LABEL:-fixed_packet_count_size_006}"
CONFIG_PATH="${CONFIG_PATH:-${CLOUD_ROOT}/04_Steps/setups/config_LLM_baseline_003.json}"
MODEL_PATH="${MODEL_PATH:-${CLOUD_ROOT}/03_Models/Llama-3.1-8B-Instruct}"
PROMPT_DIR="${PROMPT_DIR:-}"
CALIBRATION_LABEL="${CALIBRATION_LABEL:-baseline003_fixed006_hybrid_wide_1500}"
CALIBRATION_ROOT="${CALIBRATION_ROOT:-${CLOUD_ROOT}/02_OutputFiles/batch_calibration/${CALIBRATION_LABEL}}"
LIMIT_PROMPTS_S17="${LIMIT_PROMPTS_S17:-1500}"
BATCH_SIZES="${BATCH_SIZES:-16 32 64 96 128 160 188 224 256 320}"
SAMPLE_METHOD="${SAMPLE_METHOD:-editable_count_stratified}"
RUNNER="${RUNNER:-${CLOUD_ROOT}/04_Steps/run_step16_17.sh}"
COMPARATOR="${COMPARATOR:-${CLOUD_ROOT}/04_Steps/compare_step17_batch_calibration.py}"
SAMPLE_BUILDER="${SAMPLE_BUILDER:-${CLOUD_ROOT}/04_Steps/build_prompt_manifest_sample.py}"
VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION:-0.90}"
VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-12288}"
RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN:-${VLLM_MAX_MODEL_LEN}}"
VLLM_DTYPE="${VLLM_DTYPE:-auto}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-0}"
current_monitor_pid=""

cleanup_monitor() {
  if [[ -n "${current_monitor_pid}" ]]; then
    kill "${current_monitor_pid}" 2>/dev/null || true
    wait "${current_monitor_pid}" 2>/dev/null || true
    current_monitor_pid=""
  fi
}
trap cleanup_monitor EXIT INT TERM

if [[ -z "${PROMPT_DIR}" ]]; then
  echo "PROMPT_DIR is required and must point to one existing Step 16 prompt run."
  exit 1
fi
for required_path in \
  "${RUNNER}" \
  "${COMPARATOR}" \
  "${SAMPLE_BUILDER}" \
  "${CONFIG_PATH}" \
  "${PROMPT_DIR}/prompt_units_manifest_v1.json" \
  "${MODEL_PATH}"; do
  if [[ ! -e "${required_path}" ]]; then
    echo "Required path not found: ${required_path}"
    exit 1
  fi
done

mkdir -p "${CALIBRATION_ROOT}"
sample_manifest="${CALIBRATION_ROOT}/prompt_units_manifest_sample_${LIMIT_PROMPTS_S17}.json"
python3 "${SAMPLE_BUILDER}" \
  --input-manifest "${PROMPT_DIR}/prompt_units_manifest_v1.json" \
  --output-manifest "${sample_manifest}" \
  --sample-size "${LIMIT_PROMPTS_S17}" \
  --sample-method "${SAMPLE_METHOD}"

campaign_started_at="$(date -u +%Y%m%d_%H%M%S)"
campaign_log="${CALIBRATION_ROOT}/calibration_${campaign_started_at}.log"
exec > >(tee -a "${campaign_log}") 2>&1

echo "Calibration root: ${CALIBRATION_ROOT}"
echo "Prompt directory: ${PROMPT_DIR}"
echo "Prompt limit: ${LIMIT_PROMPTS_S17}"
echo "Sample method: ${SAMPLE_METHOD}"
echo "Batch sizes: ${BATCH_SIZES}"
echo "Model: ${MODEL_PATH}"
echo "Runtime max model len: ${RUNTIME_MAX_MODEL_LEN}"
echo "vLLM max model len: ${VLLM_MAX_MODEL_LEN}"

for batch_size in ${BATCH_SIZES}; do
  if ! [[ "${batch_size}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid batch size: ${batch_size}"
    exit 1
  fi

  batch_label="$(printf 'batch_%03d' "${batch_size}")"
  batch_root="${CALIBRATION_ROOT}/${batch_label}"
  run_id="run_$(date -u +%Y%m%d_%H%M%S)_${CALIBRATION_LABEL}_${batch_label}"
  monitor_file="${batch_root}/${run_id}_gpu_metrics.csv"
  mkdir -p "${batch_root}"

  if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi \
      --query-gpu=timestamp,utilization.gpu,memory.used,memory.total,power.draw,temperature.gpu \
      --format=csv,nounits \
      --loop=1 > "${monitor_file}" &
    current_monitor_pid=$!
  fi

  echo -e "\n################################################################################"
  echo "  STARTING BATCH SIZE: ${batch_size} (${batch_label})"
  echo "  Run ID: ${run_id}"
  echo "  Timestamp: $(date --iso-8601=seconds)"
  echo -e "################################################################################\n"
  set +e
  CLOUD_ROOT="${CLOUD_ROOT}" \
  EXPERIMENT_ID="${EXPERIMENT_ID}" \
  GROUPING_LABEL="${GROUPING_LABEL}" \
  CONFIG_PATH="${CONFIG_PATH}" \
  MODEL_PATH="${MODEL_PATH}" \
  PROMPT_DIR="${PROMPT_DIR}" \
  PROMPT_MANIFEST="${sample_manifest}" \
  STEP17_OUTPUT_ROOT="${batch_root}" \
  RUN_ID="${run_id}" \
  BATCH_SIZE="${batch_size}" \
  LIMIT_PROMPTS_S17="${LIMIT_PROMPTS_S17}" \
  SKIP_STEP16=1 \
  COMPRESS_STEP16=0 \
  COMPRESS_STEP17=0 \
  VLLM_DTYPE="${VLLM_DTYPE}" \
  VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION}" \
  VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN}" \
  RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN}" \
  bash "${RUNNER}"
  run_exit_code=$?
  set -e

  cleanup_monitor

  if [[ ${run_exit_code} -ne 0 ]]; then
    echo "${batch_label} failed with exit code ${run_exit_code}."
    if [[ "${CONTINUE_ON_ERROR}" != "1" ]]; then
      exit "${run_exit_code}"
    fi
  else
    echo "${batch_label} completed at $(date --iso-8601=seconds)."
  fi

  if find "${CALIBRATION_ROOT}" -path '*/runtime_summary.json' -print -quit | grep -q .; then
    python3 "${COMPARATOR}" \
      --calibration-root "${CALIBRATION_ROOT}" \
      --output-prefix "${CALIBRATION_ROOT}/batch_calibration_comparison"
  fi
done

echo "Calibration completed at $(date --iso-8601=seconds)."
echo "Comparison: ${CALIBRATION_ROOT}/batch_calibration_comparison.md"
