#!/usr/bin/env bash
set -Eeuo pipefail

CLOUD_ROOT="${CLOUD_ROOT:-/tf/thesis_Santos}"
EXPERIMENT_ID="${EXPERIMENT_ID:-exp_cicids2017_thursday_baseline_003}"
GROUPING_LABEL="${GROUPING_LABEL:-fixed_packet_count_size_006}"
CONFIG_PATH="${CONFIG_PATH:-${CLOUD_ROOT}/04_Steps/setups/config_LLM_baseline_003.json}"
MODEL_PATH="${MODEL_PATH:-${CLOUD_ROOT}/03_Models/Llama-3.1-8B-Instruct}"
PROMPT_DIR="${PROMPT_DIR:-}"
TEST_LABEL="${TEST_LABEL:-baseline003_hybrid_parallel_process_smoke_500}"
TEST_ROOT="${TEST_ROOT:-${CLOUD_ROOT}/02_OutputFiles/parallel_process_tests/${TEST_LABEL}}"
RUNNER="${RUNNER:-${CLOUD_ROOT}/04_Steps/run_step16_17.sh}"
SAMPLE_BUILDER="${SAMPLE_BUILDER:-${CLOUD_ROOT}/04_Steps/build_prompt_manifest_sample.py}"
SAMPLE_METHOD="${SAMPLE_METHOD:-editable_count_stratified}"
SAMPLE_SIZE="${SAMPLE_SIZE:-500}"
PROCESS_PROMPTS="${PROCESS_PROMPTS:-250}"
BATCH_SIZE_A="${BATCH_SIZE_A:-96}"
BATCH_SIZE_B="${BATCH_SIZE_B:-96}"
VLLM_GPU_MEMORY_UTILIZATION_A="${VLLM_GPU_MEMORY_UTILIZATION_A:-0.42}"
VLLM_GPU_MEMORY_UTILIZATION_B="${VLLM_GPU_MEMORY_UTILIZATION_B:-0.42}"
RUNTIME_MAX_MODEL_LEN_A="${RUNTIME_MAX_MODEL_LEN_A:-4096}"
RUNTIME_MAX_MODEL_LEN_B="${RUNTIME_MAX_MODEL_LEN_B:-4096}"
VLLM_DTYPE="${VLLM_DTYPE:-auto}"
STEP17_BACKEND="${STEP17_BACKEND:-vllm}"

if [[ -z "${PROMPT_DIR}" ]]; then
  echo "PROMPT_DIR is required and must point to an existing Step 16 prompt run."
  exit 1
fi

for required_path in \
  "${RUNNER}" \
  "${SAMPLE_BUILDER}" \
  "${CONFIG_PATH}" \
  "${PROMPT_DIR}/prompt_units_manifest_v2.json" \
  "${MODEL_PATH}"; do
  if [[ ! -e "${required_path}" ]]; then
    echo "Required path not found: ${required_path}"
    exit 1
  fi
done

mkdir -p "${TEST_ROOT}"
sample_manifest="${TEST_ROOT}/prompt_units_manifest_sample_${SAMPLE_SIZE}.json"
manifest_a="${TEST_ROOT}/prompt_units_manifest_parallel_a_${PROCESS_PROMPTS}.json"
manifest_b="${TEST_ROOT}/prompt_units_manifest_parallel_b_${PROCESS_PROMPTS}.json"
test_log="${TEST_ROOT}/parallel_process_test_$(date -u +%Y%m%d_%H%M%S).log"

exec > >(tee -a "${test_log}") 2>&1

echo "Parallel Step 17 process test"
echo "Test root: ${TEST_ROOT}"
echo "Prompt dir: ${PROMPT_DIR}"
echo "Sample size: ${SAMPLE_SIZE}"
echo "Process prompts: ${PROCESS_PROMPTS}"
echo "Process A: batch=${BATCH_SIZE_A}, gpu_memory_utilization=${VLLM_GPU_MEMORY_UTILIZATION_A}, max_model_len=${RUNTIME_MAX_MODEL_LEN_A}"
echo "Process B: batch=${BATCH_SIZE_B}, gpu_memory_utilization=${VLLM_GPU_MEMORY_UTILIZATION_B}, max_model_len=${RUNTIME_MAX_MODEL_LEN_B}"

python3 "${SAMPLE_BUILDER}" \
  --input-manifest "${PROMPT_DIR}/prompt_units_manifest_v2.json" \
  --output-manifest "${sample_manifest}" \
  --sample-size "${SAMPLE_SIZE}" \
  --sample-method "${SAMPLE_METHOD}"

python3 - "${sample_manifest}" "${manifest_a}" "${manifest_b}" "${PROCESS_PROMPTS}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

sample_path = Path(sys.argv[1])
manifest_a_path = Path(sys.argv[2])
manifest_b_path = Path(sys.argv[3])
process_prompts = int(sys.argv[4])

manifest = json.loads(sample_path.read_text(encoding="utf-8"))
units = manifest.get("prompt_units")
if not isinstance(units, list):
    raise SystemExit(f"Manifest has no prompt_units list: {sample_path}")
if len(units) < process_prompts * 2:
    raise SystemExit(
        f"Sample has {len(units)} prompt units, but {process_prompts * 2} are required."
    )

selected = units[: process_prompts * 2]
units_a = selected[0::2][:process_prompts]
units_b = selected[1::2][:process_prompts]

def write_split(path: Path, split_units: list[dict], split_name: str) -> None:
    split_manifest = dict(manifest)
    split_manifest["prompt_units"] = split_units
    metadata = dict(manifest.get("metadata") or {})
    metadata["total_prompt_count"] = len(split_units)
    metadata["parallel_process_split"] = {
        "split_name": split_name,
        "source_manifest": str(sample_path),
        "source_sample_prompt_count": len(units),
        "split_prompt_count": len(split_units),
        "split_strategy": "alternating_first_2n_units",
        "editable_region_count_distribution": {
            str(key): sum(1 for unit in split_units if unit.get("editable_region_count") == key)
            for key in sorted({unit.get("editable_region_count") for unit in split_units}, key=str)
        },
    }
    split_manifest["metadata"] = metadata
    path.write_text(json.dumps(split_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

write_split(manifest_a_path, units_a, "parallel_a")
write_split(manifest_b_path, units_b, "parallel_b")
print(f"Split A manifest: {manifest_a_path} ({len(units_a)} prompts)")
print(f"Split B manifest: {manifest_b_path} ({len(units_b)} prompts)")
PY

monitor_file="${TEST_ROOT}/parallel_gpu_metrics.csv"
monitor_pid=""
cleanup_monitor() {
  if [[ -n "${monitor_pid}" ]]; then
    kill "${monitor_pid}" 2>/dev/null || true
    wait "${monitor_pid}" 2>/dev/null || true
    monitor_pid=""
  fi
}
trap cleanup_monitor EXIT INT TERM

if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi \
    --query-gpu=timestamp,utilization.gpu,memory.used,memory.total,power.draw,temperature.gpu \
    --format=csv,nounits \
    --loop=1 > "${monitor_file}" &
  monitor_pid=$!
fi

started_epoch="$(date +%s)"
run_id_a="run_$(date -u +%Y%m%d_%H%M%S)_${TEST_LABEL}_parallel_a"
run_id_b="run_$(date -u +%Y%m%d_%H%M%S)_${TEST_LABEL}_parallel_b"
output_root_a="${TEST_ROOT}/parallel_a_outputs"
output_root_b="${TEST_ROOT}/parallel_b_outputs"

echo "Starting parallel processes at $(date --iso-8601=seconds)."

(
  CLOUD_ROOT="${CLOUD_ROOT}" \
  EXPERIMENT_ID="${EXPERIMENT_ID}" \
  GROUPING_LABEL="${GROUPING_LABEL}" \
  CONFIG_PATH="${CONFIG_PATH}" \
  MODEL_PATH="${MODEL_PATH}" \
  PROMPT_DIR="${PROMPT_DIR}" \
  PROMPT_MANIFEST="${manifest_a}" \
  STEP17_OUTPUT_ROOT="${output_root_a}" \
  RUN_ID="${run_id_a}" \
  BATCH_SIZE="${BATCH_SIZE_A}" \
  LIMIT_PROMPTS_S17="${PROCESS_PROMPTS}" \
  SKIP_STEP16=1 \
  COMPRESS_STEP16=0 \
  COMPRESS_STEP17=0 \
  STEP17_BACKEND="${STEP17_BACKEND}" \
  VLLM_DTYPE="${VLLM_DTYPE}" \
  VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION_A}" \
  RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN_A}" \
  PYTHONUNBUFFERED=1 \
  bash "${RUNNER}"
) &
pid_a=$!

(
  CLOUD_ROOT="${CLOUD_ROOT}" \
  EXPERIMENT_ID="${EXPERIMENT_ID}" \
  GROUPING_LABEL="${GROUPING_LABEL}" \
  CONFIG_PATH="${CONFIG_PATH}" \
  MODEL_PATH="${MODEL_PATH}" \
  PROMPT_DIR="${PROMPT_DIR}" \
  PROMPT_MANIFEST="${manifest_b}" \
  STEP17_OUTPUT_ROOT="${output_root_b}" \
  RUN_ID="${run_id_b}" \
  BATCH_SIZE="${BATCH_SIZE_B}" \
  LIMIT_PROMPTS_S17="${PROCESS_PROMPTS}" \
  SKIP_STEP16=1 \
  COMPRESS_STEP16=0 \
  COMPRESS_STEP17=0 \
  STEP17_BACKEND="${STEP17_BACKEND}" \
  VLLM_DTYPE="${VLLM_DTYPE}" \
  VLLM_GPU_MEMORY_UTILIZATION="${VLLM_GPU_MEMORY_UTILIZATION_B}" \
  RUNTIME_MAX_MODEL_LEN="${RUNTIME_MAX_MODEL_LEN_B}" \
  PYTHONUNBUFFERED=1 \
  bash "${RUNNER}"
) &
pid_b=$!

exit_a=0
exit_b=0
wait "${pid_a}" || exit_a=$?
wait "${pid_b}" || exit_b=$?

cleanup_monitor
finished_epoch="$(date +%s)"
elapsed_seconds="$((finished_epoch - started_epoch))"

echo "Parallel process A exit code: ${exit_a}"
echo "Parallel process B exit code: ${exit_b}"
echo "Combined wall-clock seconds: ${elapsed_seconds}"

python3 - "${TEST_ROOT}" "${elapsed_seconds}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

test_root = Path(sys.argv[1])
elapsed_seconds = float(sys.argv[2])
summaries = sorted(test_root.glob("parallel_*_outputs/**/runtime_summary.json"))
total_attempted = 0
total_accepted = 0
total_failed = 0
for summary_path in summaries:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    counts = summary["counts"]
    attempted = int(counts.get("metadata_files", 0))
    accepted = int(counts.get("by_status", {}).get("accepted", 0))
    failed = int(counts.get("by_status", {}).get("failed", 0))
    total_attempted += attempted
    total_accepted += accepted
    total_failed += failed
    print(
        f"{summary_path}: attempted={attempted}, accepted={accepted}, "
        f"failed={failed}, failures={counts.get('by_failure_reason', {})}"
    )

if total_attempted and elapsed_seconds:
    prompts_per_second = total_attempted / elapsed_seconds
    projected_hours = 96080 / prompts_per_second / 3600
    acceptance = 100 * total_accepted / total_attempted
    print(f"Combined attempted: {total_attempted}")
    print(f"Combined accepted: {total_accepted}")
    print(f"Combined failed: {total_failed}")
    print(f"Combined acceptance percent: {acceptance:.2f}")
    print(f"Combined prompts/s: {prompts_per_second:.3f}")
    print(f"Projected full-run hours for 96080 prompts: {projected_hours:.2f}")
else:
    print("No completed runtime summaries found for combined projection.")
PY

if [[ "${exit_a}" -ne 0 || "${exit_b}" -ne 0 ]]; then
  exit 1
fi
