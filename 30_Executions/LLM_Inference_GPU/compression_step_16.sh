#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <experiment_output_dir> <prompt_run_dir> <archive_path>"
  exit 2
fi

experiment_output_dir="${1%/}"
prompt_run_dir="${2%/}"
archive_path="$3"

if ! command -v tar >/dev/null 2>&1; then
  echo "Required command not found: tar"
  exit 1
fi
if ! command -v gzip >/dev/null 2>&1; then
  echo "Required command not found: gzip"
  exit 1
fi
if [[ ! -d "${experiment_output_dir}" ]]; then
  echo "Experiment output directory not found: ${experiment_output_dir}"
  exit 1
fi
if [[ ! -d "${prompt_run_dir}" ]]; then
  echo "Step 16 prompt directory not found: ${prompt_run_dir}"
  exit 1
fi
if [[ ! -f "${prompt_run_dir}/prompt_manifest.json" ]]; then
  echo "Step 16 prompt manifest not found: ${prompt_run_dir}/prompt_manifest.json"
  exit 1
fi

experiment_output_dir="$(cd "${experiment_output_dir}" && pwd -P)"
prompt_run_dir="$(cd "${prompt_run_dir}" && pwd -P)"
case "${prompt_run_dir}/" in
  "${experiment_output_dir}/"*) ;;
  *)
    echo "Step 16 prompt directory must be inside ${experiment_output_dir}: ${prompt_run_dir}"
    exit 1
    ;;
esac

relative_prompt_dir="${prompt_run_dir#"${experiment_output_dir}/"}"
mkdir -p "$(dirname "${archive_path}")"
temporary_archive="${archive_path}.tmp.$$"
trap 'rm -f "${temporary_archive}"' EXIT

echo "Compressing Step 16 output: ${prompt_run_dir}"
tar -czf "${temporary_archive}" \
  -C "${experiment_output_dir}" \
  "${relative_prompt_dir}"
gzip -t "${temporary_archive}"
mv -f "${temporary_archive}" "${archive_path}"
trap - EXIT

echo "Step 16 archive: ${archive_path}"
du -h "${archive_path}"
