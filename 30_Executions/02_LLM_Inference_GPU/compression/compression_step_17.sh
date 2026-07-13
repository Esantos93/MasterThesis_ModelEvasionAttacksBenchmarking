#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <experiment_output_dir> <step17_output_root> <run_id> <archive_path>"
  exit 2
fi

experiment_output_dir="${1%/}"
step17_root="${2%/}"
run_id="$3"
archive_path="$4"

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
if [[ ! -d "${step17_root}" ]]; then
  echo "Step 17 output directory not found: ${step17_root}"
  exit 1
fi

experiment_output_dir="$(cd "${experiment_output_dir}" && pwd -P)"
step17_root="$(cd "${step17_root}" && pwd -P)"
case "${step17_root}" in
  "${experiment_output_dir}"/*) ;;
  *)
    echo "Step 17 output root must be inside the experiment output directory: ${step17_root}"
    exit 1
    ;;
esac
mapfile -t model_run_dirs < <(
  find "${step17_root}" -mindepth 2 -maxdepth 2 -type d -name "${run_id}" | sort
)
if [[ ${#model_run_dirs[@]} -eq 0 ]]; then
  echo "No Step 17 output directories found for run ${run_id} under ${step17_root}."
  exit 1
fi

relative_run_dirs=()
tar_transform_args=()
for model_run_dir in "${model_run_dirs[@]}"; do
  relative_run_dir="${model_run_dir#"${experiment_output_dir}/"}"
  relative_model_dir="$(dirname "${relative_run_dir}")"
  relative_run_dirs+=("${relative_run_dir}")
  tar_transform_args+=("--transform=s#^${relative_run_dir}#${relative_model_dir}#")
done

mkdir -p "$(dirname "${archive_path}")"
temporary_archive="${archive_path}.tmp.$$"
trap 'rm -f "${temporary_archive}"' EXIT

echo "Compressing ${#relative_run_dirs[@]} Step 17 model output directorie(s) for run ${run_id}."
tar -czf "${temporary_archive}" \
  -C "${experiment_output_dir}" \
  "${tar_transform_args[@]}" \
  "${relative_run_dirs[@]}"
gzip -t "${temporary_archive}"
mv -f "${temporary_archive}" "${archive_path}"
trap - EXIT

echo "Step 17 archive: ${archive_path}"
du -h "${archive_path}"
