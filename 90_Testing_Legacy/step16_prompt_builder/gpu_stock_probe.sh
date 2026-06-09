#!/usr/bin/env bash
set -u -o pipefail

# Probe real Google Compute Engine L4 stock by creating short-lived VMs and deleting them immediately.
# The preferred defaults mirror orchestrate_step16_17-googleCloud.py.

PROJECT="${PROJECT:-master-thesis-rise}"
GCLOUD="${GCLOUD:-gcloud}"
IMAGE_FAMILY="${IMAGE_FAMILY:-common-cu129-ubuntu-2204-nvidia-580}"
IMAGE_PROJECT="${IMAGE_PROJECT:-deeplearning-platform-release}"
GPU_TYPE="${GPU_TYPE:-nvidia-l4}"
BOOT_DISK_TYPE="${BOOT_DISK_TYPE:-pd-balanced}"
BOOT_DISK_SIZE_GB="${BOOT_DISK_SIZE_GB:-200}"
PROVISIONING_MODEL="${PROVISIONING_MODEL:-STANDARD}"
PROBE_NAME="${PROBE_NAME:-gpu-stock-probe}"
PRIMARY_MACHINE_SPEC="${PRIMARY_MACHINE_SPEC:-g2-standard-8:1}"
FALLBACK_MACHINE_SPECS="${FALLBACK_MACHINE_SPECS:-g2-standard-4:1 g2-standard-12:1 g2-standard-16:1 g2-standard-24:2}"
ZONES="${ZONES:-}"
DRY_RUN=0
STOP_AFTER_FIRST=0
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-}"

CURRENT_INSTANCE_NAME=""
CURRENT_INSTANCE_ZONE=""
declare -a AVAILABLE_ROWS=()

# European regions are tried before every other region. The order keeps western Europe first,
# then southern/central/northern Europe, before falling back to the rest of the world.
EUROPE_REGION_ORDER=(
  europe-west1 europe-west2 europe-west3 europe-west4 europe-west6
  europe-west8 europe-west9 europe-west10 europe-west12
  europe-southwest1 europe-central2 europe-north1
)

DEFAULT_ZONES=(
  europe-west1-b europe-west1-c europe-west1-d
  europe-west2-a europe-west2-b europe-west2-c
  europe-west3-a europe-west3-b europe-west3-c
  europe-west4-a europe-west4-b europe-west4-c
  europe-west6-a europe-west6-b europe-west6-c
  europe-west8-a europe-west8-b europe-west8-c
  europe-west9-a europe-west9-b europe-west9-c
  europe-west10-a europe-west10-b europe-west10-c
  europe-west12-a europe-west12-b europe-west12-c
  europe-southwest1-a europe-southwest1-b europe-southwest1-c
  europe-central2-a europe-central2-b europe-central2-c
  europe-north1-a europe-north1-b europe-north1-c
  asia-east1-a asia-east1-b asia-east1-c
  asia-northeast1-a asia-northeast1-b asia-northeast1-c
  asia-south1-a asia-south1-b asia-south1-c
  asia-southeast1-a asia-southeast1-b asia-southeast1-c
  australia-southeast1-a australia-southeast1-b australia-southeast1-c
  northamerica-northeast1-a northamerica-northeast1-b northamerica-northeast1-c
  southamerica-east1-a southamerica-east1-b southamerica-east1-c
  us-central1-a us-central1-b us-central1-c us-central1-f
  us-east1-b us-east1-c us-east1-d
  us-east4-a us-east4-b us-east4-c
  us-west1-a us-west1-b us-west1-c
  us-west2-a us-west2-b us-west2-c
  us-west3-a us-west3-b us-west3-c
  us-west4-a us-west4-b us-west4-c
)

usage() {
  cat <<'EOF'
Usage:
  gpu_stock_probe.sh [options]

Options:
  --project PROJECT                 Google Cloud project. Default: $PROJECT or master-thesis-rise.
  --zones "ZONE ..."                Space-separated zones to test. Default: discover zones with nvidia-l4.
  --primary MACHINE[:GPU_COUNT]     Preferred machine spec. Default: g2-standard-8:1.
  --fallback "SPEC ..."             Fallback MACHINE[:GPU_COUNT] specs used only if primary has no stock.
  --first                           Stop after the first available configuration.
  --all                             Continue and list all available configurations. Default.
  --dry-run                         Print create commands without creating VMs.
  --service-account EMAIL           Service account for probe VMs.
  --help                            Show this help.

Environment overrides:
  PROJECT, GCLOUD, IMAGE_FAMILY, IMAGE_PROJECT, GPU_TYPE, BOOT_DISK_TYPE,
  BOOT_DISK_SIZE_GB, PROVISIONING_MODEL, PROBE_NAME, PRIMARY_MACHINE_SPEC,
  FALLBACK_MACHINE_SPECS, ZONES, SERVICE_ACCOUNT.

Examples:
  ./gpu_stock_probe.sh --project master-thesis-rise --first
  ./gpu_stock_probe.sh --zones "europe-west4-c us-central1-a" --all
  FALLBACK_MACHINE_SPECS="g2-standard-4:1 g2-standard-16:1" ./gpu_stock_probe.sh
EOF
}

print_command() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

order_zones() {
  local zones=("$@")
  local zone
  local region
  local preferred_region
  declare -A emitted=()

  for preferred_region in "${EUROPE_REGION_ORDER[@]}"; do
    for zone in "${zones[@]}"; do
      [[ -z "$zone" ]] && continue
      region="${zone%-*}"
      if [[ "$region" == "$preferred_region" && -z "${emitted[$zone]+x}" ]]; then
        printf '%s\n' "$zone"
        emitted["$zone"]=1
      fi
    done
  done

  for zone in "${zones[@]}"; do
    [[ -z "$zone" ]] && continue
    if [[ "$zone" == europe-* && -z "${emitted[$zone]+x}" ]]; then
      printf '%s\n' "$zone"
      emitted["$zone"]=1
    fi
  done

  for zone in "${zones[@]}"; do
    [[ -z "$zone" ]] && continue
    if [[ "$zone" != europe-* && -z "${emitted[$zone]+x}" ]]; then
      printf '%s\n' "$zone"
      emitted["$zone"]=1
    fi
  done
}

cleanup_current_instance() {
  if [[ -z "$CURRENT_INSTANCE_NAME" || -z "$CURRENT_INSTANCE_ZONE" ]]; then
    return 0
  fi

  "$GCLOUD" compute instances delete "$CURRENT_INSTANCE_NAME" \
    --project "$PROJECT" \
    --zone "$CURRENT_INSTANCE_ZONE" \
    --delete-disks all \
    --quiet >/dev/null 2>&1 || true

  CURRENT_INSTANCE_NAME=""
  CURRENT_INSTANCE_ZONE=""
}

trap cleanup_current_instance EXIT INT TERM

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project)
        PROJECT="$2"
        shift 2
        ;;
      --zones)
        ZONES="$2"
        shift 2
        ;;
      --primary)
        PRIMARY_MACHINE_SPEC="$2"
        shift 2
        ;;
      --fallback)
        FALLBACK_MACHINE_SPECS="$2"
        shift 2
        ;;
      --first|--stop-after-first)
        STOP_AFTER_FIRST=1
        shift
        ;;
      --all)
        STOP_AFTER_FIRST=0
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --service-account)
        SERVICE_ACCOUNT="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

discover_l4_zones() {
  local discovered
  local discovered_zones
  local requested_zones

  if [[ -n "$ZONES" ]]; then
    # shellcheck disable=SC2206
    requested_zones=($ZONES)
    order_zones "${requested_zones[@]}"
    return 0
  fi

  discovered="$("$GCLOUD" compute accelerator-types list \
    --project "$PROJECT" \
    --filter "name=${GPU_TYPE}" \
    --format "value(zone.basename())" 2>/dev/null)" || discovered=""

  if [[ -n "$discovered" ]]; then
    mapfile -t discovered_zones < <(printf '%s\n' "$discovered")
    order_zones "${discovered_zones[@]}"
    return 0
  fi

  echo "Warning: could not discover ${GPU_TYPE} zones; using built-in fallback zone list." >&2
  order_zones "${DEFAULT_ZONES[@]}"
}

normalise_spec() {
  local spec="$1"
  local machine_type="${spec%%:*}"
  local gpu_count="${spec#*:}"

  if [[ "$gpu_count" == "$machine_type" ]]; then
    gpu_count="1"
  fi

  printf '%s:%s\n' "$machine_type" "$gpu_count"
}

try_gpu_vm() {
  local raw_spec="$1"
  local zone="$2"
  local spec
  local machine_type
  local gpu_count
  local name

  spec="$(normalise_spec "$raw_spec")"
  machine_type="${spec%%:*}"
  gpu_count="${spec#*:}"
  name="${PROBE_NAME}-${machine_type}-${zone}-${RANDOM}"

  echo "=== Trying ${machine_type} with ${gpu_count} ${GPU_TYPE} in ${zone} ==="

  local command=(
    "$GCLOUD" compute instances create "$name"
    --project "$PROJECT"
    --zone "$zone"
    --machine-type "$machine_type"
    --accelerator "type=${GPU_TYPE},count=${gpu_count}"
    --maintenance-policy TERMINATE
    --provisioning-model "$PROVISIONING_MODEL"
    --boot-disk-type "$BOOT_DISK_TYPE"
    --boot-disk-size "${BOOT_DISK_SIZE_GB}GB"
    --image-family "$IMAGE_FAMILY"
    --image-project "$IMAGE_PROJECT"
    --metadata "startup-script=#!/usr/bin/env bash
echo probe-ready"
    --scopes cloud-platform
  )

  if [[ -n "$SERVICE_ACCOUNT" ]]; then
    command+=(--service-account "$SERVICE_ACCOUNT")
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    print_command "${command[@]}"
    echo "DRY RUN: not classifying availability."
    return 1
  fi

  CURRENT_INSTANCE_NAME="$name"
  CURRENT_INSTANCE_ZONE="$zone"

  if "${command[@]}"; then
    echo "AVAILABLE: ${machine_type}:${gpu_count} in ${zone}"
    AVAILABLE_ROWS+=("${machine_type}:${gpu_count}:${zone}")
    cleanup_current_instance
    return 0
  fi

  echo "NOT AVAILABLE: ${machine_type}:${gpu_count} in ${zone}"
  cleanup_current_instance
  return 1
}

probe_specs() {
  local phase_name="$1"
  shift

  local phase_found=0
  local raw_spec
  local zone

  echo
  echo "## ${phase_name}"

  for raw_spec in "$@"; do
    for zone in "${TEST_ZONES[@]}"; do
      if try_gpu_vm "$raw_spec" "$zone"; then
        phase_found=1
        if [[ "$STOP_AFTER_FIRST" -eq 1 ]]; then
          return 0
        fi
      fi
    done
  done

  [[ "$phase_found" -eq 1 ]]
}

print_summary() {
  echo
  if [[ "${#AVAILABLE_ROWS[@]}" -eq 0 ]]; then
    echo "No ${GPU_TYPE} stock found for tested machine specs/zones."
    return 1
  fi

  echo "Available configurations:"
  printf '%-18s %-5s %s\n' "MACHINE_TYPE" "GPUS" "ZONE"

  local row
  local machine_type
  local gpu_count
  local zone

  for row in "${AVAILABLE_ROWS[@]}"; do
    machine_type="${row%%:*}"
    zone="${row##*:}"
    gpu_count="${row#*:}"
    gpu_count="${gpu_count%:*}"
    printf '%-18s %-5s %s\n' "$machine_type" "$gpu_count" "$zone"
  done

  echo
  echo "Use these orchestrator overrides:"
  row="${AVAILABLE_ROWS[0]}"
  machine_type="${row%%:*}"
  zone="${row##*:}"
  gpu_count="${row#*:}"
  gpu_count="${gpu_count%:*}"
  echo "--zone ${zone} --machine-type ${machine_type} --gpu-type ${GPU_TYPE} --gpu-count ${gpu_count} --boot-disk-type ${BOOT_DISK_TYPE} --boot-disk-size-gb ${BOOT_DISK_SIZE_GB}"
}

main() {
  parse_args "$@"

  mapfile -t TEST_ZONES < <(discover_l4_zones)

  if [[ "${#TEST_ZONES[@]}" -eq 0 ]]; then
    echo "No zones to test." >&2
    exit 1
  fi

  echo "Project: ${PROJECT}"
  echo "GPU: ${GPU_TYPE}"
  echo "Boot disk: ${BOOT_DISK_TYPE}, ${BOOT_DISK_SIZE_GB}GB"
  echo "Zones to test: ${#TEST_ZONES[@]}"

  if ! probe_specs "Preferred orchestrator shape" "$PRIMARY_MACHINE_SPEC"; then
    # Only broaden the machine shape after every preferred-zone attempt has failed.
    # shellcheck disable=SC2086
    probe_specs "Fallback machine shapes" $FALLBACK_MACHINE_SPECS || true
  fi

  print_summary
}

main "$@"
