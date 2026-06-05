#!/usr/bin/env bash

PROJECT="master-thesis-rise"
IMAGE_FAMILY="common-cu129-ubuntu-2204-nvidia-580"
IMAGE_PROJECT="deeplearning-platform-release"
PROBE_NAME="gpu-stock-probe"

try_gpu_vm () {
  local machine_type="$1"
  local zone="$2"
  local name="${PROBE_NAME}-${machine_type}-${zone}"

  echo "=== Trying ${machine_type} in ${zone} ==="

  if gcloud compute instances create "$name" \
    --project "$PROJECT" \
    --zone "$zone" \
    --machine-type "$machine_type" \
    --accelerator type=nvidia-l4,count=1 \
    --maintenance-policy TERMINATE \
    --provisioning-model STANDARD \
    --boot-disk-type pd-balanced \
    --boot-disk-size 50GB \
    --image-family "$IMAGE_FAMILY" \
    --image-project "$IMAGE_PROJECT" \
    --metadata startup-script='#!/usr/bin/env bash
echo probe-ready' \
    --scopes cloud-platform; then

    echo "AVAILABLE: ${machine_type} in ${zone}"

    gcloud compute instances delete "$name" \
      --project "$PROJECT" \
      --zone "$zone" \
      --delete-disks all \
      --quiet

    return 0
  fi

  echo "NOT AVAILABLE: ${machine_type} in ${zone}"
  return 1
}

main () {
  local zones="
europe-west4-c europe-west4-a europe-west4-b
europe-west1-b europe-west1-c
europe-west2-a europe-west2-b
europe-west3-a europe-west3-b
europe-west6-b europe-west6-c
us-central1-a us-central1-b us-central1-c
us-east1-b us-east1-c us-east1-d
us-west1-a us-west1-b us-west1-c
us-east4-a us-east4-c
"

  local found=0

  for mt in g2-standard-8 g2-standard-4; do
    for z in $zones; do
      if try_gpu_vm "$mt" "$z"; then
        echo "SELECTED_MACHINE_TYPE=$mt"
        echo "SELECTED_ZONE=$z"
        found=1
        break 2
      fi
    done
  done

  if [ "$found" -eq 0 ]; then
    echo "No L4 stock found for tested machine types/zones."
  fi
}

main
