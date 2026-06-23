from __future__ import annotations

import argparse
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass


# Probe real Google Compute Engine L4 stock by creating short-lived VMs and deleting them immediately.
# The preferred defaults mirror orchestrate_step16_17-googleCloud.py.

DEFAULT_PROJECT = "master-thesis-rise"
DEFAULT_IMAGE_FAMILY = "common-cu129-ubuntu-2204-nvidia-580"
DEFAULT_IMAGE_PROJECT = "deeplearning-platform-release"
DEFAULT_GPU_TYPE = "nvidia-l4"
DEFAULT_BOOT_DISK_TYPE = "pd-balanced"
DEFAULT_BOOT_DISK_SIZE_GB = 200
DEFAULT_PROVISIONING_MODEL = "STANDARD"
DEFAULT_PROBE_NAME = "gpu-stock-probe"
DEFAULT_PRIMARY_SPEC = "g2-standard-8:1"
DEFAULT_FALLBACK_SPECS = "g2-standard-4:1 g2-standard-12:1 g2-standard-16:1 g2-standard-24:2"

# European regions are tried before every other region. The order keeps western Europe first,
# then southern/central/northern Europe, before falling back to the rest of the world.
EUROPE_REGION_ORDER = [
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "europe-west10",
    "europe-west12",
    "europe-southwest1",
    "europe-central2",
    "europe-north1",
]

DEFAULT_ZONES = [
    "europe-west1-b",
    "europe-west1-c",
    "europe-west1-d",
    "europe-west2-a",
    "europe-west2-b",
    "europe-west2-c",
    "europe-west3-a",
    "europe-west3-b",
    "europe-west3-c",
    "europe-west4-a",
    "europe-west4-b",
    "europe-west4-c",
    "europe-west6-a",
    "europe-west6-b",
    "europe-west6-c",
    "europe-west8-a",
    "europe-west8-b",
    "europe-west8-c",
    "europe-west9-a",
    "europe-west9-b",
    "europe-west9-c",
    "europe-west10-a",
    "europe-west10-b",
    "europe-west10-c",
    "europe-west12-a",
    "europe-west12-b",
    "europe-west12-c",
    "europe-southwest1-a",
    "europe-southwest1-b",
    "europe-southwest1-c",
    "europe-central2-a",
    "europe-central2-b",
    "europe-central2-c",
    "europe-north1-a",
    "europe-north1-b",
    "europe-north1-c",
    "asia-east1-a",
    "asia-east1-b",
    "asia-east1-c",
    "asia-northeast1-a",
    "asia-northeast1-b",
    "asia-northeast1-c",
    "asia-south1-a",
    "asia-south1-b",
    "asia-south1-c",
    "asia-southeast1-a",
    "asia-southeast1-b",
    "asia-southeast1-c",
    "australia-southeast1-a",
    "australia-southeast1-b",
    "australia-southeast1-c",
    "northamerica-northeast1-a",
    "northamerica-northeast1-b",
    "northamerica-northeast1-c",
    "southamerica-east1-a",
    "southamerica-east1-b",
    "southamerica-east1-c",
    "us-central1-a",
    "us-central1-b",
    "us-central1-c",
    "us-central1-f",
    "us-east1-b",
    "us-east1-c",
    "us-east1-d",
    "us-east4-a",
    "us-east4-b",
    "us-east4-c",
    "us-west1-a",
    "us-west1-b",
    "us-west1-c",
    "us-west2-a",
    "us-west2-b",
    "us-west2-c",
    "us-west3-a",
    "us-west3-b",
    "us-west3-c",
    "us-west4-a",
    "us-west4-b",
    "us-west4-c",
]


@dataclass(frozen=True)
class MachineSpec:
    machine_type: str
    gpu_count: int

    @classmethod
    def parse(cls, value: str) -> "MachineSpec":
        machine_type, separator, gpu_count = value.partition(":")
        if not machine_type:
            raise ValueError(f"Invalid machine spec: {value!r}")
        if not separator:
            return cls(machine_type=machine_type, gpu_count=1)
        try:
            parsed_gpu_count = int(gpu_count)
        except ValueError as exc:
            raise ValueError(f"Invalid GPU count in machine spec: {value!r}") from exc
        if parsed_gpu_count < 1:
            raise ValueError(f"GPU count must be >= 1 in machine spec: {value!r}")
        return cls(machine_type=machine_type, gpu_count=parsed_gpu_count)


@dataclass
class AvailableConfig:
    machine_type: str
    gpu_count: int
    zone: str


class QuotaExceededError(RuntimeError):
    pass


def gcloud_command() -> str:
    configured = os.environ.get("GCLOUD")
    if configured:
        return configured
    if os.name == "nt":
        return shutil.which("gcloud.cmd") or shutil.which("gcloud") or "gcloud.cmd"
    return shutil.which("gcloud") or "gcloud"


def command_to_text(command: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([arg]) if os.name == "nt" else sh_quote(arg) for arg in command)


def sh_quote(value: str) -> str:
    if not value:
        return "''"
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-=.,/:@%"
    if all(char in safe_chars for char in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_capture(command: list[str]) -> subprocess.CompletedProcess[str]:
    print("+ " + command_to_text(command))
    return subprocess.run(command, text=True, capture_output=True, check=False)


def run_stream(command: list[str], dry_run: bool) -> subprocess.CompletedProcess[str]:
    print("+ " + command_to_text(command))
    if dry_run:
        print("DRY RUN: command not executed.")
        return subprocess.CompletedProcess(command, 1, "", "")
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def is_quota_error(output: str) -> bool:
    lowered = output.lower()
    return "quota" in lowered and "exceeded" in lowered


def zone_region(zone: str) -> str:
    return zone.rsplit("-", 1)[0]


def order_zones(zones: list[str]) -> list[str]:
    unique_zones = list(dict.fromkeys(zone for zone in zones if zone))
    original_indexes = {zone: index for index, zone in enumerate(unique_zones)}
    europe_priorities = {region: index for index, region in enumerate(EUROPE_REGION_ORDER)}

    def sort_key(zone: str) -> tuple[int, int, int]:
        if zone.startswith("europe-"):
            return (0, europe_priorities.get(zone_region(zone), len(EUROPE_REGION_ORDER)), original_indexes[zone])
        return (1, 0, original_indexes[zone])

    return sorted(unique_zones, key=sort_key)


def discover_l4_zones(args: argparse.Namespace, gcloud: str) -> list[str]:
    if args.zones:
        return order_zones(args.zones)

    command = [
        gcloud,
        "compute",
        "accelerator-types",
        "list",
        "--project",
        args.project,
        "--filter",
        f"name={args.gpu_type}",
        "--format",
        "value(zone.basename())",
    ]
    result = run_capture(command)
    if result.returncode == 0:
        zones = order_zones([line.strip() for line in result.stdout.splitlines() if line.strip()])
        if zones:
            return zones

    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    print(f"Warning: could not discover {args.gpu_type} zones; using built-in fallback zone list.", file=sys.stderr)
    return order_zones(DEFAULT_ZONES)


def build_create_command(args: argparse.Namespace, gcloud: str, spec: MachineSpec, zone: str, name: str) -> list[str]:
    command = [
        gcloud,
        "compute",
        "instances",
        "create",
        name,
        "--project",
        args.project,
        "--zone",
        zone,
        "--machine-type",
        spec.machine_type,
        "--accelerator",
        f"type={args.gpu_type},count={spec.gpu_count}",
        "--maintenance-policy",
        "TERMINATE",
        "--provisioning-model",
        args.provisioning_model,
        "--boot-disk-type",
        args.boot_disk_type,
        "--boot-disk-size",
        f"{args.boot_disk_size_gb}GB",
        "--image-family",
        args.image_family,
        "--image-project",
        args.image_project,
        "--metadata",
        "startup-script=#!/usr/bin/env bash\necho probe-ready",
        "--scopes",
        "cloud-platform",
    ]
    if args.service_account:
        command.extend(["--service-account", args.service_account])
    return command


def delete_instance(args: argparse.Namespace, gcloud: str, name: str, zone: str, dry_run: bool) -> None:
    command = [
        gcloud,
        "compute",
        "instances",
        "delete",
        name,
        "--project",
        args.project,
        "--zone",
        zone,
        "--delete-disks",
        "all",
        "--quiet",
    ]
    if dry_run:
        return
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def try_gpu_vm(args: argparse.Namespace, gcloud: str, spec: MachineSpec, zone: str) -> AvailableConfig | None:
    random_suffix = random.randint(10000, 99999)
    name = f"{args.probe_name}-{spec.machine_type}-{zone}-{random_suffix}"
    print(f"=== Trying {spec.machine_type} with {spec.gpu_count} {args.gpu_type} in {zone} ===")

    command = build_create_command(args, gcloud, spec, zone, name)
    try:
        result = run_stream(command, args.dry_run)
        if args.dry_run:
            return None
        combined_output = f"{result.stdout}\n{result.stderr}"
        if result.returncode == 0:
            print(f"AVAILABLE: {spec.machine_type}:{spec.gpu_count} in {zone}")
            return AvailableConfig(spec.machine_type, spec.gpu_count, zone)
        if is_quota_error(combined_output):
            raise QuotaExceededError(
                f"Quota exceeded while trying {spec.machine_type}:{spec.gpu_count} in {zone}. "
                "Stop probing and free GPU quota or request a quota increase."
            )
        print(f"NOT AVAILABLE: {spec.machine_type}:{spec.gpu_count} in {zone}")
        return None
    finally:
        delete_instance(args, gcloud, name, zone, args.dry_run)


def probe_specs(
    phase_name: str,
    args: argparse.Namespace,
    gcloud: str,
    specs: list[MachineSpec],
    zones: list[str],
) -> list[AvailableConfig]:
    print()
    print(f"## {phase_name}")
    available: list[AvailableConfig] = []

    for spec in specs:
        for zone in zones:
            config = try_gpu_vm(args, gcloud, spec, zone)
            if config:
                available.append(config)
                if args.first:
                    return available

    return available


def print_summary(args: argparse.Namespace, available: list[AvailableConfig]) -> int:
    print()
    if not available:
        print(f"No {args.gpu_type} stock found for tested machine specs/zones.")
        return 1

    print("Available configurations:")
    print(f"{'MACHINE_TYPE':<18} {'GPUS':<5} ZONE")
    for config in available:
        print(f"{config.machine_type:<18} {config.gpu_count:<5} {config.zone}")

    selected = available[0]
    print()
    print("Use these orchestrator overrides:")
    print(
        f"--zone {selected.zone} "
        f"--machine-type {selected.machine_type} "
        f"--gpu-type {args.gpu_type} "
        f"--gpu-count {selected.gpu_count} "
        f"--boot-disk-type {args.boot_disk_type} "
        f"--boot-disk-size-gb {args.boot_disk_size_gb}"
    )
    return 0


def split_specs(value: str) -> list[MachineSpec]:
    return [MachineSpec.parse(item) for item in value.split() if item.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe Google Compute Engine L4 stock by creating and deleting short-lived VMs."
    )
    parser.add_argument("--project", default=os.environ.get("PROJECT", DEFAULT_PROJECT))
    parser.add_argument("--zones", nargs="+", help="Zones to test. Default: discover zones with the selected GPU.")
    parser.add_argument("--primary", default=os.environ.get("PRIMARY_MACHINE_SPEC", DEFAULT_PRIMARY_SPEC))
    parser.add_argument("--fallback", default=os.environ.get("FALLBACK_MACHINE_SPECS", DEFAULT_FALLBACK_SPECS))
    parser.add_argument("--first", action="store_true", help="Stop after the first available configuration.")
    parser.add_argument("--all", action="store_true", help="Continue and list all available configurations. Default.")
    parser.add_argument("--dry-run", action="store_true", help="Print create commands without creating VMs.")
    parser.add_argument("--service-account", default=os.environ.get("SERVICE_ACCOUNT", ""))
    parser.add_argument("--image-family", default=os.environ.get("IMAGE_FAMILY", DEFAULT_IMAGE_FAMILY))
    parser.add_argument("--image-project", default=os.environ.get("IMAGE_PROJECT", DEFAULT_IMAGE_PROJECT))
    parser.add_argument("--gpu-type", default=os.environ.get("GPU_TYPE", DEFAULT_GPU_TYPE))
    parser.add_argument("--boot-disk-type", default=os.environ.get("BOOT_DISK_TYPE", DEFAULT_BOOT_DISK_TYPE))
    parser.add_argument(
        "--boot-disk-size-gb",
        type=int,
        default=int(os.environ.get("BOOT_DISK_SIZE_GB", str(DEFAULT_BOOT_DISK_SIZE_GB))),
    )
    parser.add_argument("--provisioning-model", default=os.environ.get("PROVISIONING_MODEL", DEFAULT_PROVISIONING_MODEL))
    parser.add_argument("--probe-name", default=os.environ.get("PROBE_NAME", DEFAULT_PROBE_NAME))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gcloud = gcloud_command()
    primary_specs = split_specs(args.primary)
    fallback_specs = split_specs(args.fallback)
    zones = discover_l4_zones(args, gcloud)

    print(f"Project: {args.project}")
    print(f"gcloud: {gcloud}")
    print(f"GPU: {args.gpu_type}")
    print(f"Boot disk: {args.boot_disk_type}, {args.boot_disk_size_gb}GB")
    print(f"Zones to test: {len(zones)}")

    try:
        available = probe_specs("Preferred orchestrator shape", args, gcloud, primary_specs, zones)
        if not available:
            available.extend(probe_specs("Fallback machine shapes", args, gcloud, fallback_specs, zones))
        return print_summary(args, available)
    except QuotaExceededError as exc:
        print()
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
