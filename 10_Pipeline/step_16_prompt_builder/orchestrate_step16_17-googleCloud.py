from __future__ import annotations

import argparse
import shlex
import subprocess
import tempfile
import time
from pathlib import Path


# This script orchestrates a temporary Google Compute Engine GPU VM for Steps 16 and 17.
# It does not change the original Step 16 or Step 17 scripts; it copies them to the VM and runs them there.

PIPELINE_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INSTANCE_NAME = "llm-runner-step16-17"
DEFAULT_ZONE = "europe-west4-c"
DEFAULT_MACHINE_TYPE = "g2-standard-8"
DEFAULT_GPU_TYPE = "nvidia-l4"
DEFAULT_GPU_COUNT = 1
DEFAULT_BOOT_DISK_TYPE = "pd-balanced"
DEFAULT_BOOT_DISK_SIZE_GB = 200
DEFAULT_IMAGE_FAMILY = "common-cu129-ubuntu-2204-nvidia-580"
DEFAULT_IMAGE_PROJECT = "deeplearning-platform-release"
DEFAULT_REMOTE_ROOT = "thesis_Santos"
DEFAULT_CONFIG = PIPELINE_ROOT / "step_11_experiment_setup" / "config_LLM_baseline.json"
DEFAULT_GCS_MODEL_ROOT = "gs://thesis-santos-llm-artifacts/models"

# This catalog maps short model names used by the orchestrator to their Cloud Storage directories.
# Add new entries here when more Hugging Face models are staged in the project bucket.
GCS_MODEL_CATALOG = {
    "llama-3.1-8b-instruct": "meta-llama/Llama-3.1-8B-Instruct",
}


# This function formats command lists as shell-like strings for readable logs before execution.
def quote_args(args: list[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


# This function prints and runs a local command. The dry-run flag keeps orchestration testable without touching Google Cloud.
def run_command(command: list[str], dry_run: bool) -> None:
    print(quote_args(command))
    if not dry_run:
        subprocess.run(command, check=True)


# This function runs a command inside the Google Compute VM over gcloud SSH.
def run_remote(args: argparse.Namespace, remote_command: str) -> None:
    command = [
        "gcloud",
        "compute",
        "ssh",
        args.instance_name,
        "--project",
        args.project,
        "--zone",
        args.zone,
        "--command",
        remote_command,
    ]
    if args.tunnel_through_iap:
        command.append("--tunnel-through-iap")
    run_command(command, args.dry_run)


# This function runs a remote command and returns stdout. It is used when the local script needs information from the VM, such as the remote home directory.
def capture_remote(args: argparse.Namespace, remote_command: str) -> str:
    command = [
        "gcloud",
        "compute",
        "ssh",
        args.instance_name,
        "--project",
        args.project,
        "--zone",
        args.zone,
        "--command",
        remote_command,
    ]
    if args.tunnel_through_iap:
        command.append("--tunnel-through-iap")
    print(quote_args(command))
    if args.dry_run:
        return ""
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    if result.stderr:
        print(result.stderr, end="")
    if result.stdout:
        print(result.stdout, end="")
    return result.stdout.strip()


# This function turns a relative remote root into an absolute path under the SSH user's home directory.
# This avoids assuming that Google images always use /home/ubuntu.
def resolve_remote_root(args: argparse.Namespace) -> None:
    if args.remote_root.startswith("/"):
        return
    remote_home = capture_remote(args, "printf '%s' \"$HOME\"")
    if not remote_home:
        return
    args.remote_root = f"{remote_home.rstrip('/')}/{args.remote_root.strip('/')}"


# This function copies local files or folders to the VM using gcloud scp.
def scp_to_remote(args: argparse.Namespace, local_path: Path, remote_path: str) -> None:
    command = [
        "gcloud",
        "compute",
        "scp",
        "--recurse",
        str(local_path),
        f"{args.instance_name}:{remote_path}",
        "--project",
        args.project,
        "--zone",
        args.zone,
    ]
    if args.tunnel_through_iap:
        command.append("--tunnel-through-iap")
    run_command(command, args.dry_run)


# This function copies experiment outputs from the VM back to the local machine.
def scp_from_remote(args: argparse.Namespace, remote_path: str, local_path: Path) -> None:
    local_path.mkdir(parents=True, exist_ok=True)
    command = [
        "gcloud",
        "compute",
        "scp",
        "--recurse",
        f"{args.instance_name}:{remote_path}",
        str(local_path),
        "--project",
        args.project,
        "--zone",
        args.zone,
    ]
    if args.tunnel_through_iap:
        command.append("--tunnel-through-iap")
    run_command(command, args.dry_run)


# This function builds the startup script used when creating a new VM.
# The image already provides the NVIDIA driver; this script installs the basic tooling needed by the pipeline.
def build_startup_script() -> str:
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y python3-venv python3-pip git build-essential curl wget jq docker.io",
            "python3 -m pip install --upgrade pip",
            "python3 -m pip install diskcache jinja2 numpy typing-extensions",
        ]
    ) + "\n"


# This function creates the Google Compute Engine VM with the requested machine type, GPU, boot disk and image.
def create_instance(args: argparse.Namespace) -> None:
    with tempfile.NamedTemporaryFile("w", suffix="-startup-googleCloud.sh", delete=False, encoding="utf-8") as startup_file:
        startup_file.write(build_startup_script())
        startup_path = Path(startup_file.name)

    command = [
        "gcloud",
        "compute",
        "instances",
        "create",
        args.instance_name,
        "--project",
        args.project,
        "--zone",
        args.zone,
        "--machine-type",
        args.machine_type,
        "--accelerator",
        f"type={args.gpu_type},count={args.gpu_count}",
        "--maintenance-policy",
        "TERMINATE",
        "--provisioning-model",
        "STANDARD",
        "--boot-disk-type",
        args.boot_disk_type,
        "--boot-disk-size",
        f"{args.boot_disk_size_gb}GB",
        "--image-family",
        args.image_family,
        "--image-project",
        args.image_project,
        "--metadata-from-file",
        f"startup-script={startup_path}",
        "--scopes",
        "cloud-platform",
    ]
    if args.service_account:
        command.extend(["--service-account", args.service_account])
    run_command(command, args.dry_run)


# This function deletes the VM and all attached disks when the user explicitly asks for cleanup.
def delete_instance(args: argparse.Namespace) -> None:
    command = [
        "gcloud",
        "compute",
        "instances",
        "delete",
        args.instance_name,
        "--project",
        args.project,
        "--zone",
        args.zone,
        "--delete-disks",
        "all",
        "--quiet",
    ]
    run_command(command, args.dry_run)


# This function waits until gcloud SSH can connect to the VM.
# It is needed because instance creation can finish before SSH and startup scripts are ready.
def wait_for_ssh(args: argparse.Namespace) -> None:
    if args.dry_run:
        print("# dry-run: skipping SSH readiness wait")
        return
    deadline = time.monotonic() + args.ssh_timeout_seconds
    while time.monotonic() < deadline:
        try:
            run_remote(args, "echo READY")
            return
        except subprocess.CalledProcessError:
            time.sleep(10)
    raise TimeoutError(f"VM did not become reachable over SSH within {args.ssh_timeout_seconds} seconds.")


# This function creates the same high-level folder layout used in the RISE cloud environment.
def create_remote_layout(args: argparse.Namespace) -> None:
    remote_root = shlex.quote(args.remote_root)
    experiment_id = shlex.quote(args.experiment_id)
    command = "\n".join(
        [
            "set -euo pipefail",
            f"mkdir -p {remote_root}/01_InputFiles/{experiment_id}",
            f"mkdir -p {remote_root}/02_OutputFiles/{experiment_id}",
            f"mkdir -p {remote_root}/03_Models",
            f"mkdir -p {remote_root}/04_Steps/Step16",
            f"mkdir -p {remote_root}/04_Steps/Step17",
            f"mkdir -p {remote_root}/04_Steps/common",
            f"mkdir -p {remote_root}/04_Steps/setups",
        ]
    )
    run_remote(args, command)


# This function transfers the Step 16, Step 17, shared code, config, and Dockerfile to the VM.
def transfer_pipeline_files(args: argparse.Namespace) -> None:
    remote_steps = f"{args.remote_root}/04_Steps"
    scp_to_remote(args, PIPELINE_ROOT / "common", f"{remote_steps}/")
    scp_to_remote(args, PIPELINE_ROOT / "step_16_prompt_builder" / "build_prompts.py", f"{remote_steps}/Step16/")
    scp_to_remote(args, PIPELINE_ROOT / "step_16_prompt_builder" / "build_prompts-googleCloud.py", f"{remote_steps}/Step16/")
    scp_to_remote(args, PIPELINE_ROOT / "step_16_prompt_builder" / "Dockerfile.step16-17-googleCloud", f"{remote_steps}/Step16/")
    scp_to_remote(args, PIPELINE_ROOT / "step_17_llm_batch_runner" / "run_llm_batch.py", f"{remote_steps}/Step17/")
    scp_to_remote(args, PIPELINE_ROOT / "step_17_llm_batch_runner" / "run_llm_batch-googleCloud.py", f"{remote_steps}/Step17/")
    scp_to_remote(args, Path(args.config), f"{remote_steps}/setups/config_LLM_baseline.json")


# This function optionally transfers local Step 15 group files into the VM input folder.
def transfer_group_inputs(args: argparse.Namespace) -> None:
    if not args.local_groups_dir:
        return
    remote_input = f"{args.remote_root}/01_InputFiles/{args.experiment_id}/"
    scp_to_remote(args, Path(args.local_groups_dir), remote_input)


# This function downloads model files from direct URLs when the user chooses URL-based model staging.
def download_models(args: argparse.Namespace) -> None:
    if not args.model_url:
        return
    commands = ["set -euo pipefail", f"mkdir -p {shlex.quote(args.remote_root)}/03_Models"]
    for model_url in args.model_url:
        filename = model_url.rstrip("/").split("/")[-1].split("?")[0]
        output_path = f"{args.remote_root}/03_Models/{filename}"
        commands.append(f"wget -c -O {shlex.quote(output_path)} {shlex.quote(model_url)}")
    run_remote(args, "\n".join(commands))


# This function resolves the model selection requested with --sync-model.
# It accepts catalog names, relative paths under the GCS model root, full gs:// paths, or all.
def resolve_selected_gcs_model_dirs(args: argparse.Namespace) -> list[str]:
    selected_dirs = list(args.gcs_model_dir or [])
    requested_models = args.sync_model or ["all"]
    lowered_requests = [model_name.lower() for model_name in requested_models]

    if "all" in lowered_requests:
        catalog_values = list(GCS_MODEL_CATALOG.values())
    else:
        catalog_values = []
        for model_name in requested_models:
            lookup_key = model_name.lower()
            if lookup_key in GCS_MODEL_CATALOG:
                catalog_values.append(GCS_MODEL_CATALOG[lookup_key])
            elif model_name.startswith("gs://"):
                selected_dirs.append(model_name)
            else:
                catalog_values.append(model_name.strip("/"))

    model_root = args.gcs_model_root.rstrip("/")
    for catalog_value in catalog_values:
        if catalog_value.startswith("gs://"):
            selected_dirs.append(catalog_value.rstrip("/"))
        else:
            selected_dirs.append(f"{model_root}/{catalog_value.strip('/')}")

    unique_dirs = []
    seen = set()
    for model_dir in selected_dirs:
        clean_dir = model_dir.rstrip("/")
        if clean_dir not in seen:
            unique_dirs.append(clean_dir)
            seen.add(clean_dir)
    return unique_dirs


# This function synchronises selected models from Google Cloud Storage to the VM local model directory.
# For the vLLM backend, the synced local model paths are passed into Step 17 automatically.
def sync_models_from_gcs(args: argparse.Namespace) -> None:
    selected_model_dirs = resolve_selected_gcs_model_dirs(args)
    if not selected_model_dirs:
        return
    local_model_paths = []
    commands = ["set -euo pipefail", f"mkdir -p {shlex.quote(args.remote_root)}/03_Models"]
    for gcs_model_dir in selected_model_dirs:
        clean_gcs_path = gcs_model_dir.rstrip("/")
        model_name = clean_gcs_path.split("/")[-1]
        remote_model_path = f"{args.remote_root}/03_Models/{model_name}"
        commands.append(f"mkdir -p {shlex.quote(remote_model_path)}")
        commands.append(f"gcloud storage rsync -r {shlex.quote(clean_gcs_path)} {shlex.quote(remote_model_path)}")
        local_model_paths.append(remote_model_path)
    run_remote(args, "\n".join(commands))
    if args.step17_backend == "vllm" and not args.hf_model_id and not args.model_path:
        args.model_path = local_model_paths


# This function installs and smoke-tests llama-cpp-python only when the legacy llama-cpp backend is selected.
def install_llama_cpp(args: argparse.Namespace) -> None:
    if args.step17_backend != "llama-cpp" or args.skip_llama_cpp_install:
        return
    command = "\n".join(
        [
            "set -euo pipefail",
            "python3 -m pip install --upgrade pip",
            f"python3 -m pip install --no-cache-dir --force-reinstall {shlex.quote(args.llama_cpp_package)}",
            "python3 - <<'PY'",
            "import llama_cpp",
            "print('llama_cpp version:', getattr(llama_cpp, '__version__', 'unknown'))",
            "print('supports gpu offload:', llama_cpp.llama_supports_gpu_offload())",
            "PY",
        ]
    )
    run_remote(args, command)


# This function builds the Docker image used by the Google Cloud vLLM execution path.
def build_docker_image(args: argparse.Namespace) -> None:
    if not args.use_docker or args.skip_docker_build:
        return
    command = (
        f"cd {shlex.quote(args.remote_root + '/04_Steps/Step16')} && "
        f"sudo docker build -f Dockerfile.step16-17-googleCloud -t {shlex.quote(args.docker_image)} ."
    )
    run_remote(args, command)


# This function wraps a pipeline command in docker run when --use-docker is enabled.
# The thesis folder is mounted at the same path inside the container so config paths remain stable.
def dockerized_command(args: argparse.Namespace, workdir: str, command: list[str]) -> str:
    if not args.use_docker:
        return f"cd {shlex.quote(workdir)} && {quote_args(command)}"
    docker_command = [
        "sudo",
        "docker",
        "run",
        "--rm",
        "--gpus",
        "all",
        "-e",
        f"HF_TOKEN={args.hf_token}" if args.hf_token else "HF_TOKEN=",
        "-e",
        "HF_HUB_ENABLE_HF_TRANSFER=1",
        "-v",
        f"{args.remote_root}:{args.remote_root}",
        "-w",
        workdir,
        args.docker_image,
    ]
    docker_command.extend(command)
    return quote_args(docker_command)


# This function runs Step 16 on the VM to build prompt packages from the configured group inputs.
def run_step16(args: argparse.Namespace) -> None:
    command = [
        "python3",
        "build_prompts-googleCloud.py",
        "--config",
        f"{args.remote_root}/04_Steps/setups/config_LLM_baseline.json",
        "--cloud-root",
        args.remote_root,
    ]
    if args.step16_input_dir:
        command.extend(["--input-dir", args.step16_input_dir])
    if args.step16_output_dir:
        command.extend(["--output-dir", args.step16_output_dir])
    if args.limit_groups is not None:
        command.extend(["--limit-groups", str(args.limit_groups)])
    remote_command = dockerized_command(args, args.remote_root + "/04_Steps/Step16", command)
    run_remote(args, remote_command)


# This function runs Step 17 on the VM.
# The default Google Cloud path uses vLLM, while the legacy llama-cpp runner can still be selected explicitly.
def run_step17(args: argparse.Namespace) -> None:
    step17_script = "run_llm_batch-googleCloud.py" if args.step17_backend == "vllm" else "run_llm_batch.py"
    command = [
        "python3",
        step17_script,
        "--config",
        f"{args.remote_root}/04_Steps/setups/config_LLM_baseline.json",
        "--cloud-root",
        args.remote_root,
        "--n-gpu-layers",
        str(args.n_gpu_layers),
        "--progress-every",
        str(args.progress_every),
        "--heartbeat-seconds",
        str(args.heartbeat_seconds),
    ]
    if args.n_threads is not None:
        command.extend(["--n-threads", str(args.n_threads)])
    if args.limit_prompts is not None:
        command.extend(["--limit-prompts", str(args.limit_prompts)])
    if args.model_filter:
        command.extend(["--model-filter", args.model_filter])
    if args.hf_model_id:
        for hf_model_id in args.hf_model_id:
            command.extend(["--hf-model-id", hf_model_id])
    if args.model_path:
        for model_path in args.model_path:
            command.extend(["--model-path", model_path])
    if args.step17_backend == "vllm":
        command.extend(["--vllm-dtype", args.vllm_dtype])
        command.extend(["--vllm-gpu-memory-utilization", str(args.vllm_gpu_memory_utilization)])
        if args.vllm_quantization:
            command.extend(["--vllm-quantization", args.vllm_quantization])
        if args.vllm_max_model_len is not None:
            command.extend(["--vllm-max-model-len", str(args.vllm_max_model_len)])
        if args.trust_remote_code:
            command.append("--trust-remote-code")
    if args.output_token_margin_percent is not None:
        command.extend(["--output-token-margin-percent", str(args.output_token_margin_percent)])
    remote_command = dockerized_command(args, args.remote_root + "/04_Steps/Step17", command)
    run_remote(args, remote_command)


# This function fetches the experiment output folder from the VM after Step 16/17 execution.
def fetch_outputs(args: argparse.Namespace) -> None:
    if not args.local_output_dir:
        return
    local_output_dir = Path(args.local_output_dir)
    remote_experiment_output = f"{args.remote_root}/02_OutputFiles/{args.experiment_id}"
    scp_from_remote(args, remote_experiment_output, local_output_dir)


# This function defines all command-line options used by the orchestrator.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a Google GPU VM, run Step 16 and Step 17 there, and copy outputs back."
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", default=DEFAULT_ZONE)
    parser.add_argument("--instance-name", default=DEFAULT_INSTANCE_NAME)
    parser.add_argument("--machine-type", default=DEFAULT_MACHINE_TYPE)
    parser.add_argument("--gpu-type", default=DEFAULT_GPU_TYPE)
    parser.add_argument("--gpu-count", type=int, default=DEFAULT_GPU_COUNT)
    parser.add_argument("--boot-disk-type", default=DEFAULT_BOOT_DISK_TYPE)
    parser.add_argument("--boot-disk-size-gb", type=int, default=DEFAULT_BOOT_DISK_SIZE_GB)
    parser.add_argument("--image-family", default=DEFAULT_IMAGE_FAMILY)
    parser.add_argument("--image-project", default=DEFAULT_IMAGE_PROJECT)
    parser.add_argument("--service-account")
    parser.add_argument("--tunnel-through-iap", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-create-instance", action="store_true")
    parser.add_argument("--test-setup-only", action="store_true", help="Create/reuse the VM, create the remote layout, transfer scripts, build Docker, sync requested models, and stop before Step 16/17 execution.")
    parser.add_argument("--delete-instance-after-run", action="store_true")
    parser.add_argument("--ssh-timeout-seconds", type=int, default=900)

    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--local-groups-dir")
    parser.add_argument("--local-output-dir")

    parser.add_argument("--model-url", action="append", help="Direct downloadable model URL. Can be repeated.")
    parser.add_argument("--gcs-model-dir", action="append", help="Cloud Storage model directory to sync to the VM. Can be repeated.")
    parser.add_argument("--gcs-model-root", default=DEFAULT_GCS_MODEL_ROOT, help="Cloud Storage root used for catalog/relative model names.")
    parser.add_argument(
        "--sync-model",
        action="append",
        help="Model name to sync from the GCS catalog, a relative path under --gcs-model-root, a gs:// path, or all. Defaults to all.",
    )
    parser.add_argument("--skip-llama-cpp-install", action="store_true")
    parser.add_argument("--llama-cpp-package", default="llama-cpp-python")
    parser.add_argument("--use-docker", action="store_true")
    parser.add_argument("--skip-docker-build", action="store_true")
    parser.add_argument("--docker-image", default="thesis-step16-17-vllm:latest")
    parser.add_argument("--hf-token", default="")

    parser.add_argument("--step16-input-dir")
    parser.add_argument("--step16-output-dir")
    parser.add_argument("--limit-groups", type=int)

    parser.add_argument("--limit-prompts", type=int)
    parser.add_argument("--step17-backend", choices=["vllm", "llama-cpp"], default="vllm")
    parser.add_argument("--hf-model-id", action="append")
    parser.add_argument("--model-filter")
    parser.add_argument("--model-path", action="append")
    parser.add_argument("--vllm-dtype", default="auto")
    parser.add_argument("--vllm-quantization")
    parser.add_argument("--vllm-gpu-memory-utilization", type=float, default=0.90)
    parser.add_argument("--vllm-max-model-len", type=int)
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--n-gpu-layers", type=int, default=-1)
    parser.add_argument("--n-threads", type=int)
    parser.add_argument("--progress-every", type=int, default=1)
    parser.add_argument("--heartbeat-seconds", type=int, default=30)
    parser.add_argument("--output-token-margin-percent", type=float)
    return parser.parse_args()


# This is the main orchestration sequence.
# In test setup mode it stops after VM setup, file transfer, Docker build, group transfer, and model sync.
def main() -> None:
    args = parse_args()
    try:
        if not args.skip_create_instance:
            create_instance(args)
        wait_for_ssh(args)
        resolve_remote_root(args)
        create_remote_layout(args)
        transfer_pipeline_files(args)
        build_docker_image(args)
        transfer_group_inputs(args)
        sync_models_from_gcs(args)
        download_models(args)
        if args.test_setup_only:
            return
        install_llama_cpp(args)
        run_step16(args)
        run_step17(args)
        fetch_outputs(args)
    finally:
        if args.delete_instance_after_run:
            delete_instance(args)


if __name__ == "__main__":
    main()
