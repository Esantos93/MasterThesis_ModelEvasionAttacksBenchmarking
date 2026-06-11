from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
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
DEFAULT_SSH_USER = "dornas93"
DEFAULT_CONFIG = PIPELINE_ROOT / "step_11_experiment_setup" / "config_LLM_baseline.json"
DEFAULT_GCS_MODEL_ROOT = "gs://thesis-santos-llm-artifacts/models"
DEFAULT_GCS_GROUP_ROOT = "gs://thesis-santos-llm-artifacts"
GCLOUD_COMMAND = "gcloud.cmd" if os.name == "nt" else "gcloud"

# This catalog maps short model names used by the orchestrator to their Cloud Storage directories.
# Add new entries here when more Hugging Face models are staged in the project bucket.
GCS_MODEL_CATALOG = {
    "llama-3.1-8b-instruct": "meta-llama/Llama-3.1-8B-Instruct",
}


# This small wrapper mirrors orchestrator stdout/stderr into a persistent local log file.
class TeeStream:
    def __init__(self, stream, log_file):
        self.stream = stream
        self.log_file = log_file

    def write(self, text: str) -> int:
        written = self.stream.write(text)
        self.log_file.write(text)
        self.log_file.flush()
        return written

    def flush(self) -> None:
        self.stream.flush()
        self.log_file.flush()


# This function starts persistent terminal logging for the orchestrator run.
def configure_logging(args: argparse.Namespace):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_id = args.step17_run_id or "no_run_id_yet"
    if args.log_file:
        log_path = Path(args.log_file).expanduser()
    elif args.local_output_dir:
        log_path = (
            Path(args.local_output_dir).expanduser()
            / "logs"
            / "orchestrate_step16_17-googleCloud"
            / run_id
            / f"orchestrator_{timestamp}.log"
        )
    else:
        log_path = (
            Path("logs")
            / "orchestrate_step16_17-googleCloud"
            / run_id
            / f"orchestrator_{timestamp}.log"
        )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("w", encoding="utf-8", buffering=1)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeStream(original_stdout, log_file)
    sys.stderr = TeeStream(original_stderr, log_file)
    print(f"Orchestrator log: {log_path}")
    return log_file, original_stdout, original_stderr


# This function formats command lists as shell-like strings for readable logs before execution.
def quote_args(args: list[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


# This function prints and runs a local command. The dry-run flag keeps orchestration testable without touching Google Cloud.
def run_command(command: list[str], dry_run: bool) -> None:
    print(quote_args(command))
    if dry_run:
        return
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")
    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, command)


# This function runs a local command and returns stdout when the orchestrator needs local command output.
def capture_command(command: list[str], dry_run: bool) -> str:
    print(quote_args(command))
    if dry_run:
        return ""
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    if result.stderr:
        print(result.stderr, end="")
    if result.stdout:
        print(result.stdout, end="")
    return result.stdout.strip()


# This function builds the gcloud SSH/SCP target. When --ssh-user is set, gcloud connects as that Linux user.
def remote_target(args: argparse.Namespace) -> str:
    if args.ssh_user:
        return f"{args.ssh_user}@{args.instance_name}"
    return args.instance_name


# This function runs a command inside the Google Compute VM over gcloud SSH.
def run_remote(args: argparse.Namespace, remote_command: str) -> None:
    command = [
        GCLOUD_COMMAND,
        "compute",
        "ssh",
        remote_target(args),
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
        GCLOUD_COMMAND,
        "compute",
        "ssh",
        remote_target(args),
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
        GCLOUD_COMMAND,
        "compute",
        "scp",
        "--recurse",
        str(local_path),
        f"{remote_target(args)}:{remote_path}",
        "--project",
        args.project,
        "--zone",
        args.zone,
    ]
    if args.tunnel_through_iap:
        command.append("--tunnel-through-iap")
    run_command(command, args.dry_run)


# This function generates local runtime summaries after Step 17 artifacts have been fetched.
def summarize_local_runtime(args: argparse.Namespace, local_model_run_dir: Path, local_prompt_dir: Path) -> None:
    if args.skip_runtime_summary:
        return
    summarizer_path = PIPELINE_ROOT / "step_17_llm_batch_runner" / "summarize_llm_runtime.py"
    command = [
        sys.executable,
        str(summarizer_path),
        "--run-dir",
        str(local_model_run_dir),
        "--prompt-dir",
        str(local_prompt_dir),
    ]
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
        GCLOUD_COMMAND,
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
        GCLOUD_COMMAND,
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
    for common_file in sorted((PIPELINE_ROOT / "common").glob("*.py")):
        scp_to_remote(args, common_file, f"{remote_steps}/common/")
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


# This function returns the Step 16 input directory, using an explicit override when provided.
def step16_input_dir(args: argparse.Namespace) -> str:
    if args.step16_input_dir:
        return args.step16_input_dir
    return f"{args.remote_root}/01_InputFiles/{args.experiment_id}/05_groups"


# This function extracts a folder label from a Cloud Storage path, for example size_003.
def gcs_path_leaf(gcs_path: str) -> str:
    return gcs_path.rstrip("/").split("/")[-1]


# This function keeps run ids and grouping labels safe for local and remote path segments.
def safe_path_label(value: str) -> str:
    cleaned = []
    for character in value.strip():
        if character.isalnum() or character in {"-", "_", "."}:
            cleaned.append(character)
        else:
            cleaned.append("_")
    return "".join(cleaned).strip("._") or "default"


# This function resolves the grouping label used in remote and local Step 16/17 output paths.
def resolve_grouping_label(args: argparse.Namespace) -> str:
    if args.grouping_label:
        return safe_path_label(args.grouping_label)
    for candidate in (args.step16_input_dir, args.gcs_groups_dir, args.local_groups_dir):
        if candidate:
            return safe_path_label(str(candidate).rstrip("/\\").replace("\\", "/").split("/")[-1])
    return "05_groups"


# This function resolves a stable run id before Step 16/17 execute so both steps use the same run-specific paths.
def resolve_step17_run_id(args: argparse.Namespace) -> str:
    if args.step17_run_id:
        args.step17_run_id = safe_path_label(args.step17_run_id)
        return args.step17_run_id
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    label = args.step17_run_label or resolve_grouping_label(args)
    args.step17_run_id = f"run_{timestamp}_{safe_path_label(label)}"
    return args.step17_run_id


# This function resolves the run-specific remote prompt directory produced by Step 16.
def resolve_step16_output_dir(args: argparse.Namespace) -> str:
    if args.step16_output_dir:
        return args.step16_output_dir.rstrip("/")
    grouping_label = resolve_grouping_label(args)
    run_id = resolve_step17_run_id(args)
    args.step16_output_dir = (
        f"{args.remote_root}/02_OutputFiles/{args.experiment_id}/06_prompts/{grouping_label}/{run_id}"
    )
    return args.step16_output_dir


# This function resolves the remote Step 17 output root. Step 17 itself appends <model_name>/<run_id>.
def resolve_step17_output_root(args: argparse.Namespace) -> str:
    if args.step17_output_root:
        return args.step17_output_root.rstrip("/")
    grouping_label = resolve_grouping_label(args)
    args.step17_output_root = f"{args.remote_root}/02_OutputFiles/{args.experiment_id}/07_llm_outputs/{grouping_label}"
    return args.step17_output_root


# This function finds model-specific Step 17 run directories below the resolved remote output root.
def list_remote_model_run_dirs(args: argparse.Namespace, remote_step17_root: str, run_id: str) -> list[str]:
    if args.dry_run:
        return [f"{remote_step17_root}/MODEL_NAME/{run_id}"]
    command = (
        f"find {shlex.quote(remote_step17_root)} -mindepth 2 -maxdepth 2 "
        f"-type d -name {shlex.quote(run_id)} | sort"
    )
    stdout = capture_remote(args, command)
    model_run_dirs = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not model_run_dirs:
        raise FileNotFoundError(f"No Step 17 model run directories found under {remote_step17_root} for run_id={run_id}.")
    return model_run_dirs


# This function resolves the GCS root used for run artifact exchange.
def resolve_gcs_output_root(args: argparse.Namespace) -> str:
    if args.gcs_output_root:
        return args.gcs_output_root.rstrip("/")
    args.gcs_output_root = f"{DEFAULT_GCS_GROUP_ROOT.rstrip('/')}/{args.experiment_id}/runs"
    return args.gcs_output_root


# This function resolves the run-specific GCS artifact root.
def resolve_gcs_run_root(args: argparse.Namespace) -> str:
    return f"{resolve_gcs_output_root(args)}/{resolve_step17_run_id(args)}"


# This function lists model folders already staged in the run-specific GCS Step 17 output tree.
def list_gcs_model_output_dirs(args: argparse.Namespace, gcs_run_root: str) -> list[str]:
    if args.dry_run:
        return [f"{gcs_run_root}/07_llm_outputs/MODEL_NAME/"]
    command = [GCLOUD_COMMAND, "storage", "ls", f"{gcs_run_root}/07_llm_outputs/"]
    stdout = capture_command(command, args.dry_run)
    model_dirs = [line.strip().rstrip("/") for line in stdout.splitlines() if line.strip().endswith("/")]
    if not model_dirs:
        raise FileNotFoundError(f"No model output directories found under {gcs_run_root}/07_llm_outputs/.")
    return model_dirs


# This function checks whether a GCS path exists without dumping storage command errors into the normal flow.
def gcs_path_exists(args: argparse.Namespace, gcs_path: str) -> bool:
    print(quote_args([GCLOUD_COMMAND, "storage", "ls", gcs_path]))
    if args.dry_run:
        return True
    result = subprocess.run(
        [GCLOUD_COMMAND, "storage", "ls", gcs_path],
        text=True,
        capture_output=True,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


# This function synchronises Step 15 group files from Cloud Storage into the VM input directory used by Step 16.
def sync_groups_from_gcs(args: argparse.Namespace) -> None:
    if not args.gcs_groups_dir:
        return
    source_dir = args.gcs_groups_dir.rstrip("/")
    if not source_dir.startswith("gs://"):
        source_dir = f"{args.gcs_group_root.rstrip('/')}/{source_dir.strip('/')}"
    if args.step16_input_dir:
        destination_dir = args.step16_input_dir
    else:
        destination_dir = f"{args.remote_root}/01_InputFiles/{args.experiment_id}/05_groups/{gcs_path_leaf(source_dir)}"
        args.step16_input_dir = destination_dir
    command = "\n".join(
        [
            "set -euo pipefail",
            f"mkdir -p {shlex.quote(destination_dir)}",
            f"gcloud storage rsync -r {shlex.quote(source_dir)} {shlex.quote(destination_dir)}",
        ]
    )
    run_remote(args, command)


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
    if args.skip_model_sync:
        return
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
    docker_entrypoint: list[str] = []
    docker_payload = command
    if command and command[0] == "python3":
        docker_entrypoint = ["--entrypoint", "python3"]
        docker_payload = command[1:]
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
        *docker_entrypoint,
        args.docker_image,
    ]
    docker_command.extend(docker_payload)
    return quote_args(docker_command)


# This function runs Step 16 on the VM to build prompt packages from the configured group inputs.
def run_step16(args: argparse.Namespace) -> None:
    if args.skip_step16:
        return
    step16_output_dir = resolve_step16_output_dir(args)
    command = [
        "python3",
        "build_prompts-googleCloud.py",
        "--config",
        f"{args.remote_root}/04_Steps/setups/config_LLM_baseline.json",
        "--cloud-root",
        args.remote_root,
        "--output-dir",
        step16_output_dir,
    ]
    if args.step16_input_dir:
        command.extend(["--input-dir", args.step16_input_dir])
    if args.limit_groups is not None:
        command.extend(["--limit-groups", str(args.limit_groups)])
    if not args.step17_prompt_dir:
        args.step17_prompt_dir = step16_output_dir
    if not args.step17_prompt_manifest:
        args.step17_prompt_manifest = f"{step16_output_dir}/prompt_manifest.json"
    remote_command = dockerized_command(args, args.remote_root + "/04_Steps/Step16", command)
    run_remote(args, remote_command)


# This function runs Step 17 on the VM.
# The default Google Cloud path uses vLLM, while the legacy llama-cpp runner can still be selected explicitly.
def run_step17(args: argparse.Namespace) -> None:
    if args.skip_step17:
        return
    resolve_step17_run_id(args)
    resolve_step17_output_root(args)
    if not args.step17_prompt_dir:
        args.step17_prompt_dir = resolve_step16_output_dir(args)
    if not args.step17_prompt_manifest:
        args.step17_prompt_manifest = f"{args.step17_prompt_dir.rstrip('/')}/prompt_manifest.json"
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
    if args.step17_prompt_manifest:
        command.extend(["--prompt-manifest", args.step17_prompt_manifest])
    if args.step17_prompt_dir:
        command.extend(["--prompt-dir", args.step17_prompt_dir])
    if args.step17_output_root:
        command.extend(["--output-root", args.step17_output_root])
    if args.step17_run_id:
        command.extend(["--run-id", args.step17_run_id])
    if args.step17_run_label:
        command.extend(["--run-label", args.step17_run_label])
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
    if args.runtime_max_model_len is not None:
        command.extend(["--runtime-max-model-len", str(args.runtime_max_model_len)])
    if args.expected_output_patch_tokens is not None:
        command.extend(["--expected-output-patch-tokens", str(args.expected_output_patch_tokens)])
    if args.output_token_margin_percent is not None:
        command.extend(["--output-token-margin-percent", str(args.output_token_margin_percent)])
    remote_command = dockerized_command(args, args.remote_root + "/04_Steps/Step17", command)
    run_remote(args, remote_command)


# This function uploads run-specific Step 16 prompts and Step 17 outputs from the GPU VM to GCS.
def upload_outputs_to_gcs(args: argparse.Namespace) -> None:
    run_id = resolve_step17_run_id(args)
    remote_prompt_dir = resolve_step16_output_dir(args)
    remote_step17_root = resolve_step17_output_root(args)
    remote_model_run_dirs = list_remote_model_run_dirs(args, remote_step17_root, run_id)
    gcs_run_root = resolve_gcs_run_root(args)
    gcs_output_root = resolve_gcs_output_root(args)
    metadata_dirs = " ".join(
        shlex.quote(f"{remote_model_run_dir.rstrip('/')}/metadata") for remote_model_run_dir in remote_model_run_dirs
    )

    commands = [
        "set -euo pipefail",
        "marker=$(mktemp)",
        ": > \"$marker\"",
        f"gcloud storage cp \"$marker\" {shlex.quote(gcs_output_root + '/.keep')}",
        "rm -f \"$marker\"",
    ]

    if args.fetch_all_prompts:
        commands.append(
            f"gcloud storage rsync -r {shlex.quote(remote_prompt_dir)} {shlex.quote(gcs_run_root + '/06_prompts')}"
        )
    else:
        commands.extend(
            [
                "prompt_stage=$(mktemp -d)",
                "mkdir -p \"$prompt_stage/06_prompts\"",
                f"cp {shlex.quote(remote_prompt_dir + '/prompt_manifest.json')} \"$prompt_stage/06_prompts/\"",
                f"python3 - {shlex.quote(remote_prompt_dir)} \"$prompt_stage/06_prompts\" {metadata_dirs} <<'PY'",
                "import json",
                "import shutil",
                "import sys",
                "from pathlib import Path",
                "",
                "prompt_dir = Path(sys.argv[1])",
                "stage_dir = Path(sys.argv[2])",
                "metadata_dirs = [Path(value) for value in sys.argv[3:]]",
                "prompt_files = set()",
                "for metadata_dir in metadata_dirs:",
                "    for metadata_path in sorted(metadata_dir.glob('*.metadata.json')):",
                "        try:",
                "            metadata = json.loads(metadata_path.read_text(encoding='utf-8'))",
                "        except Exception:",
                "            continue",
                "        prompt_file = metadata.get('prompt_file')",
                "        if isinstance(prompt_file, str) and prompt_file:",
                "            prompt_files.add(Path(prompt_file).name)",
                "            continue",
                "        prompt_unit_id = metadata.get('prompt_unit_id') or metadata.get('group_id')",
                "        if isinstance(prompt_unit_id, str) and prompt_unit_id:",
                "            prompt_files.add(f'{prompt_unit_id}.prompt.json')",
                "for prompt_file in sorted(prompt_files):",
                "    source = prompt_dir / prompt_file",
                "    if source.exists():",
                "        shutil.copy2(source, stage_dir / prompt_file)",
                "print(f'Staged prompt packages: {len(prompt_files)}')",
                "PY",
                f"gcloud storage rsync -r \"$prompt_stage/06_prompts\" {shlex.quote(gcs_run_root + '/06_prompts')}",
                "rm -rf \"$prompt_stage\"",
            ]
        )

    for remote_model_run_dir in remote_model_run_dirs:
        model_name = Path(remote_model_run_dir.rstrip("/")).parent.name
        commands.append(
            f"gcloud storage rsync -r {shlex.quote(remote_model_run_dir)} "
            f"{shlex.quote(gcs_run_root + '/07_llm_outputs/' + model_name)}"
        )

    run_remote(args, "\n".join(commands))


# This function fetches run-specific Step 16 prompts and Step 17 outputs from GCS into the local experiment tree.
def fetch_outputs_from_gcs(args: argparse.Namespace) -> None:
    if not args.local_output_dir:
        raise ValueError("--fetch-outputs-from-gcs requires --local-output-dir.")
    local_experiment_root = Path(args.local_output_dir).expanduser()
    grouping_label = resolve_grouping_label(args)
    run_id = resolve_step17_run_id(args)
    gcs_run_root = resolve_gcs_run_root(args)
    prompt_manifest_gcs = f"{gcs_run_root}/06_prompts/prompt_manifest.json"
    step17_outputs_gcs = f"{gcs_run_root}/07_llm_outputs/"
    if not gcs_path_exists(args, prompt_manifest_gcs) or not gcs_path_exists(args, step17_outputs_gcs):
        raise FileNotFoundError(
            f"No complete GCS artifacts found for run_id={run_id} under {gcs_run_root}. "
            "Run first with --upload-outputs-to-gcs, or pass both --upload-outputs-to-gcs "
            "and --fetch-outputs-from-gcs in the same run."
        )

    local_prompt_dir = local_experiment_root / "06_prompts" / grouping_label / run_id
    local_prompt_dir.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            GCLOUD_COMMAND,
            "storage",
            "rsync",
            "-r",
            f"{gcs_run_root}/06_prompts",
            str(local_prompt_dir),
        ],
        args.dry_run,
    )

    for gcs_model_dir in list_gcs_model_output_dirs(args, gcs_run_root):
        model_name = gcs_model_dir.rstrip("/").split("/")[-1]
        local_model_run_dir = local_experiment_root / "07_llm_outputs" / grouping_label / model_name / run_id
        local_model_run_dir.mkdir(parents=True, exist_ok=True)
        run_command(
            [
                GCLOUD_COMMAND,
                "storage",
                "rsync",
                "-r",
                gcs_model_dir,
                str(local_model_run_dir),
            ],
            args.dry_run,
        )
        summarize_local_runtime(args, local_model_run_dir, local_prompt_dir)


# This function defines all command-line options used by the orchestrator.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a Google GPU VM, run Step 16 and Step 17 there, and copy outputs back."
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", default=DEFAULT_ZONE)
    parser.add_argument("--instance-name", default=DEFAULT_INSTANCE_NAME)
    parser.add_argument("--ssh-user", default=DEFAULT_SSH_USER, help="Linux user to use for gcloud compute ssh/scp.")
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
    parser.add_argument("--skip-remote-layout", action="store_true", help="Skip creating the remote thesis folder layout.")
    parser.add_argument("--skip-file-transfer", action="store_true", help="Skip copying Step 16/17 scripts and shared files to the VM.")
    parser.add_argument("--test-setup-only", action="store_true", help="Create/reuse the VM, create the remote layout, transfer scripts, build Docker, sync requested models, and stop before Step 16/17 execution.")
    parser.add_argument("--delete-instance-after-run", action="store_true")
    parser.add_argument("--ssh-timeout-seconds", type=int, default=900)

    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--local-groups-dir")
    parser.add_argument("--gcs-groups-dir", help="Cloud Storage directory containing group_*.json and group_manifest.json for Step 16.")
    parser.add_argument("--gcs-group-root", default=DEFAULT_GCS_GROUP_ROOT, help="Cloud Storage root used when --gcs-groups-dir is a relative path.")
    parser.add_argument("--grouping-label", help="Explicit grouping label used in remote/local Step 16 and Step 17 output paths.")
    parser.add_argument("--local-output-dir", help="Local experiment root where run-specific Step 16/17 artifacts are fetched.")
    parser.add_argument("--log-file", help="Optional local log file for all orchestrator terminal output. Defaults to <local-output-dir>/logs/orchestrate_step16_17-googleCloud/<run_id>/ when --local-output-dir is available.")
    parser.add_argument("--gcs-output-root", help="Cloud Storage root for run artifact exchange. Defaults to gs://thesis-santos-llm-artifacts/<experiment_id>/runs.")
    parser.add_argument("--upload-outputs-to-gcs", action="store_true", help="Upload run-specific Step 16 prompts and Step 17 outputs from the GPU VM to --gcs-output-root/<run_id>. If neither GCS transfer flag is passed, both upload and fetch run by default.")
    parser.add_argument("--fetch-outputs-from-gcs", action="store_true", help="Fetch run-specific Step 16 prompts and Step 17 outputs from --gcs-output-root/<run_id> to --local-output-dir. If neither GCS transfer flag is passed, both upload and fetch run by default.")
    parser.add_argument("--fetch-all-prompts", action="store_true", help="Upload/fetch the full Step 16 prompt run directory. By default, only prompt_manifest.json and prompt packages referenced by Step 17 metadata are staged.")
    parser.add_argument("--skip-runtime-summary", action="store_true", help="Do not generate local Step 17 runtime_summary JSON/CSV/MD files after fetched outputs.")

    parser.add_argument("--model-url", action="append", help="Direct downloadable model URL. Can be repeated.")
    parser.add_argument("--gcs-model-dir", action="append", help="Cloud Storage model directory to sync to the VM. Can be repeated.")
    parser.add_argument("--gcs-model-root", default=DEFAULT_GCS_MODEL_ROOT, help="Cloud Storage root used for catalog/relative model names.")
    parser.add_argument("--skip-model-sync", action="store_true", help="Skip syncing models from Cloud Storage.")
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
    parser.add_argument("--skip-step16", action="store_true")

    parser.add_argument("--limit-prompts", type=int)
    parser.add_argument("--skip-step17", action="store_true")
    parser.add_argument("--step17-prompt-manifest")
    parser.add_argument("--step17-prompt-dir")
    parser.add_argument("--step17-output-root")
    parser.add_argument("--step17-run-id")
    parser.add_argument("--step17-run-label")
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
    parser.add_argument("--runtime-max-model-len", type=int)
    parser.add_argument("--expected-output-patch-tokens", type=int)
    parser.add_argument("--output-token-margin-percent", type=float)
    return parser.parse_args()


# This is the main orchestration sequence.
# In test setup mode it stops after VM setup, file transfer, Docker build, group transfer, and model sync.
# The skip flags allow testing individual stages, for example Step 16 without immediately running Step 17.
def main() -> None:
    args = parse_args()
    resolve_step17_run_id(args)
    log_file, original_stdout, original_stderr = configure_logging(args)
    try:
        if not args.skip_create_instance:
            create_instance(args)
        wait_for_ssh(args)
        resolve_remote_root(args)
        if not args.skip_remote_layout:
            create_remote_layout(args)
        if not args.skip_file_transfer:
            transfer_pipeline_files(args)
        build_docker_image(args)
        transfer_group_inputs(args)
        sync_groups_from_gcs(args)
        sync_models_from_gcs(args)
        download_models(args)
        if args.test_setup_only:
            return
        install_llama_cpp(args)
        run_step16(args)
        run_step17(args)
        transfer_flags_requested = args.upload_outputs_to_gcs or args.fetch_outputs_from_gcs
        should_upload_to_gcs = args.upload_outputs_to_gcs or not transfer_flags_requested
        should_fetch_from_gcs = args.fetch_outputs_from_gcs or not transfer_flags_requested
        if should_upload_to_gcs:
            upload_outputs_to_gcs(args)
        if should_fetch_from_gcs:
            fetch_outputs_from_gcs(args)
    finally:
        if args.delete_instance_after_run:
            delete_instance(args)
        sys.stdout.flush()
        sys.stderr.flush()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_file.close()


if __name__ == "__main__":
    main()
