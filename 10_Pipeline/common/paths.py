from __future__ import annotations

from pathlib import Path


EXPERIMENT_SUBDIRS = [
    "00_config",
    "01_labels",
    "02_selected_traffic",
    "03_packet_json",
    "04_groups",
    "05_prompts",
    "06_transfer_to_rise",
    "07_llm_outputs",
    "08_merged_outputs",
    "09_validation",
    "10_reconstructed_pcap",
    "11_snort/pre",
    "11_snort/post",
    "12_alerts/pre",
    "12_alerts/post",
    "13_comparison",
    "14_metrics",
    "logs",
]


def create_experiment_dirs(experiment_root: str | Path) -> list[Path]:
    root = Path(experiment_root)
    root.mkdir(parents=True, exist_ok=True)
    created = []
    for subdir in EXPERIMENT_SUBDIRS:
        path = root / subdir
        path.mkdir(parents=True, exist_ok=True)
        created.append(path)
    return created
