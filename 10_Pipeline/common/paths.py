from __future__ import annotations

from pathlib import Path


EXPERIMENT_SUBDIRS = [
    "01_setup",
    "02_labels",
    "03_selected_traffic",
    "04_packet_json",
    "05_groups",
    "06_prompts",
    "07_llm_outputs",
    "08_merged_outputs",
    "09_validation",
    "10_reconstructed_pcap",
    "11_snort_raw/pre",
    "11_snort_raw/post",
    "12_alerts_processed/pre",
    "12_alerts_processed/post",
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
