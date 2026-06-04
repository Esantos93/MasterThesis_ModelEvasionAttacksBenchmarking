from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common.naming import sanitize_name_component


# This function normalizes pipeline naming fields when they are present in a config.
# It keeps direct script execution consistent with Step 11 resolved_config.json.
def normalize_pipeline_names(config: dict[str, Any]) -> None:
    pipeline = config.get("pipeline")
    if not isinstance(pipeline, dict):
        return
    if isinstance(pipeline.get("experiment_config_label"), str):
        pipeline["experiment_config_label"] = sanitize_name_component(pipeline["experiment_config_label"])
    label_options = pipeline.get("experiment_config_label_options")
    if isinstance(label_options, list):
        pipeline["experiment_config_label_options"] = [
            sanitize_name_component(item) if isinstance(item, str) else item
            for item in label_options
        ]

# This function loads a JSON configuration file from the specified path. It ensures that the loaded JSON is a dictionary (JSON object) 
# and adds the absolute path of the configuration file to the resulting dictionary under the key "_config_path". 
# If the JSON is not a dictionary, it raises a ValueError.
def load_json_config(config_path: str | Path) -> dict[str, Any]:
    # The path is resolved to an absolute path, and any user home directory references are expanded.
    path = Path(config_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    # The loaded JSON must be a dictionary (JSON object) at the root level. If it's not, an error is raised.
    if not isinstance(config, dict):
        raise ValueError(f"Config root must be a JSON object: {path}")

    normalize_pipeline_names(config)
    config["_config_path"] = str(path)
    return config

# This function checks if the specified keys are present in the given dictionary. If any keys are missing, it raises a ValueError with a message indicating which keys are missing and the context in which they were expected.
def require_keys(data: dict[str, Any], keys: list[str], context: str) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"Missing required key(s) in {context}: {joined}")
