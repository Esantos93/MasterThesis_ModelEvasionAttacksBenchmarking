from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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

    config["_config_path"] = str(path)
    return config

# This function checks if the specified keys are present in the given dictionary. If any keys are missing, it raises a ValueError with a message indicating which keys are missing and the context in which they were expected.
def require_keys(data: dict[str, Any], keys: list[str], context: str) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"Missing required key(s) in {context}: {joined}")
