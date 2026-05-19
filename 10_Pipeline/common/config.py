from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json_config(config_path: str | Path) -> dict[str, Any]:
    path = Path(config_path).expanduser().resolve()
    with path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not isinstance(config, dict):
        raise ValueError(f"Config root must be a JSON object: {path}")

    config["_config_path"] = str(path)
    return config


def require_keys(data: dict[str, Any], keys: list[str], context: str) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"Missing required key(s) in {context}: {joined}")
