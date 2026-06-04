from __future__ import annotations

import re


# This function sanitizes one value that will be used as a pipeline name component.
# It keeps words inside one component separated with dashes, while later code can use underscores or double underscores to separate larger filename fields.
def sanitize_name_component(value: str) -> str:
    cleaned = str(value).strip().replace("_", "-")
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", cleaned)
    cleaned = cleaned.strip("-_.")
    return cleaned or "unknown"
