from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# This function writes data to a JSON file at the specified path.
# It ensures that the parent directories of the output path exist, 
# and then writes the data to the file in a pretty-printed format with sorted keys.
def write_json(path: str | Path, data: Any) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        # A newline is added at the end of the file for better readability 
        # and to ensure that the file ends with a newline character, which is a common convention in text files.
        output_file.write("\n")
