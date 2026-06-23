from __future__ import annotations

import sys
from pathlib import Path


#This Google Cloud entrypoint intentionally delegates to the regular Step 16 implementation.
#It gives the cloud/Docker workflow a separate script name without duplicating prompt-building logic.

STEP16_DIR = Path(__file__).resolve().parent
if str(STEP16_DIR) not in sys.path:
    sys.path.insert(0, str(STEP16_DIR))

from build_prompts import main  # noqa: E402


if __name__ == "__main__":
    main()
