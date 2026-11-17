"""Entry point for the ticket-triage API: `python app.py` serves on $PORT (default 8000).

Works straight from a checkout, with no install step, by putting ./src on the import path.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from triage.server import main  # noqa: E402

if __name__ == "__main__":
    main()
