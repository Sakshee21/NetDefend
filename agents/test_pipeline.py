"""End-to-end smoke test for the graph wiring.

Every agent is a stub, so this proves execution order and state merging
only. Run it from the repo root:

    python -m agents.test_pipeline

Direct execution (``python agents/test_pipeline.py``) also works via the
sys.path bootstrap below.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.graph import app  # noqa: E402


if __name__ == "__main__":
    result = app.invoke({
        "pcap_path": "dummy_test.pcap",
        "log_path": "dummy_test.log"
    })

    print("\n=== FINAL STATE ===")
    print(json.dumps(result, indent=2, default=str))
