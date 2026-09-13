"""End-to-end smoke test for the graph wiring.

Runs partial_app (see agents/graph.py) -- packet, intrusion, threat
hunting, and troubleshooting -- since those are the only agents with
real implementations right now. The Dialectical Arbiter and Incident
Response Agent are still stubs returning fixed content disconnected
from the actual evidence, so this deliberately stops before them
instead of printing fabricated verdicts alongside real output.

Switch back to `app` (agents/graph.py's full, documented pipeline) once
those two agents have real implementations -- see
build_partial_graph()'s docstring for removal criteria.

Run it from the repo root:

    python -m agents.test_pipeline

Direct execution (``python agents/test_pipeline.py``) also works via the
sys.path bootstrap below.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.graph import partial_app  # noqa: E402


if __name__ == "__main__":
    result = partial_app.invoke({
        "pcap_path": "dataset/raw/acl_misconfig.pcap",
        "log_path": "dataset/raw/acl_misconfig_firewall.log"
    })

    print("\n=== FINAL STATE (packet / intrusion / threat hunting / "
          "troubleshooting agents only -- arbiter + response agent are "
          "still stubs, excluded for now) ===")
    print(json.dumps(result, indent=2, default=str))
