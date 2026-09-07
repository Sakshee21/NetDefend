"""Incident Response Agent — assembles the final incident report.

STUB — replace with real logic. The real version resolves the technique
name through knowledge/mitre/lookup.py and has the LLM write the
recommended action. It reads the arbiter's verdict rather than deciding
one itself.
"""

import uuid
from datetime import datetime, timezone

from agents.state_schema import NetDefendState

# STUB — stands in for knowledge/mitre/lookup.py, which is still empty.
_TTP_NAMES = {
    "T1021.002": "SMB/Windows Admin Shares",
}


def run_response_agent(state: NetDefendState) -> dict:
    """Build the incident report handed back to the API caller.

    Args:
        state: Current pipeline state; reads ``arbiter_verdict``, plus
            ``ttp_id`` and ``packet_features``.

    Returns:
        Partial state update containing the completed ``final_report``.
    """
    print("[Incident Response Agent] running...")

    # The arbiter committed to a verdict; build the report around it.
    verdict = state.get("arbiter_verdict") or {}
    classification = verdict.get("classification", "UNCERTAIN")
    confidence = verdict.get("confidence", 0.0)

    features = state.get("packet_features") or {}
    ttp_id = state.get("ttp_id")

    mitre_ttp = None
    if classification == "ATTACK" and ttp_id:
        mitre_ttp = {"id": ttp_id, "name": _TTP_NAMES.get(ttp_id, "Unknown")}

    final_report = {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "classification": classification,
        # STUB — the real version derives risk from verdict and confidence.
        "risk_level": "HIGH",
        "confidence": confidence,
        "mitre_ttp": mitre_ttp,
        "recommended_action": (
            "Isolate 10.0.0.14 from the access VLAN and revoke the cached "
            "credentials it used. Review SMB session logs on the 12 hosts "
            "that completed a handshake."
        ),
        "affected_host": features.get("top_talker_ip", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return {"final_report": final_report}
