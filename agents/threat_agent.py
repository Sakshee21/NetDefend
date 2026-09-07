"""Threat Hunting Agent — builds the attack-side hypothesis.

STUB — replace with real logic. The real version prompts the LLM with the
packet features and ML prediction, then maps its conclusion to a MITRE
ATT&CK technique via knowledge/mitre/lookup.py.

Runs in parallel with the Network Troubleshooting Agent. It writes only the
attack-side keys, so the two branches never touch the same state field.
"""

from agents.state_schema import NetDefendState


def run_threat_agent(state: NetDefendState) -> dict:
    """Propose an attack hypothesis and map it to a MITRE ATT&CK technique.

    Args:
        state: Current pipeline state; reads ``packet_features`` and
            ``ml_prediction``.

    Returns:
        Partial state update containing ``ttp_id`` and ``threat_hypothesis``.
    """
    print("[Threat Hunting Agent] running...")

    # STUB — fixed SMB lateral movement hypothesis, no LLM call.
    ttp_id = "T1021.002"

    threat_hypothesis = {
        "summary": (
            "Host 10.0.0.14 is performing lateral movement over SMB, "
            "authenticating to administrative shares across the /24 subnet."
        ),
        "evidence": [
            "128 SYNs to TCP/445 against 23 distinct internal hosts in 62s",
            "Only 12 completed handshakes, consistent with sweeping for "
            "reachable SMB services rather than normal file access",
            "Source host has no prior baseline of SMB traffic",
            "Random Forest labelled the flow set 'Infiltration' at p=0.87",
        ],
    }

    return {"ttp_id": ttp_id, "threat_hypothesis": threat_hypothesis}
