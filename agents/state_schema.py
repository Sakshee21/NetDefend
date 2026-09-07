"""Shared state schema — the contract passed between every NetDefend agent.

Each agent node receives the full state and returns a dict containing only
the fields it updates. LangGraph merges that partial dict into the running
state, so agents never mutate the state object directly.
"""

from typing import Optional, TypedDict


class NetDefendState(TypedDict):
    """State threaded through the LangGraph pipeline, start to finish."""

    # --- Inputs -----------------------------------------------------------
    pcap_path: str
    log_path: str

    # --- Packet Analysis Agent -------------------------------------------
    packet_features: Optional[dict]

    # --- Intrusion Detection Agent ---------------------------------------
    # {"attack_probability": float, "predicted_class": str}
    ml_prediction: Optional[dict]

    # --- Threat Hunting Agent (attack hypothesis) -------------------------
    ttp_id: Optional[str]
    # {"summary": str, "evidence": list[str]}
    threat_hypothesis: Optional[dict]

    # --- Network Troubleshooting Agent (misconfiguration hypothesis) ------
    is_misconfiguration: Optional[float]
    misconfig_reasoning: Optional[str]
    # {"summary": str, "taxonomy_category": str, "evidence": list[str]}
    misconfig_hypothesis: Optional[dict]

    # --- Dialectical Arbiter ---------------------------------------------
    # list of {"challenged_agent": str, "challenge": str, "response": str}
    refutation_exchange: Optional[list]
    # {"classification": str, "confidence": float}
    arbiter_verdict: Optional[dict]

    # --- Incident Response Agent -----------------------------------------
    final_report: Optional[dict]
