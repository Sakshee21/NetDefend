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
    # Cross-flow aggregate evidence -- groups ALL flows in the capture by
    # (destination IP, destination port, protocol), ignoring source port,
    # to surface repeated connection attempts to the same target that no
    # single flow's packet_features can show (e.g. 10 blocked SYNs, each
    # from a different ephemeral source port, so each is its own flow).
    # Never fed into the Intrusion Detection Agent's ML models -- those
    # stay strictly per-flow. See agents/packet_agent.py's
    # _compute_cross_flow_pattern().
    # {"destination": {"ip": str|None, "port": int|None}, "flow_count": int,
    #  "total_syn_count": int, "total_synack_count": int,
    #  "time_span_s": float,
    #  "pattern": "repeated_blocked_attempts" | "none_detected"}
    cross_flow_pattern: Optional[dict]

    # --- Intrusion Detection Agent ---------------------------------------
    # {"attack_probability": float, "predicted_class": str}
    ml_prediction: Optional[dict]

    # --- Threat Hunting Agent (attack hypothesis) -------------------------
    ttp_id: Optional[str]
    ttp_confidence: Optional[float]
    # "class_lookup" | "feature_heuristic" | "llm_fallback" | "fallback_default"
    ttp_mapping_method: Optional[str]
    # True only when the LLM fallback call was invoked and failed (raised,
    # or returned no usable ttp_id) -- NOT set when the deterministic
    # table resolved the TTP, and NOT set for a genuine (if low-
    # confidence) LLM answer. Lets eval/ablation code tell "genuinely low
    # confidence" apart from "the call never actually succeeded".
    llm_call_failed: Optional[bool]
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
