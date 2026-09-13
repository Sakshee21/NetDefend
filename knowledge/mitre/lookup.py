"""Deterministic MITRE ATT&CK lookup table.

Aligned to the REAL upstream contracts:
  - packet_features: ONE flow's feature dict from the Packet Analysis
    Agent (packet_count, byte_count, duration_s, packets_per_sec,
    bytes_per_sec, mean_inter_arrival, std_inter_arrival, syn_count,
    synack_count, rst_count, ssh_auth_attempts, protocol [IANA number
    string], plus flow_count/top_talker_ip/top_dst_port). This is a
    single 5-tuple conversation, never an aggregate across the capture —
    so heuristics here must not assume multi-host/multi-flow signals
    like "distinct destination hosts" (an earlier draft of this file
    wrongly assumed that; it's been removed).
  - ml_prediction: {"attack_probability": float, "predicted_class": str,
    "anomaly_score": float | None} from a Random Forest trained on
    CICIDS2017 (+ Isolation Forest for anomaly_score, unused for mapping
    here). predicted_class values are CICIDS2017's own label strings
    (e.g. "DDoS", "PortScan", "Web Attack - Brute Force", "FTP-Patator"),
    not generic category names -- matching below is tuned to those exact
    strings, with a few extra entries for UNSW-NB15 / CICIoT2023 label
    conventions since the project also uses those datasets elsewhere.

Design note (per project plan): get this cheap, testable path working
first -- it gives a real baseline for the RQ2 mapping-accuracy metric and
means the LLM is only asked to map techniques for cases the table can't
already resolve.

Two-tier matching:
  1. ``predicted_class`` from the ML model -- the strongest available
     signal, checked in priority order below (see comments on ordering).
  2. ``packet_features`` heuristics -- used when predicted_class is
     missing, generic ("BENIGN", "Unknown"), or unmatched by tier 1.

Returns ``None`` when nothing matches, signaling the caller to fall back
to LLM-based mapping.
"""

from __future__ import annotations

from typing import Optional, TypedDict


class TTPMatch(TypedDict):
    ttp_id: str
    technique_name: str
    tactic: str
    mapping_method: str  # "class_lookup" | "feature_heuristic"
    confidence: float


# ---------------------------------------------------------------------------
# Tier 1: ML predicted_class -> TTP
# ---------------------------------------------------------------------------
# ORDER MATTERS: this is a list, not a dict, and the first predicate to
# match wins. Substrings collide (e.g. "DDoS".lower() contains "dos"),
# so more specific / higher-priority phrases must come before broader
# ones. In particular "web attack" must be checked before "brute force",
# since CICIDS2017's "Web Attack - Brute Force" is a web exploit, not a
# credential brute-force tool like FTP-Patator/SSH-Patator.

CLASS_TO_TTP: list[tuple[str, TTPMatch]] = [
    # --- CICIDS2017 exact labels (primary -- matches the trained RF) ----
    ("ddos", {
        "ttp_id": "T1498", "technique_name": "Network Denial of Service",
        "tactic": "Impact", "mapping_method": "class_lookup", "confidence": 0.85,
    }),
    ("web attack", {
        "ttp_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "mapping_method": "class_lookup", "confidence": 0.8,
    }),
    ("patator", {  # FTP-Patator, SSH-Patator
        "ttp_id": "T1110", "technique_name": "Brute Force",
        "tactic": "Credential Access", "mapping_method": "class_lookup", "confidence": 0.85,
    }),
    ("heartbleed", {
        "ttp_id": "T1212", "technique_name": "Exploitation for Credential Access",
        "tactic": "Credential Access", "mapping_method": "class_lookup", "confidence": 0.75,
    }),
    ("dos", {  # DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest
        "ttp_id": "T1499", "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact", "mapping_method": "class_lookup", "confidence": 0.8,
    }),
    ("portscan", {
        "ttp_id": "T1046", "technique_name": "Network Service Discovery",
        "tactic": "Discovery", "mapping_method": "class_lookup", "confidence": 0.85,
    }),
    ("port scan", {
        "ttp_id": "T1046", "technique_name": "Network Service Discovery",
        "tactic": "Discovery", "mapping_method": "class_lookup", "confidence": 0.85,
    }),
    ("infiltration", {
        "ttp_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement", "mapping_method": "class_lookup", "confidence": 0.8,
    }),
    ("bot", {  # CICIDS2017 "Bot"
        "ttp_id": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control", "mapping_method": "class_lookup", "confidence": 0.7,
    }),

    # --- CICIoT2023 / UNSW-NB15 label conventions (secondary datasets) --
    ("brute force", {
        "ttp_id": "T1110", "technique_name": "Brute Force",
        "tactic": "Credential Access", "mapping_method": "class_lookup", "confidence": 0.8,
    }),
    ("bruteforce", {
        "ttp_id": "T1110", "technique_name": "Brute Force",
        "tactic": "Credential Access", "mapping_method": "class_lookup", "confidence": 0.8,
    }),
    ("recon", {
        "ttp_id": "T1046", "technique_name": "Network Service Discovery",
        "tactic": "Discovery", "mapping_method": "class_lookup", "confidence": 0.7,
    }),
    ("web-based", {
        "ttp_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "mapping_method": "class_lookup", "confidence": 0.7,
    }),
    ("spoof", {
        "ttp_id": "T1584", "technique_name": "Compromise Infrastructure",
        "tactic": "Resource Development", "mapping_method": "class_lookup", "confidence": 0.55,
    }),
    ("mirai", {
        "ttp_id": "T1584.005", "technique_name": "Compromise Infrastructure: Botnet",
        "tactic": "Resource Development", "mapping_method": "class_lookup", "confidence": 0.75,
    }),
    ("backdoor", {
        "ttp_id": "T1505.003", "technique_name": "Server Software Component: Web Shell",
        "tactic": "Persistence", "mapping_method": "class_lookup", "confidence": 0.55,
    }),
    ("exploits", {
        "ttp_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "mapping_method": "class_lookup", "confidence": 0.6,
    }),
    ("shellcode", {
        "ttp_id": "T1203", "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution", "mapping_method": "class_lookup", "confidence": 0.6,
    }),
    ("worms", {
        "ttp_id": "T1210", "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement", "mapping_method": "class_lookup", "confidence": 0.55,
    }),
    ("fuzzers", {
        "ttp_id": "T1595", "technique_name": "Active Scanning",
        "tactic": "Reconnaissance", "mapping_method": "class_lookup", "confidence": 0.5,
    }),
    # NOTE: UNSW-NB15's "Generic" and "Analysis" categories are too
    # ambiguous to hardcode a TTP for -- deliberately left out so those
    # cases fall through to feature heuristics / LLM fallback rather
    # than being force-mapped to something misleading.
]


def _match_predicted_class(predicted_class: str) -> Optional[TTPMatch]:
    label = predicted_class.strip().lower()
    for key, ttp in CLASS_TO_TTP:
        if key in label:
            return dict(ttp)  # copy, caller may adjust confidence
    return None


# ---------------------------------------------------------------------------
# Tier 2: packet_features heuristics (fallback / corroboration)
# ---------------------------------------------------------------------------
# These operate on a SINGLE flow's fields only -- no cross-flow/cross-host
# aggregates exist in the real contract, so heuristics like "N distinct
# destination hosts" from an earlier draft are not usable here and have
# been removed.

def _match_packet_features(packet_features: dict) -> Optional[TTPMatch]:
    if not packet_features:
        return None

    syn_count = packet_features.get("syn_count", 0) or 0
    synack_count = packet_features.get("synack_count", 0) or 0
    rst_count = packet_features.get("rst_count", 0) or 0
    ssh_auth_attempts = packet_features.get("ssh_auth_attempts", 0) or 0
    packets_per_sec = packet_features.get("packets_per_sec", 0) or 0
    top_dst_port = packet_features.get("top_dst_port")

    # Repeated SSH auth attempts on one flow -> credential brute forcing.
    if ssh_auth_attempts >= 5:
        return {
            "ttp_id": "T1110", "technique_name": "Brute Force",
            "tactic": "Credential Access", "mapping_method": "feature_heuristic",
            "confidence": 0.7,
        }

    # SMB port with a lopsided SYN:SYN-ACK ratio -> looks like a sweep/probe
    # against admin shares rather than a completed legitimate session.
    if top_dst_port in (445, 139) and syn_count >= 5 and syn_count > synack_count * 2:
        return {
            "ttp_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement", "mapping_method": "feature_heuristic",
            "confidence": 0.6,
        }

    # Many SYNs, essentially no completed handshakes -> service discovery probe.
    if syn_count >= 10 and synack_count == 0:
        return {
            "ttp_id": "T1046", "technique_name": "Network Service Discovery",
            "tactic": "Discovery", "mapping_method": "feature_heuristic",
            "confidence": 0.55,
        }

    # High RST relative to SYNs on one flow -> probing/refused-connection pattern.
    if syn_count >= 5 and rst_count >= syn_count * 0.5:
        return {
            "ttp_id": "T1046", "technique_name": "Network Service Discovery",
            "tactic": "Discovery", "mapping_method": "feature_heuristic",
            "confidence": 0.5,
        }

    # Very high packet rate on a single flow -> flooding pattern.
    if packets_per_sec and packets_per_sec > 1000:
        return {
            "ttp_id": "T1498", "technique_name": "Network Denial of Service",
            "tactic": "Impact", "mapping_method": "feature_heuristic",
            "confidence": 0.55,
        }

    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def lookup_ttp(ml_prediction: Optional[dict], packet_features: Optional[dict]) -> Optional[TTPMatch]:
    """Try to resolve a TTP without calling an LLM.

    Args:
        ml_prediction: ``{"attack_probability": float, "predicted_class": str,
            "anomaly_score": float | None}``
        packet_features: single-flow feature dict from the Packet Analysis Agent.

    Returns:
        A TTPMatch dict, or ``None`` if neither tier matched -- caller
        should fall back to LLM-based mapping.
    """
    predicted_class = (ml_prediction or {}).get("predicted_class", "") or ""

    if predicted_class and predicted_class.strip().lower() not in ("benign", "unknown", ""):
        class_match = _match_predicted_class(predicted_class)
        if class_match:
            return class_match

    return _match_packet_features(packet_features or {})