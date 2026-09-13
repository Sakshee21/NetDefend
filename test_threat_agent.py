"""Offline sanity tests for the Threat Hunting Agent.

Run with: python test_threat_agent.py

Monkeypatches agents.llm_client.call_llm so this runs without
ANTHROPIC_API_KEY. Field names match the REAL Packet Analysis Agent /
Intrusion Detection Agent contracts (single-flow features, CICIDS2017
label strings) -- not the aggregate/multi-host fields an earlier draft
of this test assumed.

Exercises:
  1. Deterministic class-lookup hit ("Infiltration" -> T1021.002)
  2. Deterministic feature-heuristic hit (ambiguous class, SSH brute-force
     pattern in the single-flow features)
  3. LLM fallback path (nothing matches the table)
"""

import json

import agents.llm_client as llm_client
from agents.threat_agent import run_threat_agent


def fake_call_llm(prompt: str, system: str = None, model: str = None) -> str:
    if system and "MITRE ATT&CK mapping assistant" in system:
        return json.dumps({
            "ttp_id": "T1595",
            "technique_name": "Active Scanning",
            "tactic": "Reconnaissance",
            "confidence": 0.4,
        })
    if system and "Threat Hunting Agent" in system:
        return json.dumps({
            "summary": "Host performing lateral movement over SMB against an internal host.",
            "evidence": [
                "syn_count=40 with only synack_count=3 on a flow to destination port 445",
                "Random Forest labelled the flow 'Infiltration' with attack_probability=0.87",
            ],
        })
    return "{}"


def test_class_lookup_hit():
    """predicted_class='Infiltration' should resolve via the deterministic
    table regardless of the exact feature values."""
    state = {
        "packet_features": {
            "packet_count": 180, "byte_count": 21000, "duration_s": 4.2,
            "packets_per_sec": 42.8, "bytes_per_sec": 5000.0,
            "mean_inter_arrival": 0.02, "std_inter_arrival": 0.01,
            "syn_count": 40, "synack_count": 3, "rst_count": 2,
            "ssh_auth_attempts": 0, "protocol": "6",
            "top_dst_port": 445, "top_talker_ip": "10.0.0.14", "flow_count": 340,
        },
        "ml_prediction": {"attack_probability": 0.87, "predicted_class": "Infiltration",
                           "anomaly_score": -0.12},
    }
    result = run_threat_agent(state)
    assert result["ttp_id"] == "T1021.002", result["ttp_id"]
    assert result["ttp_confidence"] == 0.8, result["ttp_confidence"]
    assert "summary" in result["threat_hypothesis"]
    assert len(result["threat_hypothesis"]["evidence"]) > 0
    print("test_class_lookup_hit passed:", result["ttp_id"], result["ttp_confidence"])


def test_feature_heuristic_fallback():
    """predicted_class is ambiguous ('BENIGN' at low confidence, treated as
    unresolved by the RF), but the single flow's ssh_auth_attempts alone
    should trigger the brute-force heuristic."""
    state = {
        "packet_features": {
            "packet_count": 60, "byte_count": 9000, "duration_s": 12.0,
            "packets_per_sec": 5.0, "bytes_per_sec": 750.0,
            "mean_inter_arrival": 0.2, "std_inter_arrival": 0.05,
            "syn_count": 8, "synack_count": 6, "rst_count": 1,
            "ssh_auth_attempts": 9, "protocol": "6",
            "top_dst_port": 22, "top_talker_ip": "10.0.0.22", "flow_count": 12,
        },
        "ml_prediction": {"attack_probability": 0.55, "predicted_class": "BENIGN",
                           "anomaly_score": -0.05},
    }
    result = run_threat_agent(state)
    assert result["ttp_id"] == "T1110", result["ttp_id"]
    print("test_feature_heuristic_fallback passed:", result["ttp_id"], result["ttp_confidence"])


def test_llm_fallback_path():
    """Nothing in packet_features or predicted_class matches the table --
    should fall through to the LLM for both TTP mapping and hypothesis."""
    state = {
        "packet_features": {
            "packet_count": 5, "byte_count": 400, "duration_s": 1.0,
            "packets_per_sec": 5.0, "bytes_per_sec": 400.0,
            "mean_inter_arrival": 0.2, "std_inter_arrival": 0.05,
            "syn_count": 1, "synack_count": 1, "rst_count": 0,
            "ssh_auth_attempts": 0, "protocol": "6",
            "top_dst_port": 8080, "top_talker_ip": "10.0.0.5", "flow_count": 3,
        },
        "ml_prediction": {"attack_probability": 0.51, "predicted_class": "Unknown",
                           "anomaly_score": None},
    }
    result = run_threat_agent(state)
    assert result["ttp_id"] == "T1595", result["ttp_id"]
    print("test_llm_fallback_path passed:", result["ttp_id"], result["ttp_confidence"])


if __name__ == "__main__":
    llm_client.call_llm = fake_call_llm
    import agents.threat_agent as threat_agent_module
    threat_agent_module.call_llm = fake_call_llm

    test_class_lookup_hit()
    test_feature_heuristic_fallback()
    test_llm_fallback_path()
    print("\nAll tests passed.")