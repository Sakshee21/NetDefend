"""Packet Analysis Agent.

STUB — replace with real logic. The real version calls into
packet_processing/ to parse the PCAP at state["pcap_path"] and aggregate
per-flow features. Keys below intentionally mirror the columns produced by
packet_processing/feature_extractor.py so the swap-in is a drop-in.
"""

from agents.state_schema import NetDefendState


def run_packet_agent(state: NetDefendState) -> dict:
    """Extract flow-level features from the capture.

    Args:
        state: Current pipeline state; reads ``pcap_path``.

    Returns:
        Partial state update containing ``packet_features``.
    """
    print("[Packet Analysis Agent] running...")

    # STUB — fixed values standing in for a parsed capture. The shape here is
    # what the Intrusion Detection Agent will consume.
    packet_features = {
        "flow_count": 47,
        "packet_count": 1284,
        "byte_count": 196540,
        "duration_s": 62.4,
        "packets_per_sec": 20.58,
        "bytes_per_sec": 3149.7,
        "mean_inter_arrival": 0.0486,
        "std_inter_arrival": 0.1122,
        "syn_count": 128,
        "synack_count": 12,
        "rst_count": 34,
        "ssh_auth_attempts": 0,
        "protocol": 6,
        "top_talker_ip": "10.0.0.14",
        "top_dst_port": 445,
    }

    return {"packet_features": packet_features}
