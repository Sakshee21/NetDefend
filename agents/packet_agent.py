"""Packet Analysis Agent.

Calls packet_processing/flow_extractor.py and feature_extractor.py directly
(the same functions run_pipeline.py uses) to parse the PCAP at
state["pcap_path"] into flows, then selects ONE flow to hand forward to the
Intrusion Detection Agent.

IMPORTANT: does NOT aggregate statistics across the whole capture. The
Random Forest / Isolation Forest models were trained on CICIDS2017, where
each row is exactly one 5-tuple flow -- not a summary across many flows.
Feeding capture-wide totals produces statistically meaningless predictions.
This agent picks the single most notable flow instead of averaging/summing.
"""
import sys
from pathlib import Path

import pandas as pd
from scapy.all import rdpcap

from agents.state_schema import NetDefendState

# packet_processing/ sits as a sibling to agents/ at the repo root, but its
# own modules use bare imports ("from flow_extractor import extract_flows",
# not "from packet_processing.flow_extractor import ..."), so it isn't set
# up as a proper importable package. Add it to sys.path so the bare-style
# imports inside those files resolve correctly when called from here.
PACKET_PROCESSING_DIR = Path(__file__).resolve().parent.parent / "packet_processing"
if str(PACKET_PROCESSING_DIR) not in sys.path:
    sys.path.insert(0, str(PACKET_PROCESSING_DIR))

from flow_extractor import extract_flows
from feature_extractor import calculate_features

FEATURE_COLUMNS = [
    "packet_count", "byte_count", "duration_s", "packets_per_sec",
    "bytes_per_sec", "mean_inter_arrival", "std_inter_arrival",
    "syn_count", "synack_count", "rst_count", "ssh_auth_attempts",
]


def _select_representative_flow(flows_df: pd.DataFrame) -> dict:
    """
    Picks ONE flow -- never averages or sums across rows, since that
    breaks the per-flow-trained models. Uses highest packets_per_sec as
    the most plausible candidate worth deeper ML scrutiny, since these
    CSVs don't carry rule-based anomaly tags of their own.
    """
    if flows_df.empty:
        return {}
    idx = flows_df["packets_per_sec"].idxmax()
    return flows_df.loc[idx].to_dict()


def run_packet_agent(state: NetDefendState) -> dict:
    """Extract flow-level features from the capture and select one flow.

    Args:
        state: Current pipeline state; reads ``pcap_path``.

    Returns:
        Partial state update containing ``packet_features`` -- ONE flow's
        feature dict, not an aggregate across the capture.
    """
    print("[Packet Analysis Agent] running...")

    pcap_path = state.get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        print(f"[Packet Analysis Agent] pcap_path missing or not found: {pcap_path}")
        return {"packet_features": {}}

    print("[Packet Analysis Agent] reading PCAP...")
    packets = rdpcap(pcap_path)
    print(f"[Packet Analysis Agent] packets found: {len(packets)}")

    print("[Packet Analysis Agent] extracting flows...")
    flows = extract_flows(packets)
    print(f"[Packet Analysis Agent] flows found: {len(flows)}")

    print("[Packet Analysis Agent] calculating features...")
    features = calculate_features(flows)
    flows_df = pd.DataFrame(features)
    flows_df.columns = [c.strip() for c in flows_df.columns]

    if flows_df.empty:
        print("[Packet Analysis Agent] no flows extracted, returning empty packet_features")
        return {"packet_features": {}}

    selected_flow = _select_representative_flow(flows_df)

    packet_features = {col: selected_flow.get(col, 0) for col in FEATURE_COLUMNS}
    packet_features["protocol"] = selected_flow.get("protocol", 0)

    # Context fields for other agents -- harmless extras, Intrusion
    # Detection Agent only reads FEATURE_COLUMNS + protocol.
    packet_features["flow_count"] = len(flows_df)
    packet_features["top_talker_ip"] = selected_flow.get("src_ip") or selected_flow.get("source_ip")
    packet_features["top_dst_port"] = selected_flow.get("dst_port") or selected_flow.get("dest_port")

    print(f"[Packet Analysis Agent] selected flow: "
          f"packet_count={packet_features['packet_count']}, "
          f"syn_count={packet_features['syn_count']}, "
          f"out of {len(flows_df)} total flows in capture")

    return {"packet_features": packet_features}