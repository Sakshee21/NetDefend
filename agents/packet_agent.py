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
from collections import defaultdict
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


def _select_representative_flow(flows_df: pd.DataFrame) -> tuple:
    """
    Picks ONE flow -- never averages or sums across rows, since that
    breaks the per-flow-trained models.

    Candidates are restricted to real TCP/UDP traffic first. flows_df's
    `protocol` column is the raw IANA protocol/next-header number (see
    packet_processing/flow_extractor.py); non-6/17 values here are
    background noise, not attack or misconfiguration signal -- protocol
    0 is IPv6 Hop-by-Hop (multicast listener reports), 58 is ICMPv6
    (router solicitations). ARP has no IP layer at all and is already
    dropped in flow_extractor.py, so no separate ARP filter is needed;
    flows_df also has no ethertype column, only `protocol`, to filter on.

    Among TCP/UDP candidates, prefers the flow with the highest SYN
    count that got zero SYN-ACKs back -- the silent-drop signature this
    project's ACL misconfiguration scenario is built around (see
    mininet/scenarios/acl_misconfig.py). Falls back to the highest
    packet_count candidate when no flow matches that signature, or (in
    the degenerate case of a capture that is nothing but background
    noise) to the highest packet_count flow overall.

    Returns (selected_flow, reason) so the caller can log why this flow
    was picked, not just which one.
    """
    if flows_df.empty:
        return {}, "no flows extracted"

    candidates = flows_df[flows_df["protocol"].isin([6, 17])]
    if candidates.empty:
        idx = flows_df["packet_count"].idxmax()
        return (
            flows_df.loc[idx].to_dict(),
            "fallback to highest packet count, no TCP/UDP flows found",
        )

    silent_drop = candidates[(candidates["syn_count"] > 0) & (candidates["synack_count"] == 0)]
    if not silent_drop.empty:
        idx = silent_drop["syn_count"].idxmax()
        return silent_drop.loc[idx].to_dict(), "highest SYN count with no reply"

    idx = candidates["packet_count"].idxmax()
    return (
        candidates.loc[idx].to_dict(),
        "fallback to highest packet count, no candidate signature found",
    )


def _compute_cross_flow_pattern(flows: dict) -> dict:
    """Cross-flow aggregate evidence: groups flows by (dst_ip, dst_port,
    protocol) -- ignoring source port -- to surface repeated connection
    attempts to the same target that no single flow's features can show
    on their own (e.g. 10 separate blocked SYNs, each from a different
    ephemeral source port, so each is its own 5-tuple flow with
    syn_count~2).

    Deliberately built from the raw `flows` dict extract_flows() returns
    (keyed by the full 5-tuple, each value still carrying dst_ip/dst_port),
    not from flows_df. calculate_features() drops dst_ip/dst_port from its
    output entirely (see packet_processing/feature_extractor.py), so
    flows_df alone has nothing to group by destination with. This
    function does not touch flow_extractor.py, feature_extractor.py, or
    _select_representative_flow() -- it's a second, independent read of
    the same flows dict run_packet_agent() already has in hand, with no
    effect on per-flow feature computation.

    A group only counts as a "repeated attempts" pattern with at least
    two flows -- a single flow is not a cross-flow pattern, it's just
    the ordinary per-flow case _select_representative_flow() already
    covers. "Close to zero" SYN-ACKs (per the spec) is treated as
    exactly zero here, matching the same silent-drop definition
    _select_representative_flow() already uses, rather than introducing
    a separate fuzzy threshold.

    Returns the exact shape documented on NetDefendState's
    cross_flow_pattern field.
    """
    groups = defaultdict(list)
    for flow in flows.values():
        key = (flow["dst_ip"], flow["dst_port"], flow["protocol"])
        groups[key].append(flow)

    candidates = []
    for (dst_ip, dst_port, _protocol), group in groups.items():
        if len(group) < 2:
            continue
        total_syn = sum(f["syn_count"] for f in group)
        total_synack = sum(f["synack_count"] for f in group)
        if total_syn > 0 and total_synack == 0:
            candidates.append((total_syn, dst_ip, dst_port, total_synack, group))

    if not candidates:
        return {
            "destination": {"ip": None, "port": None},
            "flow_count": 0,
            "total_syn_count": 0,
            "total_synack_count": 0,
            "time_span_s": 0.0,
            "pattern": "none_detected",
        }

    total_syn, dst_ip, dst_port, total_synack, group = max(candidates, key=lambda c: c[0])
    earliest = min(f["first_timestamp"] for f in group)
    latest = max(f["last_timestamp"] for f in group)

    return {
        "destination": {"ip": dst_ip, "port": int(dst_port)},
        "flow_count": len(group),
        "total_syn_count": int(total_syn),
        "total_synack_count": int(total_synack),
        "time_span_s": max(latest - earliest, 0.0),
        "pattern": "repeated_blocked_attempts",
    }


def run_packet_agent(state: NetDefendState) -> dict:
    """Extract flow-level features from the capture and select one flow.

    Args:
        state: Current pipeline state; reads ``pcap_path``.

    Returns:
        Partial state update containing ``packet_features`` -- ONE flow's
        feature dict, not an aggregate across the capture -- and
        ``cross_flow_pattern``, separate aggregate evidence computed
        across ALL flows (see _compute_cross_flow_pattern()). The two
        are deliberately kept apart: packet_features is what the
        Intrusion Detection Agent's per-flow-trained ML models score,
        cross_flow_pattern never reaches those models at all.
    """
    print("[Packet Analysis Agent] running...")

    pcap_path = state.get("pcap_path")
    if not pcap_path or not Path(pcap_path).exists():
        print(f"[Packet Analysis Agent] pcap_path missing or not found: {pcap_path}")
        return {"packet_features": {}, "cross_flow_pattern": _compute_cross_flow_pattern({})}

    print("[Packet Analysis Agent] reading PCAP...")
    packets = rdpcap(pcap_path)
    print(f"[Packet Analysis Agent] packets found: {len(packets)}")

    print("[Packet Analysis Agent] extracting flows...")
    flows = extract_flows(packets)
    print(f"[Packet Analysis Agent] flows found: {len(flows)}")

    cross_flow_pattern = _compute_cross_flow_pattern(flows)
    print(f"[Packet Analysis Agent] cross-flow pattern: {cross_flow_pattern['pattern']} "
          f"(flow_count={cross_flow_pattern['flow_count']}, "
          f"total_syn_count={cross_flow_pattern['total_syn_count']}, "
          f"total_synack_count={cross_flow_pattern['total_synack_count']}, "
          f"time_span_s={cross_flow_pattern['time_span_s']:.2f})")

    print("[Packet Analysis Agent] calculating features...")
    features = calculate_features(flows)
    flows_df = pd.DataFrame(features)
    flows_df.columns = [c.strip() for c in flows_df.columns]

    if flows_df.empty:
        print("[Packet Analysis Agent] no flows extracted, returning empty packet_features")
        return {"packet_features": {}, "cross_flow_pattern": cross_flow_pattern}

    selected_flow, selection_reason = _select_representative_flow(flows_df)

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
          f"out of {len(flows_df)} total flows in capture "
          f"(reason: {selection_reason})")

    return {"packet_features": packet_features, "cross_flow_pattern": cross_flow_pattern}