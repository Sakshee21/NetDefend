"""v2 evidence-fidelity tests.

1. source_ip / destination_port are recovered for the representative flow
   even when the selector falls back ("no candidate signature"), and are
   OMITTED (never reported as a misleading null) when unrecoverable.
2. config_evidence_supplied drives the arbiter's "no configuration evidence
   supplied" note and the 0.6 confidence cap under v2.

No LLM calls, no pcap on disk.

Run: ./venv/bin/python tests/test_evidence_fidelity_v2.py
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "packet_processing"))

import pandas as pd  # noqa: E402
from feature_extractor import calculate_features       # noqa: E402
from agents.packet_agent import _select_representative_flow  # noqa: E402
from agents.troubleshooting_agent import _build_incident_evidence  # noqa: E402
from agents import arbiter                              # noqa: E402


def _udp_flows():
    """Several single-packet UDP flows from one source: no SYN, so the
    selector finds no candidate signature and falls back to highest packet
    count."""
    flows = {}
    for i in range(4):
        key = ("10.0.0.1", "10.0.0.2", 40000 + i, 53, 17)
        flows[key] = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 40000 + i, "dst_port": 53, "protocol": 17,
            "packet_count": 1, "byte_count": 94,
            "first_timestamp": float(i), "last_timestamp": float(i),
            "timestamps": [float(i)],
            "syn_count": 0, "synack_count": 0, "rst_count": 0,
        }
    return flows


# ---------------------------------------------------- item 1: selector fallback
def test_selector_fallback_recovers_5_tuple():
    flows = _udp_flows()
    flows_df = pd.DataFrame(calculate_features(flows))
    flows_df.columns = [c.strip() for c in flows_df.columns]
    # Re-attach the 5-tuple exactly as the packet agent does under v2.
    raw = list(flows.values())
    for col in ("src_ip", "dst_ip", "src_port", "dst_port"):
        flows_df[col] = [f.get(col) for f in raw]

    selected, reason = _select_representative_flow(flows_df)
    assert "fallback" in reason, reason          # no candidate signature
    assert selected.get("src_ip") == "10.0.0.1"  # 5-tuple recovered
    assert selected.get("dst_port") == 53


# ------------------------------------------- item 1: evidence-builder fidelity
def _state(top_ip, top_port, subject, dest_port=None):
    return {
        "packet_features": {"protocol": 17, "top_talker_ip": top_ip,
                            "top_dst_port": top_port, "flow_count": 4},
        "ml_prediction": {},
        "cross_flow_pattern": {"subject_source": subject,
                               "destination": {"ip": None, "port": dest_port}},
        "log_path": "",
    }


def test_v2_uses_flow_5tuple_when_present():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    b = _build_incident_evidence(_state("10.0.0.1", 53, "10.0.0.9"))
    rf = b["network_observation"]["representative_flow"]
    assert rf["source_ip"] == "10.0.0.1"
    assert rf["destination_port"] == 53


def test_v2_falls_back_to_subject_source_and_dest_port():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    b = _build_incident_evidence(_state(None, None, "10.0.0.1", dest_port=8000))
    rf = b["network_observation"]["representative_flow"]
    assert rf["source_ip"] == "10.0.0.1"          # from cross_flow subject
    assert rf["destination_port"] == 8000          # from cross_flow destination


def test_v2_omits_when_unrecoverable():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    b = _build_incident_evidence(_state(None, None, None))
    rf = b["network_observation"]["representative_flow"]
    assert "source_ip" not in rf                   # omitted, not null
    assert "destination_port" not in rf


def test_v1_keeps_null_fields():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v1"
    b = _build_incident_evidence(_state(None, None, "10.0.0.1"))
    rf = b["network_observation"]["representative_flow"]
    assert "source_ip" in rf and rf["source_ip"] is None   # v1 unchanged
    assert "destination_port" in rf and rf["destination_port"] is None


# ------------------------------------------ item 2: config_evidence_supplied
def _verdict_out(conf):
    return {"refutation_exchange": [],
            "arbiter_verdict": {"classification": "ATTACK", "confidence": conf,
                                "reasoning": "synthetic"}}


def test_v2_no_config_evidence_caps_and_notes():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    out = arbiter._apply_no_config_evidence(_verdict_out(0.9),
                                            {"config_evidence_supplied": False})
    v = out["arbiter_verdict"]
    assert v["confidence"] == 0.6
    assert v["note"] == "no configuration evidence supplied"


def test_v2_config_evidence_supplied_unchanged():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    out = arbiter._apply_no_config_evidence(_verdict_out(0.9),
                                            {"config_evidence_supplied": True})
    v = out["arbiter_verdict"]
    assert v["confidence"] == 0.9
    assert "note" not in v


def test_v2_low_confidence_not_raised_by_cap():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    out = arbiter._apply_no_config_evidence(_verdict_out(0.3),
                                            {"config_evidence_supplied": False})
    assert out["arbiter_verdict"]["confidence"] == 0.3   # cap lowers only


def test_v1_no_config_evidence_cap_not_applied():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v1"
    out = arbiter._apply_no_config_evidence(_verdict_out(0.9),
                                            {"config_evidence_supplied": False})
    assert out["arbiter_verdict"]["confidence"] == 0.9   # v1 untouched


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
            passed += 1
        except AssertionError as e:
            print("FAIL", fn.__name__, "--", e)
    os.environ.pop("NETDEFEND_REASONING_VERSION", None)
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
