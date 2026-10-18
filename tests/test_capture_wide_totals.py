"""v2 capture-wide totals test.

When no cross-flow pattern is detected, cross_flow_pattern's pattern-specific
flow_count / time_span_s read 0, which previously made it look as if there
were zero flows. Under v2 evidence, a separate capture_wide_totals field holds
the true totals (flows from the subject source, distinct ports/hosts, time
span) regardless of the pattern label. This test uses a synthetic capture with
several UDP flows and no detectable pattern.

No LLM calls, no pcap on disk.

Run: ./venv/bin/python tests/test_capture_wide_totals.py
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from agents.packet_agent import _compute_cross_flow_pattern  # noqa: E402


def _synthetic_no_pattern_flows():
    """Five single-packet UDP flows from one source to one host on five
    distinct ports -- no SYN activity, so no pattern is detected, yet the
    capture clearly holds five flows spanning 4 seconds."""
    flows = {}
    for i in range(5):
        key = ("10.0.0.1", "10.0.0.2", 40000 + i, 1 + i, 17)  # 5-tuple, UDP
        flows[key] = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 40000 + i, "dst_port": 1 + i, "protocol": 17,
            "packet_count": 1, "byte_count": 94,
            "first_timestamp": float(i), "last_timestamp": float(i),
            "timestamps": [float(i)],
            "syn_count": 0, "synack_count": 0, "rst_count": 0,
        }
    return flows


def test_v2_capture_wide_totals_when_no_pattern():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
    flows = _synthetic_no_pattern_flows()
    r = _compute_cross_flow_pattern(flows)

    # pattern is unchanged / still its own field
    assert r["pattern"] == "none_detected", r["pattern"]
    # the pattern-specific flow_count stays 0 (not repurposed)
    assert r["flow_count"] == 0

    cw = r["capture_wide_totals"]
    assert cw["subject_source"] == "10.0.0.1"
    assert cw["subject_flow_count"] == 5, cw
    assert cw["distinct_dst_ports"] == 5, cw
    assert cw["distinct_dst_hosts"] == 1, cw
    assert abs(cw["time_span_s"] - 4.0) < 1e-6, cw
    assert cw["total_flows_in_capture"] == 5, cw
    assert cw["pattern"] == "none_detected"


def test_v1_has_no_capture_wide_totals():
    os.environ["NETDEFEND_REASONING_VERSION"] = "v1"
    flows = _synthetic_no_pattern_flows()
    r = _compute_cross_flow_pattern(flows)
    assert "capture_wide_totals" not in r
    # v1 behaviour unchanged: none_detected, flow_count 0, time_span 0
    assert r["pattern"] == "none_detected"
    assert r["flow_count"] == 0 and r["time_span_s"] == 0.0


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
