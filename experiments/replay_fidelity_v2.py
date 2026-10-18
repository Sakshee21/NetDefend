"""No-LLM before/after replay of the v2 evidence-fidelity changes for two
scenarios. Recomputes the bundle under v1 and v2 from the pcap + evidence
file (no Groq). Read-only; writes nothing to the v1 cache/results.

Run: ./venv/bin/python experiments/replay_fidelity_v2.py
"""
import io
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
RAW = REPO / "dataset" / "raw"


def bundle_for(sid, version):
    os.environ["NETDEFEND_REASONING_VERSION"] = version
    os.environ["NETDEFEND_FEATURE_VERSION"] = version
    from agents.packet_agent import run_packet_agent
    from agents.troubleshooting_agent import _build_incident_evidence
    from agents import grounding
    state = {"pcap_path": str(RAW / f"{sid}.pcap"),
             "log_path": str(RAW / f"{sid}_evidence.txt")}
    buf = io.StringIO()
    with redirect_stdout(buf):
        state.update(run_packet_agent(state))
        bundle = _build_incident_evidence(state)
        null = not grounding.bundle_has_config_artifact(bundle)
    log_ev = bundle.get("log_evidence") or {}
    return state, bundle, null, bool(log_ev.get("raw_log_excerpt"))


def show(sid):
    print("\n" + "=" * 72)
    print(sid)
    for ver in ("v1", "v2"):
        state, bundle, null, cfg_supplied = bundle_for(sid, ver)
        no = bundle["network_observation"]
        rf = no["representative_flow"]
        cf = state.get("cross_flow_pattern") or {}
        cw = cf.get("capture_wide_totals")
        print(f"\n  --- {ver} ---")
        print("  representative_flow.source_ip     :",
              rf["source_ip"] if "source_ip" in rf else "(omitted)")
        print("  representative_flow.destination_port:",
              rf["destination_port"] if "destination_port" in rf else "(omitted)")
        print("  cross_flow flow_count / time_span_s:",
              cf.get("flow_count"), "/", cf.get("time_span_s"))
        print("  capture_wide_totals               :",
              json.dumps(cw) if cw else "(absent under v1)")
        print("  config_evidence_supplied          :", cfg_supplied)
        print("  null decision (misconfig)         :", "NULL" if null else "not null")


def main():
    for sid in ("udp_port_scan_a", "tcp_syn_burst_a"):
        show(sid)
    print("\nNo LLM calls. Recomputed from pcaps; v1 cache/results not written.")


if __name__ == "__main__":
    main()
