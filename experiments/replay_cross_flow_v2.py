"""No-LLM replay of the v2 cross-flow capture-wide totals + null decision.

Recomputes cross_flow_pattern for every benchmark scenario by running ONLY the
Packet Analysis agent under v2 evidence (no Groq, no ML-feature change to the
numbers scored), and prints per scenario the true capture-wide totals
(flow_count, distinct ports/hosts, time span) and the bundle-based null
decision. Reads pcaps + evidence files read-only; writes nothing to the v1
cache/results.

Run: ./venv/bin/python experiments/replay_cross_flow_v2.py
"""
import io
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

os.environ["NETDEFEND_REASONING_VERSION"] = "v2"
os.environ["NETDEFEND_FEATURE_VERSION"] = "v2"

from agents.packet_agent import run_packet_agent          # noqa: E402
from agents.troubleshooting_agent import _build_incident_evidence  # noqa: E402
from agents import grounding                               # noqa: E402

RAW = REPO / "dataset" / "raw"
MISC = ("acl_misconfig", "dns_misconfig", "disabled_logging_misconfig")
_LOG_SUFFIXES = ("_evidence.txt", "_firewall.log", "_evidence.log",
                 "_config.txt", "_firewall_rules.txt")


def benchmark_scenarios():
    out = []
    for mp in sorted(RAW.glob("*_metadata.json")):
        sid = mp.name[: -len("_metadata.json")]
        if not (RAW / f"{sid}.pcap").exists():
            continue
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            meta = {}
        fam = meta.get("family")
        if not fam or str(fam).startswith("robustness"):
            continue
        truth = "MISCONFIG" if any(sid.startswith(m) for m in MISC) else "ATTACK"
        out.append((sid, truth))
    return out


def resolve_log(sid):
    for suf in _LOG_SUFFIXES:
        c = RAW / f"{sid}{suf}"
        if c.exists():
            return str(c)
    return ""


def one(sid):
    state = {"pcap_path": str(RAW / f"{sid}.pcap"), "log_path": resolve_log(sid)}
    buf = io.StringIO()
    with redirect_stdout(buf):                      # silence agent logging
        state.update(run_packet_agent(state))
    cf = state.get("cross_flow_pattern") or {}
    cw = cf.get("capture_wide_totals") or {}
    bundle = _build_incident_evidence(state)
    null = not grounding.bundle_has_config_artifact(bundle)
    return cf, cw, null


def main():
    rows = []
    for sid, truth in benchmark_scenarios():
        cf, cw, null = one(sid)
        rows.append((sid, truth, cf, cw, null))

    print("=== v2 cross-flow capture-wide totals + null decision (no LLM) ===\n")
    print("%-30s %-9s %8s %6s %6s %9s %-14s %5s" % (
        "scenario", "truth", "flows", "ports", "hosts", "span_s",
        "pattern", "null"))
    for sid, truth, cf, cw, null in rows:
        print("%-30s %-9s %8s %6s %6s %9s %-14s %5s" % (
            sid, truth,
            cw.get("subject_flow_count"),
            cw.get("distinct_dst_ports"),
            cw.get("distinct_dst_hosts"),
            ("%.3f" % cw["time_span_s"]) if cw.get("time_span_s") is not None else "n/a",
            cf.get("pattern"),
            "YES" if null else "no"))

    # spotlight dns_misconfig_A: the scenario that motivated the fix
    for sid, truth, cf, cw, null in rows:
        if sid == "dns_misconfig_A":
            print("\n--- dns_misconfig_A detail ---")
            print("pattern-specific flow_count (old field):", cf.get("flow_count"),
                  "time_span_s:", cf.get("time_span_s"))
            print("capture_wide_totals:", json.dumps(cw, indent=2))
    print("\nNo LLM calls. Recomputed from pcaps; v1 cache/results not written.")


if __name__ == "__main__":
    main()
