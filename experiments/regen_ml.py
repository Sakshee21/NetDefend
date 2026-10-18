"""Regenerate ONLY the ML outputs (RF attack_probability, IF anomaly_score)
for every benchmark scenario, under a selectable feature version, with NO LLM
calls.

This runs just the first two agents -- Packet Analysis and Intrusion Detection
-- which are entirely local (no Groq). It never touches the committed cache or
results: v2 outputs are written under experiments/cache_v2/ and
experiments/results_v2/ml_scores.csv, and every row records feature_version.

Usage:
    ./venv/bin/python experiments/regen_ml.py            # v2 regen + v1-vs-v2 table
    ./venv/bin/python experiments/regen_ml.py --version v2
"""
import argparse
import csv
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

RAW_DIR = REPO / "dataset" / "raw"
V1_CACHE = REPO / "experiments" / "cache"            # existing, read-only here

ML_COLUMNS = [
    "scenario_id", "family", "ground_truth", "feature_version",
    "predicted_class", "attack_probability", "anomaly_score",
    "rep_packet_count", "rep_duration_s", "rep_mean_inter_arrival",
    "rep_syn_count", "rep_protocol",
]


def benchmark_scenarios():
    """The 23 benchmark scenarios: every <id>_metadata.json whose metadata
    carries a family (the paired A/B/C and _a/_b ids), with a .pcap present.
    The three superseded no-pair ids (family=None) are excluded."""
    out = []
    for mp in sorted(RAW_DIR.glob("*_metadata.json")):
        sid = mp.name[: -len("_metadata.json")]
        if not (RAW_DIR / f"{sid}.pcap").exists():
            continue
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            meta = {}
        fam = meta.get("family")
        if not fam or str(fam).startswith("robustness"):
            continue
        out.append((sid, meta.get("family"), meta.get("ground_truth")))
    return out


def score_one(scenario, version):
    """Run Packet Analysis + Intrusion Detection on one scenario's pcap under
    the given feature version. Returns (packet_features, ml_prediction). No LLM."""
    os.environ["NETDEFEND_FEATURE_VERSION"] = version
    # Import inside the call so the version env var is already set, and reload
    # config so get_feature_version() reflects it.
    import importlib
    import agents.config as cfg
    importlib.reload(cfg)
    from agents.packet_agent import run_packet_agent
    from agents.intrusion_agent import run_intrusion_agent

    state = {"pcap_path": str(RAW_DIR / f"{scenario}.pcap"), "log_path": ""}
    state.update(run_packet_agent(state))
    state.update(run_intrusion_agent(state))
    return state.get("packet_features") or {}, state.get("ml_prediction") or {}


def v1_from_cache(scenario):
    """Read the committed v1 ML output for a scenario, if cached."""
    p = V1_CACHE / scenario / "run0.json"
    if not p.exists():
        return None
    j = json.loads(p.read_text(encoding="utf-8"))
    return j.get("ml_prediction") or {}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", default="v2", choices=("v1", "v2"),
                    help="feature version to regenerate (default v2)")
    ap.add_argument("--out", default=str(REPO / "experiments"),
                    help="base dir for versioned outputs")
    args = ap.parse_args()

    ver = args.version
    out_base = Path(args.out)
    cache_dir = out_base / f"cache_{ver}"
    results_dir = out_base / f"results_{ver}"
    cache_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    scores_csv = results_dir / "ml_scores.csv"

    scenarios = benchmark_scenarios()
    print(f"Scoring {len(scenarios)} benchmark scenarios under feature "
          f"{ver} (no LLM calls)...\n")

    rows = []
    compare = []  # (sid, family, truth, v1_prob, v2_prob, v1_iso, v2_iso)
    for sid, family, truth in scenarios:
        pf, ml = score_one(sid, ver)
        rows.append({
            "scenario_id": sid, "family": family, "ground_truth": truth,
            "feature_version": ver,
            "predicted_class": ml.get("predicted_class"),
            "attack_probability": ml.get("attack_probability"),
            "anomaly_score": ml.get("anomaly_score"),
            "rep_packet_count": pf.get("packet_count"),
            "rep_duration_s": pf.get("duration_s"),
            "rep_mean_inter_arrival": pf.get("mean_inter_arrival"),
            "rep_syn_count": pf.get("syn_count"),
            "rep_protocol": pf.get("protocol"),
        })
        # write per-scenario ML-only cache (does not touch experiments/cache)
        (cache_dir / sid).mkdir(parents=True, exist_ok=True)
        (cache_dir / sid / "run0.json").write_text(json.dumps({
            "scenario_id": sid, "run_idx": 0, "feature_version": ver,
            "ml_only": True, "packet_features": pf, "ml_prediction": ml,
        }, indent=2, default=str), encoding="utf-8")

        v1 = v1_from_cache(sid)
        compare.append((sid, family, truth,
                        (v1 or {}).get("attack_probability"),
                        ml.get("attack_probability"),
                        (v1 or {}).get("anomaly_score"),
                        ml.get("anomaly_score")))

    with open(scores_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ML_COLUMNS)
        w.writeheader()
        w.writerows(rows)

    print(f"Wrote {len(rows)} ML rows -> {scores_csv}")
    print(f"Per-scenario ML caches -> {cache_dir}/<scenario>/run0.json\n")

    # ---- v1 vs v2 comparison, by true class ----
    def _avg(xs):
        xs = [x for x in xs if x is not None]
        return (sum(xs) / len(xs)) if xs else float("nan")

    print("=== Per-scenario P(attack) and IF score: v1 vs v2 ===")
    print("%-30s %-9s | %7s %7s | %8s %8s" %
          ("scenario", "truth", "v1 P", "v2 P", "v1 iso", "v2 iso"))
    for sid, fam, truth, v1p, v2p, v1i, v2i in compare:
        print("%-30s %-9s | %7s %7s | %8s %8s" % (
            sid, (truth or "")[:9],
            "n/a" if v1p is None else "%.3f" % v1p,
            "n/a" if v2p is None else "%.3f" % v2p,
            "n/a" if v1i is None else "%.3f" % v1i,
            "n/a" if v2i is None else "%.3f" % v2i))

    print("\n=== Means by TRUE class (v1 from committed cache; v2 regenerated) ===")
    print("%-14s %4s | %14s %14s | %14s %14s" %
          ("true_class", "n", "v1 meanP", "v2 meanP", "v1 meanIso", "v2 meanIso"))
    for cls in ("ATTACK", "MISCONFIGURATION"):
        sub = [c for c in compare if c[2] == cls]
        n = len(sub)
        v1p = _avg([c[3] for c in sub]); v2p = _avg([c[4] for c in sub])
        v1i = _avg([c[5] for c in sub]); v2i = _avg([c[6] for c in sub])
        nv1 = sum(1 for c in sub if c[3] is not None)
        print("%-14s %4d | %14.3f %14.3f | %14.3f %14.3f" %
              (cls, n, v1p, v2p, v1i, v2i))
        if nv1 < n:
            print("%-14s      | (v1 means over the %d cached of %d; %d not in "
                  "committed cache)" % ("", nv1, n, n - nv1))

    # class separation: how far apart are ATTACK vs MISCONFIG mean P(attack)
    def sep(idx):
        a = _avg([c[idx] for c in compare if c[2] == "ATTACK"])
        m = _avg([c[idx] for c in compare if c[2] == "MISCONFIGURATION"])
        return a - m
    print("\nATTACK-minus-MISCONFIG mean P(attack):  v1=%+.3f   v2=%+.3f"
          % (sep(3), sep(4)))
    print("ATTACK-minus-MISCONFIG mean IF score :  v1=%+.3f   v2=%+.3f"
          % (sep(5), sep(6)))
    print("\nNo LLM calls were made. Existing cache/results untouched. "
          "STOP: awaiting confirmation before any Groq run.")


if __name__ == "__main__":
    main()
