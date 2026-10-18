"""Write experiments/results_v2/freeze_manifest.json: sha256 of the v2 code,
models and the 23 benchmark scenarios' evidence/metadata, with a UTC stamp.
No behaviour change; read-only over the repo."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RAW = REPO / "dataset" / "raw"
OUT = REPO / "experiments" / "results_v2" / "freeze_manifest.json"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def benchmark_ids():
    ids = []
    for mp in sorted(RAW.glob("*_metadata.json")):
        sid = mp.name[: -len("_metadata.json")]
        if not (RAW / f"{sid}.pcap").exists():
            continue
        try:
            fam = (json.loads(mp.read_text(encoding="utf-8")) or {}).get("family")
        except (ValueError, OSError):
            fam = None
        if not fam or str(fam).startswith("robustness"):
            continue
        ids.append(sid)
    return ids


def main():
    files = []
    files += sorted((REPO / "agents").glob("*.py"))
    files += [REPO / "knowledge" / "mitre" / "lookup.py"]
    files += [REPO / "experiments" / "run_scenarios.py",
              REPO / "experiments" / "analyze.py",
              REPO / "experiments" / "regen_ml.py"]
    files += [REPO / "ml" / "models" / n for n in (
        "rf_intrusion_detector.joblib", "isolation_forest.joblib",
        "isolation_forest_scaler.joblib", "label_encoder.joblib",
        "protocol_encoder.joblib")]

    ids = benchmark_ids()
    for sid in ids:
        for suffix in ("_evidence.txt", "_firewall_rules.txt", "_metadata.json"):
            p = RAW / f"{sid}{suffix}"
            if p.exists():
                files.append(p)

    entries = {}
    for p in files:
        rel = str(p.relative_to(REPO))
        entries[rel] = {"sha256": sha256(p), "bytes": p.stat().st_size}

    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "v2 freeze manifest -- integrity of code, models and the 23 "
                   "benchmark scenarios' evidence/metadata before the v2/v2 run",
        "benchmark_scenario_count": len(ids),
        "benchmark_scenarios": ids,
        "file_count": len(entries),
        "files": entries,
    }
    OUT.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("wrote", OUT)
    print("files hashed:", len(entries), "| benchmark scenarios:", len(ids))
    # quick category tally
    cats = {"agents": 0, "evidence": 0, "firewall_rules": 0, "metadata": 0,
            "models": 0, "experiments": 0, "knowledge": 0}
    for rel in entries:
        if rel.startswith("agents/"):
            cats["agents"] += 1
        elif rel.endswith("_evidence.txt"):
            cats["evidence"] += 1
        elif rel.endswith("_firewall_rules.txt"):
            cats["firewall_rules"] += 1
        elif rel.endswith("_metadata.json"):
            cats["metadata"] += 1
        elif rel.startswith("ml/models/"):
            cats["models"] += 1
        elif rel.startswith("experiments/"):
            cats["experiments"] += 1
        elif rel.startswith("knowledge/"):
            cats["knowledge"] += 1
    print("by category:", cats)


if __name__ == "__main__":
    main()
