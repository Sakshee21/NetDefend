#!/usr/bin/env python3
"""Regenerate the whole NetDefend-Bench capture set into dataset/raw.

Runs, in sequence:
  * every attack scenario in generate_attack_scenarios.py (one capture each)
  * each of the three misconfiguration generators on all three host pairs
    (A, B, C), so every pair carries both attack and misconfiguration
    traffic and the IP pair never predicts the label

Each generator is launched with THIS interpreter (sys.executable), so run
this driver with the repo venv python (which has both mininet and scapy):

    sudo /home/sakshee/NetDefend/venv/bin/python mininet/scenarios/run_all.py

At the end it prints a per-scenario summary of pcap_verified and
rules_verified, read back from each *_metadata.json.

Nothing is deleted. New ids (attack *_a/_b, misconfig *_A/_B/_C) never
collide with the old h1<->h2 misconfig captures or the friend's timestamped
attack set.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

# Imported for its scenario table only (no mininet import at module top).
import generate_attack_scenarios as atk

ATTACK_SCRIPT = HERE / "generate_attack_scenarios.py"
MISCONFIG_SCRIPTS = [
    HERE / "acl_misconfig.py",
    HERE / "dns_misconfig.py",
    HERE / "disabled_logging_misconfig.py",
]
MISCONFIG_FAMILIES = {
    "acl_misconfig.py": "acl_misconfig",
    "dns_misconfig.py": "dns_misconfig",
    "disabled_logging_misconfig.py": "disabled_logging_misconfig",
}
PAIRS = ["A", "B", "C"]


def _interpreter_has_deps() -> bool:
    r = subprocess.run([sys.executable, "-c", "import mininet, scapy"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def _run(cmd):
    print("\n" + "=" * 78)
    print("$ " + " ".join(str(c) for c in cmd))
    print("=" * 78, flush=True)
    return subprocess.run(cmd).returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", default=str(REPO_ROOT / "dataset" / "raw"),
                    help="output directory (default <repo>/dataset/raw)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root: sudo <repo-venv>/bin/python mininet/scenarios/run_all.py")
    if not _interpreter_has_deps():
        sys.exit("this interpreter cannot import mininet AND scapy.\n"
                 "Re-run with the repo venv python:\n"
                 "    sudo %s/venv/bin/python mininet/scenarios/run_all.py" % REPO_ROOT)

    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Expected scenario ids (for the summary read-back).
    attack_ids = [atk.sid_of(s) for s in atk.SCENARIOS]
    misconfig_ids = [f"{fam}_{p}" for fam in MISCONFIG_FAMILIES.values() for p in PAIRS]

    # --- 1. all attack scenarios (one generator run writes them all) ---
    _run([sys.executable, str(ATTACK_SCRIPT), "--outdir", str(out_dir)])

    # --- 2. each misconfig generator on each pair ---
    for script in MISCONFIG_SCRIPTS:
        for pair in PAIRS:
            _run([sys.executable, str(script), "--pair", pair, "--outdir", str(out_dir)])

    # --- 3. summary, read back from the metadata ---
    print("\n" + "#" * 78)
    print("SUMMARY  (read back from *_metadata.json in %s)" % out_dir)
    print("#" * 78)
    print("%-32s %-18s %-13s %s" % ("scenario_id", "ground_truth", "pcap_verified", "rules_verified"))
    print("-" * 78)
    missing = []
    for sid in attack_ids + misconfig_ids:
        mp = out_dir / f"{sid}_metadata.json"
        if not mp.exists():
            missing.append(sid)
            print("%-32s %-18s %-13s %s" % (sid, "?", "MISSING", "MISSING"))
            continue
        m = json.loads(mp.read_text(encoding="utf-8"))
        print("%-32s %-18s %-13s %s" % (
            sid, m.get("ground_truth", "?"),
            m.get("pcap_verified"), m.get("rules_verified")))
    if missing:
        print("\nMISSING metadata (generator skipped or failed): %s" % ", ".join(missing))
    print("\nReview any pcap_verified=False or rules_verified=False before using "
          "that scenario as labelled data.")


if __name__ == "__main__":
    main()
