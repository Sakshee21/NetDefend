#!/usr/bin/env python3
"""Run one scenario through the full NetDefend pipeline N times and report the
distribution of Dialectical Arbiter verdicts against the scenario's ground
truth.

LLM-backed agents (and especially the arbiter's debate) vary between runs, so a
single run says little; this repeats the run and summarizes how often the
verdict lands on each class and how often it matches the labelled ground truth.

Usage:
    python experiments/run_scenarios.py acl_misconfig
    python experiments/run_scenarios.py dns_misconfig --runs 20
    python experiments/run_scenarios.py --pcap dataset/raw/tcp_port_scan.pcap

A scenario name is resolved under dataset/raw/:
    <name>.pcap                       capture (required)
    <name>_firewall.log |             log passed to the Troubleshooting Agent
      <name>_evidence.log |             (first that exists; optional)
      <name>_config.txt |
      <name>_firewall_rules.txt
    <name>_metadata.json              ground_truth label (optional, scoring only)

--pcap / --log override the resolved paths; --runs sets N (default 10).
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

RAW_DIR = REPO_ROOT / "dataset" / "raw"
# Log/evidence suffixes tried in order when a scenario name is given without
# --log. "_evidence.txt" is the uniform, label-neutral evidence file every
# current NetDefend-Bench generator writes (same section format for attack and
# misconfiguration); it is tried first. The remaining suffixes are legacy names
# kept only so older captures still resolve -- the leak guardrail below rejects
# any of them that still carry a label.
#
# A bare "<name>.log" and "<name>_metadata.json" are deliberately NOT matched:
# the old attack .log files are a verbatim echo of the metadata (which contains
# ground_truth), so feeding either would leak the label. ground_truth is read
# only for scoring, never passed to an agent.
_LOG_SUFFIXES = ("_evidence.txt", "_firewall.log", "_evidence.log",
                 "_config.txt", "_firewall_rules.txt")

# Substrings that must NEVER appear in an evidence file fed to an agent: a
# ground-truth word, any form of "misconfig", "attack" as a label, or a
# generator/source file reference. The scenario id and family are added at
# call time. Checked case-insensitively; a hit is a hard error, not a warning.
_FORBIDDEN_TOKENS = ("misconfig", "attack", "ground_truth", "ground truth",
                     "generate_attack_scenarios", "_benchlib", ".py")


def _resolve_paths(args):
    """Return (pcap_path, log_path, metadata_path) from the CLI arguments."""
    if args.pcap:
        pcap = Path(args.pcap)
        stem = pcap.stem
    else:
        pcap = RAW_DIR / f"{args.scenario}.pcap"
        stem = args.scenario

    log = ""
    if args.log:
        log = args.log
    else:
        for suffix in _LOG_SUFFIXES:
            candidate = RAW_DIR / f"{stem}{suffix}"
            if candidate.exists():
                log = str(candidate)
                break

    metadata = RAW_DIR / f"{stem}_metadata.json"
    return str(pcap), log, metadata


def _metadata(metadata_path):
    if not metadata_path.exists():
        return {}
    try:
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def _assert_log_label_safe(log_path, scenario, family):
    """Hard guardrail: refuse to feed an evidence file that leaks the label.

    Raises SystemExit if the file contains any ground-truth word, any form of
    "misconfig"/"attack", a generator/source reference, or the scenario id or
    family name. Checked case-insensitively. A fed evidence file is the only
    scenario-derived text that reaches an agent prompt, so this is where the
    leak audit's findings are enforced."""
    if not log_path:
        return
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"cannot read evidence file {log_path}: {exc}")
    low = text.lower()
    tokens = list(_FORBIDDEN_TOKENS)
    for extra in (scenario, family):
        if extra:
            tokens.append(str(extra).lower())
    hits = sorted({t for t in tokens if t and t in low})
    if hits:
        raise SystemExit(
            f"LEAK GUARDRAIL: evidence file {log_path} contains forbidden "
            f"label/identifier token(s) {hits}; refusing to feed it to the "
            f"pipeline. Regenerate the scenario with neutral evidence, or pass "
            f"a clean --log.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", nargs="?",
                        help="scenario base name resolved under dataset/raw/")
    parser.add_argument("--pcap", help="explicit PCAP path (overrides scenario)")
    parser.add_argument("--log", help="explicit log path (overrides auto-resolution)")
    parser.add_argument("--runs", type=int, default=10, help="number of runs (default 10)")
    args = parser.parse_args()

    if not args.scenario and not args.pcap:
        parser.error("give a scenario name or --pcap")

    pcap_path, log_path, metadata_path = _resolve_paths(args)
    if not Path(pcap_path).exists():
        parser.error(f"pcap not found: {pcap_path}")

    meta = _metadata(metadata_path)
    ground_truth = meta.get("ground_truth")
    family = meta.get("family")

    # Enforce the leak audit: never feed an evidence file that carries the
    # label, the scenario id/family, or a source reference. Hard error.
    scenario_id = args.scenario or Path(pcap_path).stem
    _assert_log_label_safe(log_path, scenario_id, family)

    # Imported here so --help stays fast and import errors are reported cleanly.
    from agents.graph import app

    print(f"Scenario : {args.scenario or Path(pcap_path).stem}")
    print(f"  pcap   : {pcap_path}")
    print(f"  log    : {log_path or '(none)'}")
    print(f"  truth  : {ground_truth or 'unknown (no *_metadata.json)'}")
    print(f"Running {args.runs} time(s)...\n")

    verdicts = []
    for i in range(1, args.runs + 1):
        t = time.time()
        try:
            result = app.invoke({"pcap_path": pcap_path, "log_path": log_path})
            verdict = (result.get("arbiter_verdict") or {})
            classification = verdict.get("classification", "ERROR")
            confidence = verdict.get("confidence")
        except Exception as exc:  # noqa: BLE001 -- keep going; one bad run shouldn't abort the batch
            classification, confidence = "ERROR", None
            print(f"  run {i:>2}: ERROR ({str(exc)[:80]})  [{time.time()-t:.0f}s]")
            verdicts.append(classification)
            continue
        verdicts.append(classification)
        match = ""
        if ground_truth:
            match = "  [match]" if classification == ground_truth else "  [miss]"
        conf = f" conf {confidence:.2f}" if isinstance(confidence, (int, float)) else ""
        print(f"  run {i:>2}: {classification}{conf}{match}  [{time.time()-t:.0f}s]")

    counts = Counter(verdicts)
    n = len(verdicts)
    print(f"\nVerdict distribution (N={n}):")
    for cls, c in counts.most_common():
        tag = "  <- ground truth" if cls == ground_truth else ""
        print(f"  {cls:<18} {c:>3}  ({100*c/n:5.1f}%){tag}")

    if ground_truth:
        agree = counts.get(ground_truth, 0)
        print(f"\nAgreement with ground truth ({ground_truth}): "
              f"{agree}/{n} ({100*agree/n:.1f}%)")
    else:
        print("\nNo ground_truth metadata; distribution only.")


if __name__ == "__main__":
    main()
