#!/usr/bin/env python3
"""NetDefend-Bench evaluation harness.

For each (scenario_id, run_idx) the upstream agents are executed exactly ONCE
(Packet -> Intrusion -> Threat Hunting -> Network Troubleshooting), cached, and
then the Dialectical Arbiter is run once for C4. All four conditions are derived
from that single cached execution so comparisons are paired and the LLM is never
queried twice for the same evidence:

  C1  Random Forest only            ATTACK if P(attack) >= 0.5 else MISCONFIGURATION   (no LLM)
  C2  attack hypothesis only        ATTACK (no competing hypothesis)
  C3  rule-based fusion             higher prior confidence wins; TIE -> ATTACK
  C4  full system                   Dialectical Arbiter verdict (may be UNCERTAIN)

C3's attack-side prior is ttp_confidence -- the SAME quantity the Arbiter itself
receives as the attack hypothesis's confidence (see agents/arbiter.py
_attack_package). NOTE: ttp_confidence is the ATT&CK-mapping confidence; the
threat hypothesis has no separate scalar confidence. C3 therefore fuses the same
priors the Arbiter sees, which is the intended "debate removed" ablation. (This
is flagged for sign-off; change C3_ATTACK_PRIOR to override.)

Orchestration is done by calling the agent functions directly rather than
through agents/graph.py, so each agent can be timed and its token usage
captured, and so C2/C3/C4 derive from one upstream pass. An equivalence test
(experiments/test_equivalence.py) proves this matches graph.py with the LLM
mocked. The Incident Response agent is not run (no condition needs its report).

Exclusion rule: a (scenario, run_idx) is EXCLUDED for ALL conditions if the
threat agent failed (llm_call_failed), the troubleshooting agent returned
LLM_UNAVAILABLE, or the Arbiter fell to its rule-based fallback. Such rows are
written with llm_failed=True and dropped by analyze.py; this keeps the paired
comparisons on the same valid runs. A failed-then-retried/repaired attempt that
still produced a real answer is KEPT and flagged (retry_succeeded/json_repaired).

Usage:
    python experiments/run_scenarios.py --all --runs 1 --tag personA
    python experiments/run_scenarios.py --only id1,id2 --runs 1 --run-start 1
    python experiments/run_scenarios.py --all --daily-token-budget 180000
"""
import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

RAW_DIR = REPO_ROOT / "dataset" / "raw"
RESULTS_DIR = REPO_ROOT / "experiments" / "results"
CACHE_DIR = REPO_ROOT / "experiments" / "cache"
RUNS_CSV = RESULTS_DIR / "runs.csv"
TRANSCRIPTS = RESULTS_DIR / "transcripts.jsonl"

# Evidence file resolved for a scenario (label-neutral _evidence.txt first).
_LOG_SUFFIXES = ("_evidence.txt", "_firewall.log", "_evidence.log",
                 "_config.txt", "_firewall_rules.txt")
# Tokens that must never appear in a fed evidence file (+ scenario id/family).
_FORBIDDEN_TOKENS = ("misconfig", "attack", "ground_truth", "ground truth",
                     "generate_attack_scenarios", "_benchlib", ".py")

# C3 attack-side prior (see module docstring / gate c).
C3_ATTACK_PRIOR = "ttp_confidence"
C1_THRESHOLD = 0.5
# The sklearn version the committed models were trained with; a mismatch makes
# the RF/IsolationForest outputs (C1 + ML evidence) unreliable and is recorded
# in every row so mixed-environment data is visible after a merge.
EXPECTED_SKLEARN = "1.6.1"

CSV_COLUMNS = [
    "scenario_id", "family", "ground_truth", "condition", "run_idx", "verdict",
    "confidence", "mitre_technique", "latency_s", "llm_calls", "prompt_tokens",
    "completion_tokens", "llm_failed", "failed_agents", "retry_succeeded",
    "arbiter_fallback_used", "json_fallback_used", "json_repaired",
    "evidence_present", "model_name", "sklearn_version", "run_tag", "timestamp",
]

# Feature / reasoning versions in effect for this process. v1 keeps the
# committed cache / results / CSV schema byte-for-byte; selecting v2 on either
# axis redirects all outputs to *_v2 dirs and adds the version + grounding
# columns (see --feature-version / --reasoning-version in main()).
# ACTIVE_COLUMNS is what the CSV writers actually use, so v1 never gains the
# extra columns.
FEATURE_VERSION = "v1"
REASONING_VERSION = "v1"
# Columns added only when reasoning v2 is active.
_V2_REASONING_COLUMNS = [
    "feature_version", "reasoning_version",
    "attack_evidence_dropped", "misconfig_evidence_dropped",
    "misconfig_null_hypothesis", "grounding_flagged",
    # Verbatim text of each dropped (ungrounded) evidence item, JSON-encoded.
    "attack_evidence_dropped_items", "misconfig_evidence_dropped_items",
]
ACTIVE_COLUMNS = CSV_COLUMNS


# ----------------------------------------------------------------------------------
# Resolution + guardrail
# ----------------------------------------------------------------------------------
def _resolve(scenario):
    pcap = RAW_DIR / f"{scenario}.pcap"
    log = ""
    for suffix in _LOG_SUFFIXES:
        c = RAW_DIR / f"{scenario}{suffix}"
        if c.exists():
            log = str(c)
            break
    return str(pcap), log, RAW_DIR / f"{scenario}_metadata.json"


def _metadata(path):
    if not Path(path).exists():
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def _assert_log_label_safe(log_path, scenario, family):
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
            f"token(s) {hits}; refusing to feed it. Regenerate with neutral "
            f"evidence or pass a clean evidence file.")


def list_scenarios():
    # Excludes the robustness_* families (adversarial probes that live beside
    # the benchmark but must never enter the headline 23-scenario runs); they
    # are reachable only by naming them explicitly with --only.
    ids = []
    for mp in sorted(RAW_DIR.glob("*_metadata.json")):
        sid = mp.name[: -len("_metadata.json")]
        if not (RAW_DIR / f"{sid}.pcap").exists():
            continue
        try:
            fam = (json.loads(mp.read_text(encoding="utf-8")) or {}).get("family") or ""
        except (ValueError, OSError):
            fam = ""
        if str(fam).startswith("robustness"):
            continue
        ids.append(sid)
    return ids


# ----------------------------------------------------------------------------------
# Telemetry helpers
# ----------------------------------------------------------------------------------
def _tel_summary(tel):
    calls = tel["calls"]
    pt = sum((c.get("prompt_tokens") or 0) for c in calls)
    ct = sum((c.get("completion_tokens") or 0) for c in calls)
    statuses = [c.get("status") for c in calls]
    return {
        "calls": len(calls),
        "prompt_tokens": pt,
        "completion_tokens": ct,
        "had_nonok": any(s != "ok" for s in statuses),
        "json_fail": any(s == "json_validate_failed" for s in statuses),
        "repaired": any(p.get("repaired") for p in tel["parses"]),
        "statuses": statuses,
    }


def _run_agent(fn, state, llm):
    llm.reset_telemetry()
    t0 = time.time()
    upd = fn(state) or {}
    dt = time.time() - t0
    state.update(upd)
    return dt, _tel_summary(llm.get_telemetry())


# ----------------------------------------------------------------------------------
# One (scenario, run_idx): orchestrate, cache, derive C1-C4
# ----------------------------------------------------------------------------------
def run_one(scenario, run_idx, tag, model_name, sklearn_version):
    import agents.llm_client as llm
    from agents.packet_agent import run_packet_agent
    from agents.intrusion_agent import run_intrusion_agent
    from agents.threat_agent import run_threat_agent
    from agents.troubleshooting_agent import run_troubleshooting_agent
    from agents.arbiter import run_arbiter

    pcap, log, meta_path = _resolve(scenario)
    meta = _metadata(meta_path)
    truth = meta.get("ground_truth")
    family = meta.get("family")
    _assert_log_label_safe(log, scenario, family)

    llm.reset_tpd_flag()
    state = {"pcap_path": pcap, "log_path": log}
    t_packet, _ = _run_agent(run_packet_agent, state, llm)
    t_intr, _ = _run_agent(run_intrusion_agent, state, llm)
    t_threat, tel_threat = _run_agent(run_threat_agent, state, llm)
    t_trbl, tel_trbl = _run_agent(run_troubleshooting_agent, state, llm)
    # upstream cached point reached here; now the one expensive step:
    t_arb, tel_arb = _run_agent(run_arbiter, state, llm)

    # ---- failure / reliability flags ----
    ml = state.get("ml_prediction") or {}
    attack_prob = ml.get("attack_probability")
    ttp_id = state.get("ttp_id")
    ttp_conf = float(state.get("ttp_confidence") or 0.0)
    is_mis = float(state.get("is_misconfiguration") or 0.0)
    arb = state.get("arbiter_verdict") or {}
    arb_reason = str(arb.get("reasoning", ""))

    threat_failed = bool(state.get("llm_call_failed"))
    trbl_failed = (state.get("misconfig_hypothesis") or {}).get(
        "taxonomy_category") == "LLM_UNAVAILABLE"
    arbiter_fallback = "fallback rule used" in arb_reason
    failed_agents = []
    if threat_failed:
        failed_agents.append("threat")
    if trbl_failed:
        failed_agents.append("troubleshooting")
    if arbiter_fallback:
        failed_agents.append("arbiter")
    excluded = bool(failed_agents)

    retry_succeeded = (
        (tel_threat["had_nonok"] and not threat_failed)
        or (tel_trbl["had_nonok"] and not trbl_failed)
        or (tel_arb["had_nonok"] and not arbiter_fallback)
    )
    json_repaired = tel_threat["repaired"] or tel_trbl["repaired"] or tel_arb["repaired"]
    json_fallback_used = (
        (threat_failed and tel_threat["json_fail"])
        or (trbl_failed and tel_trbl["json_fail"])
        or (arbiter_fallback and tel_arb["json_fail"])
    )
    evidence_present = bool(log)

    # ---- verdicts ----
    c1 = "ATTACK" if (attack_prob is not None and attack_prob >= C1_THRESHOLD) else "MISCONFIGURATION"
    c2 = "ATTACK"
    attack_prior = ttp_conf if C3_ATTACK_PRIOR == "ttp_confidence" else float(attack_prob or 0.0)
    if attack_prior > is_mis:
        c3, c3_conf = "ATTACK", attack_prior
    elif is_mis > attack_prior:
        c3, c3_conf = "MISCONFIGURATION", is_mis
    else:
        c3, c3_conf = "ATTACK", attack_prior  # tie -> ATTACK

    # ---- C3+gate (supplementary): the same fusion rule, but gated by the
    # bundle-based null check. If the misconfiguration side is null (the
    # evidence bundle holds no configuration artifact), the verdict is ATTACK;
    # otherwise it is exactly C3. Computed from cached upstream only, no LLM.
    from agents import grounding as _grounding
    from agents.troubleshooting_agent import _build_incident_evidence as _bie
    _mg = state.get("misconfig_grounding") or {}
    if "null_hypothesis" in _mg:
        misconfig_null_gate = bool(_mg["null_hypothesis"])
    else:
        misconfig_null_gate = not _grounding.bundle_has_config_artifact(_bie(state))
    if misconfig_null_gate:
        c3_gate, c3_gate_conf = "ATTACK", attack_prior
    else:
        c3_gate, c3_gate_conf = c3, c3_conf

    c4 = arb.get("classification", "ERROR")
    c4_conf = arb.get("confidence")

    def mitre(v):
        return ttp_id if v == "ATTACK" else None

    common = dict(
        scenario_id=scenario, family=family, ground_truth=truth, run_idx=run_idx,
        llm_failed=excluded, failed_agents=";".join(failed_agents),
        retry_succeeded=retry_succeeded, arbiter_fallback_used=arbiter_fallback,
        json_fallback_used=json_fallback_used, json_repaired=json_repaired,
        evidence_present=evidence_present, model_name=model_name,
        sklearn_version=sklearn_version, run_tag=tag,
        feature_version=FEATURE_VERSION, reasoning_version=REASONING_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # v2-reasoning grounding results (absent/None under v1). Recorded in every
    # row so a flagged run is visible after merge (see --reasoning-version).
    attack_grounding = state.get("attack_grounding") or {}
    misconfig_grounding = state.get("misconfig_grounding") or {}
    common.update(
        attack_evidence_dropped=attack_grounding.get("evidence_dropped"),
        misconfig_evidence_dropped=misconfig_grounding.get("evidence_dropped"),
        misconfig_null_hypothesis=misconfig_grounding.get("null_hypothesis"),
        grounding_flagged=bool(attack_grounding.get("flagged")
                               or misconfig_grounding.get("flagged")),
        attack_evidence_dropped_items=json.dumps(
            attack_grounding.get("dropped_items") or []),
        misconfig_evidence_dropped_items=json.dumps(
            misconfig_grounding.get("dropped_items") or []),
    )
    rows = [
        {**common, "condition": "C1", "verdict": c1, "confidence": attack_prob,
         "mitre_technique": None, "latency_s": round(t_packet + t_intr, 3),
         "llm_calls": 0, "prompt_tokens": 0, "completion_tokens": 0},
        {**common, "condition": "C2", "verdict": c2, "confidence": ttp_conf,
         "mitre_technique": mitre(c2),
         "latency_s": round(t_packet + t_intr + t_threat, 3),
         "llm_calls": tel_threat["calls"],
         "prompt_tokens": tel_threat["prompt_tokens"],
         "completion_tokens": tel_threat["completion_tokens"]},
        {**common, "condition": "C3", "verdict": c3, "confidence": round(c3_conf, 4),
         "mitre_technique": mitre(c3),
         "latency_s": round(t_packet + t_intr + t_threat + t_trbl, 3),
         "llm_calls": tel_threat["calls"] + tel_trbl["calls"],
         "prompt_tokens": tel_threat["prompt_tokens"] + tel_trbl["prompt_tokens"],
         "completion_tokens": tel_threat["completion_tokens"] + tel_trbl["completion_tokens"]},
        # Supplementary condition: fusion after the bundle-based null gate.
        # Same upstream calls as C3 (no extra LLM), so cost mirrors C3.
        {**common, "condition": "C3+gate", "verdict": c3_gate,
         "confidence": round(c3_gate_conf, 4), "mitre_technique": mitre(c3_gate),
         "latency_s": round(t_packet + t_intr + t_threat + t_trbl, 3),
         "llm_calls": tel_threat["calls"] + tel_trbl["calls"],
         "prompt_tokens": tel_threat["prompt_tokens"] + tel_trbl["prompt_tokens"],
         "completion_tokens": tel_threat["completion_tokens"] + tel_trbl["completion_tokens"]},
        {**common, "condition": "C4", "verdict": c4, "confidence": c4_conf,
         "mitre_technique": mitre(c4),
         "latency_s": round(t_packet + t_intr + t_threat + t_trbl + t_arb, 3),
         "llm_calls": tel_threat["calls"] + tel_trbl["calls"] + tel_arb["calls"],
         "prompt_tokens": (tel_threat["prompt_tokens"] + tel_trbl["prompt_tokens"]
                           + tel_arb["prompt_tokens"]),
         "completion_tokens": (tel_threat["completion_tokens"] + tel_trbl["completion_tokens"]
                               + tel_arb["completion_tokens"])},
    ]

    cache = {
        "scenario_id": scenario, "run_idx": run_idx, "tag": tag,
        "packet_features": state.get("packet_features"),
        "cross_flow_pattern": state.get("cross_flow_pattern"),
        "ml_prediction": ml,
        "attack_hypothesis": {"ttp_id": ttp_id, "ttp_confidence": ttp_conf,
                              "threat_hypothesis": state.get("threat_hypothesis"),
                              "llm_call_failed": threat_failed},
        "misconfig_hypothesis": {"is_misconfiguration": is_mis,
                                 "hypothesis": state.get("misconfig_hypothesis")},
        "latency_s": {"packet": round(t_packet, 3), "intrusion": round(t_intr, 3),
                      "threat": round(t_threat, 3), "troubleshooting": round(t_trbl, 3),
                      "arbiter": round(t_arb, 3)},
        "telemetry": {"threat": tel_threat, "troubleshooting": tel_trbl, "arbiter": tel_arb},
        "arbiter_verdict": arb,
        "refutation_exchange": state.get("refutation_exchange"),
        "feature_version": FEATURE_VERSION,
        "reasoning_version": REASONING_VERSION,
        "grounding": {"attack": state.get("attack_grounding"),
                      "misconfig": state.get("misconfig_grounding")},
    }
    transcript = {
        "scenario_id": scenario, "run_idx": run_idx, "tag": tag,
        "timestamp": common["timestamp"], "ground_truth": truth,
        "attack_hypothesis": cache["attack_hypothesis"],
        "misconfig_hypothesis": cache["misconfig_hypothesis"],
        "cross_flow_pattern": state.get("cross_flow_pattern"),
        "refutation_exchange": state.get("refutation_exchange"),
        "arbiter_verdict": arb,
    }
    tpd_hit = llm.daily_token_budget_exceeded()
    return rows, cache, transcript, tpd_hit


# ----------------------------------------------------------------------------------
# CSV + cache IO
# ----------------------------------------------------------------------------------
def _ensure_results():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not RUNS_CSV.exists():
        with open(RUNS_CSV, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=ACTIVE_COLUMNS).writeheader()


def _done_set():
    """(scenario, run_idx) already present with 4 VALID rows (llm_failed False)."""
    if not RUNS_CSV.exists():
        return set()
    seen = {}
    with open(RUNS_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            key = (r["scenario_id"], int(r["run_idx"]))
            ok = str(r.get("llm_failed")).lower() in ("false", "0", "")
            seen.setdefault(key, []).append(ok)
    return {k for k, oks in seen.items() if len(oks) >= 4 and all(oks)}


def _append_rows(rows):
    with open(RUNS_CSV, "a", newline="", encoding="utf-8") as f:
        # extrasaction='ignore' so the feature_version key present on every row
        # is simply dropped under v1 (where ACTIVE_COLUMNS omits it), keeping
        # the existing v1 runs.csv schema unchanged.
        w = csv.DictWriter(f, fieldnames=ACTIVE_COLUMNS, extrasaction="ignore")
        for r in rows:
            w.writerow(r)


def _write_cache(cache):
    d = CACHE_DIR / cache["scenario_id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / f"run{cache['run_idx']}.json").write_text(
        json.dumps(cache, indent=2, default=str), encoding="utf-8")


def _append_transcript(t):
    with open(TRANSCRIPTS, "a", encoding="utf-8") as f:
        f.write(json.dumps(t, default=str) + "\n")


def _resume_cmd(remaining_ids, run_idx, tag, budget):
    only = ",".join(remaining_ids)
    cmd = (f"python experiments/run_scenarios.py --only {only} "
           f"--runs 1 --run-start {run_idx}")
    if tag:
        cmd += f" --tag {tag}"
    if budget:
        cmd += f" --daily-token-budget {budget}"
    return cmd


# ----------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------
def main():
    import os
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="every scenario with metadata")
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("positional", nargs="*", help="scenario ids (same as --only)")
    ap.add_argument("--runs", type=int, default=1, help="run indices per scenario")
    ap.add_argument("--run-start", type=int, default=0, help="first run index")
    ap.add_argument("--tag", default="", help="who/what produced this run")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between runs")
    ap.add_argument("--daily-token-budget", type=int, default=0,
                    help="stop cleanly once this many tokens are used this process")
    ap.add_argument("--max-tokens", type=int, default=0,
                    help="optional per-call completion cap (0 = unchanged)")
    ap.add_argument("--feature-version", default="v1", choices=("v1", "v2"),
                    help="v1 (default) keeps existing dirs/schema; v2 applies the "
                         "feature-unit fixes and writes to *_v2 dirs with a "
                         "feature_version column")
    ap.add_argument("--reasoning-version", default="v1", choices=("v1", "v2"),
                    help="v1 (default) keeps existing behaviour; v2 turns on the "
                         "grounding validator, misconfiguration null-hypothesis "
                         "rule, evidence-support adjudication rubric and neutral "
                         "default-ruleset statement, writing to *_v2 dirs with "
                         "grounding columns")
    args = ap.parse_args()

    # Select the versions BEFORE any agent import so the agents pick them up.
    # If EITHER axis is v2, redirect every output to *_v2 dirs so the committed
    # v1 cache/results stay untouched, and add the version columns.
    global FEATURE_VERSION, REASONING_VERSION, ACTIVE_COLUMNS
    global RESULTS_DIR, CACHE_DIR, RUNS_CSV, TRANSCRIPTS
    FEATURE_VERSION = args.feature_version
    REASONING_VERSION = args.reasoning_version
    os.environ["NETDEFEND_FEATURE_VERSION"] = FEATURE_VERSION
    os.environ["NETDEFEND_REASONING_VERSION"] = REASONING_VERSION
    if FEATURE_VERSION == "v2" or REASONING_VERSION == "v2":
        ACTIVE_COLUMNS = CSV_COLUMNS + _V2_REASONING_COLUMNS
        RESULTS_DIR = REPO_ROOT / "experiments" / "results_v2"
        CACHE_DIR = REPO_ROOT / "experiments" / "cache_v2"
        RUNS_CSV = RESULTS_DIR / "runs.csv"
        TRANSCRIPTS = RESULTS_DIR / "transcripts.jsonl"
        print(f"[v2: feature={FEATURE_VERSION} reasoning={REASONING_VERSION}] "
              f"outputs -> {CACHE_DIR} and {RUNS_CSV}")

    if args.only:
        scenarios = [s for s in args.only.split(",") if s]
    elif args.positional:
        scenarios = args.positional
    elif args.all:
        scenarios = list_scenarios()
    else:
        ap.error("give --all, --only id1,id2, or scenario ids positionally")

    import agents.llm_client as llm
    if args.max_tokens:
        llm.set_max_tokens(args.max_tokens)
    model_name = "%s|%s" % (
        os.environ.get("MODEL_NAME_HEAVY", "openai/gpt-oss-120b"),
        os.environ.get("MODEL_NAME_LIGHT", "openai/gpt-oss-20b"))

    import sklearn
    sklearn_version = sklearn.__version__
    if sklearn_version != EXPECTED_SKLEARN:
        print("=" * 72)
        print(f"!!! scikit-learn VERSION MISMATCH: installed {sklearn_version}, models "
              f"trained with {EXPECTED_SKLEARN}.")
        print(f"!!! RF/IsolationForest outputs (C1 and ML evidence) may be INVALID. "
              f"Fix with:  pip install scikit-learn=={EXPECTED_SKLEARN}")
        print(f"!!! Recording sklearn_version={sklearn_version} in every row so this is "
              f"visible after merge.")
        print("=" * 72)

    _ensure_results()
    done = _done_set()
    run_indices = list(range(args.run_start, args.run_start + args.runs))

    tokens_used = 0
    print(f"Scenarios: {len(scenarios)}  run indices: {run_indices}  tag: {args.tag or '(none)'}")
    print(f"Model: {model_name}\n")

    for ri in run_indices:
        for i, sid in enumerate(scenarios):
            if (sid, ri) in done:
                print(f"skip {sid} run{ri} (already done, valid)")
                continue
            if args.daily_token_budget and tokens_used >= args.daily_token_budget:
                remaining = scenarios[i:]
                print(f"\nDAILY TOKEN BUDGET reached ({tokens_used} >= "
                      f"{args.daily_token_budget}). Stopping cleanly.\nResume with:\n  "
                      f"{_resume_cmd(remaining, ri, args.tag, args.daily_token_budget)}")
                return
            t0 = time.time()
            try:
                rows, cache, transcript, tpd_hit = run_one(
                    sid, ri, args.tag, model_name, sklearn_version)
            except llm.DailyTokenBudgetExceeded:
                remaining = scenarios[i:]
                print(f"\nTOKENS-PER-DAY 429 from Groq. Stopping cleanly; this run was "
                      f"NOT written.\nResume after the daily reset with:\n  "
                      f"{_resume_cmd(remaining, ri, args.tag, args.daily_token_budget)}")
                return
            if tpd_hit:
                remaining = scenarios[i:]
                print(f"\nTOKENS-PER-DAY 429 hit mid-run ({sid} run{ri}); this run was "
                      f"degraded and NOT written.\nResume after the daily reset with:\n  "
                      f"{_resume_cmd(remaining, ri, args.tag, args.daily_token_budget)}")
                return

            _append_rows(rows)
            _write_cache(cache)
            _append_transcript(transcript)
            tokens_used += sum(r["prompt_tokens"] + r["completion_tokens"]
                               for r in rows if r["condition"] == "C4")
            c4 = next(r for r in rows if r["condition"] == "C4")
            flag = " EXCLUDED" if c4["llm_failed"] else ""
            print(f"{sid} run{ri}: C1={rows[0]['verdict']} C2=ATTACK "
                  f"C3={rows[2]['verdict']} C4={c4['verdict']}{flag}  "
                  f"[{time.time()-t0:.0f}s, ~{tokens_used} tok]")
            if args.sleep:
                time.sleep(args.sleep)

    print(f"\nDone. Rows in {RUNS_CSV}. Transcripts in {TRANSCRIPTS}.")


if __name__ == "__main__":
    main()
