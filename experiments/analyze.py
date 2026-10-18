#!/usr/bin/env python3
"""Analyze experiments/results/runs.csv and emit the paper's tables + figures.

Positive class = ATTACK. MISCONFIGURATION and UNCERTAIN both count as "not
attack". A run with llm_failed=True is EXCLUDED (all conditions), keeping the
paired comparisons on the same valid runs.

Point metrics are RUN-LEVEL; 95% CIs are a SCENARIO-cluster bootstrap (resample
scenarios, carry all their runs together; 10,000 draws, fixed seed). Paired
C4-vs-Cx differences use the same resamples. Paired significance uses an exact
McNemar test on SCENARIO-level correctness (majority verdict per scenario, tie
-> UNCERTAIN), Holm-corrected across the 3 comparisons. (The paper text
currently specifies per-run McNemar and 2000 resamples; this harness follows the
newer spec -- scenario-level McNemar, 10,000 draws -- and the divergence is noted
in summary.md.)

Outputs (experiments/results/): table_main.csv, table_pairwise.csv,
table_reliability.csv, table_errors.csv, table_by_scenario.csv, summary.md, and
fig1_metrics / fig2_confusion / fig3_by_scenario_type / fig4_debate_vs_fusion /
fig5_latency_calls / fig6_confidence (PNG, 300 dpi). table_ttp.csv only if every
attack scenario has a non-null attack_technique.

Usage:
    python experiments/analyze.py
    python experiments/analyze.py --selftest
"""
import argparse
import csv
import json
import math
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
RESULTS_DIR = REPO_ROOT / "experiments" / "results"
RAW_DIR = REPO_ROOT / "dataset" / "raw"
RUNS_CSV = RESULTS_DIR / "runs.csv"
TRANSCRIPTS = RESULTS_DIR / "transcripts.jsonl"

CONDITIONS = ["C1", "C2", "C3", "C4"]
# Supplementary condition: fusion after the bundle-based null gate. Reported
# separately; the primary Holm family stays C4 vs C1/C2/C3 (see
# supplementary_c3gate). Evidence-file suffixes used to resolve the gate.
C3_GATE = "C3+gate"
_LOG_SUFFIXES = ("_evidence.txt", "_firewall.log", "_evidence.log",
                 "_config.txt", "_firewall_rules.txt")
ATTACK, MIS, UNC = "ATTACK", "MISCONFIGURATION", "UNCERTAIN"
B_BOOTSTRAP = 10_000
SEED = 1234
# Okabe-Ito colour-blind-safe palette.
CB = ["#0072B2", "#E69F00", "#009E73", "#D55E00", "#CC79A7", "#56B4E9", "#F0E442"]


# ----------------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------------
def _to_bool(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def load_runs(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r["run_idx"] = int(r["run_idx"])
            r["llm_failed"] = _to_bool(r["llm_failed"])
            r["latency_s"] = _to_float(r.get("latency_s"))
            r["confidence"] = _to_float(r.get("confidence"))
            r["llm_calls"] = int(float(r.get("llm_calls") or 0))
            for k in ("retry_succeeded", "arbiter_fallback_used",
                      "json_fallback_used", "json_repaired", "evidence_present"):
                r[k] = _to_bool(r.get(k))
            rows.append(r)
    return rows


def valid_rows(rows):
    return [r for r in rows if not r["llm_failed"]]


# ----------------------------------------------------------------------------------
# Run-level metrics (operate on a list of rows for ONE condition)
# ----------------------------------------------------------------------------------
def _counts(rows):
    tp = fp = fn = tn = 0
    for r in rows:
        pred_attack = r["verdict"] == ATTACK
        truth_attack = r["ground_truth"] == ATTACK
        if pred_attack and truth_attack:
            tp += 1
        elif pred_attack and not truth_attack:
            fp += 1
        elif not pred_attack and truth_attack:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def m_disambiguation(rows):
    return np.mean([r["verdict"] == r["ground_truth"] for r in rows]) if rows else float("nan")


def m_fpr(rows):
    mis = [r for r in rows if r["ground_truth"] == MIS]
    return np.mean([r["verdict"] == ATTACK for r in mis]) if mis else float("nan")


def m_escalation(rows):
    return np.mean([r["verdict"] == UNC for r in rows]) if rows else float("nan")


def m_selective(rows):
    nn = [r for r in rows if r["verdict"] != UNC]
    return np.mean([r["verdict"] == r["ground_truth"] for r in nn]) if nn else float("nan")


def m_precision(rows):
    tp, fp, _, _ = _counts(rows)
    return tp / (tp + fp) if (tp + fp) else float("nan")


def m_recall(rows):
    tp, _, fn, _ = _counts(rows)
    return tp / (tp + fn) if (tp + fn) else float("nan")


def m_f1(rows):
    p, r = m_precision(rows), m_recall(rows)
    if math.isnan(p) or math.isnan(r) or (p + r) == 0:
        return float("nan")
    return 2 * p * r / (p + r)


def m_latency(rows):
    vals = [r["latency_s"] for r in rows if not math.isnan(r["latency_s"])]
    return float(np.mean(vals)) if vals else float("nan")


METRICS = {
    "disambiguation_accuracy": m_disambiguation, "fpr": m_fpr,
    "escalation_rate": m_escalation, "selective_accuracy": m_selective,
    "precision": m_precision, "recall": m_recall, "f1": m_f1, "latency_s": m_latency,
}


# ----------------------------------------------------------------------------------
# Scenario-cluster bootstrap
# ----------------------------------------------------------------------------------
def _by_scenario(rows):
    g = defaultdict(list)
    for r in rows:
        g[r["scenario_id"]].append(r)
    return g


def bootstrap_ci(rows, metric_fn, b=B_BOOTSTRAP, seed=SEED):
    g = _by_scenario(rows)
    keys = list(g.keys())
    if not keys:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    n = len(keys)
    idx = np.arange(n)
    vals = []
    for _ in range(b):
        draw = rng.choice(idx, size=n, replace=True)
        sample = []
        for j in draw:
            sample.extend(g[keys[j]])
        v = metric_fn(sample)
        if not (isinstance(v, float) and math.isnan(v)):
            vals.append(v)
    if not vals:
        return (float("nan"), float("nan"))
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5)))


def observed_delta(rows_a, rows_b, metric_fn):
    """The point difference on the ORIGINAL data: metric(a) - metric(b).
    This is what table_pairwise reports; the bootstrap only supplies the CI.
    Returns exactly 0.0 when both sides have identical metric values."""
    va, vb = metric_fn(rows_a), metric_fn(rows_b)
    if (isinstance(va, float) and math.isnan(va)) or (isinstance(vb, float) and math.isnan(vb)):
        return float("nan")
    return va - vb


def paired_bootstrap_diff(rows_a, rows_b, metric_fn, b=B_BOOTSTRAP, seed=SEED):
    """CI of metric(rows_a) - metric(rows_b) over the SAME scenario resample.
    Only the (lo, hi) percentile bounds are used by callers; the mean is not a
    point estimate (use observed_delta for that)."""
    ga, gb = _by_scenario(rows_a), _by_scenario(rows_b)
    keys = sorted(set(ga) & set(gb))
    if not keys:
        return (float("nan"), float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    n = len(keys)
    idx = np.arange(n)
    diffs = []
    for _ in range(b):
        draw = rng.choice(idx, size=n, replace=True)
        sa, sb = [], []
        for j in draw:
            sa.extend(ga[keys[j]])
            sb.extend(gb[keys[j]])
        va, vb = metric_fn(sa), metric_fn(sb)
        if not (math.isnan(va) or math.isnan(vb)):
            diffs.append(va - vb)
    if not diffs:
        return (float("nan"), float("nan"), float("nan"))
    return (float(np.mean(diffs)), float(np.percentile(diffs, 2.5)),
            float(np.percentile(diffs, 97.5)))


# ----------------------------------------------------------------------------------
# Scenario-level correctness + exact McNemar + Holm
# ----------------------------------------------------------------------------------
def scenario_verdict(rows_for_condition_and_scenario):
    verdicts = [r["verdict"] for r in rows_for_condition_and_scenario]
    if not verdicts:
        return None
    counts = Counter(verdicts)
    top = counts.most_common()
    if len(top) > 1 and top[0][1] == top[1][1]:
        return UNC  # tie -> UNCERTAIN
    return top[0][0]


def scenario_correct(rows, condition):
    cond_rows = [r for r in rows if r["condition"] == condition]
    g = _by_scenario(cond_rows)
    out = {}
    for sid, rs in g.items():
        v = scenario_verdict(rs)
        out[sid] = (v == rs[0]["ground_truth"])
    return out


def exact_mcnemar(correct_a, correct_b):
    """b = A right & B wrong; c = A wrong & B right. Exact two-sided binomial."""
    from scipy.stats import binomtest
    keys = sorted(set(correct_a) & set(correct_b))
    b = sum(1 for k in keys if correct_a[k] and not correct_b[k])
    c = sum(1 for k in keys if not correct_a[k] and correct_b[k])
    n = b + c
    p = 1.0 if n == 0 else binomtest(min(b, c), n, 0.5, alternative="two-sided").pvalue
    return b, c, float(p)


def holm(pvals):
    """Holm-Bonferroni adjusted p-values, preserving input order."""
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    m = len(pvals)
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        val = (m - rank) * pvals[i]
        running = max(running, val)
        adj[i] = min(1.0, running)
    return adj


# ----------------------------------------------------------------------------------
# Report builder
# ----------------------------------------------------------------------------------
def fmt(x, nd=3):
    return "nan" if (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def _scenario_null_gate(scenarios, raw_dir):
    """Per-scenario bundle-based null gate: True when the scenario's evidence
    bundle holds NO configuration artifact (so the misconfiguration side is
    null). Deterministic, reads only the evidence file -- no LLM."""
    from agents import grounding
    gate = {}
    for sid in scenarios:
        raw = ""
        for suf in _LOG_SUFFIXES:
            p = Path(raw_dir) / f"{sid}{suf}"
            if p.exists():
                raw = p.read_text(encoding="utf-8", errors="replace")
                break
        bundle = {"log_evidence": {"raw_log_excerpt": raw}}
        gate[sid] = not grounding.bundle_has_config_artifact(bundle)
    return gate


def _c3gate_rows(cond_rows, gate):
    """Derive C3+gate rows from the C3 rows: verdict becomes ATTACK when the
    scenario's misconfiguration side is null-gated, else it stays the C3
    verdict. Same upstream, no extra LLM calls."""
    out = []
    for r in cond_rows["C3"]:
        rr = dict(r)
        rr["condition"] = C3_GATE
        if gate.get(r["scenario_id"]):
            rr["verdict"] = ATTACK
        out.append(rr)
    return out


def supplementary_c3gate(rows, cond_rows, sc_correct, raw_p_primary,
                         scenarios, out_dir, raw_dir):
    """Compute and write the C3+gate supplementary condition and the extra
    pre-declared C4-vs-C3+gate test.

    Returns a list of summary lines. The primary Holm family (C4 vs C1/C2/C3)
    is passed in as ``raw_p_primary`` and is NOT modified; this adds the extra
    test and a clearly-separate Holm correction over all four tests.
    """
    gate = _scenario_null_gate(scenarios, raw_dir)
    c3g_rows = _c3gate_rows(cond_rows, gate)
    rows_plus = rows + c3g_rows

    disamb = m_disambiguation(c3g_rows)
    d_lo, d_hi = bootstrap_ci(c3g_rows, m_disambiguation)
    fpr = m_fpr(c3g_rows)
    f_lo, f_hi = bootstrap_ci(c3g_rows, m_fpr)
    esc = m_escalation(c3g_rows)

    sc_c3g = scenario_correct(rows_plus, C3_GATE)
    # extra pre-declared test: C4 vs C3+gate
    bb, cc, p_extra = exact_mcnemar(sc_correct["C4"], sc_c3g)
    d_acc = observed_delta(cond_rows["C4"], c3g_rows, m_disambiguation)
    _, lo_acc, hi_acc = paired_bootstrap_diff(cond_rows["C4"], c3g_rows, m_disambiguation)

    holm_primary = holm(list(raw_p_primary))                 # 3 tests, unchanged
    holm_all4 = holm(list(raw_p_primary) + [p_extra])        # 4 tests, labelled

    # ---- table_c3gate.csv ----
    with open(out_dir / "table_c3gate.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "key", "value"])
        w.writerow(["metric", "disambiguation_accuracy", fmt(disamb)])
        w.writerow(["metric", "disambiguation_ci_lo", fmt(d_lo)])
        w.writerow(["metric", "disambiguation_ci_hi", fmt(d_hi)])
        w.writerow(["metric", "fpr", fmt(fpr)])
        w.writerow(["metric", "fpr_ci_lo", fmt(f_lo)])
        w.writerow(["metric", "fpr_ci_hi", fmt(f_hi)])
        w.writerow(["metric", "escalation_rate", fmt(esc)])
        w.writerow(["metric", "n_scenarios_null_gated",
                    str(sum(1 for v in gate.values() if v))])
        w.writerow(["extra_test", "comparison", "C4_vs_C3+gate"])
        w.writerow(["extra_test", "delta_disambig_acc", fmt(d_acc)])
        w.writerow(["extra_test", "acc_ci_lo", fmt(lo_acc)])
        w.writerow(["extra_test", "acc_ci_hi", fmt(hi_acc)])
        w.writerow(["extra_test", "mcnemar_b", str(bb)])
        w.writerow(["extra_test", "mcnemar_c", str(cc)])
        w.writerow(["extra_test", "mcnemar_p", fmt(p_extra, 4)])
        w.writerow(["extra_test", "holm_p_over_4_tests", fmt(holm_all4[-1], 4)])
        for (a, b), hp3, hp4 in zip([("C4", "C1"), ("C4", "C2"), ("C4", "C3")],
                                    holm_primary, holm_all4[:3]):
            w.writerow(["holm", f"{a}_vs_{b}_holm_primary3", fmt(hp3, 4)])
            w.writerow(["holm", f"{a}_vs_{b}_holm_all4", fmt(hp4, 4)])

    # ---- summary lines ----
    L = ["", "## Supplementary condition: C3+gate (fusion after the bundle-based "
         "null gate)",
         "",
         "C3+gate applies the same fusion rule as C3 (higher prior confidence "
         "wins, tie -> ATTACK) but first applies the bundle-based null gate: if "
         "the misconfiguration side is null (the evidence bundle holds no "
         "configuration artifact) the verdict is ATTACK. Computed from cached "
         "upstream outputs only, no LLM calls.",
         "",
         f"- scenarios null-gated (-> ATTACK): "
         f"{sum(1 for v in gate.values() if v)} of {len(scenarios)}",
         f"- disambiguation accuracy = {fmt(disamb)} [95% CI {fmt(d_lo)}, {fmt(d_hi)}]",
         f"- false-positive rate = {fmt(fpr)} [95% CI {fmt(f_lo)}, {fmt(f_hi)}]",
         f"- escalation rate = {fmt(esc)}",
         "",
         "Primary Holm family is UNCHANGED (C4 vs C1/C2/C3, 3 tests). The "
         "C4-vs-C3+gate test below is a separate, pre-declared extra test.",
         "",
         f"- EXTRA TEST C4 vs C3+gate: delta disambiguation acc = {fmt(d_acc)} "
         f"[95% CI {fmt(lo_acc)}, {fmt(hi_acc)}], McNemar b={bb} c={cc} "
         f"p={fmt(p_extra, 4)}, Holm-over-4 adjusted p={fmt(holm_all4[-1], 4)}",
         "",
         "Holm-adjusted p-values, primary(3) vs all-four, clearly labelled:"]
    for (a, b), hp3, hp4 in zip([("C4", "C1"), ("C4", "C2"), ("C4", "C3")],
                                holm_primary, holm_all4[:3]):
        L.append(f"  - {a} vs {b}: Holm/primary-3 = {fmt(hp3, 4)}; "
                 f"Holm/all-4 = {fmt(hp4, 4)}")
    L.append(f"  - C4 vs C3+gate: Holm/all-4 = {fmt(holm_all4[-1], 4)} "
             f"(not in the primary family)")
    return L


def build_report(rows, out_dir, raw_dir=RAW_DIR, transcripts=TRANSCRIPTS,
                 make_figures=True, label=""):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    allrows = rows
    rows = valid_rows(rows)
    warnings = []
    cond_rows = {c: [r for r in rows if r["condition"] == c] for c in CONDITIONS}

    scenarios = sorted({r["scenario_id"] for r in rows})
    truths = {r["scenario_id"]: r["ground_truth"] for r in rows}
    n_attack = sum(1 for s in scenarios if truths[s] == ATTACK)
    n_mis = sum(1 for s in scenarios if truths[s] == MIS)
    if n_attack == 0 or n_mis == 0:
        warnings.append(f"Benchmark contains only ONE ground-truth class "
                        f"(attack={n_attack}, misconfig={n_mis}); attack-detection "
                        f"metrics (precision/recall/F1/FPR) are not meaningful.")

    # verdict distribution + single-class-prediction warning
    dist = {}
    for c in CONDITIONS:
        d = Counter(r["verdict"] for r in cond_rows[c])
        dist[c] = d
        if cond_rows[c] and len(d) == 1:
            warnings.append(f"Condition {c} predicted a SINGLE verdict "
                            f"({next(iter(d))}) for the whole benchmark.")

    # ---- table_main ----
    main_path = out_dir / "table_main.csv"
    with open(main_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric"] + [f"{c}_mean" for c in CONDITIONS]
                   + [f"{c}_ci_lo" for c in CONDITIONS] + [f"{c}_ci_hi" for c in CONDITIONS]
                   + ["n_runs_" + c for c in CONDITIONS])
        for mname, mfn in METRICS.items():
            means, los, his, ns = [], [], [], []
            for c in CONDITIONS:
                means.append(mfn(cond_rows[c]))
                lo, hi = bootstrap_ci(cond_rows[c], mfn)
                los.append(lo)
                his.append(hi)
                ns.append(len(cond_rows[c]))
            w.writerow([mname] + [fmt(x) for x in means] + [fmt(x) for x in los]
                       + [fmt(x) for x in his] + ns)

    # ---- table_pairwise ----
    sc_correct = {c: scenario_correct(rows, c) for c in CONDITIONS}
    pw_path = out_dir / "table_pairwise.csv"
    comparisons = [("C4", "C1"), ("C4", "C2"), ("C4", "C3")]
    raw_p = []
    pw_rows = []
    for a, b in comparisons:
        # Point estimate = observed difference on the original data; bootstrap
        # supplies only the percentile CI bounds.
        d_acc = observed_delta(cond_rows[a], cond_rows[b], m_disambiguation)
        _, lo_acc, hi_acc = paired_bootstrap_diff(cond_rows[a], cond_rows[b], m_disambiguation)
        d_fpr = observed_delta(cond_rows[a], cond_rows[b], m_fpr)
        _, lo_fpr, hi_fpr = paired_bootstrap_diff(cond_rows[a], cond_rows[b], m_fpr)
        bb, cc, p = exact_mcnemar(sc_correct[a], sc_correct[b])
        raw_p.append(p)
        pw_rows.append([a, b, d_acc, lo_acc, hi_acc, d_fpr, lo_fpr, hi_fpr, bb, cc, p])
    adj = holm(raw_p)
    with open(pw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["comparison", "delta_disambig_acc", "acc_ci_lo", "acc_ci_hi",
                    "delta_fpr", "fpr_ci_lo", "fpr_ci_hi", "mcnemar_b", "mcnemar_c",
                    "mcnemar_p", "holm_p"])
        for row, ap in zip(pw_rows, adj):
            a, b, dacc, lacc, hacc, dfpr, lfpr, hfpr, bb, cc, p = row
            w.writerow([f"{a}_vs_{b}", fmt(dacc), fmt(lacc), fmt(hacc), fmt(dfpr),
                        fmt(lfpr), fmt(hfpr), bb, cc, fmt(p, 4), fmt(ap, 4)])

    # ---- table_reliability ----
    rel_path = out_dir / "table_reliability.csv"
    runkeys = {(r["scenario_id"], r["run_idx"]) for r in allrows}
    # per-run flags from C4 rows (flags are run-level, identical across conditions)
    c4_all = [r for r in allrows if r["condition"] == "C4"]
    n_runs = len(runkeys)
    n_excluded = sum(1 for r in c4_all if r["llm_failed"])
    n_retry = sum(1 for r in c4_all if r["retry_succeeded"])
    n_arb_fb = sum(1 for r in c4_all if r["arbiter_fallback_used"])
    n_jsonrep = sum(1 for r in c4_all if r["json_repaired"])
    n_hypfail = sum(1 for r in c4_all
                    if ("threat" in (r["failed_agents"] or "")
                        or "troubleshooting" in (r["failed_agents"] or "")))
    n_unc = sum(1 for r in cond_rows["C4"] if r["verdict"] == UNC)
    with open(rel_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "count", "of_total_runs"])
        for name, val in [("total_runs", n_runs),
                          ("runs_failed_then_retried_ok", n_retry),
                          ("runs_decided_by_arbiter_fallback", n_arb_fb),
                          ("runs_json_repaired", n_jsonrep),
                          ("runs_hypothesis_agent_failed", n_hypfail),
                          ("runs_excluded_total", n_excluded),
                          ("C4_uncertain_verdicts", n_unc)]:
            w.writerow([name, val, n_runs])

    # ---- table_errors (verbatim C4 adjudicator rationale from transcripts) ----
    rationale = {}
    if Path(transcripts).exists():
        with open(transcripts, encoding="utf-8") as f:
            for line in f:
                try:
                    t = json.loads(line)
                except ValueError:
                    continue
                rationale[(t["scenario_id"], t["run_idx"])] = \
                    (t.get("arbiter_verdict") or {}).get("reasoning", "")
    err_path = out_dir / "table_errors.csv"
    with open(err_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scenario_id", "ground_truth", "C4_scenario_verdict",
                    "example_run_idx", "adjudicator_rationale_verbatim"])
        for sid in scenarios:
            sv = scenario_verdict([r for r in cond_rows["C4"] if r["scenario_id"] == sid])
            if sv is not None and sv != truths[sid]:
                ex = next((r for r in cond_rows["C4"] if r["scenario_id"] == sid), None)
                ri = ex["run_idx"] if ex else ""
                w.writerow([sid, truths[sid], sv, ri, rationale.get((sid, ri), "")])

    # ---- table_by_scenario ----
    bysc_path = out_dir / "table_by_scenario.csv"
    with open(bysc_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scenario_id", "family", "ground_truth", "condition",
                    "valid_runs", "verdict_counts", "scenario_verdict", "agreement"])
        fam = {r["scenario_id"]: r["family"] for r in rows}
        for sid in scenarios:
            for c in CONDITIONS:
                rs = [r for r in cond_rows[c] if r["scenario_id"] == sid]
                cnt = Counter(r["verdict"] for r in rs)
                sv = scenario_verdict(rs)
                agree = (max(cnt.values()) / sum(cnt.values())) if cnt else float("nan")
                w.writerow([sid, fam.get(sid), truths[sid], c, len(rs),
                            dict(cnt), sv, fmt(agree)])

    # ---- table_ttp (only if every attack scenario has a technique) ----
    ttp_note = ""
    attack_scen = [s for s in scenarios if truths[s] == ATTACK]
    gt_tech = {}
    for s in attack_scen:
        meta = {}
        mp = Path(raw_dir) / f"{s}_metadata.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except ValueError:
                pass
        gt_tech[s] = meta.get("attack_technique")
    # Mapped subset = attack scenarios whose ground-truth attack_technique is
    # non-null. ATT&CK accuracy is computed over THIS subset only -- never all
    # attacks, never misconfig scenarios. Null-technique attacks are excluded
    # (not counted wrong). The denominators (mapped scenarios and mapped
    # scenario-runs) are printed as explicit columns.
    mapped = [s for s in attack_scen if gt_tech[s]]
    mapped_runs = sum(len([r for r in cond_rows["C4"] if r["scenario_id"] == s]) for s in mapped)
    if mapped:
        ttp_path = out_dir / "table_ttp.csv"
        correct_total = 0
        with open(ttp_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["scenario_id", "gt_technique", "C4_predicted_mitre", "n_runs",
                        "n_correct_runs", "match", "mapped_scenarios_total",
                        "mapped_runs_total"])
            for s in mapped:
                rs = [r for r in cond_rows["C4"] if r["scenario_id"] == s]
                n_correct = sum(1 for r in rs if r["mitre_technique"] == gt_tech[s])
                correct_total += n_correct
                preds = [r["mitre_technique"] for r in rs if r["verdict"] == ATTACK]
                pred = Counter(preds).most_common(1)[0][0] if preds else None
                w.writerow([s, gt_tech[s], pred, len(rs), n_correct, pred == gt_tech[s],
                            len(mapped), mapped_runs])
        acc = correct_total / mapped_runs if mapped_runs else float("nan")
        ttp_note = (f"table_ttp.csv over the MAPPED subset only: {len(mapped)}/"
                    f"{len(attack_scen)} attack scenarios have a technique "
                    f"({mapped_runs} mapped runs); technique accuracy (runs) = {fmt(acc)}. "
                    f"Null-technique attacks excluded, not counted wrong.")
    else:
        ttp_note = (f"table_ttp.csv SKIPPED: 0/{len(attack_scen)} attack scenarios have a "
                    f"non-null attack_technique.")

    # ---- C1 ROC-AUC supplement (threshold-free; NOT a decision rule) ----
    auc_line = ""
    c1_scores = {}
    for r in cond_rows["C1"]:
        c1_scores.setdefault(r["scenario_id"], []).append(r["confidence"])
    if n_attack and n_mis:
        sids = [s for s in scenarios if s in c1_scores]
        y = np.array([1 if truths[s] == ATTACK else 0 for s in sids])
        score = np.array([np.nanmean(c1_scores[s]) for s in sids])
        if len(set(y.tolist())) == 2 and not np.any(np.isnan(score)):
            from sklearn.metrics import roc_auc_score
            auc = roc_auc_score(y, score)
            rng = np.random.default_rng(SEED)
            boots = []
            idx = np.arange(len(sids))
            for _ in range(B_BOOTSTRAP):
                d = rng.choice(idx, size=len(sids), replace=True)
                if len(set(y[d].tolist())) < 2:
                    continue
                boots.append(roc_auc_score(y[d], score[d]))
            lo, hi = (float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))) \
                if boots else (float("nan"), float("nan"))
            auc_line = (f"C1 scenario-level ROC-AUC of attack_probability "
                        f"(ATTACK vs MISCONFIG) = {auc:.3f} [95% CI {lo:.3f}, {hi:.3f}]. "
                        f"THRESHOLD-FREE separability, NOT a decision rule; the headline "
                        f"C1 row uses threshold {0.5}.")

    # ---- figures ----
    figs_written = []
    if make_figures:
        figs_written = _make_figures(out_dir, cond_rows, scenarios, truths, dist)

    # ---- C3+gate supplementary condition + extra pre-declared test ----
    c3gate_lines = supplementary_c3gate(rows, cond_rows, sc_correct, raw_p,
                                        scenarios, out_dir, raw_dir)

    # ---- summary.md ----
    _write_summary(out_dir, label, scenarios, n_attack, n_mis, cond_rows, dist,
                   warnings, ttp_note, auc_line, figs_written)
    # append the C3+gate supplementary block
    with open(out_dir / "summary.md", "a", encoding="utf-8") as f:
        f.write("\n".join(c3gate_lines) + "\n")
    return {"warnings": warnings, "ttp_note": ttp_note, "auc": auc_line,
            "tables": [p.name for p in out_dir.glob("table_*.csv")]}


def _make_figures(out_dir, cond_rows, scenarios, truths, dist):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    written = []

    def save(fig, name):
        fig.savefig(out_dir / f"{name}.png", dpi=300, bbox_inches="tight")
        fig.savefig(out_dir / f"{name}.pdf", bbox_inches="tight")  # vector copy
        plt.close(fig)
        written.append(name)

    ns = {c: len(cond_rows[c]) for c in CONDITIONS}
    labels = [f"{c}\n(n={ns[c]})" for c in CONDITIONS]

    # fig1: FPR, disambiguation accuracy, coverage. CIs only when >=5 scenarios;
    # otherwise bars with no error bars and a "CI omitted" subtitle.
    n_scen = len(scenarios)
    show_ci = n_scen >= 5
    fig, ax = plt.subplots(figsize=(7.5, 4))
    metricset = [("disambiguation_accuracy", m_disambiguation),
                 ("fpr", m_fpr), ("coverage", lambda rs: 1 - m_escalation(rs))]
    x = np.arange(len(CONDITIONS))
    width = 0.26
    for k, (mname, mfn) in enumerate(metricset):
        means = [mfn(cond_rows[c]) for c in CONDITIONS]
        heights = [0 if math.isnan(m) else m for m in means]
        yerr = None
        if show_ci:
            cis = [bootstrap_ci(cond_rows[c], mfn) for c in CONDITIONS]
            lo_e = [0 if math.isnan(m) else max(0, m - lo) for m, (lo, _h) in zip(means, cis)]
            hi_e = [0 if math.isnan(m) else max(0, h - m) for m, (_l, h) in zip(means, cis)]
            yerr = np.array([lo_e, hi_e])
        ax.bar(x + (k - 1) * width, heights, width, label=mname, color=CB[k],
               yerr=yerr, capsize=3, error_kw=dict(ecolor="#666666", elinewidth=1.0))
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1)
    ax.set_ylabel("rate")
    subtitle = "95% scenario-bootstrap CI" if show_ci else f"n={n_scen} scenarios, CI omitted"
    ax.set_title(f"Metrics by condition ({subtitle})")
    ax.legend(fontsize=8, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
    save(fig, "fig1_metrics")

    # fig2: confusion per condition (truth rows x pred cols)
    preds = [ATTACK, MIS, UNC]
    rowsT = [ATTACK, MIS]
    fig, axes = plt.subplots(1, 4, figsize=(14, 3.2))
    for ax, c in zip(axes, CONDITIONS):
        M = np.zeros((2, 3), dtype=int)
        for r in cond_rows[c]:
            if r["ground_truth"] in rowsT:
                M[rowsT.index(r["ground_truth"]), preds.index(r["verdict"])] += 1
        im = ax.imshow(M, cmap="Blues")
        ax.set_xticks(range(3))
        ax.set_xticklabels(["ATT", "MIS", "UNC"])
        ax.set_yticks(range(2))
        ax.set_yticklabels(["ATT", "MIS"])
        ax.set_title(f"{c} (n={ns[c]})")
        for i in range(2):
            for j in range(3):
                ax.text(j, i, str(M[i, j]), ha="center", va="center",
                        color="black", fontsize=9)
    fig.suptitle("Confusion per condition (rows=truth, cols=verdict)")
    save(fig, "fig2_confusion")

    # fig3: accuracy by family x condition
    fams = sorted({r["family"] for c in CONDITIONS for r in cond_rows[c] if r["family"]})
    fig, ax = plt.subplots(figsize=(max(7, len(fams) * 1.1), 4))
    x = np.arange(len(fams))
    width = 0.2
    for k, c in enumerate(CONDITIONS):
        accs, famn = [], []
        for fm in fams:
            rs = [r for r in cond_rows[c] if r["family"] == fm]
            accs.append(m_disambiguation(rs) if rs else 0)
            famn.append(len({r["scenario_id"] for r in rs}))
        ax.bar(x + (k - 1.5) * width, accs, width, label=c, color=CB[k])
    ax.set_xticks(x)
    ax.set_xticklabels([f"{fm}\n(n={len({r['scenario_id'] for r in cond_rows['C4'] if r['family']==fm})})"
                        for fm in fams], rotation=40, ha="right", fontsize=7)
    ax.set_ylim(0, 1)
    ax.set_ylabel("disambiguation accuracy")
    ax.set_title("Accuracy by scenario family and condition")
    ax.legend(fontsize=8, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
    save(fig, "fig3_by_scenario_type")

    # fig4: paired C4 vs C3 scenario outcomes
    sc4 = scenario_correct([r for c in ["C4"] for r in cond_rows[c]], "C4")
    sc3 = scenario_correct([r for c in ["C3"] for r in cond_rows[c]], "C3")
    keys = sorted(set(sc4) & set(sc3))
    both = sum(1 for k in keys if sc4[k] and sc3[k])
    only4 = sum(1 for k in keys if sc4[k] and not sc3[k])
    only3 = sum(1 for k in keys if not sc4[k] and sc3[k])
    neither = sum(1 for k in keys if not sc4[k] and not sc3[k])
    fig, ax = plt.subplots(figsize=(6, 4))
    cats = ["both correct", "only C4", "only C3", "neither"]
    vals = [both, only4, only3, neither]
    ax.bar(cats, vals, color=[CB[2], CB[0], CB[1], CB[3]])
    for i, v in enumerate(vals):
        ax.text(i, v, str(v), ha="center", va="bottom")
    ax.set_ylabel(f"scenarios (n={len(keys)})")
    ax.set_title("Debate (C4) vs rule-based fusion (C3), scenario-level")
    save(fig, "fig4_debate_vs_fusion")

    # fig5: (a) mean seconds by agent  (b) mean LLM calls per condition
    fig, (axa, axb) = plt.subplots(1, 2, figsize=(11, 4))

    def mean_lat(c):
        v = [r["latency_s"] for r in cond_rows[c] if not math.isnan(r["latency_s"])]
        return float(np.mean(v)) if v else 0.0
    lat = {c: mean_lat(c) for c in CONDITIONS}
    agent_times = [lat["C1"], max(0, lat["C2"] - lat["C1"]),
                   max(0, lat["C3"] - lat["C2"]), max(0, lat["C4"] - lat["C3"])]
    agent_lbls = ["packet+intrusion", "threat", "troubleshooting", "arbiter"]
    axa.bar(agent_lbls, agent_times, color=CB[:4])
    axa.set_ylabel("mean seconds")
    axa.set_title("Mean latency by agent (derived from condition deltas)")
    axa.tick_params(axis="x", rotation=25)
    calls = [np.mean([r["llm_calls"] for r in cond_rows[c]]) if cond_rows[c] else 0
             for c in CONDITIONS]
    axb.bar(labels, calls, color=CB[:4])
    axb.set_ylabel("mean LLM calls")
    axb.set_title("Mean LLM calls per condition")
    save(fig, "fig5_latency_calls")

    # fig6: C4 accuracy by arbiter confidence bin
    bins = [0, 0.2, 0.4, 0.6, 0.8, 1.01]
    binlbl = ["0-.2", ".2-.4", ".4-.6", ".6-.8", ".8-1"]
    acc, cnt = [], []
    for i in range(len(bins) - 1):
        rs = [r for r in cond_rows["C4"]
              if not math.isnan(r["confidence"]) and bins[i] <= r["confidence"] < bins[i + 1]]
        cnt.append(len(rs))
        acc.append(m_disambiguation(rs) if rs else 0)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(binlbl, acc, color=CB[0])
    for i, (a, n) in enumerate(zip(acc, cnt)):
        ax.text(i, a, f"n={n}", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, 1)
    ax.set_xlabel("arbiter confidence")
    ax.set_ylabel("C4 disambiguation accuracy")
    ax.set_title("C4 accuracy by confidence bin")
    save(fig, "fig6_confidence")
    return written


def _write_summary(out_dir, label, scenarios, n_attack, n_mis, cond_rows, dist,
                   warnings, ttp_note, auc_line, figs):
    lines = ["# NetDefend-Bench evaluation summary"]
    if label:
        lines.append(f"\n**{label}**")
    lines.append(f"\nScenarios (valid): {len(scenarios)} "
                 f"(ATTACK={n_attack}, MISCONFIGURATION={n_mis}).")
    lines.append("\n## Verdict distribution per condition (sanity)")
    for c in CONDITIONS:
        lines.append(f"- {c} (n={len(cond_rows[c])}): {dict(dist[c])}")
    lines.append("\n## Headline (run-level)")
    for c in CONDITIONS:
        lines.append(f"- {c}: disambiguation={fmt(m_disambiguation(cond_rows[c]))}, "
                     f"FPR={fmt(m_fpr(cond_rows[c]))}, "
                     f"escalation={fmt(m_escalation(cond_rows[c]))}, "
                     f"recall={fmt(m_recall(cond_rows[c]))}, "
                     f"precision={fmt(m_precision(cond_rows[c]))}, F1={fmt(m_f1(cond_rows[c]))}")
    if auc_line:
        lines.append(f"\n## C1 threshold-free supplement\n{auc_line}")
    lines.append(f"\n## ATT&CK mapping\n{ttp_note}")
    if warnings:
        lines.append("\n## WARNINGS")
        for wmsg in warnings:
            lines.append(f"- {wmsg}")
    lines.append("\n## Method notes")
    lines.append("- Positive class = ATTACK; MISCONFIGURATION and UNCERTAIN both "
                 "count as not-attack. A run with llm_failed=True is excluded for all "
                 "conditions (paired).")
    lines.append("- CIs: 95% percentile, scenario-cluster bootstrap, "
                 f"{B_BOOTSTRAP} draws, seed {SEED}. Paired C4-vs-Cx diffs use the same draws.")
    lines.append("- Significance: exact McNemar on SCENARIO-level correctness "
                 "(majority verdict, tie->UNCERTAIN), Holm across the 3 comparisons.")
    lines.append("- PAPER DIVERGENCE: paper/netdefend.tex §Evaluation specifies per-RUN "
                 "McNemar and 2000 bootstrap resamples, and leaves the C3 fusion rule as a "
                 "TODO. This harness uses scenario-level McNemar, 10,000 draws, and the "
                 "fusion rule 'higher prior confidence wins, tie->ATTACK'. Update the paper "
                 "text to match.")
    lines.append(f"\n## Figures\n{', '.join(figs) if figs else '(none)'}")
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ----------------------------------------------------------------------------------
# Self-test (synthetic, writes nothing to real results)
# ----------------------------------------------------------------------------------
def selftest():
    print("=== analyze.py --selftest (SYNTHETIC DATA; nothing written to results) ===")
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    def mk(sid, truth, cond, verdict, run=0, fam="fam", conf=0.5, lat=1.0,
           failed=False, mitre=None):
        return {"scenario_id": sid, "ground_truth": truth, "condition": cond,
                "verdict": verdict, "run_idx": run, "family": fam, "confidence": conf,
                "latency_s": lat, "llm_calls": 1, "mitre_technique": mitre,
                "llm_failed": failed, "failed_agents": "", "retry_succeeded": False,
                "arbiter_fallback_used": False, "json_fallback_used": False,
                "json_repaired": False, "evidence_present": True}

    # 5 scenarios, condition X, hand-computable metrics
    X = [
        mk("A1", ATTACK, "X", ATTACK), mk("A2", ATTACK, "X", ATTACK),
        mk("A3", ATTACK, "X", MIS), mk("M1", MIS, "X", MIS), mk("M2", MIS, "X", ATTACK),
    ]
    check("disambiguation 3/5=0.6", abs(m_disambiguation(X) - 0.6) < 1e-9)
    check("FPR 1/2=0.5", abs(m_fpr(X) - 0.5) < 1e-9)
    check("recall 2/3", abs(m_recall(X) - 2 / 3) < 1e-9)
    check("precision 2/3", abs(m_precision(X) - 2 / 3) < 1e-9)
    check("f1 2/3", abs(m_f1(X) - 2 / 3) < 1e-9)
    check("escalation 0", m_escalation(X) == 0.0)
    check("selective 0.6", abs(m_selective(X) - 0.6) < 1e-9)

    # observed_delta is the point estimate on original data, NOT the bootstrap
    # mean: identical per-scenario verdicts -> delta exactly 0.0
    Y = [mk(r["scenario_id"], r["ground_truth"], "Y", r["verdict"]) for r in X]
    check("observed_delta == 0.0 for identical conditions",
          observed_delta(X, Y, m_disambiguation) == 0.0)

    # UNCERTAIN handling
    U = [mk("A1", ATTACK, "X", ATTACK), mk("A2", ATTACK, "X", UNC),
         mk("M1", MIS, "X", MIS)]
    check("UNC counts wrong: disambig 2/3", abs(m_disambiguation(U) - 2 / 3) < 1e-9)
    check("UNC escalation 1/3", abs(m_escalation(U) - 1 / 3) < 1e-9)
    check("UNC selective 2/2=1.0", abs(m_selective(U) - 1.0) < 1e-9)

    # exact McNemar: b=1, c=2 -> two-sided exact p = 1.0
    ca = {"A1": True, "A2": True, "A3": False, "M1": True, "M2": False}
    cb = {"A1": True, "A2": False, "A3": True, "M1": True, "M2": True}
    b, c, p = exact_mcnemar(ca, cb)
    check("McNemar b=1", b == 1)
    check("McNemar c=2", c == 2)
    check("McNemar exact p=1.0", abs(p - 1.0) < 1e-9)
    # b=4,c=0 -> p = 2*0.5^4 = 0.125
    ca2 = {f"s{i}": True for i in range(4)}
    cb2 = {f"s{i}": False for i in range(4)}
    b2, c2, p2 = exact_mcnemar(ca2, cb2)
    check("McNemar b=4,c=0", (b2, c2) == (4, 0))
    check("McNemar p=0.125", abs(p2 - 0.125) < 1e-9)

    # Holm
    adj = holm([0.01, 0.04, 0.03])
    check("Holm[0]=0.03", abs(adj[0] - 0.03) < 1e-9)
    check("Holm monotone & <=1", all(0 <= a <= 1 for a in adj))

    # bootstrap: point estimate equals full-sample; CI brackets it
    lo, hi = bootstrap_ci(X, m_disambiguation, b=2000, seed=1)
    check("bootstrap CI brackets 0.6", lo <= 0.6 <= hi and 0 <= lo <= hi <= 1)

    # full report into a temp dir; assert nothing lands in real results
    before = set(p.name for p in RESULTS_DIR.glob("*")) if RESULTS_DIR.exists() else set()
    with tempfile.TemporaryDirectory() as td:
        raw = Path(td)
        # mix of mapped (A1=T1046, A2=T1018) and null-technique (A3) attacks,
        # plus misconfigs -- the ttp denominator must be the mapped subset only.
        meta_map = {"A1": ("T1046", ATTACK), "A2": ("T1018", ATTACK),
                    "A3": (None, ATTACK), "M1": (None, MIS), "M2": (None, MIS)}
        for sid, (tech, gt) in meta_map.items():
            (raw / f"{sid}_metadata.json").write_text(
                json.dumps({"ground_truth": gt, "attack_technique": tech, "family": "synfam"}),
                encoding="utf-8")
        syn = []
        for r in X:
            for c in CONDITIONS:
                syn.append(mk(r["scenario_id"], r["ground_truth"], c, r["verdict"],
                              fam="synfam"))
        build_report(syn, raw / "SYNTHETIC_results", raw_dir=raw,
                     transcripts=raw / "none.jsonl", make_figures=True,
                     label="SYNTHETIC SELFTEST OUTPUT — DO NOT USE")
        syn_out = raw / "SYNTHETIC_results"
        produced = list(syn_out.glob("*"))
        check("report produced tables+figs in temp", len(produced) >= 6)
        ttp_rows = list(csv.DictReader(open(syn_out / "table_ttp.csv", encoding="utf-8")))
        check("ttp denominator = mapped subset only (A1,A2; A3/misconfig excluded)",
              sorted(r["scenario_id"] for r in ttp_rows) == ["A1", "A2"])
        check("ttp mapped_scenarios_total == 2",
              all(int(r["mapped_scenarios_total"]) == 2 for r in ttp_rows))
        check("ttp mapped_runs_total == 2",
              all(int(r["mapped_runs_total"]) == 2 for r in ttp_rows))
    after = set(p.name for p in RESULTS_DIR.glob("*")) if RESULTS_DIR.exists() else set()
    check("nothing written to real results/", before == after)

    print(f"\n=== SELFTEST {'PASSED' if ok else 'FAILED'} ===")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs-csv", default=str(RUNS_CSV))
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--split", action="store_true",
                    help="(reserved) dev/test split; OFF by default, not implemented")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if not Path(args.runs_csv).exists():
        sys.exit(f"no runs.csv at {args.runs_csv} -- run run_scenarios.py first")
    rows = load_runs(args.runs_csv)
    info = build_report(rows, RESULTS_DIR)
    print("Wrote:", ", ".join(sorted(info["tables"])), "+ summary.md + fig1..6")
    print(info["ttp_note"])
    if info["auc"]:
        print(info["auc"])
    for w in info["warnings"]:
        print("WARNING:", w)


if __name__ == "__main__":
    main()
