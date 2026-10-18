"""Replay the cached v1 troubleshooting + threat hypotheses through the v2
post-processing ONLY (grounding validator + null rule). No LLM calls, no
writes to the v1 cache -- read-only analysis.

For each scenario in experiments/cache it reconstructs the incident evidence
bundle the Troubleshooting Agent would have built (from the cached packet
features / cross-flow / ML prediction plus the scenario's evidence file),
infers the categorical hypothesis the v1 agent produced, and runs exactly the
v2 post-processing on the cached hypotheses.

Usage: ./venv/bin/python experiments/replay_v2.py
"""
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

# Replay under v2 reasoning so the rebuilt bundle matches what v2 would see.
os.environ["NETDEFEND_REASONING_VERSION"] = "v2"

from agents import grounding                                  # noqa: E402
from agents.troubleshooting_agent import (                    # noqa: E402
    _apply_v2_reasoning, _build_incident_evidence)

CACHE = REPO / "experiments" / "cache"
RAW = REPO / "dataset" / "raw"
MISCONFIG_FAMILIES = ("acl_misconfig", "dns_misconfig", "disabled_logging_misconfig")
_LOG_SUFFIXES = ("_evidence.txt", "_firewall.log", "_evidence.log",
                 "_config.txt", "_firewall_rules.txt")


def true_class(sid):
    return "MISCONFIG" if any(sid.startswith(m) for m in MISCONFIG_FAMILIES) else "ATTACK"


def resolve_log(sid):
    for suffix in _LOG_SUFFIXES:
        c = RAW / f"{sid}{suffix}"
        if c.exists():
            return str(c)
    return ""


def infer_hypothesis_type(taxonomy, is_mis):
    """Recover the categorical hypothesis the v1 agent produced from the
    cached taxonomy_category + is_misconfiguration score (see
    troubleshooting_agent._hypothesis_to_score / the SYSTEM_PROMPT rule that
    sets misconfiguration_type='NONE' for non-misconfiguration verdicts)."""
    if taxonomy == "LLM_UNAVAILABLE":
        return "LLM_UNAVAILABLE"
    if taxonomy and taxonomy != "NONE":
        return "MISCONFIGURATION"
    # taxonomy == "NONE": UNCERTAIN maps to exactly 0.5, else NO_CLEAR.
    if is_mis is not None and abs(float(is_mis) - 0.5) < 1e-9:
        return "UNCERTAIN"
    return "NO_CLEAR_MISCONFIGURATION"


def replay_one(sid):
    j = json.loads((CACHE / sid / "run0.json").read_text(encoding="utf-8"))
    packet_features = j.get("packet_features") or {}
    cross_flow = j.get("cross_flow_pattern") or {}
    ml_prediction = j.get("ml_prediction") or {}

    mh_block = j.get("misconfig_hypothesis") or {}
    inner = mh_block.get("hypothesis") or {}
    is_mis = mh_block.get("is_misconfiguration")
    taxonomy = inner.get("taxonomy_category")
    hyp_type = infer_hypothesis_type(taxonomy, is_mis)

    # Rebuild the evidence bundle the Troubleshooting Agent would have seen.
    state = {
        "packet_features": packet_features,
        "ml_prediction": ml_prediction,
        "cross_flow_pattern": cross_flow,
        "log_path": resolve_log(sid),
    }
    bundle = _build_incident_evidence(state)

    # --- misconfiguration side through v2 post-processing ---
    result = {
        "is_misconfiguration": float(is_mis or 0.0),
        "misconfig_reasoning": "",
        "misconfig_hypothesis": {
            "summary": inner.get("summary", ""),
            "taxonomy_category": taxonomy or "NONE",
            "evidence": list(inner.get("evidence", []) or []),
        },
    }
    if hyp_type == "LLM_UNAVAILABLE":
        mg = {"evidence_dropped": 0, "flagged": False, "null_hypothesis": True}
    else:
        out = _apply_v2_reasoning(result, hyp_type, bundle)
        mg = out["misconfig_grounding"]

    # --- attack side: grounding validator only ---
    ah_block = j.get("attack_hypothesis") or {}
    threat = ah_block.get("threat_hypothesis") or {}
    attack_evidence = list(threat.get("evidence", []) or [])
    attack_bundle = {
        "packet_features": packet_features,
        "ml_prediction": ml_prediction,
        "cross_flow_evidence": cross_flow,
    }
    attack_kept, attack_dropped_n, attack_dropped_items = grounding.validate_items(
        attack_evidence, attack_bundle)

    return {
        "sid": sid, "truth": true_class(sid), "hyp_type": hyp_type,
        "misconfig_dropped": mg["evidence_dropped"],
        "null": mg["null_hypothesis"], "attack_dropped": attack_dropped_n,
        "bundle": bundle,
        "cited_evidence": list(inner.get("evidence", []) or []),
        "attack_total": len(attack_evidence),
        "attack_kept": attack_kept,
        "attack_dropped_items": attack_dropped_items,
        "has_artifact": grounding.bundle_has_config_artifact(bundle),
    }


def _artifact_lines(bundle):
    """Re-walk the bundle's log text and return the lines that the config-
    artifact detector would accept (mirrors grounding.bundle_has_config_artifact,
    for transparency)."""
    hits = []
    raw = (bundle.get("log_evidence") or {}).get("raw_log_excerpt") or ""
    for line in raw.splitlines():
        s = line.strip(); low = s.lower()
        if grounding._is_boilerplate(low):
            continue
        is_hit = (
            low.startswith("-a ")
            or (any(t in low for t in (" drop ", " reject ", " log ")) and
                any(p in low for p in ("tcp", "udp", "icmp")))
            or "meta l4proto" in low or "log prefix" in low
            or "-j log" in low or "src=" in low
            or any(tok in low for tok in grounding._DNS_ARTIFACT_TOKENS)
        )
        if is_hit:
            hits.append(s)
    return hits


def main():
    sids = sorted(p.name for p in CACHE.iterdir()
                  if (p / "run0.json").exists())
    rows = [replay_one(s) for s in sids]

    print("=== v2 post-processing replay over experiments/cache (%d scenarios, "
          "no LLM) ===\n" % len(rows))
    print("%-30s %-9s %-24s %7s %6s %7s" % (
        "scenario", "truth", "hypothesis_type", "misc_dr", "null", "atk_dr"))
    for r in sorted(rows, key=lambda x: (x["truth"], x["sid"])):
        print("%-30s %-9s %-24s %7d %6s %7d" % (
            r["sid"], r["truth"], r["hyp_type"], r["misconfig_dropped"],
            "YES" if r["null"] else "no", r["attack_dropped"]))

    # summary counts
    print("\nMisconfiguration scenarios nulled under v2 (bundle-based): %d of %d" % (
        sum(1 for r in rows if r["truth"] == "MISCONFIG" and r["null"]),
        sum(1 for r in rows if r["truth"] == "MISCONFIG")))
    print("Attack scenarios with misconfig nulled: %d of %d" % (
        sum(1 for r in rows if r["truth"] == "ATTACK" and r["null"]),
        sum(1 for r in rows if r["truth"] == "ATTACK")))

    by = {r["sid"]: r for r in rows}

    # ---- item 2 detail: config-artifact check for two attack scenarios ----
    print("\n\n=== Config-artifact check detail (item 2) ===")
    for sid in ("http_request_flood_a", "tcp_syn_burst_a"):
        r = by.get(sid)
        if not r:
            continue
        hits = _artifact_lines(r["bundle"])
        print("\n%s  (true class %s): bundle_has_config_artifact = %s -> "
              "misconfig %s"
              % (sid, r["truth"], r["has_artifact"],
                 "NULLED" if r["null"] else "kept"))
        if hits:
            print("  evidence item(s) that PASSED the config-artifact check:")
            for h in hits:
                print("     + " + h[:110])
        else:
            print("  NO evidence item passed the config-artifact check. The "
                  "captured ruleset is default-ACCEPT only:")
            print("     - default policies (-P INPUT/FORWARD/OUTPUT ACCEPT) are "
                  "not artifacts")
            print("     - the nft ruleset is (empty) and the netfilter "
                  "log-trail returns (no matching lines)")
            print("     - the only 'SRC=' text is inside the grep COMMAND line, "
                  "which is skipped")
            print("  => no custom rule, no LOG target, no resolver/DNS setting "
                  "=> misconfiguration hypothesis is nulled.")

    # ---- item 3: attack-side dropped evidence; confirm none left empty ----
    print("\n\n=== Attack-side grounding: dropped items per attack scenario "
          "(item 3) ===")
    empty_after = []
    for r in sorted((x for x in rows if x["truth"] == "ATTACK"),
                    key=lambda x: x["sid"]):
        remaining = len(r["attack_kept"])
        if remaining == 0:
            empty_after.append(r["sid"])
        print("\n%s: %d cited -> %d dropped, %d remaining"
              % (r["sid"], r["attack_total"], r["attack_dropped"], remaining))
        for d in r["attack_dropped_items"]:
            print("   DROP: " + d[:108])
    print("\nAttack hypotheses left with ZERO remaining evidence: %s"
          % (", ".join(empty_after) if empty_after else "none (all retain >=1 item)"))

    print("\nNo LLM calls. v1 cache not modified (read-only replay).")


if __name__ == "__main__":
    main()
