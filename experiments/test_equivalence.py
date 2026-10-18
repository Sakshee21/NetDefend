#!/usr/bin/env python3
"""Prove the harness's sequential orchestration matches agents/graph.py.

Runs ONE scenario through both paths with the LLM client mocked (fixed canned
responses -- zero tokens) and asserts:
  * the Arbiter-relevant pipeline state is identical, and
  * the exact prompts passed to the Arbiter are identical.

Run:  python experiments/test_equivalence.py
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
RAW = REPO / "dataset" / "raw"

import agents.threat_agent as threat_mod
import agents.troubleshooting_agent as trbl_mod
import agents.arbiter as arb_mod
import agents.response_agent as resp_mod
from agents.packet_agent import run_packet_agent
from agents.intrusion_agent import run_intrusion_agent

_ARBITER_SYSTEMS = (arb_mod._CHALLENGER_SYSTEM, arb_mod._DEFENDER_SYSTEM,
                    arb_mod._ADJUDICATOR_SYSTEM)
_calls = []  # (system, prompt) in call order


def mock_call_llm(prompt, system=None, model=None, timeout=None, json_mode=False):
    # Route most-specific first. NOTE: the Troubleshooting system prompt mentions
    # "Threat Hunting Agent", so troubleshooting must be matched by its own unique
    # marker ("MISCONFIGURATION side") BEFORE the threat check.
    _calls.append((system, prompt))
    s = system or ""
    if "challenger inside a Dialectical Arbiter" in s:
        return json.dumps({"challenge_to_attack": "q-to-attack",
                           "challenge_to_misconfiguration": "q-to-misconfig"})
    if "defending ONE hypothesis" in s:
        return json.dumps({"response": "canned defence"})
    if "delivering a final verdict" in s:
        return json.dumps({"classification": "ATTACK", "confidence": 0.8,
                           "reasoning": "canned adjudication"})
    if "Incident Response Agent" in s:
        return json.dumps({"recommended_action": "canned action"})
    if "MITRE ATT&CK mapping assistant" in s:
        return json.dumps({"ttp_id": "T1046", "technique_name": "Network Service Discovery",
                           "tactic": "Discovery", "confidence": 0.7})
    if "MISCONFIGURATION side" in s:  # Network Troubleshooting Agent's own prompt
        return json.dumps({"agent": "Network Troubleshooting Agent",
                           "hypothesis": "MISCONFIGURATION", "misconfiguration_type": "ACL_FIREWALL",
                           "confidence": 0.6, "problem": "canned misconfig",
                           "evidence": ["ev-m-1"], "reasoning": "canned reasoning",
                           "recommended_action": "fix rule"})
    if "Threat Hunting Agent" in s:
        return json.dumps({"summary": "canned attack summary",
                           "evidence": ["ev-a-1", "ev-a-2"]})
    return "{}"


# Patch every agent module's bound call_llm (they imported it by name).
for mod in (threat_mod, trbl_mod, arb_mod, resp_mod):
    mod.call_llm = mock_call_llm


def arbiter_prompts():
    return [(s, p) for (s, p) in _calls if s in _ARBITER_SYSTEMS]


def subset(state):
    keys = ["packet_features", "cross_flow_pattern", "ml_prediction", "ttp_id",
            "ttp_confidence", "threat_hypothesis", "is_misconfiguration",
            "misconfig_hypothesis", "refutation_exchange", "arbiter_verdict"]
    return {k: state.get(k) for k in keys}


def main():
    scenario = "acl_misconfig_A"
    pcap = str(RAW / f"{scenario}.pcap")
    log = str(RAW / f"{scenario}_evidence.txt")
    if not Path(pcap).exists():
        sys.exit(f"need {pcap}; regenerate the bench first")

    # ---- Path 1: manual sequential orchestration ----
    _calls.clear()
    s1 = {"pcap_path": pcap, "log_path": log}
    s1.update(run_packet_agent(s1))
    s1.update(run_intrusion_agent(s1))
    s1.update(threat_mod.run_threat_agent(s1))
    s1.update(trbl_mod.run_troubleshooting_agent(s1))
    s1.update(arb_mod.run_arbiter(s1))
    manual_state = subset(s1)
    manual_arb = arbiter_prompts()

    # ---- Path 2: graph.py ----
    _calls.clear()
    from agents.graph import build_graph
    app = build_graph()
    s2 = app.invoke({"pcap_path": pcap, "log_path": log})
    graph_state = subset(s2)
    graph_arb = arbiter_prompts()

    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    state_eq = json.dumps(manual_state, sort_keys=True, default=str) == \
        json.dumps(graph_state, sort_keys=True, default=str)
    check("Arbiter-relevant state identical (manual == graph)", state_eq)
    check("Arbiter issued 4 prompts in each path",
          len(manual_arb) == 4 and len(graph_arb) == 4)
    check("Arbiter prompts identical (same order & content)", manual_arb == graph_arb)

    if not state_eq:
        for k in manual_state:
            a = json.dumps(manual_state[k], sort_keys=True, default=str)
            b = json.dumps(graph_state[k], sort_keys=True, default=str)
            if a != b:
                print(f"    DIFF in {k}:\n      manual={a[:200]}\n      graph ={b[:200]}")

    print(f"\n=== EQUIVALENCE {'PROVEN' if ok else 'FAILED'} (LLM mocked, 0 tokens) ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
