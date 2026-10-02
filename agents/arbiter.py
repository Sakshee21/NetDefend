"""Dialectical Arbiter — forces both hypotheses through adversarial refutation.

This is NetDefend's core novelty. By the time this node runs, the state holds
two independently-built hypotheses that have never seen each other:

  * threat_hypothesis    (attack side, from the Threat Hunting Agent)
  * misconfig_hypothesis (misconfiguration side, from the Network
    Troubleshooting Agent)

The arbiter does NOT fuse their confidence scores numerically -- that naive
"simple fusion" is exactly the baseline the ablation study exists to beat.
Instead it stages a real adversarial exchange over four Groq calls:

  1. Challenger  -- one call that sees BOTH hypotheses and crafts a pointed
     refutation challenge against each, every challenge built from the
     OTHER hypothesis's strongest, most specific evidence.
  2/3. Defenders -- two SEPARATE calls, one per hypothesis, each isolated: a
     defender sees only the challenge aimed at it plus its OWN evidence,
     never the opponent's evidence. That is the same separation principle
     that keeps the two hypothesis agents independent in the first place,
     which is why the defenses are two calls and not one batched call.
  4. Adjudicator -- one call that sees both hypotheses, both challenges and
     both responses, and judges which hypothesis actually survived scrutiny
     (not which had the higher prior confidence number).

Fan-in node: runs once, after both hypothesis agents finish. Writes
``refutation_exchange`` and ``arbiter_verdict``; it never touches
``final_report`` -- that is the Incident Response Agent's job.

Failure handling mirrors the other agents. Each Groq call is retried once
and its JSON validated; if the adversarial machinery still cannot complete,
the arbiter falls back to a transparent rule (higher-confidence hypothesis
wins) whose reasoning says so verbatim, so an ablation/eval downstream can
tell a real adjudication from a degraded one. A hypothesis that already
failed upstream (threat with llm_call_failed, or misconfig tagged
LLM_UNAVAILABLE) is never allowed to win by default.
"""
import json
import os

from agents.llm_client import call_llm, parse_json_response
from agents.state_schema import NetDefendState

# Same Groq model the Network Troubleshooting Agent uses -- MODEL_NAME_LIGHT
# (gpt-oss-20b), chosen there for its JSON-mode reliability over the 120b
# model. llm_client has already loaded .env on import.
GROQ_MODEL = os.environ.get("MODEL_NAME_LIGHT", "openai/gpt-oss-20b")
GROQ_TIMEOUT_S = 30
LLM_MAX_ATTEMPTS = 2

_VALID_CLASSIFICATIONS = {"ATTACK", "MISCONFIGURATION", "UNCERTAIN"}

_UNCERTAIN_ESCALATION = (
    "Verdict is UNCERTAIN — the adversarial exchange did not clearly favour "
    "either hypothesis. Recommend human analyst review; the system is "
    "deliberately not forcing a classification."
)


# ======================================================
# PROMPTS
# ======================================================

_CHALLENGER_SYSTEM = """You are the challenger inside a Dialectical Arbiter for a network-incident
analysis system. You are given two competing hypotheses about the SAME
incident: an ATTACK hypothesis and a MISCONFIGURATION hypothesis, each with
its own supporting evidence.

Write ONE sharp refutation challenge against EACH hypothesis. Each challenge
must be built from the OTHER hypothesis's strongest, most specific evidence:
cite concrete values from that opposing evidence (counts, ports, log counter
values, ML scores) and press the challenged hypothesis to explain them. Do
NOT write generic questions -- a good challenge could only have been written
for THIS incident.

Respond with JSON only, no prose, no markdown fences, exactly:
{
  "challenge_to_attack": "one specific question pressing the ATTACK hypothesis, built from the misconfiguration evidence",
  "challenge_to_misconfiguration": "one specific question pressing the MISCONFIGURATION hypothesis, built from the attack evidence"
}"""

_DEFENDER_SYSTEM = """You are defending ONE hypothesis in a network-incident analysis. You are
given your hypothesis, its OWN supporting evidence, and a single challenge
raised against it. Rebut the challenge using ONLY your own evidence and
reasoning drawn from it. You do NOT have access to the opposing hypothesis's
evidence -- do not invent facts to fill the gap. If your evidence genuinely
cannot answer the challenge, say so plainly; an honest concession is better
than a fabricated rebuttal.

Respond with JSON only, no prose, no markdown fences, exactly:
{
  "response": "your rebuttal, grounded only in your own evidence"
}"""

_ADJUDICATOR_SYSTEM = """You are the Dialectical Arbiter delivering a final verdict for a network
incident. You are given two competing hypotheses (ATTACK vs
MISCONFIGURATION), the refutation challenge put to each, and each
hypothesis's response to its challenge.

Judge which hypothesis BETTER SURVIVED its challenge -- which response more
directly and specifically answered the challenge using real evidence, versus
which was weak, evasive, or conceded. Do NOT simply pick whichever hypothesis
had the higher prior confidence number; weigh the quality of the rebuttals.

Choose exactly one classification:
- "ATTACK": the attack hypothesis's rebuttal was substantially stronger and
  the misconfiguration rebuttal was weak or evasive.
- "MISCONFIGURATION": the reverse.
- "UNCERTAIN": neither rebuttal clearly resolved its challenge, or both were
  comparably strong or comparably weak. Prefer UNCERTAIN over a forced guess.

Respond with JSON only, no prose, no markdown fences, exactly:
{
  "classification": "ATTACK" | "MISCONFIGURATION" | "UNCERTAIN",
  "confidence": a number between 0.0 and 1.0 for how sure you are of this verdict,
  "reasoning": "which hypothesis survived scrutiny and why, referencing the responses"
}"""


# ======================================================
# HYPOTHESIS PACKAGING + FAILURE DETECTION
# ======================================================

def _attack_package(state: NetDefendState) -> dict:
    th = state.get("threat_hypothesis") or {}
    return {
        "side": "ATTACK",
        "summary": th.get("summary", ""),
        "mitre_ttp": state.get("ttp_id"),
        "confidence": state.get("ttp_confidence"),
        "evidence": th.get("evidence", []),
    }


def _misconfig_package(state: NetDefendState) -> dict:
    mh = state.get("misconfig_hypothesis") or {}
    return {
        "side": "MISCONFIGURATION",
        "summary": mh.get("summary", ""),
        "taxonomy_category": mh.get("taxonomy_category"),
        "confidence": state.get("is_misconfiguration"),
        "evidence": mh.get("evidence", []),
    }


def _attack_failed(state: NetDefendState) -> bool:
    """True when the attack hypothesis never got a real answer upstream.
    ``llm_call_failed`` is the Threat Hunting Agent's explicit signal for
    exactly this (see agents/threat_agent.py); the empty-summary check is a
    belt-and-braces guard."""
    if state.get("llm_call_failed") is True:
        return True
    return not (state.get("threat_hypothesis") or {}).get("summary")


def _misconfig_failed(state: NetDefendState) -> bool:
    """True when the misconfiguration hypothesis never got a real answer
    upstream. ``LLM_UNAVAILABLE`` is the Troubleshooting Agent's explicit
    "call never produced a real answer" sentinel (see
    agents/troubleshooting_agent.py)."""
    mh = state.get("misconfig_hypothesis") or {}
    if mh.get("taxonomy_category") == "LLM_UNAVAILABLE":
        return True
    return not mh.get("summary")


def _conf(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ======================================================
# LLM HELPER (retry-then-raise, same contract as the other agents)
# ======================================================

def _call_json(system: str, user: str, text_keys=(), numeric_keys=()) -> dict:
    """One Groq call constrained to JSON, retried once. Raises if every
    attempt returns unparseable JSON, leaves any ``text_keys`` field empty,
    or omits any ``numeric_keys`` field -- the same retry-then-raise contract
    the Troubleshooting Agent uses, so a persistent failure propagates up to
    run_arbiter()'s rule-based fallback."""
    last_exc = None
    for attempt in range(1, LLM_MAX_ATTEMPTS + 1):
        try:
            raw = call_llm(
                user,
                system=system,
                model=GROQ_MODEL,
                timeout=GROQ_TIMEOUT_S,
                json_mode=True,
            )
            parsed = parse_json_response(raw)
            if not parsed:
                raise ValueError(f"non-JSON or empty output: {raw[:200]!r}")
            for key in text_keys:
                if not str(parsed.get(key) or "").strip():
                    raise ValueError(f"missing or empty required field {key!r}")
            for key in numeric_keys:
                if parsed.get(key) is None:
                    raise ValueError(f"missing required numeric field {key!r}")
            return parsed
        except Exception as exc:  # noqa: BLE001 -- retried, then re-raised below
            last_exc = exc
            print(f"[Dialectical Arbiter] LLM attempt "
                  f"{attempt}/{LLM_MAX_ATTEMPTS} failed: {str(exc)[:160]}")
    raise last_exc


def _defender_view(pkg: dict) -> dict:
    """What a defending hypothesis is allowed to see: its OWN summary and
    evidence only, never the opponent's. Its prior confidence number is
    dropped deliberately -- a defence should argue from evidence, not from
    how confident it already claimed to be."""
    view = {"summary": pkg["summary"], "evidence": pkg["evidence"]}
    if pkg.get("mitre_ttp"):
        view["mitre_ttp"] = pkg["mitre_ttp"]
    if pkg.get("taxonomy_category"):
        view["taxonomy_category"] = pkg["taxonomy_category"]
    return view


# ======================================================
# RESOLUTION PATHS
# ======================================================

def _run_adversarial_exchange(attack: dict, misconfig: dict) -> dict:
    """The real dialectical path: challenge -> isolated defences -> verdict.
    Raises on any unrecoverable LLM failure so run_arbiter() can fall back."""
    # 1. Challenger sees both hypotheses, crafts a challenge against each.
    challenges = _call_json(
        _CHALLENGER_SYSTEM,
        "ATTACK hypothesis:\n" + json.dumps(attack, indent=2) +
        "\n\nMISCONFIGURATION hypothesis:\n" + json.dumps(misconfig, indent=2),
        text_keys=("challenge_to_attack", "challenge_to_misconfiguration"),
    )
    challenge_to_attack = challenges["challenge_to_attack"].strip()
    challenge_to_misconfig = challenges["challenge_to_misconfiguration"].strip()

    # 2/3. Each hypothesis defends in isolation -- its OWN evidence plus the
    #      challenge aimed at it, never the opponent's evidence.
    attack_response = _call_json(
        _DEFENDER_SYSTEM,
        "Your hypothesis (ATTACK):\n" + json.dumps(_defender_view(attack), indent=2) +
        "\n\nChallenge raised against you:\n" + challenge_to_attack,
        text_keys=("response",),
    )["response"].strip()
    misconfig_response = _call_json(
        _DEFENDER_SYSTEM,
        "Your hypothesis (MISCONFIGURATION):\n" + json.dumps(_defender_view(misconfig), indent=2) +
        "\n\nChallenge raised against you:\n" + challenge_to_misconfig,
        text_keys=("response",),
    )["response"].strip()

    refutation_exchange = [
        {"challenged_agent": "threat_hunting",
         "challenge": challenge_to_attack, "response": attack_response},
        {"challenged_agent": "troubleshooting",
         "challenge": challenge_to_misconfig, "response": misconfig_response},
    ]

    # 4. Adjudicate on the exchange -- explicitly NOT on the prior confidences.
    adjudication = _call_json(
        _ADJUDICATOR_SYSTEM,
        "ATTACK hypothesis:\n" + json.dumps(attack, indent=2) +
        "\n\nMISCONFIGURATION hypothesis:\n" + json.dumps(misconfig, indent=2) +
        "\n\nChallenge put to the ATTACK hypothesis:\n" + challenge_to_attack +
        "\nATTACK hypothesis's response:\n" + attack_response +
        "\n\nChallenge put to the MISCONFIGURATION hypothesis:\n" + challenge_to_misconfig +
        "\nMISCONFIGURATION hypothesis's response:\n" + misconfig_response,
        text_keys=("classification", "reasoning"),
        numeric_keys=("confidence",),
    )

    classification = str(adjudication["classification"]).strip().upper()
    if classification not in _VALID_CLASSIFICATIONS:
        raise ValueError(f"adjudicator returned invalid classification: {classification!r}")
    confidence = max(0.0, min(1.0, _conf(adjudication["confidence"])))

    verdict = {
        "classification": classification,
        "confidence": round(confidence, 2),
        "reasoning": str(adjudication["reasoning"]).strip(),
    }
    if classification == "UNCERTAIN":
        verdict["escalation"] = _UNCERTAIN_ESCALATION

    print(f"[Dialectical Arbiter] verdict: {classification} ({confidence:.2f})")
    return {"refutation_exchange": refutation_exchange, "arbiter_verdict": verdict}


def _resolve_with_broken_hypothesis(
    attack: dict, misconfig: dict, attack_broken: bool, misconfig_broken: bool
) -> dict:
    """One or both hypotheses failed upstream. A hypothesis that never
    produced a real answer cannot defend itself and must not win by default,
    so there is nothing to adjudicate -- lean (transparently) toward whichever
    side still carries real evidence, or UNCERTAIN if neither does."""
    attack_conf = _conf(attack["confidence"])
    misconfig_conf = _conf(misconfig["confidence"])

    if attack_broken and misconfig_broken:
        classification, confidence = "UNCERTAIN", 0.0
        reasoning = (
            "Both hypotheses failed upstream before the arbiter ran (the "
            "attack side and the misconfiguration side each returned a "
            "non-answer), so there is nothing to adjudicate. Returning "
            "UNCERTAIN."
        )
        note_attack = "Attack hypothesis failed upstream; could not be challenged."
        note_misconfig = "Misconfiguration hypothesis failed upstream; could not be challenged."
        resp_attack = resp_misconfig = "(no response — hypothesis unavailable)"
    elif attack_broken:
        classification, confidence = "MISCONFIGURATION", misconfig_conf
        reasoning = (
            "The attack hypothesis failed upstream (the Threat Hunting Agent "
            "never produced a real answer), so it cannot be defended and must "
            "not win by default. Leaning to the misconfiguration hypothesis, "
            "which carries real evidence; no adversarial exchange was run."
        )
        note_attack = "Attack hypothesis failed upstream; could not be challenged."
        note_misconfig = "Opponent failed upstream; no challenge was raised against this hypothesis."
        resp_attack = "(no response — hypothesis unavailable)"
        resp_misconfig = "(not challenged — opponent unavailable)"
    else:  # misconfig_broken only
        classification, confidence = "ATTACK", attack_conf
        reasoning = (
            "The misconfiguration hypothesis failed upstream (the Network "
            "Troubleshooting Agent returned LLM_UNAVAILABLE), so it cannot be "
            "defended and must not win by default. Leaning to the attack "
            "hypothesis, which carries real evidence; no adversarial exchange "
            "was run."
        )
        note_attack = "Opponent failed upstream; no challenge was raised against this hypothesis."
        note_misconfig = "Misconfiguration hypothesis failed upstream; could not be challenged."
        resp_attack = "(not challenged — opponent unavailable)"
        resp_misconfig = "(no response — hypothesis unavailable)"

    verdict = {
        "classification": classification,
        "confidence": round(confidence, 2),
        "reasoning": reasoning,
    }
    if classification == "UNCERTAIN":
        verdict["escalation"] = _UNCERTAIN_ESCALATION

    refutation_exchange = [
        {"challenged_agent": "threat_hunting", "challenge": note_attack, "response": resp_attack},
        {"challenged_agent": "troubleshooting", "challenge": note_misconfig, "response": resp_misconfig},
    ]
    print(f"[Dialectical Arbiter] verdict (upstream-failure path): "
          f"{classification} ({confidence:.2f})")
    return {"refutation_exchange": refutation_exchange, "arbiter_verdict": verdict}


def _rule_based_fallback(attack: dict, misconfig: dict) -> dict:
    """Reached only when the adversarial LLM machinery could not complete.
    Higher prior confidence wins. The reasoning carries a fixed sentinel so
    downstream eval/ablation code can tell this apart from a genuine
    LLM-adjudicated verdict."""
    attack_conf = _conf(attack["confidence"])
    misconfig_conf = _conf(misconfig["confidence"])

    if attack_conf > misconfig_conf:
        classification, confidence = "ATTACK", attack_conf
    elif misconfig_conf > attack_conf:
        classification, confidence = "MISCONFIGURATION", misconfig_conf
    else:
        classification, confidence = "UNCERTAIN", attack_conf

    verdict = {
        "classification": classification,
        "confidence": round(confidence, 2),
        "reasoning": (
            "fallback rule used — full adversarial exchange could not "
            f"complete. Chose the higher-confidence hypothesis "
            f"(attack={attack_conf:.2f}, misconfiguration={misconfig_conf:.2f})."
        ),
    }
    if classification == "UNCERTAIN":
        verdict["escalation"] = _UNCERTAIN_ESCALATION

    refutation_exchange = [
        {"challenged_agent": "threat_hunting",
         "challenge": "(adversarial exchange unavailable — LLM calls failed)",
         "response": "(unavailable)"},
        {"challenged_agent": "troubleshooting",
         "challenge": "(adversarial exchange unavailable — LLM calls failed)",
         "response": "(unavailable)"},
    ]
    print(f"[Dialectical Arbiter] verdict (rule-based fallback): "
          f"{classification} ({confidence:.2f})")
    return {"refutation_exchange": refutation_exchange, "arbiter_verdict": verdict}


# ======================================================
# ENTRY POINT
# ======================================================

def run_arbiter(state: NetDefendState) -> dict:
    """Challenge both hypotheses adversarially and commit to a verdict.

    Args:
        state: Current pipeline state; reads ``threat_hypothesis``,
            ``ttp_id``, ``ttp_confidence``, ``llm_call_failed``,
            ``misconfig_hypothesis`` and ``is_misconfiguration``.

    Returns:
        Partial state update containing ``refutation_exchange`` and
        ``arbiter_verdict``.
    """
    print("[Dialectical Arbiter] running...")

    attack = _attack_package(state)
    misconfig = _misconfig_package(state)
    attack_broken = _attack_failed(state)
    misconfig_broken = _misconfig_failed(state)

    # A hypothesis that failed upstream cannot defend itself -- resolve
    # deterministically rather than staging a sham exchange.
    if attack_broken or misconfig_broken:
        return _resolve_with_broken_hypothesis(
            attack, misconfig, attack_broken, misconfig_broken
        )

    # Both hypotheses are real: run the genuine adversarial exchange, with a
    # transparent rule-based fallback if the LLM machinery cannot complete.
    try:
        return _run_adversarial_exchange(attack, misconfig)
    except Exception as exc:  # noqa: BLE001 -- degrade gracefully, don't crash the pipeline
        print(f"[Dialectical Arbiter] adversarial exchange failed: {exc}")
        return _rule_based_fallback(attack, misconfig)
