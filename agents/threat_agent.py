"""Threat Hunting Agent — builds the attack-side hypothesis.

Prompts the LLM with packet features and the ML prediction, then maps the
conclusion to a MITRE ATT&CK technique via knowledge/mitre/lookup.py
(deterministic table first, LLM fallback only if the table can't resolve
it).

Runs in parallel with the Network Troubleshooting Agent. It writes only the
attack-side keys, so the two branches never touch the same state field.
"""

import json
from typing import Optional

from agents.state_schema import NetDefendState
from agents.llm_client import call_llm, parse_json_response
from knowledge.mitre.lookup import lookup_ttp


HYPOTHESIS_SYSTEM_PROMPT = """You are the Threat Hunting Agent in a network defense system.
You are given packet-level features and an ML classifier's prediction for a
suspicious flow. A MITRE ATT&CK technique has already been identified for you.

Write an attack hypothesis grounded ONLY in the data provided. Do not invent
statistics, hosts, or events that are not present in the input. Every item in
"evidence" must restate a specific fact from the input (a feature value, a
count, the ML label and its probability) — not a generic claim.

Respond with JSON only, no prose, no markdown fences, matching exactly:
{
  "summary": "one or two sentences describing the suspected attack",
  "evidence": ["fact 1 grounded in the input data", "fact 2", ...]
}
"""

# Fallback used only if the LLM call fails outright (e.g. network/API
# error) so a transient failure degrades gracefully instead of crashing
# the pipeline. This is NOT a substitute for real reasoning — it should
# rarely fire in practice.
_FALLBACK_TTP_ID = "T1071"
_FALLBACK_HYPOTHESIS = {
    "summary": (
        "Unable to generate a grounded hypothesis due to an LLM call failure; "
        "flow flagged as anomalous by the ML model and requires manual review."
    ),
    "evidence": ["LLM hypothesis generation failed — see logs for the underlying error."],
}


def run_threat_agent(state: NetDefendState) -> dict:
    """Propose an attack hypothesis and map it to a MITRE ATT&CK technique.

    Args:
        state: Current pipeline state; reads ``packet_features`` and
            ``ml_prediction``.

    Returns:
        Partial state update containing ``ttp_id``, ``ttp_confidence``, and
        ``threat_hypothesis``.
    """
    print("[Threat Hunting Agent] running...")

    packet_features = state.get("packet_features") or {}
    ml_prediction = state.get("ml_prediction") or {}
    # Aggregate evidence across ALL flows (see agents/packet_agent.py) --
    # never fed to the ML models, but real evidence for the LLM: e.g. 10
    # blocked SYNs to the same destination across separate flows, a
    # pattern packet_features alone (one representative flow) can't show.
    cross_flow_pattern = state.get("cross_flow_pattern") or {}

    (
        ttp_id, technique_name, tactic, mapping_method, ttp_confidence,
        llm_call_failed,
    ) = _resolve_ttp(ml_prediction, packet_features, cross_flow_pattern)

    threat_hypothesis = _generate_hypothesis(
        packet_features=packet_features,
        ml_prediction=ml_prediction,
        cross_flow_pattern=cross_flow_pattern,
        ttp_id=ttp_id,
        technique_name=technique_name,
        tactic=tactic,
    )

    print(f"[Threat Hunting Agent] mapped to {ttp_id} via {mapping_method} "
          f"(confidence={ttp_confidence:.2f})")

    return {
        "ttp_id": ttp_id,
        "ttp_confidence": ttp_confidence,
        "ttp_mapping_method": mapping_method,
        "llm_call_failed": llm_call_failed,
        "threat_hypothesis": threat_hypothesis,
    }


def _resolve_ttp(
    ml_prediction: dict, packet_features: dict, cross_flow_pattern: dict
) -> tuple[str, str, str, str, float, bool]:
    """Deterministic lookup first; LLM fallback only if the table misses.

    The last element, ``llm_call_failed``, is True only when the LLM
    fallback was actually invoked and either raised (missing key, network
    error, API error, etc.) or came back with no usable ``ttp_id`` — NOT
    when the deterministic table resolved it, and NOT for a genuine (if
    low-confidence) LLM answer. Without this, a crashed LLM call and a
    real low-confidence result both collapse into the same
    ``mapping_method="fallback_default"``/``confidence=0.2`` output, which
    is exactly the silent-failure ambiguity downstream eval/ablation code
    needs to be able to tell apart.
    """
    match = lookup_ttp(ml_prediction, packet_features)
    if match:
        return (
            match["ttp_id"],
            match["technique_name"],
            match["tactic"],
            match["mapping_method"],
            match["confidence"],
            False,
        )

    # LLM fallback for TTP mapping. lookup_ttp() above (the deterministic
    # table) keeps its existing fixed contract untouched -- cross_flow_pattern
    # only reaches the LLM path, not the table.
    prompt = _build_ttp_fallback_prompt(ml_prediction, packet_features, cross_flow_pattern)
    try:
        raw = call_llm(
            prompt,
            system=(
                "You are a MITRE ATT&CK mapping assistant. Respond with JSON only: "
                '{"ttp_id": "...", "technique_name": "...", "tactic": "...", '
                '"confidence": 0.0}'
            ),
        )
        parsed = parse_json_response(raw)
        if parsed.get("ttp_id"):
            return (
                parsed["ttp_id"],
                parsed.get("technique_name", "Unmapped"),
                parsed.get("tactic", "Unknown"),
                "llm_fallback",
                float(parsed.get("confidence", 0.4)),
                False,
            )
        print("[Threat Hunting Agent] LLM fallback call returned no usable "
              "ttp_id — treating as a failed call, not a genuine low-"
              "confidence result")
    except Exception as exc:  # noqa: BLE001 — degrade gracefully, don't crash the pipeline
        print(f"[Threat Hunting Agent] LLM fallback call failed: {exc}")

    return (
        _FALLBACK_TTP_ID,
        "Application Layer Protocol",
        "Command and Control",
        "fallback_default",
        0.2,
        True,
    )


def _build_ttp_fallback_prompt(
    ml_prediction: dict, packet_features: dict, cross_flow_pattern: dict
) -> str:
    return (
        "No deterministic ATT&CK mapping matched the following data. "
        "Identify the single most likely technique.\n\n"
        f"ML prediction: {json.dumps(ml_prediction)}\n"
        f"Packet features (single representative flow): {json.dumps(packet_features)}\n"
        "Cross-flow pattern (aggregate evidence across every flow in the "
        f"capture, not just the representative flow above): {json.dumps(cross_flow_pattern)}"
    )


def _generate_hypothesis(
    packet_features: dict,
    ml_prediction: dict,
    cross_flow_pattern: dict,
    ttp_id: str,
    technique_name: str,
    tactic: str,
) -> dict:
    prompt = (
        f"MITRE ATT&CK technique: {ttp_id} ({technique_name}), tactic: {tactic}\n\n"
        f"ML prediction: {json.dumps(ml_prediction)}\n"
        f"Packet features (single representative flow): {json.dumps(packet_features)}\n"
        "Cross-flow pattern (aggregate evidence across every flow in the "
        f"capture, not just the representative flow above): {json.dumps(cross_flow_pattern)}"
    )
    try:
        raw = call_llm(prompt, system=HYPOTHESIS_SYSTEM_PROMPT)
        parsed = parse_json_response(raw)
        if parsed.get("summary") and parsed.get("evidence"):
            return {"summary": parsed["summary"], "evidence": parsed["evidence"]}
        print("[Threat Hunting Agent] LLM returned malformed hypothesis JSON, using fallback")
    except Exception as exc:  # noqa: BLE001
        print(f"[Threat Hunting Agent] LLM hypothesis generation failed: {exc}")

    return dict(_FALLBACK_HYPOTHESIS)