"""Incident Response Agent — assembles the final incident report.

Runs last, after the Dialectical Arbiter. It does NOT decide a verdict: it
reads ``arbiter_verdict`` and builds the analyst-facing report around it --
deriving a risk level from the verdict, and generating a case-specific
recommended action with Groq (gpt-oss-20b, same pattern as the other LLM
agents). Consistent with NetDefend's scope, the recommendation is advice for
a human; the system never executes it, and an UNCERTAIN verdict is routed to
human review rather than an automated action.
"""
import json
import os
import uuid
from datetime import datetime, timezone

from agents.llm_client import call_llm, parse_json_response
from agents.state_schema import NetDefendState
from knowledge.mitre.lookup import CLASS_TO_TTP

# Same Groq model the arbiter and troubleshooting agents use. llm_client has
# already loaded .env on import.
GROQ_MODEL = os.environ.get("MODEL_NAME_LIGHT", "openai/gpt-oss-20b")
GROQ_TIMEOUT_S = 30
LLM_MAX_ATTEMPTS = 2

# Real technique names for every TTP the deterministic mapper can produce,
# drawn straight from the MITRE lookup table (replaces the old one-entry
# stub). TTPs that only come from the Threat Hunting Agent's LLM fallback
# won't be in here -- those resolve to "Unknown".
_TTP_NAMES = {match["ttp_id"]: match["technique_name"] for _, match in CLASS_TO_TTP}

# Techniques whose successful execution is high-impact (denial of service,
# exploitation) -- an ATTACK verdict on these at high confidence is CRITICAL
# rather than merely HIGH.
_CRITICAL_TTPS = {"T1498", "T1499", "T1190", "T1212", "T1203"}

_ACTION_FALLBACK = (
    "Automated recommendation unavailable — review the flagged evidence manually."
)

_ACTION_SYSTEM = """You are the Incident Response Agent in NetDefend. The system only
RECOMMENDS actions for a human analyst; it never executes them itself.

You are given a final verdict for a network incident, its confidence, and the
supporting evidence for the hypothesis that prevailed. Write ONE specific,
actionable recommendation that fits THIS incident: reference the actual
destination host/port and the actual issue from the evidence. Do not write
generic boilerplate, and do not invent facts beyond the evidence provided.

- ATTACK: recommend concrete containment / investigation steps appropriate to
  the named MITRE technique and the affected host.
- MISCONFIGURATION: recommend the specific configuration fix -- name the rule
  and the destination to correct -- framed as an operational repair.
- UNCERTAIN: the evidence did not resolve. Recommend routing the incident to a
  human analyst for review and name what additional evidence would settle it.
  Do NOT recommend an automated fix or a containment action.

Respond with JSON only, no prose, no markdown fences, exactly:
{
  "recommended_action": "one specific recommendation grounded in the evidence"
}"""


def _derive_risk_level(classification: str, confidence: float, ttp_id: str | None) -> str:
    """Risk level from the verdict, not a fixed value.

    ATTACK: CRITICAL for high-impact techniques at high confidence, otherwise
    HIGH; MEDIUM when the attack verdict is low-confidence. MISCONFIGURATION:
    MEDIUM when confidently identified (a misconfig actively blocking or
    degrading traffic is an availability problem worth flagging, even though
    it is not malicious), otherwise LOW. UNCERTAIN: MEDIUM -- the real risk
    cannot be settled until a human reviews it (see the report's escalation
    note)."""
    if classification == "ATTACK":
        if confidence > 0.7:
            return "CRITICAL" if ttp_id in _CRITICAL_TTPS else "HIGH"
        return "MEDIUM"
    if classification == "MISCONFIGURATION":
        return "MEDIUM" if confidence >= 0.6 else "LOW"
    return "MEDIUM"  # UNCERTAIN


def _call_json(system: str, user: str, text_keys=()) -> dict:
    """One Groq call constrained to JSON, retried once; raises if every
    attempt returns unparseable JSON or leaves a required field empty. Same
    retry-then-raise contract as the other agents, so a persistent failure
    propagates to run_response_agent()'s honest fallback."""
    last_exc = None
    for attempt in range(1, LLM_MAX_ATTEMPTS + 1):
        try:
            raw = call_llm(
                user, system=system, model=GROQ_MODEL,
                timeout=GROQ_TIMEOUT_S, json_mode=True,
            )
            parsed = parse_json_response(raw)
            if not parsed:
                raise ValueError(f"non-JSON or empty output: {raw[:200]!r}")
            for key in text_keys:
                if not str(parsed.get(key) or "").strip():
                    raise ValueError(f"missing or empty required field {key!r}")
            return parsed
        except Exception as exc:  # noqa: BLE001 -- retried, then re-raised below
            last_exc = exc
            print(f"[Incident Response Agent] LLM attempt "
                  f"{attempt}/{LLM_MAX_ATTEMPTS} failed: {str(exc)[:160]}")
    raise last_exc


def _generate_recommended_action(
    state: NetDefendState, classification: str, confidence: float,
    mitre_ttp: dict | None, destination: dict,
) -> str:
    """Case-specific recommended action from the winning hypothesis's real
    evidence. Falls back to an honest placeholder if the LLM call fails --
    never stale or fabricated text."""
    threat = state.get("threat_hypothesis") or {}
    misconfig = state.get("misconfig_hypothesis") or {}

    context = {
        "classification": classification,
        "confidence": confidence,
        "affected_destination": destination,
    }
    if classification == "ATTACK":
        context["mitre_technique"] = mitre_ttp
        context["attack_evidence"] = threat.get("evidence", [])
    elif classification == "MISCONFIGURATION":
        context["misconfiguration"] = {
            "taxonomy_category": misconfig.get("taxonomy_category"),
            "evidence": misconfig.get("evidence", []),
        }
    else:  # UNCERTAIN -- give both sides so the review note can be specific
        context["attack_summary"] = threat.get("summary")
        context["misconfiguration_summary"] = misconfig.get("summary")
        context["arbiter_reasoning"] = (state.get("arbiter_verdict") or {}).get("reasoning")

    try:
        parsed = _call_json(
            _ACTION_SYSTEM,
            "Incident:\n" + json.dumps(context, indent=2),
            text_keys=("recommended_action",),
        )
        return parsed["recommended_action"].strip()
    except Exception as exc:  # noqa: BLE001 -- degrade gracefully
        print(f"[Incident Response Agent] recommended_action generation failed: {exc}")
        return _ACTION_FALLBACK


def run_response_agent(state: NetDefendState) -> dict:
    """Build the incident report handed back to the API caller.

    Args:
        state: Current pipeline state; reads ``arbiter_verdict``, ``ttp_id``,
            ``cross_flow_pattern`` and ``packet_features``.

    Returns:
        Partial state update containing the completed ``final_report``.
    """
    print("[Incident Response Agent] running...")

    verdict = state.get("arbiter_verdict") or {}
    classification = verdict.get("classification", "UNCERTAIN")
    confidence = float(verdict.get("confidence", 0.0) or 0.0)

    ttp_id = state.get("ttp_id")
    mitre_ttp = None
    if classification == "ATTACK" and ttp_id:
        mitre_ttp = {"id": ttp_id, "name": _TTP_NAMES.get(ttp_id, "Unknown")}

    # The affected host is the real target of the traffic. cross_flow_pattern
    # carries the actual destination IP/port (see agents/packet_agent.py);
    # fall back to the selected flow's talker IP, then to "unknown".
    cross_flow = state.get("cross_flow_pattern") or {}
    destination = cross_flow.get("destination") or {}
    features = state.get("packet_features") or {}
    affected_host = destination.get("ip") or features.get("top_talker_ip") or "unknown"

    risk_level = _derive_risk_level(classification, confidence, ttp_id)
    recommended_action = _generate_recommended_action(
        state, classification, confidence, mitre_ttp, destination
    )

    final_report = {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "classification": classification,
        "risk_level": risk_level,
        "confidence": confidence,
        "mitre_ttp": mitre_ttp,
        "recommended_action": recommended_action,
        "affected_host": affected_host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Surface the arbiter's escalation note so a human reading the final
    # report understands WHY no confident classification was reached, and
    # that risk cannot be firmly assessed until they review it. Keyed
    # ``escalation_note`` to match the frontend/API contract.
    if classification == "UNCERTAIN":
        final_report["escalation_note"] = verdict.get("escalation") or (
            "Verdict is UNCERTAIN — recommend human analyst review before the "
            "risk level is treated as settled."
        )

    print(f"[Incident Response Agent] {classification} / risk={risk_level} "
          f"/ affected_host={affected_host}")

    return {"final_report": final_report}
