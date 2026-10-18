# """Network Troubleshooting Agent — builds the misconfiguration-side hypothesis.

# STUB — replace with real logic. The real version prompts the LLM with the
# packet features plus the router/firewall logs at state["log_path"], and
# classifies the result against knowledge/misconfigurations/taxonomy.json.

# Runs in parallel with the Threat Hunting Agent. It writes only the
# misconfiguration-side keys, so the two branches never touch the same field.
# """

# from agents.state_schema import NetDefendState


# def run_troubleshooting_agent(state: NetDefendState) -> dict:
#     """Propose a misconfiguration hypothesis for the same anomaly.

#     Args:
#         state: Current pipeline state; reads ``packet_features`` and
#             ``log_path``.

#     Returns:
#         Partial state update containing ``is_misconfiguration``,
#         ``misconfig_reasoning`` and ``misconfig_hypothesis``.
#     """
#     print("[Network Troubleshooting Agent] running...")

#     # STUB — fixed ACL hypothesis, no LLM call and no log parsing.
#     is_misconfiguration = 0.34

#     misconfig_reasoning = (
#         "An ACL change on the core switch could produce the same unanswered "
#         "SYN pattern: if TCP/445 is newly denied, a legitimate backup agent "
#         "would retry across every host it serves and receive nothing back. "
#         "The absence of RSTs is consistent with a silent deny rule, but the "
#         "34 observed RSTs and the fresh source host weaken this reading."
#     )

#     misconfig_hypothesis = {
#         "summary": (
#             "A recently applied ACL deny rule on TCP/445 is causing a "
#             "legitimate service to retry connections across the subnet."
#         ),
#         "taxonomy_category": "acl_misconfiguration",
#         "evidence": [
#             "Unanswered SYNs are the signature of a silent drop, not a refusal",
#             "Fan-out pattern matches a backup agent's normal host list",
#             "No payload was exchanged on any completed connection",
#         ],
#     }

#     return {
#         "is_misconfiguration": is_misconfiguration,
#         "misconfig_reasoning": misconfig_reasoning,
#         "misconfig_hypothesis": misconfig_hypothesis,
#     }

import json
import os
from pathlib import Path

from agents.llm_client import call_llm, parse_json_response
from agents.state_schema import NetDefendState
from agents.config import get_reasoning_version
from agents import grounding

# v2 reasoning sentinel: a misconfiguration hypothesis that cites no concrete
# configuration artifact present in the evidence is replaced by this null
# hypothesis, which the arbiter is not allowed to let win.
NO_MISCONFIG_EVIDENCE = "NO_MISCONFIG_EVIDENCE"


# ======================================================
# LLM CONFIGURATION
# ======================================================

# Groq via the shared agents/llm_client.py -- the same client the Threat
# Hunting Agent uses. Cloud inference answers in seconds, so a short
# timeout is plenty.
#
# Model: MODEL_NAME_LIGHT (openai/gpt-oss-20b), not the MODEL_NAME_HEAVY
# the Threat Hunting Agent uses. On this prompt, gpt-oss-120b in JSON mode
# intermittently emitted an invalid number token ("confidence": 0. nine)
# and failed Groq's JSON validation on roughly a third of attempts, while
# gpt-oss-20b and qwen3.8-27b each returned valid JSON on 6/6 calls.
# llm_client is imported above, which has already loaded .env.
GROQ_MODEL = os.environ.get("MODEL_NAME_LIGHT", "openai/gpt-oss-20b")
GROQ_TIMEOUT_S = 30
LLM_MAX_ATTEMPTS = 2


# ======================================================
# TROUBLESHOOTING AGENT ROLE
# ======================================================

SYSTEM_PROMPT = """

You are the Network Troubleshooting Agent in NetDefend,
a multi-agent network security system.

Your responsibility is to investigate whether an observed
network problem can be explained by a legitimate network,
configuration, or operational problem.

You represent the MISCONFIGURATION side of a dialectical
security analysis.

A separate Threat Hunting Agent independently investigates
whether the same incident could represent malicious activity.

You must NOT make the final security decision.

Your job is to construct the strongest troubleshooting
hypothesis based ONLY on the evidence provided.

--------------------------------------------------
EVIDENCE YOU MAY CONSIDER
--------------------------------------------------

You may consider:

- network flow observations
- IP addresses
- protocols
- ports
- packet behaviour
- Random Forest predictions
- Isolation Forest results
- firewall rules
- ACL rules
- routing configuration
- DNS configuration
- NAT configuration
- service configuration
- network/system logs
- correlations between traffic and configuration

--------------------------------------------------
POSSIBLE HYPOTHESES
--------------------------------------------------

Your hypothesis must be exactly one of:

MISCONFIGURATION
NO_CLEAR_MISCONFIGURATION
UNCERTAIN

--------------------------------------------------
IMPORTANT REASONING RULES
--------------------------------------------------

1. Do NOT automatically classify an incident as an attack.

2. Do NOT automatically classify an incident as a
   misconfiguration.

3. Use ONLY evidence present in the incident evidence.

4. NEVER invent firewall rules, routing entries,
   DNS records, logs, IP addresses, ports, or other facts.

5. Clearly distinguish observed evidence from your reasoning.

6. If the evidence is insufficient, use UNCERTAIN.

7. Do NOT use ground-truth labels to make your decision.

8. Random Forest and Isolation Forest results are evidence.
   They are NOT the final answer.

9. A benign Random Forest prediction does NOT prove that
   a network configuration is correct.

10. A normal Isolation Forest result does NOT prove that
    a network configuration is correct.

11. Configuration evidence can explain an operational
    network problem even when the ML models classify
    the traffic as benign or normal.

12. If a configuration rule directly matches the affected
    traffic and can explain the observed problem, this
    is strong evidence supporting MISCONFIGURATION.

--------------------------------------------------
CRITICAL EVIDENCE CONSISTENCY RULES
--------------------------------------------------

You MUST NOT contradict explicit evidence.

For example, if the evidence says:

"traffic_matches_firewall_rule": true

you MUST treat this as a factual derived observation.

Do NOT claim that the firewall rule does not match.

If the evidence says:

"total_syn_packets": 13

you MUST NOT claim that there are zero SYN packets.

Do NOT reinterpret aggregate statistics as
incident-specific observations unless the evidence
explicitly establishes that relationship.

When correlation evidence is provided, prioritize it
when determining whether a configuration can explain
the observed problem.

--------------------------------------------------
MISCONFIGURATION CATEGORIES
--------------------------------------------------

If the hypothesis is MISCONFIGURATION, select the most
appropriate category:

ACL_FIREWALL
DNS
ROUTING
NAT
SERVICE
OTHER

If the hypothesis is:

NO_CLEAR_MISCONFIGURATION

or:

UNCERTAIN

then:

misconfiguration_type = "NONE"

--------------------------------------------------
OUTPUT FORMAT
--------------------------------------------------

Return ONLY valid JSON.

Use exactly this structure:

{
    "agent": "Network Troubleshooting Agent",

    "hypothesis": "MISCONFIGURATION",

    "misconfiguration_type": "ACL_FIREWALL",

    "confidence": 0.0,

    "problem": "...",

    "evidence": [
        "...",
        "..."
    ],

    "reasoning": "...",

    "recommended_action": "..."
}

The confidence must be between 0.0 and 1.0.

Do not include markdown.

Do not include explanations outside the JSON.

"""


# ======================================================
# CALL LLM
# ======================================================

def investigate(incident_evidence):

    user_prompt = """

Investigate the following network incident.

Read ALL of the evidence carefully.

Determine whether a network or operational
misconfiguration provides a reasonable explanation
for the observed problem.

Pay particular attention to:

1. Incident context
2. Network observations
3. ML evidence
4. Configuration evidence
5. Correlation evidence

Do not assume that a firewall rule is a
misconfiguration merely because it exists.

However, if the rule directly matches the affected
traffic AND explains the observed problem, treat this
as strong evidence for MISCONFIGURATION.

INCIDENT EVIDENCE:

""" + json.dumps(
        incident_evidence,
        indent=4
    )

    # Two failure modes are retried: the model occasionally emits an invalid
    # number token (observed: "confidence": 0. nine) which Groq's JSON mode
    # rejects with a 400, and about 1 call in 6 returns valid JSON with a
    # blank "reasoning" field. A call takes ~3s, so one retry is cheap; if
    # every attempt fails the last error is re-raised and
    # run_troubleshooting_agent()'s existing except-branch reports the
    # honest "unavailable" fallback rather than a result with no reasoning.
    last_exc = None
    for attempt in range(1, LLM_MAX_ATTEMPTS + 1):
        try:
            raw = call_llm(
                user_prompt,
                system=SYSTEM_PROMPT,
                timeout=GROQ_TIMEOUT_S,
                model=GROQ_MODEL,
                json_mode=True,  # replaces Ollama's "format": "json"
            )
            # parse_json_response() returns {} on unparseable output;
            # raise instead so it counts as a failed attempt.
            parsed = parse_json_response(raw)
            if not parsed:
                raise ValueError(f"LLM returned malformed or non-JSON output: {raw[:200]!r}")
            if not str(parsed.get("reasoning") or "").strip():
                raise ValueError("LLM returned valid JSON but an empty reasoning field")
            return parsed
        except Exception as exc:  # noqa: BLE001 -- retried, then re-raised below
            last_exc = exc
            print(f"[Network Troubleshooting Agent] LLM attempt "
                  f"{attempt}/{LLM_MAX_ATTEMPTS} failed: {str(exc)[:160]}")
    raise last_exc


# ======================================================
# STATE SCHEMA WRAPPER
# ======================================================
#
# investigate() and SYSTEM_PROMPT above are the real agent logic and are
# untouched by this section. Everything below just adapts them to the
# NetDefendState contract graph.py imports: build the incident evidence
# investigate() expects out of the pipeline state, call it, and map its
# JSON response onto the state keys other agents/the arbiter read.

_KNOWN_HYPOTHESES = {"MISCONFIGURATION", "NO_CLEAR_MISCONFIGURATION", "UNCERTAIN"}

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# Returned when the Groq call itself never produced a usable answer
# (bad key, network error, malformed/non-JSON response, empty reasoning,
# unrecognized hypothesis value, etc.) -- NOT a genuine "probably not a
# misconfiguration" reading. is_misconfiguration=0.0 here means "the
# agent has no opinion", not "confidently ruled out", so this should be
# treated as missing evidence by anything downstream, the same
# distinction llm_call_failed makes for the Threat Hunting Agent.
_FALLBACK_RESULT = {
    "is_misconfiguration": 0.0,
    "misconfig_reasoning": (
        "Network Troubleshooting Agent could not complete its analysis -- "
        "the Groq call failed or returned an unusable response. This is "
        "NOT evidence against a misconfiguration; the agent simply never "
        "produced a real answer. See logs for the underlying error."
    ),
    "misconfig_hypothesis": {
        "summary": "Troubleshooting analysis unavailable (Groq call failed).",
        # Matched exactly by frontend/src/components/HypothesesView.jsx --
        # change both together.
        "taxonomy_category": "LLM_UNAVAILABLE",
        "evidence": ["Groq call failed or returned an unusable response -- see logs."],
    },
}


def _build_incident_evidence(state: NetDefendState) -> dict:
    """Build the incident evidence dict investigate()'s prompt expects,
    from pipeline state instead of the hardcoded incident_evidence.json
    main() reads. Mirrors the shape agents/evidence_builder.py produces
    (network_observation / ml_evidence / configuration_evidence /
    log_evidence / context) so the prompt's evidence categories line up
    with what the SYSTEM_PROMPT tells the LLM it may consider.

    Known gaps, passed through honestly rather than faked:
      - packet_features (see agents/packet_agent.py) carries only the
        source/"top talker" IP and destination port for the selected
        flow -- no destination-IP field is extracted yet, so none is
        reported here.
      - There is no structured parser yet for router/firewall/DNS/NAT
        config out of state["log_path"] (no log-side equivalent of
        packet_processing/feature_extractor.py). Until one exists, the
        raw log text is passed through as-is under log_evidence so the
        LLM can read firewall/ACL/DNS/routing/NAT lines directly,
        instead of fabricating structured fields (firewall_rule,
        rule_effect, ...) that nothing actually extracted.
      - For the same reason, there's no automated correlation_evidence
        (e.g. "traffic_matches_firewall_rule") -- the SYSTEM_PROMPT
        already tells the LLM it may reason about correlations between
        traffic and configuration itself from network_observation +
        log_evidence, so this isn't required for it to do its job.

    cross_flow_evidence is new: aggregate evidence across every flow in
    the capture (see agents/packet_agent.py's _compute_cross_flow_pattern()),
    kept as its own top-level key rather than folded into
    network_observation so it stays visibly distinct from that single
    representative flow's numbers -- e.g. "10 blocked SYNs to the same
    destination across 10 separate flows" versus "this one flow saw 2".
    """
    packet_features = state.get("packet_features") or {}
    ml_prediction = state.get("ml_prediction") or {}
    cross_flow_pattern = state.get("cross_flow_pattern") or {}
    log_path = state.get("log_path")

    protocol_raw = packet_features.get("protocol")
    try:
        protocol_name = _PROTOCOL_NAMES.get(int(protocol_raw), f"Protocol {protocol_raw}")
    except (TypeError, ValueError):
        protocol_name = None

    # Values are grouped so the LLM cannot mistake one representative flow's
    # numbers for capture-wide behaviour. Numbers are unchanged from before;
    # only the labelling/grouping and the scope note are added.
    representative_flow = {
        "packet_count": packet_features.get("packet_count"),
        "byte_count": packet_features.get("byte_count"),
        "duration_s": packet_features.get("duration_s"),
        "packets_per_sec": packet_features.get("packets_per_sec"),
        "bytes_per_sec": packet_features.get("bytes_per_sec"),
        "syn_count": packet_features.get("syn_count"),
        "synack_count": packet_features.get("synack_count"),
        "rst_count": packet_features.get("rst_count"),
        "protocol": protocol_name,
    }
    # source_ip / destination_port fidelity. Under v2, prefer the selected
    # flow's own 5-tuple (now re-attached in the packet agent), fall back to
    # the cross-flow subject_source and the cross-flow destination port, and
    # OMIT the field entirely when genuinely unrecoverable -- never report a
    # misleading null. v1 keeps the original behaviour (always include, even
    # when null).
    if get_reasoning_version() == "v2":
        src_ip = packet_features.get("top_talker_ip") or cross_flow_pattern.get("subject_source")
        dst_port = packet_features.get("top_dst_port")
        if not dst_port:
            dst_port = (cross_flow_pattern.get("destination") or {}).get("port")
        if src_ip:
            representative_flow["source_ip"] = src_ip
        if dst_port:
            representative_flow["destination_port"] = dst_port
    else:
        representative_flow["source_ip"] = packet_features.get("top_talker_ip")
        representative_flow["destination_port"] = packet_features.get("top_dst_port")
    network_observation = {
        "scope_note": (
            "The fields under 'representative_flow' describe ONE flow selected "
            "from the capture; the fields under 'capture_wide' summarise all "
            "flows. The ML models (see ml_evidence) score ONLY the "
            "representative flow, not the cross-flow behaviour reported under "
            "'cross_flow_evidence'."
        ),
        "representative_flow": representative_flow,
        "capture_wide": {
            "flow_count": packet_features.get("flow_count"),
        },
    }

    ml_evidence = {
        "random_forest": {
            "predicted_class": ml_prediction.get("predicted_class"),
            "attack_probability": ml_prediction.get("attack_probability"),
        },
        "isolation_forest": {
            "anomaly_score": ml_prediction.get("anomaly_score"),
        },
    }

    log_evidence = {}
    if log_path and Path(log_path).exists():
        raw_log = Path(log_path).read_text(encoding="utf-8", errors="replace")
        log_evidence["raw_log_excerpt"] = raw_log[-4000:]  # bound prompt size
        print(f"[Network Troubleshooting Agent] log evidence loaded from "
              f"{log_path} ({len(raw_log)} bytes)")
    else:
        # Neutral note only -- never echo the log_path into the prompt, since a
        # scenario-named path (e.g. acl_misconfig_B...) would leak the label.
        log_evidence["note"] = "no log evidence available"
        print(f"[Network Troubleshooting Agent] WARNING: log_path not found: {log_path!r}")

    context = {
        "source_ip": packet_features.get("top_talker_ip"),
        "destination_port": packet_features.get("top_dst_port"),
        "protocol": protocol_name,
    }

    bundle = {
        "network_observation": network_observation,
        "cross_flow_evidence": cross_flow_pattern,
        "ml_evidence": ml_evidence,
        "configuration_evidence": {},
        "log_evidence": log_evidence,
        "context": context,
    }

    # v2 reasoning: when the captured firewall ruleset has no custom rules,
    # state that neutrally and factually, without interpreting what it means
    # for the verdict. v1 leaves configuration_evidence empty as before.
    if get_reasoning_version() == "v2" and grounding.ruleset_has_no_custom_rules(bundle):
        bundle["configuration_evidence"] = {
            "firewall_ruleset": "default ACCEPT only, no custom rules",
        }

    return bundle


def _hypothesis_to_score(hypothesis: str, confidence: float) -> float:
    """Map the LLM's categorical hypothesis plus its own confidence onto
    the single is_misconfiguration float NetDefendState expects.

    - MISCONFIGURATION: the LLM's confidence already means "confidence
      this IS a misconfiguration" -- used directly.
    - NO_CLEAR_MISCONFIGURATION: the LLM's confidence means "confidence
      this is NOT a misconfiguration" -- inverted, so a confident "no"
      produces a low is_misconfiguration score.
    - UNCERTAIN: the hypothesis itself already says the evidence didn't
      clearly resolve either way, so this returns a fixed 0.5 rather
      than reinterpreting the LLM's confidence field, which isn't
      scoped to mean anything specific in this branch.
    """
    confidence = max(0.0, min(1.0, confidence))
    if hypothesis == "MISCONFIGURATION":
        return confidence
    if hypothesis == "NO_CLEAR_MISCONFIGURATION":
        return 1.0 - confidence
    return 0.5  # UNCERTAIN


def _apply_v2_reasoning(result: dict, hypothesis: str, incident_evidence: dict) -> dict:
    """v2 reasoning post-processing for the misconfiguration hypothesis:

    (2) Grounding validator: drop every cited evidence item that quotes a
        concrete value absent from the evidence bundle, record how many were
        dropped, and flag the run if any were.
    (1) Null-hypothesis rule (bundle-based): the misconfiguration hypothesis is
        null -- which the arbiter is not allowed to let win -- if, and only if,
        the evidence bundle itself contains NO configuration artifact (no
        custom firewall rule, no log / LOG-target line, no resolver/DNS setting
        beyond defaults). When the bundle DOES contain an artifact the
        hypothesis is not nulled even if the agent returned
        NO_CLEAR_MISCONFIGURATION or UNCERTAIN, and the debate runs as in v1.
        ``hypothesis`` is recorded for context but does not drive the decision.

    Returns the updated result dict with a ``misconfig_grounding`` block.
    """
    mh = result["misconfig_hypothesis"]
    kept, dropped_n, dropped_items = grounding.validate_items(
        mh.get("evidence", []), incident_evidence)
    mh["evidence"] = kept

    if grounding.bundle_has_config_artifact(incident_evidence):
        null_hypothesis = False
        null_reason = None
    else:
        null_hypothesis = True
        null_reason = (
            "v2 null rule: the evidence bundle contains no configuration "
            "artifact (no custom firewall rule, log/LOG-target line, or "
            "resolver/DNS setting beyond defaults), so the misconfiguration "
            "hypothesis has nothing to rest on and is recorded as a null "
            "hypothesis that cannot win adjudication. (Agent hypothesis was %s.)"
            % hypothesis
        )

    if null_hypothesis:
        result["misconfig_hypothesis"] = {
            "summary": ("No misconfiguration evidence: the agent did not claim "
                        "a grounded misconfiguration for this incident."),
            "taxonomy_category": NO_MISCONFIG_EVIDENCE,
            "evidence": [],
            "null_hypothesis": True,
        }
        # A null hypothesis carries no misconfiguration support.
        result["is_misconfiguration"] = 0.0
        result["misconfig_reasoning"] = null_reason

    result["misconfig_grounding"] = {
        "evidence_dropped": dropped_n,
        "flagged": dropped_n > 0,
        "null_hypothesis": null_hypothesis,
        # The verbatim text of each dropped (ungrounded) evidence item.
        "dropped_items": dropped_items,
    }
    return result


def run_troubleshooting_agent(state: NetDefendState) -> dict:
    """Propose a misconfiguration hypothesis for the same anomaly.

    Args:
        state: Current pipeline state; reads ``packet_features``,
            ``ml_prediction``, and ``log_path``.

    Returns:
        Partial state update containing ``is_misconfiguration``,
        ``misconfig_reasoning`` and ``misconfig_hypothesis``.
    """
    print("[Network Troubleshooting Agent] running...")

    incident_evidence = _build_incident_evidence(state)

    # Whether any firewall/evidence file was actually supplied for this
    # incident (not just whether it had custom rules). Used by the arbiter
    # under v2 to add the "no configuration evidence supplied" note and cap
    # confidence; it does not change the null gate (an empty bundle is still
    # null). Absent evidence -> the log_evidence note is set, not a raw excerpt.
    log_evidence = incident_evidence.get("log_evidence") or {}
    config_evidence_supplied = bool(log_evidence.get("raw_log_excerpt"))

    try:
        llm_result = investigate(incident_evidence)

        hypothesis = llm_result["hypothesis"]
        if hypothesis not in _KNOWN_HYPOTHESES:
            raise ValueError(f"unrecognized hypothesis value: {hypothesis!r}")

        confidence = float(llm_result.get("confidence", 0.5))
        is_misconfiguration = _hypothesis_to_score(hypothesis, confidence)

        misconfig_reasoning = llm_result.get("reasoning", "")

        misconfig_hypothesis = {
            "summary": llm_result.get("problem", ""),
            "taxonomy_category": llm_result.get("misconfiguration_type", "NONE"),
            "evidence": llm_result.get("evidence", []),
        }

        result = {
            "is_misconfiguration": is_misconfiguration,
            "misconfig_reasoning": misconfig_reasoning,
            "misconfig_hypothesis": misconfig_hypothesis,
        }

        if get_reasoning_version() == "v2":
            result = _apply_v2_reasoning(result, hypothesis, incident_evidence)
        result["config_evidence_supplied"] = config_evidence_supplied

        mh = result["misconfig_hypothesis"]
        print(f"[Network Troubleshooting Agent] hypothesis={hypothesis} "
              f"confidence={confidence:.2f} -> "
              f"is_misconfiguration={result['is_misconfiguration']:.2f}"
              f"{' [NULL: no config artifact]' if mh.get('null_hypothesis') else ''}"
              f"{'' if config_evidence_supplied else ' [no config evidence supplied]'}")

        return result

    except Exception as exc:  # noqa: BLE001 -- degrade gracefully, don't crash the pipeline
        print(f"[Network Troubleshooting Agent] Groq call failed: {exc}")
        fallback = dict(_FALLBACK_RESULT)
        fallback["config_evidence_supplied"] = config_evidence_supplied
        return fallback


# ======================================================
# MAIN
# ======================================================

def main():

    evidence_file = (
        "agents/incident_evidence.json"
    )

    with open(
        evidence_file,
        "r"
    ) as f:

        incident_evidence = json.load(f)

    result = investigate(
        incident_evidence
    )

    print(
        "\n========================================"
    )

    print(
        "NETWORK TROUBLESHOOTING AGENT"
    )

    print(
        "========================================\n"
    )

    print(
        json.dumps(
            result,
            indent=4
        )
    )


if __name__ == "__main__":
    main()