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
import requests


# ======================================================
# LLM CONFIGURATION
# ======================================================

OLLAMA_URL = "http://localhost:11434/api/generate"

MODEL = "qwen2.5:7b"


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

    payload = {

        "model": MODEL,

        "prompt":
            SYSTEM_PROMPT +
            "\n\n" +
            user_prompt,

        "stream": False,

        "format": "json"
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=300
    )

    response.raise_for_status()

    result = response.json()

    return json.loads(
        result["response"]
    )


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