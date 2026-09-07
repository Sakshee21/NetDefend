"""Network Troubleshooting Agent — builds the misconfiguration-side hypothesis.

STUB — replace with real logic. The real version prompts the LLM with the
packet features plus the router/firewall logs at state["log_path"], and
classifies the result against knowledge/misconfigurations/taxonomy.json.

Runs in parallel with the Threat Hunting Agent. It writes only the
misconfiguration-side keys, so the two branches never touch the same field.
"""

from agents.state_schema import NetDefendState


def run_troubleshooting_agent(state: NetDefendState) -> dict:
    """Propose a misconfiguration hypothesis for the same anomaly.

    Args:
        state: Current pipeline state; reads ``packet_features`` and
            ``log_path``.

    Returns:
        Partial state update containing ``is_misconfiguration``,
        ``misconfig_reasoning`` and ``misconfig_hypothesis``.
    """
    print("[Network Troubleshooting Agent] running...")

    # STUB — fixed ACL hypothesis, no LLM call and no log parsing.
    is_misconfiguration = 0.34

    misconfig_reasoning = (
        "An ACL change on the core switch could produce the same unanswered "
        "SYN pattern: if TCP/445 is newly denied, a legitimate backup agent "
        "would retry across every host it serves and receive nothing back. "
        "The absence of RSTs is consistent with a silent deny rule, but the "
        "34 observed RSTs and the fresh source host weaken this reading."
    )

    misconfig_hypothesis = {
        "summary": (
            "A recently applied ACL deny rule on TCP/445 is causing a "
            "legitimate service to retry connections across the subnet."
        ),
        "taxonomy_category": "acl_misconfiguration",
        "evidence": [
            "Unanswered SYNs are the signature of a silent drop, not a refusal",
            "Fan-out pattern matches a backup agent's normal host list",
            "No payload was exchanged on any completed connection",
        ],
    }

    return {
        "is_misconfiguration": is_misconfiguration,
        "misconfig_reasoning": misconfig_reasoning,
        "misconfig_hypothesis": misconfig_hypothesis,
    }
