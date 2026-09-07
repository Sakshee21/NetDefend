"""Dialectical Arbiter — forces both hypotheses through refutation.

STUB — replace with real logic. The real version generates a refutation
challenge against each hypothesis, feeds each challenge back to the agent
that raised it, and only then commits to ATTACK, MISCONFIGURATION or
UNCERTAIN based on which hypothesis survived.

Fan-in node: it runs once, after both the Threat Hunting Agent and the
Network Troubleshooting Agent have finished.

The verdict goes into ``arbiter_verdict``. The Incident Response Agent
reads it from there and builds the final report; the arbiter never writes
into ``final_report`` itself.
"""

from agents.state_schema import NetDefendState


def run_arbiter(state: NetDefendState) -> dict:
    """Challenge both hypotheses and commit to a verdict.

    Args:
        state: Current pipeline state; reads ``threat_hypothesis`` and
            ``misconfig_hypothesis``.

    Returns:
        Partial state update containing ``refutation_exchange`` and
        ``arbiter_verdict``.
    """
    print("[Dialectical Arbiter] running...")

    # Read both competing hypotheses. The real arbiter builds its challenges
    # from these; the stub only proves they arrived from both branches.
    threat = state.get("threat_hypothesis") or {}
    misconfig = state.get("misconfig_hypothesis") or {}

    # STUB — fixed challenges, one against each hypothesis.
    refutation_exchange = [
        {
            "challenged_agent": "threat_hunting",
            "challenge": (
                "If this were lateral movement, why did the source host make "
                "no attempt to authenticate after the 12 handshakes it did "
                "complete? A denied ACL explains the silence just as well."
            ),
            "response": (
                "The 34 RSTs rule out a silent deny rule, and the sweep "
                "covers hosts the source has never contacted before. That "
                "fan-out is discovery behaviour, not a retry loop."
            ),
        },
        {
            "challenged_agent": "troubleshooting",
            "challenge": (
                "If an ACL deny rule were responsible, every host on the "
                "subnet would fail identically. Why did 12 connections "
                "succeed?"
            ),
            "response": (
                "A partially applied rule could explain that, but no ACL "
                "change appears in the router log window. This hypothesis "
                "does not survive the challenge."
            ),
        },
    ]

    # STUB — fixed verdict; the real arbiter derives this from which
    # hypothesis withstood refutation.
    arbiter_verdict = {
        "classification": "ATTACK",
        "confidence": 0.81,
    }

    print(
        f"[Dialectical Arbiter] verdict: {arbiter_verdict['classification']} "
        f"(threat summary present: {bool(threat)}, "
        f"misconfig summary present: {bool(misconfig)})"
    )

    return {
        "refutation_exchange": refutation_exchange,
        "arbiter_verdict": arbiter_verdict,
    }
