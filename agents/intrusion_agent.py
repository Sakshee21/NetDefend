"""Intrusion Detection Agent.

STUB — replace with real logic. The real version loads the trained Random
Forest and Isolation Forest models and scores the feature vector produced by
the Packet Analysis Agent. The two model outputs stay separate on purpose:
``predicted_class``/``attack_probability`` come from the Random Forest,
``anomaly_score`` from the Isolation Forest. They are downstream evidence,
not a single merged score.
"""

from agents.state_schema import NetDefendState


def run_intrusion_agent(state: NetDefendState) -> dict:
    """Score packet features with the supervised and anomaly models.

    Args:
        state: Current pipeline state; reads ``packet_features``.

    Returns:
        Partial state update containing ``ml_prediction``.
    """
    print("[Intrusion Detection Agent] running...")

    # STUB — no model is loaded; these are fixed stand-in scores.
    ml_prediction = {
        "attack_probability": 0.87,
        "predicted_class": "Infiltration",
        "anomaly_score": -0.42,
    }

    return {"ml_prediction": ml_prediction}
