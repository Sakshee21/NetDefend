"""Intrusion Detection Agent.

Loads the trained Random Forest and Isolation Forest models and scores the
feature vector produced by the Packet Analysis Agent. The two model outputs
stay separate on purpose: ``predicted_class``/``attack_probability`` come
from the Random Forest, ``anomaly_score`` from the Isolation Forest. They
are downstream evidence, not a single merged score.

INPUT CONTRACT: state["packet_features"] must be a SINGLE flow's feature
dict (one 5-tuple conversation), not an aggregate/average across the whole
PCAP. Both models were trained on CICIDS2017 where each row is exactly one
flow -- feeding aggregated/averaged statistics across multiple flows will
run without error but produce meaningless predictions, since aggregate
feature distributions differ entirely from per-flow ones. Expected keys:
    packet_count, byte_count, duration_s, packets_per_sec, bytes_per_sec,
    mean_inter_arrival, std_inter_arrival, syn_count, synack_count,
    rst_count, ssh_auth_attempts, protocol (IANA number as string, e.g. "6")
"""
from pathlib import Path

import joblib
import pandas as pd

from agents.state_schema import NetDefendState

MODEL_DIR = Path(__file__).resolve().parent.parent / "ml" / "models"
FEATURE_COLUMNS = [
    "packet_count", "byte_count", "duration_s", "packets_per_sec",
    "bytes_per_sec", "mean_inter_arrival", "std_inter_arrival",
    "syn_count", "synack_count", "rst_count", "ssh_auth_attempts",
]

# Lazy-loaded module-level cache so models are read from disk once per
# process, not once per graph invocation.
_clf = None
_proto_encoder = None
_label_encoder = None
_iso_forest = None
_iso_scaler = None


def _load_models() -> None:
    global _clf, _proto_encoder, _label_encoder, _iso_forest, _iso_scaler
    if _clf is not None:
        return  # already loaded

    _clf = joblib.load(MODEL_DIR / "rf_intrusion_detector.joblib")
    _proto_encoder = joblib.load(MODEL_DIR / "protocol_encoder.joblib")
    _label_encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")

    iso_path = MODEL_DIR / "isolation_forest.joblib"
    scaler_path = MODEL_DIR / "isolation_forest_scaler.joblib"
    if iso_path.exists() and scaler_path.exists():
        _iso_forest = joblib.load(iso_path)
        _iso_scaler = joblib.load(scaler_path)


def _build_feature_row(packet_features: dict) -> pd.DataFrame:
    """Turns one packet_features dict into the (1, 12) matrix both models
    expect, applying the same protocol-encoding fallback used at training
    time for values the encoder never saw."""
    row = {col: packet_features.get(col, 0) for col in FEATURE_COLUMNS}
    df = pd.DataFrame([row])

    protocol_value = str(packet_features.get("protocol", _proto_encoder.classes_[0]))
    known = set(_proto_encoder.classes_)
    safe_protocol = protocol_value if protocol_value in known else _proto_encoder.classes_[0]
    df["protocol_enc"] = _proto_encoder.transform([safe_protocol])

    return df[FEATURE_COLUMNS + ["protocol_enc"]]


def run_intrusion_agent(state: NetDefendState) -> dict:
    """Score packet features with the supervised and anomaly models.

    Args:
        state: Current pipeline state; reads ``packet_features``.

    Returns:
        Partial state update containing ``ml_prediction``.
    """
    print("[Intrusion Detection Agent] running...")

    packet_features = state.get("packet_features")
    if not packet_features:
        print("[Intrusion Detection Agent] no packet_features in state, skipping.")
        return {"ml_prediction": {
            "attack_probability": 0.0,
            "predicted_class": "Unknown",
            "anomaly_score": None,
        }}

    _load_models()
    X = _build_feature_row(packet_features)

    # Random Forest: supervised classification -> predicted_class + attack_probability
    probs = _clf.predict_proba(X)[0]
    pred_idx = probs.argmax()
    predicted_class = str(_label_encoder.inverse_transform([pred_idx])[0])

    benign_labels = {"Benign", "BENIGN", "benign", "Normal", "normal"}
    if predicted_class in benign_labels:
        # attack_probability = confidence the flow is NOT benign
        benign_idx = list(_label_encoder.classes_).index(predicted_class)
        attack_probability = float(1.0 - probs[benign_idx])
    else:
        attack_probability = float(probs[pred_idx])

    # Isolation Forest: unsupervised anomaly score, kept separate.
    # sklearn convention: negative score = more anomalous, positive = more normal.
    anomaly_score = None
    if _iso_forest is not None and _iso_scaler is not None:
        X_scaled = _iso_scaler.transform(X)
        anomaly_score = float(_iso_forest.decision_function(X_scaled)[0])

    ml_prediction = {
        "attack_probability": attack_probability,
        "predicted_class": predicted_class,
        "anomaly_score": anomaly_score,
    }

    print(f"[Intrusion Detection Agent] predicted_class={predicted_class}, "
          f"attack_probability={attack_probability:.2f}, anomaly_score={anomaly_score}")

    return {"ml_prediction": ml_prediction}
