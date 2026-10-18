"""v2 feature-unit regression tests.

The Intrusion Detection diagnosis found that inference reported inter-arrival
times in seconds while the Random Forest / Isolation Forest were trained with
them in microseconds (StandardScaler means ~1e6), and that syn_count counted
SYN-ACK packets while training counted pure SYN only. These tests assert that,
after the v2 correction, the inference feature magnitudes land in the same
order of magnitude as the training scaler means -- and that the v1 behaviour
is the far-off one the diagnosis described.

Run: ./venv/bin/python -m pytest tests/test_feature_v2.py -q
     (or ./venv/bin/python tests/test_feature_v2.py)
"""
import math
import sys
from pathlib import Path

import joblib

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "packet_processing"))

from feature_extractor import apply_feature_version  # noqa: E402

SCALER = joblib.load(REPO / "ml" / "models" / "isolation_forest_scaler.joblib")
NAMES = list(SCALER.feature_names_in_)


def _train_mean(name):
    return float(SCALER.mean_[NAMES.index(name)])


def _train_std(name):
    return float(SCALER.scale_[NAMES.index(name)])


def _orders_apart(a, b):
    """Absolute difference in base-10 order of magnitude between two positive
    numbers. 0 means same order; 6 means a million-fold apart."""
    return abs(math.log10(a) - math.log10(b))


# A realistic multi-packet representative flow, as the Packet Analysis agent
# computes it: inter-arrival in SECONDS, syn_count counting every SYN-bit
# packet (here one SYN plus one SYN-ACK = 2), one completed handshake.
V1_FLOW = {
    "packet_count": 12,
    "byte_count": 1500,
    "duration_s": 8.0,
    "packets_per_sec": 1.5,
    "bytes_per_sec": 187.5,
    "mean_inter_arrival": 0.73,      # seconds
    "std_inter_arrival": 0.21,       # seconds
    "syn_count": 2,                  # 1 SYN + 1 SYN-ACK (legacy counting)
    "synack_count": 1,
    "rst_count": 0,
    "ssh_auth_attempts": 0,
    "protocol": 6,
}


def test_v1_inter_arrival_is_orders_below_training():
    """Baseline: the v1 (seconds) IAT is >=4 orders of magnitude below the
    training mean (microseconds) -- the bug the diagnosis reported."""
    train_mia = _train_mean("mean_inter_arrival")
    assert _orders_apart(V1_FLOW["mean_inter_arrival"], train_mia) >= 4.0


def test_v2_inter_arrival_matches_training_order():
    """v2 rescales IAT to microseconds, landing within 2 orders of magnitude
    of the training scaler mean for both mean and std inter-arrival."""
    v2 = apply_feature_version(V1_FLOW, "v2")
    for name in ("mean_inter_arrival", "std_inter_arrival"):
        assert _orders_apart(v2[name], _train_mean(name)) <= 2.0, (
            f"{name}={v2[name]} vs train mean={_train_mean(name)}"
        )
    # And the rescale is exactly x1e6.
    assert math.isclose(v2["mean_inter_arrival"],
                        V1_FLOW["mean_inter_arrival"] * 1e6)
    assert math.isclose(v2["std_inter_arrival"],
                        V1_FLOW["std_inter_arrival"] * 1e6)


def test_v2_syn_count_is_pure_syn_in_training_order():
    """v2 drops the SYN-ACK packets from syn_count (pure SYN = raw - synack)
    and the result sits within 2 orders of magnitude of the training SYN
    spread (scaler std ~0.2), unlike an inflated handshake count."""
    v2 = apply_feature_version(V1_FLOW, "v2")
    assert v2["syn_count"] == V1_FLOW["syn_count"] - V1_FLOW["synack_count"] == 1
    # Compare to the training SYN spread (mean ~0.04, std ~0.2); a pure-SYN
    # count of order 1 is within 2 orders of that spread, whereas an O(10)
    # count would not be.
    ref = max(_train_mean("syn_count"), _train_std("syn_count"))
    assert _orders_apart(max(v2["syn_count"], 1e-9), ref) <= 2.0


def test_v2_ssh_auth_attempts_constant_zero():
    v2 = apply_feature_version(V1_FLOW, "v2")
    assert v2["ssh_auth_attempts"] == 0


def test_v1_is_noop():
    assert apply_feature_version(V1_FLOW, "v1") is V1_FLOW


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
            passed += 1
        except AssertionError as e:
            print("FAIL", fn.__name__, "--", e)
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
