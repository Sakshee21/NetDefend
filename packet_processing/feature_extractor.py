import numpy as np


def apply_feature_version(features, version):
    """Apply versioned corrections to ONE flow's feature dict.

    v1 -- returns the features unchanged. This is the legacy behaviour that
    produced the committed cache/results, so default runs are unaffected.

    v2 -- aligns the inference features to the CICIDS2017 training units
    identified in the Intrusion Detection diagnosis:
      * mean_inter_arrival / std_inter_arrival: computed in SECONDS here but
        trained in MICROSECONDS, so they are multiplied by 1e6 to match the
        training scaler means (~1e6).
      * syn_count: trained as "SYN flag set AND ACK not set" (pure SYN), but
        the legacy flow counter also counted SYN-ACK packets; recompute it as
        (raw SYN count - SYN-ACK count), clamped at zero.
      * ssh_auth_attempts: left at a constant 0 -- a documented dead feature
        (never populated at training or inference).

    Returns a shallow copy with only the four model-fed fields adjusted; every
    other key (protocol, context fields) is preserved. Applied only to the
    already-selected representative flow, so upstream flow selection -- which
    reads the un-transformed flows -- is unaffected.
    """
    if version != "v2":
        return features
    f = dict(features)
    f["mean_inter_arrival"] = float(f.get("mean_inter_arrival", 0) or 0) * 1e6
    f["std_inter_arrival"] = float(f.get("std_inter_arrival", 0) or 0) * 1e6
    raw_syn = float(f.get("syn_count", 0) or 0)
    synack = float(f.get("synack_count", 0) or 0)
    f["syn_count"] = max(raw_syn - synack, 0.0)
    f["ssh_auth_attempts"] = 0
    return f


def calculate_features(flows):

    feature_list = []

    for flow in flows.values():

        # --------------------------------
        # Duration
        # --------------------------------

        duration = (
            flow["last_timestamp"]
            - flow["first_timestamp"]
        )

        if duration < 0:
            duration = 0

        # --------------------------------
        # Packet rate
        # --------------------------------

        if duration > 0:

            packets_per_sec = (
                flow["packet_count"] / duration
            )

            bytes_per_sec = (
                flow["byte_count"] / duration
            )

        else:

            packets_per_sec = 0

            bytes_per_sec = 0

        # --------------------------------
        # Inter-arrival time
        # --------------------------------

        timestamps = sorted(
            flow["timestamps"]
        )

        if len(timestamps) > 1:

            inter_arrivals = np.diff(
                timestamps
            )

            mean_inter_arrival = float(
                np.mean(inter_arrivals)
            )

            std_inter_arrival = float(
                np.std(inter_arrivals)
            )

        else:

            mean_inter_arrival = 0

            std_inter_arrival = 0

        # --------------------------------
        # Create feature row
        # --------------------------------

        features = {

            "packet_count":
                flow["packet_count"],

            "byte_count":
                flow["byte_count"],

            "duration_s":
                duration,

            "packets_per_sec":
                packets_per_sec,

            "bytes_per_sec":
                bytes_per_sec,

            "mean_inter_arrival":
                mean_inter_arrival,

            "std_inter_arrival":
                std_inter_arrival,

            "syn_count":
                flow["syn_count"],

            "synack_count":
                flow["synack_count"],

            "rst_count":
                flow["rst_count"],

            # Not available yet
            # Will be enriched later
            "ssh_auth_attempts":
                0,

            # RAW IANA protocol number
            "protocol":
                flow["protocol"]
        }

        feature_list.append(features)

    return feature_list