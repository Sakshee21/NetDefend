import numpy as np


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