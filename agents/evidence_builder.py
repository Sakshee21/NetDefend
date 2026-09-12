# import json
# import pandas as pd
# from pathlib import Path


# class EvidenceBuilder:

#     def __init__(self, flow_file):
#         self.flow_file = Path(flow_file)

#     def load_flows(self):
#         return pd.read_csv(self.flow_file)
    

#     def protocol_name(protocol):

#         protocol_map = {
#             6: "TCP",
#             17: "UDP",
#             1: "ICMP",
#             58: "ICMPv6"
#         }

#         return protocol_map.get(
#             int(protocol),
#             f"Protocol {protocol}"
#         )
    
#     def summarize_flows(self, df):

#         evidence = {
#             "flow_count": int(len(df)),
#             "total_packets": int(df["packet_count"].sum()),
#             "total_bytes": int(df["byte_count"].sum()),

#             # "protocols": (
#             #     df["protocol"]
#             #     .dropna()
#             #     .unique()
#             #     .tolist()
#             # ),
#             "protocols": [
#                 self.protocol_name(p)
#                 for p in df["protocol"].dropna().unique()
#             ],

#             "total_syn_packets": int(
#                 df["syn_count"].sum()
#             ),

#             "total_synack_packets": int(
#                 df["synack_count"].sum()
#             ),

#             "total_rst_packets": int(
#                 df["rst_count"].sum()
#             ),

#             "average_packets_per_sec": float(
#                 df["packets_per_sec"].mean()
#             ),

#             "average_bytes_per_sec": float(
#                 df["bytes_per_sec"].mean()
#             ),

#             "average_flow_duration_s": float(
#                 df["duration_s"].mean()
#             )
#         }

#         return evidence

#     # def summarize_flows(self, df):

#     #     evidence = {
#     #         "flow_count": len(df),
#     #         "total_packets": int(df["packet_count"].sum()),
#     #         "total_bytes": int(df["byte_count"].sum())
#     #     }

#     #     # Unique source/destination information
#     #     if "src_ip" in df.columns:
#     #         evidence["source_ips"] = (
#     #             df["src_ip"]
#     #             .dropna()
#     #             .unique()
#     #             .tolist()
#     #         )

#     #     if "dst_ip" in df.columns:
#     #         evidence["destination_ips"] = (
#     #             df["dst_ip"]
#     #             .dropna()
#     #             .unique()
#     #             .tolist()
#     #         )

#     #     if "dst_port" in df.columns:
#     #         evidence["destination_ports"] = (
#     #             df["dst_port"]
#     #             .dropna()
#     #             .unique()
#     #             .tolist()
#     #         )

#     #     return evidence

#     # def build(
#     #     self,
#     #     ml_results=None,
#     #     configuration=None,
#     #     logs=None,
#     #     metadata=None
#     # ):

#     #     df = self.load_flows()

#     #     evidence = {

#     #         "network_observation":
#     #             self.summarize_flows(df),

#     #         "ml_evidence":
#     #             ml_results or {},

#     #         "configuration_evidence":
#     #             configuration or {},

#     #         "log_evidence":
#     #             logs or {},

#     #         "context":
#     #             metadata or {}
#     #     }

#     #     return evidence


# # if __name__ == "__main__":

# #     builder = EvidenceBuilder(
# #         "dataset/processed/acl_misconfig_flows.csv"
# #     )

# #     evidence = builder.build(

# #         ml_results={
# #             "random_forest": {
# #                 "prediction": "Benign",
# #                 "confidence": 0.70
# #             },
# #             "isolation_forest": {
# #                 "prediction": "Normal"
# #             }
# #         },

# #         configuration={
# #             "firewall_rule":
# #                 "-A INPUT -s 10.0.0.1/32 "
# #                 "-p tcp --dport 8000 -j DROP"
# #         },

# #         metadata={
# #             "scenario": "ACL_MISCONFIGURATION"
# #         }
# #     )

# #     print(json.dumps(evidence, indent=4))
# if __name__ == "__main__":

#     builder = EvidenceBuilder(
#         "dataset/processed/acl_misconfig_flows.csv"
#     )

#     evidence = builder.build(

#         ml_results={
#             "random_forest": {
#                 "prediction": "Benign",
#                 "confidence": 0.70
#             },
#             "isolation_forest": {
#                 "prediction": "Normal"
#             }
#         },

#         configuration={
#             "firewall_rule":
#                 "-A INPUT -s 10.0.0.1/32 "
#                 "-p tcp --dport 8000 -j DROP"
#         },

#         metadata={
#             "scenario": "ACL_TEST"
#         }
#     )

#     output_file = "agents/incident_evidence.json"

#     with open(output_file, "w") as f:
#         json.dump(evidence, f, indent=4)

#     print(f"Evidence saved to {output_file}")

import json
import pandas as pd
from pathlib import Path


class EvidenceBuilder:

    def __init__(self, flow_file):
        self.flow_file = Path(flow_file)

    # --------------------------------------------------
    # Load flow CSV
    # --------------------------------------------------

    def load_flows(self):
        return pd.read_csv(self.flow_file)

    # --------------------------------------------------
    # Convert protocol number to readable name
    # --------------------------------------------------

    def protocol_name(self, protocol):

        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6"
        }

        return protocol_map.get(
            int(protocol),
            f"Protocol {protocol}"
        )

    # --------------------------------------------------
    # Summarize network flow information
    # --------------------------------------------------

    def summarize_flows(self, df):

        evidence = {

            "flow_count": int(len(df)),

            "total_packets": int(
                df["packet_count"].sum()
            ),

            "total_bytes": int(
                df["byte_count"].sum()
            ),

            "protocols": [
                self.protocol_name(p)
                for p in df["protocol"]
                .dropna()
                .unique()
            ],

            "total_syn_packets": int(
                df["syn_count"].sum()
            ),

            "total_synack_packets": int(
                df["synack_count"].sum()
            ),

            "total_rst_packets": int(
                df["rst_count"].sum()
            ),

            "average_packets_per_sec": float(
                df["packets_per_sec"].mean()
            ),

            "average_bytes_per_sec": float(
                df["bytes_per_sec"].mean()
            ),

            "average_flow_duration_s": float(
                df["duration_s"].mean()
            )
        }

        return evidence

    # --------------------------------------------------
    # Build complete incident evidence
    # --------------------------------------------------

    def build(
        self,
        ml_results=None,
        configuration=None,
        logs=None,
        metadata=None
    ):

        df = self.load_flows()

        evidence = {

            "network_observation":
                self.summarize_flows(df),

            "ml_evidence":
                ml_results or {},

            "configuration_evidence":
                configuration or {},

            "log_evidence":
                logs or {},

            "context":
                metadata or {}
        }

        return evidence


# ======================================================
# Main - ACL TEST
# ======================================================

if __name__ == "__main__":

    builder = EvidenceBuilder(
        "dataset/processed/acl_misconfig_flows.csv"
    )

    evidence = builder.build(

        # --------------------------------------------------
        # ML results
        # --------------------------------------------------

        ml_results={

            "random_forest": {
                "prediction": "Benign",
                "confidence": 0.70
            },

            "isolation_forest": {
                "prediction": "Normal"
            }
        },

        # --------------------------------------------------
        # Configuration evidence
        # --------------------------------------------------

        configuration={

            "firewall_rule":
                "-A INPUT -s 10.0.0.1/32 "
                "-p tcp --dport 8000 -j DROP",

            "rule_effect":
                "Drops TCP traffic from 10.0.0.1 "
                "to destination port 8000"
        },

        # --------------------------------------------------
        # Incident context
        # --------------------------------------------------

        metadata={

            "scenario": "ACL_TEST",

            "source_ip": "10.0.0.1",

            "destination_ip": "10.0.0.2",

            "protocol": "TCP",

            "destination_port": 8000,

            "observed_service": "HTTP",

            "observed_problem":
                "HTTP connection failed",

            "traffic_expected": True
        }
    )

    # --------------------------------------------------
    # Add correlation evidence
    #
    # This is derived from the known ACL experiment.
    # Later we will automate this instead of hard-coding it.
    # --------------------------------------------------

    evidence["correlation_evidence"] = {

        "traffic_source":
            "10.0.0.1",

        "traffic_destination":
            "10.0.0.2",

        "traffic_protocol":
            "TCP",

        "traffic_destination_port":
            8000,

        "firewall_source":
            "10.0.0.1",

        "firewall_protocol":
            "TCP",

        "firewall_destination_port":
            8000,

        "firewall_action":
            "DROP",

        "traffic_matches_firewall_rule":
            True,

        "connection_failure_consistent_with_drop":
            True
    }

    # --------------------------------------------------
    # Save evidence
    # --------------------------------------------------

    output_file = (
        "agents/incident_evidence.json"
    )

    with open(output_file, "w") as f:

        json.dump(
            evidence,
            f,
            indent=4
        )

    print(
        f"\nEvidence saved to {output_file}"
    )

    print("\nGenerated Evidence:\n")

    print(
        json.dumps(
            evidence,
            indent=4
        )
    )