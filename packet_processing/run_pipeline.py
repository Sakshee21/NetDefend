import pandas as pd
from scapy.all import rdpcap

from flow_extractor import extract_flows
from feature_extractor import calculate_features


# ---------------------------------------
# File paths
# ---------------------------------------

# PCAP_FILE = "../dataset/raw/test_normal.pcapng" #for real pcap
#PCAP_FILE = "../dataset/raw/mininet_normal.pcap" #for mininet pcap
#OUTPUT_FILE = "../dataset/processed/flows.csv" # for real pcap output
#OUTPUT_FILE = "../dataset/processed/mininet_normal_flows.csv" #for mininet normal pcap output
PCAP_FILE = "../dataset/raw/acl_misconfig.pcap"
OUTPUT_FILE = "../dataset/processed/acl_misconfig_flows.csv"
def main():

    print("=" * 50)
    print("        NetDefend PCAP Pipeline")
    print("=" * 50)

    # -----------------------------------
    # Step 1: Read PCAP
    # -----------------------------------

    print("\n[1] Reading PCAP...")

    packets = rdpcap(PCAP_FILE)

    print(
        f"Packets found: {len(packets)}"
    )

    # -----------------------------------
    # Step 2: Extract flows
    # -----------------------------------

    print("\n[2] Extracting flows...")

    flows = extract_flows(packets)

    print(
        f"Flows found: {len(flows)}"
    )

    # -----------------------------------
    # Step 3: Calculate features
    # -----------------------------------

    print("\n[3] Calculating features...")

    features = calculate_features(
        flows
    )

    # -----------------------------------
    # Step 4: Create DataFrame
    # -----------------------------------

    df = pd.DataFrame(features)

    print("\n[4] Feature table:")

    print(
        df.head(10).to_string(
            index=False
        )
    )

    # -----------------------------------
    # Step 5: Display columns
    # -----------------------------------

    print("\n[5] Columns:")

    for column in df.columns:

        print(
            f"  - {column}"
        )

    # -----------------------------------
    # Step 6: Save CSV
    # -----------------------------------

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n[6] CSV created successfully!")

    print(
        f"Location: {OUTPUT_FILE}"
    )

    print("=" * 50)


if __name__ == "__main__":

    main()