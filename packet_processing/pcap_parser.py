# from scapy.all import rdpcap


# PCAP_FILE = "../dataset/test_normal.pcapng"


# def read_pcap(file_path):

#     packets = rdpcap(file_path)

#     print("Total packets:", len(packets))

#     return packets


# if __name__ == "__main__":

#     packets = read_pcap(PCAP_FILE)

#     print("\nFirst 10 packets:\n")

#     for i, packet in enumerate(packets[:10]):

#         print(f"Packet {i + 1}:")
#         print(packet.summary())
#         print()

from scapy.all import rdpcap, IP, TCP, UDP


PCAP_FILE = "../dataset/raw/test_normal.pcapng"


def read_pcap(file_path):

    packets = rdpcap(file_path)

    print("Total packets:", len(packets))

    return packets


def extract_packet_info(packet):

    # Ignore packets that don't contain IPv4
    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = packet[IP].proto

    src_port = 0
    dst_port = 0
    tcp_flags = ""

    if packet.haslayer(TCP):

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        tcp_flags = str(packet[TCP].flags)

        protocol_name = "TCP"

    elif packet.haslayer(UDP):

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        protocol_name = "UDP"

    else:

        protocol_name = str(protocol)

    packet_info = {

        "timestamp": float(packet.time),

        "src_ip": src_ip,

        "dst_ip": dst_ip,

        "src_port": src_port,

        "dst_port": dst_port,

        "protocol": protocol_name,

        "packet_length": len(packet),

        "tcp_flags": tcp_flags
    }

    return packet_info


if __name__ == "__main__":

    packets = read_pcap(PCAP_FILE)

    print("\nExtracted packet information:\n")

    count = 0

    for packet in packets:

        info = extract_packet_info(packet)

        if info is not None:

            print(info)

            count += 1

        if count == 10:

            break