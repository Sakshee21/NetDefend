from scapy.all import IP, IPv6, TCP, UDP


def extract_flows(packets):

    flows = {}

    for packet in packets:

        # --------------------------------
        # Get IP information
        # --------------------------------

        if packet.haslayer(IP):

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

        elif packet.haslayer(IPv6):

            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh

        else:

            # Ignore ARP and other non-IP packets
            continue

        # --------------------------------
        # Get ports
        # --------------------------------

        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # --------------------------------
        # Create flow key
        # --------------------------------

        flow_key = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        # --------------------------------
        # Create flow
        # --------------------------------

        if flow_key not in flows:

            flows[flow_key] = {

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

                "packet_count": 0,
                "byte_count": 0,

                "first_timestamp": float(packet.time),
                "last_timestamp": float(packet.time),

                "timestamps": [],

                "syn_count": 0,
                "synack_count": 0,
                "rst_count": 0
            }

        flow = flows[flow_key]

        # --------------------------------
        # Packet statistics
        # --------------------------------

        flow["packet_count"] += 1

        flow["byte_count"] += len(packet)

        timestamp = float(packet.time)

        flow["timestamps"].append(timestamp)

        flow["last_timestamp"] = timestamp

        # --------------------------------
        # TCP flags
        # --------------------------------

        if packet.haslayer(TCP):

            flags = packet[TCP].flags

            # SYN
            if flags & 0x02:
                flow["syn_count"] += 1

            # SYN + ACK
            if (flags & 0x02) and (flags & 0x10):
                flow["synack_count"] += 1

            # RST
            if flags & 0x04:
                flow["rst_count"] += 1

    return flows