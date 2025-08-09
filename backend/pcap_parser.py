import pyshark

def parse_pcap(file_path):
    capture = pyshark.FileCapture(file_path)
    stats = {
        "total_packets": 0,
        "protocols": {}
    }

    for packet in capture:
        stats["total_packets"] += 1
        proto = packet.highest_layer
        stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1

    capture.close()
    return stats
