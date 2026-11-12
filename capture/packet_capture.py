
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from datetime import datetime


# DeepShield Live Packet Capture
# Initial test: capture packet headers only

INTERFACE_INDEX = 15
PACKET_LIMIT = 20


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = "OTHER"
    source_port = None
    destination_port = None

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    packet_info = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet)
    }

    print(packet_info)


def start_capture():

    interface = conf.ifaces.dev_from_index(
        INTERFACE_INDEX
    )

    print("================================")
    print("       DEEPSHIELD LIVE          ")
    print("       PACKET CAPTURE           ")
    print("================================")
    print(f"Interface: {interface.name}")
    print(f"Packet limit: {PACKET_LIMIT}")
    print("Capturing packet headers only...")
    print("")

    sniff(
        iface=interface,
        prn=process_packet,
        count=PACKET_LIMIT,
        store=False,
        filter="ip"
    )

    print("\nCapture completed.")


if __name__ == "__main__":
    try:
        start_capture()
    except PermissionError:
        print("Permission denied. Run VS Code as Administrator.")
    except Exception as error:
        print(f"Capture error: {error}")
