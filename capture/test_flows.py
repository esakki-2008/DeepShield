
from scapy.all import sniff, conf
from flow_generator import FlowGenerator


INTERFACE_INDEX = 15
PACKET_LIMIT = 50

generator = FlowGenerator()


def handle_packet(packet):
    flow = generator.process_packet(packet)

    if flow:
        print(
            f"{flow['protocol']} | "
            f"{flow['source_ip']}:{flow['source_port']} -> "
            f"{flow['destination_ip']}:{flow['destination_port']} | "
            f"Packets: {flow['total_packets']} | "
            f"Bytes: {flow['total_bytes']}"
        )


def main():

    interface = conf.ifaces.dev_from_index(
        INTERFACE_INDEX
    )

    print("DEEPSHIELD NETWORK FLOW TEST")
    print("Interface:", interface.name)
    print("Capturing 50 packets...")

    sniff(
        iface=interface,
        prn=handle_packet,
        count=PACKET_LIMIT,
        store=False,
        filter="ip and (tcp or udp)"
    )

    print("\nFLOW SUMMARY")

    for flow in generator.get_all_flows():
        print(flow)


if __name__ == "__main__":
    main()
