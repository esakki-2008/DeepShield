
from scapy.all import IP, TCP

try:
    from .flow_generator import FlowGenerator
except ImportError:
    from flow_generator import FlowGenerator


def test_tcp_flow_expires_after_idle_timeout():
    generator = FlowGenerator()

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=5000, dport=443, flags="S")
    )

    packet.time = 1000.0

    generator.process_packet(packet)

    assert len(generator.flows) == 1

    # Simulate 61 seconds of inactivity.
    generator.expire_flows(current_timestamp=1061.0)

    assert len(generator.flows) == 0

    expired = generator.pop_expired_flows()

    assert len(expired) == 1
    assert expired[0]["closed_reason"] == "idle_timeout"
    assert expired[0]["protocol"] == "TCP"

def test_bidirectional_tcp_flow_tracking():
    generator = FlowGenerator()

    forward = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=5000, dport=443, flags="S")
    )
    forward.time = 1000.0

    backward = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=5000, flags="SA")
    )
    backward.time = 1001.0

    generator.process_packet(forward)
    generator.process_packet(backward)

    assert len(generator.flows) == 1

    flow = generator.get_all_flows()[0]

    assert flow["forward_packets"] == 1
    assert flow["backward_packets"] == 1
    assert flow["total_packets"] == 2

from scapy.all import UDP


def test_udp_flow_tracking():
    generator = FlowGenerator()

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5000, dport=53)
    )
    packet.time = 1000.0

    generator.process_packet(packet)

    assert len(generator.flows) == 1

    flow = generator.get_all_flows()[0]

    assert flow["protocol"] == "UDP"
    assert flow["forward_packets"] == 1
    assert flow["total_packets"] == 1

    generator.expire_flows(current_timestamp=1031.0)

    assert len(generator.flows) == 0

    expired = generator.pop_expired_flows()

    assert len(expired) == 1
    assert expired[0]["closed_reason"] == "idle_timeout"