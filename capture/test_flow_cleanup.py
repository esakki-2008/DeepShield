
from scapy.all import IP, TCP
from flow_generator import FlowGenerator


generator = FlowGenerator()

# Create a synthetic TCP packet.
packet = (
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=5000, dport=443, flags="S")
)

# Give the packet a controlled timestamp.
packet.time = 1000.0

generator.process_packet(packet)

print("Active flows before cleanup:", len(generator.flows))

# Simulate 61 seconds of inactivity.
generator.expire_flows(current_timestamp=1061.0)

print("Active flows after cleanup:", len(generator.flows))

expired = generator.pop_expired_flows()

print("Expired flows:", len(expired))

if len(generator.flows) == 0 and len(expired) == 1:
    print("\nFLOW CLEANUP TEST: PASS")
    print("Closed reason:", expired[0]["closed_reason"])
else:
    print("\nFLOW CLEANUP TEST: FAILED")
