
from collections import defaultdict
from datetime import datetime
from threading import Lock


from scapy.all import IP, TCP, UDP


class FlowGenerator:

    TCP_FLAG_NAMES = {
        "FIN": 0x01,
        "SYN": 0x02,
        "RST": 0x04,
        "PSH": 0x08,
        "ACK": 0x10,
        "URG": 0x20,
        "ECE": 0x40,
        "CWE": 0x80,
    }

    TCP_IDLE_TIMEOUT = 60
    UDP_IDLE_TIMEOUT = 30
    MAX_FLOW_LIFETIME = 300
    MAX_ACTIVE_FLOWS = 5000
    CLEANUP_INTERVAL = 100

    def __init__(self):
        self.flows = defaultdict(self._new_flow)
        self.expired_flows = []
        self.lock = Lock()
        self.packet_counter = 0

    @staticmethod
    def _new_flow():
        return {
            "protocol": None,
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,

            "forward_packets": 0,
            "backward_packets": 0,

            "forward_bytes": 0,
            "backward_bytes": 0,

            "forward_packet_lengths": [],
            "backward_packet_lengths": [],

            "forward_times": [],
            "backward_times": [],
            "packet_times": [],
            "packet_lengths": [],

            "forward_header_lengths": [],
            "backward_header_lengths": [],

            "tcp_flags": {
                name: 0 for name in FlowGenerator.TCP_FLAG_NAMES
            },

            "forward_psh_flags": 0,
            "backward_psh_flags": 0,
            "forward_urg_flags": 0,
            "backward_urg_flags": 0,

            "init_window_forward": -1,
            "init_window_backward": -1,

            "forward_data_packets": 0,
            "min_segment_size_forward": -1,

            "start_time": None,
            "last_seen": None,
        }

    def process_packet(self, packet):

        if IP not in packet:
            return None

        ip = packet[IP]

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        else:
            return None

        timestamp = float(packet.time)
        packet_size = len(ip)

        forward_key = (
            ip.src, source_port,
            ip.dst, destination_port,
            protocol
        )

        backward_key = (
            ip.dst, destination_port,
            ip.src, source_port,
            protocol
        )

        with self.lock:

            self.packet_counter += 1

            if forward_key in self.flows:
                key = forward_key
                direction = "forward"

            elif backward_key in self.flows:
                key = backward_key
                direction = "backward"

            else:
                key = forward_key
                direction = "forward"

                if len(self.flows) >= self.MAX_ACTIVE_FLOWS:
                    self._evict_oldest_flow()

            flow = self.flows[key]

            if flow["start_time"] is None:

                flow["protocol"] = protocol
                flow["source_ip"] = key[0]
                flow["destination_ip"] = key[2]
                flow["source_port"] = key[1]
                flow["destination_port"] = key[3]
                flow["start_time"] = timestamp

            flow["last_seen"] = timestamp

            flow["packet_times"].append(timestamp)
            flow["packet_lengths"].append(packet_size)

            if TCP in packet:

                tcp = packet[TCP]

                flags = int(tcp.flags)
                tcp_header_length = int(tcp.dataofs or 5) * 4
                ip_header_length = int(ip.ihl or 5) * 4

                combined_header_length = (
                    ip_header_length + tcp_header_length
                )

                payload_length = len(tcp.payload)

                for name, flag_value in self.TCP_FLAG_NAMES.items():
                    if flags & flag_value:
                        flow["tcp_flags"][name] += 1

                if direction == "forward":

                    if flow["init_window_forward"] == -1:
                        flow["init_window_forward"] = int(tcp.window)

                    flow["forward_header_lengths"].append(
                        combined_header_length
                    )

                    if flags & self.TCP_FLAG_NAMES["PSH"]:
                        flow["forward_psh_flags"] += 1

                    if flags & self.TCP_FLAG_NAMES["URG"]:
                        flow["forward_urg_flags"] += 1

                    if payload_length > 0:
                        flow["forward_data_packets"] += 1

                    if flow["min_segment_size_forward"] == -1:
                        flow["min_segment_size_forward"] = (
                            combined_header_length
                        )

                else:

                    if flow["init_window_backward"] == -1:
                        flow["init_window_backward"] = int(tcp.window)

                    flow["backward_header_lengths"].append(
                        combined_header_length
                    )

                    if flags & self.TCP_FLAG_NAMES["PSH"]:
                        flow["backward_psh_flags"] += 1

                    if flags & self.TCP_FLAG_NAMES["URG"]:
                        flow["backward_urg_flags"] += 1

            else:

                combined_header_length = (
                    int(ip.ihl or 5) * 4 + 8
                )

                if direction == "forward":
                    flow["forward_header_lengths"].append(
                        combined_header_length
                    )
                else:
                    flow["backward_header_lengths"].append(
                        combined_header_length
                    )

            if direction == "forward":

                flow["forward_packets"] += 1
                flow["forward_bytes"] += packet_size
                flow["forward_packet_lengths"].append(packet_size)
                flow["forward_times"].append(timestamp)

            else:

                flow["backward_packets"] += 1
                flow["backward_bytes"] += packet_size
                flow["backward_packet_lengths"].append(packet_size)
                flow["backward_times"].append(timestamp)

            # Run cleanup periodically rather than scanning
            # every active flow for every packet.
            if self.packet_counter % self.CLEANUP_INTERVAL == 0:
                self._cleanup_locked(timestamp)

            return self._build_flow_summary(flow)

    def _cleanup_locked(self, current_timestamp):

        expired_keys = []

        for key, flow in self.flows.items():

            idle_timeout = (
                self.TCP_IDLE_TIMEOUT
                if flow["protocol"] == "TCP"
                else self.UDP_IDLE_TIMEOUT
            )

            idle_time = current_timestamp - flow["last_seen"]

            flow_age = current_timestamp - flow["start_time"]

            if idle_time >= idle_timeout:
                expired_keys.append((key, "idle_timeout"))

            elif flow_age >= self.MAX_FLOW_LIFETIME:
                expired_keys.append((key, "maximum_lifetime"))

        for key, reason in expired_keys:

            flow = self.flows.pop(key)

            summary = self._build_flow_summary(flow)
            summary["closed_reason"] = reason

            self.expired_flows.append(summary)

    def _evict_oldest_flow(self):

        if not self.flows:
            return

        oldest_key = min(
            self.flows,
            key=lambda key: self.flows[key]["last_seen"]
        )

        flow = self.flows.pop(oldest_key)

        summary = self._build_flow_summary(flow)
        summary["closed_reason"] = "capacity_limit"

        self.expired_flows.append(summary)

    def expire_flows(self, current_timestamp=None):

        with self.lock:

            if current_timestamp is None:
                current_timestamp = datetime.now().timestamp()

            self._cleanup_locked(float(current_timestamp))

    def pop_expired_flows(self):

        with self.lock:

            expired = self.expired_flows
            self.expired_flows = []

            return expired

    @staticmethod
    def _build_flow_summary(flow):

        duration = flow["last_seen"] - flow["start_time"]

        return {
            "protocol": flow["protocol"],

            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],

            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],

            "forward_packets": flow["forward_packets"],
            "backward_packets": flow["backward_packets"],

            "forward_bytes": flow["forward_bytes"],
            "backward_bytes": flow["backward_bytes"],

            "total_packets": (
                flow["forward_packets"] +
                flow["backward_packets"]
            ),

            "total_bytes": (
                flow["forward_bytes"] +
                flow["backward_bytes"]
            ),

            "duration_seconds": round(duration, 6),

            "first_seen": datetime.fromtimestamp(
                flow["start_time"]
            ).isoformat(),

            "last_seen": datetime.fromtimestamp(
                flow["last_seen"]
            ).isoformat(),

            "tcp_flags": dict(flow["tcp_flags"]),

            "forward_packet_lengths": list(
                flow["forward_packet_lengths"]
            ),

            "backward_packet_lengths": list(
                flow["backward_packet_lengths"]
            ),

            "forward_times": list(flow["forward_times"]),
            "backward_times": list(flow["backward_times"]),

            "packet_times": list(flow["packet_times"]),

            "forward_header_lengths": list(
                flow["forward_header_lengths"]
            ),

            "backward_header_lengths": list(
                flow["backward_header_lengths"]
            ),

            "init_window_forward": flow["init_window_forward"],
            "init_window_backward": flow["init_window_backward"],

            "forward_data_packets": flow["forward_data_packets"],

            "min_segment_size_forward": (
                flow["min_segment_size_forward"]
            ),

            "forward_psh_flags": flow["forward_psh_flags"],
            "backward_psh_flags": flow["backward_psh_flags"],

            "forward_urg_flags": flow["forward_urg_flags"],
            "backward_urg_flags": flow["backward_urg_flags"],
        }

    def get_flow(self, key):

        with self.lock:

            flow = self.flows.get(key)

            if flow is None:
                return None

            return self._build_flow_summary(flow)

    def get_all_flows(self):

        with self.lock:

            return [
                self._build_flow_summary(flow)
                for flow in self.flows.values()
            ]
