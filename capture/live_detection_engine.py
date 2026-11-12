
from collections import defaultdict
from pathlib import Path
import sys
import time

from scapy.all import sniff, conf, IP

# Project paths
CAPTURE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CAPTURE_DIR.parent

if str(CAPTURE_DIR) not in sys.path:
    sys.path.insert(0, str(CAPTURE_DIR))

# DeepShield modules
from flow_generator import FlowGenerator
from live_predictor import LivePredictor
from alert_manager import AlertManager
from event_store import EventStore


# Configuration
INTERFACE_INDEX = 15

MIN_PACKETS_FOR_PREDICTION = 10
PREDICT_EVERY_NEW_PACKETS = 10


class LiveDetectionEngine:

    def __init__(self):

        print("\nInitializing DeepShield...")

        self.flow_generator = FlowGenerator()
        self.predictor = LivePredictor()
        self.alert_manager = AlertManager()
        self.event_store = EventStore()

        self.last_prediction_count = defaultdict(int)

        # Avoid duplicate alerts for the same flow.
        self.alerted_flow_ids = set()

        # Session statistics
        self.total_packets = 0
        self.total_predictions = 0
        self.total_attacks = 0
        self.total_benign = 0
        self.total_alerts = 0
        self.total_expired_flows = 0

        print("\nAll DeepShield modules initialized successfully.")

    def get_flow_id(self, flow):

        return (
            flow.get("source_ip"),
            flow.get("destination_ip"),
            flow.get("source_port"),
            flow.get("destination_port"),
            flow.get("protocol")
        )

    def process_packet(self, packet):

        if IP not in packet:
            return

        self.total_packets += 1

        try:

            flow = self.flow_generator.process_packet(packet)

            if not flow:
                self._process_expired_flows()
                return

            flow_id = self.get_flow_id(flow)

            packet_count = flow.get("total_packets", 0)

            previous_count = self.last_prediction_count[flow_id]

            if packet_count >= MIN_PACKETS_FOR_PREDICTION:

                if (
                    packet_count - previous_count
                    >= PREDICT_EVERY_NEW_PACKETS
                ):

                    self.last_prediction_count[flow_id] = packet_count

                    # Provisional prediction on an active flow.
                    self.run_prediction(
                        flow,
                        flow_id,
                        prediction_stage="PROVISIONAL"
                    )

            # Process flows expired by packet-based cleanup.
            self._process_expired_flows()

        except Exception as error:

            print("\nPacket processing error:", error)

    def run_prediction(
        self,
        flow,
        flow_id,
        prediction_stage
    ):

        result = self.predictor.predict_flow(flow)

        self.total_predictions += 1

        if result["prediction"] == "ATTACK":

            self.total_attacks += 1

            # Avoid duplicate alerts during this flow's lifetime.
            if flow_id not in self.alerted_flow_ids:

                alert = self.alert_manager.create_alert(result)

                if alert:
                    self.total_alerts += 1
                    self.alerted_flow_ids.add(flow_id)

        else:

            self.total_benign += 1

        # Attach prediction stage.
        result["prediction_stage"] = prediction_stage

        # Save prediction for the SOC dashboard.
        try:

            self.event_store.append_prediction(result)

        except Exception as error:

            print("\nEvent storage error:", error)

        # Display prediction in the terminal.
        self.display_result(result)

    def _process_expired_flows(self):

        expired_flows = self.flow_generator.pop_expired_flows()

        for flow in expired_flows:

            flow_id = self.get_flow_id(flow)

            packet_count = flow.get("total_packets", 0)

            self.total_expired_flows += 1

            print("\n[FLOW CLOSED]")
            print("Reason:", flow.get("closed_reason"))
            print("Total packets:", packet_count)

            try:

                if packet_count >= MIN_PACKETS_FOR_PREDICTION:

                    # Final prediction using the completed flow.
                    self.run_prediction(
                        flow,
                        flow_id,
                        prediction_stage="FINAL"
                    )

                else:

                    print(
                        "Final prediction skipped: "
                        "not enough packets."
                    )

            except Exception as error:

                print("Final flow prediction error:", error)

            finally:

                # Release tracking data for this flow.
                self.last_prediction_count.pop(flow_id, None)
                self.alerted_flow_ids.discard(flow_id)

    def display_result(self, result):

        print("\n" + "=" * 60)
        print("             DEEPSHIELD LIVE DETECTION")
        print("=" * 60)

        print(
            "Prediction Stage     :",
            result.get("prediction_stage", "UNKNOWN")
        )

        print("Classification       :", result["prediction"])

        print(
            "Attack Probability   :",
            f'{result["attack_probability"]:.4f}'
        )

        print("Source IP            :", result["source_ip"])
        print("Destination IP       :", result["destination_ip"])
        print("Destination Port     :", result["destination_port"])
        print("Protocol             :", result["protocol"])
        print("Packets in Flow      :", result["total_packets"])

        if result["prediction"] == "ATTACK":

            print("\n!!! POTENTIAL SECURITY THREAT DETECTED !!!")

        else:

            print("\nTraffic classified as BENIGN")

        print("=" * 60)

    def start(self):

        interface = conf.ifaces.dev_from_index(
            INTERFACE_INDEX
        )

        if interface is None:
            raise RuntimeError(
                f"Network interface index {INTERFACE_INDEX} not found."
            )

        print("\n" + "=" * 60)
        print("        DEEPSHIELD REAL-TIME DETECTION ENGINE")
        print("=" * 60)

        print("Network Interface    :", interface.name)
        print("Minimum Packets      :", MIN_PACKETS_FOR_PREDICTION)
        print("Prediction Interval  :", PREDICT_EVERY_NEW_PACKETS)

        print(
            "TCP Idle Timeout     :",
            self.flow_generator.TCP_IDLE_TIMEOUT
        )

        print(
            "UDP Idle Timeout     :",
            self.flow_generator.UDP_IDLE_TIMEOUT
        )

        print(
            "Maximum Flow Lifetime:",
            self.flow_generator.MAX_FLOW_LIFETIME
        )

        print("\nMonitoring authorized network traffic...")
        print("Press CTRL + C to stop monitoring.")

        print("=" * 60)

        # Short capture windows allow cleanup without new packets.
        while True:

            sniff(
                iface=interface,
                prn=self.process_packet,
                store=False,
                filter="ip",
                timeout=1
            )

            # Check for idle flows after each capture window.
            self.flow_generator.expire_flows(time.time())

            self._process_expired_flows()

    def show_summary(self):

        print("\n\n" + "=" * 60)
        print("             DEEPSHIELD SESSION SUMMARY")
        print("=" * 60)

        print("Total Packets Captured :", self.total_packets)
        print("Total Predictions      :", self.total_predictions)
        print("BENIGN Predictions     :", self.total_benign)
        print("ATTACK Predictions     :", self.total_attacks)
        print("Security Alerts Saved  :", self.total_alerts)
        print("Expired Flows          :", self.total_expired_flows)

        print("=" * 60)
        print("\nLive monitoring session ended.")


if __name__ == "__main__":

    engine = LiveDetectionEngine()

    try:

        engine.start()

    except KeyboardInterrupt:

        print("\n\nStopping DeepShield monitoring...")
        engine.show_summary()

    except PermissionError:

        print("\nPermission denied.")
        print("Run PowerShell or VS Code as Administrator.")

    except Exception as error:

        print("\nDeepShield engine error:", error)
