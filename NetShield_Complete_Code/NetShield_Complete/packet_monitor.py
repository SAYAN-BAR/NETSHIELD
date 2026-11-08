import threading
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
try:
    from scapy.layers.inet6 import ICMPv6
except ImportError:
    ICMPv6 = None

from logger import initialize_database, log_event


class PacketMonitor:
    """One background Scapy capture worker, controlled by start/stop methods."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._running = False
        self._last_error = None
        self._started_at = None

    def status(self):
        with self._lock:
            alive = bool(self._thread and self._thread.is_alive())
            return {
                "running": alive and self._running,
                "started_at": self._started_at,
                "error": self._last_error
            }

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False, "Packet monitoring is already running."
            self._stop_event.clear()
            self._last_error = None
            self._started_at = datetime.now().astimezone().isoformat(timespec="seconds")
            self._running = True
            self._thread = threading.Thread(
                target=self._capture_loop,
                name="NetShieldPacketCapture",
                daemon=True
            )
            self._thread.start()
        return True, "Packet monitoring started."

    def stop(self):
        with self._lock:
            if not self._thread or not self._thread.is_alive():
                self._running = False
                return False, "Packet monitoring is not running."
            self._stop_event.set()
            thread = self._thread

        thread.join(timeout=3)

        with self._lock:
            self._running = bool(thread.is_alive())
        if self._running:
            return False, "Stop requested. Capture is still shutting down."
        return True, "Packet monitoring stopped."

    def _capture_loop(self):
        try:
            initialize_database()
            while not self._stop_event.is_set():
                sniff(
                    prn=self._analyze_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda packet: self._stop_event.is_set()
                )
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
        finally:
            with self._lock:
                self._running = False

    @staticmethod
    def _analyze_packet(packet):
        source = "Unknown"
        destination = "Unknown"
        protocol = "Other"
        source_port = "-"
        destination_port = "-"

        if IP in packet:
            source, destination = packet[IP].src, packet[IP].dst
        elif IPv6 in packet:
            source, destination = packet[IPv6].src, packet[IPv6].dst

        if TCP in packet:
            protocol = "TCP"
            source_port, destination_port = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            source_port, destination_port = packet[UDP].sport, packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        elif ICMPv6 is not None and ICMPv6 in packet:
            protocol = "ICMPv6"

        log_event(
            source_ip=source,
            destination_ip=destination,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            action="OBSERVED",
            details="Packet captured by NetShield. Observation does not mean allowed."
        )


monitor = PacketMonitor()


def start_monitoring():
    return monitor.start()


def stop_monitoring():
    return monitor.stop()


def get_monitor_status():
    return monitor.status()


if __name__ == "__main__":
    success, message = start_monitoring()
    print(message)
    if success:
        try:
            while monitor.status()["running"]:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            stop_monitoring()
            print("Monitoring stopped.")
