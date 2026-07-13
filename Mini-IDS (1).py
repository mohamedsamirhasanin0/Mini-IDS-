import argparse
import logging
import os
import sys
import time
from collections import defaultdict
from threading import Thread


class _NullStream:
    def write(self, message):
        return len(message)

    def flush(self):
        return None

try:
    from scapy.all import IP, Raw, TCP, UDP, sniff
except ImportError:  # pragma: no cover - fallback for environments without scapy
    IP = Raw = TCP = UDP = None
    sniff = None

try:
    from colorama import Fore, Style, init
except ImportError:  # pragma: no cover - fallback for environments without colorama
    class Fore:
        RED = ""
        YELLOW = ""
        GREEN = ""
        CYAN = ""

    class Style:
        BRIGHT = ""

    def init(*args, **kwargs):
        return None


init(autoreset=True)

logging.basicConfig(
    filename="ids_alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class MiniIDS:
    def __init__(
        self,
        port_scan_threshold=15,
        port_scan_window=5,
        syn_flood_threshold=30,
        syn_flood_window=2,
        alert_cooldown=30,
        quiet=False,
    ):
        self.PORT_SCAN_THRESHOLD = port_scan_threshold
        self.PORT_SCAN_WINDOW = port_scan_window
        self.SYN_FLOOD_THRESHOLD = syn_flood_threshold
        self.SYN_FLOOD_WINDOW = syn_flood_window
        self.ALERT_COOLDOWN = alert_cooldown
        self.FLOW_RATE_THRESHOLD = 100
        self.FLOW_RATE_WINDOW = 2
        self.quiet = quiet

        self.port_scan_history = defaultdict(list)
        self.syn_flood_history = defaultdict(list)
        self.flow_history = defaultdict(list)
        self.last_alert_time = {}
        self.alerts = []
        self.stats = {
            "total_packets": 0,
            "payload_alerts": 0,
            "port_scan_alerts": 0,
            "syn_flood_alerts": 0,
        }
        self.signatures = [
            b"UNION SELECT",
            b"UNION ALL SELECT",
            b"../",
            b"/etc/passwd",
            b"<script>",
        ]

    def inspect_payload(self, payload):
        """Return a list of known suspicious signatures found in the payload."""
        if payload is None:
            return []

        if isinstance(payload, (bytes, bytearray)):
            payload_bytes = bytes(payload)
        else:
            payload_bytes = str(payload).encode("utf-8", errors="ignore")

        payload_text = payload_bytes.decode("latin-1", errors="ignore").lower()
        matches = []
        for signature in self.signatures:
            sig_text = signature.decode("latin-1", errors="ignore").lower()
            if sig_text in payload_text:
                matches.append(signature)
        return matches

    def process_packet(self, packet):
        """Callback executed for each captured packet."""
        if packet is None or not hasattr(packet, "haslayer"):
            return
        if IP is None or not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()
        self.stats["total_packets"] += 1

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            matches = self.inspect_payload(payload)
            if matches:
                matched = ", ".join(sig.decode("utf-8", errors="ignore") for sig in matches)
                msg = f"[🚨 PAYLOAD ALERT] Suspicious signature(s) {matched} detected from {src_ip} -> {dst_ip}"
                self._emit_alert(msg, Fore.RED, logging.WARNING, current_time=current_time, category="payload")
                self.stats["payload_alerts"] += 1

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            self.detect_tcp_anomalies(src_ip, dst_ip, tcp_layer, current_time)
            if self._is_syn_packet(tcp_layer):
                self.detect_syn_flood(src_ip, current_time)
            self.detect_port_scan(src_ip, tcp_layer.dport, current_time)
            self.detect_flow_spike(src_ip, dst_ip, current_time, len(packet))
        elif packet.haslayer(UDP):
            self.detect_port_scan(src_ip, packet[UDP].dport, current_time)
            self.detect_flow_spike(src_ip, dst_ip, current_time, len(packet))

    def detect_port_scan(self, src_ip, dst_port, current_time):
        """Detect a scan when one host quickly targets many unique ports."""
        history = self.port_scan_history[src_ip]
        history[:] = [
            (port, ts) for port, ts in history if current_time - ts <= self.PORT_SCAN_WINDOW
        ]

        if not any(port == dst_port for port, _ in history):
            history.append((dst_port, current_time))

        unique_ports_count = len({port for port, _ in history})
        if unique_ports_count >= self.PORT_SCAN_THRESHOLD:
            msg = (
                f"[⚠️ ALERT] Port scanning detected from {src_ip}! "
                f"Targeted {unique_ports_count} unique ports within {self.PORT_SCAN_WINDOW}s."
            )
            if self._emit_alert(msg, Fore.YELLOW, logging.WARNING, current_time=current_time, category="port-scan"):
                self.stats["port_scan_alerts"] += 1
                self.port_scan_history[src_ip].clear()
            return True
        return False

    def detect_syn_flood(self, src_ip, current_time):
        """Detect a burst of SYN packets that suggests a DDoS attempt."""
        history = self.syn_flood_history[src_ip]
        history[:] = [ts for ts in history if current_time - ts <= self.SYN_FLOOD_WINDOW]
        history.append(current_time)

        syn_count = len(history)
        if syn_count >= self.SYN_FLOOD_THRESHOLD:
            msg = (
                f"[🚨 CRITICAL ALERT] SYN flood detected from {src_ip}! "
                f"Received {syn_count} SYN packets within {self.SYN_FLOOD_WINDOW}s."
            )
            if self._emit_alert(msg, Fore.RED, logging.ERROR, current_time=current_time, category="syn-flood"):
                self.stats["syn_flood_alerts"] += 1
                self.syn_flood_history[src_ip].clear()
            return True
        return False

    def detect_tcp_anomalies(self, src_ip, dst_ip, tcp_layer, current_time):
        """Flag suspicious TCP behavior such as Xmas scans or malformed flags."""
        flags = getattr(tcp_layer, "flags", "")
        if isinstance(flags, str) and flags.upper() in {"FPU", "SFRPU", "FUP"}:
            msg = f"[⚠️ TCP ANOMALY] Suspicious Xmas-like flags {flags.upper()} from {src_ip} to {dst_ip}"
            if self._emit_alert(msg, Fore.YELLOW, logging.WARNING, current_time=current_time, category="tcp-anomaly"):
                self.stats["port_scan_alerts"] += 1
            return True
        return False

    def detect_flow_spike(self, src_ip, dst_ip, current_time, size):
        """Detect bursts of traffic volume from a single endpoint."""
        history = self.flow_history[(src_ip, dst_ip)]
        history[:] = [entry for entry in history if current_time - entry[0] <= self.FLOW_RATE_WINDOW]
        history.append((current_time, size))

        total_bytes = sum(entry[1] for entry in history)
        if total_bytes >= self.FLOW_RATE_THRESHOLD:
            msg = f"[📈 FLOW SPIKE] Unusual traffic burst from {src_ip} -> {dst_ip} ({total_bytes} bytes)"
            if self._emit_alert(msg, Fore.CYAN, logging.WARNING, current_time=current_time, category="flow-spike"):
                self.stats["payload_alerts"] += 1
            return True
        return False

    def _emit_alert(self, message, color, level, current_time=None, category=None):
        if current_time is None:
            current_time = time.time()

        key = category or message
        last_time = self.last_alert_time.get(key)
        if last_time is not None and current_time - last_time < self.ALERT_COOLDOWN:
            return False

        self.last_alert_time[key] = current_time
        self.alerts.append((time.strftime("%H:%M:%S"), message))
        if not self.quiet:
            print(color + Style.BRIGHT + message)
        logging.log(level, message)
        return True

    def _is_syn_packet(self, tcp_layer):
        flags = getattr(tcp_layer, "flags", None)
        if isinstance(flags, str):
            return flags == "S"
        if hasattr(flags, "S"):
            return bool(flags.S)
        return False

    def start(self, iface=None, count=None, timeout=None):
        if sniff is None:
            raise RuntimeError("Scapy is not installed. Install it with: pip install scapy")

        kwargs = {"prn": self.process_packet, "store": False}
        if iface:
            kwargs["iface"] = iface
        if count is not None:
            kwargs["count"] = int(count)
        if timeout is not None:
            kwargs["timeout"] = float(timeout)

        sniff(**kwargs)


def build_parser():
    parser = argparse.ArgumentParser(description="Mini IDS - lightweight network intrusion detection")
    parser.add_argument("--iface", help="Network interface to sniff")
    parser.add_argument("--count", type=int, help="Stop after capturing this many packets")
    parser.add_argument("--timeout", type=float, help="Stop after this many seconds")
    parser.add_argument("--port-scan-threshold", type=int, default=15, help="Unique ports threshold")
    parser.add_argument("--port-scan-window", type=float, default=5, help="Window in seconds")
    parser.add_argument("--syn-flood-threshold", type=int, default=30, help="SYN packets threshold")
    parser.add_argument("--syn-flood-window", type=float, default=2, help="Window in seconds")
    parser.add_argument("--alert-cooldown", type=float, default=30, help="Cooldown between repeated alerts")
    parser.add_argument("--panel", action="store_true", help="Show a live terminal dashboard")
    parser.add_argument("--quiet", action="store_true", help="Hide startup messages and keep output minimal")
    return parser


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
         
                /\
               /  \ 
              /____\ 
             /|    |\ 
            /_|____|_\
            |  .--.  |
            | (    ) |
            |  '--'  | 
     MOHAMED   SAMIR    HASANIN     
            |   /\   |
            |  /  \  |
            | /____\ |
             /|    |\ 
            /_|____|_\ 
              / /_\ \
             / / _ \ \
            / /  _  \ \ 
    """)


def render_panel(ids):
    print(Fore.CYAN + Style.BRIGHT + "\n=== Mini IDS Live Panel ===")
    print(Fore.WHITE + "Monitoring in real time. Press Ctrl+C to stop.")
    while True:
        status = (
            f"{Fore.GREEN}Packets: {ids.stats['total_packets']} | "
            f"{Fore.RED}Payload alerts: {ids.stats['payload_alerts']} | "
            f"{Fore.YELLOW}Port scan alerts: {ids.stats['port_scan_alerts']} | "
            f"{Fore.RED}SYN flood alerts: {ids.stats['syn_flood_alerts']}"
        )
        print("\r" + status, end="", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        print_banner()
        print(Fore.GREEN + "[*] Initializing detection engines...")
        print(Fore.GREEN + "[*] Logging system active (ids_alerts.log)")
        print(Fore.GREEN + "[*] Monitoring network interfaces for traffic anomalies...\n")

    ids = MiniIDS(
        port_scan_threshold=args.port_scan_threshold,
        port_scan_window=args.port_scan_window,
        syn_flood_threshold=args.syn_flood_threshold,
        syn_flood_window=args.syn_flood_window,
        alert_cooldown=args.alert_cooldown,
        quiet=args.quiet,
    )

    if os.geteuid() != 0 and sys.platform != "win32" and not args.quiet:
        print(Fore.YELLOW + "[!] Running without root privileges may limit packet capture on Linux.")

    if args.panel:
        panel_thread = Thread(target=render_panel, args=(ids,), daemon=True)
        panel_thread.start()

    try:
        ids.start(iface=args.iface, count=args.count, timeout=args.timeout)
    except PermissionError:
        print(Fore.RED + "[X] Error: Root privileges required. Please run this script with 'sudo'.")
        sys.exit(1)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] Shutting down Mini-IDS. Stay secure!")
        sys.exit(0)
    except RuntimeError as exc:
        print(Fore.RED + f"[X] {exc}")
        sys.exit(1)