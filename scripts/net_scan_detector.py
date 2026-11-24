#!/usr/bin/env python3
import argparse
import time
from collections import defaultdict

from scapy.all import IP, TCP, sniff


class PortScanDetector:
    def __init__(self, port_threshold: int = 15, window_sec: int = 10) -> None:
        self.port_threshold = port_threshold
        self.window_sec = window_sec
        self.seen_ports: dict[str, dict[int, float]] = defaultdict(dict)
        self.alerted_at: dict[str, float] = {}

    def process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return

        src_ip = pkt[IP].src
        dst_port = int(tcp.dport)
        now = time.monotonic()

        ports_map = self.seen_ports[src_ip]
        ports_map[dst_port] = now

        expired = [p for p, ts in ports_map.items() if now - ts > self.window_sec]
        for p in expired:
            del ports_map[p]

        if len(ports_map) >= self.port_threshold:
            if now - self.alerted_at.get(src_ip, 0.0) > self.window_sec:
                self.alerted_at[src_ip] = now
                sample_ports = sorted(ports_map.keys())[:10]
                print(
                    f"[ALERT] Возможное сканирование портов от {src_ip}: "
                    f"{len(ports_map)} портов за {self.window_sec}s (пример: {sample_ports})"
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP SYN port scan detector")
    parser.add_argument("-i", "--interface", required=True, help="Сетевой интерфейс (например, eth0)")
    parser.add_argument("--ports", type=int, default=15, help="Порог уникальных портов")
    parser.add_argument("--window", type=int, default=10, help="Временное окно в секундах")
    args = parser.parse_args()

    detector = PortScanDetector(port_threshold=args.ports, window_sec=args.window)
    print(f"Слушаем {args.interface}... (порог: {args.ports} портов / {args.window}s)")
    sniff(iface=args.interface, filter="tcp", prn=detector.process_packet, store=False)


if __name__ == "__main__":
    main()
