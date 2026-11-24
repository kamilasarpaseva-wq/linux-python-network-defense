#!/usr/bin/env python3
import argparse
import ipaddress
import re
import subprocess
import time
from collections import defaultdict, deque

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def is_valid_ipv4(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return isinstance(ip, ipaddress.IPv4Address) and not ip.is_loopback
    except ValueError:
        return False


def ban_ip_nftables(ip: str, timeout_sec: int, apply: bool) -> None:
    cmd = [
        "nft",
        "add",
        "element",
        "inet",
        "filter",
        "blacklist_v4",
        "{",
        f"{ip} timeout {timeout_sec}s",
        "}",
    ]
    if not apply:
        print(f"[DRY-RUN] Выполнена бы команда: {' '.join(cmd)}")
        return

    subprocess.run(cmd, check=True)
    print(f"[BANNED] IP {ip} добавлен в blacklist_v4 на {timeout_sec}s")


def monitor_log(log_path: str, threshold: int, window_sec: int, ban_sec: int, apply: bool) -> None:
    attempts: dict[str, deque[float]] = defaultdict(deque)
    banned_recently: dict[str, float] = {}

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            match = FAILED_PATTERN.search(line)
            if not match:
                continue

            ip = match.group("ip")
            if not is_valid_ipv4(ip):
                continue

            now = time.monotonic()
            if ip in banned_recently and now - banned_recently[ip] < ban_sec:
                continue

            q = attempts[ip]
            q.append(now)
            while q and now - q[0] > window_sec:
                q.popleft()

            if len(q) >= threshold:
                ban_ip_nftables(ip, ban_sec, apply=apply)
                banned_recently[ip] = now
                q.clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH brute-force detector + nftables blocker")
    parser.add_argument("--log", default="/var/log/auth.log", help="Путь к лог-файлу")
    parser.add_argument("--threshold", type=int, default=5, help="Порог неудачных попыток")
    parser.add_argument("--window", type=int, default=60, help="Окно подсчёта в секундах")
    parser.add_argument("--ban-time", type=int, default=3600, help="Время блокировки в секундах")
    parser.add_argument("--apply", action="store_true", help="Реально применять правила nftables")
    args = parser.parse_args()

    monitor_log(
        log_path=args.log,
        threshold=args.threshold,
        window_sec=args.window,
        ban_sec=args.ban_time,
        apply=args.apply,
    )


if __name__ == "__main__":
    main()
