# Linux & Python Network Defense

Практический учебный проект по анализу сетевых угроз, усилению сетевого стека Linux (`sysctl`, `nftables`) и разработке скриптов обнаружения атак на Python.

## Структура репозитория

- `configs/sysctl-hardening.conf` — параметры ядра Linux для защиты от SYN-flood, IP-spoofing и ICMP-атак.
- `configs/nftables.conf` — базовая политика файрвола и динамический чёрный список IP-адресов.
- `scripts/log_bruteforce_guard.py` — анализатор логов аутентификации (SSH) с автоматической блокировкой атакующих IP через `nftables`.
- `scripts/net_scan_detector.py` — детектор горизонтального TCP SYN-сканирования портов на базе библиотеки `scapy`.
- `requirements.txt` — список зависимостей для Python-скриптов.

## Быстрый старт

### 1. Применение сетевых настроек Linux
```bash
sudo cp configs/sysctl-hardening.conf /etc/sysctl.d/99-network-hardening.conf
sudo sysctl --system
sudo nft -f configs/nftables.conf
