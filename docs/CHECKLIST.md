# Production Readiness Checklist

## System Requirements
- [x] **OS**: Debian 11/12, Ubuntu 20.04/22.04 LTS (Kernel 5.4+).
- [x] **Hardware**:
    - CPU: 2 Cores (Recommended), 1 Core (Minimum).
    - RAM: 512MB (Minimum), 1GB+ (Recommended for Docker overhead).
    - Storage: 10GB free space.
- [x] **Network**:
    - Public IPv4 (Static or Reserved DHCP recommended).
    - UDP Port 51820 (default) open on upstream firewall/router.

## Security (Audited 2025)
- [x] **Root Access**: Installer requires root (`sudo`) but drops privileges for containers.
- [x] **Firewall**:
    - NFTables installed and enabled.
    - SSH (Port 22) allowed (Failsafe).
    - ICMP rate-limited.
- [x] **WireGuard**:
    - Private keys generated on-device (never transmitted).
    - Pre-shared keys (PSK) enabled by default for Quantum resistance readiness.
- [x] **Hardening**:
    - 10-Scenario Audit Passed.
    - Zero-Trust IP Validation employed.
    - Containers run as non-root (UID 1000).

## Reliability
- [x] **Self-Healing**: `samnet-wg.service` enabled to ensure interfaces are up.
- [x] **Persistence**:
    - `wg-quick@wg0` enabled.
    - Docker enabled (`systemctl enable docker`).
- [x] **Updates**: `samnet.sh` handles migration from previous versions (idempotent code).

## Monitoring
- [x] **Logs**:
    - `/var/log/samnet-wg/install.log` (Rotated).
    - `journalctl -u samnet-wg` for runtime issues.
- [x] **Health Check**:
    - CLI "Status" screen shows realtime health.
    - Web UI provides deep insights into bandwidth/latency.
