# Operations Guide

## 🔄 Upgrading

To upgrade SamNet-WG to the latest version:

1.  **Backup**:
    ```bash
    # Backup script is available (or manual copy)
    cp /var/lib/samnet-wg/samnet.db /var/lib/samnet-wg/samnet.db.bak
    ```
2.  **Pull & Re-Install**:
    ```bash
    git pull
    sudo ./samnet.sh --install
    ```
    The installer is **idempotent**. It will preserve your database and peers while updating binaries and containers.

---

## 🗑️ Uninstalling

We provide a comprehensive, safe uninstaller that cleans up all SamNet traces while protecting your other system data.

```bash
sudo ./samnet.sh --uninstall
```
*   **Scoped Pruning**: Removes Docker images with label `project=samnet-wg`.
*   **File Cleanup**: Removes `/opt/samnet`, `/var/lib/samnet-wg`, `/etc/wireguard/wg0.conf`.
*   **Services**: Stops and disables `samnet-wg` and `samnet-reconcile`.

---

## 💾 Backup & Restore

**Critical Files**:
*   `/var/lib/samnet-wg/samnet.db`: The entire system state (Users, Peers, Configs).
*   `/var/lib/samnet-wg/master.key`: The key required to decrypt Peer Private Keys.

**Restore**:
1.  Install a fresh SamNet-WG instance.
2.  Stop services: `systemctl stop samnet-wg`
3.  Restore the two files above.
4.  Run `samnet reconcile` to apply the restored state to the system.

---

## 🚨 Troubleshooting

### High CPU Usage
*   Check peer traffic: `samnet` -> Status -> `wg show`.
*   Check logs: `journalctl -u samnet-wg` or `docker logs samnet-wg-api`.

### "Handshake" not completing
*   **Firewall**: Ensure UDP port (default 51820) is forwarded to this server.
*   **Clients**: Ensure clients have the correct Endpoint IP/DNS.

### Web UI Unreachable
*   Check container status: `docker ps`.
*   Check port conflict: `netstat -tulpn | grep 8080`.
*   Restart containers: `sudo samnet.sh --rebuild`
