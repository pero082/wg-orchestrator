# SamNet-WG Architecture

## Hybrid Design: Dual Control Plane
SamNet-WG employs a unique "Dual Control Plane" architecture that decouples the high-performance network layer from the management layer, bridged by a robust synchronization engine.

## Components

### 1. Network Control Plane (Host)
- **Components**: `wg-quick`, `nftables`, `samnet-cli`, `sqlite3`.
- **Role**: The "Actuator". Applies changes to the kernel.
- **Trigger**: Bi-directional file watches.

### 2. Management Plane (Docker - Always Running)
- **API Service** (Headless Backend):
    - **Lang**: Golang 1.21+.
    - **Role**: Auth, Validation, Data Limits, Auto-Expiry, Observability.
    - **Access**: Mounts `/var/lib/samnet-wg` to read/write DB directly.
    - **Security**: Runs as unprivileged user (uid:1000).
    - **Note**: Runs in **both** CLI-only and Web UI modes.
- **UI Service** (Optional):
    - **Lang**: React (Vite).
    - **Role**: SPA Frontend. Served via Nginx.
    - **Note**: Only deployed when Web UI mode is enabled.

### 3. Synchronization Engine (The "Brain")
The heart of SamNet-WG is the sync engine that ensures the CLI and Web UI are always consistent.

**Write Path (from Web UI):**
1.  **User** (UI) -> **POST /api/peers**.
2.  **API**: Validates -> Writes to `samnet.db` -> Touches `reconcile.trigger`.
3.  **Host Watchdog**: Detects trigger -> Runs `samnet reconcile`.
4.  **Reconciler**: Updates `wg0.conf` -> Reloads WireGuard -> Updates Firewall.

**Write Path (from CLI):**
1.  **User** (CLI) -> `samnet peer add`.
2.  **CLI**: Creates `clients/peer.conf` -> Updates `samnet.db` -> Reloads WireGuard.
3.  **Consistency**: CLI commands call the same internal libraries as the API logic where possible.

### 4. Security Model
- **Isolation**: API/UI cannot directly run shell commands on the host. They can only modify the DB.
- **Validation**: Host script re-validates DB state before applying ("Trust but Verify").
- **Blast Radius**: API enforces strict limits (e.g., max 50 peers) to prevent resource exhaustion.
- **Audit**: All actions are logged to an append-only SQLite table.
