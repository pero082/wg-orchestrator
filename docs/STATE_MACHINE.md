# State Machine & Rollback Strategy

## Installer State Machine

The installer (`install.sh`) operates as a finite state machine to ensure deterministic outcomes.

### States
1.  **INIT**: Startup. Validating environment (Preflight).
    - *Transition*: Success -> **PLANNING** | Failure -> **EXIT(1)**
2.  **PLANNING**: Calculating required changes (Subnets, Ports).
    - *Transition*: Zero-Touch -> **APPLYING** | Interactive -> **USER_INPUT**
3.  **USER_INPUT** (Interactive Mode): Gathering configuration.
    - *Transition*: Done -> **APPLYING** | Abort -> **EXIT(0)**
4.  **APPLYING**: Executing changes.
    - *Action*: Create Backup.
    - *Transition*: Success -> **VERIFYING** | Failure -> **ROLLBACK**
5.  **ROLLBACK**: Restoring previous state from backup.
    - *Transition*: Done -> **EXIT(ERR)**
6.  **VERIFYING**: Running self-tests (Ping, Port Check).
    - *Transition*: Success -> **DONE** | Failure -> **WARNING/ROLLBACK**
7.  **DONE**: Final stats and receipt generation.

## Rollback Strategy (Safety-First)

### Principles
- **Atomic Operations**: DB transactions for state.
- **Snapshot-Before-Write**: Critical directories referenced are backed up before modification.
- **Verify-Then-Commit**: Configs are generated to temp files and validated (`nft -c`, `wg-quick strip`) before moving to production paths.

### Rollback Process
1.  **Trigger**: Any fatal error during `APPLYING` or `VERIFYING`.
2.  **Scope**:
    - `/etc/wireguard/wg0.conf` -> Restore `wg0.conf.bak`.
    - `/var/lib/samnet-wg/` -> Restore DB backup.
    - `nftables` -> Reload previous handle/ruleset.
3.  **Notification**: Inform user of failure and restoration status.

### File Safety
- **Idempotency**: Retrying a failed install resumes or repairs purely based on declared state.
- **Cleanup**: Temp files (`/tmp/samnet-wg-*`) are securely wiped on exit (trap handler).
