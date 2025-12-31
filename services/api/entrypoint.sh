#!/bin/bash
set -e

# This entrypoint ONLY starts the API server.
# WireGuard interface and NAT/Firewall are managed on the HOST, not inside this container.
# The HOST uses wg-quick@wg0 and nftables for networking.

echo "Starting SamNet API..."
exec ./api
