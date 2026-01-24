#!/bin/bash
# NetBird Router-Peer Defense-in-Depth Setup Script
# This script configures iptables and kernel parameters for secure routing.
#
# Usage: sudo ./setup-hardening.sh [--dry-run]
#
# Prerequisites:
# - Ubuntu 22.04 LTS or similar
# - iptables and iptables-persistent installed
# - NetBird WireGuard interface (wt0) configured
#
# Network assumptions (adjust as needed):
# - eth0: Management network (SSH access)
# - eth1: DC network (vmbr1 - 192.168.100.0/24)
# - eth2: Client network (vmbr2 - 192.168.101.0/24)
# - wt0: WireGuard tunnel interface (100.64.0.0/10)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSCTL_CONF="${SCRIPT_DIR}/99-netbird-hardening.conf"
SYSCTL_DEST="/etc/sysctl.d/99-netbird-hardening.conf"

# Interfaces (adjust for your environment)
MGMT_IFACE="${MGMT_IFACE:-eth0}"
DC_IFACE="${DC_IFACE:-eth1}"
CLIENT_IFACE="${CLIENT_IFACE:-eth2}"
WG_PORT="${WG_PORT:-51820}"

# Rate limits
SYN_RATE="100/sec"
SYN_BURST="200"
ICMP_RATE="10/sec"
LOG_RATE="5/min"
CONNLIMIT_PER_IP="200"

DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

run_cmd() {
    if $DRY_RUN; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]] && ! $DRY_RUN; then
        echo "Error: This script must be run as root"
        exit 1
    fi
}

check_prerequisites() {
    log "Checking prerequisites..."

    local missing=()

    if ! command -v iptables &>/dev/null; then
        missing+=("iptables")
    fi

    if ! command -v netfilter-persistent &>/dev/null; then
        missing+=("iptables-persistent")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: Missing packages: ${missing[*]}"
        echo "Install with: apt-get install ${missing[*]}"
        exit 1
    fi

    log "Prerequisites OK"
}

setup_sysctl() {
    log "Setting up kernel parameters..."

    if [[ ! -f "$SYSCTL_CONF" ]]; then
        echo "Error: Sysctl config not found: $SYSCTL_CONF"
        exit 1
    fi

    run_cmd cp "$SYSCTL_CONF" "$SYSCTL_DEST"
    run_cmd sysctl -p "$SYSCTL_DEST"

    log "Kernel parameters configured"
}

setup_input_chain() {
    log "Configuring INPUT chain (protect router-peer itself)..."

    # Set default policy to DROP
    run_cmd iptables -P INPUT DROP

    # Allow loopback
    run_cmd iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    run_cmd iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packets early
    run_cmd iptables -A INPUT -m state --state INVALID -j DROP

    # SSH only from management interface
    run_cmd iptables -A INPUT -i "$MGMT_IFACE" -p tcp --dport 22 -j ACCEPT

    # NetBird WireGuard (UDP)
    run_cmd iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT

    # ICMP with rate limiting (for diagnostics)
    run_cmd iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit "$ICMP_RATE" -j ACCEPT

    # Log dropped packets (rate limited)
    run_cmd iptables -A INPUT -m limit --limit "$LOG_RATE" -j LOG --log-prefix "INPUT-DROP: "

    log "INPUT chain configured"
}

setup_forward_chain() {
    log "Configuring FORWARD chain (traffic routing)..."

    # Drop invalid packets first (prevents state confusion attacks)
    run_cmd iptables -I FORWARD 1 -m state --state INVALID -j DROP

    # SYN flood protection (rate limiting for new TCP connections)
    run_cmd iptables -I FORWARD 2 -p tcp --syn -m limit --limit "$SYN_RATE" --limit-burst "$SYN_BURST" -j ACCEPT
    run_cmd iptables -I FORWARD 3 -p tcp --syn -j DROP

    # Connection limit per source IP (prevents resource exhaustion)
    run_cmd iptables -I FORWARD 4 -p tcp -m connlimit --connlimit-above "$CONNLIMIT_PER_IP" --connlimit-mask 32 -j REJECT

    # Allow established and related
    run_cmd iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    log "FORWARD chain configured"
}

setup_output_chain() {
    log "Configuring OUTPUT chain (outbound traffic)..."

    # Default ACCEPT (router needs outbound for NetBird)
    run_cmd iptables -P OUTPUT ACCEPT

    # Log suspicious outbound to client network (router should not initiate)
    run_cmd iptables -A OUTPUT -o "$CLIENT_IFACE" -m state --state NEW -m limit --limit "$LOG_RATE" -j LOG --log-prefix "SUSPICIOUS-OUTPUT: "

    log "OUTPUT chain configured"
}

save_rules() {
    log "Saving iptables rules persistently..."
    run_cmd netfilter-persistent save
    log "Rules saved"
}

main() {
    log "=== NetBird Router-Peer Defense-in-Depth Setup ==="

    if $DRY_RUN; then
        log "Running in DRY-RUN mode (no changes will be made)"
    fi

    check_root
    check_prerequisites

    log ""
    log "Configuration:"
    log "  Management interface: $MGMT_IFACE"
    log "  DC interface: $DC_IFACE"
    log "  Client interface: $CLIENT_IFACE"
    log "  WireGuard port: $WG_PORT"
    log ""

    setup_sysctl
    setup_input_chain
    setup_forward_chain
    setup_output_chain
    save_rules

    log ""
    log "=== Setup Complete ==="
    log "Run './verify-hardening.sh' to verify the configuration"
}

main "$@"
