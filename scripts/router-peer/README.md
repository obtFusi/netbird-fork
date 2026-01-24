# Router-Peer Defense-in-Depth Scripts

Defense-in-depth hardening scripts for the NetBird Machine Tunnel router-peer.

## Overview

The router-peer is a Linux VM that routes traffic between the WireGuard mesh and the DC network. These scripts implement security hardening beyond the basic firewall rules.

## Files

| File | Purpose |
|------|---------|
| `setup-hardening.sh` | Main setup script (run as root) |
| `verify-hardening.sh` | Verification script |
| `99-netbird-hardening.conf` | Sysctl kernel parameters |

## Quick Start

```bash
# 1. Copy scripts to router-peer
scp -r scripts/router-peer/ user@router-peer:/tmp/

# 2. SSH to router-peer
ssh user@router-peer

# 3. Run setup (dry-run first!)
cd /tmp/router-peer
sudo ./setup-hardening.sh --dry-run

# 4. Run setup for real
sudo ./setup-hardening.sh

# 5. Verify
./verify-hardening.sh
```

## Security Layers

### 1. Kernel Parameters (sysctl)

| Parameter | Value | Protection |
|-----------|-------|------------|
| `rp_filter` | 1 | Anti-IP-spoofing (reverse path filtering) |
| `log_martians` | 1 | Log impossible source addresses |
| `accept_redirects` | 0 | Prevent ICMP route hijacking |
| `send_redirects` | 0 | Don't send ICMP redirects |
| `tcp_syncookies` | 1 | SYN flood protection |

### 2. INPUT Chain (Protect Router Itself)

- **Default Policy:** DROP
- **Allowed:** Loopback, established connections, SSH (mgmt only), WireGuard (UDP 51820), ICMP (rate limited)
- **Logging:** Dropped packets logged (rate limited)

### 3. FORWARD Chain (Traffic Routing)

- **Invalid Packets:** Dropped (prevents state confusion)
- **SYN Flood:** Rate limited (100/sec, burst 200)
- **Connection Limit:** 200 per source IP (prevents resource exhaustion)

### 4. OUTPUT Chain

- **Default Policy:** ACCEPT (router needs outbound)
- **Logging:** Suspicious outbound to client network logged

## Network Assumptions

Default interface mapping (adjust in `setup-hardening.sh`):

| Interface | Network | Purpose |
|-----------|---------|---------|
| eth0 | 10.0.0.0/24 | Management (SSH) |
| eth1 | 192.168.100.0/24 | DC network (vmbr1) |
| eth2 | 192.168.101.0/24 | Client network (vmbr2) |
| wt0 | 100.64.0.0/10 | WireGuard tunnel |

To customize:

```bash
MGMT_IFACE=ens3 DC_IFACE=ens4 CLIENT_IFACE=ens5 ./setup-hardening.sh
```

## Verification

Run `verify-hardening.sh` to check all security measures:

```bash
./verify-hardening.sh
```

Expected output:
```
[PASS] net.ipv4.conf.all.rp_filter = 1
[PASS] iptables INPUT policy: DROP
[PASS] SYN flood protection
...
All checks passed! Router-peer is properly hardened.
```

## Troubleshooting

### Locked out of SSH

If you lose SSH access:

1. Access via console (Proxmox, etc.)
2. Flush iptables: `iptables -F && iptables -P INPUT ACCEPT`
3. Fix configuration
4. Re-run setup

### Traffic not forwarding

Check:
1. `ip_forward` enabled: `cat /proc/sys/net/ipv4/ip_forward`
2. FORWARD chain rules: `iptables -L FORWARD -v -n`
3. Connection tracking: `conntrack -L | wc -l`

### High connection count

If conntrack table fills up:
```bash
# Check current usage
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max

# Increase if needed
echo 524288 > /proc/sys/net/netfilter/nf_conntrack_max
```

## References

- [Issue #25](https://github.com/obtFusi/netbird-fork/issues/25) - Task description
- [iptables Tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html)
- [Linux Kernel Networking Parameters](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
