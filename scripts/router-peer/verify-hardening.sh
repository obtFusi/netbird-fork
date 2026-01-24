#!/bin/bash
# NetBird Router-Peer Defense-in-Depth Verification Script
# Verifies that all hardening measures are properly configured.
#
# Usage: ./verify-hardening.sh
#
# Exit codes:
#   0 - All checks passed
#   1 - One or more checks failed

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
WARNINGS=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

check_sysctl() {
    local param=$1
    local expected=$2
    local actual

    actual=$(cat "/proc/sys/${param//./\/}" 2>/dev/null || echo "NOT_FOUND")

    if [[ "$actual" == "$expected" ]]; then
        check_pass "$param = $expected"
        return 0
    else
        check_fail "$param = $actual (expected: $expected)"
        return 1
    fi
}

check_iptables_policy() {
    local chain=$1
    local expected=$2
    local actual

    actual=$(iptables -L "$chain" -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "UNKNOWN")

    if [[ "$actual" == "$expected" ]]; then
        check_pass "iptables $chain policy: $expected"
        return 0
    else
        check_fail "iptables $chain policy: $actual (expected: $expected)"
        return 1
    fi
}

check_iptables_rule() {
    local description=$1
    local grep_pattern=$2

    if iptables-save 2>/dev/null | grep -qE "$grep_pattern"; then
        check_pass "$description"
        return 0
    else
        check_fail "$description"
        return 1
    fi
}

echo "═══════════════════════════════════════════════════════════════════════"
echo " NetBird Router-Peer Defense-in-Depth Verification"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Note: Running without root - some checks may fail${NC}"
    echo ""
fi

echo "1. KERNEL PARAMETERS (sysctl)"
echo "─────────────────────────────────────────────────────────────────────────"

# Anti-spoofing
check_sysctl "net.ipv4.conf.all.rp_filter" "1"
check_sysctl "net.ipv4.conf.default.rp_filter" "1"

# Martian logging
check_sysctl "net.ipv4.conf.all.log_martians" "1"
check_sysctl "net.ipv4.conf.default.log_martians" "1"

# ICMP redirects
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.all.send_redirects" "0"

# IP forwarding (required for router)
check_sysctl "net.ipv4.ip_forward" "1"

# Conntrack tuning
conntrack_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "0")
if [[ "$conntrack_max" -ge 262144 ]]; then
    check_pass "nf_conntrack_max >= 262144 (actual: $conntrack_max)"
else
    check_warn "nf_conntrack_max = $conntrack_max (recommended: >= 262144)"
fi

echo ""
echo "2. IPTABLES INPUT CHAIN"
echo "─────────────────────────────────────────────────────────────────────────"

check_iptables_policy "INPUT" "DROP"
check_iptables_rule "Loopback allowed" "-A INPUT -i lo -j ACCEPT"
check_iptables_rule "Established connections allowed" "-A INPUT .* --state ESTABLISHED,RELATED -j ACCEPT"
check_iptables_rule "Invalid packets dropped" "-A INPUT .* --state INVALID -j DROP"
check_iptables_rule "SSH allowed (port 22)" "-A INPUT .* --dport 22 -j ACCEPT"
check_iptables_rule "WireGuard allowed (UDP 51820)" "-A INPUT .* --dport 51820 -j ACCEPT"
check_iptables_rule "ICMP rate limited" "-A INPUT .* icmp .* --limit .* -j ACCEPT"

echo ""
echo "3. IPTABLES FORWARD CHAIN"
echo "─────────────────────────────────────────────────────────────────────────"

check_iptables_rule "Invalid packets dropped in FORWARD" "-A FORWARD .* --state INVALID -j DROP"
check_iptables_rule "SYN flood protection" "-A FORWARD .* --tcp-flags .* SYN .* --limit"
check_iptables_rule "Connection limit per IP" "-A FORWARD .* connlimit"

echo ""
echo "4. IPTABLES OUTPUT CHAIN"
echo "─────────────────────────────────────────────────────────────────────────"

check_iptables_policy "OUTPUT" "ACCEPT"
# OUTPUT logging is optional, just check policy

echo ""
echo "5. PERSISTENT RULES"
echo "─────────────────────────────────────────────────────────────────────────"

if [[ -f /etc/iptables/rules.v4 ]]; then
    check_pass "Persistent rules file exists: /etc/iptables/rules.v4"
else
    check_warn "Persistent rules file not found (rules may not survive reboot)"
fi

if [[ -f /etc/sysctl.d/99-netbird-hardening.conf ]]; then
    check_pass "Sysctl config installed: /etc/sysctl.d/99-netbird-hardening.conf"
else
    check_fail "Sysctl config not found: /etc/sysctl.d/99-netbird-hardening.conf"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo " SUMMARY"
echo "═══════════════════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC}   $PASSED"
echo -e "  ${RED}Failed:${NC}   $FAILED"
echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}Some checks failed. Run 'sudo ./setup-hardening.sh' to fix.${NC}"
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}All critical checks passed with some warnings.${NC}"
    exit 0
else
    echo -e "${GREEN}All checks passed! Router-peer is properly hardened.${NC}"
    exit 0
fi
