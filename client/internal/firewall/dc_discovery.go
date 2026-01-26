// Machine Tunnel Fork - DC IP Discovery
// This file provides automatic Domain Controller IP discovery via DNS SRV lookup.

package firewall

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultRefreshInterval is the default interval for DC list refresh
	DefaultRefreshInterval = 1 * time.Hour

	// MinRefreshInterval is the minimum allowed refresh interval
	MinRefreshInterval = 5 * time.Minute

	// DiscoveryTimeout is the timeout for DNS lookups
	DiscoveryTimeout = 30 * time.Second
)

// DCDiscovery manages automatic DC IP discovery
type DCDiscovery struct {
	mu sync.Mutex

	// domain is the AD domain name
	domain string

	// currentIPs are the currently known DC IPs
	currentIPs []string

	// refreshInterval is the interval between DC list refreshes
	refreshInterval time.Duration

	// onUpdate is called when the DC list changes
	onUpdate func([]string) error

	// stopCh signals the refresh goroutine to stop
	stopCh chan struct{}

	// running indicates if the refresh loop is active
	running bool
}

// DCDiscoveryConfig configures DC discovery
type DCDiscoveryConfig struct {
	// Domain is the AD domain name (e.g., "corp.local")
	Domain string

	// RefreshInterval is the interval between DC list refreshes
	// Defaults to 1 hour, minimum 5 minutes
	RefreshInterval time.Duration

	// OnUpdate is called when the DC list changes
	OnUpdate func([]string) error

	// InitialIPs are fallback IPs to use if discovery fails
	InitialIPs []string
}

// NewDCDiscovery creates a new DC discovery instance
func NewDCDiscovery(config *DCDiscoveryConfig) (*DCDiscovery, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if config.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	refreshInterval := config.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = DefaultRefreshInterval
	}
	if refreshInterval < MinRefreshInterval {
		refreshInterval = MinRefreshInterval
	}

	return &DCDiscovery{
		domain:          config.Domain,
		currentIPs:      config.InitialIPs,
		refreshInterval: refreshInterval,
		onUpdate:        config.OnUpdate,
		stopCh:          make(chan struct{}),
	}, nil
}

// DiscoverDCIPs performs DNS SRV lookup to find Domain Controller IPs
// This uses standard DNS queries, no Active Directory module required
func DiscoverDCIPs(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DiscoveryTimeout)
	defer cancel()

	return DiscoverDCIPsWithContext(ctx, domain)
}

// DiscoverDCIPsWithContext performs DNS SRV lookup with context
func DiscoverDCIPsWithContext(ctx context.Context, domain string) ([]string, error) {
	// Normalize domain
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")

	var allIPs []string

	// Try multiple SRV records for redundancy
	srvRecords := []string{
		fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain), // DC Locator (preferred)
		fmt.Sprintf("_ldap._tcp.%s", domain),           // LDAP fallback
		fmt.Sprintf("_kerberos._tcp.%s", domain),       // Kerberos fallback
	}

	var lastErr error

	for _, srvName := range srvRecords {
		ips, err := lookupSRVAndResolve(ctx, srvName)
		if err != nil {
			lastErr = err
			log.WithError(err).WithField("srv", srvName).Debug("SRV lookup failed")
			continue
		}

		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		}
	}

	// Deduplicate IPs
	allIPs = deduplicateStrings(allIPs)

	if len(allIPs) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no DCs found: %w", lastErr)
		}
		return nil, fmt.Errorf("no DCs found for domain %s", domain)
	}

	// Sort for consistent ordering
	sort.Strings(allIPs)

	log.WithFields(log.Fields{
		"domain": domain,
		"dc_ips": allIPs,
		"count":  len(allIPs),
	}).Debug("Discovered DC IPs")

	return allIPs, nil
}

// lookupSRVAndResolve performs SRV lookup and resolves hostnames to IPs
func lookupSRVAndResolve(ctx context.Context, srvName string) ([]string, error) {
	resolver := net.DefaultResolver

	_, srvs, err := resolver.LookupSRV(ctx, "", "", srvName)
	if err != nil {
		return nil, fmt.Errorf("SRV lookup %s: %w", srvName, err)
	}

	var ips []string
	for _, srv := range srvs {
		// Resolve the SRV target to IP addresses
		addrs, err := resolver.LookupHost(ctx, srv.Target)
		if err != nil {
			log.WithError(err).WithField("target", srv.Target).Debug("Host lookup failed")
			continue
		}

		for _, addr := range addrs {
			// Validate it's an IP address
			if ip := net.ParseIP(addr); ip != nil {
				// Only include IPv4 for now (AD typically uses IPv4)
				if ip.To4() != nil {
					ips = append(ips, addr)
				}
			}
		}
	}

	return ips, nil
}

// Start begins the periodic DC list refresh
func (d *DCDiscovery) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	// Perform initial discovery
	ips, err := DiscoverDCIPs(d.domain)
	if err != nil {
		// If we have initial IPs, log warning but continue
		if len(d.currentIPs) > 0 {
			log.WithError(err).Warn("Initial DC discovery failed, using fallback IPs")
		} else {
			return fmt.Errorf("initial DC discovery failed: %w", err)
		}
	} else {
		d.currentIPs = ips
		if d.onUpdate != nil {
			if err := d.onUpdate(ips); err != nil {
				log.WithError(err).Warn("Failed to update firewall with discovered DCs")
			}
		}
	}

	// Start refresh goroutine
	d.running = true
	go d.refreshLoop()

	log.WithFields(log.Fields{
		"domain":   d.domain,
		"interval": d.refreshInterval,
		"dc_count": len(d.currentIPs),
	}).Info("DC discovery started")

	return nil
}

// refreshLoop periodically refreshes the DC list
func (d *DCDiscovery) refreshLoop() {
	ticker := time.NewTicker(d.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.refresh()
		}
	}
}

// refresh performs a single DC list refresh
func (d *DCDiscovery) refresh() {
	d.mu.Lock()
	defer d.mu.Unlock()

	ips, err := DiscoverDCIPs(d.domain)
	if err != nil {
		log.WithError(err).Warn("DC discovery refresh failed")
		return
	}

	// Check if IPs changed
	if equalStringSlices(d.currentIPs, ips) {
		log.Debug("DC list unchanged")
		return
	}

	log.WithFields(log.Fields{
		"old_ips": d.currentIPs,
		"new_ips": ips,
	}).Info("DC list changed")

	// Update current IPs
	oldIPs := d.currentIPs
	d.currentIPs = ips

	// Notify callback
	if d.onUpdate != nil {
		if err := d.onUpdate(ips); err != nil {
			log.WithError(err).Warn("Failed to update firewall with new DC IPs")
			// Revert on failure
			d.currentIPs = oldIPs
		}
	}
}

// Stop stops the periodic refresh
func (d *DCDiscovery) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	close(d.stopCh)
	d.running = false

	log.Info("DC discovery stopped")
}

// GetCurrentIPs returns a copy of the current DC IPs
func (d *DCDiscovery) GetCurrentIPs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]string, len(d.currentIPs))
	copy(result, d.currentIPs)
	return result
}

// ForceRefresh triggers an immediate DC list refresh
func (d *DCDiscovery) ForceRefresh() error {
	d.refresh()
	return nil
}

// deduplicateStrings removes duplicate strings from a slice
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))

	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}
