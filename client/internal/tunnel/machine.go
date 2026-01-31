// Machine Tunnel Fork - Core Machine Tunnel Logic
// This file contains the main orchestration for Windows pre-login VPN.
// It integrates bootstrap, WireGuard setup, NRPT, firewall configuration,
// and Signal/Relay peer connections via PeerEngine.
//
// References:
// - Issue #111: Integrate PeerEngine into machine.go
// - ADR-001: Direct Reuse pattern for Signal/Relay

//go:build windows

package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// MachineState represents the current state of the Machine Tunnel
type MachineState int

const (
	// StateDisconnected - tunnel is not running
	StateDisconnected MachineState = iota
	// StateConnecting - establishing connection to management server
	StateConnecting
	// StateConnected - tunnel is up and running
	StateConnected
	// StateReconnecting - lost connection, attempting to reconnect
	StateReconnecting
	// StateError - unrecoverable error state
	StateError
)

func (s MachineState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// MachineTunnel orchestrates the Windows pre-login VPN connection
type MachineTunnel struct {
	config *MachineTunnelConfig

	// State management
	state    MachineState
	stateMu  sync.RWMutex
	stateErr error

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Current connection result
	bootstrapResult *BootstrapResult
	machineConfig   *MachineConfig // Stored for management client creation
	resultMu        sync.RWMutex

	// WireGuard interface
	wgInterface *iface.WGIface

	// Management client for GetNetworkMap calls
	mgmClient mgm.Client

	// Peer Engine for Signal/Relay connections (Issue #110/111)
	peerEngine *PeerEngine

	// System route operations (Enterprise SOTA - Direct Reuse via ADR-001)
	sysOps       *systemops.SysOps
	activeRoutes []netip.Prefix // Tracks added routes for cleanup
	routesMu     sync.Mutex

	// Callbacks
	onStateChange func(MachineState, error)

	// Health checker (initialized after connection)
	healthChecker *HealthChecker

	// Unhealthy channel for health check failures
	unhealthyCh chan struct{}
}

// MachineTunnelConfig holds the configuration for Machine Tunnel
type MachineTunnelConfig struct {
	// ManagementURL is the URL of the NetBird management server
	ManagementURL string

	// SetupKey for Phase 1 bootstrap (one-time use, should be revoked after Phase 2)
	SetupKey string

	// MachineCertEnabled indicates whether to use machine certificate authentication
	MachineCertEnabled bool

	// MachineCertThumbprint is the expected certificate thumbprint (optional validation)
	MachineCertThumbprint string

	// MTLSPort is the port for mTLS connections (default: 33074)
	MTLSPort int

	// MachineCert contains machine certificate configuration for discovery
	MachineCert MachineCertConfig

	// InterfaceName is the WireGuard interface name (default: wg-nb-machine)
	InterfaceName string

	// ReconnectInterval is the base interval for reconnection attempts
	ReconnectInterval time.Duration

	// MaxReconnectInterval is the maximum backoff interval
	MaxReconnectInterval time.Duration

	// DNSServers is the list of DNS servers for NRPT rules (typically DC IPs)
	DNSServers []string

	// DNSNamespaces is the list of DNS namespaces for NRPT rules
	DNSNamespaces []string

	// AllowedDCIPs is the list of allowed DC IPs for firewall rules
	AllowedDCIPs []string

	// DCRoutes are the Domain Controller network CIDRs to route through the tunnel
	DCRoutes []string

	// HealthCheckInterval is the interval for health checks (default: 30s)
	HealthCheckInterval time.Duration
}

// DefaultConfig returns a MachineTunnelConfig with sensible defaults
func DefaultConfig() *MachineTunnelConfig {
	return &MachineTunnelConfig{
		InterfaceName:        "wg-nb-machine",
		ReconnectInterval:    5 * time.Second,
		MaxReconnectInterval: 5 * time.Minute,
		MTLSPort:             DefaultMTLSPort,
		HealthCheckInterval:  30 * time.Second,
		MachineCert: MachineCertConfig{
			RequiredEKU:  DefaultClientAuthEKU,
			SANMustMatch: true,
		},
	}
}

// NewMachineTunnel creates a new Machine Tunnel instance
func NewMachineTunnel(config *MachineTunnelConfig) (*MachineTunnel, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.ManagementURL == "" {
		return nil, fmt.Errorf("ManagementURL is required")
	}

	// Validate that we have at least one auth method
	if config.SetupKey == "" && !config.MachineCertEnabled {
		return nil, fmt.Errorf("either SetupKey or MachineCertEnabled must be configured")
	}

	return &MachineTunnel{
		config:      config,
		state:       StateDisconnected,
		unhealthyCh: make(chan struct{}, 1),
	}, nil
}

// SetStateChangeCallback sets a callback that is invoked on state changes
func (t *MachineTunnel) SetStateChangeCallback(cb func(MachineState, error)) {
	t.onStateChange = cb
}

// State returns the current tunnel state
func (t *MachineTunnel) State() MachineState {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.state
}

// StateError returns the error if state is StateError
func (t *MachineTunnel) StateError() error {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.stateErr
}

// AuthMethod returns the authentication method used for the current connection
func (t *MachineTunnel) AuthMethod() AuthMethod {
	t.resultMu.RLock()
	defer t.resultMu.RUnlock()
	if t.bootstrapResult == nil {
		return AuthMethodUnknown
	}
	return t.bootstrapResult.AuthMethod
}

// setState updates the tunnel state and notifies callbacks
func (t *MachineTunnel) setState(state MachineState, err error) {
	t.stateMu.Lock()
	oldState := t.state
	t.state = state
	t.stateErr = err
	t.stateMu.Unlock()

	if oldState != state {
		log.WithFields(log.Fields{
			"old_state": oldState.String(),
			"new_state": state.String(),
			"error":     err,
		}).Info("Machine Tunnel state changed")

		if t.onStateChange != nil {
			t.onStateChange(state, err)
		}
	}
}

// Start begins the Machine Tunnel connection process
// This is non-blocking and runs the connection loop in a goroutine
func (t *MachineTunnel) Start(ctx context.Context) error {
	if t.State() != StateDisconnected {
		return fmt.Errorf("tunnel already started (state: %s)", t.State())
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.setState(StateConnecting, nil)

	t.wg.Add(1)
	go t.connectionLoop()

	return nil
}

// Stop gracefully stops the Machine Tunnel
func (t *MachineTunnel) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}

	// Wait for connection loop to finish
	t.wg.Wait()

	// Cleanup resources
	if err := t.Cleanup(); err != nil {
		log.WithError(err).Warn("Cleanup failed during stop")
	}

	t.setState(StateDisconnected, nil)
	log.Info("Machine Tunnel stopped")
	return nil
}

// connectionLoop is the main connection loop with reconnection logic
func (t *MachineTunnel) connectionLoop() {
	defer t.wg.Done()

	reconnectInterval := t.config.ReconnectInterval

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		err := t.connect()
		if err == nil {
			// Connection successful, reset backoff
			reconnectInterval = t.config.ReconnectInterval
			t.setState(StateConnected, nil)

			// Wait for connection to be terminated
			t.maintainConnection()

			// If context is done, exit
			select {
			case <-t.ctx.Done():
				return
			default:
			}

			// Otherwise, attempt reconnect
			t.setState(StateReconnecting, nil)
		} else {
			log.WithError(err).Warn("Machine Tunnel connection failed")

			// Exponential backoff
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(reconnectInterval):
			}

			reconnectInterval = min(reconnectInterval*2, t.config.MaxReconnectInterval)
		}
	}
}

// toMachineConfig converts MachineTunnelConfig to MachineConfig for bootstrap.
// It loads persisted keys from SecureConfig if available, otherwise generates new ones.
//
// Key Persistence Strategy (Enterprise SOTA):
//   - WireGuard and SSH keys are DPAPI-encrypted with machine scope
//   - Keys survive service restarts (critical for management server auth)
//   - Setup key is loaded from SecureConfig or MachineTunnelConfig (fallback)
//   - After first successful bootstrap, keys are persisted to SecureConfig
func (t *MachineTunnel) toMachineConfig() (*MachineConfig, error) {
	// Parse management URL
	mgmtURL, err := url.Parse(t.config.ManagementURL)
	if err != nil {
		return nil, fmt.Errorf("parse management URL: %w", err)
	}

	var wgKeyStr string
	var sshKeyStr string
	var setupKey string
	var needsPersist bool

	// Try to load existing SecureConfig with persisted keys
	configPath := GetConfigPath()
	secureConfig, loadErr := LoadMachineConfigFrom(configPath)

	if loadErr == nil && secureConfig != nil {
		log.Debug("Loaded SecureConfig from disk")

		// Load persisted WireGuard key if available
		if secureConfig.HasPrivateKey() {
			wgKeyStr, err = secureConfig.GetPrivateKey()
			if err != nil {
				log.Warnf("Failed to decrypt persisted WireGuard key, will generate new: %v", err)
			} else {
				log.Debug("Using persisted WireGuard key from SecureConfig")
			}
		}

		// Load persisted SSH key if available
		if secureConfig.HasSSHKey() {
			sshKeyStr, err = secureConfig.GetSSHKey()
			if err != nil {
				log.Warnf("Failed to decrypt persisted SSH key, will generate new: %v", err)
			} else {
				log.Debug("Using persisted SSH key from SecureConfig")
			}
		}

		// Load setup key from SecureConfig (preferred) or fallback to MachineTunnelConfig
		if secureConfig.HasSetupKey() {
			setupKey, err = secureConfig.GetSetupKey()
			if err != nil {
				log.Warnf("Failed to decrypt setup key from SecureConfig: %v", err)
			}
		}
	} else {
		log.Debugf("No SecureConfig found or load failed: %v - will create new", loadErr)
		needsPersist = true
	}

	// Fallback: use setup key from MachineTunnelConfig if not in SecureConfig
	if setupKey == "" && t.config.SetupKey != "" {
		setupKey = t.config.SetupKey
		needsPersist = true // Need to persist the encrypted setup key
	}

	// Generate WireGuard key if not loaded from SecureConfig
	if wgKeyStr == "" {
		log.Info("Generating new WireGuard private key (first bootstrap or key migration)")
		wgKey, err := wgtypes.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate WireGuard private key: %w", err)
		}
		wgKeyStr = wgKey.String()
		needsPersist = true
	}

	// Generate SSH key if not loaded from SecureConfig
	if sshKeyStr == "" {
		log.Info("Generating new SSH private key (first bootstrap or key migration)")
		sshKeyPEM, err := ssh.GeneratePrivateKey(ssh.ED25519)
		if err != nil {
			return nil, fmt.Errorf("generate SSH private key: %w", err)
		}
		sshKeyStr = string(sshKeyPEM)
		needsPersist = true
	}

	// Persist keys if this is first bootstrap or migration
	if needsPersist {
		if err := t.persistKeys(mgmtURL.String(), wgKeyStr, sshKeyStr, setupKey); err != nil {
			// Log but don't fail - keys are in memory and bootstrap can proceed
			// Next restart will regenerate keys (not ideal but functional)
			log.Warnf("Failed to persist keys to SecureConfig: %v", err)
		}
	}

	// Create base profile config
	baseConfig := &profilemanager.Config{
		ManagementURL: mgmtURL,
		PrivateKey:    wgKeyStr,
		SSHKey:        sshKeyStr,
	}

	// Build auth.MachineCertConfig from MachineTunnelConfig
	// Merge the individual fields into auth.MachineCertConfig for certificate discovery
	machineCertCfg := auth.MachineCertConfig{
		Enabled:            t.config.MachineCertEnabled,
		TemplateOID:        t.config.MachineCert.TemplateOID,
		TemplateName:       t.config.MachineCert.TemplateName,
		RequiredEKU:        t.config.MachineCert.RequiredEKU,
		SANMustMatch:       t.config.MachineCert.SANMustMatch,
		ThumbprintOverride: t.config.MachineCertThumbprint,
	}

	// Get hostname for SAN matching
	hostname, _ := os.Hostname()

	return &MachineConfig{
		Config:      baseConfig,
		MachineCert: machineCertCfg,
		SetupKey:    setupKey,
		MTLSPort:    t.config.MTLSPort,
		DCRoutes:    t.config.DCRoutes,
		Hostname:    hostname,
	}, nil
}

// persistKeys saves the WireGuard, SSH, and setup keys to SecureConfig with DPAPI encryption.
// This ensures keys survive service restarts.
func (t *MachineTunnel) persistKeys(managementURL, wgKey, sshKey, setupKey string) error {
	configPath := GetConfigPath()

	// Load existing config or create new one
	secureConfig, err := LoadMachineConfigFrom(configPath)
	if err != nil {
		// Create new SecureConfig
		secureConfig = &SecureConfig{
			ManagementURL:      managementURL,
			MachineCertEnabled: t.config.MachineCertEnabled,
		}
	}

	// Update management URL if changed
	secureConfig.ManagementURL = managementURL
	secureConfig.MachineCertEnabled = t.config.MachineCertEnabled
	secureConfig.MachineCertThumbprint = t.config.MachineCertThumbprint

	// Encrypt and store WireGuard key
	if wgKey != "" {
		if err := secureConfig.SetPrivateKey(wgKey); err != nil {
			return fmt.Errorf("encrypt WireGuard key: %w", err)
		}
	}

	// Encrypt and store SSH key
	if sshKey != "" {
		if err := secureConfig.SetSSHKey(sshKey); err != nil {
			return fmt.Errorf("encrypt SSH key: %w", err)
		}
	}

	// Encrypt and store setup key (if not already stored)
	if setupKey != "" && !secureConfig.HasSetupKey() {
		if err := secureConfig.SetSetupKey(setupKey); err != nil {
			return fmt.Errorf("encrypt setup key: %w", err)
		}
	}

	// Save to disk with hardened ACLs
	if err := secureConfig.SaveTo(configPath); err != nil {
		return fmt.Errorf("save SecureConfig: %w", err)
	}

	log.WithField("path", configPath).Info("Persisted encrypted keys to SecureConfig")
	return nil
}

// connect establishes the Machine Tunnel connection
// This includes:
// 1. Bootstrap authentication (Setup-Key or mTLS)
// 2. Setting up WireGuard interface
// 3. Configuring NRPT rules for AD DNS
// 4. Configuring firewall rules for DC traffic
// 5. Initialize PeerEngine and connect to remote peers (Issue #111)
func (t *MachineTunnel) connect() error {
	log.Info("Machine Tunnel connecting...")

	// Step 1: Bootstrap - authenticate and get peer configuration
	machineConfig, err := t.toMachineConfig()
	if err != nil {
		return fmt.Errorf("create machine config: %w", err)
	}

	result, err := Bootstrap(t.ctx, machineConfig)
	if err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	log.WithFields(log.Fields{
		"auth_method": result.AuthMethod.String(),
		"peer_ip":     result.PeerConfig.GetAddress(),
	}).Info("Bootstrap successful")

	// Store result and config for later use
	t.resultMu.Lock()
	t.bootstrapResult = result
	t.machineConfig = machineConfig
	t.resultMu.Unlock()

	// Step 2: Setup WireGuard interface
	// The bootstrap result contains the peer config with WireGuard keys and allowed IPs
	if err := t.setupWireGuardInterface(result, machineConfig); err != nil {
		return fmt.Errorf("WireGuard setup failed: %w", err)
	}

	// Step 3: Configure NRPT rules for AD DNS routing
	if err := t.configureNRPT(result); err != nil {
		// Non-fatal - log warning and continue
		log.WithError(err).Warn("NRPT configuration failed, DNS resolution may not work correctly")
	}

	// Step 4: Configure firewall rules for DC traffic
	if err := t.configureFirewall(result); err != nil {
		// Non-fatal - log warning and continue
		log.WithError(err).Warn("Firewall configuration failed, DC traffic may be blocked")
	}

	// Step 5: Initialize PeerEngine and connect to remote peers (Issue #111)
	if err := t.initializePeerEngine(result, machineConfig); err != nil {
		return fmt.Errorf("PeerEngine initialization failed: %w", err)
	}

	return nil
}

// setupWireGuardInterface creates and configures the WireGuard interface
func (t *MachineTunnel) setupWireGuardInterface(result *BootstrapResult, machineConfig *MachineConfig) error {
	if result.PeerConfig == nil {
		return fmt.Errorf("no peer config in bootstrap result")
	}

	address := result.PeerConfig.GetAddress()
	log.WithFields(log.Fields{
		"interface": t.config.InterfaceName,
		"address":   address,
	}).Info("Creating WireGuard interface")

	// Use defaults if not specified
	mtu := uint16(iface.DefaultMTU)
	wgPort := iface.DefaultWgPort

	// Create WireGuard interface options
	// Note: TransportNet and FilterFn are optional for basic operation
	opts := iface.WGIFaceOpts{
		IFaceName: t.config.InterfaceName,
		Address:   address,
		WGPort:    wgPort,
		WGPrivKey: machineConfig.Config.PrivateKey,
		MTU:       mtu,
		// TransportNet: nil - uses default
		// FilterFn: nil - no filtering
		// DisableDNS: false - allow DNS
	}

	// Create WireGuard interface instance
	wgIface, err := iface.NewWGIFace(opts)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %w", err)
	}

	// Create the actual TUN device
	log.Info(">>> Calling wgIface.Create()...")
	if err := wgIface.Create(); err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	log.Info(">>> wgIface.Create() completed successfully")

	// Bring the interface up
	log.Info(">>> Calling wgIface.Up()...")
	_, err = wgIface.Up()
	if err != nil {
		log.WithError(err).Error(">>> wgIface.Up() failed")
		return fmt.Errorf("failed to bring up WireGuard interface: %w", err)
	}
	log.Info(">>> wgIface.Up() completed successfully")

	// Store the interface for later use (peer connections, cleanup)
	t.wgInterface = wgIface

	// Initialize SysOps for system route management (Enterprise SOTA - ADR-001)
	// Uses NetBird's native route handling via Windows IP Helper API
	t.sysOps = systemops.New(wgIface, nil)
	log.Debug("SysOps initialized for system route management")

	log.WithFields(log.Fields{
		"interface": wgIface.Name(),
		"address":   wgIface.Address().String(),
		"mtu":       wgIface.MTU(),
	}).Info("WireGuard interface created successfully")

	return nil
}

// configureNRPT sets up Name Resolution Policy Table rules for AD DNS
func (t *MachineTunnel) configureNRPT(result *BootstrapResult) error {
	if result.DNSConfig == nil {
		log.Debug("No DNS config in bootstrap result, skipping NRPT")
		return nil
	}

	log.Info("Configuring NRPT rules for AD DNS routing")

	// Extract DNS servers and namespaces from config
	var dnsServers []string
	var namespaces []string

	// Use config from bootstrap result or fall back to MachineTunnelConfig
	if len(t.config.DNSServers) > 0 {
		dnsServers = t.config.DNSServers
	}
	if len(t.config.DNSNamespaces) > 0 {
		namespaces = t.config.DNSNamespaces
	}

	if len(dnsServers) == 0 || len(namespaces) == 0 {
		log.Debug("No DNS servers or namespaces configured, skipping NRPT")
		return nil
	}

	// Use NRPT manager
	nrptMgr := NewNRPTManager()
	for _, ns := range namespaces {
		if err := nrptMgr.AddRule(ns, dnsServers); err != nil {
			return fmt.Errorf("failed to add NRPT rule for %s: %w", ns, err)
		}
	}

	log.WithField("namespaces", namespaces).Info("NRPT rules configured")
	return nil
}

// configureFirewall sets up Windows Firewall rules for DC traffic
func (t *MachineTunnel) configureFirewall(result *BootstrapResult) error {
	log.Info("Configuring firewall rules for DC traffic")

	// Get DC IPs from config or bootstrap result
	dcIPs := t.config.AllowedDCIPs
	if len(dcIPs) == 0 && result.AllowedDCRoutes != nil {
		// Extract IPs from routes
		for _, route := range result.AllowedDCRoutes {
			dcIPs = append(dcIPs, route.GetNetwork())
		}
	}

	if len(dcIPs) == 0 {
		log.Debug("No DC IPs configured, skipping firewall rules")
		return nil
	}

	// Use firewall manager
	fwMgr := NewFirewallManager(t.config.InterfaceName)

	// Add allow rules for DC IPs
	for _, ip := range dcIPs {
		if err := fwMgr.AllowDCTraffic(ip); err != nil {
			return fmt.Errorf("failed to add firewall rule for %s: %w", ip, err)
		}
	}

	// Enable deny-default rule (T-4.6)
	if err := fwMgr.EnableDenyDefault(); err != nil {
		log.WithError(err).Warn("Failed to enable deny-default rule")
	}

	log.WithField("dc_ips", dcIPs).Info("Firewall rules configured")
	return nil
}

// initializePeerEngine creates and starts the PeerEngine for Signal/Relay connections.
// It fetches the current NetworkMap to get RemotePeers and connects to them.
// Reference: Issue #111, ADR-001 (Direct Reuse pattern)
func (t *MachineTunnel) initializePeerEngine(result *BootstrapResult, machineConfig *MachineConfig) error {
	log.Info("Initializing PeerEngine for Signal/Relay connections")

	// Use the EXISTING WireGuard key from Bootstrap (stored in config)
	// CRITICAL: Must use same key that was registered during Bootstrap!
	// Using a new key would cause "failed handling request" from management server.
	// Reference: bootstrap.go:409 uses same pattern
	wgKey, err := wgtypes.ParseKey(machineConfig.Config.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse WireGuard key from config: %w", err)
	}
	log.WithField("wg_pubkey", wgKey.PublicKey().String()[:8]+"...").Debug("Using existing WireGuard key from config")

	// Create management client for GetNetworkMap calls
	mgmClient, err := t.createMgmClient(machineConfig, wgKey)
	if err != nil {
		return fmt.Errorf("create management client: %w", err)
	}
	t.mgmClient = mgmClient

	// Get NetworkMap to retrieve RemotePeers
	sysInfo := system.GetInfo(t.ctx)
	networkMap, err := mgmClient.GetNetworkMap(sysInfo)
	if err != nil {
		return fmt.Errorf("get network map: %w", err)
	}

	remotePeers := networkMap.GetRemotePeers()
	if len(remotePeers) == 0 {
		log.Warn("No remote peers in NetworkMap - tunnel will have no peer connections")
		// Not an error - machine might not have any assigned peers yet
		return nil
	}

	log.WithField("peer_count", len(remotePeers)).Info("Got remote peers from NetworkMap")

	// Parse routes from NetworkMap to build peerKey -> []networks map
	// Routes define which networks should be routed through which peer (router-peers)
	// Reference: NetBird engine.go uses routeManager for this, we do a simplified version
	peerRouteMap := buildPeerRouteMap(networkMap.GetRoutes())
	if len(peerRouteMap) > 0 {
		log.WithField("routing_peers", len(peerRouteMap)).Info("Parsed routes from NetworkMap")
		for peer, networks := range peerRouteMap {
			log.WithFields(log.Fields{
				"peer":     peer[:8] + "...",
				"networks": networks,
			}).Debug("Route networks for peer")
		}
	}

	// Build PeerEngineConfig from BootstrapResult
	peerEngineCfg, err := t.buildPeerEngineConfig(result, wgKey)
	if err != nil {
		return fmt.Errorf("build peer engine config: %w", err)
	}

	// Create PeerEngine
	peerEngine, err := NewPeerEngine(t.ctx, wgKey, peerEngineCfg)
	if err != nil {
		return fmt.Errorf("create peer engine: %w", err)
	}
	t.peerEngine = peerEngine

	// Start PeerEngine (starts Signal receive loop and Relay manager)
	if err := t.peerEngine.Start(); err != nil {
		return fmt.Errorf("start peer engine: %w", err)
	}

	// Connect to remote peers (parallel with limit)
	// Pass peerRouteMap to merge route networks into peer AllowedIPs
	if err := t.connectToRemotePeers(remotePeers, peerRouteMap); err != nil {
		log.WithError(err).Warn("Some peer connections failed")
		// Not fatal - some peers might still work
	}

	log.Info("PeerEngine initialized successfully")
	return nil
}

// createMgmClient creates a management client for ongoing management server communication.
// This is separate from Bootstrap which creates its own temporary client.
// The wgKey parameter is the WireGuard private key used for client authentication.
func (t *MachineTunnel) createMgmClient(machineConfig *MachineConfig, wgKey wgtypes.Key) (mgm.Client, error) {
	if machineConfig.Config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	tlsEnabled := machineConfig.Config.ManagementURL.Scheme == "https"

	client, err := mgm.NewClient(t.ctx, machineConfig.Config.ManagementURL.Host, wgKey, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("create management client: %w", err)
	}

	return client, nil
}

// buildPeerEngineConfig creates a PeerEngineConfig from BootstrapResult and NetbirdConfig.
// CRITICAL: t.wgInterface MUST be set before calling this function!
func (t *MachineTunnel) buildPeerEngineConfig(result *BootstrapResult, wgKey wgtypes.Key) (PeerEngineConfig, error) {
	if t.wgInterface == nil {
		return PeerEngineConfig{}, fmt.Errorf("WireGuard interface not set - call setupWireGuardInterface first")
	}
	netbirdCfg := result.NetbirdConfig
	if netbirdCfg == nil {
		return PeerEngineConfig{}, fmt.Errorf("no NetbirdConfig in bootstrap result")
	}

	// Extract Signal config
	signalCfg := netbirdCfg.GetSignal()
	if signalCfg == nil {
		return PeerEngineConfig{}, fmt.Errorf("no Signal config in NetbirdConfig")
	}

	// Extract Relay URLs
	relayURLs := extractRelayURLs(netbirdCfg)

	// Extract Relay Token
	relayToken := extractRelayToken(netbirdCfg)

	// Extract STUN URLs
	stunURLs := extractStunURLs(netbirdCfg)

	// Extract TURN configs
	turnConfigs := extractTurnConfigs(netbirdCfg)

	cfg := PeerEngineConfig{
		SignalAddr:     signalCfg.GetUri(),
		SignalTLS:      signalCfg.GetProtocol() == mgmProto.HostConfig_HTTPS,
		SignalProtocol: signalCfg.GetProtocol().String(),

		RelayURLs:  relayURLs,
		RelayToken: relayToken,

		StunURLs: stunURLs,
		TurnURLs: turnConfigs,

		// ICE config - use defaults for now
		InterfaceBlackList:   []string{},
		DisableIPv6Discovery: false,
		NATExternalIPs:       []string{},

		// WireGuard config - use the interface created in setupWireGuardInterface
		WgInterface:  t.wgInterface,
		WgPort:       51820,
		PreSharedKey: nil,

		MTU:           uint16(result.PeerConfig.GetMtu()),
		MgmtURL:       t.config.ManagementURL,
		MaxConcurrent: DefaultMaxConcurrentPeers,
	}

	return cfg, nil
}

// connectToRemotePeers connects to all remote peers in parallel with a concurrency limit.
// peerRouteMap contains peerKey -> []networks for route-based AllowedIPs extension.
// Enterprise SOTA: Routes from NetworkMap are merged into peer AllowedIPs.
func (t *MachineTunnel) connectToRemotePeers(remotePeers []*mgmProto.RemotePeerConfig, peerRouteMap map[string][]string) error {
	if t.peerEngine == nil {
		return fmt.Errorf("peer engine not initialized")
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, DefaultMaxConcurrentPeers)
	var connErrors atomic.Int32

	// Collect route networks for Windows system route creation
	var routeNetworksMu sync.Mutex
	routeNetworks := make([]string, 0)

	for _, rp := range remotePeers {
		wg.Add(1)
		go func(peer *mgmProto.RemotePeerConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerKey := peer.GetWgPubKey()
			allowedIPs := peer.GetAllowedIps()

			// Merge route networks into AllowedIPs if this peer is a routing peer
			if routeNets, hasRoutes := peerRouteMap[peerKey]; hasRoutes {
				log.WithFields(log.Fields{
					"peer":           peerKey[:8] + "...",
					"base_allowed":   allowedIPs,
					"route_networks": routeNets,
				}).Info("Merging route networks into peer AllowedIPs")

				// Merge: original AllowedIPs + route networks (deduplicated)
				allowedIPs = mergeAllowedIPs(allowedIPs, routeNets)

				// Track route networks for Windows system routes
				routeNetworksMu.Lock()
				routeNetworks = append(routeNetworks, routeNets...)
				routeNetworksMu.Unlock()
			}

			log.WithFields(log.Fields{
				"peer":       peerKey[:8] + "...",
				"allowedIPs": allowedIPs,
			}).Debug("Connecting to peer with AllowedIPs")

			_, err := t.peerEngine.ConnectPeer(t.ctx, peerKey, allowedIPs)
			if err != nil {
				log.WithFields(log.Fields{
					"peer":  peerKey[:8] + "...",
					"error": err,
				}).Warn("Failed to connect to peer")
				connErrors.Add(1)
				return
			}

			log.WithField("peer", peerKey[:8]+"...").Info("Connected to peer")
		}(rp)
	}

	wg.Wait()

	failedCount := connErrors.Load()
	if failedCount == int32(len(remotePeers)) {
		return fmt.Errorf("all %d peer connections failed", len(remotePeers))
	}

	if failedCount > 0 {
		log.WithFields(log.Fields{
			"failed":    failedCount,
			"succeeded": int32(len(remotePeers)) - failedCount,
		}).Warn("Some peer connections failed")
	}

	// Add Windows system routes for route networks
	// This ensures traffic to these networks goes through the WireGuard interface
	if len(routeNetworks) > 0 {
		if err := t.addWindowsSystemRoutes(routeNetworks); err != nil {
			log.WithError(err).Warn("Failed to add some Windows system routes")
			// Not fatal - peer connection still works, just routing might be incomplete
		}
	}

	return nil
}

// mergeAllowedIPs merges base AllowedIPs with route networks, removing duplicates.
func mergeAllowedIPs(base []string, routes []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(base)+len(routes))

	// Add base AllowedIPs
	for _, ip := range base {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}

	// Add route networks
	for _, ip := range routes {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}

	return result
}

// addWindowsSystemRoutes adds Windows system routes for the given networks.
// Routes are added via the WireGuard interface using Windows IP Helper API.
// This is Enterprise SOTA - Direct Reuse of NetBird's systemops (ADR-001).
//
// Why system routes are needed:
// - WireGuard AllowedIPs control crypto-routing (which peer handles which IPs)
// - Windows also needs SYSTEM routes to direct traffic to the WireGuard TUN interface
// - Without system routes, traffic to DC networks goes to physical gateway instead of tunnel
func (t *MachineTunnel) addWindowsSystemRoutes(networks []string) error {
	if t.wgInterface == nil {
		return fmt.Errorf("WireGuard interface not available")
	}
	if t.sysOps == nil {
		return fmt.Errorf("SysOps not initialized")
	}

	interfaceName := t.wgInterface.Name()

	// Get the *net.Interface for the WireGuard TUN device
	wgNetInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("get WireGuard interface by name %q: %w", interfaceName, err)
	}

	log.WithFields(log.Fields{
		"interface":       interfaceName,
		"interface_index": wgNetInterface.Index,
		"networks":        networks,
	}).Info("Adding Windows system routes via systemops (Enterprise SOTA)")

	var errs []error
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			log.WithFields(log.Fields{
				"network": network,
				"error":   err,
			}).Warn("Invalid network CIDR, skipping route")
			continue
		}

		// Add system route via Windows IP Helper API (CreateIpForwardEntry2)
		// This directs traffic matching the prefix to the WireGuard TUN interface
		if err := t.sysOps.AddVPNRoute(prefix, wgNetInterface); err != nil {
			log.WithFields(log.Fields{
				"network":   prefix.String(),
				"interface": interfaceName,
				"error":     err,
			}).Error("Failed to add system route")
			errs = append(errs, fmt.Errorf("add route %s: %w", prefix, err))
			continue
		}

		// Track successfully added route for cleanup
		t.routesMu.Lock()
		t.activeRoutes = append(t.activeRoutes, prefix)
		t.routesMu.Unlock()

		log.WithFields(log.Fields{
			"network":         prefix.String(),
			"interface":       interfaceName,
			"interface_index": wgNetInterface.Index,
		}).Info("System route added successfully")
	}

	if len(errs) > 0 {
		return fmt.Errorf("route errors: %v", errs)
	}

	return nil
}

// removeWindowsSystemRoutes removes all system routes that were added.
// Called during Cleanup to ensure clean state.
func (t *MachineTunnel) removeWindowsSystemRoutes() error {
	if t.wgInterface == nil {
		log.Debug("No WireGuard interface, skipping route cleanup")
		return nil
	}
	if t.sysOps == nil {
		log.Debug("No SysOps, skipping route cleanup")
		return nil
	}

	t.routesMu.Lock()
	routes := make([]netip.Prefix, len(t.activeRoutes))
	copy(routes, t.activeRoutes)
	t.activeRoutes = nil
	t.routesMu.Unlock()

	if len(routes) == 0 {
		log.Debug("No active routes to remove")
		return nil
	}

	interfaceName := t.wgInterface.Name()
	wgNetInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		// Interface might already be gone - that's okay, routes are removed with it
		log.WithFields(log.Fields{
			"interface": interfaceName,
			"error":     err,
		}).Debug("Could not get interface for route cleanup, routes may already be removed")
		return nil //nolint:nilerr // intentional: interface gone during cleanup is expected
	}

	log.WithFields(log.Fields{
		"interface": interfaceName,
		"routes":    len(routes),
	}).Info("Removing Windows system routes")

	var errs []error
	for _, prefix := range routes {
		if err := t.sysOps.RemoveVPNRoute(prefix, wgNetInterface); err != nil {
			log.WithFields(log.Fields{
				"network":   prefix.String(),
				"interface": interfaceName,
				"error":     err,
			}).Warn("Failed to remove system route")
			errs = append(errs, fmt.Errorf("remove route %s: %w", prefix, err))
			continue
		}
		log.WithField("network", prefix.String()).Debug("System route removed")
	}

	if len(errs) > 0 {
		return fmt.Errorf("route cleanup errors: %v", errs)
	}

	return nil
}

// extractRelayURLs extracts Relay URLs from NetbirdConfig.
func extractRelayURLs(cfg *mgmProto.NetbirdConfig) []string {
	if cfg == nil || cfg.GetRelay() == nil {
		return nil
	}
	return cfg.GetRelay().GetUrls()
}

// extractRelayToken extracts HMAC token for Relay auth from NetbirdConfig.
func extractRelayToken(cfg *mgmProto.NetbirdConfig) *RelayToken {
	if cfg == nil || cfg.GetRelay() == nil {
		return nil
	}
	relay := cfg.GetRelay()
	payload := relay.GetTokenPayload()
	sig := relay.GetTokenSignature()
	if payload == "" || sig == "" {
		return nil
	}
	return &RelayToken{Payload: payload, Signature: sig}
}

// extractStunURLs extracts STUN URLs from NetbirdConfig.
func extractStunURLs(cfg *mgmProto.NetbirdConfig) []string {
	if cfg == nil {
		return nil
	}
	stuns := cfg.GetStuns()
	if len(stuns) == 0 {
		return nil
	}
	urls := make([]string, 0, len(stuns))
	for _, s := range stuns {
		urls = append(urls, s.GetUri())
	}
	return urls
}

// extractTurnConfigs extracts TURN configurations with credentials from NetbirdConfig.
func extractTurnConfigs(cfg *mgmProto.NetbirdConfig) []TurnConfig {
	if cfg == nil {
		return nil
	}
	turns := cfg.GetTurns()
	if len(turns) == 0 {
		return nil
	}
	configs := make([]TurnConfig, 0, len(turns))
	for _, turn := range turns {
		host := turn.GetHostConfig()
		if host == nil {
			continue
		}
		configs = append(configs, TurnConfig{
			URL:      host.GetUri(),
			Username: turn.GetUser(),
			Password: turn.GetPassword(),
		})
	}
	return configs
}

// maintainConnection monitors the connection and handles keepalives
func (t *MachineTunnel) maintainConnection() {
	// Initialize health checker
	healthConfig := DefaultHealthCheckConfig()
	healthConfig.Interval = t.config.HealthCheckInterval
	healthConfig.InterfaceName = t.config.InterfaceName

	t.healthChecker = NewHealthChecker(healthConfig)

	// Set interface checker function
	t.healthChecker.SetInterfaceChecker(func() (bool, error) {
		ifaceMgr := NewInterfaceManager(t.config.InterfaceName)
		err := ifaceMgr.CheckHealth()
		if err != nil {
			return false, err
		}
		return true, nil
	})

	// Set unhealthy callback
	t.healthChecker.SetOnUnhealthy(func() {
		// Non-blocking send to signal unhealthy
		select {
		case t.unhealthyCh <- struct{}{}:
		default:
		}
	})

	// Start health checking in background
	healthCtx, healthCancel := context.WithCancel(t.ctx)
	defer healthCancel()

	if err := t.healthChecker.Start(healthCtx); err != nil {
		log.WithError(err).Warn("Failed to start health checker")
	}
	defer t.healthChecker.Stop()

	// Wait for context cancellation or health failure
	select {
	case <-t.ctx.Done():
		log.Info("Connection maintenance stopped: context cancelled")
	case <-t.unhealthyCh:
		log.Warn("Connection maintenance stopped: health check failed")
	}
}

// Cleanup removes NRPT rules, firewall rules, WireGuard interface,
// and closes PeerEngine and management client.
func (t *MachineTunnel) Cleanup() error {
	log.Info("Machine Tunnel cleanup...")

	var errs []error

	// Close PeerEngine first (to stop peer connections and Signal/Relay)
	if t.peerEngine != nil {
		if err := t.peerEngine.Close(); err != nil {
			errs = append(errs, fmt.Errorf("PeerEngine cleanup: %w", err))
		}
		t.peerEngine = nil
	}

	// Close management client
	if t.mgmClient != nil {
		if err := t.mgmClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("management client cleanup: %w", err))
		}
		t.mgmClient = nil
	}

	// Remove NRPT rules
	nrptMgr := NewNRPTManager()
	if err := nrptMgr.RemoveAllRules(); err != nil {
		errs = append(errs, fmt.Errorf("NRPT cleanup: %w", err))
	}

	// Remove firewall rules
	fwMgr := NewFirewallManager(t.config.InterfaceName)
	if err := fwMgr.RemoveAllRules(); err != nil {
		errs = append(errs, fmt.Errorf("firewall cleanup: %w", err))
	}

	// Remove system routes (before closing WireGuard interface)
	if err := t.removeWindowsSystemRoutes(); err != nil {
		errs = append(errs, fmt.Errorf("route cleanup: %w", err))
	}

	// Close WireGuard interface (the iface.WGIface we created)
	if t.wgInterface != nil {
		if err := t.wgInterface.Close(); err != nil {
			errs = append(errs, fmt.Errorf("WireGuard interface close: %w", err))
		}
		t.wgInterface = nil
	}

	// Remove WireGuard interface (legacy InterfaceManager, for any remaining cleanup)
	ifaceMgr := NewInterfaceManager(t.config.InterfaceName)
	if err := ifaceMgr.Teardown(); err != nil {
		errs = append(errs, fmt.Errorf("interface cleanup: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	log.Info("Machine Tunnel cleanup complete")
	return nil
}

// buildPeerRouteMap parses routes from NetworkMap and builds a map of peer -> []networks.
// This is used to add route networks to peer AllowedIPs when connecting.
// Enterprise SOTA: Proper route handling like standard NetBird engine.
// Reference: engine.go:1093 (toRoutes), routemanager/client/client.go:285 (addAllowedIPs)
func buildPeerRouteMap(routes []*mgmProto.Route) map[string][]string {
	if len(routes) == 0 {
		return nil
	}

	peerRouteMap := make(map[string][]string)

	for _, r := range routes {
		if r == nil {
			continue
		}

		peerKey := r.GetPeer()
		network := r.GetNetwork()

		// Skip invalid entries
		if peerKey == "" || network == "" {
			continue
		}

		// Skip domain-based routes (DNS forwarding) - we only handle network routes
		if len(r.GetDomains()) > 0 {
			log.WithField("domains", r.GetDomains()).Debug("Skipping domain-based route")
			continue
		}

		// Skip if SkipAutoApply is set (admin explicitly disabled auto-routing)
		if r.GetSkipAutoApply() {
			log.WithFields(log.Fields{
				"network": network,
				"peer":    peerKey[:8] + "...",
			}).Debug("Skipping route with SkipAutoApply=true")
			continue
		}

		// Validate CIDR format
		_, err := netip.ParsePrefix(network)
		if err != nil {
			log.WithFields(log.Fields{
				"network": network,
				"error":   err,
			}).Warn("Invalid network CIDR in route, skipping")
			continue
		}

		// Add to peer's route list
		peerRouteMap[peerKey] = append(peerRouteMap[peerKey], network)

		log.WithFields(log.Fields{
			"peer":       peerKey[:8] + "...",
			"network":    network,
			"masquerade": r.GetMasquerade(),
			"keep_route": r.GetKeepRoute(),
		}).Debug("Added route to peer map")
	}

	return peerRouteMap
}
