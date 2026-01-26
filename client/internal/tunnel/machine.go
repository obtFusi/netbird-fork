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
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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

	// Current machine config (contains WG private key)
	machineConfig *MachineConfig

	// WireGuard interface
	wgInterface *iface.WGIface

	// Management client for GetNetworkMap calls
	mgmClient mgm.Client

	// Peer Engine for Signal/Relay connections (Issue #110/111)
	peerEngine *PeerEngine

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

	// WGPort is the WireGuard listening port (default: 51820)
	WGPort int

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
		WGPort:               iface.DefaultWgPort,
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

// toMachineConfig converts MachineTunnelConfig to MachineConfig for bootstrap
func (t *MachineTunnel) toMachineConfig() (*MachineConfig, error) {
	// Parse management URL
	mgmtURL, err := url.Parse(t.config.ManagementURL)
	if err != nil {
		return nil, fmt.Errorf("parse management URL: %w", err)
	}

	// Generate WireGuard key if not already stored
	// For Machine Tunnel, we generate ephemeral keys per session
	// (unlike user tunnel which persists keys)
	wgKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate WireGuard key: %w", err)
	}
	log.Debug("Generated new WireGuard key for Machine Tunnel")

	// Generate SSH key
	sshKeyPEM, err := ssh.GeneratePrivateKey(ssh.ED25519)
	if err != nil {
		return nil, fmt.Errorf("generate SSH key: %w", err)
	}
	log.Debug("Generated new SSH key for Machine Tunnel")

	// Create base profile config with generated keys
	baseConfig := &profilemanager.Config{
		ManagementURL: mgmtURL,
		PrivateKey:    wgKey.String(),
		SSHKey:        string(sshKeyPEM),
	}

	return &MachineConfig{
		Config:                baseConfig,
		MachineCertEnabled:    t.config.MachineCertEnabled,
		MachineCertThumbprint: t.config.MachineCertThumbprint,
		SetupKey:              t.config.SetupKey,
		MTLSPort:              t.config.MTLSPort,
		DCRoutes:              t.config.DCRoutes,
	}, nil
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

	// Store machine config for later use (contains WG private key)
	t.machineConfig = machineConfig

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
	// Create the actual WireGuard interface using the peer config and our private key
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

	// Get peer address from bootstrap result
	peerAddress := result.PeerConfig.GetAddress()
	if peerAddress == "" {
		return fmt.Errorf("no peer address in bootstrap result")
	}

	// Get MTU from peer config, fall back to default if not set
	mtu := uint16(iface.DefaultMTU)
	if result.PeerConfig.GetMtu() > 0 {
		mtu = uint16(result.PeerConfig.GetMtu())
	}

	log.WithFields(log.Fields{
		"interface": t.config.InterfaceName,
		"address":   peerAddress,
		"wg_port":   t.config.WGPort,
		"mtu":       mtu,
	}).Info("Creating WireGuard interface")

	// Create WireGuard interface options
	opts := iface.WGIFaceOpts{
		IFaceName: t.config.InterfaceName,
		Address:   peerAddress,
		WGPort:    t.config.WGPort,
		WGPrivKey: machineConfig.Config.PrivateKey,
		MTU:       mtu,
	}

	// Create the WireGuard interface object
	wgIface, err := iface.NewWGIFace(opts)
	if err != nil {
		return fmt.Errorf("create WireGuard interface object: %w", err)
	}

	// Actually create the interface on the system
	if err := wgIface.Create(); err != nil {
		return fmt.Errorf("create WireGuard interface on system: %w", err)
	}

	// Store the interface for later use
	t.wgInterface = wgIface

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

	// Generate WireGuard key for peer connections FIRST
	// This key is used for both management client authentication and PeerEngine
	wgKey, err := wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate WireGuard key: %w", err)
	}

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
	if err := t.connectToRemotePeers(remotePeers); err != nil {
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
func (t *MachineTunnel) buildPeerEngineConfig(result *BootstrapResult, wgKey wgtypes.Key) (PeerEngineConfig, error) {
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

		// WireGuard config - will be populated per-peer
		WgInterface:  nil, // Set when connecting peers
		WgPort:       51820,
		PreSharedKey: nil,

		MTU:           uint16(result.PeerConfig.GetMtu()),
		MgmtURL:       t.config.ManagementURL,
		MaxConcurrent: DefaultMaxConcurrentPeers,
	}

	return cfg, nil
}

// connectToRemotePeers connects to all remote peers in parallel with a concurrency limit.
func (t *MachineTunnel) connectToRemotePeers(remotePeers []*mgmProto.RemotePeerConfig) error {
	if t.peerEngine == nil {
		return fmt.Errorf("peer engine not initialized")
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, DefaultMaxConcurrentPeers)
	var connErrors atomic.Int32

	for _, rp := range remotePeers {
		wg.Add(1)
		go func(peer *mgmProto.RemotePeerConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerKey := peer.GetWgPubKey()
			allowedIPs := peer.GetAllowedIps()

			log.WithField("peer", peerKey[:8]).Debug("Connecting to peer")

			_, err := t.peerEngine.ConnectPeer(t.ctx, peerKey, allowedIPs)
			if err != nil {
				log.WithFields(log.Fields{
					"peer":  peerKey[:8],
					"error": err,
				}).Warn("Failed to connect to peer")
				connErrors.Add(1)
				return
			}

			log.WithField("peer", peerKey[:8]).Info("Connected to peer")
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

	// Close WireGuard interface if it exists
	if t.wgInterface != nil {
		if err := t.wgInterface.Close(); err != nil {
			errs = append(errs, fmt.Errorf("WireGuard interface close: %w", err))
		}
		t.wgInterface = nil
	}

	// Also try legacy interface cleanup
	ifaceMgr := NewInterfaceManager(t.config.InterfaceName)
	if err := ifaceMgr.Teardown(); err != nil {
		// Only log warning, don't append as error (interface may already be closed)
		log.WithError(err).Debug("Legacy interface teardown (may be expected)")
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	log.Info("Machine Tunnel cleanup complete")
	return nil
}
