// Machine Tunnel Fork - PeerEngine for Signal/Relay Integration
// This file orchestrates peer connections using existing NetBird components.
// It follows the Direct Reuse pattern (ADR-001) to minimize code duplication.
//
// References:
// - Engine pattern: client/internal/engine.go:1414-1475
// - ServiceDependencies: client/internal/peer/conn.go:31-39
// - Signal client: shared/signal/client/grpc.go
// - Issue #110: PeerEngine with Direct Reuse

//go:build windows

package tunnel

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/route"
	relayAuth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
	semaphoregroup "github.com/netbirdio/netbird/util/semaphore-group"
)

const (
	// PeerConnectionTimeoutMin is the minimum connection timeout (engine.go:68)
	PeerConnectionTimeoutMin = 30000 // ms = 30s
	// PeerConnectionTimeoutMax is the maximum connection timeout (engine.go:67)
	PeerConnectionTimeoutMax = 45000 // ms = 45s
	// DefaultMaxConcurrentPeers is the default max concurrent peer connections
	DefaultMaxConcurrentPeers = 10
)

// PeerEngine manages peer connections using existing NetBird components.
// It reuses peer.ServiceDependencies and peer.Conn directly (ADR-001).
// PeerEngine is ONLY orchestration glue - NO feature duplication!
// All logic comes from the reused NetBird components.
type PeerEngine struct {
	mu sync.RWMutex

	// Reused NetBird components (NO wrappers!)
	// ALL 6 ServiceDependencies fields (except PeerConnDispatcher - unused)
	signalClient   signal.Client
	relayManager   *relayClient.Manager
	statusRecorder *peer.Status
	signaler       *peer.Signaler
	ifaceDiscover  stdnet.ExternalIFaceDiscover
	srWatcher      *guard.SRWatcher

	// STUN/TURN URLs as atomic.Value wrapper (engine.go pattern)
	stunTurn icemaker.StunTurn

	// GLOBAL Semaphore for concurrency limit (NOT per peer!)
	semaphore *semaphoregroup.SemaphoreGroup

	// Peer connections - Key = WG Public Key (msg.Key)
	peerConns map[string]*peer.Conn

	// Mutex for message routing (like Engine: syncMsgMux)
	syncMsgMux sync.Mutex

	// Shutdown coordination
	shutdownWg sync.WaitGroup

	// Configuration
	config PeerEngineConfig
	wgKey  wgtypes.Key
	ctx    context.Context
	cancel context.CancelFunc
}

// PeerEngineConfig configures the peer engine.
type PeerEngineConfig struct {
	// Signal Server Config
	SignalAddr     string
	SignalTLS      bool
	SignalProtocol string // "https" or "http"

	// Relay Config
	RelayURLs      []string
	RelayToken     *RelayToken // Optional HMAC token for relay auth

	// STUN/TURN Config - will be parsed internally
	StunURLs []string
	TurnURLs []TurnConfig

	// ICE Config
	InterfaceBlackList   []string
	DisableIPv6Discovery bool
	NATExternalIPs       []string

	// WireGuard Config
	WgInterface  peer.WGIface
	WgPort       int
	PreSharedKey *wgtypes.Key

	// General Config
	MTU           uint16
	MgmtURL       string
	MaxConcurrent int // Default: 10
}

// RelayToken holds HMAC token for relay authentication
type RelayToken struct {
	Payload   string
	Signature string
}

// TurnConfig holds TURN server configuration with credentials
type TurnConfig struct {
	URL      string
	Username string
	Password string
}

// NewPeerEngine creates a peer engine with reused NetBird components.
func NewPeerEngine(ctx context.Context, wgKey wgtypes.Key, cfg PeerEngineConfig) (*PeerEngine, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrentPeers
	}

	pe := &PeerEngine{
		config:    cfg,
		wgKey:     wgKey,
		peerConns: make(map[string]*peer.Conn),
	}
	pe.ctx, pe.cancel = context.WithCancel(ctx)

	// 0. GLOBAL Semaphore for concurrency limit (NOT per peer!)
	pe.semaphore = semaphoregroup.NewSemaphoreGroup(cfg.MaxConcurrent)

	// 1. Create Signal Client (DIRECT REUSE)
	// Engine Pattern: signal.NewClient() with backoff, then WaitStreamConnected()
	// Reference: shared/signal/client/grpc.go:56-84, engine.go:1474
	signalClient, err := signal.NewClient(pe.ctx, cfg.SignalAddr, wgKey, cfg.SignalTLS)
	if err != nil {
		return nil, fmt.Errorf("create signal client: %w", err)
	}
	pe.signalClient = signalClient

	// 2. Create Relay Manager (DIRECT REUSE)
	// PeerID = WG Public Key as string (connect.go:293)
	peerID := wgKey.PublicKey().String()
	pe.relayManager = relayClient.NewManager(pe.ctx, cfg.RelayURLs, peerID, cfg.MTU)

	// 3. Create Status Recorder (DIRECT REUSE)
	// Reference: engine.go:1393
	pe.statusRecorder = peer.NewRecorder(cfg.MgmtURL)
	pe.statusRecorder.SetRelayMgr(pe.relayManager)

	// 4. Create Signaler (DIRECT REUSE)
	pe.signaler = peer.NewSignaler(pe.signalClient, wgKey)

	// 5. IFaceDiscover - nil for desktop (only used on mobile)
	// Reference: engine.go:1395 - uses mobileDep.IFaceDiscover which is nil for desktop
	// MobileDependency{}.IFaceDiscover is nil
	pe.ifaceDiscover = nil

	// 6. Parse STUN/TURN URLs and store in stunTurn
	if err := pe.parseStunTurnURLs(cfg); err != nil {
		return nil, fmt.Errorf("parse STUN/TURN URLs: %w", err)
	}

	// 7. Create SrWatcher
	// Reference: guard/sr_watcher.go:31
	iceConfig := pe.createICEConfig()
	pe.srWatcher = guard.NewSRWatcher(
		pe.signalClient, // chNotifier interface
		pe.relayManager, // chNotifier interface
		pe.ifaceDiscover,
		iceConfig,
	)

	return pe, nil
}

// Start begins the peer engine.
// Follows the Engine pattern from engine.go:1414-1475.
//
// IMPORTANT: Start-Order Race Condition (ADR-007)
// - Signal Receive-Loop starts BEFORE ConnectPeer() is called
// - Messages for not-yet-connected peers are IGNORED (return nil + log)
// - This is ACCEPTABLE because:
//   1. peer.Conn.Open() initiates ICE handshake (we are initiator)
//   2. Remote peer sends new offers when we initiate
//   3. Error return would only cause unnecessary log spam
//
// Caller MUST call ConnectPeer() IMMEDIATELY after Start()!
func (pe *PeerEngine) Start() error {
	// 1. Update Relay Token (BEFORE Relay Manager starts!)
	// Reference: connect.go:297 - UpdateToken before Serve()
	if pe.config.RelayToken != nil {
		token := &relayAuth.Token{
			Payload:   pe.config.RelayToken.Payload,
			Signature: pe.config.RelayToken.Signature,
		}
		if err := pe.relayManager.UpdateToken(token); err != nil {
			log.WithError(err).Warn("Failed to update relay token")
			// Not fatal - relay can still work without token (if configured)
		}
	}

	// 2. Signal Receive-Loop FIRST (Engine: engine.go:1416-1472)
	// IMPORTANT: Receive() starts the stream, THEN WaitStreamConnected()!
	pe.shutdownWg.Add(1)
	go func() {
		defer pe.shutdownWg.Done()
		err := pe.signalClient.Receive(pe.ctx, pe.handleSignalMessage)
		if err != nil {
			if pe.ctx.Err() == nil {
				log.WithError(err).Warn("Signal receive loop stopped unexpectedly")
				// Engine behavior: on permanent error, cancel client
				pe.cancel()
			}
		}
	}()

	// 3. THEN wait for stream connection (Engine: engine.go:1474)
	// WaitStreamConnected() returns void (no error!)
	pe.signalClient.WaitStreamConnected()

	// 4. Start Relay Manager in background
	go func() {
		if err := pe.relayManager.Serve(); err != nil {
			if pe.ctx.Err() == nil {
				log.WithError(err).Warn("Relay manager stopped unexpectedly")
			}
		}
	}()

	// 5. Start SRWatcher (Engine calls this explicitly)
	pe.srWatcher.Start()

	log.Info("PeerEngine started successfully")
	return nil
}

// handleSignalMessage is called by the Signal Receive-Loop.
// Implements the Engine pattern from engine.go:1419-1464.
//
// ADR-002: convertToOfferAnswer Duplication
// - Engine has convertToOfferAnswer() as private function (engine.go:2179)
// - Decision: Minimal duplication in peerengine.go
// - Reason: Minimal upstream impact, easier fork merge
func (pe *PeerEngine) handleSignalMessage(msg *sProto.Message) error {
	pe.syncMsgMux.Lock()
	defer pe.syncMsgMux.Unlock()

	// Context check inside lock (like Engine: engine.go:1424-1426)
	if pe.ctx.Err() != nil {
		return pe.ctx.Err()
	}

	peerKey := msg.Key

	pe.mu.RLock()
	conn, exists := pe.peerConns[peerKey]
	pe.mu.RUnlock()

	if !exists {
		// ADR-007: return nil instead of error
		// DEVIATION from Engine: Engine returns error (engine.go:1428-1430), but
		// Signal Worker only logs errors and does NOT treat them as fatal.
		// We use return nil INTENTIONALLY because:
		// 1. Avoids unnecessary error logging in Signal worker
		// 2. Message for unknown peer is not our error
		// 3. Reduces log noise during race conditions at Start()
		log.Debugf("ignoring message for unknown peer %s", peerKey[:8])
		return nil
	}

	// Type-Switch pattern from engine.go:1438-1461
	switch msg.GetBody().Type {
	case sProto.Body_OFFER, sProto.Body_ANSWER:
		offerAnswer, err := pe.convertToOfferAnswer(msg)
		if err != nil {
			return err
		}
		if msg.GetBody().Type == sProto.Body_OFFER {
			conn.OnRemoteOffer(*offerAnswer)
		} else {
			conn.OnRemoteAnswer(*offerAnswer)
		}

	case sProto.Body_CANDIDATE:
		candidate, err := ice.UnmarshalCandidate(msg.GetBody().Payload)
		if err != nil {
			log.Errorf("failed on parsing remote candidate %s -> %s", candidate, err)
			return err
		}
		go conn.OnRemoteCandidate(candidate, pe.getClientRoutes())

	case sProto.Body_MODE:
		// Ignored - Machine Tunnel has no mode changes
	case sProto.Body_GO_IDLE:
		// ADR-005: Simplified Message Routing
		// Machine Tunnel has fixed peer list, no lazy-connect
		// GO_IDLE is ignored - Machine Tunnel needs permanent connection
	}

	return nil
}

// convertToOfferAnswer converts Signal message to OfferAnswer.
// DUPLICATED from engine.go:2179-2218 (see ADR-002).
func (pe *PeerEngine) convertToOfferAnswer(msg *sProto.Message) (*peer.OfferAnswer, error) {
	remoteCred, err := signal.UnMarshalCredential(msg)
	if err != nil {
		return nil, err
	}

	var (
		rosenpassPubKey []byte
		rosenpassAddr   string
	)
	if cfg := msg.GetBody().GetRosenpassConfig(); cfg != nil {
		rosenpassPubKey = cfg.GetRosenpassPubKey()
		rosenpassAddr = cfg.GetRosenpassServerAddr()
	}

	// Handle optional SessionID
	// Reference: engine.go:2194-2203
	var sessionID *peer.ICESessionID
	if sessionBytes := msg.GetBody().GetSessionId(); sessionBytes != nil {
		if id, err := peer.ICESessionIDFromBytes(sessionBytes); err != nil {
			log.Warnf("Invalid session ID in message: %v", err)
			sessionID = nil // Set to nil if conversion fails
		} else {
			sessionID = &id
		}
	}

	offerAnswer := peer.OfferAnswer{
		IceCredentials: peer.IceCredentials{
			UFrag: remoteCred.UFrag,
			Pwd:   remoteCred.Pwd,
		},
		WgListenPort:    int(msg.GetBody().GetWgListenPort()),
		Version:         msg.GetBody().GetNetBirdVersion(),
		RosenpassPubKey: rosenpassPubKey,
		RosenpassAddr:   rosenpassAddr,
		RelaySrvAddress: msg.GetBody().GetRelayServerAddress(),
		SessionID:       sessionID,
	}
	return &offerAnswer, nil
}

// getClientRoutes returns routes for candidate processing.
// TODO-1: Implement when RouteManager is integrated, for now return nil.
func (pe *PeerEngine) getClientRoutes() route.HAMap {
	return nil // Machine Tunnel has no client routes initially
}

// ConnectPeer creates and opens a connection to a remote peer.
func (pe *PeerEngine) ConnectPeer(ctx context.Context, remotePeerKey string, allowedIPs []string) (*peer.Conn, error) {
	// Parse allowed IPs
	var allowedIPPrefixes []netip.Prefix
	for _, ip := range allowedIPs {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("parse allowed IP %q: %w", ip, err)
		}
		allowedIPPrefixes = append(allowedIPPrefixes, prefix)
	}

	if len(allowedIPPrefixes) == 0 {
		return nil, fmt.Errorf("no valid allowed IPs for peer %s", remotePeerKey[:8])
	}

	// WgConfig
	wgConfig := peer.WgConfig{
		RemoteKey:    remotePeerKey,
		WgListenPort: pe.config.WgPort,
		WgInterface:  pe.config.WgInterface,
		AllowedIps:   allowedIPPrefixes,
		PreSharedKey: pe.config.PreSharedKey,
	}

	// Randomized timeout (Reference: engine.go:67-73)
	timeout := time.Duration(rand.Intn(PeerConnectionTimeoutMax-PeerConnectionTimeoutMin)+PeerConnectionTimeoutMin) * time.Millisecond

	// ICE Config
	iceConfig := pe.createICEConfig()

	// ConnConfig
	connConfig := peer.ConnConfig{
		Key:          remotePeerKey,
		LocalKey:     pe.wgKey.PublicKey().String(),
		AgentVersion: "", // Set from RemotePeerConfig if available
		Timeout:      timeout,
		WgConfig:     wgConfig,
		LocalWgPort:  pe.config.WgPort,
		ICEConfig:    iceConfig,
	}

	// ALL ServiceDependencies fields (except PeerConnDispatcher - unused in Engine)
	// Reference: engine.go:1392-1399
	deps := peer.ServiceDependencies{
		StatusRecorder: pe.statusRecorder,
		Signaler:       pe.signaler,
		IFaceDiscover:  pe.ifaceDiscover,
		RelayManager:   pe.relayManager,
		SrWatcher:      pe.srWatcher,
		Semaphore:      pe.semaphore, // GLOBAL, not newly created!
		// PeerConnDispatcher: nil, // Engine also doesn't set this!
	}

	conn, err := peer.NewConn(connConfig, deps)
	if err != nil {
		return nil, fmt.Errorf("create peer conn: %w", err)
	}

	if err := conn.Open(ctx); err != nil {
		return nil, fmt.Errorf("open peer conn: %w", err)
	}

	pe.mu.Lock()
	pe.peerConns[remotePeerKey] = conn
	pe.mu.Unlock()

	log.WithField("peer", remotePeerKey[:8]).Info("Peer connection opened")
	return conn, nil
}

// GetPeerStatus returns connection status for all peers.
func (pe *PeerEngine) GetPeerStatus() map[string]bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	status := make(map[string]bool)
	for key, conn := range pe.peerConns {
		status[key] = conn.IsConnected()
	}
	return status
}

// Close stops all peer connections and the engine.
func (pe *PeerEngine) Close() error {
	log.Info("Closing PeerEngine...")
	pe.cancel()

	// Wait for Signal Receive-Loop
	pe.shutdownWg.Wait()

	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Close all peer connections
	for key, conn := range pe.peerConns {
		if conn != nil {
			log.WithField("peer", key[:8]).Debug("Closing peer connection")
			conn.Close(true) // signalToRemote=true to notify remote peer
		}
	}
	pe.peerConns = make(map[string]*peer.Conn)

	// Close SRWatcher (CRITICAL - must be before Signal/Relay!)
	if pe.srWatcher != nil {
		pe.srWatcher.Close()
	}

	if pe.signalClient != nil {
		pe.signalClient.Close()
	}
	// Note: relayManager uses context for cancellation (no Close method)
	// When we called pe.cancel() above, the relay manager's context gets cancelled

	log.Info("PeerEngine closed")
	return nil
}

// parseStunTurnURLs parses STUN/TURN URLs from config.
// Reference: engine.go:1006-1042
func (pe *PeerEngine) parseStunTurnURLs(cfg PeerEngineConfig) error {
	var urls []*stun.URI

	// Parse STUN URLs
	for _, stunURL := range cfg.StunURLs {
		url, err := stun.ParseURI(stunURL)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse STUN URL: %s", stunURL)
			continue
		}
		urls = append(urls, url)
	}

	// Parse TURN URLs with credentials
	for _, turnCfg := range cfg.TurnURLs {
		url, err := stun.ParseURI(turnCfg.URL)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse TURN URL: %s", turnCfg.URL)
			continue
		}
		url.Username = turnCfg.Username
		url.Password = turnCfg.Password
		urls = append(urls, url)
	}

	pe.stunTurn.Store(urls)
	return nil
}

// createICEConfig creates the ICE config.
// Reference: engine_generic.go:10-18
// ADR-006: UDPMux not used (Windows Desktop, no multi-port sharing needed)
func (pe *PeerEngine) createICEConfig() icemaker.Config {
	return icemaker.Config{
		StunTurn:             &pe.stunTurn,
		InterfaceBlackList:   pe.config.InterfaceBlackList,
		DisableIPv6Discovery: pe.config.DisableIPv6Discovery,
		// ADR-006: UDPMux and UDPMuxSrflx are nil
		// - Engine uses these for Mobile UDP Multiplexing
		// - Machine Tunnel is Windows Desktop -> not needed
		UDPMux:         nil,
		UDPMuxSrflx:    nil,
		NATExternalIPs: pe.config.NATExternalIPs,
	}
}
