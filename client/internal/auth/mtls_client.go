// Machine Tunnel Fork - mTLS gRPC Client
// This file provides the mTLS gRPC client for machine tunnel authentication.
// It uses machine certificates from Windows Certificate Store for mTLS.

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/tunnel"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
)

// MTLSClient provides mTLS authenticated gRPC connection for Machine Tunnel
type MTLSClient struct {
	mu sync.RWMutex

	// config holds the certificate discovery configuration
	config *CertDiscoveryConfig

	// loadedCert is the currently loaded certificate
	loadedCert *LoadedCertificate

	// conn is the gRPC connection
	conn *grpc.ClientConn

	// client is the management service client
	client mgmtProto.ManagementServiceClient

	// serverAddr is the management server address
	serverAddr string

	// closed indicates if the client has been closed
	closed bool
}

// MTLSClientConfig configures the mTLS client
type MTLSClientConfig struct {
	// ServerAddr is the management server address (host:port)
	ServerAddr string

	// MachineCert is the machine certificate configuration
	MachineCert tunnel.MachineCertConfig

	// FallbackCertPath is the path to a fallback PEM certificate
	FallbackCertPath string

	// FallbackKeyPath is the path to a fallback PEM private key
	FallbackKeyPath string

	// Hostname is the expected hostname for SAN matching
	Hostname string

	// TLSEnabled indicates whether to use TLS (should always be true for mTLS)
	TLSEnabled bool
}

// NewMTLSClient creates a new mTLS client for machine tunnel
func NewMTLSClient(config *MTLSClientConfig) (*MTLSClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if config.ServerAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}

	if !config.MachineCert.Enabled {
		return nil, fmt.Errorf("machine certificate authentication must be enabled")
	}

	discoveryConfig := &CertDiscoveryConfig{
		MachineCert:      config.MachineCert,
		FallbackCertPath: config.FallbackCertPath,
		FallbackKeyPath:  config.FallbackKeyPath,
		Hostname:         config.Hostname,
	}

	return &MTLSClient{
		config:     discoveryConfig,
		serverAddr: config.ServerAddr,
	}, nil
}

// Connect establishes the mTLS connection to the management server
func (c *MTLSClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client is closed")
	}

	if c.conn != nil {
		return nil // Already connected
	}

	// Discover the machine certificate
	loadedCert, err := DiscoverCertificate(c.config)
	if err != nil {
		return fmt.Errorf("discover certificate: %w", err)
	}
	c.loadedCert = loadedCert

	log.WithFields(log.Fields{
		"thumbprint": loadedCert.Thumbprint,
		"subject":    loadedCert.Certificate.Subject.CommonName,
		"source":     loadedCert.Source,
		"identity":   loadedCert.Identity,
	}).Info("Loaded machine certificate for mTLS")

	// Create TLS config with client certificate
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		return fmt.Errorf("create TLS config: %w", err)
	}

	// Create gRPC connection with mTLS
	conn, err := c.dialWithMTLS(ctx, tlsConfig)
	if err != nil {
		return fmt.Errorf("dial with mTLS: %w", err)
	}

	c.conn = conn
	c.client = mgmtProto.NewManagementServiceClient(conn)

	log.WithField("server", c.serverAddr).Info("Connected to management server with mTLS")
	return nil
}

// createTLSConfig creates a TLS configuration with the machine certificate
func (c *MTLSClient) createTLSConfig() (*tls.Config, error) {
	if c.loadedCert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	// Convert to tls.Certificate
	tlsCert := c.loadedCert.ToTLSCertificate()

	// Get root CA pool
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		log.Debug("System cert pool not available, using embedded roots")
		rootCAs = embeddedroots.Get()
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
		// Server name verification will use the address host part
	}, nil
}

// dialWithMTLS creates a gRPC connection with mTLS authentication
func (c *MTLSClient) dialWithMTLS(ctx context.Context, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	// Create connection context with timeout
	connCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create transport credentials from TLS config
	transportCreds := credentials.NewTLS(tlsConfig)

	// Dial options
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	}

	conn, err := grpc.DialContext(connCtx, c.serverAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %w", err)
	}

	return conn, nil
}

// RegisterMachinePeer registers this machine peer with the management server
func (c *MTLSClient) RegisterMachinePeer(ctx context.Context, wireGuardPubKey []byte) (*mgmtProto.MachineRegisterResponse, error) {
	c.mu.RLock()
	client := c.client
	loadedCert := c.loadedCert
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected")
	}

	if loadedCert == nil || loadedCert.Identity == nil {
		return nil, fmt.Errorf("no machine identity available")
	}

	req := &mgmtProto.MachineRegisterRequest{
		WgPubKey: wireGuardPubKey,
		Meta: &mgmtProto.PeerSystemMeta{
			Hostname:       loadedCert.Identity.Hostname,
			GoOS:           "windows",
			NetbirdVersion: "machine-tunnel/1.0",
			Platform:       "windows",
			OS:             "windows",
		},
	}

	resp, err := client.RegisterMachinePeer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register machine peer: %w", err)
	}

	log.WithField("assigned_ip", resp.GetPeerConfig().GetAddress()).Info("Machine peer registered")
	return resp, nil
}

// SyncMachinePeer starts the synchronization stream for machine peer updates
func (c *MTLSClient) SyncMachinePeer(ctx context.Context) (mgmtProto.ManagementService_SyncMachinePeerClient, error) {
	c.mu.RLock()
	client := c.client
	loadedCert := c.loadedCert
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected")
	}

	if loadedCert == nil || loadedCert.Identity == nil {
		return nil, fmt.Errorf("no machine identity available")
	}

	req := &mgmtProto.MachineSyncRequest{
		Meta: &mgmtProto.PeerSystemMeta{
			Hostname:       loadedCert.Identity.Hostname,
			GoOS:           "windows",
			NetbirdVersion: "machine-tunnel/1.0",
			Platform:       "windows",
			OS:             "windows",
		},
	}

	stream, err := client.SyncMachinePeer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sync machine peer: %w", err)
	}

	return stream, nil
}

// GetMachineRoutes retrieves the routes for this machine peer
func (c *MTLSClient) GetMachineRoutes(ctx context.Context) (*mgmtProto.MachineRoutesResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected")
	}

	resp, err := client.GetMachineRoutes(ctx, &mgmtProto.MachineRoutesRequest{})
	if err != nil {
		return nil, fmt.Errorf("get machine routes: %w", err)
	}

	return resp, nil
}

// ReportMachineStatus reports the machine tunnel status to the server
func (c *MTLSClient) ReportMachineStatus(ctx context.Context, status *MachineStatus) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("not connected")
	}

	req := &mgmtProto.MachineStatusRequest{
		TunnelUp:            status.TunnelUp,
		ConnectedRouterPeer: status.ConnectedRouterPeer,
		DcReachable:         status.DCReachable,
		UptimeSeconds:       status.UptimeSeconds,
	}

	if status.LastHandshake != nil {
		req.LastHandshake = timestamppb.New(*status.LastHandshake)
	}

	if len(status.Errors) > 0 {
		req.Errors = status.Errors
	}

	_, err := client.ReportMachineStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("report machine status: %w", err)
	}

	return nil
}

// MachineStatus represents the current status of the machine tunnel
type MachineStatus struct {
	TunnelUp            bool
	ConnectedRouterPeer string
	LastHandshake       *time.Time
	DCReachable         bool
	Errors              []string
	UptimeSeconds       int64
}

// GetIdentity returns the machine identity from the loaded certificate
func (c *MTLSClient) GetIdentity() *tunnel.MachineIdentity {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.loadedCert == nil {
		return nil
	}
	return c.loadedCert.Identity
}

// GetCertificate returns the loaded certificate
func (c *MTLSClient) GetCertificate() *LoadedCertificate {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.loadedCert
}

// IsConnected returns true if the client is connected
func (c *MTLSClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.conn != nil && !c.closed
}

// Reconnect forces a reconnection to the management server
func (c *MTLSClient) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.client = nil
	}
	c.mu.Unlock()

	return c.Connect(ctx)
}

// Close closes the mTLS client connection
func (c *MTLSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.WithError(err).Warn("Error closing gRPC connection")
		}
		c.conn = nil
		c.client = nil
	}

	// Close the certificate signer if it has a Close method
	if c.loadedCert != nil && c.loadedCert.Source == CertSourceWindowsStore {
		if closer, ok := c.loadedCert.PrivateKey.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				log.WithError(err).Warn("Error closing certificate signer")
			}
		}
	}

	return nil
}

// IsUnauthenticated checks if the error indicates unauthenticated status
func IsUnauthenticated(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.Unauthenticated
}

// IsPermissionDenied checks if the error indicates permission denied
func IsPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.PermissionDenied
}

// IsCertificateExpired checks if the error indicates an expired certificate
func IsCertificateExpired(err error) bool {
	if err == nil {
		return false
	}
	// Check for TLS certificate errors
	errStr := err.Error()
	return containsAny(errStr, []string{
		"certificate has expired",
		"x509: certificate has expired",
		"certificate is not yet valid",
	})
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
