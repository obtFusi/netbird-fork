// Machine Tunnel Fork - Windows Service Handler
// This file implements the Windows service control manager integration
// using native Windows APIs for optimal control.

//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/yaml.v3"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

// serviceHandler implements svc.Handler for Windows Service Control Manager
type serviceHandler struct {
	// tunnel is the machine tunnel instance
	tunnel *tunnel.MachineTunnel

	// ctx is the service context
	ctx context.Context

	// cancel cancels the service context
	cancel context.CancelFunc

	// mu protects tunnel access
	mu sync.Mutex

	// stopped indicates if the service has been stopped
	stopped bool
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the service (called by Windows SCM)",
	Long: `Run the NetBird Machine Tunnel service.
This command is typically called by the Windows Service Control Manager.
For debugging, use --debug to run interactively.`,
	RunE: runService,
}

var debugMode bool

func init() {
	runCmd.Flags().BoolVar(&debugMode, "debug", false, "Run in debug mode (interactive)")
}

func runService(cmd *cobra.Command, args []string) error {
	// Check if we're running interactively or as a service
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("check interactive session: %w", err)
	}

	if isInteractive || debugMode {
		// Running interactively (for debugging)
		return runInteractive()
	}

	// Running as Windows service
	return runAsService()
}

// runAsService runs under the Windows Service Control Manager
func runAsService() error {
	elog, err := eventlog.Open(ServiceName)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", ServiceName))

	handler := &serviceHandler{}
	err = svc.Run(ServiceName, handler)
	if err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
		return fmt.Errorf("service run: %w", err)
	}

	elog.Info(1, fmt.Sprintf("%s service stopped", ServiceName))
	return nil
}

// runInteractive runs in interactive/debug mode
func runInteractive() error {
	log.Info("Running in interactive mode (Ctrl+C to stop)")

	handler := &serviceHandler{}
	err := debug.Run(ServiceName, handler)
	if err != nil {
		return fmt.Errorf("debug run: %w", err)
	}

	return nil
}

// Execute implements svc.Handler
// This is the main service control loop called by Windows SCM.
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// v3.2: Only accept Stop and Shutdown (no SessionChange in MVP)
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Report that we're starting
	changes <- svc.Status{State: svc.StartPending}

	// Create service context
	h.ctx, h.cancel = context.WithCancel(context.Background())

	// Start the machine tunnel in a goroutine
	// IMPORTANT: Start must return quickly (<30s) or SCM will kill us
	startErr := make(chan error, 1)
	go func() {
		startErr <- h.startMachineTunnel()
	}()

	// Wait for tunnel start with timeout
	select {
	case err := <-startErr:
		if err != nil {
			log.Errorf("Failed to start machine tunnel: %v", err)
			changes <- svc.Status{State: svc.StopPending}
			return false, 1
		}
	case <-time.After(25 * time.Second):
		// Don't fail - tunnel may still be starting, continue to Running
		log.Warn("Machine tunnel start taking longer than expected, continuing...")
	}

	// Report that we're running
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Info("NetBird Machine Tunnel service is running")

	// Service control loop
	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			log.Info("Received stop/shutdown request")
			changes <- svc.Status{State: svc.StopPending}
			h.stopMachineTunnel()
			return false, 0

		case svc.Interrogate:
			// Report current status
			changes <- c.CurrentStatus

		default:
			log.Warnf("Unexpected service control request: %d", c.Cmd)
		}
	}

	return false, 0
}

// startMachineTunnel initializes and starts the Machine Tunnel
func (h *serviceHandler) startMachineTunnel() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.stopped {
		return fmt.Errorf("service is stopping")
	}

	log.Info("Starting Machine Tunnel...")

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Create machine tunnel
	h.tunnel, err = tunnel.NewMachineTunnel(config)
	if err != nil {
		return fmt.Errorf("create machine tunnel: %w", err)
	}

	// Set state change callback for logging
	h.tunnel.SetStateChangeCallback(func(state tunnel.MachineState, err error) {
		if err != nil {
			log.Errorf("Machine tunnel state: %s (error: %v)", state, err)
		} else {
			log.Infof("Machine tunnel state: %s", state)
		}
	})

	// Start the tunnel
	if err := h.tunnel.Start(h.ctx); err != nil {
		return fmt.Errorf("start tunnel: %w", err)
	}

	log.Info("Machine Tunnel started successfully")
	return nil
}

// stopMachineTunnel stops the Machine Tunnel gracefully
func (h *serviceHandler) stopMachineTunnel() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stopped = true

	log.Info("Stopping Machine Tunnel...")

	// Cancel context first
	if h.cancel != nil {
		h.cancel()
	}

	// Stop tunnel with timeout
	if h.tunnel != nil {
		stopDone := make(chan struct{})
		go func() {
			if err := h.tunnel.Stop(); err != nil {
				log.Errorf("Error stopping tunnel: %v", err)
			}
			close(stopDone)
		}()

		select {
		case <-stopDone:
			log.Info("Machine Tunnel stopped")
		case <-time.After(10 * time.Second):
			log.Warn("Machine Tunnel stop timed out")
		}

		// Cleanup resources (NRPT, firewall rules)
		if err := h.tunnel.Cleanup(); err != nil {
			log.Errorf("Error cleaning up tunnel resources: %v", err)
		}
	}
}

// configYAML represents the YAML configuration file structure
type configYAML struct {
	// Management server configuration
	ManagementURL string `yaml:"management_url"`

	// Authentication
	SetupKey           string `yaml:"setup_key,omitempty"`
	MachineCertEnabled bool   `yaml:"machine_cert_enabled"`
	MachineCertThumbprint string `yaml:"machine_cert_thumbprint,omitempty"`

	// mTLS port (default: 33074)
	MTLSPort int `yaml:"mtls_port,omitempty"`

	// Machine certificate discovery settings
	MachineCert struct {
		TemplateOID  string `yaml:"template_oid,omitempty"`
		TemplateName string `yaml:"template_name,omitempty"`
		RequiredEKU  string `yaml:"required_eku,omitempty"`
		SANMustMatch bool   `yaml:"san_must_match,omitempty"`
	} `yaml:"machine_cert,omitempty"`

	// Interface configuration
	InterfaceName string `yaml:"interface_name,omitempty"`

	// Reconnection settings
	ReconnectInterval    string `yaml:"reconnect_interval,omitempty"`
	MaxReconnectInterval string `yaml:"max_reconnect_interval,omitempty"`

	// Health check settings
	HealthCheckInterval string `yaml:"health_check_interval,omitempty"`

	// DNS servers for NRPT rules (DC IPs)
	DNSServers []string `yaml:"dns_servers,omitempty"`

	// DNS namespaces for NRPT rules (AD domains)
	DNSNamespaces []string `yaml:"dns_namespaces,omitempty"`

	// Allowed DC IPs for firewall rules
	AllowedDCIPs []string `yaml:"allowed_dc_ips,omitempty"`

	// DC network CIDRs for routing
	DCRoutes []string `yaml:"dc_routes,omitempty"`
}

// loadConfig loads the machine tunnel configuration from YAML file
func loadConfig() (*tunnel.MachineTunnelConfig, error) {
	// Start with defaults
	config := tunnel.DefaultConfig()
	if config == nil {
		return nil, fmt.Errorf("failed to get default config")
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Parse YAML
	var yamlConfig configYAML
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// Validate required fields
	if yamlConfig.ManagementURL == "" {
		return nil, fmt.Errorf("management_url is required in config file")
	}

	// Map YAML to config struct
	config.ManagementURL = yamlConfig.ManagementURL
	config.SetupKey = yamlConfig.SetupKey
	config.MachineCertEnabled = yamlConfig.MachineCertEnabled
	config.MachineCertThumbprint = yamlConfig.MachineCertThumbprint

	if yamlConfig.MTLSPort > 0 {
		config.MTLSPort = yamlConfig.MTLSPort
	}

	if yamlConfig.InterfaceName != "" {
		config.InterfaceName = yamlConfig.InterfaceName
	}

	// Parse duration strings
	if yamlConfig.ReconnectInterval != "" {
		if d, err := time.ParseDuration(yamlConfig.ReconnectInterval); err == nil {
			config.ReconnectInterval = d
		} else {
			log.Warnf("Invalid reconnect_interval '%s', using default", yamlConfig.ReconnectInterval)
		}
	}

	if yamlConfig.MaxReconnectInterval != "" {
		if d, err := time.ParseDuration(yamlConfig.MaxReconnectInterval); err == nil {
			config.MaxReconnectInterval = d
		} else {
			log.Warnf("Invalid max_reconnect_interval '%s', using default", yamlConfig.MaxReconnectInterval)
		}
	}

	if yamlConfig.HealthCheckInterval != "" {
		if d, err := time.ParseDuration(yamlConfig.HealthCheckInterval); err == nil {
			config.HealthCheckInterval = d
		} else {
			log.Warnf("Invalid health_check_interval '%s', using default", yamlConfig.HealthCheckInterval)
		}
	}

	// Machine cert config
	if yamlConfig.MachineCert.TemplateOID != "" {
		config.MachineCert.TemplateOID = yamlConfig.MachineCert.TemplateOID
	}
	if yamlConfig.MachineCert.TemplateName != "" {
		config.MachineCert.TemplateName = yamlConfig.MachineCert.TemplateName
	}
	if yamlConfig.MachineCert.RequiredEKU != "" {
		config.MachineCert.RequiredEKU = yamlConfig.MachineCert.RequiredEKU
	}
	// SANMustMatch defaults to true in DefaultConfig()
	if !yamlConfig.MachineCert.SANMustMatch {
		config.MachineCert.SANMustMatch = yamlConfig.MachineCert.SANMustMatch
	}

	// DNS and network configuration
	config.DNSServers = yamlConfig.DNSServers
	config.DNSNamespaces = yamlConfig.DNSNamespaces
	config.AllowedDCIPs = yamlConfig.AllowedDCIPs
	config.DCRoutes = yamlConfig.DCRoutes

	log.WithFields(log.Fields{
		"config_path":        configPath,
		"management_url":     config.ManagementURL,
		"machine_cert_enabled": config.MachineCertEnabled,
		"interface_name":     config.InterfaceName,
	}).Info("Configuration loaded")

	return config, nil
}
