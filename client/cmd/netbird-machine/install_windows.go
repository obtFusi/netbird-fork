// Machine Tunnel Fork - Windows Service Installation
// This file provides install/uninstall commands for the Windows service.

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the Windows service",
	Long: `Install the NetBird Machine Tunnel as a Windows service.
The service will be configured to start automatically and run as LocalSystem.

Service Dependencies:
  - Dnscache: DNS resolution
  - NlaSvc: Network Location Awareness
  - W32Time: Time synchronization
  - MpsSvc: Windows Firewall
  - BFE: Base Filtering Engine`,
	RunE: installService,
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the Windows service",
	RunE:  uninstallService,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Windows service",
	RunE:  startService,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Windows service",
	RunE:  stopService,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the Windows service status",
	RunE:  serviceStatus,
}

func installService(cmd *cobra.Command, args []string) error {
	// Get the path to the current executable
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	log.Infof("Installing service from: %s", exePath)

	// Open service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	// Service configuration
	// v3.2: Dependencies include MpsSvc and BFE for firewall/NRPT support
	config := mgr.Config{
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem", // Run as SYSTEM
		Dependencies: []string{
			"Dnscache", // DNS Client
			"NlaSvc",   // Network Location Awareness
			"W32Time",  // Windows Time
			"MpsSvc",   // Windows Firewall
			"BFE",      // Base Filtering Engine
		},
	}

	// Build service arguments
	serviceArgs := []string{
		"run",
		"--config", configPath,
		"--log-level", logLevel,
		"--log-file", logFile,
	}

	// Create the service
	s, err = m.CreateService(ServiceName, exePath, config, serviceArgs...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Configure recovery actions (restart on failure)
	// v3.2 Security: This is allowed - it's service-level recovery, not privilege escalation
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},  // First failure: restart after 5s
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, // Second failure: restart after 10s
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, // Subsequent failures: restart after 30s
	}
	err = s.SetRecoveryActions(recoveryActions, 86400) // Reset failure count after 24 hours
	if err != nil {
		log.Warnf("Failed to set recovery actions: %v", err)
	}

	// Setup event log source
	err = eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		log.Warnf("Failed to install event log source: %v", err)
	}

	log.Infof("Service %s installed successfully", ServiceName)
	fmt.Printf("Service '%s' installed successfully.\n", ServiceName)
	fmt.Println("Use 'netbird-machine start' to start the service.")
	return nil
}

func uninstallService(cmd *cobra.Command, args []string) error {
	// Open service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop service if running
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		log.Info("Stopping service before uninstall...")
		_, err = s.Control(svc.Stop)
		if err != nil {
			log.Warnf("Failed to stop service: %v", err)
		}

		// Wait for service to stop
		for i := 0; i < 30; i++ {
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(time.Second)
		}
	}

	// Delete the service
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Remove event log source
	err = eventlog.Remove(ServiceName)
	if err != nil {
		log.Warnf("Failed to remove event log source: %v", err)
	}

	log.Infof("Service %s uninstalled successfully", ServiceName)
	fmt.Printf("Service '%s' uninstalled successfully.\n", ServiceName)
	return nil
}

func startService(cmd *cobra.Command, args []string) error {
	// Open service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	log.Infof("Service %s started", ServiceName)
	fmt.Printf("Service '%s' started.\n", ServiceName)
	return nil
}

func stopService(cmd *cobra.Command, args []string) error {
	// Open service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop the service
	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service: %w", err)
	}

	// Wait for service to stop
	for i := 0; i < 30; i++ {
		if status.State == svc.Stopped {
			break
		}
		time.Sleep(time.Second)
		status, err = s.Query()
		if err != nil {
			break
		}
	}

	log.Infof("Service %s stopped", ServiceName)
	fmt.Printf("Service '%s' stopped.\n", ServiceName)
	return nil
}

func serviceStatus(cmd *cobra.Command, args []string) error {
	// Open service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(ServiceName)
	if err != nil {
		fmt.Printf("Service '%s' is not installed.\n", ServiceName)
		return nil
	}
	defer s.Close()

	// Query status
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service status: %w", err)
	}

	// Format status
	var stateStr string
	switch status.State {
	case svc.Stopped:
		stateStr = "Stopped"
	case svc.StartPending:
		stateStr = "Start Pending"
	case svc.StopPending:
		stateStr = "Stop Pending"
	case svc.Running:
		stateStr = "Running"
	case svc.ContinuePending:
		stateStr = "Continue Pending"
	case svc.PausePending:
		stateStr = "Pause Pending"
	case svc.Paused:
		stateStr = "Paused"
	default:
		stateStr = fmt.Sprintf("Unknown (%d)", status.State)
	}

	fmt.Printf("Service: %s\n", ServiceName)
	fmt.Printf("Status:  %s\n", stateStr)
	fmt.Printf("PID:     %d\n", status.ProcessId)
	return nil
}
