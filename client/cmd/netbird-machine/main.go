// Machine Tunnel Fork - Windows Pre-Login VPN Service
// This is the entry point for the NetBird Machine Tunnel service binary.
// The service runs as SYSTEM before user login to provide domain connectivity.

package main

import (
	"fmt"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/util"
)

const (
	// ServiceName is the Windows service name
	ServiceName = "NetBirdMachine"
	// ServiceDisplayName is the display name in services.msc
	ServiceDisplayName = "NetBird Machine Tunnel"
	// ServiceDescription is the service description
	ServiceDescription = "NetBird VPN for machine authentication (pre-login)"
)

var (
	// Version is set at build time
	Version = "dev"

	// Flags
	configPath string
	logLevel   string
	logFile    string
)

var rootCmd = &cobra.Command{
	Use:   "netbird-machine",
	Short: "NetBird Machine Tunnel - Pre-Login VPN Service",
	Long: `NetBird Machine Tunnel provides VPN connectivity before user login.
It runs as a Windows service under the SYSTEM account and authenticates
using machine certificates from the Windows Certificate Store.

This enables:
- Domain authentication before Windows login (Kerberos TGT)
- Group Policy processing for remote machines
- Network drive access at login`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		log.Infof("NetBird Machine Tunnel %s", Version)
		log.Infof("  OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
		defaultConfigPath(),
		"Configuration file path")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l",
		"info",
		"Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file",
		defaultLogPath(),
		"Log file path")

	rootCmd.AddCommand(versionCmd)

	// Platform-specific commands (install, uninstall, run) added via init() in platform files
}

func main() {
	if err := util.InitLog(logLevel, logFile); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logging: %v\n", err)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// defaultConfigPath returns the default configuration path
func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\NetBird\machine-config.yaml`
	}
	return "/etc/netbird/machine-config.yaml"
}

// defaultLogPath returns the default log file path
func defaultLogPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\NetBird\machine-tunnel.log`
	}
	return "/var/log/netbird/machine-tunnel.log"
}
