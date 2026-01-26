// Machine Tunnel Fork - Stub for non-Windows platforms
// The Machine Tunnel service is Windows-only.

//go:build !windows

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

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
	Short: "Run the service (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the service (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the service (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the service (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the service (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show service status (Windows only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("NetBird Machine Tunnel service is only supported on Windows")
	},
}
