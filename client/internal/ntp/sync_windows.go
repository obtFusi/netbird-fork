// Machine Tunnel Fork - NTP Windows Implementation
// This file provides Windows-specific NTP operations using w32tm.

//go:build windows

package ntp

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// getTimeOffsetImpl gets the time offset from an NTP server using w32tm
func getTimeOffsetImpl(ctx context.Context, server string, timeout time.Duration) (time.Duration, error) {
	// Use w32tm /stripchart to get time offset
	// Output format: "time,offset[,msg]"
	// Example: "12:34:56, -0.1234567s"

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctxWithTimeout, "w32tm", "/stripchart",
		"/computer:"+server,
		"/samples:1",
		"/dataonly")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("w32tm stripchart failed: %w (output: %s)", err, string(output))
	}

	// Parse the offset from output
	// Looking for pattern like "+0.1234567s" or "-0.1234567s"
	re := regexp.MustCompile(`([+-]\d+\.\d+)s`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		// Try alternative format (no decimal)
		re = regexp.MustCompile(`([+-]\d+)s`)
		matches = re.FindStringSubmatch(string(output))
		if len(matches) < 2 {
			return 0, fmt.Errorf("failed to parse time offset from output: %s", string(output))
		}
	}

	offsetSeconds, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse offset value %q: %w", matches[1], err)
	}

	offset := time.Duration(offsetSeconds * float64(time.Second))

	log.WithFields(log.Fields{
		"server":         server,
		"offset_seconds": offsetSeconds,
	}).Debug("Time offset retrieved from NTP server")

	return offset, nil
}

// forceSyncImpl forces time synchronization using w32tm
func forceSyncImpl(ctx context.Context, timeout time.Duration) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctxWithTimeout, "w32tm", "/resync", "/force")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("w32tm resync failed: %w (output: %s)", err, string(output))
	}

	// Check for success message
	outputStr := string(output)
	if strings.Contains(outputStr, "The command completed successfully") ||
		strings.Contains(outputStr, "successfully") {
		log.Debug("Time sync completed via w32tm /resync")
		return nil
	}

	// If no success message, check for errors
	if strings.Contains(outputStr, "error") || strings.Contains(outputStr, "failed") {
		return fmt.Errorf("w32tm resync reported error: %s", outputStr)
	}

	// Assume success if no clear error
	log.WithField("output", outputStr).Debug("Time sync completed")
	return nil
}

// switchToManualPeerImpl switches NTP to use a specific peer (DC IP)
func switchToManualPeerImpl(dcIP string) error {
	// Configure w32tm to use the DC as manual peer
	// w32tm /config /syncfromflags:manual /manualpeerlist:DC-IP /update

	cmd := exec.Command("w32tm", "/config",
		"/syncfromflags:manual",
		"/manualpeerlist:"+dcIP,
		"/update")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("w32tm config manualpeerlist failed: %w (output: %s)", err, string(output))
	}

	// Trigger resync to apply the change
	cmd = exec.Command("w32tm", "/resync")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("w32tm resync after config failed: %w (output: %s)", err, string(output))
	}

	log.WithField("dc_ip", dcIP).Debug("NTP switched to DC as manual peer")
	return nil
}

// switchToDomainHierarchyImpl switches NTP to use domain hierarchy
func switchToDomainHierarchyImpl() error {
	// Configure w32tm to use domain hierarchy
	// w32tm /config /syncfromflags:domhier /update

	cmd := exec.Command("w32tm", "/config",
		"/syncfromflags:domhier",
		"/update")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("w32tm config domhier failed: %w (output: %s)", err, string(output))
	}

	// Trigger resync to apply the change
	cmd = exec.Command("w32tm", "/resync")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("w32tm resync after config failed: %w (output: %s)", err, string(output))
	}

	log.Debug("NTP switched to domain hierarchy")
	return nil
}

// GetW32TimeStatus gets the current W32Time service status
func GetW32TimeStatus() (string, error) {
	cmd := exec.Command("w32tm", "/query", "/status")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("w32tm query status failed: %w", err)
	}

	return string(output), nil
}

// GetW32TimeSource gets the current NTP source
func GetW32TimeSource() (string, error) {
	cmd := exec.Command("w32tm", "/query", "/source")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("w32tm query source failed: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// IsW32TimeServiceRunning checks if the W32Time service is running
func IsW32TimeServiceRunning() bool {
	cmd := exec.Command("sc", "query", "w32time")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "RUNNING")
}
