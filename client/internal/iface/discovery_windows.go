// Machine Tunnel Fork - Interface Discovery (Windows)
// This file provides Windows-specific interface discovery using PowerShell.

//go:build windows

package iface

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// discoverByGUID finds an interface by its GUID using PowerShell
func discoverByGUID(guid string) (*InterfaceInfo, error) {
	// Use Get-NetAdapter with InterfaceGuid filter
	script := fmt.Sprintf(`
$adapter = Get-NetAdapter | Where-Object { $_.InterfaceGuid -eq "%s" } | Select-Object -First 1
if ($adapter) {
    $adapter | Format-List Name,InterfaceGuid,ifIndex,InterfaceDescription,Status,MtuSize
} else {
    exit 1
}
`, guid)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("GUID lookup failed: %w", err)
	}

	return parseNetAdapterOutput(string(output))
}

// discoverByDescription finds an interface by description pattern (e.g., "WireGuard*")
func discoverByDescription(pattern string) (*InterfaceInfo, error) {
	// Use Get-NetAdapter with InterfaceDescription filter
	script := fmt.Sprintf(`
$adapter = Get-NetAdapter -InterfaceDescription "%s" -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "Up" } |
    Select-Object -First 1
if (-not $adapter) {
    # Fallback: Try without status filter
    $adapter = Get-NetAdapter -InterfaceDescription "%s" -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if ($adapter) {
    $adapter | Format-List Name,InterfaceGuid,ifIndex,InterfaceDescription,Status,MtuSize
} else {
    exit 1
}
`, pattern, pattern)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("description lookup failed: %w", err)
	}

	return parseNetAdapterOutput(string(output))
}

// discoverByNamePrefix finds an interface by name prefix (e.g., "wg-nb-")
func discoverByNamePrefix(prefix string) (*InterfaceInfo, error) {
	// Use Get-NetAdapter with Name filter
	script := fmt.Sprintf(`
$adapter = Get-NetAdapter -Name "%s*" -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "Up" } |
    Select-Object -First 1
if (-not $adapter) {
    # Fallback: Try without status filter
    $adapter = Get-NetAdapter -Name "%s*" -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if ($adapter) {
    $adapter | Format-List Name,InterfaceGuid,ifIndex,InterfaceDescription,Status,MtuSize
} else {
    exit 1
}
`, prefix, prefix)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("name prefix lookup failed: %w", err)
	}

	return parseNetAdapterOutput(string(output))
}

// parseNetAdapterOutput parses the Format-List output from PowerShell
func parseNetAdapterOutput(output string) (*InterfaceInfo, error) {
	info := &InterfaceInfo{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			info.Name = value
		case "InterfaceGuid":
			info.GUID = value
		case "ifIndex":
			if idx, err := strconv.Atoi(value); err == nil {
				info.Index = idx
			}
		case "InterfaceDescription":
			info.Description = value
		case "Status":
			info.Status = value
		case "MtuSize":
			if mtu, err := strconv.Atoi(value); err == nil {
				info.MTU = mtu
			}
		}
	}

	if info.Name == "" {
		return nil, fmt.Errorf("failed to parse interface name from output")
	}

	return info, nil
}

// GetInterfaceGUID retrieves the GUID for a named interface
func GetInterfaceGUID(name string) (string, error) {
	script := fmt.Sprintf(`(Get-NetAdapter -Name "%s" -ErrorAction Stop).InterfaceGuid`, name)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get GUID failed: %w (output: %s)", err, string(output))
	}

	guid := strings.TrimSpace(string(output))
	if guid == "" {
		return "", fmt.Errorf("empty GUID returned")
	}

	return guid, nil
}

// GetInterfaceByGUID retrieves interface info by GUID
func GetInterfaceByGUID(guid string) (*InterfaceInfo, error) {
	return discoverByGUID(guid)
}

// IsInterfaceUp checks if the named interface is up
func IsInterfaceUp(name string) (bool, error) {
	script := fmt.Sprintf(`(Get-NetAdapter -Name "%s" -ErrorAction Stop).Status`, name)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("status check failed: %w", err)
	}

	status := strings.TrimSpace(string(output))
	return status == "Up", nil
}

// ListWireGuardAdapters lists all WireGuard adapters on the system
func ListWireGuardAdapters() ([]*InterfaceInfo, error) {
	script := `
Get-NetAdapter -InterfaceDescription "WireGuard*" -ErrorAction SilentlyContinue |
    ForEach-Object {
        "---ADAPTER---"
        $_ | Format-List Name,InterfaceGuid,ifIndex,InterfaceDescription,Status,MtuSize
    }
`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list adapters failed: %w", err)
	}

	var adapters []*InterfaceInfo
	sections := strings.Split(string(output), "---ADAPTER---")

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}

		info, err := parseNetAdapterOutput(section)
		if err != nil {
			continue
		}

		adapters = append(adapters, info)
	}

	return adapters, nil
}
