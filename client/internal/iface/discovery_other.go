// Machine Tunnel Fork - Interface Discovery (Non-Windows Stub)
// This file provides stub implementations for non-Windows platforms.

//go:build !windows

package iface

import (
	"fmt"
	"net"
	"strings"
)

// discoverByGUID is not fully supported on non-Windows platforms
// Falls back to name-based discovery
func discoverByGUID(guid string) (*InterfaceInfo, error) {
	return nil, fmt.Errorf("GUID-based lookup not supported on this platform")
}

// discoverByDescription is not supported on non-Windows platforms
func discoverByDescription(pattern string) (*InterfaceInfo, error) {
	return nil, fmt.Errorf("description-based lookup not supported on this platform")
}

// discoverByNamePrefix finds an interface by name prefix using net package
func discoverByNamePrefix(prefix string) (*InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces failed: %w", err)
	}

	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, prefix) {
			status := "Down"
			if iface.Flags&net.FlagUp != 0 {
				status = "Up"
			}

			return &InterfaceInfo{
				Name:   iface.Name,
				Index:  iface.Index,
				MTU:    iface.MTU,
				Status: status,
			}, nil
		}
	}

	return nil, fmt.Errorf("interface with prefix %q not found", prefix)
}

// GetInterfaceGUID is not supported on non-Windows platforms
func GetInterfaceGUID(name string) (string, error) {
	return "", fmt.Errorf("GUID not supported on this platform")
}

// GetInterfaceByGUID is not supported on non-Windows platforms
func GetInterfaceByGUID(guid string) (*InterfaceInfo, error) {
	return nil, fmt.Errorf("GUID-based lookup not supported on this platform")
}

// IsInterfaceUp checks if the named interface is up using net package
func IsInterfaceUp(name string) (bool, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, fmt.Errorf("interface not found: %w", err)
	}

	return iface.Flags&net.FlagUp != 0, nil
}

// ListWireGuardAdapters lists interfaces with the WireGuard prefix
func ListWireGuardAdapters() ([]*InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces failed: %w", err)
	}

	var adapters []*InterfaceInfo
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "wg") {
			status := "Down"
			if iface.Flags&net.FlagUp != 0 {
				status = "Up"
			}

			adapters = append(adapters, &InterfaceInfo{
				Name:   iface.Name,
				Index:  iface.Index,
				MTU:    iface.MTU,
				Status: status,
			})
		}
	}

	return adapters, nil
}
