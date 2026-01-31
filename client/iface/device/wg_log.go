package device

import (
	"golang.zx2c4.com/wireguard/device"
)

func wgLogLevel() int {
	// DEBUG: Temporarily force verbose logging to diagnose device.Up() blocking (Issue #113)
	// TODO: Revert after debugging - should check NB_WG_DEBUG env var
	return device.LogLevelVerbose
}
