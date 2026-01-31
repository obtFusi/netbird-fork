package stdnet

import (
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them.
func InterfaceFilter(disallowList []string) func(string) bool {

	return func(iFace string) bool {
		log.Infof(">>> InterfaceFilter: checking interface %s", iFace)

		if strings.HasPrefix(iFace, "lo") {
			// hardcoded loopback check to support already installed agents
			log.Infof(">>> InterfaceFilter: %s is loopback, filtering out", iFace)
			return false
		}

		for _, s := range disallowList {
			if strings.HasPrefix(iFace, s) && runtime.GOOS != "ios" {
				log.Infof(">>> InterfaceFilter: %s matches disallowList entry %s, filtering out", iFace, s)
				return false
			}
		}

		// Quick check for NetBird WireGuard interfaces by name pattern
		// This avoids deadlock when filtering interfaces during device.Up()
		// The wg.Device() call below can block if the interface is being initialized
		if strings.HasPrefix(iFace, "wg-nb") || strings.HasPrefix(iFace, "utun") || strings.HasPrefix(iFace, "wg") {
			log.Infof(">>> InterfaceFilter: %s matches WireGuard name pattern, filtering out (avoiding deadlock)", iFace)
			return false
		}

		// look for unlisted WireGuard interfaces
		log.Infof(">>> InterfaceFilter: %s - calling wgctrl.New()...", iFace)
		wg, err := wgctrl.New()
		if err != nil {
			log.Infof(">>> InterfaceFilter: %s - wgctrl.New() failed: %v, allowing interface", iFace, err)
			return true
		}
		log.Infof(">>> InterfaceFilter: %s - wgctrl.New() succeeded, calling wg.Device()...", iFace)
		defer func() {
			_ = wg.Close()
		}()

		_, err = wg.Device(iFace)
		if err != nil {
			log.Infof(">>> InterfaceFilter: %s - wg.Device() failed (not a WG interface), allowing", iFace)
		} else {
			log.Infof(">>> InterfaceFilter: %s - wg.Device() succeeded (IS a WG interface), filtering out", iFace)
		}
		return err != nil
	}
}
