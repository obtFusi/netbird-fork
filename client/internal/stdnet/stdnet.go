// Package stdnet is an extension of the pion's stdnet.
// With it the list of the interface can come from external source.
// More info: https://github.com/golang/go/issues/40569
package stdnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	updateInterval    = 30 * time.Second
	dnsResolveTimeout = 30 * time.Second
)

var errNoSuitableAddress = errors.New("no suitable address found")

// Net is an implementation of the net.Net interface
// based on functions of the standard net package.
type Net struct {
	stdnet.Net
	interfaces    []*transport.Interface
	iFaceDiscover iFaceDiscover
	// interfaceFilter should return true if the given interfaceName is allowed
	interfaceFilter func(interfaceName string) bool
	lastUpdate      time.Time

	// mu is shared between interfaces and lastUpdate
	mu sync.Mutex

	// ctx is the context for network operations that supports cancellation
	ctx context.Context
}

// NewNetWithDiscover creates a new StdNet instance.
func NewNetWithDiscover(ctx context.Context, iFaceDiscover ExternalIFaceDiscover, disallowList []string) (*Net, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	n := &Net{
		interfaceFilter: InterfaceFilter(disallowList),
		ctx:             ctx,
	}
	// current ExternalIFaceDiscover implement in android-client https://github.dev/netbirdio/android-client
	// so in android cli use pionDiscover
	if netstack.IsEnabled() {
		n.iFaceDiscover = pionDiscover{}
	} else {
		n.iFaceDiscover = newMobileIFaceDiscover(iFaceDiscover)
	}
	return n, n.UpdateInterfaces()
}

// NewNet creates a new StdNet instance.
func NewNet(ctx context.Context, disallowList []string) (*Net, error) {
	log.Info(">>> stdnet.NewNet: starting...")
	if ctx == nil {
		ctx = context.Background()
	}
	log.Info(">>> stdnet.NewNet: creating Net struct...")
	n := &Net{
		iFaceDiscover:   pionDiscover{},
		interfaceFilter: InterfaceFilter(disallowList),
		ctx:             ctx,
	}
	log.Info(">>> stdnet.NewNet: calling UpdateInterfaces...")
	err := n.UpdateInterfaces()
	log.Infof(">>> stdnet.NewNet: UpdateInterfaces returned, err=%v", err)
	return n, err
}

// resolveAddr performs DNS resolution with context support and timeout.
func (n *Net) resolveAddr(network, address string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %w", err)
	}
	if port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %d", port)
	}

	ipNet := "ip"
	switch network {
	case "tcp4", "udp4":
		ipNet = "ip4"
	case "tcp6", "udp6":
		ipNet = "ip6"
	}

	if host == "" {
		addr := netip.IPv4Unspecified()
		if ipNet == "ip6" {
			addr = netip.IPv6Unspecified()
		}
		return netip.AddrPortFrom(addr, uint16(port)), nil
	}

	ctx, cancel := context.WithTimeout(n.ctx, dnsResolveTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, ipNet, host)
	if err != nil {
		return netip.AddrPort{}, err
	}

	if len(addrs) == 0 {
		return netip.AddrPort{}, errNoSuitableAddress
	}

	return netip.AddrPortFrom(addrs[0], uint16(port)), nil
}

// UpdateInterfaces updates the internal list of network interfaces
// and associated addresses filtering them by name.
// The interfaces are discovered by an external iFaceDiscover function or by a default discoverer if the external one
// wasn't specified.
func (n *Net) UpdateInterfaces() (err error) {
	log.Info(">>> UpdateInterfaces: acquiring mutex...")
	n.mu.Lock()
	defer n.mu.Unlock()
	log.Info(">>> UpdateInterfaces: mutex acquired, calling updateInterfaces()...")

	err = n.updateInterfaces()
	log.Infof(">>> UpdateInterfaces: updateInterfaces() returned, err=%v", err)
	return err
}

func (n *Net) updateInterfaces() (err error) {
	log.Info(">>> updateInterfaces: calling iFaceDiscover.iFaces()...")
	allIfaces, err := n.iFaceDiscover.iFaces()
	if err != nil {
		log.Errorf(">>> updateInterfaces: iFaces() failed: %v", err)
		return err
	}
	log.Infof(">>> updateInterfaces: iFaces() returned %d interfaces", len(allIfaces))

	log.Info(">>> updateInterfaces: calling filterInterfaces()...")
	n.interfaces = n.filterInterfaces(allIfaces)
	log.Infof(">>> updateInterfaces: filterInterfaces() returned %d interfaces", len(n.interfaces))

	n.lastUpdate = time.Now()
	log.Info(">>> updateInterfaces: done!")

	return nil
}

// Interfaces returns a slice of interfaces which are available on the
// system
func (n *Net) Interfaces() ([]*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if time.Since(n.lastUpdate) < updateInterval {
		return slices.Clone(n.interfaces), nil
	}

	if err := n.updateInterfaces(); err != nil {
		return nil, fmt.Errorf("update interfaces: %w", err)
	}

	return slices.Clone(n.interfaces), nil
}

// InterfaceByIndex returns the interface specified by index.
//
// On Solaris, it returns one of the logical network interfaces
// sharing the logical data link; for more precision use
// InterfaceByName.
func (n *Net) InterfaceByIndex(index int) (*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

// InterfaceByName returns the interface specified by name.
func (n *Net) InterfaceByName(name string) (*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (n *Net) filterInterfaces(interfaces []*transport.Interface) []*transport.Interface {
	log.Infof(">>> filterInterfaces: starting with %d interfaces, filter=%v", len(interfaces), n.interfaceFilter != nil)
	if n.interfaceFilter == nil {
		log.Info(">>> filterInterfaces: no filter, returning all interfaces")
		return interfaces
	}
	var result []*transport.Interface
	for i, iface := range interfaces {
		log.Infof(">>> filterInterfaces: checking interface %d: %s...", i, iface.Name)
		if n.interfaceFilter(iface.Name) {
			log.Infof(">>> filterInterfaces: interface %s ALLOWED", iface.Name)
			result = append(result, iface)
		} else {
			log.Infof(">>> filterInterfaces: interface %s FILTERED OUT", iface.Name)
		}
	}
	log.Infof(">>> filterInterfaces: done, returning %d interfaces", len(result))
	return result
}

// ResolveUDPAddr resolves UDP addresses with context support and timeout.
func (n *Net) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	switch network {
	case "udp", "udp4", "udp6":
	case "":
		network = "udp"
	default:
		return nil, &net.OpError{Op: "resolve", Net: network, Err: net.UnknownNetworkError(network)}
	}

	addrPort, err := n.resolveAddr(network, address)
	if err != nil {
		return nil, &net.OpError{Op: "resolve", Net: network, Addr: &net.UDPAddr{IP: nil}, Err: err}
	}

	return net.UDPAddrFromAddrPort(addrPort), nil
}

// ResolveTCPAddr resolves TCP addresses with context support and timeout.
func (n *Net) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	case "":
		network = "tcp"
	default:
		return nil, &net.OpError{Op: "resolve", Net: network, Err: net.UnknownNetworkError(network)}
	}

	addrPort, err := n.resolveAddr(network, address)
	if err != nil {
		return nil, &net.OpError{Op: "resolve", Net: network, Addr: &net.TCPAddr{IP: nil}, Err: err}
	}

	return net.TCPAddrFromAddrPort(addrPort), nil
}
