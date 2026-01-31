package stdnet

import (
	"net"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
)

type pionDiscover struct {
}

func (d pionDiscover) iFaces() ([]*transport.Interface, error) {
	log.Info(">>> pionDiscover.iFaces: starting...")
	ifs := []*transport.Interface{}

	log.Info(">>> pionDiscover.iFaces: calling net.Interfaces()...")
	oifs, err := net.Interfaces()
	if err != nil {
		log.Errorf(">>> pionDiscover.iFaces: net.Interfaces() failed: %v", err)
		return nil, err
	}
	log.Infof(">>> pionDiscover.iFaces: net.Interfaces() returned %d interfaces", len(oifs))

	for i, oif := range oifs {
		log.Infof(">>> pionDiscover.iFaces: processing interface %d: %s (index=%d, flags=%v)", i, oif.Name, oif.Index, oif.Flags)
		ifc := transport.NewInterface(oif)

		log.Infof(">>> pionDiscover.iFaces: calling Addrs() for interface %s...", oif.Name)
		addrs, err := oif.Addrs()
		if err != nil {
			log.Errorf(">>> pionDiscover.iFaces: Addrs() failed for %s: %v", oif.Name, err)
			return nil, err
		}
		log.Infof(">>> pionDiscover.iFaces: Addrs() for %s returned %d addresses", oif.Name, len(addrs))

		for _, addr := range addrs {
			ifc.AddAddress(addr)
		}

		ifs = append(ifs, ifc)
	}

	log.Infof(">>> pionDiscover.iFaces: done, returning %d interfaces", len(ifs))
	return ifs, nil
}
