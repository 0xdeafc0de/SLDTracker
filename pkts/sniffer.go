package pkts

import (
	"fmt"
	//"log"
	//"strings"
	//"time"

	"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketSniffer captures packets from interface and extracts domains
type PacketSniffer struct {
	iface string
	pcapFile string
}

func NewPacketSniffer(interfaceName string) *PacketSniffer {
	return &PacketSniffer{iface: interfaceName}
}

func NewPacketSnifferFromPcap(pcapFile string) *PacketSniffer {
    return &PacketSniffer{pcapFile: pcapFile}
}

func (ps *PacketSniffer) Start(domainHandler func(domain string)) error {
	var (
        handle *pcap.Handle
        err error
    )

	if ps.pcapFile != "" {
		fmt.Println("OFFLine - ", ps.pcapFile)
        handle, err = pcap.OpenOffline(ps.pcapFile)
        if err != nil {
            return fmt.Errorf("failed to open pcap file %s: %v", ps.pcapFile, err)
        }
	} else {
		fmt.Println("Live - ", ps.iface)
		handle, err = pcap.OpenLive(ps.iface, 65535, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("failed to open interface %s: %v", ps.iface, err)
		}

		// Only capture DNS, TLS, QUIC ports
		err = handle.SetBPFFilter("udp port 53 or tcp port 443 or udp port 443")
		if err != nil {
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	// Ensure handle is not nil
    if handle == nil {
        return fmt.Errorf("pcap handle is nil")
    }

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go func(p gopacket.Packet) {
			if domain := extractDomainFromDNS(p); domain != "" {
				domainHandler(domain)
			} else if domain := extractDomainFromTLS(p); domain != "" {
				domainHandler(domain)
			} else if domain := extractDomainFromQUIC(p); domain != "" {
				domainHandler(domain)
			}
		}(packet)
	}

	return nil
}

