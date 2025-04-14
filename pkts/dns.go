package pkts

import (
	//"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func extractDomainFromDNS(packet gopacket.Packet) string {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return ""
	}
	//fmt.Println("**DNS Layet Found ***")
	dns, _ := dnsLayer.(*layers.DNS)
	for _, q := range dns.Questions {
		if q.Type == layers.DNSTypeA || q.Type == layers.DNSTypeAAAA {
			return string(q.Name)
		}
	}
	return ""
}

