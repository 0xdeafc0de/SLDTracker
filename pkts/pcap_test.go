package pkts

import (
    "testing"
	"time"
)

func TestExtractFromPcap(t *testing.T) {
    var domains []string
	//pcapFile := "pkts/testdata/sample.pcap"
	pcapFile := "testdata/sample.pcap"

	sniffer := NewPacketSnifferFromPcap(pcapFile)
    err := sniffer.Start(func(domain string) {
        //t.Logf("Extracted domain: %s", domain)
        domains = append(domains, domain)
    })
    if err != nil {
        t.Fatalf("Failed to extract from pcap: %v", err)
    }

	// Wait briefly to ensure all goroutines finish
    time.Sleep(2 * time.Second)

    if len(domains) == 0 {
        t.Errorf("Expected domains to be extracted, got 0")
    }

    for _, d := range domains {
        t.Logf("Extracted domain: %s", d)
    }
}
