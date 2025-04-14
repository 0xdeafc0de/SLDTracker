package pkts

import (
	"bytes"
	"encoding/binary"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"crypto/tls"
	//"crypto/x509"
	//"errors"
)

func extractDomainFromTLS(packet gopacket.Packet) string {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return ""
	}
	tcp := tcpLayer.(*layers.TCP)

	payload := tcp.Payload
    if len(payload) < 5 {
        return ""
    }

	// TLS handshake record
    if payload[0] != 0x16 { // Handshake
        return ""
    }

	// TLS Version (bytes 1 and 2)
    // Handshake length (bytes 3 and 4)
    if payload[5] != 0x01 { // ClientHello
        return ""
    }

	sessionIDLenOffset := 43
    if len(payload) <= sessionIDLenOffset {
        return ""
    }

    sessionIDLen := int(payload[sessionIDLenOffset])
    offset := sessionIDLenOffset + 1 + sessionIDLen
    if len(payload) <= offset+2 {
        return ""
    }

	cipherSuiteLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
    offset += 2 + cipherSuiteLen
    if len(payload) <= offset {
        return ""
    }

    compressionMethodLen := int(payload[offset])
    offset += 1 + compressionMethodLen
    if len(payload) <= offset+2 {
        return ""
    }

	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
    offset += 2
    end := offset + extensionsLen
    if len(payload) < end {
        return ""
    }

    // Loop through extensions
    for offset+4 <= end {
        extType := binary.BigEndian.Uint16(payload[offset : offset+2])
        extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
        offset += 4

        if extType == 0x00 { // Server Name Extension
            if offset+2 > len(payload) {
                return ""
            }

            serverNameListLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
            offset += 2

            if offset+serverNameListLen > len(payload) {
                return ""
            }

            nameType := payload[offset]
            if nameType != 0x00 {
                return ""
            }

            nameLen := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
            if offset+3+nameLen > len(payload) {
                return ""
            }

            sni := string(payload[offset+3 : offset+3+nameLen])
            return strings.ToLower(sni)
        }

        offset += extLen
    }

	return ""
}

func parseSNI(payload []byte) string {
	// Simplified parsing: look for server_name extension (0x00 0x00)
	sniMarker := []byte{0x00, 0x00}
	idx := bytes.Index(payload, sniMarker)
	if idx == -1 || len(payload) < idx+9 {
		return ""
	}
	serverNameLen := int(payload[idx+7])
	if len(payload) < idx+8+serverNameLen {
		return ""
	}
	return string(payload[idx+8 : idx+8+serverNameLen])
}

