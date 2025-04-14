package pkts

import (
	"encoding/binary"
    //"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func extractDomainFromQUIC(packet gopacket.Packet) string {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return ""
	}
	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 6 {
        return ""
    }

	// First byte: Header Form (bit 7) and other flags
    isLongHeader := (payload[0] & 0x80) != 0
    if !isLongHeader {
        return "" // Not an Initial packet
    }

    // Long Header: Must be Initial packet type (0x00)
    packetType := payload[0] & 0x30 >> 4
    if packetType != 0x0 {
        return ""
    }

	// Skip to payload: first 6 bytes: flags, version (4), DCID len
    offset := 1 + 4 // flags + version
    if offset >= len(payload) {
        return ""
    }

    dcil := int(payload[offset])
    offset += 1 + dcil
    if offset >= len(payload) {
        return ""
    }

    scil := int(payload[offset])
    offset += 1 + scil
    if offset+2 >= len(payload) {
        return ""
    }
	// Token Length (varint) – skip
    tokenLen, tokenLenBytes := readVarInt(payload[offset:])
    offset += tokenLenBytes + int(tokenLen)
    if offset+2 >= len(payload) {
        return ""
    }

    // Length of the actual crypto payload (also varint)
    cryptoLen, cryptoLenBytes := readVarInt(payload[offset:])
    offset += cryptoLenBytes

    if offset+int(cryptoLen) > len(payload) {
        return ""
    }

	// Extract TLS Client Hello from this portion
    crypto := payload[offset : offset+int(cryptoLen)]
	_ = crypto
	return ""
    //return parseTLSClientHello(crypto)
}

// Helper to read QUIC varint
func readVarInt(buf []byte) (val uint64, bytesRead int) {
    if len(buf) < 1 {
        return 0, 0
    }

    switch buf[0] >> 6 {
    case 0:
        return uint64(buf[0] & 0x3f), 1
    case 1:
        if len(buf) < 2 {
            return 0, 0
        }
        return uint64(binary.BigEndian.Uint16(buf) & 0x3fff), 2
    case 2:
        if len(buf) < 4 {
            return 0, 0
        }
        return uint64(binary.BigEndian.Uint32(buf) & 0x3fffffff), 4
    case 3:
        if len(buf) < 8 {
            return 0, 0
        }
        return binary.BigEndian.Uint64(buf) & 0x3fffffffffffffff, 8
    }
    return 0, 0
}
