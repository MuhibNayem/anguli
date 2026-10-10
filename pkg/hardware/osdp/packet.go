package osdp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// SOM is the OSDP Start of Message byte defined in SIA OSDP v2.2
	SOM byte = 0x53

	// OSDP Standard Command Codes
	CmdPoll    byte = 0x60 // osdp_POLL
	CmdId      byte = 0x61 // osdp_ID
	CmdCap     byte = 0x62 // osdp_CAP
	CmdDiag    byte = 0x63 // osdp_DIAG
	CmdLStat   byte = 0x64 // osdp_LSTAT
	CmdRStat   byte = 0x65 // osdp_RSTAT
	CmdOut     byte = 0x66 // osdp_OUT
	CmdLed     byte = 0x69 // osdp_LED
	CmdBuz     byte = 0x6A // osdp_BUZ
	CmdBioRead byte = 0x74 // osdp_BIOREAD
	CmdKeySet  byte = 0x75 // osdp_KEYSET
	CmdChlng   byte = 0x76 // osdp_CHLNG
	CmdSCrypt  byte = 0x77 // osdp_SCRYPT

	// OSDP Standard Reply Codes
	ReplyAck      byte = 0x40 // osdp_ACK
	ReplyNak      byte = 0x41 // osdp_NAK
	ReplyPdId     byte = 0x45 // osdp_PDID
	ReplyPdCap    byte = 0x46 // osdp_PDCAP
	ReplyLStatR   byte = 0x48 // osdp_LSTATR
	ReplyRaw      byte = 0x50 // osdp_RAW (Card / Badge data)
	ReplyFmt      byte = 0x51 // osdp_FMT
	ReplyBioReadR byte = 0x74 // osdp_BIOREADR (Biometric data returned)
	ReplyCCrypt   byte = 0x76 // osdp_CCRYPT
	ReplyRMacI    byte = 0x78 // osdp_RMAC_I
)

var (
	ErrInvalidSOM      = errors.New("invalid OSDP start of message byte (expected 0x53)")
	ErrPacketTooShort  = errors.New("OSDP packet too short to contain header and CRC")
	ErrCRCMismatch     = errors.New("OSDP packet CRC-16 checksum verification failed")
	ErrPayloadTooLarge = errors.New("OSDP payload exceeds maximum frame size")
)

// Packet represents a fully framed SIA OSDP v2 message packet.
type Packet struct {
	Address  byte
	Sequence byte
	UseCRC   bool
	Command  byte
	Data     []byte
}

// Encode serializes an OSDP Packet into wire-format bytes including SOM, length, CTRL, and CRC-16.
func (p *Packet) Encode() ([]byte, error) {
	if len(p.Data) > 1400 {
		return nil, ErrPayloadTooLarge
	}

	// Header: SOM (1) + ADDR (1) + LEN_LSB (1) + LEN_MSB (1) + CTRL (1) + CMD (1) = 6 bytes
	// Trailer: CRC-16 (2 bytes)
	totalLen := 6 + len(p.Data) + 2
	buf := make([]byte, totalLen)

	buf[0] = SOM
	buf[1] = p.Address & 0x7F // 7-bit peripheral address

	binary.LittleEndian.PutUint16(buf[2:4], uint16(totalLen))

	ctrl := p.Sequence & 0x03
	if p.UseCRC {
		ctrl |= 0x04 // bit 2: CRC-16 enabled
	}
	buf[4] = ctrl
	buf[5] = p.Command

	if len(p.Data) > 0 {
		copy(buf[6:6+len(p.Data)], p.Data)
	}

	crc := ComputeCRC16(buf[:totalLen-2])
	binary.LittleEndian.PutUint16(buf[totalLen-2:], crc)

	return buf, nil
}

// DecodePacket parses and verifies a raw OSDP wire-format frame with CRC validation.
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 8 {
		return nil, ErrPacketTooShort
	}

	if data[0] != SOM {
		return nil, ErrInvalidSOM
	}

	pktLen := int(binary.LittleEndian.Uint16(data[2:4]))
	if len(data) < pktLen {
		return nil, fmt.Errorf("truncated packet: expected %d bytes, got %d", pktLen, len(data))
	}

	ctrl := data[4]
	useCRC := (ctrl & 0x04) != 0

	if useCRC {
		expectedCRC := binary.LittleEndian.Uint16(data[pktLen-2 : pktLen])
		actualCRC := ComputeCRC16(data[:pktLen-2])
		if expectedCRC != actualCRC {
			return nil, ErrCRCMismatch
		}
	}

	dataEnd := pktLen - 2
	if !useCRC {
		dataEnd = pktLen - 1
	}

	payload := make([]byte, dataEnd-6)
	if len(payload) > 0 {
		copy(payload, data[6:dataEnd])
	}

	return &Packet{
		Address:  data[1] & 0x7F,
		Sequence: ctrl & 0x03,
		UseCRC:   useCRC,
		Command:  data[5],
		Data:     payload,
	}, nil
}

// ComputeCRC16 calculates the standard ITU-T CRC-16 (polynomial 0x1021) for SIA OSDP.
func ComputeCRC16(data []byte) uint16 {
	var crc uint16 = 0x1D0F
	for _, b := range data {
		x := (crc >> 8) ^ uint16(b)
		x ^= x >> 4
		crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x
	}
	return crc
}
