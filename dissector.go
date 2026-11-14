package dissector

import (
	"fmt"
	"io"
)

type ClientHelloInfo struct {
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	SupportedProtos    []string
	SupportedVersions  []uint16
	ServerName         string
}

// ParseClientHello parses the TLS ClientHello from r.
//
// A single handshake message may be fragmented across several TLS records
// (RFC 8446 section 5.1), so records are read in a loop until the whole
// ClientHello handshake message has been accumulated. A parser that inspects
// only the first record returns io.ErrUnexpectedEOF on such traffic, which in
// turn makes SNI-based routing drop otherwise perfectly valid connections.
func ParseClientHello(r io.Reader) (*ClientHelloInfo, error) {
	msg, err := readClientHelloMsg(r)
	if err != nil {
		return nil, err
	}

	info := &ClientHelloInfo{
		SessionID:          msg.SessionID,
		CipherSuites:       msg.CipherSuites,
		CompressionMethods: msg.CompressionMethods,
	}

	for _, ext := range msg.Extensions {
		switch ext.Type() {
		case ExtServerName:
			sniExt := ext.(*ServerNameExtension)
			info.ServerName = sniExt.Name
		case ExtSupportedVersions:
			verExt := ext.(*SupportedVersionsExtension)
			info.SupportedVersions = verExt.Versions
		case ExtALPN:
			alpnExt := ext.(*ALPNExtension)
			info.SupportedProtos = alpnExt.Protos
		}
	}

	return info, nil
}

// maxClientHelloLen bounds the reassembly buffer. A ClientHello is at most
// 2^24-1 bytes per the handshake header, but anything near that is abusive.
const maxClientHelloLen = 64 * 1024

// readClientHelloMsg reassembles the ClientHello handshake message from one or
// more consecutive handshake records.
func readClientHelloMsg(r io.Reader) (*ClientHelloMsg, error) {
	var hs []byte
	for {
		record, err := ReadRecord(r)
		if err != nil {
			return nil, err
		}
		if record.Type != Handshake {
			return nil, ErrBadType
		}
		hs = append(hs, record.Opaque...)
		if len(hs) > maxClientHelloLen {
			return nil, fmt.Errorf("client hello too large (over %d bytes)", maxClientHelloLen)
		}
		if len(hs) < handshakeHeaderLen {
			continue // handshake header not complete yet
		}
		if hs[0] != ClientHello {
			return nil, ErrBadType
		}
		length := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if length < 34 {
			return nil, fmt.Errorf("bad length, need at least 34 bytes, got %d", length)
		}
		if len(hs) < handshakeHeaderLen+length {
			continue // handshake message still incomplete, read the next record
		}
		msg := &ClientHelloMsg{}
		if err := msg.Decode(hs[:handshakeHeaderLen+length]); err != nil {
			return nil, err
		}
		return msg, nil
	}
}

type ServerHelloInfo struct {
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Proto             string
	Version           uint16
}

func ParseServerHello(r io.Reader) (*ServerHelloInfo, error) {
	record, err := ReadRecord(r)
	if err != nil {
		return nil, err
	}

	switch record.Type {
	case Handshake:
	case EncryptedAlert:
		msg := &AlertMsg{}
		if err := msg.Decode(record.Opaque); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", ErrAlert, msg.String())
	default:
		return nil, fmt.Errorf("%w %d", ErrBadType, record.Type)
	}

	msg := &ServerHelloMsg{}
	if err := msg.Decode(record.Opaque); err != nil {
		return nil, err
	}

	info := &ServerHelloInfo{
		SessionID:         msg.SessionID,
		CipherSuite:       msg.CipherSuite,
		CompressionMethod: msg.CompressionMethod,
		Version:           uint16(msg.Version),
	}

	for _, ext := range msg.Extensions {
		switch ext.Type() {
		case ExtSupportedVersions:
			verExt := ext.(*SupportedVersionsExtension)
			if len(verExt.Versions) > 0 {
				info.Version = verExt.Versions[0]
			}
		case ExtALPN:
			alpnExt := ext.(*ALPNExtension)
			if len(alpnExt.Protos) > 0 {
				info.Proto = alpnExt.Protos[0]
			}
		}
	}

	return info, nil
}
