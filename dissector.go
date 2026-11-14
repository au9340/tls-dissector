package dissector

import (
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
// The message is reassembled from the record layer first: a single handshake
// message may be fragmented across several TLS records (RFC 5246 §6.2.1,
// RFC 8446 §5.1). This happens in practice when a middlebox re-segments the
// record layer, and whenever the ClientHello outgrows one record, which is
// routine for modern clients whose post-quantum key share pushes the message
// past 1 KB but also for large ALPN/SNI/extension sets.
//
// Records that follow the ClientHello are left unread in r, so the caller can
// continue parsing the same stream.
func ParseClientHello(r io.Reader) (*ClientHelloInfo, error) {
	raw, err := newHandshakeReader(r).readMessage(ClientHello, true)
	if err != nil {
		return nil, err
	}

	msg := &ClientHelloMsg{}
	if err := msg.Decode(raw); err != nil {
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

type ServerHelloInfo struct {
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Proto             string
	Version           uint16
}

// ParseServerHello parses the TLS ServerHello from r, reassembling it if it was
// fragmented across several TLS records. An alert record in place of the
// ServerHello is reported as ErrAlert. Records that follow the ServerHello are
// left unread in r.
func ParseServerHello(r io.Reader) (*ServerHelloInfo, error) {
	h := &handshakeReader{r: r, first: true, alert: true}
	raw, err := h.readMessage(ServerHello, true)
	if err != nil {
		return nil, err
	}

	msg := &ServerHelloMsg{}
	if err := msg.Decode(raw); err != nil {
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

// newHandshakeReader wraps r so that handshake messages can span records.
func newHandshakeReader(r io.Reader) *handshakeReader {
	return &handshakeReader{r: r, first: true}
}
