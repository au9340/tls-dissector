package dissector

import (
	"fmt"
	"io"
)

// MaxHandshakeLength is the largest handshake message, 4-byte handshake header
// included, that the reassembler will buffer.
//
// A handshake message may legally be up to 2^24-1 bytes long, and it may be
// fragmented across arbitrarily many TLS records (RFC 5246 §6.2.1, RFC 8446
// §5.1). ClientHello and ServerHello never carry certificates, so 64 KiB is
// two orders of magnitude above real traffic; the cap keeps an attacker from
// driving an unbounded allocation through the 24-bit length field.
const MaxHandshakeLength = 64 * 1024

// ReadHandshakeMessage reads one complete handshake message from r and
// reassembles it from the TLS records that carry it.
//
// It returns the handshake type and the message body, i.e. everything after
// the 4-byte handshake header (type + 24-bit length). Records that precede the
// message must be Handshake records; any other content type yields ErrBadType.
//
// Records following the one that completes the message are left unread in r,
// so a caller can keep using r to parse the rest of the stream. The tail of the
// completing record is consumed together with it — record framing makes it
// impossible to hand back a partial record.
func ReadHandshakeMessage(r io.Reader) (typ uint8, body []byte, err error) {
	h := &handshakeReader{r: r, first: true}
	raw, err := h.readMessage(0, false)
	if err != nil {
		return 0, nil, err
	}
	return raw[0], raw[handshakeHeaderLen:], nil
}

// handshakeReader sits between the record layer and the handshake layer: it
// hands out handshake bytes without regard for record boundaries, which is what
// lets a message fragmented over several records be decoded by the ordinary
// message parsers.
type handshakeReader struct {
	r io.Reader
	// alert makes an EncryptedAlert in place of the expected message decode to
	// ErrAlert instead of ErrBadType (server side: the peer may answer a
	// ClientHello with an alert record).
	alert bool
	// first is true until the first record has been read.
	first bool
}

// nextRecord returns the next Handshake record, or an error if the stream
// carries something else where a handshake message was expected.
func (h *handshakeReader) nextRecord() (*Record, error) {
	rec, err := ReadRecord(h.r)
	if err != nil {
		return nil, err
	}
	if h.first {
		h.first = false
		if h.alert && rec.Type == EncryptedAlert {
			msg := &AlertMsg{}
			if err := msg.Decode(rec.Opaque); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %s", ErrAlert, msg)
		}
	}
	if rec.Type != Handshake {
		return nil, fmt.Errorf("%w %d", ErrBadType, rec.Type)
	}
	return rec, nil
}

// readMessage accumulates handshake bytes across records until a whole message
// is available and returns it with its 4-byte handshake header. When checkType
// is set, a message whose type is not want is reported as ErrBadType.
func (h *handshakeReader) readMessage(want uint8, checkType bool) ([]byte, error) {
	rec, err := h.nextRecord()
	if err != nil {
		return nil, err
	}

	need, err := handshakeLen(rec.Opaque, want, checkType)
	if err != nil {
		return nil, err
	}
	if need > 0 && need <= len(rec.Opaque) {
		// Fast path: the message sits entirely in the first record, which is
		// what a peer that does not fragment the record layer sends. Decode
		// straight out of the record payload instead of copying it.
		return rec.Opaque[:need], nil
	}

	// Slow path: the message is fragmented. Grow a buffer with the bytes seen so
	// far and keep appending record payloads until the message is complete.
	buf := make([]byte, len(rec.Opaque), len(rec.Opaque)+256)
	copy(buf, rec.Opaque)
	for {
		if need > 0 && len(buf) >= need {
			return buf[:need], nil
		}
		if rec, err = h.nextRecord(); err != nil {
			return nil, err
		}
		buf = append(buf, rec.Opaque...)
		if need, err = handshakeLen(buf, want, checkType); err != nil {
			return nil, err
		}
	}
}

// handshakeLen validates the 4-byte handshake header at the start of b and
// returns the total message size, header included. It returns 0 while b holds
// fewer than handshakeHeaderLen bytes, so the caller keeps reading records.
func handshakeLen(b []byte, want uint8, checkType bool) (int, error) {
	if len(b) < handshakeHeaderLen {
		return 0, nil // header itself still incomplete: nothing to validate yet
	}
	if checkType && b[0] != want {
		return 0, fmt.Errorf("%w %d", ErrBadType, b[0])
	}
	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length < 34 { // version + random
		return 0, fmt.Errorf("bad length, need at least 34 bytes, got %d", length)
	}
	total := handshakeHeaderLen + length
	if total > MaxHandshakeLength {
		return 0, errHandshakeTooLarge()
	}
	return total, nil
}

func errHandshakeTooLarge() error {
	return fmt.Errorf("handshake message too large (over %d bytes)", MaxHandshakeLength)
}
