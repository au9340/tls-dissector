package dissector

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// reassemble splits a handshake message (header included) into one TLS record
// per chunk and concatenates the records, i.e. simulates a peer that fragmented
// the message across the record layer.
func reassemble(version Version, hs []byte, cuts ...int) []byte {
	var out []byte
	prev := 0
	for _, c := range cuts {
		out = append(out, makeRecordBytes(Handshake, version, hs[prev:c])...)
		prev = c
	}
	return append(out, makeRecordBytes(Handshake, version, hs[prev:])...)
}

// TestParseClientHelloFragmentEverySplit splits a ClientHello at every possible
// byte offset into two records. The parser must produce identical results no
// matter where the record boundary falls: the handshake header, the session ID,
// the cipher-suite list, the extension block, or even the SNI hostname can be
// cut in half.
func TestParseClientHelloFragmentEverySplit(t *testing.T) {
	want := makeClientHelloMsg()
	hs, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	whole, err := ParseClientHello(bytes.NewReader(makeRecordBytes(Handshake, 0x0303, hs)))
	if err != nil {
		t.Fatalf("ParseClientHello (single record): %v", err)
	}

	for cut := 1; cut < len(hs); cut++ {
		data := reassemble(0x0303, hs, cut)
		got, err := ParseClientHello(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("cut at %d: ParseClientHello: %v", cut, err)
		}
		if got.ServerName != whole.ServerName || got.ServerName != "example.com" {
			t.Errorf("cut at %d: ServerName = %q, want %q", cut, got.ServerName, "example.com")
		}
		if len(got.SupportedProtos) != 2 || got.SupportedProtos[0] != "h2" || got.SupportedProtos[1] != "http/1.1" {
			t.Errorf("cut at %d: SupportedProtos = %v, want [h2 http/1.1]", cut, got.SupportedProtos)
		}
		if len(got.SupportedVersions) != 2 || got.SupportedVersions[0] != 0x0304 {
			t.Errorf("cut at %d: SupportedVersions = %v", cut, got.SupportedVersions)
		}
		if !bytes.Equal(got.SessionID, want.SessionID) {
			t.Errorf("cut at %d: SessionID = %v, want %v", cut, got.SessionID, want.SessionID)
		}
		if len(got.CipherSuites) != len(want.CipherSuites) {
			t.Errorf("cut at %d: CipherSuites = %v", cut, got.CipherSuites)
		}
	}
}

// TestParseClientHelloFragmentOneBytePerRecord is the pathological case: the
// 4-byte handshake header arrives one byte at a time. The parser must not
// inspect the type or length field before all four bytes are buffered.
func TestParseClientHelloFragmentOneBytePerRecord(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var data []byte
	for i := 0; i < len(hs); i++ {
		data = append(data, makeRecordBytes(Handshake, 0x0303, hs[i:i+1])...)
	}

	info, err := ParseClientHello(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "example.com")
	}
}

// TestParseClientHelloFragmentThreeWays covers fragmentation into more than two
// records, including record boundaries inside the handshake header.
func TestParseClientHelloFragmentThreeWays(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	splits := [][2]int{
		{1, 2},            // header split into 1/1/rest
		{1, 3},            // type / length split
		{2, 3},            // length split
		{3, 4},            // last header byte alone
		{4, 5},            // header complete, 1 body byte, rest
		{10, 20},          // middle of version/random
		{40, 41},          // inside session ID
		{50, len(hs) - 1}, // up to the very last byte
		{len(hs) / 3, len(hs) * 2 / 3},
	}
	for _, sp := range splits {
		if sp[0] <= 0 || sp[1] <= sp[0] || sp[1] >= len(hs) {
			t.Fatalf("bad split %v for message of %d bytes", sp, len(hs))
		}
		data := reassemble(0x0303, hs, sp[0], sp[1])
		info, err := ParseClientHello(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("splits %v: ParseClientHello: %v", sp, err)
		}
		if info.ServerName != "example.com" {
			t.Errorf("splits %v: ServerName = %q", sp, info.ServerName)
		}
	}
}

// TestParseClientHelloEmptyRecords makes sure zero-length handshake records,
// which some middleboxes inject while re-segmenting, are skipped instead of
// being mistaken for a complete (empty) message.
func TestParseClientHelloEmptyRecords(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cut := len(hs) / 2

	var data []byte
	data = append(data, makeRecordBytes(Handshake, 0x0303, nil)...)
	data = append(data, makeRecordBytes(Handshake, 0x0303, hs[:cut])...)
	data = append(data, makeRecordBytes(Handshake, 0x0303, nil)...)
	data = append(data, makeRecordBytes(Handshake, 0x0303, hs[cut:])...)
	data = append(data, makeRecordBytes(Handshake, 0x0303, nil)...)

	info, err := ParseClientHello(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "example.com")
	}
}

// TestParseServerHelloFragmentEverySplit is the server-side counterpart: a
// ServerHello fragmented across records must parse like an unfragmented one.
func TestParseServerHelloFragmentEverySplit(t *testing.T) {
	hs, err := makeServerHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for cut := 1; cut < len(hs); cut++ {
		data := reassemble(0x0303, hs, cut)
		info, err := ParseServerHello(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("cut at %d: ParseServerHello: %v", cut, err)
		}
		if info.CipherSuite != 0xC02B {
			t.Errorf("cut at %d: CipherSuite = 0x%04x, want 0xc02b", cut, info.CipherSuite)
		}
		if info.Proto != "h2" {
			t.Errorf("cut at %d: Proto = %q, want h2", cut, info.Proto)
		}
		if info.Version != 0x0304 {
			t.Errorf("cut at %d: Version = 0x%04x, want 0x0304", cut, info.Version)
		}
	}
}

// TestParseClientHelloFragmentRealTraffic re-fragments a ClientHello captured
// from a real connection (TLS 1.3, post-quantum style key share) at the point
// where a 1-record ClientHello would have been split by a 1500-byte MTU.
func TestParseClientHelloFragmentRealTraffic(t *testing.T) {
	const hexData = "160301013a010001360303d0c13e538a2bf6f73d50b151cf02629d15d9b49fbd589ef4472f71c16d5203e520aa7775f73feb9cee597c57aeaeae30b2bb9cfd6622815072ba2cea00c17aba530026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000000180016000013636c6f7564666c6172652d717569632e636f6d000b00020100ff010001000017000000120000000500050100000000000a000a0008001d001700180019000d001a00180804040308070805080604010501060105030603020102030032001a00180804040308070805080604010501060105030603020102030010000e000c02683208687474702f312e31002b00050403040303003300260024001d0020eefe8c9fab6c9c521ce4e09a3f4b34065ef7374da0a542503378b8e0cabc9f4b"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	hs := data[RecordHeaderLen:]

	for _, cut := range []int{1000, 1400, 1448, len(hs) - 1} {
		if cut <= 0 || cut >= len(hs) {
			continue
		}
		info, err := ParseClientHello(bytes.NewReader(reassemble(0x0301, hs, cut)))
		if err != nil {
			t.Fatalf("cut at %d: ParseClientHello: %v", cut, err)
		}
		if info.ServerName != "cloudflare-quic.com" {
			t.Errorf("cut at %d: ServerName = %q, want cloudflare-quic.com", cut, info.ServerName)
		}
		if len(info.SupportedProtos) != 2 || info.SupportedProtos[0] != "h2" {
			t.Errorf("cut at %d: SupportedProtos = %v", cut, info.SupportedProtos)
		}
	}
}

// TestParseClientHelloFragmentWrongType verifies that a fragment stream that
// starts with some other handshake message is rejected, and that the sentinel
// error stays matchable through errors.Is.
func TestParseClientHelloFragmentWrongType(t *testing.T) {
	hs, err := makeServerHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	_, err = ParseClientHello(bytes.NewReader(reassemble(0x0303, hs, 3)))
	if !errors.Is(err, ErrBadType) {
		t.Fatalf("err = %v, want ErrBadType", err)
	}
}

// TestParseClientHelloFragmentNonHandshakeRecord verifies that a non-handshake
// record in the middle of a fragmented message is reported as ErrBadType
// (RFC 8446 §5.1 forbids interleaving other content types).
func TestParseClientHelloFragmentNonHandshakeRecord(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cut := len(hs) / 2

	var data []byte
	data = append(data, makeRecordBytes(Handshake, 0x0303, hs[:cut])...)
	data = append(data, makeRecordBytes(EncryptedAlert, 0x0303, []byte{0x02, 0x28})...)
	data = append(data, makeRecordBytes(Handshake, 0x0303, hs[cut:])...)

	_, err = ParseClientHello(bytes.NewReader(data))
	if !errors.Is(err, ErrBadType) {
		t.Fatalf("err = %v, want ErrBadType", err)
	}
}

// TestParseClientHelloFragmentTooLarge checks the size guard: the reassembler
// must refuse a message whose declared length exceeds MaxHandshakeLength
// instead of allocating whatever the peer asks for.
func TestParseClientHelloFragmentTooLarge(t *testing.T) {
	// ClientHello header claiming 0x010000 (65536) bytes of body.
	hdr := []byte{ClientHello, 0x01, 0x00, 0x00}
	data := makeRecordBytes(Handshake, 0x0303, hdr)

	_, err := ParseClientHello(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected an error for an oversized handshake message")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %q, want containing 'too large'", err.Error())
	}
}

// TestParseClientHelloFragmentTruncated: the peer closes the connection in the
// middle of a fragmented ClientHello. The parser must report an unexpected EOF
// rather than hanging or accepting a partial message.
func TestParseClientHelloFragmentTruncated(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cut := len(hs) / 2
	data := reassemble(0x0303, hs, cut)

	// Drop the last 10 bytes: the second record's body is now incomplete.
	_, err = ParseClientHello(bytes.NewReader(data[:len(data)-10]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestParseClientHelloLeavesNextRecordsUnread is the property proxies rely on:
// after sniffing the ClientHello from a connection, the following records (CCS,
// Finished, application data) must still be readable from the same reader.
func TestParseClientHelloLeavesNextRecordsUnread(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	ccs := makeRecordBytes(ChangeCipherSpec, 0x0303, []byte{0x01})
	appData := makeRecordBytes(AppData, 0x0303, []byte("GET / HTTP/1.1\r\n\r\n"))

	stream := append(reassemble(0x0303, hs, len(hs)/2), ccs...)
	stream = append(stream, appData...)

	r := bytes.NewReader(stream)
	if _, err := ParseClientHello(r); err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	rec, err := ReadRecord(r)
	if err != nil {
		t.Fatalf("ReadRecord after ClientHello: %v", err)
	}
	if rec.Type != ChangeCipherSpec {
		t.Fatalf("next record type = 0x%02x, want ChangeCipherSpec (0x%02x)", rec.Type, ChangeCipherSpec)
	}

	rec, err = ReadRecord(r)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.Type != AppData || string(rec.Opaque) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("next record = type 0x%02x %q", rec.Type, rec.Opaque)
	}
}

// TestParseClientHelloTrailingHandshakeInRecord documents the one piece of the
// stream that record-level reassembly necessarily swallows: bytes that follow
// the message inside the completing record. Parsing still succeeds and the
// ClientHello is intact; only the tail of that same record is lost, which is
// what the single-record parser did as well.
func TestParseClientHelloTrailingHandshakeInRecord(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	trailing, err := makeServerHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	payload := append(copyOf(hs), trailing...)
	info, err := ParseClientHello(bytes.NewReader(makeRecordBytes(Handshake, 0x0303, payload)))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", info.ServerName)
	}
}

// TestReadHandshakeMessage exercises the exported reassembler directly.
func TestReadHandshakeMessage(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for _, cuts := range [][]int{nil, {1}, {4}, {len(hs) / 2}, {1, len(hs) - 1}} {
		var data []byte
		if cuts == nil {
			data = makeRecordBytes(Handshake, 0x0303, hs)
		} else {
			data = reassemble(0x0303, hs, cuts...)
		}

		typ, body, err := ReadHandshakeMessage(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("cuts %v: ReadHandshakeMessage: %v", cuts, err)
		}
		if typ != ClientHello {
			t.Errorf("cuts %v: type = %d, want %d", cuts, typ, ClientHello)
		}
		if !bytes.Equal(body, hs[handshakeHeaderLen:]) {
			t.Errorf("cuts %v: body mismatch (%d bytes, want %d)", cuts, len(body), len(hs)-handshakeHeaderLen)
		}
	}
}

// TestReadHandshakeMessageBadType: the exported API rejects non-handshake
// records as well.
func TestReadHandshakeMessageBadType(t *testing.T) {
	_, _, err := ReadHandshakeMessage(bytes.NewReader(makeRecordBytes(AppData, 0x0303, []byte("x"))))
	if !errors.Is(err, ErrBadType) {
		t.Fatalf("err = %v, want ErrBadType", err)
	}
}

// TestParseClientHelloFragmentShortLength: a handshake length field smaller than
// version+random is malformed and must be rejected as soon as the header is
// buffered, without waiting for a body that can never be valid.
func TestParseClientHelloFragmentShortLength(t *testing.T) {
	hdr := []byte{ClientHello, 0x00, 0x00, 0x10}
	data := makeRecordBytes(Handshake, 0x0303, hdr)

	_, err := ParseClientHello(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected an error for a too-short handshake length")
	}
	if !strings.Contains(err.Error(), "need at least 34 bytes") {
		t.Errorf("err = %q, want containing 'need at least 34 bytes'", err.Error())
	}
}

// TestParseClientHelloFragmentMalformedBody: reassembly succeeds but the
// reassembled ClientHello body is corrupt (session ID length runs past the end
// of the message). The parser must return the decode error instead of trusting
// the length fields.
func TestParseClientHelloFragmentMalformedBody(t *testing.T) {
	hs, err := makeClientHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// handshake header (4) + version (2) + random (32) -> session ID length byte
	hs[handshakeHeaderLen+34] = 0xff

	_, err = ParseClientHello(bytes.NewReader(reassemble(0x0303, hs, 10)))
	if err == nil {
		t.Fatal("expected a decode error for a malformed session length")
	}
	if !strings.Contains(err.Error(), "session") {
		t.Errorf("err = %q, want containing 'session'", err.Error())
	}
}

// TestParseServerHelloFragmentMalformedBody is the server-side counterpart of
// TestParseClientHelloFragmentMalformedBody.
func TestParseServerHelloFragmentMalformedBody(t *testing.T) {
	hs, err := makeServerHelloMsg().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	hs[handshakeHeaderLen+34] = 0xff

	_, err = ParseServerHello(bytes.NewReader(reassemble(0x0303, hs, 10)))
	if err == nil {
		t.Fatal("expected a decode error for a malformed session length")
	}
	if !strings.Contains(err.Error(), "session") {
		t.Errorf("err = %q, want containing 'session'", err.Error())
	}
}
