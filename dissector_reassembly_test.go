package dissector

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// mkHandshakeRecord wraps a handshake message into a single TLS record.
func mkHandshakeRecord(payload []byte) []byte {
	h := []byte{Handshake, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(h[3:], uint16(len(payload)))
	return append(h, payload...)
}

func testClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	ch := &ClientHelloMsg{
		Version:            VersionTLS12,
		SessionID:          bytes.Repeat([]byte{0xab}, 32),
		CipherSuites:       []uint16{0x1301, 0x1302, 0xc02b},
		CompressionMethods: []uint8{0},
		Extensions: []Extension{
			&ServerNameExtension{NameType: 0, Name: sni},
			&SupportedVersionsExtension{Versions: []uint16{0x0304, 0x0303}},
			&ALPNExtension{Protos: []string{"h2", "http/1.1"}},
		},
	}
	hs, err := ch.Encode()
	if err != nil {
		t.Fatalf("encode ClientHello: %v", err)
	}
	return hs
}

// TestParseClientHelloSingleRecord is the regression guard for the existing
// behaviour: an unfragmented ClientHello must still be parsed.
func TestParseClientHelloSingleRecord(t *testing.T) {
	hs := testClientHello(t, "www.example.com")
	info, err := ParseClientHello(bytes.NewReader(mkHandshakeRecord(hs)))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "www.example.com" {
		t.Fatalf("ServerName = %q, want %q", info.ServerName, "www.example.com")
	}
}

// TestParseClientHelloFragmented splits the ClientHello in the middle of the
// server_name value and puts each half in its own TLS record. Both halves are
// legal per RFC 8446 section 5.1, but a parser that reads only the first record
// fails with io.ErrUnexpectedEOF.
func TestParseClientHelloFragmented(t *testing.T) {
	hs := testClientHello(t, "www.example.com")

	off := bytes.Index(hs, []byte("example")) + 3 // split inside the SNI itself
	if off <= 3 || off >= len(hs) {
		t.Fatalf("bad split offset %d", off)
	}
	split := append(mkHandshakeRecord(hs[:off]), mkHandshakeRecord(hs[off:])...)

	info, err := ParseClientHello(bytes.NewReader(split))
	if err != nil {
		t.Fatalf("ParseClientHello on fragmented ClientHello: %v", err)
	}
	if info.ServerName != "www.example.com" {
		t.Fatalf("ServerName = %q, want %q", info.ServerName, "www.example.com")
	}
	if len(info.SupportedProtos) != 2 || info.SupportedProtos[0] != "h2" {
		t.Fatalf("SupportedProtos = %v, want [h2 http/1.1]", info.SupportedProtos)
	}
}

// TestParseClientHelloFragmentedByteByByte pushes the handshake one byte per
// record, the pathological case, to make sure the loop terminates properly.
func TestParseClientHelloFragmentedByteByByte(t *testing.T) {
	hs := testClientHello(t, "a.example.com")
	var buf []byte
	for i := 0; i < len(hs); i++ {
		buf = append(buf, mkHandshakeRecord(hs[i:i+1])...)
	}
	info, err := ParseClientHello(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "a.example.com" {
		t.Fatalf("ServerName = %q", info.ServerName)
	}
}

// TestParseClientHelloTruncated ensures a truncated ClientHello is still an
// error rather than a silent zero value.
func TestParseClientHelloTruncated(t *testing.T) {
	hs := testClientHello(t, "www.example.com")
	trunc := mkHandshakeRecord(hs[:len(hs)/2]) // no second record follows
	if _, err := ParseClientHello(bytes.NewReader(trunc)); err == nil {
		t.Fatal("expected an error for a truncated ClientHello, got nil")
	}
}
