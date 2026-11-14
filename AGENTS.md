# tls-dissector (TLS Handshake Dissector)

Zero-dependency Go library for parsing TLS ClientHello and ServerHello handshake messages at the record layer. Used for extracting routing-relevant fields (SNI, ALPN, cipher suites, supported versions) in proxy/gateway scenarios.

## Module

```
github.com/go-gost/tls-dissector
```

Go 1.17+. No external dependencies (only Go standard library).

## Package layout

| File | Lines | Layer |
|------|-------|-------|
| `dissector.go` | 113 | Public API: `ParseClientHello`, `ParseServerHello`, `ClientHelloInfo`, `ServerHelloInfo` |
| `handshake.go` | 108 | Reassembly: `ReadHandshakeMessage`, record→handshake stream, `MaxHandshakeLength` cap |
| `record.go` | 79 | TLS Record layer: `ReadRecord`, `Record`, content type constants |
| `msg.go` | 522 | Handshake message types: `ClientHelloMsg`, `ServerHelloMsg`, `AlertMsg`, `Random` |
| `extension.go` | 457 | Extension system: `Extension` interface, 11 concrete types, `NewExtension` factory |

## Public API

### Parsing functions

```go
func ParseClientHello(r io.Reader) (*ClientHelloInfo, error)
func ParseServerHello(r io.Reader) (*ServerHelloInfo, error)
```

`ParseServerHello` handles both `Handshake` (0x16) and `EncryptedAlert` (0x15) record types. On alert, it returns `ErrAlert` with the alert level and description string.

Both functions reassemble the message first: a handshake message may be fragmented across consecutive TLS records, and records following the message are left unread in the reader.

### Handshake reassembly

```go
func ReadHandshakeMessage(r io.Reader) (typ uint8, body []byte, err error)

const MaxHandshakeLength = 64 * 1024 // cap, 4-byte handshake header included
```

`ReadHandshakeMessage` returns the handshake type plus the body **without** the 4-byte handshake header (the `ParseClientHello` / `ParseServerHello` path keeps the header so the reassembled bytes feed `Decode` directly).

### Output types

```go
type ClientHelloInfo struct {
    SessionID          []byte
    CipherSuites       []uint16
    CompressionMethods []uint8
    SupportedProtos    []string   // from ALPN extension
    SupportedVersions  []uint16   // from supported_versions extension
    ServerName         string     // from SNI extension
}

type ServerHelloInfo struct {
    SessionID         []byte
    CipherSuite       uint16
    CompressionMethod uint8
    Proto             string   // from ALPN extension
    Version           uint16   // from supported_versions extension, or TLS 1.2 default
}
```

### Record layer

```go
func ReadRecord(r io.Reader) (*Record, error)

type Record struct {
    Type    uint8
    Version Version
    Opaque  []byte
}
```

### Extension system

```go
type Extension interface {
    Type() uint16
    Encode() ([]byte, error)
    Decode([]byte) error
}

func NewExtension(t uint16, data []byte) (Extension, error)  // factory
func ReadExtension(r io.Reader) (Extension, error)           // read from stream
```

### Message types

All message types implement `ReadFrom(io.Reader)`, `WriteTo(io.Writer)`, `Decode([]byte)`, `Encode() ([]byte, error)`:
- `ClientHelloMsg`, `ServerHelloMsg`, `AlertMsg`

### Sentinel errors

```go
ErrBadType  // wrong record or handshake message type
ErrAlert    // server responded with an alert (ParseServerHello only)
```

## Supported TLS extensions

| Constant | Value | RFC |
|----------|-------|-----|
| `ExtServerName` | 0x0000 | RFC 6066 (SNI) |
| `ExtSupportedGroups` | 0x000a | RFC 7919/8446 |
| `ExtECPointFormats` | 0x000b | RFC 4492 |
| `ExtSignatureAlgorithms` | 0x000d | RFC 5246 |
| `ExtALPN` | 0x0010 | RFC 7301 |
| `ExtEncryptThenMac` | 0x0016 | RFC 7366 |
| `ExtExtendedMasterSecret` | 0x0017 | RFC 7627 |
| `ExtSessionTicket` | 0x0023 | RFC 5077 |
| `ExtSupportedVersions` | 0x002b | RFC 8446 (TLS 1.3) |
| `ExtRenegotiationInfo` | 0xff01 | RFC 5746 |

Unknown extensions are preserved as `unknownExtension` (raw bytes passthrough).

## Design notes

- **Passthrough parser only**: only ClientHello and ServerHello are parsed (decoded). No Certificate, ServerKeyExchange, Finished, or other handshake messages — those can still be *reassembled* via `ReadHandshakeMessage`.
- **Record fragmentation supported**: `handshakeReader` concatenates handshake bytes from consecutive records until the message announced by the 4-byte handshake header is complete. Empty handshake records are skipped; interleaved non-handshake records yield `ErrBadType`; growth is capped by `MaxHandshakeLength`.
- **Stream position preserved**: reassembly stops at the record that completes the message, so the caller can keep reading the same `io.Reader`. Only the tail of that final record is consumed with it.
- **Bidirectional**: all types support both encoding and decoding.
- **Extensible**: new extensions can be added by implementing the `Extension` interface and adding a case to `NewExtension`.

## Testing

```sh
cd tls-dissector && go test -v ./...
```

Coverage: **97.2%** of statements (219 tests/subtests across 5 test files; 100% of the reassembly path).

| Test file | Focus |
|-----------|-------|
| `record_test.go` | `ReadRecord`, `WriteTo` round-trip, truncation |
| `msg_test.go` | `ClientHelloMsg` / `ServerHelloMsg` round-trip + errors, `AlertMsg` |
| `extension_test.go` | All 11 extensions round-trip + decode errors, `NewExtension`, `ReadExtension` |
| `dissector_test.go` | `ParseClientHello` / `ParseServerHello` full end-to-end, bad records, alert path, version fix regression |
| `reassembly_test.go` | Fragmentation at every split offset, 1-byte records, empty records, real-traffic re-fragmentation, oversized/short/truncated/malformed messages, stream position, `ReadHandshakeMessage` |

## Related modules

- `core/` — defines `service.Service` interface (uses tls-dissector indirectly via `x/`)
- `x/` — all protocol implementations that depend on this module for TLS inspection
- `gost/` — main binary that integrates TLS dissection into proxy routing
