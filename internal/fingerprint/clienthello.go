// Package fingerprint turns captured client bytes into fingerprints: the
// parsed ClientHello, JA4, the HTTP/2 (Akamai-style) fingerprint and header
// order.
package fingerprint

import "errors"

// ErrNotImplemented marks parsers that are still stubs.
var ErrNotImplemented = errors.New("not implemented")

// Extension is one ClientHello extension, as it appeared on the wire.
type Extension struct {
	Type uint16 `json:"type"`
	Data []byte `json:"-"`
}

// ClientHello holds the fields fingerprinting needs. Slices keep wire order,
// including GREASE values; filtering happens where a fingerprint is built,
// not here.
type ClientHello struct {
	LegacyVersion      uint16      `json:"legacy_version"`
	SessionIDLen       int         `json:"session_id_len"`
	CipherSuites       []uint16    `json:"cipher_suites"`
	CompressionMethods []byte      `json:"compression_methods"`
	Extensions         []Extension `json:"extensions"`

	// Decoded from their extensions, for convenience.
	ServerName          string   `json:"server_name,omitempty"`          // 0x0000
	SupportedGroups     []uint16 `json:"supported_groups,omitempty"`     // 0x000a
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"` // 0x000d
	ALPN                []string `json:"alpn,omitempty"`                 // 0x0010
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`   // 0x002b
}

// ParseClientHello parses the ClientHello out of the raw bytes a client sent
// at the start of a TLS connection (capture.Conn.RawClientBytes).
//
// NOT IMPLEMENTED YET. Design notes:
//
// Input and output
//   - In: TLS records as read off the socket. The first bytes are a record
//     header, not the handshake message.
//   - Out: *ClientHello with every list in wire order.
//
// Layout (spec: RFC 8446 §5.1 record layer, §4 handshake header, §4.1.2
// ClientHello, §4.2 extensions; RFC 6066 §3 SNI; RFC 7301 §3.1 ALPN)
//
//	record:    type(1)=0x16  legacy_record_version(2)  length(2)  fragment
//	handshake: msg_type(1)=0x01  length(3)  body
//	body:      legacy_version(2) random(32)
//	           session_id<0..32>        (1-byte length prefix)
//	           cipher_suites<2..2^16-2> (2-byte length prefix)
//	           compression<1..2^8-1>    (1-byte length prefix)
//	           extensions<8..2^16-1>    (2-byte length prefix)
//	extension: type(2) data<0..2^16-1>
//
// Library options
//   - golang.org/x/crypto/cryptobyte: cryptobyte.String with ReadUint8,
//     ReadUint16, ReadUint24LengthPrefixed, ReadUint16LengthPrefixed, and so
//     on. Every read reports success, and a length-prefixed read yields a
//     bounded sub-slice. crypto/tls uses it for the same job.
//   - encoding/binary (binary.BigEndian.Uint16) plus manual offsets: no
//     dependency, but every bounds check has to be written out.
//   - crypto/tls ClientHelloInfo (from GetConfigForClient) as a cross-check
//     only: it exposes cipher suites, groups, ALPN, SNI and (since Go 1.24)
//     extension IDs, but no extension payloads.
//
// Reference implementations
//   - $GOROOT/src/crypto/tls/handshake_messages.go: clientHelloMsg.unmarshal
//   - refraction-networking/utls: u_parrots.go, u_fingerprinter.go
//   - Wireshark's TLS dissector, for checking the output against real traffic
//
// Traps
//   - The handshake message can span several records, and one TCP read can
//     end in the middle of a record. Reassemble the record fragments first,
//     then parse the handshake message.
//   - Check every length against what remains. Truncated or hostile input
//     must return an error, never panic.
//   - The ServerName extension wraps a list: list length, name_type (0 is
//     host_name), then the name length. ALPN is also a list of 1-byte
//     length-prefixed strings inside a 2-byte-prefixed list.
//   - supported_versions in a ClientHello is a 1-byte-prefixed list of
//     uint16 values (it is a single uint16 in a ServerHello).
//   - The session ID is 32 random bytes in modern clients (TLS 1.3
//     middlebox compatibility mode). Record only its length; the bytes are
//     noise.
func ParseClientHello(raw []byte) (*ClientHello, error) {
	return nil, ErrNotImplemented
}
