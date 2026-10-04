// Package fingerprint turns captured client bytes into fingerprints: the
// parsed ClientHello, JA4, the HTTP/2 (Akamai-style) fingerprint and header
// order.
package fingerprint

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

// Errors returned by ParseClientHello
var (
	// ErrNotImplemented marks parsers that are still stubs.
	ErrNotImplemented = errors.New("not implemented")

	// Outer layer errors
	ErrTooShort              = errors.New("too short to be a TLS record")
	ErrNotHandshake          = errors.New("not a handshake record")
	ErrNotClientHello        = errors.New("not a ClientHello handshake message")
	ErrRecordTruncated       = errors.New("record length exceeds captured bytes")
	ErrFragmentedClientHello = errors.New("ClientHello spans several records (not supported yet)")
	ErrHandshakeTooShort     = errors.New("handshake length too short for a ClientHello")

	// Body errors
	ErrSessionIDTooLong            = errors.New("session ID length exceeds 32 bytes")
	ErrCipherSuitesTruncated       = errors.New("cipher_suites length exceeds ClientHello")
	ErrCompressionMethodsTruncated = errors.New("compression_methods length exceeds ClientHello")
	ErrExtensionsTruncated         = errors.New("extensions length exceeds ClientHello")

	// Bounds and spec-minimum checks
	ErrCipherSuitesLengthMissing       = errors.New("ClientHello ends before the cipher_suites length")
	ErrCipherSuitesOddLength           = errors.New("cipher_suites length is odd")
	ErrNoCipherSuites                  = errors.New("cipher_suites is empty")
	ErrCompressionMethodsLengthMissing = errors.New("ClientHello ends before the compression_methods length")
	ErrNoCompressionMethods            = errors.New("compression_methods is empty")
	ErrExtensionsLengthMissing         = errors.New("one byte left where the extensions length belongs")
	ErrExtensionHeaderTruncated        = errors.New("extension header runs past the extensions block")
	ErrExtensionDataTruncated          = errors.New("extension data runs past the extensions block")
	ErrTrailingData                    = errors.New("bytes left over after the extensions block")
)

// Extension errors are not returned. DecodeExtensions collects them, and
// ParseClientHello records them in ClientHello.Malformed.
var (
	ErrServerNameTooShort            = errors.New("server_name extension too short")
	ErrServerNameListLenMismatch     = errors.New("server_name extension list length mismatch")
	ErrServerNameNameTypeNotHostName = errors.New("server_name extension name type not host_name")
	ErrServerNameNameLenMismatch     = errors.New("server_name extension name length mismatch")

	ErrSupportedGroupsTooShort        = errors.New("supported_groups extension too short")
	ErrSupportedGroupsListLenMismatch = errors.New("supported_groups extension list length mismatch")

	ErrSignatureAlgorithmsTooShort        = errors.New("signature_algorithms extension too short")
	ErrSignatureAlgorithmsListLenMismatch = errors.New("signature_algorithms extension list length mismatch")

	ErrALPNTooShort        = errors.New("alpn extension too short")
	ErrALPNListLenMismatch = errors.New("alpn extension list length mismatch")
	ErrALPNNameLenMismatch = errors.New("alpn extension string length exceeds data length")

	ErrSupportedVersionsTooShort        = errors.New("supported_versions extension too short")
	ErrSupportedVersionsListLenMismatch = errors.New("supported_versions extension list length mismatch")

	// List-shape checks
	ErrSupportedGroupsOddLength     = errors.New("supported_groups extension list length is odd")
	ErrSignatureAlgorithmsOddLength = errors.New("signature_algorithms extension list length is odd")
	ErrSupportedVersionsOddLength   = errors.New("supported_versions extension list length is odd")
	ErrALPNEmptyList                = errors.New("alpn extension list is empty")
	ErrALPNEmptyName                = errors.New("alpn extension has an empty protocol name")
)

// Layout of the bytes in front of the ClientHello body and of its fixed
// fields (RFC 9846 §5.1, §4, §4.2.2).
const (
	recordHeaderLen    = 5 // type(1) legacy_record_version(2) length(2)
	handshakeHeaderLen = 4 // msg_type(1) length(3)
	helloBodyOffset    = recordHeaderLen + handshakeHeaderLen
	legacyVersionLen   = 2
	randomLen          = 32
	maxSessionIDLen    = 32
	sessionIDLenOffset = helloBodyOffset + legacyVersionLen + randomLen
	extHeaderLen       = 4 // type(2) length(2)
)

// server_name layout (RFC 6066 §3).
const (
	sniHeaderLen = 5 // list length(2) name_type(1) name length(2)
	hostNameType = 0
)

const (
	// ClientHelloMinLen is the minimum length of a ClientHello on the wire, in
	// bytes: headers, version and random, an empty session ID (1), one cipher
	// suite (2+2) and one compression method (1+1). The extensions block is
	// optional before TLS 1.3, so it is not counted.
	ClientHelloMinLen = sessionIDLenOffset + 1 + 2 + 2 + 1 + 1

	// ClientHelloRecordType is the TLS record type for a handshake message.
	ClientHelloRecordType = 0x16

	// ClientHelloMessageType is the handshake message type for a ClientHello.
	ClientHelloMessageType = 0x01
)

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

	// Malformed lists the extensions whose contents broke their layout, one
	// entry per problem. Real browsers never send these, so they are recorded
	// as a signal rather than failing the parse.
	Malformed ErrorList `json:"malformed,omitempty"`
}

// ErrorList keeps errors as errors in memory, so callers can match them with
// errors.Is, and writes them as their messages in JSON.
type ErrorList []error

// MarshalJSON writes each error as its message string. Error values have no
// JSON form of their own; decoding the output gives strings, not errors.
func (l ErrorList) MarshalJSON() ([]byte, error) {
	msgs := make([]string, len(l))
	for i, err := range l {
		msgs[i] = err.Error()
	}
	return json.Marshal(msgs)
}

// ParseClientHello parses the ClientHello out of the raw bytes a client sent
// at the start of a TLS connection (capture.Conn.RawClientBytes). Bytes after
// the ClientHello are ignored. An error means the bytes are not a ClientHello
// this parser can read; a malformed extension inside an otherwise readable
// hello is recorded in ClientHello.Malformed instead.
//
// Design notes:
//
// Input and output
//   - In: TLS records as read off the socket. The first bytes are a record
//     header, not the handshake message.
//   - Out: *ClientHello with every list in wire order.
//
// Layout (spec: RFC 9846 §5.1 record layer, §4 handshake header, §4.2.2
// ClientHello, §4.3 extensions; RFC 6066 §3 SNI; RFC 7301 §3.1 ALPN)
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
	if len(raw) < ClientHelloMinLen {
		return nil, ErrTooShort
	}

	// outer layer
	recordType := raw[0]
	if recordType != ClientHelloRecordType {
		return nil, ErrNotHandshake
	}
	// legacy_record_version (bytes 1-2) is ignored; the length closes the header.
	recordLength := int(binary.BigEndian.Uint16(raw[recordHeaderLen-2 : recordHeaderLen]))
	if len(raw) < recordHeaderLen+recordLength {
		return nil, ErrRecordTruncated
	}
	messageType := raw[recordHeaderLen]
	if messageType != ClientHelloMessageType {
		return nil, ErrNotClientHello
	}
	hl := raw[recordHeaderLen+1 : helloBodyOffset]
	handshakeLength := int(hl[0])<<16 | int(hl[1])<<8 | int(hl[2])
	if handshakeHeaderLen+handshakeLength > recordLength {
		return nil, ErrFragmentedClientHello
	}
	helloEnd := helloBodyOffset + handshakeLength
	if helloEnd < ClientHelloMinLen {
		return nil, ErrHandshakeTooShort
	}
	// raw also holds the records that follow the ClientHello, so cut it to the
	// end of the handshake message. The full slice expression caps the
	// capacity too: a read past the end now panics instead of returning
	// whatever bytes come next.
	raw = raw[:helloEnd:helloEnd]

	// ClientHello body
	legacyVersion := raw[helloBodyOffset : helloBodyOffset+legacyVersionLen]
	// random sits between legacy_version and the session ID length.
	sessionIdLen := raw[sessionIDLenOffset : sessionIDLenOffset+1]

	if int(sessionIdLen[0]) > maxSessionIDLen {
		return nil, ErrSessionIDTooLong
	}

	nextOffset := sessionIDLenOffset + 1 + int(sessionIdLen[0])

	if len(raw) < nextOffset+2 {
		return nil, ErrCipherSuitesLengthMissing
	}

	cipherSuitesLength := int(binary.BigEndian.Uint16(raw[nextOffset : nextOffset+2]))

	nextOffset += 2
	if len(raw) < nextOffset+cipherSuitesLength {
		return nil, ErrCipherSuitesTruncated
	}
	if cipherSuitesLength == 0 {
		return nil, ErrNoCipherSuites
	}
	// Each suite is 2 bytes; an odd length would read half a suite plus the
	// first byte of compression_methods.
	if cipherSuitesLength%2 != 0 {
		return nil, ErrCipherSuitesOddLength
	}

	cipherSuites := []uint16{}
	for i := nextOffset; i < nextOffset+cipherSuitesLength; i += 2 {
		cipherSuite := raw[i : i+2]
		cipherSuites = append(cipherSuites, binary.BigEndian.Uint16(cipherSuite))
	}

	nextOffset += cipherSuitesLength
	if len(raw) < nextOffset+1 {
		return nil, ErrCompressionMethodsLengthMissing
	}

	compressionMethodsLength := raw[nextOffset : nextOffset+1]
	if len(raw) < nextOffset+1+int(compressionMethodsLength[0]) {
		return nil, ErrCompressionMethodsTruncated
	}
	if compressionMethodsLength[0] == 0 {
		return nil, ErrNoCompressionMethods
	}
	compressionMethods := raw[nextOffset+1 : nextOffset+1+int(compressionMethodsLength[0])]

	nextOffset += 1 + int(compressionMethodsLength[0])

	if len(raw) == nextOffset {
		// No extensions block, which is valid before TLS 1.3.
		ch := &ClientHello{
			LegacyVersion:      binary.BigEndian.Uint16(legacyVersion),
			SessionIDLen:       int(sessionIdLen[0]),
			CipherSuites:       cipherSuites,
			CompressionMethods: compressionMethods,
			Extensions:         []Extension{},
		}
		return ch, nil
	}
	if len(raw) < nextOffset+2 {
		return nil, ErrExtensionsLengthMissing
	}

	extensionsLength := raw[nextOffset : nextOffset+2]
	extEnd := nextOffset + 2 + int(binary.BigEndian.Uint16(extensionsLength))
	if len(raw) < extEnd {
		return nil, ErrExtensionsTruncated
	}
	// The extensions block is the last field, so it must end exactly where
	// the handshake length says the ClientHello ends.
	if extEnd != len(raw) {
		return nil, ErrTrailingData
	}

	// Each extension is checked against extEnd, not len(raw): its length is
	// client-controlled and must not reach past the block it belongs to.
	extensions := []Extension{}
	for i := nextOffset + 2; i < extEnd; {
		if i+extHeaderLen > extEnd {
			return nil, ErrExtensionHeaderTruncated
		}
		extType := binary.BigEndian.Uint16(raw[i : i+2])
		extLength := int(binary.BigEndian.Uint16(raw[i+2 : i+extHeaderLen]))
		if i+extHeaderLen+extLength > extEnd {
			return nil, ErrExtensionDataTruncated
		}
		extData := raw[i+extHeaderLen : i+extHeaderLen+extLength]
		extensions = append(extensions, Extension{Type: extType, Data: extData})
		i += extHeaderLen + extLength
	}

	ch := &ClientHello{
		LegacyVersion:      binary.BigEndian.Uint16(legacyVersion),
		SessionIDLen:       int(sessionIdLen[0]),
		CipherSuites:       cipherSuites,
		CompressionMethods: compressionMethods,
		Extensions:         extensions,
	}
	ch.Malformed = ch.DecodeExtensions()

	return ch, nil
}

type ExtTypes uint16

const (
	ServerName          ExtTypes = 0x0000
	SupportedGroups     ExtTypes = 0x000a
	SignatureAlgorithms ExtTypes = 0x000d
	ALPN                ExtTypes = 0x0010
	SupportedVersions   ExtTypes = 0x002b
)

func (ch *ClientHello) DecodeExtensions() []error {
	var errors []error
	for _, ext := range ch.Extensions {
		switch ExtTypes(ext.Type) {
		case ServerName:
			if len(ext.Data) < sniHeaderLen {
				errors = append(errors, ErrServerNameTooShort)
				continue
			}
			listLen := binary.BigEndian.Uint16(ext.Data[0:2])
			if int(listLen) != len(ext.Data)-2 {
				errors = append(errors, ErrServerNameListLenMismatch)
				continue
			}
			nameType := ext.Data[2]
			if nameType != hostNameType {
				errors = append(errors, ErrServerNameNameTypeNotHostName)
				continue
			}
			nameLen := binary.BigEndian.Uint16(ext.Data[sniHeaderLen-2 : sniHeaderLen])
			if int(nameLen) != len(ext.Data)-sniHeaderLen {
				errors = append(errors, ErrServerNameNameLenMismatch)
				continue
			}
			ch.ServerName = string(ext.Data[sniHeaderLen : sniHeaderLen+int(nameLen)])
		case SupportedGroups:
			if len(ext.Data) < 4 {
				errors = append(errors, ErrSupportedGroupsTooShort)
				continue
			}
			listLen := binary.BigEndian.Uint16(ext.Data[0:2])
			if int(listLen) != len(ext.Data)-2 {
				errors = append(errors, ErrSupportedGroupsListLenMismatch)
				continue
			}
			if listLen%2 != 0 {
				errors = append(errors, ErrSupportedGroupsOddLength)
				continue
			}
			ch.SupportedGroups = []uint16{}
			for i := 2; i < len(ext.Data); i += 2 {
				group := binary.BigEndian.Uint16(ext.Data[i : i+2])
				ch.SupportedGroups = append(ch.SupportedGroups, group)
			}
		case SignatureAlgorithms:
			if len(ext.Data) < 4 {
				errors = append(errors, ErrSignatureAlgorithmsTooShort)
				continue
			}
			listLen := binary.BigEndian.Uint16(ext.Data[0:2])
			if int(listLen) != len(ext.Data)-2 {
				errors = append(errors, ErrSignatureAlgorithmsListLenMismatch)
				continue
			}
			if listLen%2 != 0 {
				errors = append(errors, ErrSignatureAlgorithmsOddLength)
				continue
			}
			ch.SignatureAlgorithms = []uint16{}
			for i := 2; i < len(ext.Data); i += 2 {
				algo := binary.BigEndian.Uint16(ext.Data[i : i+2])
				ch.SignatureAlgorithms = append(ch.SignatureAlgorithms, algo)
			}
		case ALPN:
			if len(ext.Data) < 2 {
				errors = append(errors, ErrALPNTooShort)
				continue
			}
			listLen := binary.BigEndian.Uint16(ext.Data[0:2])
			if int(listLen) != len(ext.Data)-2 {
				errors = append(errors, ErrALPNListLenMismatch)
				continue
			}
			if listLen == 0 {
				errors = append(errors, ErrALPNEmptyList)
				continue
			}
			// Collect into a local list and keep it only if every name is
			// valid, the same all-or-nothing rule as the other extensions.
			var protos []string
			var bad error
			for i := 2; i < len(ext.Data); {
				strLen := ext.Data[i]
				i++
				if strLen == 0 {
					bad = ErrALPNEmptyName
					break
				}
				if i+int(strLen) > len(ext.Data) {
					bad = ErrALPNNameLenMismatch
					break
				}
				protos = append(protos, string(ext.Data[i:i+int(strLen)]))
				i += int(strLen)
			}
			if bad != nil {
				errors = append(errors, bad)
				continue
			}
			ch.ALPN = protos
		case SupportedVersions:
			if len(ext.Data) < 2 {
				errors = append(errors, ErrSupportedVersionsTooShort)
				continue
			}
			listLen := ext.Data[0]
			if int(listLen) != len(ext.Data)-1 {
				errors = append(errors, ErrSupportedVersionsListLenMismatch)
				continue
			}
			if listLen%2 != 0 {
				errors = append(errors, ErrSupportedVersionsOddLength)
				continue
			}
			ch.SupportedVersions = []uint16{}
			for i := 1; i < len(ext.Data); i += 2 {
				version := binary.BigEndian.Uint16(ext.Data[i : i+2])
				ch.SupportedVersions = append(ch.SupportedVersions, version)
			}
		default:
			// No op
		}
	}

	return errors
}
