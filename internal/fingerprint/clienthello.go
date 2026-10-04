// Package fingerprint turns captured client bytes into fingerprints: the
// parsed ClientHello, JA4, the HTTP/2 (Akamai-style) fingerprint and header
// order.
package fingerprint

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

// Errors returned by ParseClientHello when the bytes are not a ClientHello it
// can read, plus ErrNotImplemented for the parsers that are still stubs.
var (
	// ErrNotImplemented is returned by parsers that are still stubs. It is
	// not returned by ParseClientHello.
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

// Errors for malformed extension contents. They are never returned as the
// error of ParseClientHello: DecodeExtensions collects them, and
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
	// bytes: the record and handshake headers, version and random, an empty
	// session ID (1), one cipher suite (2+2) and one compression method
	// (1+1). The extensions block is optional before TLS 1.3, so it is not
	// counted. ParseClientHello returns ErrTooShort for shorter input.
	ClientHelloMinLen = sessionIDLenOffset + 1 + 2 + 2 + 1 + 1

	// ClientHelloRecordType is the TLS record type for a handshake message.
	ClientHelloRecordType = 0x16

	// ClientHelloMessageType is the handshake message type for a ClientHello.
	ClientHelloMessageType = 0x01
)

// Extension is one ClientHello extension, as it appeared on the wire. Data is
// the extension body without its type and length header; it is left out of
// JSON.
type Extension struct {
	Type uint16 `json:"type"`
	Data []byte `json:"-"`
}

// ClientHello holds the fields fingerprinting needs, as returned by
// ParseClientHello. Slices keep wire order, including GREASE values;
// filtering happens where a fingerprint is built, not here.
type ClientHello struct {
	LegacyVersion      uint16      `json:"legacy_version"`
	SessionIDLen       int         `json:"session_id_len"`
	CipherSuites       []uint16    `json:"cipher_suites"`
	CompressionMethods []byte      `json:"compression_methods"`
	Extensions         []Extension `json:"extensions"`

	// Decoded from their extensions by DecodeExtensions. A field stays empty
	// when its extension is absent or malformed.
	ServerName          string   `json:"server_name,omitempty"`          // 0x0000
	SupportedGroups     []uint16 `json:"supported_groups,omitempty"`     // 0x000a
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"` // 0x000d
	ALPN                []string `json:"alpn,omitempty"`                 // 0x0010
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`   // 0x002b

	// Malformed holds one error per known extension whose contents broke
	// their layout, in wire order. Well-behaved clients do not send these,
	// so they are recorded as a signal rather than failing the parse.
	Malformed ErrorList `json:"malformed,omitempty"`
}

// ErrorList is a list of errors that stay errors in memory, so callers can
// match them with errors.Is, and are written as their messages in JSON.
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
// at the start of a TLS connection (capture.Conn.RawClientBytes). raw must
// start with the TLS record that carries the ClientHello; bytes after the
// ClientHello, such as later records, are ignored.
//
// It returns the fixed fields, the extensions as they appeared on the wire,
// and the decoded fields filled in by DecodeExtensions. Every list keeps wire
// order, GREASE values included. The returned ClientHello shares memory with
// raw.
//
// A structural problem (wrong record or message type, a length that runs
// past the data, an empty cipher_suites or compression_methods list, bytes
// after the extensions block) returns an error and no ClientHello. A
// malformed extension inside an otherwise readable hello does not fail the
// parse; it is recorded in ClientHello.Malformed. Truncated or hostile input
// returns an error and never panics.
//
// A ClientHello that spans several records is not supported yet and returns
// ErrFragmentedClientHello. The extensions block is optional (it may be
// absent before TLS 1.3); without it, Extensions is empty and no extension
// fields are decoded.
//
// Wire layout (RFC 9846 §5.1 record layer, §4 handshake header, §4.2.2
// ClientHello, §4.3 extensions; RFC 6066 §3 SNI; RFC 7301 §3.1 ALPN):
//
//	record:    type(1)=0x16  legacy_record_version(2)  length(2)  fragment
//	handshake: msg_type(1)=0x01  length(3)  body
//	body:      legacy_version(2) random(32)
//	           session_id<0..32>        (1-byte length prefix)
//	           cipher_suites<2..2^16-2> (2-byte length prefix)
//	           compression<1..2^8-1>    (1-byte length prefix)
//	           extensions<8..2^16-1>    (2-byte length prefix, optional)
//	extension: type(2) data<0..2^16-1>
//
// Only the session ID length is kept: modern clients send 32 random bytes
// there (TLS 1.3 middlebox compatibility mode), which carry no signal.
func ParseClientHello(raw []byte) (*ClientHello, error) {
	if len(raw) < ClientHelloMinLen {
		return nil, ErrTooShort
	}

	// outer layer
	recordType := raw[0]
	if recordType != ClientHelloRecordType {
		return nil, ErrNotHandshake
	}
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
	// Cut off the records after the ClientHello and cap the capacity.
	raw = raw[:helloEnd:helloEnd]

	// ClientHello body
	legacyVersion := raw[helloBodyOffset : helloBodyOffset+legacyVersionLen]
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
	if extEnd != len(raw) {
		return nil, ErrTrailingData
	}

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

// ExtTypes is a TLS extension type, as registered with IANA. Only the
// types DecodeExtensions decodes have constants.
type ExtTypes uint16

// Extension types decoded into ClientHello fields.
const (
	ServerName          ExtTypes = 0x0000 // server_name (RFC 6066 §3)
	SupportedGroups     ExtTypes = 0x000a // supported_groups (RFC 9846)
	SignatureAlgorithms ExtTypes = 0x000d // signature_algorithms (RFC 9846)
	ALPN                ExtTypes = 0x0010 // application_layer_protocol_negotiation (RFC 7301 §3.1)
	SupportedVersions   ExtTypes = 0x002b // supported_versions (RFC 9846)
)

// DecodeExtensions decodes the known extensions in ch.Extensions into
// ServerName, SupportedGroups, SignatureAlgorithms, ALPN and
// SupportedVersions. Unknown extension types are ignored.
//
// Decoding is all-or-nothing per extension: a malformed extension leaves its
// field untouched and adds one error to the returned list instead of failing.
// It returns nil when every known extension decoded. If an extension type
// appears more than once, the last well-formed one wins.
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
