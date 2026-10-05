package fingerprint

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var ErrNilClientHello = errors.New("nil ClientHello")

// JA4 computes the JA4 TLS client fingerprint, e.g.
// t13d1516h2_8daaf6152771_e5627efa2ab1.
//
// In: a parsed ClientHello; quic selects the transport character ('t' for
// TCP, 'q' for QUIC). Out: JA4 in its hashed form, a_b_c. Section a stays
// human-readable; b and c are truncated SHA-256 (12 hex chars) over their
// respective lists. JA4Raw is the same fingerprint with the lists in clear
// text; both share the section builders and differ only in hashing.
//
// Source of truth: FoxIO-LLC/ja4, technical_details/JA4.md. python/ja4.py
// and rust/ja4/src/tls.rs are the reference implementations, and their pcaps
// and expected outputs make ready-made test vectors. Wireshark 4.2+ computes
// JA4 itself (field tls.handshake.ja4); compare against it on the same
// capture.
//
// Structure:
//   - a: transport, TLS version, SNI marker (d/i), cipher count, extension
//     count, ALPN marker.
//   - b: truncated SHA-256 over the sorted cipher list.
//   - c: truncated SHA-256 over the sorted extension list, followed by the
//     signature algorithms in wire order.
//
// Traps (check each one against JA4.md, not memory):
//   - GREASE (RFC 8701): values of the form 0x?a?a with equal bytes. They
//     must be excluded from counts, lists and the version choice.
//   - The version comes from the highest supported_versions entry when that
//     extension is present, not from legacy_version.
//   - The extension count in `a` includes SNI and ALPN, but the list hashed
//     in `c` excludes them.
//   - Counts are two digits and capped at 99.
//   - ALPN marker: first and last character of the first ALPN value, with a
//     special rule for non-alphanumeric values; "00" when ALPN is absent.
//   - Empty lists hash to "000000000000", not to the SHA-256 of "".
//   - Sorting is what makes JA4 stable under Chrome's extension-order
//     shuffling. A test that captures the same browser twice must produce
//     the same JA4.
func JA4(ch *ClientHello, quic bool) (string, error) {
	if ch == nil {
		return "", ErrNilClientHello
	}
	a := buildJA4a(ch, quic)
	b := ja4Hash(buildJA4b(ch))
	c := ja4Hash(buildJA4c(ch))
	return a + "_" + b + "_" + c, nil
}

// ja4Hash returns the truncated SHA-256 (first 12 lowercase hex chars) of s,
// or "000000000000" for an empty list (JA4.md: empty lists must not hash to
// the SHA-256 of the empty string).
func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}

// JA4Raw returns the unhashed form (JA4_r) with the sorted lists in clear
// text, e.g. t13d020900_00ff,1301_000a,000b,000d,0016,0017,002b,002d,0033_0403,0804.
// It is used for diffing two clients field by field. Every rule matches JA4
// (see its doc comment); only the final hashing step differs.
func JA4Raw(ch *ClientHello, quic bool) (string, error) {
	if ch == nil {
		return "", ErrNilClientHello
	}
	return buildJA4a(ch, quic) + "_" + buildJA4b(ch) + "_" + buildJA4c(ch), nil
}

func buildJA4a(ch *ClientHello, quic bool) string {
	var result strings.Builder
	if quic {
		result.WriteString("q")
	} else {
		result.WriteString("t")
	}

	version := "00"
	if hasExtension(ch.Extensions, extSupportedVersions) {
		version = convertTlsVersionToJA4(maxNonGrease(ch.SupportedVersions))
	} else if ch.LegacyVersion != 0 {
		version = convertTlsVersionToJA4(ch.LegacyVersion)
	}
	result.WriteString(version)

	if hasExtension(ch.Extensions, extServerName) {
		result.WriteString("d")
	} else {
		result.WriteString("i")
	}

	cipherCount := countWithoutGrease(ch.CipherSuites)
	extensionCount := countExtensionsWithoutGrease(ch.Extensions)
	fmt.Fprintf(&result, "%02d%02d", min(cipherCount, 99), min(extensionCount, 99))

	if len(ch.ALPN) > 0 {
		first, last := alpnMarkers(ch.ALPN[0])
		result.WriteByte(first)
		result.WriteByte(last)
	} else {
		result.WriteString("00")
	}

	return result.String()
}

func buildJA4b(ch *ClientHello) string {
	var result strings.Builder
	ciphers := make([]uint16, 0, len(ch.CipherSuites))
	for _, cipher := range ch.CipherSuites {
		if !isGreaseValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	slices.Sort(ciphers)
	joinHex(&result, ciphers)

	return result.String()
}

// joinHex writes values as comma-separated 4-digit lowercase hex.
func joinHex(result *strings.Builder, values []uint16) {
	for i, v := range values {
		if i > 0 {
			result.WriteByte(',')
		}
		fmt.Fprintf(result, "%04x", v)
	}
}

func buildJA4c(ch *ClientHello) string {
	var result strings.Builder
	extensions := make([]uint16, 0, len(ch.Extensions))
	for _, ext := range ch.Extensions {
		if !isGreaseValue(ext.Type) && ext.Type != extServerName && ext.Type != extALPN {
			extensions = append(extensions, ext.Type)
		}
	}
	slices.Sort(extensions)
	joinHex(&result, extensions)

	signatureAlgorithms := make([]uint16, 0, len(ch.SignatureAlgorithms))
	for _, algorithm := range ch.SignatureAlgorithms {
		if !isGreaseValue(algorithm) {
			signatureAlgorithms = append(signatureAlgorithms, algorithm)
		}
	}
	if len(signatureAlgorithms) > 0 {
		result.WriteByte('_')
		joinHex(&result, signatureAlgorithms)
	}

	return result.String()
}

func convertTlsVersionToJA4(version uint16) string {
	switch version {
	case 0x0304:
		return "13" // TLS 1.3
	case 0x0303:
		return "12" // TLS 1.2
	case 0x0302:
		return "11" // TLS 1.1
	case 0x0301:
		return "10" // TLS 1.0
	case 0x0300:
		return "s3" // SSL 3.0
	case 0x0002:
		return "s2" // SSL 2.0
	case 0xfeff:
		return "d1" // DTLS 1.0
	case 0xfefd:
		return "d2" // DTLS 1.2
	case 0xfefc:
		return "d3" // DTLS 1.3
	default:
		return "00" // Unknown
	}
}

func countWithoutGrease(values []uint16) int {
	count := 0
	for _, v := range values {
		if !isGreaseValue(v) {
			count++
		}
	}
	return count
}

func countExtensionsWithoutGrease(extensions []Extension) int {
	count := 0
	for _, ext := range extensions {
		if !isGreaseValue(ext.Type) {
			count++
		}
	}
	return count
}

func hasExtension(extensions []Extension, extensionType uint16) bool {
	for _, ext := range extensions {
		if ext.Type == extensionType {
			return true
		}
	}
	return false
}

// maxNonGrease returns the highest non-GREASE value, or 0 if there is none.
func maxNonGrease(values []uint16) uint16 {
	var max uint16
	for _, v := range values {
		if !isGreaseValue(v) && v > max {
			max = v
		}
	}
	return max
}

// alpnMarkers returns the JA4 ALPN characters for one protocol name: the
// first and last ASCII-alphanumeric bytes. When either endpoint byte is not
// alphanumeric, JA4.md hexes the endpoint bytes and takes the outer
// characters; hexing the whole value gives the same result because middle
// bytes never affect the endpoints of the hex string (e.g. 0xAB → "ab").
func alpnMarkers(alpn string) (byte, byte) {
	if len(alpn) == 0 {
		return '0', '0'
	}
	first, last := alpn[0], alpn[len(alpn)-1]
	if isAlphaNum(first) && isAlphaNum(last) {
		return first, last
	}
	h := fmt.Sprintf("%x", alpn)
	return h[0], h[len(h)-1]
}

func isAlphaNum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func isGreaseValue(value uint16) bool {
	return (value&0x0f0f) == 0x0a0a && value>>8 == value&0xff
}
