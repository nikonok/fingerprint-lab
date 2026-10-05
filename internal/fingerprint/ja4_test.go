package fingerprint

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestJA4RawOpenSSLMin checks JA4Raw against the minimal OpenSSL TLS 1.3
// ClientHello (testdata/openssl-min.bin, TCP transport). The expected value
// was derived by hand from the FoxIO JA4 spec on 2026-10-05 and passed the
// predict-before-run gate (see the JA4Raw worksheet), then cross-checked
// against Wireshark 4.6.6.
func TestJA4RawOpenSSLMin(t *testing.T) {
	raw, err := os.ReadFile("testdata/openssl-min.bin")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	got, err := JA4Raw(ch, false)
	if err != nil {
		t.Fatalf("JA4Raw: %v", err)
	}

	const want = "t13d020900_00ff,1301_000a,000b,000d,0016,0017,002b,002d,0033_0403,0804"
	if got != want {
		t.Errorf("JA4Raw = %q, want %q", got, want)
	}
}

// TestJA4RawBuiltHellos pins JA4Raw on synthetic hellos covering the rules
// the fixture cannot exercise. Every expected string was derived by hand
// from the FoxIO JA4 spec before running the code (predict-before-run gate).
func TestJA4RawBuiltHellos(t *testing.T) {
	tests := []struct {
		name string
		raw  func(t *testing.T) []byte
		want string
	}{
		// GREASE cipher 0x0a0a, GREASE extensions 0x1a1a and 0x4a4a, and GREASE
		// 0x3a3a inside supported_versions: all must vanish from counts, lists
		// and the version choice.
		{"grease everywhere", func(t *testing.T) []byte {
			return hello{
				sidLen:  32,
				ciphers: []uint16{0x0a0a, 0x1301, 0x1302},
				comp:    []byte{0},
				tail: extBlock(
					ext{0x1a1a, nil},
					ext{extSupportedGroups, []byte{0x00, 0x06, 0x2a, 0x2a, 0x00, 0x1d, 0x00, 0x17}},
					ext{extSupportedVersions, []byte{0x04, 0x3a, 0x3a, 0x03, 0x04}},
					ext{0x4a4a, []byte{0x00}},
				),
			}.build(t)
		}, "t13i020200_1301,1302_000a,002b"},

		// No supported_versions extension: the version digits must come from
		// legacy_version (0x0303 -> "12"), never from the record version
		// (0x0301 -> "10").
		{"version from legacy_version", func(t *testing.T) []byte {
			return withExt(t, ext{extSupportedGroups, []byte{0x00, 0x02, 0x00, 0x1d}})
		}, "t12i010100_1301_000a"},

		// No extensions at all: extension count 00, empty JA4_c, no sigalg
		// suffix. The section separator stays: a + "_" + b + "_" + "".
		{"no extensions", func(t *testing.T) []byte {
			return hello{sidLen: 0, ciphers: []uint16{0xc02f, 0x009c}, comp: []byte{0x01, 0x00}}.build(t)
		}, "t12i020000_009c,c02f_"},

		// SNI and ALPN count in a but are omitted from c. Extensions sort by
		// type, while signature algorithms retain their wire order.
		{"sni alpn and signature order", func(t *testing.T) []byte {
			return withExt(t,
				ext{0x0033, nil},
				ext{extALPN, []byte{0x00, 0x03, 0x02, 'h', '2'}},
				ext{extServerName, []byte{0x00, 0x04, 0x00, 0x00, 0x01, 'x'}},
				ext{extSignatureAlgorithms, []byte{0x00, 0x04, 0x08, 0x04, 0x04, 0x03}},
				ext{extSupportedGroups, []byte{0x00, 0x02, 0x00, 0x1d}},
				ext{extSupportedVersions, []byte{0x02, 0x03, 0x04}},
			)
		}, "t13d0106h2_1301_000a,000d,002b,0033_0804,0403"},

		// JA4 uses the outer characters of the hexadecimal ALPN bytes when
		// either endpoint is not ASCII alphanumeric: abcd becomes "ad".
		{"non-alphanumeric alpn", func(t *testing.T) []byte {
			return withExt(t, ext{extALPN, []byte{0x00, 0x03, 0x02, 0xab, 0xcd}})
		}, "t12i0101ad_1301_"},

		// GREASE is ignored everywhere, including the signature-algorithm
		// suffix, while the remaining algorithms preserve wire order.
		{"grease signature algorithm", func(t *testing.T) []byte {
			return withExt(t, ext{extSignatureAlgorithms, []byte{
				0x00, 0x06, 0x0a, 0x0a, 0x08, 0x04, 0x04, 0x03,
			}})
		}, "t12i010100_1301_000d_0804,0403"},

		// The SNI marker follows extension presence, even when its body is
		// malformed and therefore produces no decoded ServerName.
		{"malformed sni still marks domain", func(t *testing.T) []byte {
			return withExt(t, ext{extServerName, nil})
		}, "t12d010100_1301_"},

		// Presence of supported_versions suppresses legacy_version fallback.
		// If every advertised version is GREASE, the JA4 version is unknown.
		{"supported versions only grease", func(t *testing.T) []byte {
			return withExt(t, ext{extSupportedVersions, []byte{0x02, 0x0a, 0x0a}})
		}, "t00i010100_1301_002b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(tt.raw(t))
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			got, err := JA4Raw(ch, false)
			if err != nil {
				t.Fatalf("JA4Raw: %v", err)
			}
			if got != tt.want {
				t.Errorf("JA4Raw = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestJA4RawQUIC checks the transport character: same fixture, QUIC selected.
func TestJA4RawQUIC(t *testing.T) {
	ch, err := ParseClientHello(loadFixture(t))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	got, err := JA4Raw(ch, true)
	if err != nil {
		t.Fatalf("JA4Raw: %v", err)
	}
	const want = "q13d020900_00ff,1301_000a,000b,000d,0016,0017,002b,002d,0033_0403,0804"
	if got != want {
		t.Errorf("JA4Raw = %q, want %q", got, want)
	}
}

// TestJA4OpenSSLMin checks the hashed form on the fixture. Expected value:
// JA4_a identical to the raw form; b and c are the first 12 hex chars of
// sha256 of the raw list strings, computed with sha256sum:
//
//	echo -n '00ff,1301' | sha256sum                                    -> ec078ce24869...
//	echo -n '000a,000b,000d,0016,0017,002b,002d,0033_0403,0804' | sha256sum -> da91e0c78654...
func TestJA4OpenSSLMin(t *testing.T) {
	ch, err := ParseClientHello(loadFixture(t))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	got, err := JA4(ch, false)
	if err != nil {
		t.Fatalf("JA4: %v", err)
	}
	const want = "t13d020900_ec078ce24869_da91e0c78654"
	if got != want {
		t.Errorf("JA4 = %q, want %q", got, want)
	}
}

// TestJA4NoExtensions checks the empty-list rule: with no extensions and no
// signature algorithms, JA4_c is the literal "000000000000", not the SHA-256
// of the empty string. b hashes the sorted cipher list:
//
//	echo -n '009c,c02f' | sha256sum -> 08dfa304a768...
func TestJA4NoExtensions(t *testing.T) {
	raw := hello{sidLen: 0, ciphers: []uint16{0xc02f, 0x009c}, comp: []byte{0x01, 0x00}}.build(t)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	got, err := JA4(ch, false)
	if err != nil {
		t.Fatalf("JA4: %v", err)
	}
	const want = "t12i020000_08dfa304a768_000000000000"
	if got != want {
		t.Errorf("JA4 = %q, want %q", got, want)
	}
}

func TestJA4NilClientHello(t *testing.T) {
	if _, err := JA4(nil, false); !errors.Is(err, ErrNilClientHello) {
		t.Errorf("JA4(nil) error = %v, want %v", err, ErrNilClientHello)
	}
	if _, err := JA4Raw(nil, false); !errors.Is(err, ErrNilClientHello) {
		t.Errorf("JA4Raw(nil) error = %v, want %v", err, ErrNilClientHello)
	}
}

func TestJA4CountCap(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303}
	for i := range 100 {
		ch.CipherSuites = append(ch.CipherSuites, uint16(i+1))
		ch.Extensions = append(ch.Extensions, Extension{Type: uint16(0x1000 + i)})
	}

	raw, err := JA4Raw(ch, false)
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.SplitN(raw, "_", 2)[0]; a != "t12i999900" {
		t.Errorf("JA4_a = %q, want %q", a, "t12i999900")
	}
}

func TestALPNMarkers(t *testing.T) {
	tests := []struct {
		name string
		alpn string
		want string
	}{
		{"empty", "", "00"},
		{"one alphanumeric", "h", "hh"},
		{"alphanumeric endpoints", "http/1.1", "h1"},
		{"ab", "\xab", "ab"},
		{"20", "\x20", "20"},
		{"abcd", "\xab\xcd", "ad"},
		{"space a", "\x20\x61", "21"},
		{"zero ab", "\x30\xab", "3b"},
		{"a space", "\x61\x20", "60"},
		{"zero one abcd", "\x30\x31\xab\xcd", "3d"},
		{"zero abcd one", "\x30\xab\xcd\x31", "01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, last := alpnMarkers(tt.alpn)
			if got := string([]byte{first, last}); got != tt.want {
				t.Errorf("alpnMarkers(%x) = %q, want %q", tt.alpn, got, tt.want)
			}
		})
	}
}
