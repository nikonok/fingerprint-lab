package fingerprint

import (
	"os"
	"slices"
	"testing"
)

// TestParseClientHelloOpenSSLMin checks ParseClientHello against a minimal
// OpenSSL TLS 1.3 ClientHello (191 bytes: one record, SNI fp.test, no ALPN).
// The expected values come from a hand decode, cross-checked against
// tshark 3.6.2 on the same bytes.
func TestParseClientHelloOpenSSLMin(t *testing.T) {
	raw, err := os.ReadFile("../../captures/openssl-min.bin")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	if ch.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#04x, want 0x0303", ch.LegacyVersion)
	}
	if ch.SessionIDLen != 32 {
		t.Errorf("SessionIDLen = %d, want 32", ch.SessionIDLen)
	}
	if want := []uint16{0x1301, 0x00ff}; !slices.Equal(ch.CipherSuites, want) {
		t.Errorf("CipherSuites = %#04x, want %#04x", ch.CipherSuites, want)
	}
	if want := []byte{0x00}; !slices.Equal(ch.CompressionMethods, want) {
		t.Errorf("CompressionMethods = %#02x, want %#02x", ch.CompressionMethods, want)
	}

	// Wire order, with the data length of each extension.
	wantExt := []struct {
		typ    uint16
		length int
	}{
		{0x0000, 12}, // server_name
		{0x000b, 4},  // ec_point_formats
		{0x000a, 4},  // supported_groups
		{0x0016, 0},  // encrypt_then_mac
		{0x0017, 0},  // extended_master_secret
		{0x000d, 6},  // signature_algorithms
		{0x002b, 3},  // supported_versions
		{0x002d, 2},  // psk_key_exchange_modes
		{0x0033, 38}, // key_share
	}
	if len(ch.Extensions) != len(wantExt) {
		t.Fatalf("got %d extensions, want %d", len(ch.Extensions), len(wantExt))
	}
	for i, w := range wantExt {
		got := ch.Extensions[i]
		if got.Type != w.typ || len(got.Data) != w.length {
			t.Errorf("Extensions[%d] = {type %#04x, len %d}, want {type %#04x, len %d}",
				i, got.Type, len(got.Data), w.typ, w.length)
		}
	}

	if ch.ServerName != "fp.test" {
		t.Errorf("ServerName = %q, want %q", ch.ServerName, "fp.test")
	}
	if want := []uint16{0x001d}; !slices.Equal(ch.SupportedGroups, want) {
		t.Errorf("SupportedGroups = %#04x, want %#04x", ch.SupportedGroups, want)
	}
	if want := []uint16{0x0403, 0x0804}; !slices.Equal(ch.SignatureAlgorithms, want) {
		t.Errorf("SignatureAlgorithms = %#04x, want %#04x", ch.SignatureAlgorithms, want)
	}
	if len(ch.ALPN) != 0 {
		t.Errorf("ALPN = %q, want none", ch.ALPN)
	}
	if want := []uint16{0x0304}; !slices.Equal(ch.SupportedVersions, want) {
		t.Errorf("SupportedVersions = %#04x, want %#04x", ch.SupportedVersions, want)
	}
}
