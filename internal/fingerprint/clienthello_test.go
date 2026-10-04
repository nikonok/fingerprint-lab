package fingerprint

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
)

// TestParseClientHelloOpenSSLMin checks ParseClientHello against a minimal
// OpenSSL TLS 1.3 ClientHello (191 bytes: one record, SNI fp.test, no ALPN).
// The expected values come from a hand decode, cross-checked against
// tshark 3.6.2 on the same bytes.
func TestParseClientHelloOpenSSLMin(t *testing.T) {
	raw, err := os.ReadFile("testdata/openssl-min.bin")
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
	if ch.LegacyRecordVersion != 0x0301 {
		t.Errorf("LegacyRecordVersion = %#04x, want 0x0301", ch.LegacyRecordVersion)
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

const fixturePath = "testdata/openssl-min.bin"

// loadFixture returns a fresh copy of the fixture with cap == len.
func loadFixture(tb testing.TB) []byte {
	tb.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		tb.Fatal(err)
	}
	return slices.Clip(slices.Clone(raw))
}

// mutate returns a copy of the fixture with the given offsets overwritten.
func mutate(t *testing.T, edits map[int][]byte) []byte {
	t.Helper()
	b := loadFixture(t)
	for off, v := range edits {
		copy(b[off:], v)
	}
	return b
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

// wrap puts a ClientHello body behind a handshake header and a record header.
func wrap(t *testing.T, body []byte) []byte {
	t.Helper()
	hs := []byte{ClientHelloMessageType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	b := []byte{ClientHelloRecordType, 0x03, 0x01}
	b = binary.BigEndian.AppendUint16(b, uint16(len(hs)))
	b = append(b, hs...)
	return b[:len(b):len(b)]
}

// prefix returns legacy_version, random and a session ID of sidLen bytes.
func prefix(sidLen int) []byte {
	b := []byte{0x03, 0x03}
	b = append(b, make([]byte, 32)...)
	b = append(b, byte(sidLen))
	return append(b, make([]byte, sidLen)...)
}

type ext struct {
	typ  uint16
	data []byte
}

// extBlock encodes extensions as a length-prefixed extensions block.
func extBlock(exts ...ext) []byte {
	var body []byte
	for _, e := range exts {
		body = binary.BigEndian.AppendUint16(body, e.typ)
		body = binary.BigEndian.AppendUint16(body, uint16(len(e.data)))
		body = append(body, e.data...)
	}
	return append(u16(uint16(len(body))), body...)
}

// hello builds a full record from fields; tail is appended after the
// compression methods as-is (nil means no extensions block).
type hello struct {
	sidLen  int
	ciphers []uint16
	comp    []byte
	tail    []byte
}

func (h hello) build(t *testing.T) []byte {
	t.Helper()
	body := prefix(h.sidLen)
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(h.ciphers)))
	for _, c := range h.ciphers {
		body = binary.BigEndian.AppendUint16(body, c)
	}
	body = append(body, byte(len(h.comp)))
	body = append(body, h.comp...)
	body = append(body, h.tail...)
	return wrap(t, body)
}

// withExt builds a valid hello carrying the given extensions.
func withExt(t *testing.T, exts ...ext) []byte {
	t.Helper()
	return hello{sidLen: 32, ciphers: []uint16{0x1301}, comp: []byte{0}, tail: extBlock(exts...)}.build(t)
}

func TestParseClientHelloErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  func(t *testing.T) []byte
		want error
	}{
		{"one byte below minimum", func(t *testing.T) []byte {
			fx := loadFixture(t)
			return fx[: ClientHelloMinLen-1 : ClientHelloMinLen-1]
		}, ErrTooShort},
		{"empty input", func(t *testing.T) []byte { return []byte{} }, ErrTooShort},
		{"application data record", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x00: {0x17}}) }, ErrNotHandshake},
		{"record length one past capture", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x03: u16(0x00bb)}) }, ErrRecordTruncated},
		{"server hello message type", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x05: {0x02}}) }, ErrNotClientHello},
		{"handshake longer than record", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x06: {0x00, 0x00, 0xb7}}) }, ErrFragmentedClientHello},
		{"handshake length 32", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x06: {0x00, 0x00, 0x20}}) }, ErrHandshakeTooShort},
		{"record length 2", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x03: u16(2)}) }, ErrRecordTooShort},
		{"session id length 33", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x2b: {33}}) }, ErrSessionIDTooLong},
		{"session id length 255", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x2b: {0xff}}) }, ErrSessionIDTooLong},
		{"body ends after session id", func(t *testing.T) []byte { return wrap(t, prefix(32)) }, ErrCipherSuitesLengthMissing},
		{"one byte of cipher length", func(t *testing.T) []byte { return wrap(t, append(prefix(32), 0x00)) }, ErrCipherSuitesLengthMissing},
		{"cipher length 0xffff", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x4c: u16(0xffff)}) }, ErrCipherSuitesTruncated},
		{"cipher length 0", func(t *testing.T) []byte {
			return hello{sidLen: 32, comp: []byte{0}}.build(t)
		}, ErrNoCipherSuites},
		{"cipher length 3", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x4c: u16(3)}) }, ErrCipherSuitesOddLength},
		{"body ends after ciphers", func(t *testing.T) []byte {
			return wrap(t, append(prefix(32), 0x00, 0x02, 0x13, 0x01))
		}, ErrCompressionMethodsLengthMissing},
		{"compression length 0xff", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x52: {0xff}}) }, ErrCompressionMethodsTruncated},
		{"compression length 0", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x52: {0x00}}) }, ErrNoCompressionMethods},
		{"one byte after compression", func(t *testing.T) []byte {
			return hello{sidLen: 32, ciphers: []uint16{0x1301}, comp: []byte{0}, tail: []byte{0x00}}.build(t)
		}, ErrExtensionsLengthMissing},
		{"extensions length one past hello", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x54: u16(0x006a)}) }, ErrExtensionsTruncated},
		{"extensions length one short", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x54: u16(0x0068)}) }, ErrTrailingData},
		{"three-byte extension header", func(t *testing.T) []byte {
			return hello{sidLen: 32, ciphers: []uint16{0x1301}, comp: []byte{0}, tail: []byte{0x00, 0x03, 0x00, 0x00, 0x00}}.build(t)
		}, ErrExtensionHeaderTruncated},
		{"extension data past block", func(t *testing.T) []byte {
			return hello{sidLen: 32, ciphers: []uint16{0x1301}, comp: []byte{0}, tail: []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x05}}.build(t)
		}, ErrExtensionDataTruncated},
		{"last fixture extension one byte long", func(t *testing.T) []byte { return mutate(t, map[int][]byte{0x97: u16(0x0027)}) }, ErrExtensionDataTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(tt.raw(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if ch != nil {
				t.Errorf("ch = %+v, want nil on error", ch)
			}
		})
	}
}

func TestParseClientHelloMalformedExtensions(t *testing.T) {
	const (
		sni  = 0x0000
		grp  = 0x000a
		sig  = 0x000d
		alpn = 0x0010
		ver  = 0x002b
	)
	tests := []struct {
		name string
		ext  ext
		want error
	}{
		{"sni shorter than header", ext{sni, []byte{0x00, 0x02, 0x00, 0x00}}, ErrServerNameTooShort},
		{"sni empty", ext{sni, nil}, ErrServerNameTooShort},
		{"sni list length off by one", ext{sni, []byte{0x00, 0x05, 0x00, 0x00, 0x01, 'a'}}, ErrServerNameListLenMismatch},
		{"sni name type 1", ext{sni, []byte{0x00, 0x04, 0x01, 0x00, 0x01, 'a'}}, ErrServerNameNameTypeNotHostName},
		{"sni name length past data", ext{sni, []byte{0x00, 0x04, 0x00, 0x00, 0x02, 'a'}}, ErrServerNameNameLenMismatch},
		{"sni name length short of data", ext{sni, []byte{0x00, 0x05, 0x00, 0x00, 0x01, 'a', 'b'}}, ErrServerNameNameLenMismatch},
		{"groups two bytes", ext{grp, []byte{0x00, 0x02}}, ErrSupportedGroupsTooShort},
		{"groups list length mismatch", ext{grp, []byte{0x00, 0x04, 0x00, 0x1d}}, ErrSupportedGroupsListLenMismatch},
		{"groups odd list", ext{grp, []byte{0x00, 0x03, 0x00, 0x1d, 0x00}}, ErrSupportedGroupsOddLength},
		{"sigalgs two bytes", ext{sig, []byte{0x00, 0x02}}, ErrSignatureAlgorithmsTooShort},
		{"sigalgs list length mismatch", ext{sig, []byte{0x00, 0x04, 0x04, 0x03}}, ErrSignatureAlgorithmsListLenMismatch},
		{"sigalgs odd list", ext{sig, []byte{0x00, 0x03, 0x04, 0x03, 0x08}}, ErrSignatureAlgorithmsOddLength},
		{"alpn one byte", ext{alpn, []byte{0x00}}, ErrALPNTooShort},
		{"alpn list length mismatch", ext{alpn, []byte{0x00, 0x05, 0x02, 'h', '2'}}, ErrALPNListLenMismatch},
		{"alpn empty list", ext{alpn, []byte{0x00, 0x00}}, ErrALPNEmptyList},
		{"alpn empty name", ext{alpn, []byte{0x00, 0x01, 0x00}}, ErrALPNEmptyName},
		{"alpn empty name after valid one", ext{alpn, []byte{0x00, 0x04, 0x02, 'h', '2', 0x00}}, ErrALPNEmptyName},
		{"alpn name length past list", ext{alpn, []byte{0x00, 0x02, 0x05, 'h'}}, ErrALPNNameLenMismatch},
		{"versions one byte", ext{ver, []byte{0x02}}, ErrSupportedVersionsTooShort},
		{"versions list length mismatch", ext{ver, []byte{0x04, 0x03, 0x04}}, ErrSupportedVersionsListLenMismatch},
		{"versions odd list", ext{ver, []byte{0x03, 0x03, 0x04, 0x00}}, ErrSupportedVersionsOddLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(withExt(t, tt.ext))
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			if len(ch.Malformed) != 1 || !errors.Is(ch.Malformed[0], tt.want) {
				t.Fatalf("Malformed = %v, want [%v]", ch.Malformed, tt.want)
			}
			if len(ch.Extensions) != 1 || ch.Extensions[0].Type != tt.ext.typ {
				t.Errorf("Extensions = %+v, want one of type %#04x", ch.Extensions, tt.ext.typ)
			}
			if ch.ServerName != "" || ch.SupportedGroups != nil || ch.SignatureAlgorithms != nil ||
				ch.ALPN != nil || ch.SupportedVersions != nil {
				t.Errorf("decoded field set from a malformed extension: %+v", ch)
			}
		})
	}
}

func TestParseClientHelloTrailingRecords(t *testing.T) {
	fx := loadFixture(t)
	want, err := ParseClientHello(fx)
	if err != nil {
		t.Fatal(err)
	}
	tails := map[string][]byte{
		"change cipher spec":   {0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
		"partial next record":  {0x17, 0x03},
		"two trailing records": {0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x01, 0xaa},
	}
	for name, tail := range tails {
		t.Run(name, func(t *testing.T) {
			raw := slices.Concat(fx, tail)
			got, err := ParseClientHello(raw[:len(raw):len(raw)])
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	raw := hello{sidLen: 0, ciphers: []uint16{0xc02f, 0x009c}, comp: []byte{0x01, 0x00}}.build(t)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.SessionIDLen != 0 {
		t.Errorf("SessionIDLen = %d, want 0", ch.SessionIDLen)
	}
	if want := []uint16{0xc02f, 0x009c}; !slices.Equal(ch.CipherSuites, want) {
		t.Errorf("CipherSuites = %#04x, want %#04x", ch.CipherSuites, want)
	}
	if want := []byte{0x01, 0x00}; !slices.Equal(ch.CompressionMethods, want) {
		t.Errorf("CompressionMethods = %#02x, want %#02x", ch.CompressionMethods, want)
	}
	if ch.Extensions == nil || len(ch.Extensions) != 0 {
		t.Errorf("Extensions = %#v, want empty non-nil", ch.Extensions)
	}
	if ch.LegacyRecordVersion != 0x0301 {
		t.Errorf("LegacyRecordVersion = %#04x, want 0x0301", ch.LegacyRecordVersion)
	}
	if ch.Malformed != nil {
		t.Errorf("Malformed = %v, want nil", ch.Malformed)
	}
}

func TestParseClientHelloExtensionList(t *testing.T) {
	ver := ext{0x002b, []byte{0x02, 0x03, 0x04}}
	badVer := ext{0x002b, []byte{0x01, 0x03}}
	keyShare := ext{0x0033, []byte{0x00, 0x00}}
	ids := []byte{0x00, 0x0b, 0x00, 0x05, 'a', 'b', 'c', 'd', 'e', 0x00, 0x00, 0x00, 0x00}
	binders := append([]byte{0x00, 0x21, 0x20}, make([]byte, 32)...)
	psk := ext{0x0029, append(slices.Clone(ids), binders...)}

	tests := []struct {
		name string
		exts []ext
		want []error
	}{
		{"duplicate supported_versions", []ext{ver, ver}, []error{ErrExtensionDuplicate}},
		{"duplicate, first malformed", []ext{badVer, ver}, []error{ErrExtensionDuplicate, ErrSupportedVersionsOddLength}},
		{"duplicate unknown type", []ext{keyShare, keyShare}, []error{ErrExtensionDuplicate}},
		{"same GREASE value twice", []ext{{0x1a1a, nil}, {0x1a1a, nil}}, []error{ErrExtensionDuplicate}},
		{"two different GREASE values", []ext{{0x1a1a, nil}, {0x2a2a, nil}}, nil},
		{"pre_shared_key last", []ext{ver, psk}, nil},
		{"pre_shared_key not last", []ext{psk, ver}, []error{ErrPreSharedKeyIsNotLastExtension}},
		{"pre_shared_key twice", []ext{psk, psk}, []error{ErrPreSharedKeyIsNotLastExtension, ErrExtensionDuplicate}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := ParseClientHello(withExt(t, tt.exts...))
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			if len(ch.Extensions) != len(tt.exts) {
				t.Errorf("got %d extensions, want %d", len(ch.Extensions), len(tt.exts))
			}
			if len(ch.Malformed) != len(tt.want) {
				t.Fatalf("Malformed = %v, want %v", ch.Malformed, tt.want)
			}
			for i, want := range tt.want {
				if !errors.Is(ch.Malformed[i], want) {
					t.Errorf("Malformed[%d] = %v, want %v", i, ch.Malformed[i], want)
				}
			}
		})
	}
}

func TestParseClientHelloDuplicateNamesType(t *testing.T) {
	ch, err := ParseClientHello(withExt(t, ext{0x0033, nil}, ext{0x0033, nil}))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if want := "extension type appears more than once: 0x0033"; len(ch.Malformed) != 1 || ch.Malformed[0].Error() != want {
		t.Errorf("Malformed = %v, want [%s]", ch.Malformed, want)
	}
}

func TestParseClientHelloALPN(t *testing.T) {
	data := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08}
	data = append(data, "http/1.1"...)
	ch, err := ParseClientHello(withExt(t, ext{0x0010, data}))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if want := []string{"h2", "http/1.1"}; !slices.Equal(ch.ALPN, want) {
		t.Errorf("ALPN = %q, want %q", ch.ALPN, want)
	}
	if len(ch.Malformed) != 0 {
		t.Errorf("Malformed = %v, want none", ch.Malformed)
	}
}

func TestParseClientHelloKeepsGREASE(t *testing.T) {
	raw := hello{
		sidLen:  32,
		ciphers: []uint16{0x0a0a, 0x1301, 0x1302},
		comp:    []byte{0},
		tail: extBlock(
			ext{0x1a1a, nil},
			ext{0x000a, []byte{0x00, 0x06, 0x2a, 0x2a, 0x00, 0x1d, 0x00, 0x17}},
			ext{0x002b, []byte{0x04, 0x3a, 0x3a, 0x03, 0x04}},
			ext{0x4a4a, []byte{0x00}},
		),
	}.build(t)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if want := []uint16{0x0a0a, 0x1301, 0x1302}; !slices.Equal(ch.CipherSuites, want) {
		t.Errorf("CipherSuites = %#04x, want %#04x", ch.CipherSuites, want)
	}
	var types []uint16
	for _, e := range ch.Extensions {
		types = append(types, e.Type)
	}
	if want := []uint16{0x1a1a, 0x000a, 0x002b, 0x4a4a}; !slices.Equal(types, want) {
		t.Errorf("extension types = %#04x, want %#04x", types, want)
	}
	if want := []uint16{0x2a2a, 0x001d, 0x0017}; !slices.Equal(ch.SupportedGroups, want) {
		t.Errorf("SupportedGroups = %#04x, want %#04x", ch.SupportedGroups, want)
	}
	if want := []uint16{0x3a3a, 0x0304}; !slices.Equal(ch.SupportedVersions, want) {
		t.Errorf("SupportedVersions = %#04x, want %#04x", ch.SupportedVersions, want)
	}
}

func TestParseClientHelloMalformedKeepsRest(t *testing.T) {
	// SNI name_type byte (0x56 + 4 + 2) set to 1.
	ch, err := ParseClientHello(mutate(t, map[int][]byte{0x5c: {0x01}}))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if len(ch.Malformed) != 1 || !errors.Is(ch.Malformed[0], ErrServerNameNameTypeNotHostName) {
		t.Fatalf("Malformed = %v, want [%v]", ch.Malformed, ErrServerNameNameTypeNotHostName)
	}
	if ch.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", ch.ServerName)
	}
	if len(ch.Extensions) != 9 {
		t.Errorf("got %d extensions, want 9", len(ch.Extensions))
	}
	if want := []uint16{0x1301, 0x00ff}; !slices.Equal(ch.CipherSuites, want) {
		t.Errorf("CipherSuites = %#04x, want %#04x", ch.CipherSuites, want)
	}
	if want := []uint16{0x001d}; !slices.Equal(ch.SupportedGroups, want) {
		t.Errorf("SupportedGroups = %#04x, want %#04x", ch.SupportedGroups, want)
	}
	if want := []uint16{0x0403, 0x0804}; !slices.Equal(ch.SignatureAlgorithms, want) {
		t.Errorf("SignatureAlgorithms = %#04x, want %#04x", ch.SignatureAlgorithms, want)
	}
	if want := []uint16{0x0304}; !slices.Equal(ch.SupportedVersions, want) {
		t.Errorf("SupportedVersions = %#04x, want %#04x", ch.SupportedVersions, want)
	}
}

func TestParseClientHelloMultipleMalformed(t *testing.T) {
	ch, err := ParseClientHello(withExt(t,
		ext{0x0000, []byte{0x00}},
		ext{0x000a, []byte{0x00, 0x02}},
		ext{0x0010, []byte{0x00, 0x00}},
	))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	want := []error{ErrServerNameTooShort, ErrSupportedGroupsTooShort, ErrALPNEmptyList}
	if len(ch.Malformed) != len(want) {
		t.Fatalf("Malformed = %v, want %v", ch.Malformed, want)
	}
	for i, w := range want {
		if !errors.Is(ch.Malformed[i], w) {
			t.Errorf("Malformed[%d] = %v, want %v", i, ch.Malformed[i], w)
		}
	}
}

func TestClientHelloJSONMalformed(t *testing.T) {
	decode := func(t *testing.T, ch *ClientHello) map[string]any {
		t.Helper()
		b, err := json.Marshal(ch)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		return m
	}

	t.Run("clean hello omits malformed", func(t *testing.T) {
		ch, err := ParseClientHello(loadFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := decode(t, ch)["malformed"]; ok {
			t.Errorf("malformed = %v, want key absent", v)
		}
	})

	t.Run("malformed hello lists messages", func(t *testing.T) {
		ch, err := ParseClientHello(mutate(t, map[int][]byte{0x5c: {0x01}}))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := decode(t, ch)["malformed"].([]any)
		if !ok {
			t.Fatalf("malformed missing or not an array: %v", decode(t, ch)["malformed"])
		}
		want := []any{ErrServerNameNameTypeNotHostName.Error()}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("malformed = %#v, want %#v", got, want)
		}
	})

	t.Run("error list marshals as strings", func(t *testing.T) {
		b, err := json.Marshal(ErrorList{ErrALPNEmptyName, ErrSupportedVersionsOddLength})
		if err != nil {
			t.Fatal(err)
		}
		want := `["` + ErrALPNEmptyName.Error() + `","` + ErrSupportedVersionsOddLength.Error() + `"]`
		if string(b) != want {
			t.Errorf("got %s, want %s", b, want)
		}
	})
}

func TestParseClientHelloPrefixes(t *testing.T) {
	fx := loadFixture(t)
	for i := range len(fx) {
		ch, err := ParseClientHello(fx[:i:i])
		if err == nil {
			t.Errorf("prefix len %d: err = nil, ch = %+v", i, ch)
		}
		if ch != nil {
			t.Errorf("prefix len %d: ch non-nil with err %v", i, err)
		}
	}
}

func TestParseClientHelloByteMutations(t *testing.T) {
	fx := loadFixture(t)
	for i := range len(fx) {
		for _, v := range []byte{0x00, 0x01, 0xff} {
			b := slices.Clone(fx)
			b[i] = v
			ch, err := parseNoPanic(t, b[:len(b):len(b)])
			if err == nil && ch == nil {
				t.Errorf("offset %#x = %#02x: nil error and nil ch", i, v)
			}
		}
	}
}

func parseNoPanic(t *testing.T, raw []byte) (ch *ClientHello, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on % x: %v", raw, r)
		}
	}()
	return ParseClientHello(raw)
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(loadFixture(f))
	f.Add(slices.Concat(loadFixture(f), []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}))
	f.Fuzz(func(t *testing.T, raw []byte) {
		raw = raw[:len(raw):len(raw)]
		ch, err := ParseClientHello(raw)
		if err != nil {
			if ch != nil {
				t.Fatalf("ch non-nil with err %v", err)
			}
			return
		}
		if ch == nil {
			t.Fatal("nil error and nil ch")
		}
		if _, err := json.Marshal(ch); err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
	})
}
