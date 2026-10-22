package fingerprint

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var testH2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// clientBurst assembles a client-side prefix: preface plus whatever frames
// the caller writes through an x/net Framer. Synthetic fixtures only — real
// captures live in testdata/ and come from captures.jsonl.
func clientBurst(t *testing.T, write func(t *testing.T, fr *http2.Framer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(testH2Preface)
	fr := http2.NewFramer(&buf, nil)
	write(t, fr)
	return buf.Bytes()
}

func TestParseH2RejectsH1(t *testing.T) {
	h1 := []byte("GET / HTTP/1.1\r\nHost: fp.test\r\n\r\n")
	fp, err := ParseH2(h1)
	assert.Error(t, err, "an H1 request line is not an H2 preface")
	assert.Nil(t, fp)
}

func TestParseH2ShortInput(t *testing.T) {
	for _, n := range []int{0, 5, 23} {
		fp, err := ParseH2(testH2Preface[:n])
		assert.Error(t, err, "prefix shorter than 24 bytes must fail at length %d", n)
		assert.Nil(t, fp)
	}
}

func TestParseH2SettingsAndWindowUpdate(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		))
		require.NoError(t, fr.WriteWindowUpdate(0, 33333))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)

	// Wire order, unsorted — order is the signal.
	want := []Setting{
		{ID: 1, Value: 4096},
		{ID: 3, Value: 100},
	}
	assert.Equal(t, want, fp.Settings)
	assert.Equal(t, uint32(33333), fp.WindowUpdate)
}

func TestParseH2HeaderOrder(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "fp.test"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "user-agent", Value: "dummy/1.0"},
	} {
		require.NoError(t, enc.WriteField(f))
	}

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":authority", ":scheme", ":path"}, fp.PseudoHeaderOrder)
	assert.Equal(t, []string{"user-agent"}, fp.HeaderOrder)
}

// TestParseH2TruncatedFinalFrame pins the §7.3 decision: a prefix cap cut
// mid-frame after a valid preface is not an error — keep what was seen.
// Flip this test if you decide otherwise.
func TestParseH2TruncatedFinalFrame(t *testing.T) {
	full := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
	})
	// Cut inside the SETTINGS payload (frame header complete, payload not).
	raw := full[:24+9+2]

	fp, err := ParseH2(raw)
	require.NoError(t, err, "truncation after a valid preface keeps the parse")
	assert.Empty(t, fp.Settings)
}

// TestParseH2CurlFixture is the real capture: 125 bytes from
// captures/captures.jsonl (curl-h2, curl 7.81.0). Fill in wantSettings and
// wantWindowUpdate from your §9 hand decode BEFORE running ParseH2 — the
// same predict-then-check discipline as JA4 vs Wireshark.
func TestParseH2CurlFixture(t *testing.T) {
	t.Skip("fill expected values from the h2-worksheet §9 hand decode first")

	raw, err := os.ReadFile("testdata/curl-h2-prefix.bin")
	require.NoError(t, err)
	require.Equal(t, 125, len(raw), "fixture drifted — re-extract from captures.jsonl")

	fp, err := ParseH2(raw)
	require.NoError(t, err)

	wantSettings := []Setting{
		// TODO: hand-decode bytes 33..68 of the fixture.
	}
	wantWindowUpdate := uint32(0) // TODO: decode the stream-0 increment.

	assert.Equal(t, wantSettings, fp.Settings)
	assert.Equal(t, wantWindowUpdate, fp.WindowUpdate)
}
